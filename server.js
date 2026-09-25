'use strict';
const express = require('express');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');

const DB_PATH = '/data/relay.json';
let db = { users: {}, messages: [], invites: {} };
try { db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch {}

// authToken -> user index, kept in sync with db.users. auth() runs on nearly
// every API request and the WS 'auth' handshake; without this it was doing a
// linear Object.values(db.users).find(...) scan per request.
const usersByToken = new Map();
for (const u of Object.values(db.users)) usersByToken.set(u.authToken, u);

function saveDb() {
    try {
        const tmp = DB_PATH + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(db));
        fs.renameSync(tmp, DB_PATH);
    } catch (e) { console.error('[CM-Relay] saveDb error:', e.message); }
}

// Debounce disk writes under bursty traffic (e.g. a flurry of messages) instead
// of doing a synchronous write per request; flushSave() forces it immediately
// (used on graceful shutdown so a redeploy never loses the last write).
let saveTimer = null;
function scheduleSave() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => { saveTimer = null; saveDb(); }, 250);
}
function flushSave() {
    if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
    saveDb();
}

const MAX_NAME_LEN = 100;
const MAX_EMAIL_LEN = 200;
const MAX_CRYPTO_FIELD_LEN = 100_000; // base64 ciphertext / iv safety cap

// Simple in-memory sliding-window counter shared by the REST rate limiter
// below and the WebSocket connect/message limiters further down.
function withinLimit(bucketMap, key, windowMs, max) {
    const now = Date.now();
    let bucket = bucketMap.get(key);
    if (!bucket || now > bucket.resetAt) {
        bucket = { count: 0, resetAt: now + windowMs };
        bucketMap.set(key, bucket);
    }
    bucket.count++;
    return bucket.count <= max;
}

// Per-IP sliding-window rate limiter for abuse-prone REST endpoints.
const RATE_LIMITS = {
    register:        { windowMs: 60_000, max: 10 },
    messages:        { windowMs: 60_000, max: 120 },
    invites:         { windowMs: 60_000, max: 20 },
    'invite-lookup': { windowMs: 60_000, max: 30 },  // unauthenticated — no other friction on this route
    search:          { windowMs: 60_000, max: 60 },
    lookup:          { windowMs: 60_000, max: 120 },
    'messages-poll': { windowMs: 60_000, max: 300 },
    'messages-read': { windowMs: 60_000, max: 60 },
    presence:        { windowMs: 60_000, max: 60 },
};
const rateBuckets = new Map();
function rateLimit(name) {
    const { windowMs, max } = RATE_LIMITS[name];
    return (req, res, next) => {
        if (!withinLimit(rateBuckets, `${name}:${req.ip}`, windowMs, max)) {
            return res.status(429).json({ error: 'Too many requests — slow down' });
        }
        next();
    };
}

// WebSocket abuse limits: cap new connections per IP (connect flood) and
// messages per connection (e.g. a spammed 'typing' flood aimed at a peer).
const WS_CONNECT_LIMIT = { windowMs: 60_000, max: 30 };
const WS_MESSAGE_LIMIT = { windowMs: 10_000, max: 60 };
const wsConnectBuckets = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k);
    for (const [k, v] of wsConnectBuckets) if (now > v.resetAt) wsConnectBuckets.delete(k);
}, 5 * 60_000).unref();

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

function auth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const user = usersByToken.get(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    next();
}

// SECURITY: canvasUserId (a small, often-sequential per-instance integer)
// and canvasUrl (the school's public Canvas domain) are not secrets — before
// this fix, anyone who knew/guessed both could POST them to /api/register
// and walk away with an existing account's real authToken (full API access:
// read/send messages, search, presence, invites) AND silently overwrite its
// publicKey (breaking E2E confidentiality for every future message sent to
// that user). Reusing an existing account now requires proving the caller
// actually holds a live Canvas session for that exact canvasUserId, by
// presenting a Canvas API token the relay verifies server-side against
// canvasUrl's own /api/v1/users/self.
const PRIVATE_IPV4_RANGES = [
    [/^127\./], [/^10\./], [/^169\.254\./], [/^192\.168\./],
    [/^172\.(1[6-9]|2\d|3[01])\./], [/^0\./], [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./],
];
function isPrivateIp(ip) {
    if (net.isIPv4(ip)) return PRIVATE_IPV4_RANGES.some(([re]) => re.test(ip));
    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')
            || lower.startsWith('::ffff:127.') || lower.startsWith('::ffff:10.') || lower.startsWith('::ffff:169.254.')
            || lower.startsWith('::ffff:192.168.');
    }
    return true; // unrecognized format: don't trust it
}
const CANVAS_VERIFY_TIMEOUT_MS = 5_000;
const CANVAS_VERIFY_MAX_BODY = 100_000;

// Connects directly to the exact IP we already vetted with isPrivateIp,
// instead of handing the hostname to a request library that would resolve
// DNS again internally — a second, independent lookup is exactly the gap
// DNS rebinding exploits (attacker's short-TTL domain answers differently
// on each query). SNI/Host stay the original hostname so cert validation
// and virtual-hosting still work normally.
function fetchPinned(hostname, port, ip, path, token) {
    return new Promise((resolve, reject) => {
        const req = https.request({
            host: ip,
            port,
            path,
            servername: hostname,
            headers: { Host: hostname, Authorization: `Bearer ${token}` },
            timeout: CANVAS_VERIFY_TIMEOUT_MS,
        }, (res) => {
            let body = '';
            let bytes = 0;
            res.on('data', (chunk) => {
                bytes += chunk.length;
                if (bytes > CANVAS_VERIFY_MAX_BODY) { req.destroy(); return reject(new Error('response too large')); }
                body += chunk;
            });
            res.on('end', () => resolve({ status: res.statusCode, body }));
        });
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        req.end();
    });
}

async function verifyCanvasIdentity(canvasUrl, canvasUserId, canvasToken) {
    if (!canvasToken || typeof canvasToken !== 'string') return false;
    let url;
    try { url = new URL(canvasUrl); } catch { return false; }
    if (url.protocol !== 'https:') return false; // no plaintext token transport
    let addr;
    try { addr = await dns.lookup(url.hostname); } catch { return false; }
    if (isPrivateIp(addr.address)) return false; // SSRF guard: canvasUrl is client-supplied

    try {
        const port = url.port ? Number(url.port) : 443;
        const res = await fetchPinned(url.hostname, port, addr.address, '/api/v1/users/self', canvasToken);
        if (res.status < 200 || res.status >= 300) return false; // covers redirects too: we never follow them
        const parsed = JSON.parse(res.body);
        return parsed && String(parsed.id) === String(canvasUserId);
    } catch {
        return false; // fail closed: unreachable/erroring/malformed proves nothing
    }
}

// Register / update profile
app.post('/api/register', rateLimit('register'), async (req, res) => {
    let { name, email, publicKey, canvasUserId, canvasUrl, canvasToken } = req.body || {};
    if (!name || !publicKey) return res.status(400).json({ error: 'name and publicKey required' });
    name = String(name).trim().slice(0, MAX_NAME_LEN);
    if (!name) return res.status(400).json({ error: 'name and publicKey required' });
    if (email) email = String(email).trim().slice(0, MAX_EMAIL_LEN);

    let existing = canvasUserId && canvasUrl
        ? Object.values(db.users).find(u => u.canvasUserId === canvasUserId && u.canvasUrl === canvasUrl)
        : null;

    if (existing) {
        if (!(await verifyCanvasIdentity(canvasUrl, canvasUserId, canvasToken))) {
            return res.status(401).json({ error: 'Could not verify Canvas identity for this account' });
        }
        // Rotate the token on every verified reclaim: anyone who obtained the
        // old one (e.g. via this same endpoint before this fix existed) must
        // not keep standing access just because the real owner re-registered.
        usersByToken.delete(existing.authToken);
        existing.authToken = crypto.randomBytes(32).toString('hex');
        existing.name = name;
        existing.email = email || null;
        existing.publicKey = publicKey;
        usersByToken.set(existing.authToken, existing);
        saveDb();
        return res.json({ id: existing.id, authToken: existing.authToken });
    }

    const id = crypto.randomUUID();
    const authToken = crypto.randomBytes(32).toString('hex');
    const user = { id, name, email: email || null, publicKey, authToken,
        canvasUserId: canvasUserId || null, canvasUrl: canvasUrl || null,
        createdAt: new Date().toISOString() };
    db.users[id] = user;
    usersByToken.set(authToken, user);
    saveDb();
    res.json({ id, authToken });
});

// Current authenticated user's own identity — used by other services (e.g.
// cm-signaling) to verify a bearer token actually belongs to the Canvas user
// it's being presented for, without those services needing their own copy
// of user records.
app.get('/api/me', auth, (req, res) => {
    const u = req.user;
    res.json({ id: u.id, name: u.name, email: u.email, canvasUserId: u.canvasUserId, canvasUrl: u.canvasUrl });
});

// Search by name or email
app.get('/api/users/search', auth, rateLimit('search'), (req, res) => {
    const q = String(req.query.q || '').toLowerCase().trim();
    if (q.length < 2) return res.json([]);
    const results = Object.values(db.users)
        .filter(u => u.id !== req.user.id &&
            (u.name.toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q)))
        .slice(0, 20)
        .map(u => ({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey }));
    res.json(results);
});

// Get user by ID
app.get('/api/users/:id', auth, rateLimit('lookup'), (req, res) => {
    const u = db.users[req.params.id];
    if (!u) return res.status(404).json({ error: 'Not found' });
    res.json({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey });
});

// Send encrypted message
app.post('/api/messages', auth, rateLimit('messages'), (req, res) => {
    const { recipientId, encryptedBody, iv } = req.body || {};
    if (!recipientId || !encryptedBody || !iv) return res.status(400).json({ error: 'Missing fields' });
    if (typeof encryptedBody !== 'string' || typeof iv !== 'string' ||
        encryptedBody.length > MAX_CRYPTO_FIELD_LEN || iv.length > MAX_CRYPTO_FIELD_LEN) {
        return res.status(400).json({ error: 'Payload too large' });
    }
    if (!db.users[recipientId]) return res.status(404).json({ error: 'Recipient not found' });

    const threadId = [req.user.id, recipientId].sort().join('_');
    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    const message = { id, threadId, senderId: req.user.id, recipientId, encryptedBody, iv, sentAt, readAt: null };
    db.messages.push(message);
    if (db.messages.length > 50000) db.messages = db.messages.slice(-50000);
    scheduleSave();

    const ws = wsClients.get(recipientId);
    if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'message', message }));
    }
    res.json({ id, threadId, sentAt });
});

// Get messages since timestamp
app.get('/api/messages', auth, rateLimit('messages-poll'), (req, res) => {
    const since = req.query.since || '1970-01-01T00:00:00.000Z';
    const msgs = db.messages
        .filter(m => (m.senderId === req.user.id || m.recipientId === req.user.id) && m.sentAt > since)
        .slice(-500);
    res.json(msgs);
});

// Mark all messages in a thread addressed to me as read, and notify the sender.
app.post('/api/messages/read', auth, rateLimit('messages-read'), (req, res) => {
    const { threadId } = req.body || {};
    if (!threadId) return res.status(400).json({ error: 'threadId required' });

    const readAt = new Date().toISOString();
    let updated = 0;
    let senderId = null;
    for (const m of db.messages) {
        if (m.threadId === threadId && m.recipientId === req.user.id && !m.readAt) {
            m.readAt = readAt;
            senderId = m.senderId;
            updated++;
        }
    }
    if (updated > 0) {
        scheduleSave();
        const ws = senderId && wsClients.get(senderId);
        if (ws && ws.readyState === 1) {
            ws.send(JSON.stringify({ type: 'read', threadId, readAt }));
        }
    }
    res.json({ ok: true, updated, readAt });
});

// Online/last-seen status for a batch of user ids
app.get('/api/presence', auth, rateLimit('presence'), (req, res) => {
    const ids = String(req.query.ids || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 50);
    const result = {};
    for (const id of ids) {
        const u = db.users[id];
        result[id] = { online: wsClients.has(id), lastSeen: u ? (u.lastSeen || null) : null };
    }
    res.json(result);
});

// Create invite token
app.post('/api/invites', auth, rateLimit('invites'), (req, res) => {
    const token = crypto.randomBytes(16).toString('hex');
    db.invites[token] = { token, creatorId: req.user.id, createdAt: new Date().toISOString() };
    saveDb();
    res.json({ token });
});

// Resolve invite
app.get('/api/invites/:token', rateLimit('invite-lookup'), (req, res) => {
    const inv = db.invites[req.params.token];
    if (!inv) return res.status(404).json({ error: 'Invalid invite' });
    const u = db.users[inv.creatorId];
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey });
});

// WebSocket real-time delivery
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const wsClients = new Map();

wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress || 'unknown';
    if (!withinLimit(wsConnectBuckets, ip, WS_CONNECT_LIMIT.windowMs, WS_CONNECT_LIMIT.max)) {
        ws.close(1013, 'Too many connections');
        return;
    }

    let userId = null;
    let msgBucket = { count: 0, resetAt: Date.now() + WS_MESSAGE_LIMIT.windowMs };
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', data => {
        const now = Date.now();
        if (now > msgBucket.resetAt) msgBucket = { count: 0, resetAt: now + WS_MESSAGE_LIMIT.windowMs };
        msgBucket.count++;
        if (msgBucket.count > WS_MESSAGE_LIMIT.max) { ws.close(1013, 'Too many messages'); return; }
        try {
            const msg = JSON.parse(data);
            if (msg.type === 'auth') {
                const user = usersByToken.get(msg.token);
                if (user) {
                    userId = user.id;
                    wsClients.set(userId, ws);
                    ws.send(JSON.stringify({ type: 'auth-ok', userId }));
                }
                return;
            }
            if (msg.type === 'typing') {
                if (!userId || !msg.to) return;
                const peerWs = wsClients.get(String(msg.to));
                if (peerWs && peerWs.readyState === 1) {
                    peerWs.send(JSON.stringify({ type: 'typing', from: userId }));
                }
            }
        } catch {}
    });
    ws.on('close', () => {
        if (userId) {
            // Only remove the map entry if it still points at *this* socket — a user
            // reconnecting (e.g. a second tab) overwrites the entry with the new
            // socket, and the old socket's close event must not evict it.
            if (wsClients.get(userId) === ws) wsClients.delete(userId);
            if (db.users[userId]) {
                db.users[userId].lastSeen = new Date().toISOString();
                scheduleSave();
            }
        }
    });
    ws.on('error', () => {});
});

// Detect and drop half-open connections (e.g. a laptop that went to sleep)
// that never sent a close frame — without this, wsClients can keep pointing
// at a dead socket that silently swallows real-time deliveries.
const heartbeatInterval = setInterval(() => {
    for (const ws of wss.clients) {
        if (ws.isAlive === false) { ws.terminate(); continue; }
        ws.isAlive = false;
        try { ws.ping(); } catch {}
    }
}, 30_000);
wss.on('close', () => clearInterval(heartbeatInterval));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[CM-Relay] listening on :${PORT}`));

function shutdown() {
    clearInterval(heartbeatInterval);
    flushSave();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
