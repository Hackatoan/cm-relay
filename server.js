'use strict';
const express = require('express');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');

const DB_PATH = '/data/relay.json';
let db = { users: {}, messages: [], invites: {} };
try { db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch {}
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

// Simple in-memory per-IP sliding-window rate limiter for abuse-prone endpoints.
const RATE_LIMITS = {
    register: { windowMs: 60_000, max: 10 },
    messages: { windowMs: 60_000, max: 120 },
    invites:  { windowMs: 60_000, max: 20 },
};
const rateBuckets = new Map();
function rateLimit(name) {
    const { windowMs, max } = RATE_LIMITS[name];
    return (req, res, next) => {
        const key = `${name}:${req.ip}`;
        const now = Date.now();
        let bucket = rateBuckets.get(key);
        if (!bucket || now > bucket.resetAt) {
            bucket = { count: 0, resetAt: now + windowMs };
            rateBuckets.set(key, bucket);
        }
        bucket.count++;
        if (bucket.count > max) return res.status(429).json({ error: 'Too many requests — slow down' });
        next();
    };
}
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k);
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
    const user = Object.values(db.users).find(u => u.authToken === token);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    next();
}

// Register / update profile
app.post('/api/register', rateLimit('register'), (req, res) => {
    let { name, email, publicKey, canvasUserId, canvasUrl } = req.body || {};
    if (!name || !publicKey) return res.status(400).json({ error: 'name and publicKey required' });
    name = String(name).trim().slice(0, MAX_NAME_LEN);
    if (!name) return res.status(400).json({ error: 'name and publicKey required' });
    if (email) email = String(email).trim().slice(0, MAX_EMAIL_LEN);

    let existing = canvasUserId && canvasUrl
        ? Object.values(db.users).find(u => u.canvasUserId === canvasUserId && u.canvasUrl === canvasUrl)
        : null;

    if (existing) {
        existing.name = name;
        existing.email = email || null;
        existing.publicKey = publicKey;
        saveDb();
        return res.json({ id: existing.id, authToken: existing.authToken });
    }

    const id = crypto.randomUUID();
    const authToken = crypto.randomBytes(32).toString('hex');
    db.users[id] = { id, name, email: email || null, publicKey, authToken,
        canvasUserId: canvasUserId || null, canvasUrl: canvasUrl || null,
        createdAt: new Date().toISOString() };
    saveDb();
    res.json({ id, authToken });
});

// Search by name or email
app.get('/api/users/search', auth, (req, res) => {
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
app.get('/api/users/:id', auth, (req, res) => {
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
app.get('/api/messages', auth, (req, res) => {
    const since = req.query.since || '1970-01-01T00:00:00.000Z';
    const msgs = db.messages
        .filter(m => (m.senderId === req.user.id || m.recipientId === req.user.id) && m.sentAt > since)
        .slice(-500);
    res.json(msgs);
});

// Mark all messages in a thread addressed to me as read, and notify the sender.
app.post('/api/messages/read', auth, (req, res) => {
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
app.get('/api/presence', auth, (req, res) => {
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
app.get('/api/invites/:token', (req, res) => {
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

wss.on('connection', ws => {
    let userId = null;
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', data => {
        try {
            const msg = JSON.parse(data);
            if (msg.type === 'auth') {
                const user = Object.values(db.users).find(u => u.authToken === msg.token);
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
