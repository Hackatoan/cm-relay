'use strict';
const express = require('express');
const proxyaddr = require('proxy-addr');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const admin = require('firebase-admin');
const { registerAccountRoutes } = require('./account');

const DB_PATH = process.env.RELAY_DB_PATH || '/data/relay.json';

// Previously any load failure silently started an empty db, and the first
// save then overwrote relay.json — turning a truncated/unreadable file (e.g.
// after a power loss or disk-full) into permanent loss of every account and
// message. Now: a missing file starts fresh; a corrupt one is preserved
// beside the original before starting fresh; any other read error (EACCES,
// EIO, ...) aborts startup rather than clobbering data we couldn't read.
function loadDb() {
    const empty = () => ({ users: {}, messages: [], invites: {} });
    let raw;
    try { raw = fs.readFileSync(DB_PATH, 'utf8'); }
    catch (e) {
        if (e.code === 'ENOENT') return empty();
        console.error(`[CM-Relay] cannot read ${DB_PATH} (${e.code || e.message}) — refusing to start and overwrite it`);
        process.exit(1);
    }
    try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not a JSON object');
        const isMap = v => !!v && typeof v === 'object' && !Array.isArray(v);
        return {
            ...parsed,
            users: isMap(parsed.users) ? parsed.users : {},
            messages: Array.isArray(parsed.messages) ? parsed.messages : [],
            invites: isMap(parsed.invites) ? parsed.invites : {},
        };
    } catch (e) {
        const backup = `${DB_PATH}.corrupt-${Date.now()}`;
        try { fs.copyFileSync(DB_PATH, backup); }
        catch (e2) {
            console.error(`[CM-Relay] ${DB_PATH} is corrupt (${e.message}) and could not be backed up (${e2.message}) — refusing to start`);
            process.exit(1);
        }
        console.error(`[CM-Relay] ${DB_PATH} is corrupt (${e.message}); preserved as ${backup}, starting with an empty db`);
        return empty();
    }
}
let db = loadDb();

// Firestore is used only as cross-device escrow for each user's long-term
// ECDH keypair (+ their contacts list) — everything else (accounts, messages)
// stays in relay.json as before. Every access goes through this trusted
// server using the service-account's admin privileges, so there are no
// Firestore security rules to maintain and no Firebase Auth involved on the
// client. If the credential is missing/invalid, sync is skipped (logged
// once) rather than failing registration — an extension install must keep
// working even if Firestore is temporarily unreachable or unconfigured.
let fsdb = null;
try {
    const svcJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (svcJson) {
        admin.initializeApp({ credential: admin.credential.cert(JSON.parse(svcJson)) });
        fsdb = admin.firestore();
    } else {
        console.warn('[CM-Relay] FIREBASE_SERVICE_ACCOUNT not set — cross-device key sync disabled.');
    }
} catch (e) {
    console.error('[CM-Relay] Firebase Admin init failed — cross-device key sync disabled:', e.message);
}

// authToken -> user index, kept in sync with db.users. auth() runs on nearly
// every API request and the WS 'auth' handshake; without this it was doing a
// linear Object.values(db.users).find(...) scan per request.
const usersByToken = new Map();
for (const u of Object.values(db.users)) usersByToken.set(u.authToken, u);

// (canvasUrl, canvasUserId) -> user index, kept in sync with db.users. The
// /api/register reclaim path below runs on every registration (i.e. every
// extension install/reload, not just first sign-up) and was doing a linear
// Object.values(db.users).find(...) scan to find the account being reclaimed.
const usersByCanvasKey = new Map();
function canvasKey(url, id) { return JSON.stringify([url, id]); }

// Firebase Auth uid -> relay user, for accounts linked via /api/account/*.
const usersByFirebaseUid = new Map();
for (const u of Object.values(db.users)) {
    if (u.firebaseUid) usersByFirebaseUid.set(u.firebaseUid, u);
}
for (const u of Object.values(db.users)) {
    if (u.canvasUserId && u.canvasUrl) usersByCanvasKey.set(canvasKey(u.canvasUrl, u.canvasUserId), u);
}

// userId -> that user's messages (as sender or recipient), kept in sync with
// db.messages. GET /api/messages is polled up to 300x/min per user (the
// tightest limit of any REST route here) and was doing a full
// Array.filter over the *entire* global log (up to 50,000 messages) just to
// pull out one user's slice of it.
const messagesByUser = new Map();
// Users whose messagesByUser slice is NOT in ascending sentAt order (only
// possible if the wall clock stepped backwards between two sends, or a
// legacy record has no string sentAt). Every other slice is sorted, which
// lets GET /api/messages binary-search `since`.
const unsortedUsers = new Set();

// threadId -> that thread's messages, kept in sync with db.messages.
// POST /api/messages/read was iterating the entire global log to find messages
// in a specific thread — with up to 50,000 messages, that's expensive.
const messagesByThread = new Map();

function indexMessage(m) {
    for (const uid of [m.senderId, m.recipientId]) {
        let arr = messagesByUser.get(uid);
        if (!arr) { arr = []; messagesByUser.set(uid, arr); }
        if (typeof m.sentAt !== 'string' ||
            (arr.length && arr[arr.length - 1].sentAt > m.sentAt)) unsortedUsers.add(uid);
        arr.push(m);
    }
    let arr = messagesByThread.get(m.threadId);
    if (!arr) { arr = []; messagesByThread.set(m.threadId, arr); }
    arr.push(m);
}
function unindexMessage(m) {
    for (const uid of [m.senderId, m.recipientId]) {
        const arr = messagesByUser.get(uid);
        if (!arr) continue;
        const i = arr.indexOf(m);
        if (i !== -1) arr.splice(i, 1);
    }
    const arr = messagesByThread.get(m.threadId);
    if (arr) {
        const i = arr.indexOf(m);
        if (i !== -1) arr.splice(i, 1);
    }
}
// Approximate in-memory/on-disk size of one stored message (see MAX_MESSAGE_LOG_BYTES).
const messageBytes = m => (m.encryptedBody?.length || 0) + (m.iv?.length || 0) + 256; // + ids/timestamps
let messageLogBytes = 0;
for (const m of db.messages) { indexMessage(m); messageLogBytes += messageBytes(m); }

function saveDb() {
    try {
        const tmp = DB_PATH + '.tmp';
        const fd = fs.openSync(tmp, 'w');
        try {
            fs.writeFileSync(fd, JSON.stringify(db));
            fs.fsyncSync(fd); // data on disk before the rename makes it live
        } finally { fs.closeSync(fd); }
        fs.renameSync(tmp, DB_PATH);
    } catch (e) { console.error('[CM-Relay] saveDb error:', e.message); }
}

// Debounce disk writes under bursty traffic (e.g. a flurry of messages) instead
// of doing a synchronous write per request; flushSave() forces it immediately
// (used on graceful shutdown so a redeploy never loses the last write).
//
// saveDb() re-serializes the *whole* DB synchronously (~175 ms for a ~34 MB
// file at the 50k-message cap), so under steady traffic a 250 ms window kept
// the event loop blocked most of the time. 2 s cuts that ~8x; the trade-off
// is a wider window of writes lost on a hard crash (graceful stop still
// flushes).
const SAVE_DEBOUNCE_MS = 2_000;
let saveTimer = null;
function scheduleSave() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => { saveTimer = null; saveDb(); }, SAVE_DEBOUNCE_MS);
}
function flushSave() {
    if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
    saveDb();
}

const MAX_NAME_LEN = 100;
const MAX_EMAIL_LEN = 200;
const MAX_CRYPTO_FIELD_LEN = 100_000; // base64 ciphertext safety cap
const MAX_IV_LEN = 64;                // AES-GCM 12-byte IV is 16 base64 chars
// The 50,000-message cap alone bounds the log by count, not size: at the
// per-field cap that's several GB held in memory and rewritten to relay.json
// on every save. Also evict oldest-first once the log's payload bytes pass
// this budget (far above what normal text traffic produces).
const MAX_MESSAGE_LOG = 50_000;
const MAX_MESSAGE_LOG_BYTES = 64 * 1024 * 1024;
const MAX_JWK_LEN = 4096;           // JSON-serialized P-256 JWK is a few hundred chars
const MAX_CANVAS_FIELD_LEN = 2048;

// publicKey/privateKey arrive as JSON-serialized JWKs. They're stored and
// later JSON.parse'd (escrow restore), served to other users (search/lookup),
// and written to relay.json/Firestore — so accept only a bounded string that
// actually parses to an object.
function isJwkString(v) {
    if (typeof v !== 'string' || v.length > MAX_JWK_LEN) return false;
    try { const o = JSON.parse(v); return !!o && typeof o === 'object' && !Array.isArray(o); } catch { return false; }
}

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
    account:         { windowMs: 60_000, max: 20 },
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
        if (!withinLimit(rateBuckets, `${name}:${clientIp(req)}`, windowMs, max)) {
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

// Client IP for rate limiting. Behind a reverse proxy / CDN every request's
// socket address is the proxy's, so all users share one bucket per limiter
// (a single abusive client can exhaust e.g. the register or WS-connect
// budget for everyone) and per-client limits don't apply. TRUST_PROXY opts
// in to reading X-Forwarded-For from *trusted* hops only — it uses Express's
// own trust-proxy syntax: a comma list of addresses/CIDRs/presets
// ("loopback", "linklocal", "uniquelocal") or a hop count. Prefer an explicit
// address list: a hop count or "true" lets anyone who can reach the port
// directly spoof their IP. Unset = previous behavior (socket address).
const TRUST_PROXY = (process.env.TRUST_PROXY || '').trim();
if (TRUST_PROXY) {
    app.set('trust proxy', /^\d+$/.test(TRUST_PROXY) ? Number(TRUST_PROXY)
        : TRUST_PROXY === 'true' ? true : TRUST_PROXY.split(',').map(x => x.trim()).filter(Boolean));
    console.log('[CM-Relay] trust proxy:', TRUST_PROXY);
}
const trustProxyFn = app.get('trust proxy fn');
function clientIp(req) {
    try { return proxyaddr(req, trustProxyFn) || 'unknown'; } catch { return req.socket?.remoteAddress || 'unknown'; }
}
app.disable('x-powered-by');
app.use(express.json({ limit: '4mb' }));
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Firebase-Token');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    // Responses carry bearer tokens, escrowed key material and message
    // ciphertext: never let a browser, proxy or CDN cache them, and don't
    // let browsers content-sniff the JSON as something executable.
    res.header('Cache-Control', 'no-store');
    res.header('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// db.users / db.invites are plain objects used as string-keyed maps, loaded
// straight from JSON and indexed by attacker-supplied path/query/body values
// (user id, recipientId, presence ids, invite token). A bare `obj[key]` on a
// plain object also resolves inherited properties, so a key like "__proto__",
// "constructor", "hasOwnProperty" etc. returns a truthy Object.prototype value
// instead of undefined — silently bypassing "not found" checks. Route every
// such lookup through this helper so only actual own entries count.
function safeGet(obj, key) {
    return (typeof key === 'string' && Object.prototype.hasOwnProperty.call(obj, key)) ? obj[key] : undefined;
}

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
// Everything that isn't ordinary public unicast is refused: the old
// prefix-string checks missed whole classes of IPv6 spellings (unspecified
// "::", IPv4-mapped forms of most private ranges, NAT64/6to4/Teredo, which
// embed an arbitrary IPv4) plus reserved/multicast IPv4 ranges.
const BLOCKED_ADDRS = new net.BlockList();
for (const [net4, len] of [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
    ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
    ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) BLOCKED_ADDRS.addSubnet(net4, len, 'ipv4');
for (const [net6, len] of [
    ['::', 128], ['::1', 128], ['::', 96] /* IPv4-compatible */, ['64:ff9b::', 96], ['64:ff9b:1::', 48],
    ['100::', 64], ['2001::', 32] /* Teredo */, ['2001:db8::', 32], ['2002::', 16] /* 6to4 */,
    ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
]) BLOCKED_ADDRS.addSubnet(net6, len, 'ipv6');
// (IPv4-mapped ::ffff:a.b.c.d is matched against the IPv4 rules by BlockList
// itself, so it must not be blocked wholesale — that would block all IPv4.)
function isPrivateIp(ip) {
    if (net.isIPv4(ip)) return BLOCKED_ADDRS.check(ip, 'ipv4');
    if (net.isIPv6(ip)) return BLOCKED_ADDRS.check(ip, 'ipv6');
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
        // `timeout` above is only a socket *idle* timeout: a server that drips
        // a byte every few seconds would keep this (and the /api/register
        // request awaiting it) open indefinitely. Enforce a total deadline too.
        const deadline = setTimeout(() => req.destroy(new Error('deadline exceeded')), CANVAS_VERIFY_TIMEOUT_MS * 2);
        req.on('close', () => clearTimeout(deadline));
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

// Read this user's escrowed keypair/contacts from Firestore, if any. Never
// throws — callers treat a null return as "no Firestore, proceed as before".
async function readKeyEscrow(userId) {
    if (!fsdb) return null;
    try {
        const snap = await fsdb.collection('users').doc(userId).get();
        return snap.exists ? snap.data() : null;
    } catch (e) { console.error('[CM-Relay] Firestore read failed:', e.message); return null; }
}

// Escrow a keypair (+ optional contacts) for this user. Best-effort: a write
// failure must not fail registration, it just means the next device won't
// find a stored key and will fall back to today's (key-rotating) behaviour.
async function writeKeyEscrow(userId, { publicKeyJwk, privateKeyJwk, contacts }) {
    if (!fsdb) return;
    try {
        const data = { publicKeyJwk, privateKeyJwk, updatedAt: new Date().toISOString() };
        if (contacts !== undefined) data.contacts = contacts;
        await fsdb.collection('users').doc(userId).set(data, { merge: true });
    } catch (e) { console.error('[CM-Relay] Firestore write failed:', e.message); }
}

// Register / update profile
app.post('/api/register', rateLimit('register'), async (req, res) => {
    let { name, email, publicKey, privateKey, canvasUserId, canvasUrl, canvasToken } = req.body || {};
    if (!name || !publicKey) return res.status(400).json({ error: 'name and publicKey required' });
    name = String(name).trim().slice(0, MAX_NAME_LEN);
    if (!name) return res.status(400).json({ error: 'name and publicKey required' });
    if (email) email = String(email).trim().slice(0, MAX_EMAIL_LEN);
    if (!isJwkString(publicKey) || (privateKey != null && !isJwkString(privateKey))) {
        return res.status(400).json({ error: 'Invalid key format' });
    }
    if ((canvasUrl != null && (typeof canvasUrl !== 'string' || canvasUrl.length > MAX_CANVAS_FIELD_LEN)) ||
        (canvasUserId != null && !((typeof canvasUserId === 'string' && canvasUserId.length <= MAX_CANVAS_FIELD_LEN) ||
            Number.isSafeInteger(canvasUserId))) ||
        (canvasToken != null && (typeof canvasToken !== 'string' || canvasToken.length > MAX_CANVAS_FIELD_LEN))) {
        return res.status(400).json({ error: 'Invalid Canvas fields' });
    }

    // A Canvas identity attached to a relay account is trusted elsewhere
    // (cm-signaling routes calls by the canvasUserId /api/me reports, and a
    // later reclaim adopts whatever keypair was escrowed for the account), so
    // it must be proven before it is bound — for brand-new accounts too, not
    // only when reclaiming an existing one. Verifying up front (before the
    // lookup) also means the response doesn't reveal whether an account for
    // this identity already exists. Accounts without a Canvas identity are
    // unaffected.
    const hasCanvasIdentity = !!(canvasUserId && canvasUrl);
    if (hasCanvasIdentity && !(await verifyCanvasIdentity(canvasUrl, canvasUserId, canvasToken))) {
        return res.status(401).json({ error: 'Could not verify Canvas identity for this account' });
    }

    // Looked up after the await so a concurrent registration for the same
    // identity that finished first is reclaimed rather than duplicated.
    let existing = hasCanvasIdentity
        ? usersByCanvasKey.get(canvasKey(canvasUrl, canvasUserId))
        : null;

    if (existing) {
        // Rotate the token on every verified reclaim: anyone who obtained the
        // old one (e.g. via this same endpoint before this fix existed) must
        // not keep standing access just because the real owner re-registered.
        usersByToken.delete(existing.authToken);
        revokeWsSessions(existing.authToken);
        existing.authToken = crypto.randomBytes(32).toString('hex');
        existing.name = name;
        existing.email = email || null;

        // A second (or reinstalled) device just generated its own keypair and
        // sent it as `publicKey`/`privateKey` — but if we already escrowed a
        // real one for this account, that one wins: overwriting publicKey here
        // would silently break decryption of every message anyone already
        // encrypted for the escrowed key. Hand the caller the real keypair
        // back instead so it can discard the one it just generated.
        const escrow = await readKeyEscrow(existing.id);
        let responseKeypair, responseContacts;
        if (escrow?.publicKeyJwk && escrow?.privateKeyJwk) {
            // A throw here would be an unhandled rejection (Express 4 doesn't
            // catch async handlers), which takes the whole process down.
            try {
                responseKeypair = { publicKeyJwk: JSON.parse(escrow.publicKeyJwk), privateKeyJwk: JSON.parse(escrow.privateKeyJwk) };
            } catch {
                console.error('[CM-Relay] unreadable key escrow for user', existing.id, '— replacing with caller keypair');
            }
        }
        if (responseKeypair) {
            existing.publicKey = escrow.publicKeyJwk;
            try { if (escrow.contacts) responseContacts = JSON.parse(escrow.contacts); } catch { /* skip corrupt contacts */ }
        } else {
            existing.publicKey = publicKey;
            if (privateKey) await writeKeyEscrow(existing.id, { publicKeyJwk: publicKey, privateKeyJwk: privateKey });
        }
        usersByToken.set(existing.authToken, existing);
        // Debounced like message writes: a full synchronous saveDb() here
        // re-serialized the whole log (tens of MB at the 50k cap) and blocked
        // the event loop on every extension install/reload.
        scheduleSave();
        return res.json({ id: existing.id, authToken: existing.authToken, keypair: responseKeypair, contacts: responseContacts });
    }

    const id = crypto.randomUUID();
    const authToken = crypto.randomBytes(32).toString('hex');
    const user = { id, name, email: email || null, publicKey, authToken,
        canvasUserId: hasCanvasIdentity ? canvasUserId : null, canvasUrl: hasCanvasIdentity ? canvasUrl : null,
        createdAt: new Date().toISOString() };
    db.users[id] = user;
    usersByToken.set(authToken, user);
    if (hasCanvasIdentity) usersByCanvasKey.set(canvasKey(canvasUrl, canvasUserId), user);
    scheduleSave();
    if (privateKey) await writeKeyEscrow(id, { publicKeyJwk: publicKey, privateKeyJwk: privateKey });
    res.json({ id, authToken });
});

// Push an updated contacts list into this user's key escrow doc, so a future
// device restores contacts (and can decrypt their backfilled messages)
// instead of starting from zero. Best-effort, mirrors the relay's other
// fire-and-forget sync calls.
app.post('/api/sync-contacts', auth, rateLimit('register'), async (req, res) => {
    const { contacts } = req.body || {};
    if (!Array.isArray(contacts)) return res.status(400).json({ error: 'contacts array required' });
    if (!fsdb) return res.json({ ok: true, synced: false });
    const escrow = await readKeyEscrow(req.user.id);
    if (!escrow?.publicKeyJwk) return res.json({ ok: true, synced: false }); // nothing to attach contacts to yet
    await writeKeyEscrow(req.user.id, {
        publicKeyJwk: escrow.publicKeyJwk, privateKeyJwk: escrow.privateKeyJwk,
        contacts: JSON.stringify(contacts.slice(0, 500)),
    });
    res.json({ ok: true, synced: true });
});

// Firebase-Auth-backed accounts (sign in on a new device without redoing the
// Canvas token flow). See account.js.
registerAccountRoutes(app, {
    auth, rateLimit, db, saveDb, usersByFirebaseUid, fsdb,
    readKeyEscrow, verifyCanvasIdentity,
    encKey: process.env.ACCOUNT_ENC_KEY,
    verifyIdToken: async token => {
        if (!fsdb) throw new Error('firebase not configured');
        return admin.auth().verifyIdToken(token, true);
    },
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
    // Stop at the 20th match instead of lowercasing + substring-matching the
    // name/email of every user in the table just to keep the first 20. for-in
    // (not Object.values) so a match near the front doesn't still pay to copy
    // the whole user table into a temporary array first.
    const results = [];
    for (const id in db.users) {
        if (!Object.prototype.hasOwnProperty.call(db.users, id)) continue;
        const u = db.users[id];
        if (u.id !== req.user.id &&
            (u.name.toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))) {
            results.push({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey });
            if (results.length === 20) break;
        }
    }
    res.json(results);
});

// Get user by ID
app.get('/api/users/:id', auth, rateLimit('lookup'), (req, res) => {
    const u = safeGet(db.users, req.params.id);
    if (!u) return res.status(404).json({ error: 'Not found' });
    res.json({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey });
});

// Send encrypted message
app.post('/api/messages', auth, rateLimit('messages'), (req, res) => {
    const { recipientId, encryptedBody, iv } = req.body || {};
    if (!recipientId || !encryptedBody || !iv) return res.status(400).json({ error: 'Missing fields' });
    if (typeof encryptedBody !== 'string' || typeof iv !== 'string' ||
        encryptedBody.length > MAX_CRYPTO_FIELD_LEN || iv.length > MAX_IV_LEN) {
        return res.status(400).json({ error: 'Payload too large' });
    }
    if (!safeGet(db.users, recipientId)) return res.status(404).json({ error: 'Recipient not found' });

    const threadId = [req.user.id, recipientId].sort().join('_');
    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    const message = { id, threadId, senderId: req.user.id, recipientId, encryptedBody, iv, sentAt, readAt: null };
    db.messages.push(message);
    indexMessage(message);
    messageLogBytes += messageBytes(message);
    if (db.messages.length > MAX_MESSAGE_LOG || messageLogBytes > MAX_MESSAGE_LOG_BYTES) {
        let toDropCount = Math.max(0, db.messages.length - MAX_MESSAGE_LOG);
        for (let i = 0; i < toDropCount; i++) messageLogBytes -= messageBytes(db.messages[i]);
        // Keep at least the message just sent.
        while (messageLogBytes > MAX_MESSAGE_LOG_BYTES && toDropCount < db.messages.length - 1) {
            messageLogBytes -= messageBytes(db.messages[toDropCount++]);
        }
        for (let i = 0; i < toDropCount; i++) {
            unindexMessage(db.messages[i]);
        }
        // Trim in place: once the log is at the cap this runs on *every* send
        // (dropping one message), and slice(-50000) was allocating and copying
        // a fresh 50,000-element array each time just to discard the old one.
        db.messages.splice(0, toDropCount);
    }
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
    const all = messagesByUser.get(req.user.id) || [];
    if (unsortedUsers.has(req.user.id)) {
        return res.json(all.filter(m => m.sentAt > since).slice(-500));
    }
    // Sorted by sentAt: binary-search the first message newer than `since`
    // instead of testing every message this user has ever sent/received on
    // each poll. Same result as filter(...).slice(-500).
    let lo = 0, hi = all.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (all[mid].sentAt > since) hi = mid; else lo = mid + 1;
    }
    res.json(all.slice(Math.max(lo, all.length - 500)));
});

// Mark all messages in a thread addressed to me as read, and notify the sender.
app.post('/api/messages/read', auth, rateLimit('messages-read'), (req, res) => {
    const { threadId } = req.body || {};
    if (!threadId) return res.status(400).json({ error: 'threadId required' });

    const readAt = new Date().toISOString();
    let updated = 0;
    let senderId = null;
    const msgs = messagesByThread.get(threadId) || [];
    // readAt is only ever set here, for *every* unread message to me in the
    // thread at once, so my unread messages are always a suffix of the ones
    // addressed to me. Walk back from the newest and stop at the first one
    // already read, instead of rescanning the whole thread history each time.
    for (let i = msgs.length - 1; i >= 0; i--) {
        const m = msgs[i];
        if (m.recipientId !== req.user.id) continue;
        if (m.readAt) break;
        m.readAt = readAt;
        if (!senderId) senderId = m.senderId; // newest, as before
        updated++;
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
        const u = safeGet(db.users, id);
        result[id] = { online: wsClients.has(id), lastSeen: u ? (u.lastSeen || null) : null };
    }
    res.json(result);
});

// Invites never expire, so without a bound every account could grow
// db.invites (and every relay.json rewrite) without limit, 20/min at a time.
// Keep each user's newest MAX_INVITES_PER_USER links; creating one more
// retires that user's oldest.
const MAX_INVITES_PER_USER = 50;
const invitesByCreator = new Map(); // creatorId -> tokens, oldest first
for (const [token, inv] of Object.entries(db.invites).sort(([, a], [, b]) => String(a?.createdAt).localeCompare(String(b?.createdAt)))) {
    let arr = invitesByCreator.get(inv?.creatorId);
    if (!arr) { arr = []; invitesByCreator.set(inv?.creatorId, arr); }
    arr.push(token);
}

// Create invite token
app.post('/api/invites', auth, rateLimit('invites'), (req, res) => {
    const token = crypto.randomBytes(16).toString('hex');
    db.invites[token] = { token, creatorId: req.user.id, createdAt: new Date().toISOString() };
    let mine = invitesByCreator.get(req.user.id);
    if (!mine) { mine = []; invitesByCreator.set(req.user.id, mine); }
    mine.push(token);
    while (mine.length > MAX_INVITES_PER_USER) delete db.invites[mine.shift()];
    scheduleSave();
    res.json({ token });
});

// Resolve invite
app.get('/api/invites/:token', rateLimit('invite-lookup'), (req, res) => {
    const inv = safeGet(db.invites, req.params.token);
    if (!inv) return res.status(404).json({ error: 'Invalid invite' });
    const u = safeGet(db.users, inv.creatorId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ id: u.id, name: u.name, email: u.email, publicKey: u.publicKey });
});

// Final error handler. Without it, Express's default handler answers errors
// (e.g. a malformed JSON body from express.json()) with an HTML page that
// includes the stack trace and server file paths unless NODE_ENV=production.
// Keep the status for client errors (4xx from body-parser), log the rest.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
    if (status === 500) console.error('[CM-Relay] unhandled route error:', err?.stack || err);
    if (res.headersSent) return;
    res.status(status).json({ error: status === 500 ? 'Internal server error' : 'Bad request' });
});

// WebSocket real-time delivery
const server = http.createServer(app);
// The relay WS only ever carries tiny control frames ('auth', 'typing');
// message bodies go over REST. Without an explicit cap, ws accepts frames up
// to 100 MiB, each of which is buffered and JSON.parse'd before any check.
const WS_MAX_PAYLOAD = 16 * 1024;
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: WS_MAX_PAYLOAD });
const wsClients = new Map();

// Rotating a token (verified reclaim in /api/register) must also cut off
// realtime sessions that authenticated with the old one — otherwise a socket
// opened by whoever held the old token keeps receiving pushes indefinitely
// (the heartbeat keeps it alive).
function revokeWsSessions(oldToken) {
    if (!oldToken) return;
    for (const ws of wss.clients) {
        if (ws.authToken === oldToken) ws.close(4001, 'Session revoked');
    }
}

wss.on('connection', (ws, req) => {
    const ip = clientIp(req);
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
                    ws.authToken = msg.token;
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
            const u = safeGet(db.users, userId);
            if (u) {
                u.lastSeen = new Date().toISOString();
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
