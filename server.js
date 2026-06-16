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
app.post('/api/register', (req, res) => {
    const { name, email, publicKey, canvasUserId, canvasUrl } = req.body;
    if (!name || !publicKey) return res.status(400).json({ error: 'name and publicKey required' });

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
    const q = (req.query.q || '').toLowerCase().trim();
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
app.post('/api/messages', auth, (req, res) => {
    const { recipientId, encryptedBody, iv } = req.body;
    if (!recipientId || !encryptedBody || !iv) return res.status(400).json({ error: 'Missing fields' });
    if (!db.users[recipientId]) return res.status(404).json({ error: 'Recipient not found' });

    const threadId = [req.user.id, recipientId].sort().join('_');
    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    db.messages.push({ id, threadId, senderId: req.user.id, recipientId, encryptedBody, iv, sentAt });
    if (db.messages.length > 50000) db.messages = db.messages.slice(-50000);
    saveDb();

    const ws = wsClients.get(recipientId);
    if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'message',
            message: { id, threadId, senderId: req.user.id, recipientId, encryptedBody, iv, sentAt } }));
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

// Create invite token
app.post('/api/invites', auth, (req, res) => {
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
            }
        } catch {}
    });
    ws.on('close', () => { if (userId) wsClients.delete(userId); });
    ws.on('error', () => {});
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[CM-Relay] listening on :${PORT}`));
