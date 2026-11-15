'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

function freePort() {
    return new Promise((resolve, reject) => {
        const s = net.createServer();
        s.listen(0, () => { const { port } = s.address(); s.close(() => resolve(port)); });
        s.on('error', reject);
    });
}

async function startRelay(extraEnv = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-relay-health-'));
    const port = await freePort();
    const env = { ...process.env, PORT: String(port), RELAY_DB_PATH: path.join(dir, 'relay.json'), ...extraEnv };
    delete env.FIREBASE_SERVICE_ACCOUNT;
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('relay did not start')), 10_000);
        child.stdout.on('data', d => { if (String(d).includes('listening')) { clearTimeout(t); resolve(); } });
        child.on('exit', code => { clearTimeout(t); reject(new Error(`relay exited ${code}`)); });
    });
    return {
        url: `http://127.0.0.1:${port}`,
        stop: () => new Promise(r => { child.once('exit', r); child.kill('SIGTERM'); }).then(() => fs.rmSync(dir, { recursive: true, force: true })),
    };
}

test('GET /health returns status, version and uptime without stats by default', async () => {
    const relay = await startRelay({ HEALTH_STATS: '' });
    try {
        const res = await fetch(`${relay.url}/health`);
        assert.equal(res.status, 200);
        assert.equal(res.headers.get('cache-control'), 'no-store');
        const body = await res.json();
        assert.equal(body.status, 'ok');
        assert.equal(body.version, require('../package.json').version);
        assert.ok(!Number.isNaN(Date.parse(body.startedAt)));
        assert.equal(typeof body.uptimeSec, 'number');
        assert.equal(body.stats, undefined);
    } finally { await relay.stop(); }
});

test('HEALTH_STATS=1 adds aggregate counts only', async () => {
    const relay = await startRelay({ HEALTH_STATS: '1' });
    try {
        const body = await (await fetch(`${relay.url}/health`)).json();
        assert.deepEqual(body.stats, { users: 0, messages: 0, onlineSockets: 0 });
    } finally { await relay.stop(); }
});
