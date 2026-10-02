'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const { registerAccountRoutes, makeSealer } = require('../account');

const KEY = crypto.randomBytes(32).toString('base64');

// Minimal in-memory stand-in for the slice of Firestore the routes use.
function fakeFirestore() {
    const docs = new Map();
    return {
        docs,
        collection: name => ({
            doc: id => ({
                set: async d => { docs.set(`${name}/${id}`, d); },
                get: async () => ({ exists: docs.has(`${name}/${id}`), data: () => docs.get(`${name}/${id}`) }),
                delete: async () => { docs.delete(`${name}/${id}`); },
            }),
        }),
    };
}

async function setup({ encKey = KEY, canvasOk = true, withFs = true } = {}) {
    const fs = fakeFirestore();
    const db = { users: {} };
    const alice = { id: 'u-alice', name: 'Alice', email: 'a@x.edu', authToken: 'relay-alice', canvasUserId: '42', canvasUrl: 'https://school.instructure.com' };
    const bob = { id: 'u-bob', name: 'Bob', email: null, authToken: 'relay-bob', canvasUserId: '43', canvasUrl: 'https://school.instructure.com' };
    db.users[alice.id] = alice; db.users[bob.id] = bob;
    const byToken = new Map([[alice.authToken, alice], [bob.authToken, bob]]);
    const usersByFirebaseUid = new Map();
    let saves = 0;
    const app = express();
    app.use(express.json());
    registerAccountRoutes(app, {
        auth: (req, res, next) => {
            const u = byToken.get((req.headers.authorization || '').replace('Bearer ', ''));
            if (!u) return res.status(401).json({ error: 'Unauthorized' });
            req.user = u; next();
        },
        rateLimit: () => (req, res, next) => next(),
        db, saveDb: () => { saves++; }, usersByFirebaseUid,
        fsdb: withFs ? fs : null,
        readKeyEscrow: async id => id === 'u-alice'
            ? { publicKeyJwk: '{"k":"pub"}', privateKeyJwk: '{"k":"priv"}', contacts: '[{"id":"c1"}]' } : null,
        verifyCanvasIdentity: async () => canvasOk,
        encKey,
        verifyIdToken: async t => {
            if (t === 'fb-alice') return { uid: 'fb-A', email: 'a@x.edu' };
            if (t === 'fb-other') return { uid: 'fb-B', email: 'b@x.edu' };
            throw new Error('bad token');
        },
    });
    const server = await new Promise(r => { const s = app.listen(0, () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = (path, { relay, fb, body } = {}) => fetch(base + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(relay ? { Authorization: `Bearer ${relay}` } : {}), ...(fb ? { 'X-Firebase-Token': fb } : {}) },
        body: JSON.stringify(body || {}),
    }).then(async r => ({ status: r.status, json: await r.json() }));
    return { call, fs, db, alice, bob, usersByFirebaseUid, saves: () => saves, close: () => server.close() };
}

const LINK = { canvasUrl: 'https://school.instructure.com', canvasUserId: '42', canvasToken: 'canvas-secret-token' };

test('sealer round-trips and rejects tampering', () => {
    const s = makeSealer(KEY);
    const sealed = s.seal('hello');
    assert.notEqual(sealed, 'hello');
    assert.equal(s.open(sealed), 'hello');
    const raw = Buffer.from(sealed, 'base64'); raw[raw.length - 1] ^= 1;
    assert.throws(() => s.open(raw.toString('base64')));
    assert.equal(makeSealer('short').enabled, false);
    assert.equal(makeSealer(undefined).enabled, false);
});

test('link stores a sealed token (never plaintext) and indexes the uid', async t => {
    const c = await setup(); t.after(c.close);
    const r = await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK });
    assert.equal(r.status, 200);
    const doc = c.fs.docs.get('accounts/fb-A');
    assert.equal(doc.relayUserId, 'u-alice');
    assert.ok(!JSON.stringify(doc).includes('canvas-secret-token'), 'token must be sealed at rest');
    assert.equal(c.usersByFirebaseUid.get('fb-A'), c.alice);
    assert.equal(c.alice.firebaseUid, 'fb-A');
    assert.ok(c.saves() >= 1);
});

test('login returns relay token, keypair, contacts and the decrypted Canvas token', async t => {
    const c = await setup(); t.after(c.close);
    await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK });
    const r = await c.call('/api/account/login', { fb: 'fb-alice' });
    assert.equal(r.status, 200);
    assert.equal(r.json.id, 'u-alice');
    assert.equal(r.json.authToken, 'relay-alice');          // not rotated
    assert.deepEqual(r.json.keypair, { publicKeyJwk: { k: 'pub' }, privateKeyJwk: { k: 'priv' } });
    assert.deepEqual(r.json.contacts, [{ id: 'c1' }]);
    assert.deepEqual(r.json.canvas, { url: LINK.canvasUrl, userId: '42', token: 'canvas-secret-token' });
});

test('login for an unlinked sign-in is a clean 404', async t => {
    const c = await setup(); t.after(c.close);
    const r = await c.call('/api/account/login', { fb: 'fb-other' });
    assert.equal(r.status, 404);
    assert.equal(r.json.error, 'no_account');
});

test('bad / missing Firebase token is 401', async t => {
    const c = await setup(); t.after(c.close);
    assert.equal((await c.call('/api/account/login', { fb: 'nope' })).status, 401);
    assert.equal((await c.call('/api/account/login')).status, 401);
    assert.equal((await c.call('/api/account/link', { relay: 'relay-alice', body: LINK })).status, 401);
    assert.equal((await c.call('/api/account/link', { fb: 'fb-alice', body: LINK })).status, 401); // no relay auth
});

test('link refuses a Canvas identity that is not this relay account\'s', async t => {
    const c = await setup(); t.after(c.close);
    const r = await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: { ...LINK, canvasUserId: '99' } });
    assert.equal(r.status, 403);
    assert.equal(c.fs.docs.size, 0);
});

test('link refuses when Canvas does not confirm the token', async t => {
    const c = await setup({ canvasOk: false }); t.after(c.close);
    const r = await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK });
    assert.equal(r.status, 401);
    assert.equal(c.fs.docs.size, 0);
    assert.equal(c.alice.firebaseUid, undefined);
});

test('one sign-in cannot take over two relay accounts, nor one relay account two sign-ins', async t => {
    const c = await setup(); t.after(c.close);
    assert.equal((await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK })).status, 200);
    // fb-A already belongs to alice; bob tries to link it
    const bobLink = { canvasUrl: LINK.canvasUrl, canvasUserId: '43', canvasToken: 't' };
    assert.equal((await c.call('/api/account/link', { relay: 'relay-bob', fb: 'fb-alice', body: bobLink })).status, 409);
    // alice already has fb-A; a different sign-in tries to claim her
    assert.equal((await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-other', body: LINK })).status, 409);
});

test('re-linking the same account refreshes the token (rotation)', async t => {
    const c = await setup(); t.after(c.close);
    await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK });
    await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: { ...LINK, canvasToken: 'rotated' } });
    const r = await c.call('/api/account/login', { fb: 'fb-alice' });
    assert.equal(r.json.canvas.token, 'rotated');
});

test('unlink deletes the sealed token and the link, keeps the relay account', async t => {
    const c = await setup(); t.after(c.close);
    await c.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK });
    assert.equal((await c.call('/api/account/unlink', { fb: 'fb-alice' })).status, 200);
    assert.equal(c.fs.docs.size, 0);
    assert.equal(c.alice.firebaseUid, undefined);
    assert.equal(c.db.users['u-alice'].name, 'Alice');
    assert.equal((await c.call('/api/account/login', { fb: 'fb-alice' })).status, 404);
});

test('routes answer 503 when Firestore or the sealing key is missing', async t => {
    const noKey = await setup({ encKey: null }); t.after(noKey.close);
    assert.equal((await noKey.call('/api/account/login', { fb: 'fb-alice' })).status, 503);
    const noFs = await setup({ withFs: false }); t.after(noFs.close);
    assert.equal((await noFs.call('/api/account/link', { relay: 'relay-alice', fb: 'fb-alice', body: LINK })).status, 503);
});
