'use strict';
// Firebase-Auth-backed accounts for cm-relay.
//
// Until now a relay identity was "whoever can present a live Canvas token for
// this canvasUserId", so every new device had to walk the Canvas token-creation
// flow again. An account adds a second, portable way to prove who you are:
// sign in with Firebase Auth (email + password) on the client, send the
// resulting ID token here, and get back everything that device needs — relay
// authToken, escrowed E2E keypair + contacts, and the Canvas URL/token.
//
// Trust model: this server is the only thing that talks to Firestore (admin
// SDK, no client rules). The Canvas token is sealed with AES-256-GCM under
// ACCOUNT_ENC_KEY before it is written, so a Firestore-only leak or console
// view does not expose it. The relay itself can still decrypt it (that is the
// point — it hands it to a new device), so this is server-recoverable
// escrow, not zero-knowledge.
//
// Dependencies are injected so the routes can be tested without Firebase.

const crypto = require('crypto');

const MAX_FIELD = 2048;

function makeSealer(keyB64) {
    let key = null;
    if (keyB64) {
        const buf = Buffer.from(String(keyB64), 'base64');
        if (buf.length === 32) key = buf;
    }
    return {
        enabled: !!key,
        seal(plain) {
            const iv = crypto.randomBytes(12);
            const c = crypto.createCipheriv('aes-256-gcm', key, iv);
            const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
            return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
        },
        open(sealed) {
            const raw = Buffer.from(String(sealed), 'base64');
            if (raw.length < 29) throw new Error('sealed value too short');
            const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
            d.setAuthTag(raw.subarray(12, 28));
            return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
        },
    };
}

function registerAccountRoutes(app, deps) {
    const {
        auth, rateLimit, db, saveDb, usersByFirebaseUid,
        verifyIdToken, fsdb, readKeyEscrow, verifyCanvasIdentity, encKey,
    } = deps;
    const sealer = makeSealer(encKey);

    // Accounts need Firestore (to hold the sealed Canvas token) and a sealing
    // key. Without either, say so explicitly rather than half-working.
    function ready(req, res, next) {
        if (!fsdb || !sealer.enabled) return res.status(503).json({ error: 'Accounts are not configured on this relay' });
        next();
    }

    // The client sends its Firebase ID token in X-Firebase-Token (Authorization
    // is already used for the relay bearer on routes that need both).
    async function fbAuth(req, res, next) {
        const idToken = String(req.headers['x-firebase-token'] || '');
        if (!idToken) return res.status(401).json({ error: 'Missing Firebase token' });
        try {
            const decoded = await verifyIdToken(idToken);
            if (!decoded || !decoded.uid) throw new Error('no uid');
            req.fb = { uid: String(decoded.uid), email: decoded.email || null };
            next();
        } catch {
            return res.status(401).json({ error: 'Invalid or expired Firebase token' });
        }
    }

    const str = v => (typeof v === 'string' && v.length > 0 && v.length <= MAX_FIELD) ? v : null;

    // Attach (or refresh) the Canvas token for the signed-in account. Called
    // from a device that is already registered with the relay.
    app.post('/api/account/link', rateLimit('account'), ready, auth, fbAuth, async (req, res) => {
        const canvasUrl = str(req.body?.canvasUrl);
        const canvasUserId = str(String(req.body?.canvasUserId ?? ''));
        const canvasToken = str(req.body?.canvasToken);
        if (!canvasUrl || !canvasUserId || !canvasToken) return res.status(400).json({ error: 'canvasUrl, canvasUserId and canvasToken required' });

        const user = req.user;
        const { uid } = req.fb;
        // The Canvas identity being escrowed must be the one this relay user
        // was registered with — otherwise any account could be pointed at
        // someone else's relay identity.
        if (String(user.canvasUserId) !== canvasUserId || user.canvasUrl !== canvasUrl) {
            return res.status(403).json({ error: 'Canvas identity does not match this relay account' });
        }
        const holder = usersByFirebaseUid.get(uid);
        if (holder && holder.id !== user.id) return res.status(409).json({ error: 'This sign-in is already linked to a different relay account' });
        if (user.firebaseUid && user.firebaseUid !== uid) return res.status(409).json({ error: 'This relay account is already linked to a different sign-in' });
        if (!(await verifyCanvasIdentity(canvasUrl, canvasUserId, canvasToken))) {
            return res.status(401).json({ error: 'Could not verify Canvas identity' });
        }

        try {
            await fsdb.collection('accounts').doc(uid).set({
                relayUserId: user.id, canvasUrl, canvasUserId,
                canvasTokenSealed: sealer.seal(canvasToken),
                updatedAt: new Date().toISOString(),
            });
        } catch (e) {
            console.error('[CM-Relay] account write failed:', e.message);
            return res.status(503).json({ error: 'Could not save account' });
        }
        if (user.firebaseUid !== uid) {
            user.firebaseUid = uid;
            usersByFirebaseUid.set(uid, user);
            saveDb();
        }
        res.json({ ok: true });
    });

    // New device: trade a Firebase sign-in for everything needed to resume.
    app.post('/api/account/login', rateLimit('account'), ready, fbAuth, async (req, res) => {
        const user = usersByFirebaseUid.get(req.fb.uid);
        if (!user) return res.status(404).json({ error: 'no_account' });

        let canvas = null;
        try {
            const snap = await fsdb.collection('accounts').doc(req.fb.uid).get();
            if (snap.exists) {
                const a = snap.data();
                canvas = { url: a.canvasUrl, userId: a.canvasUserId, token: sealer.open(a.canvasTokenSealed) };
            }
        } catch (e) {
            console.error('[CM-Relay] account read failed:', e.message);
            return res.status(503).json({ error: 'Could not load account' });
        }

        let keypair, contacts;
        const escrow = await readKeyEscrow(user.id);
        if (escrow?.publicKeyJwk && escrow?.privateKeyJwk) {
            try {
                keypair = { publicKeyJwk: JSON.parse(escrow.publicKeyJwk), privateKeyJwk: JSON.parse(escrow.privateKeyJwk) };
                if (escrow.contacts) contacts = JSON.parse(escrow.contacts);
            } catch { /* corrupt escrow: return without it rather than failing login */ }
        }
        // Same authToken is returned (not rotated): other signed-in devices
        // keep working, and the caller has just proven identity via Firebase.
        res.json({ id: user.id, authToken: user.authToken, name: user.name, email: user.email, keypair, contacts, canvas });
    });

    // Remove the cloud copy: unlink the sign-in and delete the sealed Canvas
    // token. The relay account, messages and key escrow are left alone.
    app.post('/api/account/unlink', rateLimit('account'), ready, fbAuth, async (req, res) => {
        const user = usersByFirebaseUid.get(req.fb.uid);
        try { await fsdb.collection('accounts').doc(req.fb.uid).delete(); }
        catch (e) {
            console.error('[CM-Relay] account delete failed:', e.message);
            return res.status(503).json({ error: 'Could not remove account data' });
        }
        if (user) {
            delete user.firebaseUid;
            usersByFirebaseUid.delete(req.fb.uid);
            saveDb();
        }
        res.json({ ok: true });
    });
}

module.exports = { registerAccountRoutes, makeSealer };
