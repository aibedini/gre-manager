'use strict';
// routes.js — JSON API. Everything here except /api/login and /api/setup
// is mounted behind requireAuth (session + CSRF) in index.js.

const express = require('express');
const crypto = require('crypto');
const auth = require('./auth');
const discovery = require('./discovery');
const actions = require('./actions');
const ssh = require('./ssh');
const totp = require('./totp');
const provision = require('./provision');
const { encrypt, decrypt } = require('./crypto');
const { audit } = require('./db');

const SECURE = process.env.HUB_SECURE === '1';

// One-time, short-lived tickets for the WebSocket terminal so that no
// long-lived credential appears in URLs or logs.
const tickets = new Map(); // ticket -> { serverId, expiresAt }
const TICKET_TTL_MS = 30000;

function issueTicket(serverId) {
  const ticket = crypto.randomBytes(24).toString('hex');
  tickets.set(ticket, { serverId, expiresAt: Date.now() + TICKET_TTL_MS });
  return ticket;
}

// Single-use: a ticket is deleted as soon as it is consumed.
function consumeTicket(ticket) {
  const rec = tickets.get(ticket);
  tickets.delete(ticket);
  if (!rec || rec.expiresAt < Date.now()) return null;
  return rec.serverId;
}

// ssh options factory shared by HTTP routes and the WS terminal: host-key
// TOFU pinning (auto-pins on first connect, audits it) + fallback password.
function makeSshOpts(db, cryptKey) {
  return (server) => ({
    hostKey: {
      expected: server.host_key_fp || null,
      onNew: (fp) => {
        try {
          db.prepare('UPDATE servers SET host_key_fp = ? WHERE id = ?').run(fp, server.id);
          server.host_key_fp = fp;
          audit(db, {
            kind: 'auth',
            serverId: server.id,
            serverName: server.name,
            action: 'host_key_pin',
            params: { fingerprint: fp },
            rc: 0,
            output: 'pinned on first connect (TOFU)',
          });
        } catch { /* server row deleted mid-connect */ }
      },
    },
    fallbackPassword: server.password_enc ? decrypt(cryptKey, server.password_enc) : null,
  });
}

function createRouter(db, cryptKey, dataDir) {
  const router = express.Router();

  // Express 4 does not catch async rejections; wrap async handlers.
  const wrap = (fn) => (req, res) =>
    Promise.resolve(fn(req, res)).catch((err) => res.status(500).json({ error: err.message }));

  // Audit must never crash the process: async provisioning/discovery can
  // outlive a deleted server row, making server_id a dangling FK.
  const auditEvent = (serverId, serverName, action, params, rc = 0, output = '', kind = 'auth') => {
    try {
      audit(db, { kind, serverId, serverName, action, params, rc, output });
    } catch { /* referenced server already deleted */ }
  };

  const getSetting = (key) => {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    return row ? row.value : null;
  };
  const setSetting = (key, value) =>
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
  const delSetting = (key) => db.prepare('DELETE FROM settings WHERE key = ?').run(key);

  const totpEnabled = () => getSetting('totp_enabled') === '1';

  // Consume a one-time recovery code; returns true when valid.
  const consumeRecoveryCode = (code) => {
    const hash = totp.hashRecoveryCode(code);
    const row = db.prepare('SELECT hash FROM recovery_codes WHERE hash = ? AND used_at IS NULL').get(hash);
    if (!row) return false;
    db.prepare('UPDATE recovery_codes SET used_at = ? WHERE hash = ?').run(Date.now(), hash);
    return true;
  };

  // --- server helpers ---------------------------------------------------
  const getServer = (id) => db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
  const getSecret = (server) => (server.secret_enc ? decrypt(cryptKey, server.secret_enc) : '');

  // ssh options: host-key TOFU pinning + optional fallback password.
  const sshOptsFor = makeSshOpts(db, cryptKey);

  const getSnapshot = (id) => {
    const row = db.prepare('SELECT json, taken_at FROM snapshots WHERE server_id = ?').get(id);
    return row ? JSON.parse(row.json) : null;
  };
  const saveSnapshot = (id, snapshot) => {
    db.prepare(
      'INSERT INTO snapshots (server_id, json, taken_at) VALUES (?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET json = excluded.json, taken_at = excluded.taken_at'
    ).run(id, JSON.stringify(snapshot), Date.now());
  };

  const publicServer = (row) => {
    const { secret_enc, password_enc, ...rest } = row;
    return {
      ...rest,
      has_secret: !!secret_enc,
      has_fallback_password: !!password_enc,
      host_key_pinned: !!row.host_key_fp,
    };
  };

  // Uniform response when a server presents a different host key.
  const hostKeyMismatchResponse = (res, server, presentedFp) =>
    res.status(409).json({
      error: `host key mismatch for ${server.name} — the server presented a different key than pinned. If this is expected (reinstall, new VM), accept the new key explicitly.`,
      hostkey_mismatch: true,
      presented_fp: presentedFp,
      expected_fp: server.host_key_fp,
    });

  // --- Auth (mounted without requireAuth) -------------------------------
  router.get('/setup', (req, res) => {
    res.json({ needs_setup: !auth.hasPassword(db) });
  });

  router.post('/setup', (req, res) => {
    if (auth.hasPassword(db)) return res.status(409).json({ error: 'password already set' });
    const { password } = req.body || {};
    if (typeof password !== 'string' || password.length < auth.MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `password must be at least ${auth.MIN_PASSWORD_LENGTH} characters` });
    }
    auth.setPassword(db, password);
    const session = auth.createSession(db);
    res.setHeader('Set-Cookie', auth.sessionCookie(session.token, session.expiresAt, SECURE));
    auditEvent(null, 'hub', 'setup', null, 0, 'hub password created');
    res.json({ ok: true, csrf: session.csrf });
  });

  router.post('/login', (req, res) => {
    const ip = req.ip || 'unknown';
    if (auth.isLocked(ip)) {
      return res.status(429).json({ error: 'too many failed attempts, try again later' });
    }
    const { password, code } = req.body || {};
    if (!auth.checkPassword(db, password)) {
      const locked = auth.recordFail(ip);
      auditEvent(null, 'hub', 'login_fail', { ip }, 1, 'wrong password');
      if (locked) auditEvent(null, 'hub', 'lockout', { ip }, 1, 'locked after 5 failed logins');
      return res.status(401).json({ error: 'wrong password' });
    }
    if (totpEnabled()) {
      if (!code) {
        return res.status(401).json({ error: '2fa_required', requires_2fa: true });
      }
      const secret = decrypt(cryptKey, getSetting('totp_secret_enc'));
      if (!totp.verifyTotp(totp.base32Decode(secret), code)) {
        if (!consumeRecoveryCode(code)) {
          auditEvent(null, 'hub', 'login_fail', { ip }, 1, 'invalid 2fa code');
          return res.status(401).json({ error: 'invalid two-factor code', requires_2fa: true });
        }
        auditEvent(null, 'hub', 'recovery_code_used', { ip }, 0, 'one-time recovery code consumed');
      }
    }
    auth.clearFails(ip);
    const session = auth.createSession(db);
    res.setHeader('Set-Cookie', auth.sessionCookie(session.token, session.expiresAt, SECURE));
    auditEvent(null, 'hub', 'login_ok', { ip }, 0, '');
    res.json({ ok: true, csrf: session.csrf });
  });

  // --- Authenticated ----------------------------------------------------
  const authed = express.Router();
  authed.use(auth.requireAuth(db));

  authed.post('/logout', (req, res) => {
    auth.destroySession(db, req.sessionToken);
    res.setHeader('Set-Cookie', auth.clearCookie(SECURE));
    res.json({ ok: true });
  });

  authed.post('/logout-all', (req, res) => {
    auth.destroyOtherSessions(db, req.sessionToken);
    auditEvent(null, 'hub', 'logout_all', null, 0, 'all other sessions invalidated');
    res.json({ ok: true });
  });

  authed.get('/me', (req, res) => {
    res.json({ ok: true, user: 'admin', csrf: req.session.csrf, totp_enabled: totpEnabled() });
  });

  authed.post('/password', (req, res) => {
    const { current, next } = req.body || {};
    if (!auth.checkPassword(db, current)) {
      return res.status(400).json({ error: 'current password is wrong' });
    }
    if (typeof next !== 'string' || next.length < auth.MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `new password must be at least ${auth.MIN_PASSWORD_LENGTH} characters` });
    }
    auth.setPassword(db, next);
    auth.destroyOtherSessions(db, req.sessionToken);
    auditEvent(null, 'hub', 'password_change', null, 0, 'hub password changed, other sessions invalidated');
    res.json({ ok: true });
  });

  // --- TOTP 2FA -----------------------------------------------------------
  authed.post('/2fa/setup', (req, res) => {
    if (totpEnabled()) return res.status(409).json({ error: 'two-factor authentication is already enabled' });
    const secret = totp.generateSecret();
    setSetting('totp_pending_enc', encrypt(cryptKey, secret));
    res.json({ secret, uri: totp.otpauthUri(secret) });
  });

  authed.post('/2fa/enable', (req, res) => {
    if (totpEnabled()) return res.status(409).json({ error: 'two-factor authentication is already enabled' });
    const pending = getSetting('totp_pending_enc');
    if (!pending) return res.status(400).json({ error: 'call /api/2fa/setup first' });
    const secret = decrypt(cryptKey, pending);
    if (!totp.verifyTotp(totp.base32Decode(secret), (req.body || {}).code)) {
      return res.status(400).json({ error: 'invalid code — check your authenticator and try again' });
    }
    setSetting('totp_secret_enc', pending);
    setSetting('totp_enabled', '1');
    delSetting('totp_pending_enc');
    const codes = totp.generateRecoveryCodes(10);
    const insert = db.prepare('INSERT INTO recovery_codes (hash, used_at) VALUES (?, NULL)');
    for (const c of codes) insert.run(totp.hashRecoveryCode(c));
    auditEvent(null, 'hub', '2fa_on', null, 0, 'TOTP enabled, 10 recovery codes issued');
    res.json({ ok: true, recovery_codes: codes });
  });

  authed.post('/2fa/disable', (req, res) => {
    if (!totpEnabled()) return res.status(400).json({ error: 'two-factor authentication is not enabled' });
    const { password, code } = req.body || {};
    if (!auth.checkPassword(db, password)) return res.status(400).json({ error: 'wrong password' });
    const secret = decrypt(cryptKey, getSetting('totp_secret_enc'));
    if (!totp.verifyTotp(totp.base32Decode(secret), code) && !consumeRecoveryCode(code)) {
      return res.status(400).json({ error: 'invalid two-factor code' });
    }
    delSetting('totp_secret_enc');
    delSetting('totp_enabled');
    db.prepare('DELETE FROM recovery_codes').run();
    auditEvent(null, 'hub', '2fa_off', null, 0, 'TOTP disabled');
    res.json({ ok: true });
  });

  // --- Servers CRUD -----------------------------------------------------
  authed.get('/servers', (req, res) => {
    const rows = db.prepare('SELECT * FROM servers ORDER BY name').all();
    res.json(rows.map((r) => ({ ...publicServer(r), snapshot: getSnapshot(r.id) })));
  });

  authed.post('/servers', (req, res) => {
    const { name, host, ssh_port = 22, username = 'root', password, keep_fallback } = req.body || {};
    if (!name || !host || !password) {
      return res.status(400).json({ error: 'name, host and password are required (the password is used once to install a dedicated SSH key)' });
    }
    let server;
    try {
      const info = db
        .prepare('INSERT INTO servers (name, host, ssh_port, username, auth_type, secret_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(String(name).trim(), String(host).trim(), Number(ssh_port) || 22, String(username || 'root').trim(), 'password', encrypt(cryptKey, password), Date.now());
      server = getServer(info.lastInsertRowid);
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: 'a server with this name already exists' });
      throw err;
    }
    res.status(201).json(publicServer(server));

    // Auto-provision the SSH key, then run discovery (best effort, async).
    (async () => {
      try {
        const result = await provision.provision(db, dataDir, cryptKey, server, sshOptsFor, auditEvent);
        if (result.hostkey_mismatch) return; // stays on password auth until the key is accepted
        provision.handlePasswordAfterProvision(db, cryptKey, server.id, password, !!keep_fallback);
      } catch (err) {
        auditEvent(server.id, server.name, 'key_provision', null, 1, err.message);
      }
      try {
        const fresh = getServer(server.id);
        const snap = await discovery.discover(fresh, getSecret(fresh), sshOptsFor(fresh));
        if (!snap.hostkey_mismatch) saveSnapshot(server.id, snap);
      } catch { /* discovery is best effort here */ }
    })();
  });

  authed.get('/servers/:id', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    res.json({ ...publicServer(server), snapshot: getSnapshot(server.id) });
  });

  authed.put('/servers/:id', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const { name, host, ssh_port, username, secret } = req.body || {};
    const next = {
      name: name !== undefined ? String(name).trim() : server.name,
      host: host !== undefined ? String(host).trim() : server.host,
      ssh_port: ssh_port !== undefined ? Number(ssh_port) || 22 : server.ssh_port,
      username: username !== undefined ? String(username).trim() : server.username,
    };
    try {
      db.prepare('UPDATE servers SET name = ?, host = ?, ssh_port = ?, username = ? WHERE id = ?')
        .run(next.name, next.host, next.ssh_port, next.username, server.id);
      if (secret) {
        // On key-auth servers a provided secret becomes the fallback password;
        // on password servers it is the primary credential.
        if (server.key_installed) {
          db.prepare('UPDATE servers SET password_enc = ? WHERE id = ?').run(encrypt(cryptKey, secret), server.id);
        } else {
          db.prepare("UPDATE servers SET auth_type = 'password', secret_enc = ? WHERE id = ?").run(encrypt(cryptKey, secret), server.id);
        }
      }
      res.json(publicServer(getServer(server.id)));
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: 'a server with this name already exists' });
      throw err;
    }
  });

  authed.delete('/servers/:id', (req, res) => {
    const info = db.prepare('DELETE FROM servers WHERE id = ?').run(req.params.id);
    if (!info.changes) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  });

  // --- SSH key provisioning ----------------------------------------------
  authed.post('/servers/:id/key/reinstall', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    try {
      const result = await provision.provision(db, dataDir, cryptKey, server, sshOptsFor, auditEvent);
      if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
      res.json(result);
    } catch (err) {
      auditEvent(server.id, server.name, 'key_reinstall', null, 1, err.message);
      res.status(400).json({ error: err.message });
    }
  }));

  authed.post('/servers/:id/key/delete', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await provision.removeKey(db, dataDir, cryptKey, server, sshOptsFor, auditEvent);
    res.json(result);
  }));

  // --- Host key pinning ----------------------------------------------------
  authed.post('/servers/:id/host-key/accept', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const { fingerprint } = req.body || {};
    if (typeof fingerprint !== 'string' || !fingerprint.startsWith('SHA256:')) {
      return res.status(400).json({ error: 'fingerprint (SHA256:…) is required' });
    }
    db.prepare('UPDATE servers SET host_key_fp = ? WHERE id = ?').run(fingerprint, server.id);
    auditEvent(server.id, server.name, 'host_key_accept', { old: server.host_key_fp, new: fingerprint }, 0, 'new host key accepted by user');
    res.json({ ok: true });
  });

  // --- Connectivity / discovery ------------------------------------------
  authed.post('/servers/:id/test', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await ssh.exec(server, getSecret(server), 'echo hub-ok', { timeoutMs: 20000, ...sshOptsFor(server) });
    if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
    res.json({ ok: result.rc === 0 && result.stdout.includes('hub-ok'), rc: result.rc, stderr: result.stderr });
  }));

  authed.post('/servers/:id/discover', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const snapshot = await discovery.discover(server, getSecret(server), sshOptsFor(server));
    if (snapshot.hostkey_mismatch) return hostKeyMismatchResponse(res, server, snapshot.presented_fp);
    saveSnapshot(server.id, snapshot);
    res.json(snapshot);
  }));

  // --- Actions -------------------------------------------------------------
  authed.get('/actions', (req, res) => {
    const kind = ['action', 'auth'].includes(req.query.kind) ? req.query.kind : null;
    const rows = kind
      ? db.prepare('SELECT * FROM action_log WHERE kind = ? ORDER BY created_at DESC LIMIT 100').all(kind)
      : db.prepare('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 100').all();
    res.json(rows);
  });

  authed.post('/servers/:id/action', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const { action, params } = req.body || {};
    if (!actions.ACTION_NAMES.includes(action)) {
      return res.status(400).json({ error: `unknown action (allowed: ${actions.ACTION_NAMES.join(', ')})` });
    }
    try {
      const result = await actions.runAction(db, server, getSecret(server), action, params || {}, sshOptsFor(server));
      if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
      // Refresh the snapshot after state-changing actions (best effort).
      if (!['doctor'].includes(action)) {
        discovery.discover(server, getSecret(server), sshOptsFor(server))
          .then((snap) => { if (!snap.hostkey_mismatch) saveSnapshot(server.id, snap); })
          .catch(() => {});
      }
      // gre prints "Unknown argument" when the CLI is older than the action
      // requires (e.g. foreign-setup needs >= 2.6.0) — surface a clear hint.
      const combined = `${result.stdout || ''}\n${result.stderr || ''}`;
      const hint = result.rc !== 0 && /Unknown argument/i.test(combined)
        ? 'remote gre is too old for this action; run the \'update\' action first'
        : undefined;
      res.json({ ok: result.rc === 0, rc: result.rc, stdout: result.stdout, stderr: result.stderr, command: result.command, ...(hint ? { hint } : {}) });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }));

  // --- Peer suggestions (gre >= 2.7.0) --------------------------------------
  authed.post('/servers/:id/suggest-peer', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await ssh.exec(server, getSecret(server), 'gre iran peer suggest --json', { timeoutMs: 30000, ...sshOptsFor(server) });
    if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
    const combined = `${result.stdout || ''}\n${result.stderr || ''}`;
    if (result.rc !== 0) {
      const tooOld = /Unknown argument/i.test(combined);
      return res.status(400).json({
        error: tooOld
          ? 'remote gre is too old for this action; run the \'update\' action first'
          : (result.stderr || `suggest failed (rc=${result.rc})`).trim().slice(0, 500),
      });
    }
    try {
      res.json(JSON.parse(result.stdout.trim()));
    } catch {
      res.status(400).json({ error: 'could not parse suggest output as JSON', raw: result.stdout.slice(0, 500) });
    }
  }));

  // --- Terminal ticket -----------------------------------------------------
  authed.post('/servers/:id/terminal-ticket', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    res.json({ ticket: issueTicket(server.id) });
  });

  router.use(authed);
  return router;
}

module.exports = { createRouter, consumeTicket, makeSshOpts };
