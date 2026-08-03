'use strict';
// routes.js — JSON API. Everything here except /api/login and /api/setup
// is mounted behind requireAuth in index.js.

const express = require('express');
const crypto = require('crypto');
const auth = require('./auth');
const discovery = require('./discovery');
const actions = require('./actions');
const ssh = require('./ssh');

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

function publicServer(row) {
  const { secret_enc, ...rest } = row;
  return { ...rest, has_secret: !!secret_enc };
}

function createRouter(db, cryptKey) {
  const { encrypt, decrypt } = require('./crypto');
  const router = express.Router();

  // Express 4 does not catch async rejections; wrap async handlers.
  const wrap = (fn) => (req, res) =>
    Promise.resolve(fn(req, res)).catch((err) => res.status(500).json({ error: err.message }));

  const getServer = (id) => db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
  const getSecret = (server) => decrypt(cryptKey, server.secret_enc);
  const getSnapshot = (id) => {
    const row = db.prepare('SELECT json, taken_at FROM snapshots WHERE server_id = ?').get(id);
    return row ? JSON.parse(row.json) : null;
  };
  const saveSnapshot = (id, snapshot) => {
    db.prepare(
      'INSERT INTO snapshots (server_id, json, taken_at) VALUES (?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET json = excluded.json, taken_at = excluded.taken_at'
    ).run(id, JSON.stringify(snapshot), Date.now());
  };

  // --- Auth (mounted without requireAuth) -------------------------------
  router.get('/setup', (req, res) => {
    res.json({ needs_setup: !auth.hasPassword(db) });
  });

  router.post('/setup', (req, res) => {
    if (auth.hasPassword(db)) return res.status(409).json({ error: 'password already set' });
    const { password } = req.body || {};
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'password must be at least 8 characters' });
    }
    auth.setPassword(db, password);
    const session = auth.createSession(db);
    res.setHeader('Set-Cookie', auth.sessionCookie(session.token, session.expiresAt));
    res.json({ ok: true });
  });

  router.post('/login', (req, res) => {
    const ip = req.ip || 'unknown';
    if (auth.isLocked(ip)) {
      return res.status(429).json({ error: 'too many failed attempts, try again later' });
    }
    const { password } = req.body || {};
    if (!auth.checkPassword(db, password)) {
      auth.recordFail(ip);
      return res.status(401).json({ error: 'wrong password' });
    }
    auth.clearFails(ip);
    const session = auth.createSession(db);
    res.setHeader('Set-Cookie', auth.sessionCookie(session.token, session.expiresAt));
    res.json({ ok: true });
  });

  // --- Authenticated ----------------------------------------------------
  const authed = express.Router();
  authed.use(auth.requireAuth(db));

  authed.post('/logout', (req, res) => {
    auth.destroySession(db, req.sessionToken);
    res.setHeader('Set-Cookie', auth.clearCookie());
    res.json({ ok: true });
  });

  authed.get('/me', (req, res) => res.json({ ok: true, user: 'admin' }));

  // --- Servers CRUD -----------------------------------------------------
  authed.get('/servers', (req, res) => {
    const rows = db.prepare('SELECT * FROM servers ORDER BY name').all();
    res.json(rows.map((r) => ({ ...publicServer(r), snapshot: getSnapshot(r.id) })));
  });

  authed.post('/servers', (req, res) => {
    const { name, host, ssh_port = 22, username = 'root', auth_type, secret } = req.body || {};
    if (!name || !host || !['password', 'key'].includes(auth_type) || !secret) {
      return res.status(400).json({ error: 'name, host, auth_type (password|key) and secret are required' });
    }
    try {
      const info = db
        .prepare('INSERT INTO servers (name, host, ssh_port, username, auth_type, secret_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(String(name).trim(), String(host).trim(), Number(ssh_port) || 22, String(username || 'root').trim(), auth_type, encrypt(cryptKey, secret), Date.now());
      const server = getServer(info.lastInsertRowid);
      res.status(201).json(publicServer(server));
      // Auto-discovery after add (best effort, does not block the response).
      discovery
        .discover(server, getSecret(server))
        .then((snap) => saveSnapshot(server.id, snap))
        .catch(() => {});
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: 'a server with this name already exists' });
      throw err;
    }
  });

  authed.get('/servers/:id', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    res.json({ ...publicServer(server), snapshot: getSnapshot(server.id) });
  });

  authed.put('/servers/:id', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const { name, host, ssh_port, username, auth_type, secret } = req.body || {};
    const next = {
      name: name !== undefined ? String(name).trim() : server.name,
      host: host !== undefined ? String(host).trim() : server.host,
      ssh_port: ssh_port !== undefined ? Number(ssh_port) || 22 : server.ssh_port,
      username: username !== undefined ? String(username).trim() : server.username,
      auth_type: auth_type !== undefined ? auth_type : server.auth_type,
      secret_enc: secret ? encrypt(cryptKey, secret) : server.secret_enc, // empty = keep existing
    };
    if (!['password', 'key'].includes(next.auth_type)) return res.status(400).json({ error: 'auth_type must be password or key' });
    try {
      db.prepare('UPDATE servers SET name = ?, host = ?, ssh_port = ?, username = ?, auth_type = ?, secret_enc = ? WHERE id = ?')
        .run(next.name, next.host, next.ssh_port, next.username, next.auth_type, next.secret_enc, server.id);
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

  // --- Connectivity / discovery ----------------------------------------
  authed.post('/servers/:id/test', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await ssh.exec(server, getSecret(server), 'echo hub-ok', { timeoutMs: 20000 });
    res.json({ ok: result.rc === 0 && result.stdout.includes('hub-ok'), rc: result.rc, stderr: result.stderr });
  }));

  authed.post('/servers/:id/discover', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const snapshot = await discovery.discover(server, getSecret(server));
    saveSnapshot(server.id, snapshot);
    res.json(snapshot);
  }));

  // --- Actions ----------------------------------------------------------
  authed.get('/actions', (req, res) => {
    const rows = db.prepare('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 100').all();
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
      const result = await actions.runAction(db, server, getSecret(server), action, params || {});
      // Refresh the snapshot after state-changing actions (best effort).
      if (!['doctor'].includes(action)) {
        discovery.discover(server, getSecret(server)).then((snap) => saveSnapshot(server.id, snap)).catch(() => {});
      }
      res.json({ ok: result.rc === 0, rc: result.rc, stdout: result.stdout, stderr: result.stderr, command: result.command });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }));

  // --- Terminal ticket --------------------------------------------------
  authed.post('/servers/:id/terminal-ticket', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    res.json({ ticket: issueTicket(server.id) });
  });

  router.use(authed);
  return router;
}

module.exports = { createRouter, consumeTicket };
