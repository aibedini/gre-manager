'use strict';
// routes.js — JSON API. Everything here except /api/login and /api/setup
// is mounted behind requireAuth (session + CSRF) in index.js.

const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');
const auth = require('./auth');
const discovery = require('./discovery');
const { DiscoveryQueue } = require('./discovery-queue');
const actions = require('./actions');
const ssh = require('./ssh');
const totp = require('./totp');
const provision = require('./provision');
const connectivity = require('./connectivity');
const { encrypt, decrypt } = require('./crypto');
const { audit, schemaVersion } = require('./db');
const { XuiClient, normalizeBaseUrl } = require('./xui');
const { RouteOrchestrator } = require('./route-orchestrator');
const versionInfo = require('./version');

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

function createRouter(db, cryptKey, dataDir, transport = {}) {
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
  const routeOrchestrator = new RouteOrchestrator({
    db,
    cryptKey,
    sshOptsFor,
    // Test hooks: the end-to-end suite injects a scripted SSH transport and a
    // fake 3x-ui panel so the real HTTP surface can be exercised offline.
    ...(transport.fetchImpl ? { fetchImpl: transport.fetchImpl } : {}),
    ...(transport.sshExec ? { sshExec: transport.sshExec } : {}),
    ...(transport.runTimeoutMs ? { runTimeoutMs: transport.runTimeoutMs } : {}),
  });

  // Exposed for tests and for the startup sweep in index.js.
  router.orchestrator = routeOrchestrator;

  // QR payloads for provisioning runs started by this process. The share LINK
  // itself stays AES-encrypted in SQLite and only comes back through the
  // explicit reveal path; this map is in-memory only and dropped on restart.
  const routeResults = new Map();
  const rememberResult = (routeId, value) => {
    routeResults.set(Number(routeId), value);
    for (const key of routeResults.keys()) {
      if (routeResults.size <= 50) break;
      routeResults.delete(key);
    }
  };

  const getSnapshot = (id) => {
    const row = db.prepare('SELECT json, taken_at FROM snapshots WHERE server_id = ?').get(id);
    return row ? JSON.parse(row.json) : null;
  };
  // Only ever called with a SUCCESSFUL discovery. The authoritative snapshot is
  // the server's last known good topology; a failed probe must not reach here.
  const saveSnapshot = (id, snapshot) => {
    db.prepare(
      'INSERT INTO snapshots (server_id, json, taken_at) VALUES (?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET json = excluded.json, taken_at = excluded.taken_at'
    ).run(id, JSON.stringify(snapshot), Date.now());
  };

  // --- probe health -----------------------------------------------------
  // Availability lives beside the topology, never inside it.
  const saveProbeState = (id, probe, kind = 'full') => {
    db.prepare(`
      INSERT INTO server_probe_state (server_id, ok, checked_at, duration_ms, error_class, error_message, kind)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(server_id) DO UPDATE SET
        ok = excluded.ok, checked_at = excluded.checked_at, duration_ms = excluded.duration_ms,
        error_class = excluded.error_class, error_message = excluded.error_message, kind = excluded.kind
    `).run(
      id,
      probe.ok ? 1 : 0,
      probe.checkedAt || Date.now(),
      Number.isFinite(probe.durationMs) ? probe.durationMs : null,
      probe.ok ? null : (probe.errorClass || 'transport'),
      probe.ok ? null : (probe.detail || probe.reason || null),
      kind,
    );
  };

  const getProbeState = (id) => {
    const row = db.prepare('SELECT * FROM server_probe_state WHERE server_id = ?').get(id);
    if (!row) return null;
    return {
      ok: !!row.ok,
      checked_at: row.checked_at,
      duration_ms: row.duration_ms,
      error_class: row.error_class,
      error: row.error_message,
      reason: row.ok ? null : discovery.errorReason(row.error_class),
      kind: row.kind,
      stale_for_ms: Math.max(0, Date.now() - Number(row.checked_at || 0)),
    };
  };

  // The probe projection sent to the client: no secrets, ever.
  const publicProbe = (id) => {
    const probe = getProbeState(id);
    if (!probe) return { ok: null, checked_at: null, error: null, reason: null, stale_for_ms: null };
    return {
      ok: probe.ok,
      checked_at: probe.checked_at,
      reason: probe.reason,
      error: probe.error,
      error_class: probe.error_class,
      stale_for_ms: probe.stale_for_ms,
      kind: probe.kind,
    };
  };

  // --- discovery orchestration -----------------------------------------
  // One bounded queue for every automated probe, so a refresh can never open a
  // session per server at once.
  const discoveryQueue = new DiscoveryQueue();

  // The ONLY place the authoritative snapshot is written. It is reached only when
  // a discovery genuinely succeeded, which is what makes "a transient probe
  // failure can never change a server's topology" a structural guarantee rather
  // than a convention: a failure path below has no way to call saveSnapshot.
  const runFullDiscovery = (row) => discoveryQueue.run(row.id, async () => {
    const outcome = await discovery.discoverOutcome(row, getSecret(row), sshOptsFor(row));
    if (outcome.errorClass === 'hostkey') {
      saveProbeState(row.id, outcome);
      return { ok: false, hostkey_mismatch: true, presented_fp: outcome.presented_fp, probe: publicProbe(row.id) };
    }
    if (outcome.ok) {
      saveSnapshot(row.id, outcome.snapshot);
      saveProbeState(row.id, outcome);
      return { ok: true, snapshot: outcome.snapshot, probe: publicProbe(row.id) };
    }
    // FAILURE: the authoritative snapshot is deliberately left alone.
    saveProbeState(row.id, outcome);
    return { ok: false, probe: publicProbe(row.id), error: outcome.detail, error_class: outcome.errorClass };
  });

  // Lightweight: proves reachability without collecting topology, so it can run
  // on a short cadence for every server.
  const runHealthProbe = (row) => discoveryQueue.run(`health:${row.id}`, async () => {
    const probe = await discovery.probeHealth(row, getSecret(row), sshOptsFor(row));
    if (probe.errorClass === 'hostkey') {
      saveProbeState(row.id, probe, 'health');
      return { ok: false, hostkey_mismatch: true, presented_fp: probe.presented_fp, probe: publicProbe(row.id) };
    }
    saveProbeState(row.id, probe, 'health');
    return { ok: probe.ok, probe: publicProbe(row.id) };
  });

  const publicServer = (row) => {
    const { secret_enc, password_enc, ...rest } = row;
    return {
      ...rest,
      has_secret: !!secret_enc,
      has_fallback_password: !!password_enc,
      host_key_pinned: !!row.host_key_fp,
    };
  };

  const connectivityFor = (serverId) => db.prepare(`
    SELECT c.*,
      iran.name AS iran_name,
      foreign_server.name AS foreign_name
    FROM connectivity_checks c
    JOIN servers iran ON iran.id = c.iran_server_id
    JOIN servers foreign_server ON foreign_server.id = c.foreign_server_id
    WHERE c.iran_server_id = ? OR c.foreign_server_id = ?
    ORDER BY c.checked_at DESC
  `).all(serverId, serverId).map((row) => ({
    iran: { id: row.iran_server_id, name: row.iran_name, ip: row.iran_ip },
    foreign: { id: row.foreign_server_id, name: row.foreign_name, ip: row.foreign_ip },
    iran_to_foreign: { reachable: !!row.iran_to_foreign, detail: row.iran_to_foreign_detail },
    foreign_to_iran: { reachable: !!row.foreign_to_iran, detail: row.foreign_to_iran_detail },
    checked_at: row.checked_at,
  }));

  // Uniform response when a server presents a different host key.
  const hostKeyMismatchResponse = (res, server, presentedFp) =>
    res.status(409).json({
      error: `host key mismatch for ${server.name} — the server presented a different key than pinned. If this is expected (reinstall, new VM), accept the new key explicitly.`,
      hostkey_mismatch: true,
      presented_fp: presentedFp,
      expected_fp: server.host_key_fp,
    });

  // --- Auth (mounted without requireAuth) -------------------------------
  // Build/runtime identity. Deliberately unauthenticated except for the
  // database-backed schema number, because it is how an operator (and the
  // browser) can tell whether the running server matches the release they
  // think they deployed. No secrets, no host paths, no credentials.
  router.get('/meta', (req, res) => {
    res.json({
      name: 'gre-hub',
      ...versionInfo.resolveMeta({ schemaVersion: schemaVersion(db) }),
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

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
  //
  // Each server carries two independent facts:
  //   snapshot — the last AUTHORITATIVE topology from a successful discovery
  //              (null only if no discovery has ever succeeded)
  //   probe    — availability of the most recent probe, with a staleness age
  // A failed probe leaves `snapshot` exactly as it was.
  authed.get('/servers', (req, res) => {
    const rows = db.prepare('SELECT * FROM servers ORDER BY name').all();
    res.json(rows.map((r) => ({
      ...publicServer(r),
      snapshot: getSnapshot(r.id),
      probe: publicProbe(r.id),
      connectivity: connectivityFor(r.id),
    })));
  });

  // Topology and probe health are counted separately on purpose: a probe failure
  // is not a change of role, and the header must not conflate them.
  authed.get('/servers/health-summary', (req, res) => {
    const rows = db.prepare('SELECT id FROM servers ORDER BY id').all();
    const authoritative = { iran: 0, foreign: 0, dual: 0, unconfigured: 0 };
    const probe = { healthy: 0, failed: 0, unknown: 0 };
    let stale = 0;
    const STALE_MS = 24 * 60 * 60 * 1000;
    for (const row of rows) {
      const snapshot = getSnapshot(row.id);
      const roles = ((snapshot && snapshot.roles) || []).map((r) => String(r).toUpperCase());
      if (!snapshot) authoritative.unconfigured += 1;
      else if (roles.includes('IRAN') && roles.includes('FOREIGN')) authoritative.dual += 1;
      else if (roles.includes('IRAN')) authoritative.iran += 1;
      else if (roles.includes('FOREIGN')) authoritative.foreign += 1;
      else authoritative.unconfigured += 1;

      const state = getProbeState(row.id);
      if (!state) probe.unknown += 1;
      else if (state.ok) probe.healthy += 1;
      else probe.failed += 1;
      if (state && state.stale_for_ms > STALE_MS) stale += 1;
    }
    res.json({
      total: rows.length,
      authoritative,
      probe,
      stale_snapshots: stale,
      discovery: discoveryQueue.snapshot(),
      concurrency: discoveryQueue.concurrency,
    });
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
        await runFullDiscovery(fresh);
      } catch { /* discovery is best effort here; probe state records the outcome */ }
    })();
  });

  authed.get('/servers/:id', (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    res.json({ ...publicServer(server), snapshot: getSnapshot(server.id), connectivity: connectivityFor(server.id) });
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

  // Full discovery of one server, through the bounded queue so a refresh storm
  // cannot open a session per server at once. A repeat request for a server that
  // is already being discovered joins that run instead of starting another.
  authed.post('/servers/:id/discover', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await runFullDiscovery(server);
    if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
    auditEvent(server.id, server.name, 'discover', null, result.ok ? 0 : 1,
      result.ok ? 'authoritative snapshot updated' : `probe failed (${result.probe.error_class})`);
    // Still a usable 200 for the frontend: the payload distinguishes success from
    // failure via `ok`/`probe`, and a failure never touched the snapshot.
    if (result.ok) return res.json({ ...result.snapshot, ok: true, snapshot: result.snapshot, probe: result.probe });
    res.json({
      ok: false,
      error: result.error,
      error_class: result.error_class,
      probe: result.probe,
      snapshot: getSnapshot(server.id),
    });
  }));

  // Lightweight availability refresh: one trivial command per server, no topology
  // collection. Safe to run on a short cadence.
  authed.post('/servers/:id/health', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const result = await runHealthProbe(server);
    if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
    res.json({ ok: result.ok, probe: result.probe, snapshot: getSnapshot(server.id) });
  }));

  // Refresh every server's availability. Returns immediately with the queue
  // state; the frontend polls GET /servers for the outcome. This is what keeps
  // "refresh everything" from becoming a thundering herd.
  authed.post('/servers/health', wrap(async (req, res) => {
    const rows = db.prepare('SELECT * FROM servers ORDER BY id').all();
    const started = [];
    for (const row of rows) {
      if (discoveryQueue.has(`health:${row.id}`)) continue;
      started.push(row.id);
      runHealthProbe(row).catch(() => { /* per-server failure is recorded in probe state */ });
    }
    res.json({ ok: true, started: started.length, servers: rows.length, discovery: discoveryQueue.snapshot() });
  }));

  // Bounded rediscovery for servers whose authoritative snapshot was lost before
  // this release (roles came from a failed probe, so the server sits in
  // UNCONFIGURED without ever having been read successfully). Roles are NEVER
  // guessed from a name or an IP: only a real successful discovery restores one.
  authed.post('/servers/rediscover-unconfigured', wrap(async (req, res) => {
    const rows = db.prepare('SELECT * FROM servers ORDER BY id').all();
    const stale = rows.filter((row) => {
      const snapshot = getSnapshot(row.id);
      const roles = ((snapshot && snapshot.roles) || []);
      if (roles.length) return false;
      // Only candidates whose snapshot looks like a failed probe rather than a
      // confirmed absence of the manager.
      return !snapshot || snapshot.error || (snapshot.manager && snapshot.manager.installed === false);
    });
    for (const row of stale) {
      runFullDiscovery(row).catch(() => { /* recorded in probe state */ });
    }
    res.json({
      ok: true,
      candidates: stale.length,
      total: rows.length,
      discovery: discoveryQueue.snapshot(),
      note: 'Roles are never inferred; each candidate must complete a successful discovery.',
    });
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
      // Validate every action before doing network preflight work.
      const command = actions.buildAction(action, params || {});
      let preflight = null;
      if (connectivity.PREFLIGHT_ACTIONS.has(action)) {
        const pair = connectivity.resolvePair(db, server, action, params || {});
        preflight = await connectivity.checkPair(pair, { getSecret, sshOptsFor });
        if (preflight.hostkey_mismatch) {
          auditEvent(server.id, server.name, `${action}_preflight`, { peer: preflight.server.name }, 1, 'aborted: SSH host key mismatch', 'action');
          return hostKeyMismatchResponse(res, preflight.server, preflight.presented_fp);
        }
        connectivity.persistPair(db, preflight);
        auditEvent(server.id, server.name, `${action}_preflight`, {
          iran: `${preflight.iran.name} (${preflight.iran.ip})`,
          foreign: `${preflight.foreign.name} (${preflight.foreign.ip})`,
        }, preflight.ok ? 0 : 1,
        `IRAN -> FOREIGN: ${preflight.iran_to_foreign.reachable ? 'PASS' : 'FAIL'}; FOREIGN -> IRAN: ${preflight.foreign_to_iran.reachable ? 'PASS' : 'FAIL'}`,
        'action');
        if (!preflight.ok) {
          return res.status(409).json({
            error: 'The servers cannot reach each other in both directions. No node or peer was created. Do not retry setup until network/ICMP routing or firewall is fixed.',
            connectivity_failed: true,
            ...preflight,
          });
        }
      }

      const result = await actions.runAction(db, server, getSecret(server), action, params || {}, sshOptsFor(server), command);
      if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
      // Refresh the snapshot after state-changing actions (best effort), through
      // the same queue and with the same rule: only a successful discovery may
      // replace the authoritative snapshot.
      if (!['doctor'].includes(action)) {
        runFullDiscovery(server).catch(() => { /* recorded in probe state */ });
      }
      // gre prints "Unknown argument" when the CLI is older than the action
      // requires (e.g. foreign-setup needs >= 2.6.0) — surface a clear hint.
      const combined = `${result.stdout || ''}\n${result.stderr || ''}`;
      const hint = result.rc !== 0 && /Unknown argument/i.test(combined)
        ? 'remote gre is too old for this action; run the \'update\' action first'
        : undefined;
      res.json({ ok: result.rc === 0, rc: result.rc, stdout: result.stdout, stderr: result.stderr, command: result.command, ...(preflight ? { preflight } : {}), ...(hint ? { hint } : {}) });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }));

  // --- Collision-free value pools (gre >= 2.8.0 for count/base/node) --------
  authed.post('/servers/:id/suggest-peer', wrap(async (req, res) => {
    const server = getServer(req.params.id);
    if (!server) return res.status(404).json({ error: 'not found' });
    const { kind = 'peer', base = '' } = req.body || {};
    const count = Number((req.body || {}).count ?? 10);
    if (!['peer', 'node'].includes(kind)) return res.status(400).json({ error: 'kind must be peer or node' });
    if (!Number.isInteger(count) || count < 1 || count > 20) return res.status(400).json({ error: 'count must be an integer from 1 to 20' });
    if (base && !/^\d{1,3}\.\d{1,3}$/.test(String(base))) return res.status(400).json({ error: 'base must look like A.B' });
    const command = kind === 'node' ? 'gre node suggest' : 'gre iran peer suggest';
    const baseArg = base ? ` --base ${String(base)}` : '';
    const result = await ssh.exec(server, getSecret(server), `${command} --json --count ${count}${baseArg}`, { timeoutMs: 30000, ...sshOptsFor(server) });
    if (result.hostkey_mismatch) return hostKeyMismatchResponse(res, server, result.presented_fp);
    const combined = `${result.stdout || ''}\n${result.stderr || ''}`;
    if (result.rc !== 0) {
      const tooOld = /Unknown (?:argument|option)/i.test(combined);
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

  // --- Automatic GRE + 3x-ui routes --------------------------------------

  // Panel metadata older than this is refreshed opportunistically on read.
  const PANEL_PROBE_STALE_MS = 10 * 60 * 1000;

  const panelPublic = (row) => ({
    id: row.id,
    name: row.name,
    base_url: row.base_url,
    username: row.username,
    auth_type: row.auth_type,
    // `capability` is the historical host-mode column; host_mode is the new
    // explicit name. Both are reported so older clients keep working.
    capability: row.host_mode || row.capability || null,
    host_mode: row.host_mode || row.capability || null,
    client_model: row.client_model || null,
    panel_version: row.panel_version || null,
    panel_version_source: row.panel_version_source || null,
    last_probe_at: row.last_probe_at || null,
    last_probe_error: row.last_probe_error || null,
    created_at: row.created_at,
  });

  /**
   * Probe one panel: authenticate, detect the exact 3x-ui version and both
   * capability axes, then persist the diagnostics. A failed probe records the
   * error but deliberately leaves the last known-good metadata in place, so a
   * temporarily unreachable panel does not erase what we already learned.
   */
  const probePanel = async (panel, { audit = false } = {}) => {
    const client = routeOrchestrator.client(panel);
    const result = {
      id: panel.id,
      panel_version: null,
      panel_version_source: null,
      client_model: null,
      host_mode: null,
      error: null,
    };
    try {
      const capabilities = await client.resolveCapabilities();
      result.client_model = capabilities.clientModel;
      result.host_mode = capabilities.hostMode;
      const version = await client.detectPanelVersion().catch(() => null);
      if (version) {
        result.panel_version = version.version;
        result.panel_version_source = version.source;
      }
    } catch (err) {
      result.error = err.message;
    }
    const now = Date.now();
    if (result.error) {
      db.prepare('UPDATE xui_panels SET last_probe_at = ?, last_probe_error = ? WHERE id = ?')
        .run(now, String(result.error).slice(0, 500), panel.id);
    } else {
      db.prepare(`
        UPDATE xui_panels
           SET panel_version = ?, panel_version_source = ?, client_model = ?, host_mode = ?,
               capability = ?, last_probe_at = ?, last_probe_error = NULL
         WHERE id = ?
      `).run(result.panel_version, result.panel_version_source, result.client_model, result.host_mode,
        result.host_mode, now, panel.id);
    }
    if (audit) {
      auditEvent(null, 'hub', 'xui_panel_probe', { panel: panel.name }, result.error ? 1 : 0,
        result.error
          ? `probe failed: ${result.error}`
          : `version=${result.panel_version || '?'} client=${result.client_model} hosts=${result.host_mode}`);
    }
    return result;
  };

  authed.get('/xui-panels', wrap(async (req, res) => {
    const rows = db.prepare('SELECT * FROM xui_panels ORDER BY name').all();
    // Never block the list on a probe: refresh stale metadata in the
    // background and let the next poll show it.
    if (req.query.probe !== '0') {
      const stale = rows.filter((row) => !row.last_probe_at || (Date.now() - row.last_probe_at) > PANEL_PROBE_STALE_MS);
      if (stale.length) {
        Promise.all(stale.map((panel) => probePanel(panel))).catch(() => { /* diagnostics only */ });
      }
    }
    res.json(rows.map(panelPublic));
  }));

  authed.post('/xui-panels/:id/probe', wrap(async (req, res) => {
    const panel = db.prepare('SELECT * FROM xui_panels WHERE id = ?').get(req.params.id);
    if (!panel) return res.status(404).json({ error: 'not found' });
    const result = await probePanel(panel, { audit: true });
    const fresh = db.prepare('SELECT * FROM xui_panels WHERE id = ?').get(panel.id);
    if (result.error) {
      return res.status(502).json({ error: result.error, probe: { ...result, panel: panelPublic(fresh) } });
    }
    res.json({ ok: true, probe: { ...result, panel: panelPublic(fresh) } });
  }));

  authed.post('/xui-panels', wrap(async (req, res) => {
    const { name, base_url: baseUrl } = req.body || {};
    const authType = req.body && req.body.auth_type === 'token' ? 'token' : 'password';
    const username = String(req.body && req.body.username || '').trim();
    const rawCredential = authType === 'token' ? req.body && req.body.token : req.body && req.body.password;
    const credential = authType === 'token' ? String(rawCredential || '').trim() : rawCredential;
    if (!name || typeof credential !== 'string' || !credential || (authType === 'password' && !username)) {
      return res.status(400).json({ error: authType === 'token'
        ? 'name, base_url and API token are required'
        : 'name, base_url, username and password are required' });
    }
    let normalized;
    try { normalized = normalizeBaseUrl(baseUrl); } catch (err) { return res.status(400).json({ error: err.message }); }
    const probe = new XuiClient({
      baseUrl: normalized,
      authType,
      username,
      password: authType === 'password' ? credential : '',
      token: authType === 'token' ? credential : '',
    });
    let capabilities;
    let version = null;
    try {
      await probe.authenticate();
      [, capabilities] = await Promise.all([probe.listInbounds(), probe.resolveCapabilities()]);
      // Diagnostic only: a panel that cannot report its version is still saved.
      version = await probe.detectPanelVersion().catch(() => null);
    } catch (err) {
      return res.status(400).json({ error: `panel connection failed: ${err.message}` });
    }
    try {
      const now = Date.now();
      const result = db.prepare(`
        INSERT INTO xui_panels
          (name, base_url, username, auth_type, capability, client_model, host_mode,
           panel_version, panel_version_source, last_probe_at, last_probe_error, password_enc, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
      `).run(String(name).slice(0, 80), normalized, username.slice(0, 120), authType,
        capabilities.hostMode, capabilities.clientModel, capabilities.hostMode,
        version ? version.version : null, version ? version.source : null,
        now, encrypt(cryptKey, credential), now);
      auditEvent(null, 'hub', 'xui_panel_add', { name, base_url: normalized, auth_type: authType }, 0,
        `3x-ui panel saved (version=${version && version.version ? version.version : '?'}, client=${capabilities.clientModel}, hosts=${capabilities.hostMode})`);
      res.status(201).json({
        id: Number(result.lastInsertRowid), name, base_url: normalized, username,
        auth_type: authType, capability: capabilities.hostMode, host_mode: capabilities.hostMode,
        client_model: capabilities.clientModel,
        panel_version: version ? version.version : null,
        panel_version_source: version ? version.source : null,
        last_probe_at: now,
        last_probe_error: null,
      });
    } catch (err) {
      res.status(err.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 400).json({ error: err.message });
    }
  }));

  authed.delete('/xui-panels/:id', (req, res) => {
    try {
      const result = db.prepare('DELETE FROM xui_panels WHERE id = ?').run(req.params.id);
      if (!result.changes) return res.status(404).json({ error: 'not found' });
      res.json({ ok: true });
    } catch (err) {
      res.status(409).json({ error: 'panel is used by one or more routes' });
    }
  });

  // Client picker feed.
  //
  // Opening the Create Route dialog must not probe the panel for capabilities
  // (the hub already persisted the model in xui_panels during the last probe) and
  // must not download the whole client inventory. `?paged=1` returns one page and
  // supports `?search=`, which is what the dialog uses; without it the endpoint
  // keeps its original full-listing contract for any other caller.
  authed.get('/xui-panels/:id/clients', wrap(async (req, res) => {
    const panel = db.prepare('SELECT * FROM xui_panels WHERE id = ?').get(req.params.id);
    if (!panel) return res.status(404).json({ error: 'not found' });
    const client = routeOrchestrator.client(panel);

    const paged = req.query.paged === '1';
    const known = { clientModel: panel.client_model || null };

    // Without a stored model we cannot avoid the probe. With one, the dialog
    // renders immediately from the cache and never pays for detection.
    const capabilities = known.clientModel
      ? { clientModel: known.clientModel, hostMode: panel.host_mode || null }
      : await client.resolveCapabilities();

    const result = await client.listClients({
      known,
      paged,
      search: req.query.search || '',
      page: Number(req.query.page) || 1,
      pageSize: Number(req.query.pageSize) || 20,
      withInboundRemarks: false,
    });

    if (paged && result && Array.isArray(result.clients)) {
      return res.json({
        clients: result.clients,
        paged: result.paged,
        total: result.total,
        page: result.page,
        pageSize: result.pageSize,
        client_model: capabilities.clientModel,
        host_mode: capabilities.hostMode,
      });
    }
    res.json({
      clients: Array.isArray(result) ? result : [],
      client_model: capabilities.clientModel,
      host_mode: capabilities.hostMode,
    });
  }));

  authed.post('/gre-routes/recommend-port', wrap(async (req, res) => {
    const result = await routeOrchestrator.recommend({
      iranServerId: Number(req.body && req.body.iran_server_id),
      foreignServerId: Number(req.body && req.body.foreign_server_id),
      panelId: Number(req.body && req.body.panel_id),
      start: req.body && req.body.range_start,
      end: req.body && req.body.range_end,
      preferredPort: req.body && req.body.port,
    });
    res.json(result);
  }));

  // Persistent configuration reveal.
  //
  // The configuration an operator needs to copy is stored encrypted on the route
  // row, so it survives a browser refresh and a hub restart. The in-memory
  // routeResults cache is only a convenience for the run that just finished.
  //
  // ACTIVE only. A FAILED or cleaned-up route has no usable configuration, and a
  // soft-deleted route must never reveal one.
  authed.get('/gre-routes/:id/config', wrap(async (req, res) => {
    const id = Number(req.params.id);
    const route = db.prepare('SELECT * FROM gre_routes WHERE id = ? AND deleted_at IS NULL').get(id);
    if (!route) return res.status(404).json({ error: 'not found' });
    if (route.status !== 'ACTIVE') {
      return res.status(409).json({
        error: 'No active configuration — provisioning did not complete.',
        status: route.status,
      });
    }

    let config = null;
    try {
      config = routeOrchestrator.routeConfig(id);
    } catch (err) {
      return res.status(409).json({ error: err.message, status: route.status });
    }
    if (!config) {
      return res.status(409).json({
        error: 'Configuration cannot be reconstructed safely; Reconcile/Retry is required.',
        status: route.status,
      });
    }

    // Audit the reveal, never the secret.
    try {
      audit(db, {
        kind: 'route',
        action: 'route_config_reveal',
        params: { route_id: id, name: route.name },
        rc: 0,
        output: 'configuration revealed',
      });
    } catch { /* audit must never break a reveal */ }

    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    res.json(config);
  }));

  authed.get('/gre-routes', (req, res) => {
    res.json(routeOrchestrator.listRoutes(req.query.reveal === '1'));
  });

  authed.get('/gre-routes/:id', wrap(async (req, res) => {
    const id = Number(req.params.id);
    // While a provisioning run started by this process is still going, wait for
    // it to settle so a client that just observed `active` gets the completed
    // result (share link + QR) instead of a half-written row.
    const running = routeOrchestrator.running && routeOrchestrator.running.get(id);
    if (running && req.query.wait === '1') await running;
    const route = routeOrchestrator.safeRoute(id);
    if (!route) return res.status(404).json({ error: 'not found' });

    // The result projection is built from the DB, not from process memory, so it
    // still works after a restart. `link`/`outbound`/QR are only ever produced
    // for an ACTIVE route and never appear in the list endpoint.
    if (req.query.result === '1' && route.status === 'ACTIVE') {
      let config = null;
      try { config = routeOrchestrator.routeConfig(id); } catch { config = null; }
      if (config) {
        // The post-provision result is fetched once by the dialog that just
        // created the route, so the QR is included by default. The dedicated
        // /config endpoint does not need it, so QR generation there stays opt-in
        // via ?qr=1.
        const qr_data_url = await QRCode.toDataURL(config.link, { errorCorrectionLevel: 'M', margin: 2, width: 320 });
        res.set('Cache-Control', 'no-store');
        return res.json({
          ...route,
          link: config.link,
          outbound: config.outbound,
          qr_data_url,
          iran_endpoint: config.endpoint.host,
          inbound_id: config.inbound_id != null ? config.inbound_id : route.inbound_id,
        });
      }
    }
    res.json(route);
  }));

  // Incremental, always-cheap event read. `after_id` returns only newer rows;
  // omitting it keeps the original full-history behavior. `wait=1` long-polls
  // until something new exists (or the wait window expires) so the timeline
  // does not need to hammer the API while a route provisions.
  authed.get('/gre-routes/:id/events', wrap(async (req, res) => {
    const route = db.prepare('SELECT id, status FROM gre_routes WHERE id=?').get(req.params.id);
    if (!route) return res.status(404).json({ error: 'not found' });
    const afterId = req.query.after_id;
    if (req.query.wait === '1' && afterId !== undefined) {
      return res.json(await routeOrchestrator.waitForEvent(route.id, afterId));
    }
    res.json(routeOrchestrator.events(route.id, afterId));
  }));

  // Async job-style create: validate + reserve + return 202 immediately, then
  // provision in the background while the UI streams route_events.
  authed.post('/gre-routes', wrap(async (req, res) => {
    const body = req.body || {};
    const input = {
      name: body.name,
      iranServerId: Number(body.iran_server_id),
      foreignServerId: Number(body.foreign_server_id),
      panelId: Number(body.panel_id),
      port: body.port,
      start: body.range_start,
      end: body.range_end,
      method: body.method,
      client_mode: body.client_mode,
      client_email: body.client_email,
      // Backward compatibility for an older frontend.
      client_name: body.client_name,
      clientName: body.client_name,
    };
    let prepared;
    try {
      prepared = await routeOrchestrator.prepare(input);
    } catch (err) {
      auditEvent(null, 'hub', 'gre_route_create', { name: body.name }, 1, err.message);
      return res.status(409).json({ error: err.message, route_id: err.routeId || null });
    }
    auditEvent(null, 'hub', 'gre_route_create', {
      name: prepared.name, port: prepared.port, client_model: prepared.client_model, client_mode: prepared.client_mode,
    }, 0, `route ${prepared.route_id} reserved; provisioning started`);
    // Never leave an unhandled rejection behind: startProvisioning catches
    // everything and always resolves. The outcome is cached so the UI can pick
    // up the share link and QR code once the timeline reports a terminal
    // status, without polling the whole route list for decrypted secrets.
    routeOrchestrator.startProvisioning(prepared.route_id, prepared)
      .then((outcome) => {
        const route = routeOrchestrator.safeRoute(prepared.route_id);
        rememberResult(prepared.route_id, {
          ok: outcome.ok,
          status: route ? route.status : (outcome.ok ? 'ACTIVE' : 'FAILED'),
          error: outcome.ok ? null : outcome.error.message,
          link: outcome.ok ? outcome.result.link : null,
          qr_data_url: outcome.ok ? outcome.result.qr_data_url : null,
          outbound: outcome.ok ? outcome.result.outbound : null,
          iran_endpoint: outcome.ok ? outcome.result.iran_endpoint : null,
          inbound_id: outcome.ok ? outcome.result.inbound_id : null,
        });
      });
    // The hub already knows this panel's client model from its last probe. In
    // live mode the synchronous preflight deliberately does not probe, so without
    // this the timeline header would read "unknown" even though the value is on
    // hand. Include it so the header is correct from the first render.
    const panelRow = db.prepare('SELECT client_model, host_mode, panel_version FROM xui_panels WHERE id = ?')
      .get(Number(body.panel_id)) || {};
    res.status(202).json({
      route_id: prepared.route_id,
      status: 'RESERVED',
      name: prepared.name,
      port: prepared.port,
      method: prepared.method,
      client_email: prepared.client_email,
      client_mode: prepared.client_mode,
      client_model: prepared.client_model || panelRow.client_model || null,
      host_mode: prepared.host_mode || panelRow.host_mode || null,
      panel_client_model: panelRow.client_model || null,
      panel_version: panelRow.panel_version || null,
    });
  }));

  authed.post('/gre-routes/:id/reconcile', wrap(async (req, res) => {
    const result = await routeOrchestrator.reconcile(Number(req.params.id));
    const failed = result.components.filter((item) => item.status === 'FAIL').map((item) => item.name);
    auditEvent(null, 'hub', 'gre_route_reconcile', { id: result.id, desired: result.desiredState, status: result.status },
      result.healthy ? 0 : 1,
      `${result.summary}${failed.length ? ` [${failed.join(', ')}]` : ''}`);
    res.json(result);
  }));

  // Change the desired specification of a route WITHOUT provisioning it.
  // Infrastructure changes are refused while the route is ACTIVE: editing the
  // stored intent of a live tunnel would make the database disagree with
  // reality, and rolling it back later would delete objects the user forgot
  // they had asked for.
  authed.patch('/gre-routes/:id', wrap(async (req, res) => {
    const id = Number(req.params.id);
    const body = req.body || {};
    try {
      const result = await routeOrchestrator.editRoute(id, {
        name: body.name,
        iranServerId: body.iran_server_id,
        foreignServerId: body.foreign_server_id,
        panelId: body.panel_id,
        port: body.port,
        method: body.method,
        client_mode: body.client_mode,
        client_email: body.client_email,
        client_name: body.client_name,
      });
      auditEvent(null, 'hub', 'gre_route_edit', { id, fields: result.changed }, 0,
        `updated ${result.changed.join(', ') || 'nothing'}`);
      res.json(result.route);
    } catch (err) {
      auditEvent(null, 'hub', 'gre_route_edit', { id }, 1, err.message);
      res.status(err.status || 400).json({ error: err.message, locked: err.locked || null, fields: err.fields || null });
    }
  }));

  // Re-run provisioning for a route that is not ACTIVE. Reconcile runs first so
  // a retry never blindly collides with leftovers from the previous attempt.
  authed.post('/gre-routes/:id/retry', wrap(async (req, res) => {
    const id = Number(req.params.id);
    const route = routeOrchestrator.route(id);
    if (!route) return res.status(404).json({ error: 'not found' });
    if (route.deleted_at) return res.status(409).json({ error: 'route is deleted' });
    if (route.status === 'ACTIVE') {
      return res.status(409).json({ error: 'route is already ACTIVE; use Reconcile instead of Retry' });
    }
    if (routeOrchestrator.running && routeOrchestrator.running.has(id)) {
      return res.status(409).json({ error: 'route is already provisioning' });
    }
    try {
      const prepared = await routeOrchestrator.prepareForRetry(id);
      routeOrchestrator.startProvisioning(id, prepared);
      auditEvent(null, 'hub', 'gre_route_retry', { id, attempt: prepared.attempt_no }, 0, `attempt #${prepared.attempt_no} started`);
      return res.status(202).json({
        route_id: id,
        status: 'RESERVED',
        attempt_no: prepared.attempt_no,
        leftover: prepared.leftover || [],
      });
    } catch (err) {
      auditEvent(null, 'hub', 'gre_route_retry', { id }, 1, err.message);
      return res.status(err.status || 409).json({ error: err.message, leftover: err.leftover || [] });
    }
  }));

  // Dry run for the delete confirmation dialog: exactly what would be removed
  // and exactly what will be preserved.
  authed.get('/gre-routes/:id/delete-preview', wrap(async (req, res) => {
    const id = Number(req.params.id);
    const route = routeOrchestrator.route(id);
    if (!route) return res.status(404).json({ error: 'not found' });
    if (route.deleted_at) return res.status(409).json({ error: 'route is already deleted' });
    res.json(await routeOrchestrator.deletePreview(id));
  }));

  authed.delete('/gre-routes/:id', wrap(async (req, res) => {
    const id = Number(req.params.id);
    const route = routeOrchestrator.route(id);
    if (!route) return res.status(404).json({ error: 'not found' });
    if (route.deleted_at) return res.status(409).json({ error: 'route is already deleted' });
    if (routeOrchestrator.running && routeOrchestrator.running.has(id)) {
      return res.status(409).json({ error: 'route is provisioning right now; wait for it to finish before deleting' });
    }
    const result = await routeOrchestrator.deleteRoute(id);
    auditEvent(null, 'hub', 'gre_route_delete', { id, removed: result.removed }, result.ok ? 0 : 1,
      result.ok ? 'route removed and soft-deleted' : `cleanup incomplete: ${result.failures.map((f) => f.name).join(', ')}`);
    res.status(result.ok ? 200 : 409).json(result);
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
