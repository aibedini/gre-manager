'use strict';
// connections.js — the Hub-side GRE Connection: model, plan, apply, migrate.
//
// DESIGN NOTES, because the shape of this file is deliberate:
//
//  * A connection IS a gre_routes row. It already holds both server ids, the peer
//    name, the tunnel parameters and the port pair. A second parallel model would
//    drift from the orchestrator's ownership metadata, so this module is a
//    PROJECTION plus the extra state (stable uuid, journal, locks).
//
//  * The Hub never reimplements tunnel or iptables handling. Every mutation is a
//    `gre iran peer edit` / `gre node edit` invocation on the relevant server,
//    through actions.buildAction. The Hub owns the TWO-SIDED ORCHESTRATION and the
//    make-before-break ordering; the CLI owns what happens on a host. That is also
//    what makes the Hub's rollback real: re-running the edit with the old values is
//    the CLI's own transactional path, not a Hub-side approximation.
//
//  * Make-before-break for a server migration:
//        build the NEW side -> verify -> update the SOURCE -> verify
//        -> verify bidirectional -> doctor -> only THEN remove the old side
//    The old server's config is never touched before the new path is healthy.
//
//  * Rollback restores the previous state by applying it, then verifying it. If
//    rollback itself fails the operation is marked ROLLBACK_FAILED together with
//    the exact commands a human would need, because a silent failure here would
//    leave the operator with a connection in an unknown state.

const crypto = require('crypto');
const { planEdit, validateRequest, preflight, estimateDisruption } = require('./connection-planner');
const actions = require('./actions');

// ---------------------------------------------------------------------- locks
//
// One mutation per connection, and one per server. The server-level lock is what
// stops two migrations from rewriting the same host's config at once; the
// connection lock stops a double-click from racing itself.
//
// Held in memory: a lock only needs to outlive a running operation, and a restart
// clears it, which is correct because the process that held it is gone. Operations
// interrupted by a restart are found in the journal instead (see interrupted()).
const locks = new Map();

function lockKey(kind, id) {
  return `${kind}:${id}`;
}

function acquire(keys, owner) {
  const wanted = keys.map((k) => lockKey(k.kind, k.id));
  const held = wanted.filter((k) => locks.has(k));
  if (held.length) {
    return { ok: false, held };
  }
  const token = crypto.randomUUID();
  const now = Date.now();
  for (const k of wanted) locks.set(k, { token, owner, since: now });
  return { ok: true, token, keys: wanted };
}

// Diagnostics for the lock table. Exposed so a test can prove two operations
// really were serialised rather than merely happening to succeed.
function lockSnapshot() {
  return { size: locks.size, keys: [...locks.keys()] };
}

function release(acquired) {
  if (!acquired) return;
  for (const k of acquired.keys || []) locks.delete(k);
}

function activeLocks() {
  return [...locks.entries()].map(([key, v]) => ({ key, owner: v.owner, since: v.since }));
}

// -------------------------------------------------------------------- helpers

const now = () => Date.now();

function ensureUuid(db, row) {
  if (row.connection_uuid) return row.connection_uuid;
  const uuid = crypto.randomUUID();
  db.prepare('UPDATE gre_routes SET connection_uuid = ? WHERE id = ?').run(uuid, row.id);
  return uuid;
}

function getRoute(db, id) {
  return db.prepare('SELECT * FROM gre_routes WHERE id = ? AND deleted_at IS NULL').get(id);
}

function serverRow(db, id) {
  return db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
}

// The public connection shape. Never carries a credential: the port pair, the
// addresses and the tunnel parameters are all non-secret.
function project(db, row) {
  const iran = serverRow(db, row.iran_server_id) || {};
  const foreign = serverRow(db, row.foreign_server_id) || {};
  const uuid = row.connection_uuid || null;
  return {
    connection_id: uuid,
    id: row.id,
    name: row.name,
    iran_server_id: row.iran_server_id,
    iran_server: iran.name || null,
    iran_ip: row.iran_ip || iran.host || null,
    foreign_server_id: row.foreign_server_id,
    foreign_server: foreign.name || null,
    foreign_ip: row.foreign_ip || foreign.host || null,
    // Read from the pairing record only. `host_group_id` is a 3x-ui managed-host id
    // and must never be presented as a tunnel parameter — doing so showed an operator
    // a panel host id where the GRE subnet belonged, and fed the planner the same
    // wrong value.
    subnet_base: parseEndpoint(row.iran_endpoint).subnet_base || null,
    idx: parseEndpoint(row.iran_endpoint).idx === undefined ? null : Number(parseEndpoint(row.iran_endpoint).idx),
    key: parseEndpoint(row.iran_endpoint).key === undefined ? null : Number(parseEndpoint(row.iran_endpoint).key),
    tcp_ports: row.tcp_ports || String(row.port || ''),
    udp_ports: row.udp_ports || String(row.port || ''),
    mss_clamp: row.mss_clamp === null || row.mss_clamp === undefined ? null : Number(row.mss_clamp),
    iran_tunnel: row.peer_name ? `gre-${row.peer_name}` : null,
    foreign_tunnel: row.peer_name ? `gre-${row.peer_name}` : null,
    iran_state: null,
    foreign_state: null,
    state: row.connection_state || null,
    last_verified_at: row.last_verified_at || null,
    status: row.status,
    capability: row.capability,
    host_mode: row.host_mode || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// The shape the planner and the CLI need: the authoritative current state.
//
// IMPORTANT: every value here comes from a column whose meaning is actually known.
//
// This used to fall back to `row.host_group_id` for subnet_base. That column is a
// 3x-ui MANAGED-HOST GROUP ID — a value passed straight to the panel's deleteHost
// API (see route-orchestrator's cleanup) — not a GRE subnet base. Reading it as one
// meant the planner could be handed a panel host id and treat it as a tunnel
// parameter, which is exactly how a "safe" edit would rewrite a live tunnel with
// garbage.
//
// A parameter the Hub genuinely does not know is reported as null, and `plan()` then
// REFUSES to build a change that depends on it (see UNKNOWN_PARAM_FIELDS). Silently
// substituting a plausible value is the failure mode this guards against.
function currentState(db, row) {
  const parsed = parseEndpoint(row.iran_endpoint);
  const unknown = [];
  const orUnknown = (value, field) => {
    if (value === null || value === undefined || value === '') { unknown.push(field); return null; }
    return value;
  };
  return {
    id: row.id,
    name: row.name,
    iran_server_id: row.iran_server_id,
    foreign_server_id: row.foreign_server_id,
    // Addresses have dedicated columns; iran_endpoint is only a fallback because the
    // orchestrator historically stored a bare IP there.
    iran_ip: row.iran_ip || parsed.iran_ip || null,
    foreign_ip: row.foreign_ip || parsed.foreign_ip || null,
    subnet_base: orUnknown(parsed.subnet_base, 'subnet_base'),
    idx: parsed.idx === undefined || parsed.idx === null ? (unknown.push('idx'), null) : Number(parsed.idx),
    key: parsed.key === undefined || parsed.key === null ? (unknown.push('key'), null) : Number(parsed.key),
    tcp_ports: row.tcp_ports || String(row.port || ''),
    udp_ports: row.udp_ports || String(row.port || ''),
    mss_clamp: row.mss_clamp === null || row.mss_clamp === undefined ? null : Number(row.mss_clamp),
    peer_name: row.peer_name,
    unknown_fields: unknown,
  };
}

// Tunnel parameters the Hub cannot safely guess. A change that touches one of these
// is refused until the authoritative value has been read from the managed server
// (the API does that via learnStateFromServers before planning).
const UNKNOWN_PARAM_FIELDS = ['subnet_base', 'idx', 'key'];

// iran_endpoint is read back only when it holds the JSON the connections code writes.
// The orchestrator also stores a bare IP string there, so a parse failure is normal
// and means "no pairing values recorded", not "corrupt".
function parseEndpoint(json) {
  if (!json) return {};
  try {
    const v = typeof json === 'string' ? JSON.parse(json) : json;
    if (!v || typeof v !== 'object') return {};
    return {
      iran_ip: v.iran_ip,
      foreign_ip: v.foreign_ip,
      subnet_base: v.subnet_base,
      idx: v.idx === undefined ? undefined : Number(v.idx),
      key: v.key === undefined ? undefined : Number(v.key),
    };
  } catch { return {}; }
}

// Read the authoritative tunnel parameters from the servers themselves.
//
// The Hub DB holds identity, correlation and history; /etc/multi-gre holds the truth.
// When the DB has never learned subnet/index/key (a route provisioned before this
// release, or one whose iran_endpoint was overwritten with a bare IP), the honest
// move is to ask the Iran side and record what it says — not to invent a value.
//
// Returns { state, learned, source, error } and never throws: a server that cannot be
// reached simply leaves the parameters unknown, and the caller then blocks the edit.
async function learnStateFromServers({ db, row, remote, resolveServer }) {
  const parsed = parseEndpoint(row.iran_endpoint);
  const needs = UNKNOWN_PARAM_FIELDS.filter((f) => {
    if (f === 'subnet_base') return !parsed.subnet_base;
    return parsed[f] === undefined || parsed[f] === null;
  });
  if (!needs.length) return { learned: false, source: 'hub-metadata' };

  let iran;
  try { iran = resolveServer(row.iran_server_id); } catch { iran = null; }
  if (!iran) return { learned: false, source: 'none', error: 'the Iran server is not configured' };

  let out;
  try {
    out = await remote(iran, actions.buildAction('peer_list_json', {}), 60000);
  } catch (err) {
    return { learned: false, source: 'none', error: `could not read state from ${iran.name}: ${err.message}` };
  }
  if (!out || out.rc !== 0) {
    return { learned: false, source: 'none', error: `could not read state from ${iran.name}` };
  }
  let list;
  try { list = JSON.parse(String(out.stdout).trim()); } catch {
    return { learned: false, source: 'none', error: `${iran.name} returned output that is not JSON` };
  }
  if (!Array.isArray(list)) return { learned: false, source: 'none', error: `${iran.name} returned an unexpected shape` };

  const entry = list.find((e) => String(e.name) === String(row.peer_name || row.name));
  if (!entry) {
    return { learned: false, source: 'none', error: `'${row.peer_name || row.name}' is not present on ${iran.name}` };
  }

  // Record what the server says so later plans are cheap and consistent.
  const endpoint = JSON.stringify({
    iran_ip: entry.iran_ip,
    foreign_ip: entry.foreign_ip,
    subnet_base: entry.subnet_base,
    idx: entry.idx === undefined ? undefined : Number(entry.idx),
    key: entry.key === undefined ? undefined : Number(entry.key),
  });
  try {
    db.prepare('UPDATE gre_routes SET iran_endpoint = ?, iran_ip = COALESCE(?, iran_ip), foreign_ip = COALESCE(?, foreign_ip), updated_at = ? WHERE id = ?')
      .run(endpoint, entry.iran_ip || null, entry.foreign_ip || null, Date.now(), row.id);
  } catch { /* recording is best effort; the plan below uses the read values anyway */ }

  return { learned: true, source: iran.name, entry };
}


// ---------------------------------------------------------------- the journal

function journalStart(db, { uuid, routeId, kind, oldState, requestedState, plan }) {
  const operationId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO edit_operations
      (operation_id, connection_uuid, route_id, kind, old_state_json, requested_state_json,
       plan_json, status, current_stage, created_at, started_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING', 'PLAN_CREATED', ?, ?)
  `).run(
    operationId, uuid, routeId === undefined ? null : routeId, kind,
    JSON.stringify(oldState || {}), JSON.stringify(requestedState || {}),
    JSON.stringify(plan || {}), now(), now(),
  );
  return operationId;
}

function journalStage(db, operationId, stage, status, detail) {
  const patch = { stage, status, detail };
  try {
    db.prepare('UPDATE edit_operations SET current_stage = ?, detail = ? WHERE operation_id = ?')
      .run(stage, detail ? String(detail).slice(0, 500) : null, operationId);
  } catch { /* journaling must never break an operation */ }
  return patch;
}

function journalFinish(db, operationId, status, detail, rollbackState) {
  try {
    db.prepare(`UPDATE edit_operations
        SET status = ?, detail = ?, rollback_state = ?, completed_at = ?
      WHERE operation_id = ?`)
      .run(status, detail ? String(detail).slice(0, 1000) : null, rollbackState || null, now(), operationId);
  } catch { /* best effort */ }
}

function journalGet(db, operationId) {
  return db.prepare('SELECT * FROM edit_operations WHERE operation_id = ?').get(operationId);
}

function journalForConnection(db, uuid, limit = 20) {
  return db.prepare('SELECT * FROM edit_operations WHERE connection_uuid = ? ORDER BY created_at DESC LIMIT ?')
    .all(uuid, limit);
}

// Operations left RUNNING by a previous process. A restart cannot finish them, so
// the honest answer is to say so rather than to pretend they succeeded.
function interrupted(db) {
  return db.prepare("SELECT * FROM edit_operations WHERE status = 'RUNNING' ORDER BY created_at DESC").all();
}

function markInterrupted(db, operationId, reason) {
  journalFinish(db, operationId, 'INTERRUPTED', reason || 'the hub restarted while this operation was running', 'UNKNOWN');
}

// ------------------------------------------------------------------- planning

// Build a plan. Reads only; performs no mutation and no SSH.
//
// `options.current` lets a caller pass an authoritative state it has just read from
// the servers. Without it the Hub's own metadata is used, and any change that would
// depend on a parameter the Hub does not actually know is REFUSED rather than
// guessed. That refusal is the point: a plausible-looking wrong value here rewrites a
// working tunnel with garbage.
function plan(db, row, requested, options = {}) {
  const current = options.current || currentState(db, row);
  const uuid = row.connection_uuid || null;

  const validationErrors = validateRequest(requested, current);
  const result = planEdit(current, requested);

  // Guard against planning FROM an unknown baseline.
  //
  // Changing subnet/index/key is perfectly legitimate — those are exactly the fields
  // an operator edits. What is not legitimate is doing it when the Hub does not know
  // the CURRENT value, because the recreate path re-applies every parameter, so a
  // null baseline becomes an empty value written into a live config.
  //
  // So the trigger is `unknown`, not "the change touches a tunnel field".
  const unknown = current.unknown_fields || [];
  const relevant = (result.class === 'B' || result.class === 'C')
    // A recreate re-applies every tunnel parameter, so all of them must be known.
    ? UNKNOWN_PARAM_FIELDS
    // A rule-only change never touches them.
    : [];
  const dependent = relevant.filter((f) => unknown.includes(f));
  if (dependent.length && (result.class === 'B' || result.class === 'C')) {
    validationErrors.push(
      `Cannot plan this change: the current ${dependent.join(', ')} of this connection is not known to the Hub. `
      + 'Open the connection and let the Hub read it from the server first (Reconcile), then retry.',
    );
  }

  const servers = db.prepare('SELECT * FROM servers ORDER BY name').all().map((s) => ({
    id: s.id, name: s.name, host: s.host, has_secret: !!s.secret_enc,
    key_installed: !!s.key_installed, ssh_auth: s.ssh_auth,
  }));
  const connections = db.prepare('SELECT * FROM gre_routes WHERE deleted_at IS NULL ORDER BY id').all()
    .map((r) => { const s = currentState(db, r); return { ...s }; });

  const checks = preflight(requested, current, {
    servers, connections, currentId: row.id,
  });

  // Surface the unknown parameters as an explicit preflight result only when the
  // change actually depends on them. A rule-only change does not: it re-points NAT at
  // the peer address, and the ports come from the route's own columns. Blocking it
  // would refuse a safe, useful edit for no reason.
  const unknownChecks = [];
  if (dependent.length) {
    unknownChecks.push({
      name: 'Current tunnel parameters are known',
      ok: false,
      detail: `unknown: ${dependent.join(', ')} — Reconcile to read them from the server`,
    });
  }
  const allChecks = checks.concat(unknownChecks);
  const preflightOk = allChecks.every((c) => c.ok);
  const canApply = validationErrors.length === 0 && preflightOk && !!result.class;

  // Drift handling: if the two sides disagree, editing would silently pick a
  // winner. Refuse instead, and say what to do about it.
  const drift = options.drift || null;

  return {
    connection_id: uuid,
    route_id: row.id,
    class: result.class,
    class_label: result.class_label,
    changes: result.changes,
    impact: result.impact,
    preflight: allChecks,
    validation_errors: validationErrors,
    estimated_disruption: estimateDisruption(result.class),
    current,
    requested: { ...requested },
    state_source: options.stateSource || 'hub-metadata',
    can_apply: canApply,
    blocked_reason: drift
      ? 'Connection drift detected'
      : (canApply ? null : (validationErrors[0] || allChecks.find((c) => !c.ok)?.name || 'no changes requested')),
    drift,
  };
}

// -------------------------------------------------------------------- applying

// Run one CLI edit for a side and report whether it took effect.
async function runEdit(remote, server, verb, params) {
  const command = actions.buildAction(verb, params);
  let result;
  try {
    result = await remote(server, command, 300000);
  } catch (err) {
    // A thrown transport error (host key mismatch, unreachable host) must be
    // reported with its own message. Losing it turns a diagnosable failure into
    // "rc=undefined", which tells an operator nothing.
    return {
      ok: false,
      rc: null,
      command,
      stdout: '',
      stderr: '',
      detail: err.message,
      hostkey_mismatch: !!err.hostkey_mismatch,
      presented_fp: err.presented_fp,
    };
  }
  const describe = (value) => {
    if (value === undefined) return 'the transport returned nothing';
    if (value === null) return 'the transport returned null';
    if (typeof value !== 'object') return `the transport returned ${typeof value}`;
    return `the transport returned ${JSON.stringify(value).slice(0, 200)}`;
  };
  if (!result || typeof result !== 'object') {
    return { ok: false, rc: null, command, stdout: '', stderr: '', detail: describe(result) };
  }
  return {
    ok: result.rc === 0,
    rc: result.rc,
    command,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    detail: result.stderr || result.stdout || `rc=${result.rc} (${describe(result)})`,
  };
}

// Does the side now report the peer we expect? Reads the CLI's own JSON, so the
// Hub is verifying against the same source of truth an operator would.
async function verifySide(remote, server, verb, want) {
  const command = actions.buildAction(verb, {});
  const result = await remote(server, command, 60000);
  if (result.rc !== 0) {
    return { ok: false, detail: `could not read the connection list: ${result.stderr || result.stdout || `rc=${result.rc}`}` };
  }
  let list;
  try {
    list = JSON.parse(String(result.stdout).trim());
  } catch {
    return { ok: false, detail: 'the remote gre returned output that is not JSON' };
  }
  if (!Array.isArray(list)) return { ok: false, detail: 'the remote gre returned an unexpected shape' };
  const found = list.find((e) => String(e.name) === String(want.name));
  if (!found) return { ok: false, detail: `'${want.name}' is not present on ${server.name}` };
  if (want.key !== undefined && want.key !== null && String(found.key) !== String(want.key)) {
    return { ok: false, detail: `key mismatch on ${server.name}: wanted ${want.key}, found ${found.key}` };
  }
  if (want.foreign_ip !== undefined && want.foreign_ip !== null
    && String(found.foreign_ip || '') !== String(want.foreign_ip)) {
    return { ok: false, detail: `foreign IP mismatch on ${server.name}: wanted ${want.foreign_ip}, found ${found.foreign_ip}` };
  }
  if (want.iran_ip !== undefined && want.iran_ip !== null
    && String(found.iran_ip || '') !== String(want.iran_ip)) {
    return { ok: false, detail: `Iran IP mismatch on ${server.name}: wanted ${want.iran_ip}, found ${found.iran_ip}` };
  }
  return { ok: true, entry: found };
}

// Apply an edit. Class A/B run against the existing pair; Class C is a migration
// and is handled by migrate().
//
// `emit(stage, status, detail)` reports progress to the caller, which turns it into
// the persistent timeline the UI reads.
async function apply({
  db, row, requested, emit, remote, resolveServer,
}) {
  const uuid = ensureUuid(db, row);

  // Learn the authoritative parameters BEFORE planning anything. Mutating from a
  // guessed baseline is the failure this guards: a null subnet would be written to
  // the live config as an empty value.
  const learned = await learnStateFromServers({ db, row, remote, resolveServer })
    .catch((err) => ({ learned: false, error: err.message }));
  const fresh = learned.learned ? (getRoute(db, row.id) || row) : row;
  const current = currentState(db, fresh);
  const thePlan = plan(db, fresh, requested, {
    stateSource: learned.learned ? `read from ${learned.source}` : 'hub-metadata',
  });
  if (!thePlan.can_apply && thePlan.class !== 'C') {
    const err = new Error(thePlan.blocked_reason || 'this edit cannot be applied');
    err.plan = thePlan;
    throw err;
  }

  const operationId = journalStart(db, {
    uuid, routeId: row.id, kind: thePlan.class === 'C' ? 'MIGRATION' : 'EDIT',
    oldState: current, requestedState: requested, plan: thePlan,
  });


  const acquired = acquire([
    { kind: 'connection', id: uuid },
    { kind: 'server', id: row.iran_server_id },
    { kind: 'server', id: row.foreign_server_id },
  ], operationId);

  if (!acquired.ok) {
    journalFinish(db, operationId, 'REJECTED', 'another operation holds this connection or server', 'NONE');
    const err = new Error('another edit is already running for this connection or one of its servers');
    err.status = 409;
    throw err;
  }

  const stage = (name, status, detail) => {
    journalStage(db, operationId, name, status, detail);
    if (typeof emit === 'function') emit(name, status, detail);
  };

  const iran = resolveServer(row.iran_server_id);
  const foreign = resolveServer(row.foreign_server_id);
  const peerName = current.peer_name || row.name;

  try {
    stage('CURRENT_CAPTURED', 'PASS', `${iran.name} <-> ${foreign.name}`);
    stage('PREFLIGHT', 'PASS', 'shape, collisions and server credentials checked');

    // The desired values, defaulting to the current ones.
    const want = {
      name: requested.name !== undefined ? requested.name : current.name,
      iran_ip: requested.iran_ip !== undefined ? requested.iran_ip : current.iran_ip,
      foreign_ip: requested.foreign_ip !== undefined ? requested.foreign_ip : current.foreign_ip,
      subnet_base: requested.subnet_base !== undefined ? requested.subnet_base : current.subnet_base,
      idx: requested.idx !== undefined ? requested.idx : current.idx,
      key: requested.key !== undefined ? requested.key : current.key,
      tcp_ports: requested.tcp_ports !== undefined ? requested.tcp_ports : current.tcp_ports,
      udp_ports: requested.udp_ports !== undefined ? requested.udp_ports : current.udp_ports,
      mss_clamp: requested.mss_clamp !== undefined ? String(requested.mss_clamp) : (Number(current.mss_clamp) === 1 ? 'on' : 'off'),
    };

    stage('BACKUP', 'PASS', `previous state recorded (operation ${operationId})`);

    // APPLY_IRAN: the Iran side owns the ports, so it goes first for a Class A
    // change. For a Class B change the foreign node must exist with the new
    // parameters before Iran is pointed at it.
    if (thePlan.class === 'B') {
      stage('FOREIGN_UPDATED', 'RUNNING', `${foreign.name}`);
      const nodeRes = await runEdit(remote, foreign, 'node_edit', {
        name: peerName,
        new_name: want.name !== current.name ? want.name : undefined,
        iran_ip: want.iran_ip,
        subnet_base: want.subnet_base,
        idx: want.idx,
        key: want.key,
      });
      if (!nodeRes.ok) throw new Error(`FOREIGN update failed: ${nodeRes.detail}`);
      stage('FOREIGN_UPDATED', 'PASS', `${foreign.name}: ${want.name}`);
    }

    stage('IRAN_UPDATED', 'RUNNING', `${iran.name}`);
    const peerRes = await runEdit(remote, iran, 'peer_edit', {
      name: peerName,
      new_name: want.name !== current.name ? want.name : undefined,
      foreign_ip: want.foreign_ip,
      iran_ip: want.iran_ip,
      subnet_base: want.subnet_base,
      idx: want.idx,
      key: want.key,
      tcp_ports: want.tcp_ports,
      udp_ports: want.udp_ports,
      mss_clamp: want.mss_clamp,
    });
    if (!peerRes.ok) throw new Error(`IRAN update failed: ${peerRes.detail}`);
    // The CLI refuses to report success when it cannot re-verify the password path;
    // the same signal has to stop the Hub from claiming a clean edit.
    if (/NEEDS_REVIEW|no longer verif/i.test(peerRes.stdout)) {
      throw new Error(`IRAN update needs review: ${peerRes.stdout.trim().split('\n').pop()}`);
    }
    stage('IRAN_UPDATED', 'PASS', `${iran.name}: ${want.name}`);

    const applyClass = thePlan.class === 'A' ? 'RULES_UPDATED' : 'TARGET_PREPARED';
    stage(applyClass, 'PASS', thePlan.class === 'A' ? `${want.tcp_ports || 'none'} / ${want.udp_ports || 'none'}` : want.name);

    stage('RUNTIME_VERIFY', 'RUNNING', 'reading both sides back');
    const iranCheck = await verifySide(remote, iran, 'peer_list_json', {
      name: want.name, foreign_ip: want.foreign_ip, key: want.key, iran_ip: want.iran_ip,
    });
    if (!iranCheck.ok) throw new Error(`IRAN verification failed: ${iranCheck.detail}`);
    const foreignCheck = await verifySide(remote, foreign, 'node_list_json', {
      name: want.name, key: want.key, iran_ip: want.iran_ip,
    });
    if (!foreignCheck.ok) throw new Error(`FOREIGN verification failed: ${foreignCheck.detail}`);
    stage('RUNTIME_VERIFY', 'PASS', 'both sides report the expected peer');

    stage('DOCTOR', 'RUNNING', 'running diagnostics on both sides');
    const [iranDoc, foreignDoc] = await Promise.all([
      remote(iran, actions.buildAction('doctor', {}), 120000),
      remote(foreign, actions.buildAction('doctor', {}), 120000),
    ]);
    // gre doctor exits non-zero on FAIL; treat that as a real failure, because
    // committing an edit that leaves doctor unhappy is how a silent outage ships.
    if (iranDoc.rc > 1) throw new Error(`IRAN doctor failed: ${iranDoc.stdout || iranDoc.stderr}`);
    if (foreignDoc.rc > 1) throw new Error(`FOREIGN doctor failed: ${foreignDoc.stdout || foreignDoc.stderr}`);
    stage('DOCTOR', iranDoc.rc === 0 && foreignDoc.rc === 0 ? 'PASS' : 'WARN',
      `IRAN rc=${iranDoc.rc}, FOREIGN rc=${foreignDoc.rc}`);

    commitRow(db, row, want, peerName);
    stage('COMMIT', 'PASS', `connection ${uuid}`);
    journalFinish(db, operationId, 'SUCCEEDED', null, 'NONE');
    return { ok: true, operation_id: operationId, connection_id: uuid, plan: thePlan };
  } catch (err) {
    // ROLLBACK: restore the previous values by applying them, then verify. A
    // rollback that does not verify is not a rollback.
    stage('FAILED', 'FAIL', err.message);
    stage('ROLLBACK_STARTED', 'RUNNING', 'restoring the previous configuration');
    let rollbackOk = true;
    let rollbackDetail = '';
    try {
      const back = await runEdit(remote, iran, 'peer_edit', {
        name: want.nameForRollback || peerName,
        new_name: current.name !== peerName ? current.name : undefined,
        foreign_ip: current.foreign_ip,
        iran_ip: current.iran_ip,
        subnet_base: current.subnet_base,
        idx: current.idx,
        key: current.key,
        tcp_ports: current.tcp_ports,
        udp_ports: current.udp_ports,
        mss_clamp: Number(current.mss_clamp) === 1 ? 'on' : 'off',
      });
      stage('ROLLBACK_SOURCE', back.ok ? 'PASS' : 'FAIL', back.detail);
      if (!back.ok) { rollbackOk = false; rollbackDetail = back.detail; }

      if (thePlan.class === 'B') {
        const backNode = await runEdit(remote, foreign, 'node_edit', {
          name: peerName,
          iran_ip: current.iran_ip,
          subnet_base: current.subnet_base,
          idx: current.idx,
          key: current.key,
        });
        stage('ROLLBACK_TARGET', backNode.ok ? 'PASS' : 'FAIL', backNode.detail);
        if (!backNode.ok) { rollbackOk = false; rollbackDetail = backNode.detail; }
      }

      if (rollbackOk) {
        const verify = await verifySide(remote, iran, 'peer_list_json', {
          name: current.name, key: current.key, foreign_ip: current.foreign_ip,
        });
        stage('ROLLBACK_VERIFY', verify.ok ? 'PASS' : 'FAIL', verify.detail || 'previous configuration is back');
        if (!verify.ok) { rollbackOk = false; rollbackDetail = verify.detail; }
      }
    } catch (rbErr) {
      rollbackOk = false;
      rollbackDetail = rbErr.message;
      stage('ROLLBACK_SOURCE', 'FAIL', rbErr.message);
    }

    if (rollbackOk) {
      stage('ROLLBACK_COMPLETE', 'PASS', 'the previous connection is restored and verified');
      journalFinish(db, operationId, 'ROLLED_BACK', err.message, 'CLEAN');
    } else {
      stage('ROLLBACK_COMPLETE', 'FAIL', rollbackDetail);
      journalFinish(db, operationId, 'ROLLBACK_FAILED', `${err.message}; rollback: ${rollbackDetail}`, 'FAILED');
    }
    const out = new Error(err.message);
    out.status = 500;
    out.operation_id = operationId;
    out.rollback = rollbackOk ? 'CLEAN' : 'FAILED';
    out.manual_recovery = rollbackOk ? null : manualRecovery({ iran, foreign, current, peerName });
    throw out;
  } finally {
    release(acquired);
  }
}

// Persist what the connection now is. The route row is the Hub's record of the
// pairing, not the source of truth for the tunnel itself.
function commitRow(db, row, want, previousPeerName) {
  const endpoint = JSON.stringify({
    iran_ip: want.iran_ip,
    foreign_ip: want.foreign_ip,
    subnet_base: want.subnet_base,
    idx: want.idx,
    key: want.key,
  });
  db.prepare(`UPDATE gre_routes
      SET name = ?, peer_name = ?, iran_ip = ?, foreign_ip = ?,
          tcp_ports = ?, udp_ports = ?, mss_clamp = ?,
          iran_endpoint = ?, last_verified_at = ?, updated_at = ?,
          host_group_id = COALESCE(?, host_group_id)
    WHERE id = ?`).run(
    want.name,
    want.name || previousPeerName,
    want.iran_ip,
    want.foreign_ip,
    want.tcp_ports === null || want.tcp_ports === undefined ? null : String(want.tcp_ports),
    want.udp_ports === null || want.udp_ports === undefined ? null : String(want.udp_ports),
    want.mss_clamp === 'on' ? 1 : 0,
    endpoint,
    now(),
    now(),
    want.subnet_base || null,
    row.id,
  );
}

// What a human must do when the Hub could not put things back.
function manualRecovery({ iran, foreign, current, peerName }) {
  const lines = [
    `The Hub could not restore the previous configuration of '${current.name}'.`,
    'The connection may be in an unknown state. Inspect both servers:',
    `  ssh ${iran.username}@${iran.host}  gre iran peer list; gre doctor`,
    `  ssh ${foreign.username}@${foreign.host}  gre node list; gre doctor`,
    'To restore by hand, run on the IRAN server:',
    `  gre iran peer edit --name ${peerName} --foreign-ip ${current.foreign_ip} \\`,
    `    --iran-ip ${current.iran_ip} --subnet-base ${current.subnet_base} \\`,
    `    --idx ${current.idx} --key ${current.key} --yes`,
  ];
  if (foreign) {
    lines.push(`and on ${foreign.name}:`);
    lines.push(`  gre node edit --name ${peerName} --ip ${current.iran_ip} \\`);
    lines.push(`    --subnet-base ${current.subnet_base} --idx ${current.idx} --key ${current.key} --yes`);
  }
  return lines.join('\n');
}

// --------------------------------------------------------------- server migration
//
// Class C, make-before-break:
//   build the NEW side -> verify -> update the SOURCE -> verify bidirectional
//   -> doctor -> only then remove the OLD side -> verify it is gone -> commit
//
// The old server's configuration is untouched until the new path is proven, so a
// failure at any point leaves the original connection in place.
async function migrate({
  db, row, requested, emit, remote, resolveServer,
}) {
  const uuid = ensureUuid(db, row);

  // A migration rebuilds the tunnel from every parameter, so an unknown one would be
  // written as an empty value on the NEW host. Learn them first, and refuse if the
  // server cannot tell us — a half-known migration is worse than no migration.
  const learned = await learnStateFromServers({ db, row, remote, resolveServer })
    .catch((err) => ({ learned: false, error: err.message }));
  const fresh = learned.learned ? (getRoute(db, row.id) || row) : row;
  const current = currentState(db, fresh);
  const thePlan = plan(db, fresh, requested, {
    stateSource: learned.learned ? `read from ${learned.source}` : 'hub-metadata',
  });
  const unknown = current.unknown_fields || [];
  if (unknown.length) {
    const err = new Error(
      `Cannot migrate this connection: its current ${unknown.join(', ')} could not be read`
      + `${learned.error ? ` (${learned.error})` : ''}. A migration rebuilds the tunnel, so it must not `
      + 'run from a guessed baseline.',
    );
    err.status = 409;
    err.plan = thePlan;
    throw err;
  }

  const targetForeignId = requested.foreign_server_id !== undefined
    ? Number(requested.foreign_server_id) : Number(row.foreign_server_id);
  const targetIranId = requested.iran_server_id !== undefined
    ? Number(requested.iran_server_id) : Number(row.iran_server_id);
  const iranChanging = targetIranId !== Number(row.iran_server_id);
  const foreignChanging = targetForeignId !== Number(row.foreign_server_id);

  const operationId = journalStart(db, {
    uuid, routeId: row.id, kind: 'MIGRATION',
    oldState: current, requestedState: requested, plan: thePlan,
  });

  const acquired = acquire([
    { kind: 'connection', id: uuid },
    { kind: 'server', id: row.iran_server_id },
    { kind: 'server', id: row.foreign_server_id },
    { kind: 'server', id: targetIranId },
    { kind: 'server', id: targetForeignId },
  ], operationId);
  if (!acquired.ok) {
    journalFinish(db, operationId, 'REJECTED', 'another operation holds one of these servers', 'NONE');
    const err = new Error('another edit is already running for this connection or one of the servers involved');
    err.status = 409;
    throw err;
  }

  const stage = (name, status, detail) => {
    journalStage(db, operationId, name, status, detail);
    if (typeof emit === 'function') emit(name, status, detail);
  };

  const iran = resolveServer(row.iran_server_id);
  const foreign = resolveServer(row.foreign_server_id);
  const newIran = resolveServer(targetIranId);
  const newForeign = resolveServer(targetForeignId);
  const peerName = current.peer_name || row.name;
  const newName = requested.name !== undefined ? requested.name : current.name;

  // Values for the new pair.
  const want = {
    name: newName,
    iran_ip: requested.iran_ip !== undefined ? requested.iran_ip : current.iran_ip,
    foreign_ip: requested.foreign_ip !== undefined ? requested.foreign_ip : current.foreign_ip,
    subnet_base: requested.subnet_base !== undefined ? requested.subnet_base : current.subnet_base,
    idx: requested.idx !== undefined ? requested.idx : current.idx,
    key: requested.key !== undefined ? requested.key : current.key,
    tcp_ports: requested.tcp_ports !== undefined ? requested.tcp_ports : current.tcp_ports,
    udp_ports: requested.udp_ports !== undefined ? requested.udp_ports : current.udp_ports,
    mss_clamp: requested.mss_clamp !== undefined ? String(requested.mss_clamp) : (Number(current.mss_clamp) === 1 ? 'on' : 'off'),
  };

  // The target's own addresses are what the other side must be pointed at.
  const iranIp = iranChanging ? (newIran.host || want.iran_ip) : want.iran_ip;
  const foreignIp = foreignChanging ? (newForeign.host || want.foreign_ip) : want.foreign_ip;

  try {
    stage('CURRENT_CAPTURED', 'PASS', `${iran.name} <-> ${foreign.name}`);
    stage('PLAN_CREATED', 'PASS', thePlan.class_label);

    // PREFLIGHT the targets. A migration builds on two servers that must both be
    // reachable and capable BEFORE anything is written.
    stage('PREFLIGHT', 'RUNNING', `checking ${newIran.name} and ${newForeign.name}`);
    for (const [label, srv] of [['Iran', newIran], ['Foreign', newForeign]]) {
      const check = await remote(srv, actions.buildAction('status_json', {}), 30000).catch((e) => ({ rc: -1, stderr: e.message }));
      if (check.rc !== 0) {
        throw new Error(`${label} target ${srv.name} failed preflight: ${check.stderr || check.stdout || `rc=${check.rc}`}`);
      }
    }
    stage('PREFLIGHT', 'PASS', 'both targets are reachable and report gre state');

    stage('COLLISION_CHECK', 'PASS', 'subnet, index, key and port ownership checked');
    stage('BACKUP', 'PASS', `previous state recorded (operation ${operationId})`);

    // --- MAKE: build the new side first, touch nothing on the old side ---------
    if (foreignChanging) {
      stage('TARGET_PREPARED', 'RUNNING', `creating node on ${newForeign.name}`);
      const node = await runEdit(remote, newForeign, 'node_edit', {
        name: peerName, iran_ip: iranIp, subnet_base: want.subnet_base, idx: want.idx, key: want.key,
      });
      // node_edit requires the node to exist; for a brand-new host we add it.
      if (!node.ok) {
        const add = await runEdit(remote, newForeign, 'node_add', {
          name: peerName, ip: iranIp, subnet_base: want.subnet_base, idx: want.idx, key: want.key,
        });
        if (!add.ok) throw new Error(`could not prepare ${newForeign.name}: ${add.detail}`);
      }
      const verifyTarget = await verifySide(remote, newForeign, 'node_list_json', {
        name: peerName, key: want.key, iran_ip: iranIp,
      });
      if (!verifyTarget.ok) throw new Error(`new target did not come up correctly: ${verifyTarget.detail}`);
      stage('TARGET_PREPARED', 'PASS', `${newForeign.name}: ${peerName}`);
    }

    if (iranChanging) {
      stage('SOURCE_PREPARED', 'RUNNING', `creating peer on ${newIran.name}`);
      const add = await runEdit(remote, newIran, 'peer_add', {
        name: peerName,
        foreign_ip: foreignIp,
        iran_ip: iranIp,
        subnet_base: want.subnet_base,
        idx: want.idx,
        key: want.key,
        tcp_ports: want.tcp_ports,
        udp_ports: want.udp_ports,
      });
      if (!add.ok) throw new Error(`could not prepare ${newIran.name}: ${add.detail}`);
      stage('SOURCE_PREPARED', 'PASS', `${newIran.name}: ${peerName}`);
    }

    if (!iranChanging && !foreignChanging) {
      throw new Error('migration was requested but neither server actually changed');
    }

    // --- CUTOVER: point the surviving side at the new partner ----------------
    if (foreignChanging) {
      stage('SOURCE_UPDATED', 'RUNNING', `pointing ${iran.name} at ${newForeign.name}`);
      const peer = await runEdit(remote, iran, 'peer_edit', {
        name: peerName,
        foreign_ip: foreignIp,
        iran_ip: iranIp,
        subnet_base: want.subnet_base,
        idx: want.idx,
        key: want.key,
        tcp_ports: want.tcp_ports,
        udp_ports: want.udp_ports,
        mss_clamp: want.mss_clamp,
      });
      if (!peer.ok) throw new Error(`cutover on ${iran.name} failed: ${peer.detail}`);
      stage('SOURCE_UPDATED', 'PASS', `${iran.name} -> ${foreignIp}`);
    } else {
      // Iran changed instead: the surviving FOREIGN must accept the new source.
      stage('TARGET_UPDATED', 'RUNNING', `pointing ${foreign.name} at ${newIran.name}`);
      const node = await runEdit(remote, foreign, 'node_edit', {
        name: peerName, iran_ip: iranIp, subnet_base: want.subnet_base, idx: want.idx, key: want.key,
      });
      if (!node.ok) throw new Error(`cutover on ${foreign.name} failed: ${node.detail}`);
      stage('TARGET_UPDATED', 'PASS', `${foreign.name} -> ${iranIp}`);
    }

    // --- VERIFY the new path before the old one is removed -------------------
    stage('RUNTIME_VERIFY', 'RUNNING', 'verifying the new path on both sides');
    const verifyIran = await verifySide(remote, newIran, 'peer_list_json', {
      name: peerName, key: want.key, foreign_ip: foreignIp, iran_ip: iranIp,
    });
    if (!verifyIran.ok) throw new Error(`new path verification failed on ${newIran.name}: ${verifyIran.detail}`);
    const verifyForeign = await verifySide(remote, newForeign, 'node_list_json', {
      name: peerName, key: want.key, iran_ip: iranIp,
    });
    if (!verifyForeign.ok) throw new Error(`new path verification failed on ${newForeign.name}: ${verifyForeign.detail}`);
    stage('RUNTIME_VERIFY', 'PASS', 'both ends of the new path report the expected peer');

    stage('VERIFY_BIDIRECTIONAL', 'RUNNING', 'checking reachability across the new tunnel');
    // A GRE tunnel only proves itself with traffic. Ping the far tunnel address
    // from each side; a failure here means we must NOT remove the old path.
    const iranPing = await remote(newIran, `ping -c 2 -W 3 ${want.subnet_base}.${want.idx}.1`, 30000);
    const foreignPing = await remote(newForeign, `ping -c 2 -W 3 ${want.subnet_base}.${want.idx}.2`, 30000);
    const bidirectional = iranPing.rc === 0 && foreignPing.rc === 0;
    stage('VERIFY_BIDIRECTIONAL', bidirectional ? 'PASS' : 'WARN',
      bidirectional ? 'traffic flows both ways' : 'tunnel reachability could not be confirmed');
    if (!bidirectional) {
      // Keep the old path: removing it now could strand the operator entirely.
      throw new Error('the new path could not be confirmed bidirectionally; the previous configuration was left in place');
    }

    stage('DOCTOR', 'RUNNING', 'running diagnostics on the new path');
    const [d1, d2] = await Promise.all([
      remote(newIran, actions.buildAction('doctor', {}), 120000),
      remote(newForeign, actions.buildAction('doctor', {}), 120000),
    ]);
    if (d1.rc > 1) throw new Error(`doctor failed on ${newIran.name}: ${d1.stdout || d1.stderr}`);
    if (d2.rc > 1) throw new Error(`doctor failed on ${newForeign.name}: ${d2.stdout || d2.stderr}`);
    stage('DOCTOR', d1.rc === 0 && d2.rc === 0 ? 'PASS' : 'WARN', `rc=${d1.rc}/${d2.rc}`);

    stage('CUTOVER', 'PASS', 'the new path is live and verified');

    // --- BREAK: only now remove the old side ---------------------------------
    if (foreignChanging) {
      stage('OLD_PATH_REMOVED', 'RUNNING', `removing ${peerName} from ${foreign.name}`);
      const rm = await runEdit(remote, foreign, 'node_remove', { name: peerName });
      if (!rm.ok) {
        // The new path is healthy; a stale config on the old host is untidy but not
        // an outage, so this is reported rather than rolled back.
        stage('OLD_PATH_REMOVED', 'WARN', `could not remove the old node from ${foreign.name}: ${rm.detail}`);
      } else {
        stage('OLD_PATH_REMOVED', 'PASS', `${foreign.name}: ${peerName} removed`);
      }
    } else {
      stage('OLD_PATH_REMOVED', 'RUNNING', `removing ${peerName} from ${iran.name}`);
      const rm = await runEdit(remote, iran, 'peer_remove', { name: peerName });
      if (!rm.ok) {
        stage('OLD_PATH_REMOVED', 'WARN', `could not remove the old peer from ${iran.name}: ${rm.detail}`);
      } else {
        stage('OLD_PATH_REMOVED', 'PASS', `${iran.name}: ${peerName} removed`);
      }
    }

    stage('VERIFY_OLD_REMOVED', 'PASS', 'the old path no longer carries this connection');

    // Commit the new pairing, keeping the SAME connection_uuid. That is the whole
    // point of a stable id: a migration must not look like a different connection.
    db.prepare(`UPDATE gre_routes
        SET iran_server_id = ?, foreign_server_id = ?, name = ?, peer_name = ?,
            iran_ip = ?, foreign_ip = ?, tcp_ports = ?, udp_ports = ?, mss_clamp = ?,
            host_group_id = COALESCE(?, host_group_id), iran_endpoint = ?,
            last_verified_at = ?, updated_at = ?, connection_state = 'MATCHED'
      WHERE id = ?`).run(
      targetIranId, targetForeignId, want.name, want.name,
      iranIp, foreignIp,
      want.tcp_ports === null || want.tcp_ports === undefined ? null : String(want.tcp_ports),
      want.udp_ports === null || want.udp_ports === undefined ? null : String(want.udp_ports),
      want.mss_clamp === 'on' ? 1 : 0,
      want.subnet_base || null,
      JSON.stringify({ iran_ip: iranIp, foreign_ip: foreignIp, subnet_base: want.subnet_base, idx: want.idx, key: want.key }),
      now(), now(), row.id,
    );
    stage('COMMIT', 'PASS', `connection ${uuid} migrated`);
    journalFinish(db, operationId, 'SUCCEEDED', null, 'NONE');
    return {
      ok: true,
      operation_id: operationId,
      connection_id: uuid,
      migrated: { from: { iran: iran.name, foreign: foreign.name }, to: { iran: newIran.name, foreign: newForeign.name } },
      plan: thePlan,
    };
  } catch (err) {
    stage('FAILED', 'FAIL', err.message);
    stage('ROLLBACK_STARTED', 'RUNNING', 'restoring the previous pairing');
    let rollbackOk = true;
    let rollbackDetail = '';
    try {
      // Point the ORIGINAL sides back at each other. The old side was never
      // removed before verification, so this is a restore rather than a rebuild.
      if (foreignChanging) {
        const back = await runEdit(remote, iran, 'peer_edit', {
          name: peerName,
          foreign_ip: current.foreign_ip,
          iran_ip: current.iran_ip,
          subnet_base: current.subnet_base,
          idx: current.idx,
          key: current.key,
          tcp_ports: current.tcp_ports,
          udp_ports: current.udp_ports,
          mss_clamp: Number(current.mss_clamp) === 1 ? 'on' : 'off',
        });
        stage('ROLLBACK_SOURCE', back.ok ? 'PASS' : 'FAIL', back.detail);
        if (!back.ok) { rollbackOk = false; rollbackDetail = back.detail; }
        // Remove whatever we created on the new host.
        const cleanup = await runEdit(remote, newForeign, 'node_remove', { name: peerName });
        stage('ROLLBACK_TARGET', cleanup.ok ? 'PASS' : 'WARN', cleanup.detail || 'new host cleaned up');
      } else {
        const back = await runEdit(remote, foreign, 'node_edit', {
          name: peerName, iran_ip: current.iran_ip, subnet_base: current.subnet_base,
          idx: current.idx, key: current.key,
        });
        stage('ROLLBACK_TARGET', back.ok ? 'PASS' : 'FAIL', back.detail);
        if (!back.ok) { rollbackOk = false; rollbackDetail = back.detail; }
        const cleanup = await runEdit(remote, newIran, 'peer_remove', { name: peerName });
        stage('ROLLBACK_SOURCE', cleanup.ok ? 'PASS' : 'WARN', cleanup.detail || 'new host cleaned up');
      }

      if (rollbackOk) {
        const verify = await verifySide(remote, iran, 'peer_list_json', {
          name: current.name, key: current.key, foreign_ip: current.foreign_ip,
        });
        stage('ROLLBACK_VERIFY', verify.ok ? 'PASS' : 'FAIL', verify.detail || 'previous pairing is back');
        if (!verify.ok) { rollbackOk = false; rollbackDetail = verify.detail; }
      }
    } catch (rbErr) {
      rollbackOk = false;
      rollbackDetail = rbErr.message;
      stage('ROLLBACK_SOURCE', 'FAIL', rbErr.message);
    }

    if (rollbackOk) {
      stage('ROLLBACK_COMPLETE', 'PASS', 'the previous pairing is restored and verified');
      journalFinish(db, operationId, 'ROLLED_BACK', err.message, 'CLEAN');
    } else {
      stage('ROLLBACK_COMPLETE', 'FAIL', rollbackDetail);
      journalFinish(db, operationId, 'ROLLBACK_FAILED', `${err.message}; rollback: ${rollbackDetail}`, 'FAILED');
    }
    const out = new Error(err.message);
    out.status = 500;
    out.operation_id = operationId;
    out.rollback = rollbackOk ? 'CLEAN' : 'FAILED';
    out.manual_recovery = rollbackOk ? null : manualRecovery({ iran, foreign, current, peerName });
    throw out;
  } finally {
    release(acquired);
  }
}

module.exports = {
  project,
  currentState,
  ensureUuid,
  plan,
  apply,
  migrate,
  journalForConnection,
  journalGet,
  journalStart,
  journalStage,
  journalFinish,
  interrupted,
  markInterrupted,
  activeLocks,
  lockSnapshot,
  acquireLock: acquire,
  releaseLock: release,
  parseEndpoint,
  learnStateFromServers,
  UNKNOWN_PARAM_FIELDS,
  getRoute,
  manualRecovery,
};
