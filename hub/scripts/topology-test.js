'use strict';

// Topology preservation across transient discovery failures.
//
// This is the production bug: a temporary SSH/probe failure emptied
// snapshot.roles, the bytes overwrote the last good snapshot, and the UI dropped
// a FOREIGN server into UNCONFIGURED. These tests pin the invariant that a failed
// probe is an AVAILABILITY fact which cannot change TOPOLOGY.

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  assert, makeHarness, check, checkAsync, report,
} = require('./_harness');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');
const discovery = require('../server/discovery');
const { DiscoveryQueue, readConcurrency, DEFAULT_CONCURRENCY } = require('../server/discovery-queue');
const topology = require('../public/server-topology');

// ---------------------------------------------------------------------------
// A miniature hub: the same persistence rules the routes use, without HTTP.
// ---------------------------------------------------------------------------
function makeStore() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-topology-'));
  const db = openDb(dataDir);
  const key = cryptoUtil.loadKey(dataDir);
  const now = Date.now();
  const insert = (sql, ...params) => Number(db.prepare(sql).run(...params).lastInsertRowid);
  const addServer = (name) => insert(
    'INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
    name, `10.0.0.${insert}`, 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw'), now,
  );
  const getSnapshot = (id) => {
    const row = db.prepare('SELECT json FROM snapshots WHERE server_id=?').get(id);
    return row ? JSON.parse(row.json) : null;
  };
  const saveSnapshot = (id, snapshot) => {
    db.prepare('INSERT INTO snapshots (server_id,json,taken_at) VALUES (?,?,?) ON CONFLICT(server_id) DO UPDATE SET json=excluded.json, taken_at=excluded.taken_at')
      .run(id, JSON.stringify(snapshot), Date.now());
  };
  // Transport health and discovery health are stored in SEPARATE columns, exactly
  // as the hub does: a successful health ping must not clear a discovery failure.
  const saveProbe = (id, probe, kind) => {
    const ok = probe.ok ? 1 : 0;
    const at = probe.checkedAt || Date.now();
    const dur = probe.durationMs || 0;
    const cls = probe.ok ? null : (probe.errorClass || 'transport');
    const msg = probe.ok ? null : (probe.detail || null);
    db.prepare('INSERT INTO server_probe_state (server_id,ok,checked_at,duration_ms,error_class,error_message,kind) VALUES (?,?,?,?,?,?,?) ON CONFLICT(server_id) DO NOTHING')
      .run(id, ok, at, dur, cls, msg, kind);
    if (kind === 'health') {
      db.prepare('UPDATE server_probe_state SET health_ok=?,health_checked_at=?,health_duration_ms=?,health_error_class=?,health_error_message=? WHERE server_id=?')
        .run(ok, at, dur, cls, msg, id);
    } else {
      db.prepare('UPDATE server_probe_state SET discovery_ok=?,discovery_checked_at=?,discovery_duration_ms=?,discovery_error_class=?,discovery_error_message=? WHERE server_id=?')
        .run(ok, at, dur, cls, msg, id);
    }
  };
  const axis = (ok, at, dur, cls, msg) => (at === null || at === undefined
    ? { ok: null, checked_at: null, error: null, reason: null, error_class: null, stale_for_ms: null }
    : {
      ok: !!ok,
      checked_at: Number(at),
      duration_ms: dur === null || dur === undefined ? null : Number(dur),
      error: ok ? null : (msg || null),
      error_class: ok ? null : (cls || 'transport'),
      reason: ok ? null : discovery.errorReason(cls),
      stale_for_ms: Math.max(0, Date.now() - Number(at)),
    });
  const getProbe = (id) => {
    const row = db.prepare('SELECT * FROM server_probe_state WHERE server_id=?').get(id);
    if (!row) return { health: axis(null), discovery: axis(null) };
    return {
      health: axis(row.health_ok, row.health_checked_at, row.health_duration_ms, row.health_error_class, row.health_error_message),
      discovery: axis(row.discovery_ok, row.discovery_checked_at, row.discovery_duration_ms, row.discovery_error_class, row.discovery_error_message),
    };
  };
  // Exactly the route's rule: only a successful discovery writes the snapshot.
  const applyOutcome = (id, outcome) => {
    if (outcome.ok) {
      saveSnapshot(id, outcome.snapshot);
      saveProbe(id, outcome, 'full');
      return { ok: true };
    }
    saveProbe(id, outcome, 'full');
    return { ok: false, errorClass: outcome.errorClass };
  };
  return {
    db, dataDir, addServer, getSnapshot, saveSnapshot, getProbe, applyOutcome,
    serverView(id, name) { return { id, name, snapshot: getSnapshot(id), probe: getProbe(id) }; },
    cleanup() { try { db.close(); } catch {} try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {} },
  };
}

function goodOutcome(roles, takenAt = new Date().toISOString()) {
  return {
    ok: true,
    snapshot: { taken_at: takenAt, roles, manager: { installed: true, version: '2.8.2' }, status: {}, legacy: { present: false } },
    checkedAt: Date.now(), durationMs: 40,
  };
}
function failedOutcome(errorClass = 'timeout', detail = 'command timed out after 60000ms') {
  return { ok: false, errorClass, reason: discovery.errorReason(errorClass), detail, checkedAt: Date.now(), durationMs: 60000 };
}
function absentManagerOutcome() {
  return {
    ok: true,
    snapshot: { taken_at: new Date().toISOString(), roles: [], manager: { installed: false, version: null }, status: null, legacy: { present: false } },
    checkedAt: Date.now(), durationMs: 30,
  };
}

async function main() {
  console.log('TEST 1 — a successful discovery is the authoritative snapshot:');
  await checkAsync('roles=["FOREIGN"] is stored and groups as FOREIGN', async () => {
    const store = makeStore();
    try {
      const id = store.addServer('Hetz2');
      store.applyOutcome(id, goodOutcome(['FOREIGN']));
      assert.deepEqual(store.getSnapshot(id).roles, ['FOREIGN']);
      assert.equal(topology.roleGroup(store.serverView(id, 'Hetz2')), 'foreign');
      assert.equal(store.getProbe(id).discovery.ok, true);
    } finally { store.cleanup(); }
  });

  console.log('\nTEST 2 — a following probe timeout keeps the previous topology:');
  await checkAsync('FOREIGN survives a transient timeout; probe reports the failure', async () => {
    const store = makeStore();
    try {
      const id = store.addServer('Hetz2');
      store.applyOutcome(id, goodOutcome(['FOREIGN']));
      store.applyOutcome(id, failedOutcome('timeout'));
      const view = store.serverView(id, 'Hetz2');
      assert.deepEqual(view.snapshot.roles, ['FOREIGN'], 'the authoritative roles must be untouched');
      assert.equal(topology.roleGroup(view), 'foreign', 'the server must not move to UNCONFIGURED');
      assert.equal(view.probe.discovery.ok, false);
      assert.equal(view.probe.discovery.reason, 'SSH timeout');
      assert(!view.snapshot.error, 'a failure must not be written into the snapshot');
    } finally { store.cleanup(); }
  });

  console.log('\nTEST 3 — a successful probe finding no manager DOES change state:');
  await checkAsync('a genuine absence of the manager is an authoritative finding', async () => {
    const store = makeStore();
    try {
      const id = store.addServer('plain');
      store.applyOutcome(id, goodOutcome(['FOREIGN']));
      store.applyOutcome(id, absentManagerOutcome());
      const view = store.serverView(id, 'plain');
      assert.equal(view.snapshot.manager.installed, false);
      assert.deepEqual(view.snapshot.roles, []);
      assert.equal(topology.roleGroup(view), 'unconfigured', 'a confirmed absence may reclassify');
      assert.equal(view.probe.discovery.ok, true, 'and the discovery itself succeeded');
    } finally { store.cleanup(); }
  });

  console.log('\nTEST 4 — a host key mismatch is a security failure, not a downgrade:');
  await checkAsync('the pinned-host-key failure preserves topology and stays visible', async () => {
    const store = makeStore();
    try {
      const id = store.addServer('Hetz2');
      store.applyOutcome(id, goodOutcome(['IRAN']));
      store.applyOutcome(id, failedOutcome('hostkey', 'presented key does not match the pinned fingerprint'));
      const view = store.serverView(id, 'Hetz2');
      assert.deepEqual(view.snapshot.roles, ['IRAN']);
      assert.equal(topology.roleGroup(view), 'iran');
      assert.equal(view.probe.discovery.ok, false);
      assert.equal(view.probe.discovery.error_class, 'hostkey');
      assert(!discovery.isRetryable('hostkey'), 'a mismatch must not be retried into acceptance');
    } finally { store.cleanup(); }
  });

  console.log('\nTEST 5 — a refresh of 20 servers stays within the concurrency bound:');
  await checkAsync('the bound is never exceeded and every task completes', async () => {
    const queue = new DiscoveryQueue({ concurrency: 4 });
    let live = 0;
    let peak = 0;
    const tasks = [];
    for (let i = 0; i < 20; i++) {
      tasks.push(queue.run(`srv${i}`, async () => {
        live += 1;
        peak = Math.max(peak, live);
        await new Promise((r) => setTimeout(r, 4));
        live -= 1;
      }));
    }
    await Promise.all(tasks);
    assert.equal(peak, 4, `expected a peak of exactly 4, saw ${peak}`);
    assert(queue.snapshot().peak <= 4, 'the recorded peak must respect the bound');
    assert.equal(queue.snapshot().completed, 20);
    assert.equal(queue.inFlightCount, 0, 'nothing may be left running');
  });

  console.log('\nTEST 6 — a repeat request for the same server is coalesced:');
  await checkAsync('three requests open one session and share one result', async () => {
    const queue = new DiscoveryQueue({ concurrency: 4 });
    let calls = 0;
    const task = async () => {
      calls += 1;
      await new Promise((r) => setTimeout(r, 10));
      return { ok: true, token: Symbol('result') };
    };
    const [a, b, c] = await Promise.all([queue.run(7, task), queue.run(7, task), queue.run(7, task)]);
    assert.equal(calls, 1, `expected a single in-flight discovery, saw ${calls}`);
    assert.equal(a, b, 'callers must share the same promise');
    assert.equal(b, c, 'callers must share the same promise');
    assert.equal(queue.snapshot().coalesced, 2);
  });

  console.log('\nTEST 7 — failed probe plus a good snapshot keeps the group:');
  check('roleGroup stays FOREIGN while the transport probe says failed', () => {
    const server = {
      snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString(), manager: { installed: true } },
      probe: {
        health: { ok: false, reason: 'SSH timeout', checked_at: Date.now() },
        discovery: { ok: false, reason: 'SSH timeout', checked_at: Date.now() },
      },
    };
    assert.equal(topology.roleGroup(server), 'foreign');
    assert.equal(topology.healthState(server), 'failed');
    assert.equal(topology.discoveryState(server), 'failed');
    assert.equal(topology.healthLabel(server), 'SSH UNREACHABLE');
    assert.equal(topology.discoveryLabel(server), 'DISCOVERY FAILED');
    assert.equal(topology.probeReason(server, 'health'), 'SSH timeout');
  });

  check('a healthy SSH session with a failed discovery reports BOTH, separately', () => {
    const server = {
      snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString(), manager: { installed: true, version: '2.8.2' } },
      probe: {
        health: { ok: true, checked_at: Date.now() },
        discovery: { ok: false, reason: 'gre status timed out', checked_at: Date.now() },
      },
    };
    assert.equal(topology.roleGroup(server), 'foreign', 'a discovery failure must not move the server');
    assert.equal(topology.healthState(server), 'healthy');
    assert.equal(topology.discoveryState(server), 'failed');
    assert.equal(topology.healthLabel(server), 'SSH HEALTHY');
    assert.equal(topology.discoveryLabel(server), 'DISCOVERY FAILED');
    assert.equal(topology.probeReason(server, 'discovery'), 'gre status timed out');
  });

  console.log('\nTEST 8 — no good snapshot plus a failed probe is UNCONFIGURED:');
  check('a server never successfully discovered is unconfigured, not mislabelled', () => {
    const server = {
      snapshot: null,
      probe: {
        health: { ok: false, reason: 'SSH timeout' },
        discovery: { ok: false, reason: 'SSH timeout' },
      },
    };
    assert.equal(topology.roleGroup(server), 'unconfigured');
    assert.equal(topology.healthState(server), 'failed');
    assert.equal(topology.needsDiscovery(server), true);
  });

  check('reachable but never discovered is TOPOLOGY UNKNOWN, not a bare UNKNOWN', () => {
    const server = {
      snapshot: null,
      probe: { health: { ok: true }, discovery: { ok: null } },
    };
    assert.equal(topology.roleGroup(server), 'unconfigured');
    assert.equal(topology.healthState(server), 'healthy');
    assert.equal(topology.discoveryState(server), 'unknown');
    assert.equal(topology.needsDiscovery(server), true, 'the UI must say a discovery is still needed');
  });

  console.log('\nTEST 9 — probe errors are redacted before storage:');
  check('no credential can reach the stored or displayed message', () => {
    const verdict = discovery.classifyProbeResult({
      rc: -1, stdout: '', stderr: 'ssh error: root:sup3rsecret@10.0.0.9 refused; password=hunter2',
    });
    assert.equal(verdict.ok, false);
    const stored = verdict.detail;
    assert(!stored.includes('sup3rsecret'), `leaked a password: ${stored}`);
    assert(!stored.includes('hunter2'), `leaked a password: ${stored}`);
  });

  console.log('\nTEST 10 — a stale but good snapshot retains its role:');
  check('an 18-hour-old FOREIGN snapshot is still FOREIGN, and reported stale', () => {
    const takenAt = new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString();
    const server = {
      snapshot: { roles: ['FOREIGN'], taken_at: takenAt, manager: { installed: true } },
      probe: { ok: false, reason: 'SSH timeout' },
    };
    assert.equal(topology.roleGroup(server), 'foreign', 'age must not reclassify a server');
    const freshness = topology.snapshotFreshness(server);
    assert.equal(freshness.known, true);
    assert.equal(freshness.stale, true, 'the UI must be able to warn about staleness');
    const fresh = topology.snapshotFreshness({ snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString() } });
    assert.equal(fresh.stale, false);
  });

  console.log('\nSIMULATION — 27 servers, round 2 loses 17 to transient failures:');
  await checkAsync('grouping stays 6 IRAN / 21 FOREIGN while probe health shows 17 failed', async () => {
    const store = makeStore();
    try {
      const servers = [];
      for (let i = 0; i < 27; i++) {
        const name = i < 6 ? `iran-${i + 1}` : `foreign-${i - 5}`;
        servers.push({ id: store.addServer(name), name, role: i < 6 ? 'IRAN' : 'FOREIGN' });
      }

      // Round 1: everything reachable.
      for (const s of servers) store.applyOutcome(s.id, goodOutcome([s.role]));
      const round1 = servers.map((s) => topology.roleGroup(store.serverView(s.id, s.name)));
      const count1 = round1.reduce((acc, g) => { acc[g] = (acc[g] || 0) + 1; return acc; }, {});
      assert.equal(count1.iran, 6, `round 1 should have 6 IRAN, got ${JSON.stringify(count1)}`);
      assert.equal(count1.foreign, 21, `round 1 should have 21 FOREIGN, got ${JSON.stringify(count1)}`);
      assert.equal(count1.unconfigured || 0, 0);

      // Round 2: 17 of the 21 FOREIGN servers hit a transient SSH failure.
      const flaky = servers.filter((s) => s.role === 'FOREIGN').slice(0, 17);
      for (const s of flaky) store.applyOutcome(s.id, failedOutcome('timeout'));

      const views = servers.map((s) => store.serverView(s.id, s.name));
      const groups = views.map((v) => topology.roleGroup(v));
      const counts = groups.reduce((acc, g) => { acc[g] = (acc[g] || 0) + 1; return acc; }, {});
      const discoveryFailed = views.filter((v) => topology.discoveryState(v) === 'failed').length;
      const healthFailed = views.filter((v) => topology.healthState(v) === 'failed').length;

      assert.equal(counts.iran, 6, `IRAN must stay 6, got ${JSON.stringify(counts)}`);
      assert.equal(counts.foreign, 21, `FOREIGN must stay 21, got ${JSON.stringify(counts)}`);
      assert.equal(counts.unconfigured || 0, 0,
        `NO server may fall to UNCONFIGURED from a transient failure, got ${JSON.stringify(counts)}`);
      assert.equal(discoveryFailed, 17, `discovery health must report 17 failures, got ${discoveryFailed}`);
      // The simulation never ran a health probe, so transport health is untouched
      // by discovery failures. That separation is the whole point.
      assert.equal(healthFailed, 0, `a discovery failure must not be reported as a transport failure, got ${healthFailed}`);

      console.log(`    grouping:  ${JSON.stringify(counts)}`);
      console.log(`    discovery: ${discoveryFailed} failed / ${views.length - discoveryFailed} ok`);
      console.log(`    transport: ${healthFailed} failed (untouched by discovery failures)`);
    } finally { store.cleanup(); }
  });

  console.log('\nCONCURRENCY CONFIGURATION:');
  check('the bound is configurable with a sane default', () => {
    assert.equal(readConcurrency({}), DEFAULT_CONCURRENCY);
    assert.equal(readConcurrency({ HUB_DISCOVERY_CONCURRENCY: '3' }), 3);
    assert.equal(readConcurrency({ HUB_DISCOVERY_CONCURRENCY: '0' }), DEFAULT_CONCURRENCY, 'zero is not a valid bound');
    assert.equal(readConcurrency({ HUB_DISCOVERY_CONCURRENCY: 'nonsense' }), DEFAULT_CONCURRENCY);
    assert.equal(readConcurrency({ HUB_DISCOVERY_CONCURRENCY: '999' }) <= 32, true, 'an absurd value is clamped');
  });

  report('topology preservation tests');
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
