'use strict';
// Shape tests for the HTTP API the dashboard actually consumes.
//
// These boot a real gre-hub against a temp data dir, seed one server plus probe
// state directly in SQLite, and compare the JSON the two endpoints return. A unit
// test on the helper functions cannot catch this class of bug: the v2.15.1 API
// mismatch was purely about which KEY the fields were nested under, and the
// frontend silently rendered every server as "unknown" as a result.
//
// Run with: node scripts/api-shape-test.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PORT = 42000 + Math.floor(Math.random() * 20000);
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-shape-'));
const PASSWORD = 'shape-test-pass-1';

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  ok    ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} ${extra}`); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer(child, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let buf = '';
  child.stdout.on('data', (d) => { buf += d; });
  while (Date.now() < deadline) {
    if (buf.includes('gre-hub listening')) return buf;
    if (child.exitCode !== null) throw new Error(`server exited early (${child.exitCode})\n${buf}`);
    await sleep(100);
  }
  throw new Error(`server did not start in time.\n${buf}`);
}

function makeClient() {
  const c = {
    cookie: '', csrf: '',
    async call(pathname, { method = 'GET', body } = {}) {
      const headers = {};
      if (body) headers['Content-Type'] = 'application/json';
      if (c.cookie) headers.Cookie = c.cookie;
      if (method !== 'GET' && c.csrf) headers['x-csrf-token'] = c.csrf;
      const res = await fetch(BASE + pathname, {
        method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) c.cookie = setCookie.split(';')[0];
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = text; }
      if (data && data.csrf) c.csrf = data.csrf;
      return { status: res.status, data };
    },
  };
  return c;
}

// Seed after the hub has migrated the schema, so the additive columns exist.
function seed() {
  const { openDb } = require('../server/db');
  const cryptoUtil = require('../server/crypto');
  const db = openDb(DATA_DIR);
  const key = cryptoUtil.loadKey(DATA_DIR);
  const now = Date.now();
  const id = Number(db.prepare(
    'INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)'
  ).run('Hetz4', '10.0.0.4', 22, 'root', 'password', cryptoUtil.encrypt(key, 'x'), now).lastInsertRowid);

  // A last-known-good FOREIGN topology with a real version, as production has.
  db.prepare('INSERT INTO snapshots (server_id,json,taken_at) VALUES (?,?,?)').run(
    id,
    JSON.stringify({
      taken_at: new Date(now - 3 * 60 * 60 * 1000).toISOString(),
      manager: { installed: true, version: '2.8.2' },
      roles: ['FOREIGN'],
      status: { roles: ['FOREIGN'] },
      legacy: { present: false },
    }),
    now - 3 * 60 * 60 * 1000,
  );

  // Transport is reachable, discovery failed: the exact case that used to render
  // as a plain HEALTHY with no topology.
  db.prepare(`INSERT INTO server_probe_state
      (server_id, ok, checked_at, duration_ms, error_class, error_message, kind,
       health_ok, health_checked_at, health_duration_ms,
       discovery_ok, discovery_checked_at, discovery_duration_ms, discovery_error_class, discovery_error_message)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, 1, now, 1200, null, null, 'full',
    1, now, 1200,
    0, now, 15000, 'timeout', 'gre status --json timed out after 15s',
  );

  // A second server with nothing known at all.
  const id2 = Number(db.prepare(
    'INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)'
  ).run('Fresh', '10.0.0.9', 22, 'root', 'password', cryptoUtil.encrypt(key, 'x'), now).lastInsertRowid);

  db.close();
  return { id, id2 };
}

function shapeOf(entry) {
  // `stale_for_ms` is computed per request, so two sequential calls cannot match on
  // it. Normalise it and assert it separately as a number.
  const strip = (axis) => {
    if (!axis || typeof axis !== 'object') return axis;
    const { stale_for_ms: stale, ...rest } = axis;
    return { ...rest, staleIsNumber: typeof stale === 'number' };
  };
  return {
    hasSnapshot: entry.snapshot !== undefined,
    snapshotIsObjectOrNull: entry.snapshot === null || typeof entry.snapshot === 'object',
    health: strip(entry.health),
    discovery: strip(entry.discovery),
    probeHealth: strip(entry.probe && entry.probe.health),
    probeDiscovery: strip(entry.probe && entry.probe.discovery),
  };
}

async function main() {
  const seeds = (() => {
    // The hub must migrate the schema first; openDb is idempotent, so opening it
    // here and letting the server open it again is safe.
    const { openDb } = require('../server/db');
    openDb(DATA_DIR).close();
    return seed();
  })();

  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: { ...process.env, PORT: String(PORT), HUB_HOST: '127.0.0.1', HUB_DATA_DIR: DATA_DIR },
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  try {
    console.log(`booting gre-hub on ${BASE}`);
    await waitForServer(child);
    const client = makeClient();

    console.log('setup:');
    let r = await client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
    check('POST /api/setup creates a session', r.status === 200 && r.data.ok === true);

    console.log('\nTEST 14 — GET /servers and GET /servers/:id agree:');
    const list = await client.call('/api/servers');
    check('GET /api/servers → 200 array', list.status === 200 && Array.isArray(list.data));

    const one = await client.call(`/api/servers/${seeds.id}`);
    check('GET /api/servers/:id → 200 object', one.status === 200 && typeof one.data === 'object' && !Array.isArray(one.data));

    const fromList = list.data.find((s) => Number(s.id) === Number(seeds.id));
    check('the seeded server is in the list', !!fromList);
    if (fromList) {
      const a = shapeOf(fromList);
      const b = shapeOf(one.data);
      check('both endpoints return the identical probe shape',
        JSON.stringify(a) === JSON.stringify(b), `\n    list: ${JSON.stringify(a)}\n    one : ${JSON.stringify(b)}`);

      console.log('\nSPEC section 8 — top-level health and discovery:');
      check('server exposes top-level `health`', a.health && typeof a.health === 'object', JSON.stringify(a.health));
      check('server exposes top-level `discovery`', a.discovery && typeof a.discovery === 'object', JSON.stringify(a.discovery));
      check('health.ok is true', a.health && a.health.ok === true);
      check('discovery.ok is false', a.discovery && a.discovery.ok === false);
      check('discovery carries the specific cause in `error`',
        a.discovery && /gre status --json timed out/.test(String(a.discovery.error || '')),
        JSON.stringify(a.discovery));
      check('discovery carries the class label in `reason`',
        a.discovery && a.discovery.reason === 'SSH timeout', JSON.stringify(a.discovery));
      check('stale_for_ms is a number on both axes',
        a.health && a.health.staleIsNumber && a.discovery && a.discovery.staleIsNumber,
        JSON.stringify({ health: a.health, discovery: a.discovery }));
      check('discovery carries error_class=timeout', a.discovery && a.discovery.error_class === 'timeout');
      check('health and discovery are NOT the same object',
        a.health && a.discovery && a.health.ok !== a.discovery.ok,
        'a health success must not look like a discovery success');

      console.log('\nbackward compatibility — the nested `probe` key still works:');
      check('probe.health mirrors top-level health', JSON.stringify(a.probeHealth) === JSON.stringify(a.health));
      check('probe.discovery mirrors top-level discovery', JSON.stringify(a.probeDiscovery) === JSON.stringify(a.discovery));

      console.log('\nTEST 16 — production-like acceptance on the API:');
      check('last known topology survives the discovery failure',
        fromList.snapshot && Array.isArray(fromList.snapshot.roles) && fromList.snapshot.roles.join() === 'FOREIGN',
        JSON.stringify(fromList.snapshot && fromList.snapshot.roles));
      check('the version is still reported', fromList.snapshot && fromList.snapshot.manager.version === '2.8.2');
      check('NO MANAGER is NOT claimed', !(fromList.snapshot && fromList.snapshot.manager.installed === false),
        'a failed discovery must not claim the manager is absent');

      const topology = require('../public/server-topology');
      const groups = { roleGroup: topology.roleGroup(fromList), health: topology.healthState(fromList), discovery: topology.discoveryState(fromList) };
      console.log(`\n    rendered as: group=${groups.roleGroup} ssh=${groups.health} discovery=${groups.discovery}`);
      check('UI groups it as FOREIGN, not UNCONFIGURED', groups.roleGroup === 'foreign');
      check('UI shows SSH HEALTHY', groups.health === 'healthy');
      check('UI shows DISCOVERY FAILED', groups.discovery === 'failed');
      check('UI never says UNKNOWN for the group', groups.roleGroup !== 'unconfigured');
    }

    const fresh = list.data.find((s) => Number(s.id) === Number(seeds.id2));
    check('a server with no probe state reports null axes, not false ones',
      !!fresh && fresh.health && fresh.health.ok === null && fresh.discovery && fresh.discovery.ok === null,
      JSON.stringify(fresh && { health: fresh.health, discovery: fresh.discovery }));

    console.log('\nhealth-summary keeps the three counts distinct:');
    const summary = await client.call('/api/servers/health-summary');
    check('GET /api/servers/health-summary → 200', summary.status === 200);
    check('counts discovery failures separately', summary.data && summary.data.discovery
      && summary.data.discovery.failed >= 1, JSON.stringify(summary.data && summary.data.discovery));
    check('counts transport health separately', summary.data && summary.data.probe
      && summary.data.probe.healthy >= 1, JSON.stringify(summary.data && summary.data.probe));
    check('reports topology counts', summary.data && summary.data.authoritative
      && summary.data.authoritative.foreign >= 1, JSON.stringify(summary.data && summary.data.authoritative));
    check('summary carries no secret material',
      !/password|secret_enc|privateKey|sup3r/i.test(JSON.stringify(summary.data)));

    console.log('\nno secrets anywhere in the server payloads:');
    // `auth_type: "password"` is a legitimate field value, so match on secret
    // MATERIAL rather than on the word.
    const raw = `${JSON.stringify(list.data)}${JSON.stringify(one.data)}`;
    check('no encrypted secret or key material leaks',
      !/"secret_enc"|privateKey|BEGIN OPENSSH|BEGIN RSA|"token":|"api_token"/.test(raw),
      raw.slice(0, 200));
    check('the server payload exposes no stored credential field',
      !list.data.some((s) => 'secret_enc' in s || 'secret' in s || 'password' in s && typeof s.password === 'string'),
      JSON.stringify(Object.keys(list.data[0] || {})));
  } finally {
    child.kill();
    await sleep(150);
    try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  console.log(`\napi shape tests: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
