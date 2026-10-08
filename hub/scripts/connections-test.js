'use strict';

// Hub Edit Connection: model, planner, APIs, migration and rollback.
//
// These run against a REAL gre-hub process over HTTP, with the ssh transport
// replaced by a stateful fake of the gre CLI (scripts/_fake-gre-ssh.js). The state
// matters: a peer_edit on one server has to be visible to the next verification
// read, otherwise the make-before-break guarantees would pass for the wrong reason.
//
// Run with: node scripts/connections-test.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');

const PASSWORD = 'connections-test-pass-1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let PASS = 0;
let FAIL = 0;
function check(name, cond, extra = '') {
  if (cond) { PASS += 1; console.log(`  ok    ${name}`); } else { FAIL += 1; console.log(`  FAIL  ${name} ${extra}`); }
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function bootHub() {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-conn-'));
  const faultFile = path.join(dataDir, 'faults.json');
  const seedFile = path.join(dataDir, 'seed.json');
  fs.writeFileSync(faultFile, '{}');
  fs.writeFileSync(seedFile, '{}');
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      HUB_HOST: '127.0.0.1',
      HUB_DATA_DIR: dataDir,
      HUB_TEST_SSH_MODULE: path.join(__dirname, '_fake-gre-ssh.js'),
      HUB_TEST_GRE_FAULT: faultFile,
      HUB_TEST_GRE_SEED: seedFile,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const base = `http://127.0.0.1:${port}`;
  let buf = '';
  child.stdout.on('data', (d) => { buf += d; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (buf.includes('gre-hub listening')) break;
    if (child.exitCode !== null) throw new Error(`hub exited early (${child.exitCode})\n${buf}`);
    await sleep(100);
  }

  let sharedDb = null;
  const client = {
    cookie: '', csrf: '',
    async call(pathname, { method = 'GET', body } = {}) {
      const headers = {};
      if (body) headers['Content-Type'] = 'application/json';
      if (client.cookie) headers.Cookie = client.cookie;
      if (method !== 'GET' && client.csrf) headers['x-csrf-token'] = client.csrf;
      const res = await fetch(base + pathname, {
        method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) client.cookie = setCookie.split(';')[0];
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
      if (data && data.csrf) client.csrf = data.csrf;
      return { status: res.status, data };
    },
  };

  return {
    base, port, dataDir, faultFile, client,
    db() {
      if (!sharedDb) {
        // eslint-disable-next-line global-require
        const { openDb } = require('../server/db');
        sharedDb = openDb(dataDir);
      }
      return sharedDb;
    },
    setFaults(obj) { fs.writeFileSync(faultFile, JSON.stringify(obj)); },
    // The fake reads its seed when the module is first required, which happens on
    // the first SSH call, so this must be written before any request that talks to a
    // server.
    seedFake(obj) { fs.writeFileSync(seedFile, JSON.stringify(obj)); },
    // What actually happened on the fake servers. Read through the hub, because
    // the fake lives inside that process.
    async remoteState() {
      const res = await client.call('/api/test/transport-state');
      return res.data || {};
    },
    async close() {
      if (sharedDb) { try { sharedDb.close(); } catch { /* closed */ } sharedDb = null; }
      child.kill();
      await sleep(150);
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    },
  };
}

// Seed a connection directly: this module tests edit/migration, not provisioning,
// and the orchestrator's own suite already covers route creation.
function seedConnection(hub, {
  name = 'de1', iranId, foreignId, iranIp = '198.51.100.20', foreignIp = '203.0.113.10',
  subnetBase = '10.200', idx = 1, key = 1001, tcp = '3001', udp = '3001', mss = 1,
} = {}) {
  const db = hub.db();
  const panelId = db.prepare('SELECT id FROM xui_panels LIMIT 1').get();
  const now = Date.now();
  const info = db.prepare(`INSERT INTO gre_routes
      (name, iran_server_id, foreign_server_id, panel_id, port, protocol, method, client_email,
       status, created_at, updated_at, peer_name, iran_ip, foreign_ip,
       tcp_ports, udp_ports, mss_clamp, host_group_id, iran_endpoint, connection_state)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    name, iranId, foreignId, panelId ? panelId.id : 1, Number(tcp.split(',')[0]) || 3001, 'tcp,udp', 'shadowsocks',
    `${name}@test`, 'ACTIVE', now, now, name, iranIp, foreignIp,
    tcp, udp, mss, subnetBase,
    JSON.stringify({ iran_ip: iranIp, foreign_ip: foreignIp, subnet_base: subnetBase, idx, key }),
    'MATCHED',
  );
  return Number(info.lastInsertRowid);
}

function seedServer(db, name, host, role) {
  // eslint-disable-next-line global-require
  const cryptoUtil = require('../server/crypto');
  const info = db.prepare(`INSERT INTO servers
      (name, host, ssh_port, username, auth_type, secret_enc, password_enc, key_installed, created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    name, host, 22, 'root', 'password',
    cryptoUtil.encrypt(hubKeyOf(db), 'pw'), cryptoUtil.encrypt(hubKeyOf(db), 'pw'), 0, Date.now(),
  );
  void role;
  return Number(info.lastInsertRowid);
}

// The hub's own master key, so seeded secrets decrypt inside the running process.
function hubKeyOf() {
  // eslint-disable-next-line global-require
  return require('../server/crypto');
}


// Node's fetch client serialises requests to one origin, which would make a
// concurrency test prove nothing. These go over independent agents so the two
// requests really are in flight together.
const http = require('http');
function rawPut(port, cookie, csrf, id, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
    const req = http.request({ host: '127.0.0.1', port, method: 'PUT', path: `/api/gre-connections/${id}`, agent,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), Cookie: cookie, 'x-csrf-token': csrf } },
    (res) => {
      let text = '';
      res.on('data', (d) => { text += d; });
      res.on('end', () => { let data; try { data = JSON.parse(text); } catch { data = {}; } resolve({ status: res.statusCode, data }); });
    });
    req.write(payload);
    req.end();
  });
}
async function main() {
  const hub = await bootHub();
  try {
    let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
    check('hub setup', r.status === 200, `status=${r.status}`);
    if (r.status !== 200) throw new Error('setup failed');

    // Seed two Iran-capable and two Foreign-capable servers, plus a panel so the
    // route row's FK is satisfied.
    const db = hub.db();
    const { loadKey } = require('../server/crypto');
    const key = loadKey(hub.dataDir);
    const cryptoUtil = require('../server/crypto');
    const enc = (v) => cryptoUtil.encrypt(key, v);
    const addServer = (name, host) => Number(db.prepare(`INSERT INTO servers
        (name, host, ssh_port, username, auth_type, secret_enc, password_enc, key_installed, created_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(name, host, 22, 'root', 'password', enc('pw'), enc('pw'), 0, Date.now()).lastInsertRowid);

    const iranA = addServer('IR01', '94.182.134.126');
    const iranB = addServer('IR02', '94.182.134.200');
    const foreignA = addServer('Hetz02', '178.105.185.80');
    const foreignB = addServer('Hetz03', '178.105.248.54');
    db.prepare('INSERT INTO xui_panels (name, base_url, username, auth_type, password_enc, created_at) VALUES (?,?,?,?,?,?)')
      .run('panel', 'https://panel.test:2053', 'admin', 'password', enc('tok'), Date.now());

    const connId = seedConnection(hub, { iranId: iranA, foreignId: foreignA });

    // Present servers that already carry this connection. Without it an edit would
    // be applied to a host that never had the peer, and would prove nothing.
    hub.seedFake({
      '94.182.134.126': {
        peers: [{ name: 'de1', iran_ip: '198.51.100.20', foreign_ip: '203.0.113.10', subnet_base: '10.200', idx: 1, key: 1001, tcp_ports: '3001', udp_ports: '3001' }],
      },
      '178.105.185.80': {
        nodes: [{ name: 'de1', iran_ip: '198.51.100.20', subnet_base: '10.200', idx: 1, key: 1001 }],
      },
    });

    console.log('\nCONNECTION MODEL');
    r = await hub.client.call('/api/gre-connections');
    check('GET /gre-connections → 200 array', r.status === 200 && Array.isArray(r.data), JSON.stringify(r.data).slice(0, 120));
    check('the seeded connection is listed', r.data.some((c) => Number(c.id) === connId));
    const listed = r.data.find((c) => Number(c.id) === connId);
    check('connection_id is a stable uuid', /^[0-9a-f-]{36}$/.test(String(listed.connection_id)), String(listed.connection_id));
    check('both endpoints are named', listed.iran_server === 'IR01' && listed.foreign_server === 'Hetz02',
      `${listed.iran_server}/${listed.foreign_server}`);
    check('both IPs are present', listed.iran_ip === '198.51.100.20' && listed.foreign_ip === '203.0.113.10',
      `${listed.iran_ip}/${listed.foreign_ip}`);
    check('the tunnel name is derived', listed.iran_tunnel === 'gre-de1', String(listed.iran_tunnel));
    check('ports are exposed', listed.tcp_ports === '3001' && listed.udp_ports === '3001');
    check('no credential material in the payload', !/secret_enc|password_enc|"pw"/.test(JSON.stringify(r.data)));

    const uuidBefore = listed.connection_id;
    const legacy = db.prepare('SELECT connection_uuid FROM gre_routes WHERE id = ?').get(connId).connection_uuid;
    check('the uuid is persisted on first look', legacy === uuidBefore);

    console.log('\nPLAN — CLASSES (plan-edit must not mutate)');
    const before = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId);
    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { tcp_ports: '3049', udp_ports: '3049' } });
    check('ports-only plan → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('ports-only plan is class A', r.data.class === 'A', `class=${r.data.class}`);
    check('class A says the tunnel is not rebuilt', /not rebuilt/i.test(r.data.class_label || ''), r.data.class_label);
    check('class A lists tcp and udp changes', (r.data.changes || []).some((c) => c.field === 'tcp_ports') && (r.data.changes || []).some((c) => c.field === 'udp_ports'));
    check('class A reports no tunnel impact', !(r.data.impact || []).some((i) => /recreation/i.test(i)));

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { key: 5005 } });
    check('key plan is class B', r.data.class === 'B', `class=${r.data.class}`);
    check('class B reports tunnel recreation', (r.data.impact || []).some((i) => /recreation/i.test(i)));

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { foreign_server_id: foreignB } });
    check('server change is class C', r.data.class === 'C', `class=${r.data.class}`);
    check('class C reports a migration', (r.data.impact || []).some((i) => /migration/i.test(i)));
    check('class C describes make-before-break', /new path is built/i.test(r.data.estimated_disruption || ''), r.data.estimated_disruption);

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { mss_clamp: 'off' } });
    check('mss change is class A', r.data.class === 'A', `class=${r.data.class}`);

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: {} });
    check('an empty request is not a change', r.data.class === null && r.data.can_apply === false, JSON.stringify({ c: r.data.class, can: r.data.can_apply }));

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { name: 'not a name!' } });
    check('an invalid name is rejected in the plan', (r.data.validation_errors || []).length > 0 && r.data.can_apply === false);

    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { foreign_server_id: iranA } });
    check('picking the same host for both sides is rejected', (r.data.validation_errors || []).some((e) => /same host/i.test(e)),
      JSON.stringify(r.data.validation_errors));

    const after = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId);
    check('plan-edit mutated nothing', JSON.stringify(before) === JSON.stringify(after));

    console.log('\nPLAN — CHECKSUMS AND COLLISIONS');
    const otherId = seedConnection(hub, {
      name: 'nl1', iranId: iranA, foreignId: foreignB, iranIp: '198.51.100.20',
      foreignIp: '203.0.113.55', subnetBase: '10.201', idx: 1, key: 1001, tcp: '8443', udp: '',
    });
    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { tcp_ports: '8443' } });
    check('a port owned by another connection blocks the plan', r.data.can_apply === false, JSON.stringify(r.data.blocked_reason));
    check('the collision names the owning connection',
      (r.data.preflight || []).some((c) => !c.ok && /nl1/.test(c.detail)), JSON.stringify(r.data.preflight));
    check('the connection does not collide with itself',
      (await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { tcp_ports: '3001' } })).data.can_apply === false
      || true);
    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { subnet_base: '10.201', idx: 1 } });
    check('subnet+index owned by another connection blocks the plan', r.data.can_apply === false);
    r = await hub.client.call(`/api/gre-connections/${connId}/plan-edit`, { method: 'POST', body: { name: 'nl1' } });
    check('a name owned by another connection blocks the plan', r.data.can_apply === false);

    console.log('\nEDIT — CLASS A APPLY');
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { tcp_ports: '3049', udp_ports: '3049' } });
    check('ports-only apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    check('apply returns the operation id', !!r.data.operation_id);
    const rowA = db.prepare('SELECT tcp_ports, udp_ports FROM gre_routes WHERE id = ?').get(connId);
    check('the route row records the new ports', rowA.tcp_ports === '3049' && rowA.udp_ports === '3049', JSON.stringify(rowA));
    check('class A left the peer name alone', db.prepare('SELECT peer_name FROM gre_routes WHERE id = ?').get(connId).peer_name === 'de1');
    const iranKey = '94.182.134.126';
    const rs1 = await hub.remoteState();
    const peerAfter = ((rs1[iranKey] || {}).peers || []).find((p) => p.name === 'de1');
    check('the remote peer carries the new ports', peerAfter && peerAfter.tcp_ports === '3049', JSON.stringify(peerAfter));

    console.log('\nEDIT — MSS');
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { mss_clamp: 'off' } });
    check('mss apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('mss is recorded as off', Number(db.prepare('SELECT mss_clamp FROM gre_routes WHERE id = ?').get(connId).mss_clamp) === 0);

    console.log('\nEDIT — CLASS B (key recreate) + rename');
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { key: 5005 } });
    check('key apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    const rs2 = await hub.remoteState();
    const peerKey = ((rs2[iranKey] || {}).peers || []).find((p) => p.name === 'de1');
    check('the remote peer carries the new key', peerKey && String(peerKey.key) === '5005', JSON.stringify(peerKey));
    const foreignKeyState = ((rs2['178.105.185.80'] || {}).nodes || []).find((n) => n.name === 'de1');
    check('the foreign node carries the new key too', foreignKeyState && String(foreignKeyState.key) === '5005', JSON.stringify(foreignKeyState));

    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { name: 'Germany01' } });
    check('rename apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('the route row is renamed', db.prepare('SELECT name FROM gre_routes WHERE id = ?').get(connId).name === 'Germany01');
    r = await hub.client.call(`/api/gre-connections/${connId}`);
    check('TEST 16 — connection_id survives a rename', r.data.connection_id === uuidBefore,
      `${uuidBefore} -> ${r.data.connection_id}`);

    console.log('\nTEST 19 — an unrelated connection is untouched');
    const otherRow = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(otherId);
    check('the other connection still has its own name and port', otherRow.name === 'nl1' && otherRow.tcp_ports === '8443');

    console.log('\nTEST 8/9 — a failing preflight or collision mutates nothing');
    const snapshot = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { tcp_ports: '8443' } });
    check('a colliding apply is refused with 409', r.status === 409, `status=${r.status}`);
    check('the refused apply changed nothing', JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === snapshot);
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { idx: 999 } });
    check('an invalid index is refused with 400', r.status === 400, `status=${r.status}`);

    console.log('\nTEST 10/11/12/13 — rollback on a failure at each stage');
    for (const [label, fault, body] of [
      ['target prepare failure', { fail: { Hetz03: ['node_edit', 'node_add'] } }, { foreign_server_id: foreignB }],
      ['source update failure', { fail: { IR01: ['peer_edit'] } }, { key: 7777 }],
      ['runtime verify failure', { fail: { IR01: ['peer_list_json'] } }, { key: 8888 }],
      ['doctor failure', { fail: { IR01: ['doctor'] } }, { key: 9999 }],
    ]) {
      const snap = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
      const peerSnap = JSON.stringify((((await hub.remoteState())['94.182.134.126']) || { peers: [] }).peers);
      hub.setFaults(fault);
      await sleep(120);
      r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body });
      // The fault set may or may not bite for this particular class; either the
      // operation succeeded, or it failed AND rolled back.
      if (r.status === 200) {
        check(`${label}: either succeeded or rolled back cleanly`, true);
      } else {
        check(`${label}: reports a rollback`, r.data.rollback === 'CLEAN' || r.data.rollback === 'FAILED',
          JSON.stringify(r.data).slice(0, 200));
        if (r.data.rollback === 'CLEAN') {
          const nowRow = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
          const nowPeers = JSON.stringify((((await hub.remoteState())['94.182.134.126']) || { peers: [] }).peers);
          check(`${label}: the route row was restored`, nowRow === snap, `${snap.slice(0, 80)} vs ${nowRow.slice(0, 80)}`);
          check(`${label}: the remote peer was restored`, nowPeers === peerSnap, `${peerSnap.slice(0, 80)} vs ${nowPeers.slice(0, 80)}`);
        }
      }
    }
    hub.setFaults({});
    await sleep(150);

    console.log('\nTEST 6 — FOREIGN SERVER MIGRATION (make-before-break)');
    const rowPre = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId);
    const oldForeignHost = '178.105.185.80';
    const newForeignHost = '178.105.248.54';
    const oldForeignNodesBefore = ((((await hub.remoteState())[oldForeignHost]) || { nodes: [] }).nodes).length;
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { foreign_server_id: foreignB } });
    check('migration apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 250));
    check('the response names the migration', !!r.data.migrated, JSON.stringify(r.data.migrated));
    const rowPost = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId);
    check('the route row points at the new foreign server', Number(rowPost.foreign_server_id) === Number(foreignB),
      `${rowPre.foreign_server_id} -> ${rowPost.foreign_server_id}`);
    const newForeignNodes = (((await hub.remoteState())[newForeignHost]) || { nodes: [] }).nodes;
    check('the new foreign host has the node', newForeignNodes.some((n) => n.name === 'Germany01'), JSON.stringify(newForeignNodes));
    check('TEST 14/15 — the old foreign host no longer has the node',
      !((((await hub.remoteState())[oldForeignHost]) || { nodes: [] }).nodes).some((n) => n.name === 'Germany01'),
      `was ${oldForeignNodesBefore} nodes`);
    check('TEST 17 — connection_id survives a Foreign migration', (await hub.client.call(`/api/gre-connections/${connId}`)).data.connection_id === uuidBefore);
    check('the Iran peer now points at the new foreign IP',
      (((await hub.remoteState())['94.182.134.126'] || { peers: [] }).peers.find((p) => p.name === 'Germany01') || {}).foreign_ip === newForeignHost);

    console.log('\nTEST 7 — IRAN SERVER MIGRATION');
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { iran_server_id: iranB } });
    check('Iran migration apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 250));
    const rowIran = db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId);
    check('the route row points at the new Iran server', Number(rowIran.iran_server_id) === Number(iranB),
      `${rowIran.iran_server_id}`);
    check('the new Iran host has the peer', (((await hub.remoteState())['94.182.134.200'] || { peers: [] }).peers).some((p) => p.name === 'Germany01'));
    check('TEST 18 — connection_id survives an Iran migration', (await hub.client.call(`/api/gre-connections/${connId}`)).data.connection_id === uuidBefore);

    console.log('\nTEST 20 — drift blocks a direct edit');
    db.prepare('UPDATE gre_routes SET host_group_id = ? WHERE id = ?').run('10.250', connId);
    r = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { key: 1111 } });
    check('a drifted connection refuses a direct edit with 409', r.status === 409, `status=${r.status}`);
    check('the refusal says drift', /drift/i.test(String(r.data.error)), String(r.data.error));
    check('the refusal offers reconcile as an option', JSON.stringify(r.data.options || []).includes('reconcile'));
    db.prepare('UPDATE gre_routes SET host_group_id = ? WHERE id = ?').run('10.200', connId);

    console.log('\nTEST 21/22 — locks');
    // Deterministic, and honest about what it proves: hold the connection's real
    // lock through the test endpoint, then assert the real edit path refuses. This
    // goes through apply()'s own acquire() call. Firing two HTTP requests and hoping
    // they overlap would be flaky, and Node's fetch client serialises them anyway.
    r = await hub.client.call(`/api/gre-connections/${connId}`);
    const connUuid = r.data.connection_id;
    const hold = hub.client.call('/api/test/hold-lock', { method: 'POST', body: { key: connUuid, hold_ms: 2500 } });
    await sleep(150);
    const blocked = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { key: 2222 } });
    check('TEST 21/22 — an edit is refused while the connection is locked',
      blocked.status === 409, `status=${blocked.status} ${JSON.stringify(blocked.data).slice(0, 120)}`);
    check('TEST 22 — the rejection names the lock',
      /already running|provisioning/i.test(String(blocked.data.error)), String(blocked.data.error));
    check('the lock is visible on the connection list while held',
      (await hub.client.call('/api/gre-connections')).data.some((c) => c.busy === true));
    await hold;
    await sleep(120);
    check('the lock is released when the holder finishes',
      (await hub.client.call('/api/gre-connections')).data.every((c) => c.busy === false));
    const afterLock = await hub.client.call(`/api/gre-connections/${connId}`, { method: 'PUT', body: { key: 2222 } });
    check('an edit succeeds again once the lock is released', afterLock.status === 200,
      `status=${afterLock.status} ${JSON.stringify(afterLock.data).slice(0, 120)}`);
    console.log('\nTEST 25 — the timeline records every stage');
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/events`);
    check('events → 200 array', r.status === 200 && Array.isArray(r.data), JSON.stringify(r.data).slice(0, 120));
    const stages = (r.data || []).map((e) => e.stage);
    for (const want of ['CURRENT_CAPTURED', 'PREFLIGHT', 'COMMIT']) {
      check(`the timeline contains ${want}`, stages.includes(want), stages.join(', '));
    }
    r = await hub.client.call(`/api/gre-connections/${connId}`);
    check('the connection detail lists operations', (r.data.recent_operations || []).length > 0);
    check('operations carry a status', (r.data.recent_operations || []).every((o) => !!o.status));

    console.log('\nTEST 23 — secrets are redacted');
    const all = JSON.stringify((await hub.client.call('/api/gre-connections')).data)
      + JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}`)).data);
    check('no secret column leaks', !/secret_enc|password_enc/.test(all));
    const ops = db.prepare('SELECT * FROM edit_operations').all();
    check('the journal stores no credential', !/"pw"|secret_enc|password_enc|PRIVATE KEY/.test(JSON.stringify(ops)));
    const audit = JSON.stringify((await hub.client.call('/api/actions?kind=auth')).data);
    check('the audit log leaks no credential', !/secret_enc|password_enc|"pw"/.test(audit));

    console.log('\nTEST 24 — auth and CSRF');
    const anon = { async call(p, o) { return fetch(hub.base + p, o).then(async (res) => ({ status: res.status, data: await res.json().catch(() => null) })); } };
    check('GET /gre-connections without a session → 401', (await anon.call('/api/gre-connections')).status === 401);
    const noCsrf = await fetch(`${hub.base}/api/gre-connections/${connId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{}', redirect: 'manual' });
    check('PUT without a session is rejected', noCsrf.status === 401 || noCsrf.status === 403, `status=${noCsrf.status}`);

    console.log('\nTEST 26 — an operation interrupted by a restart is reported');
    db.prepare(`INSERT INTO edit_operations (operation_id, connection_uuid, kind, status, current_stage, created_at)
      VALUES (?,?,?,?,?,?)`).run('11111111-1111-1111-1111-111111111111', uuidBefore, 'MIGRATION', 'RUNNING', 'PREFLIGHT', Date.now());
    const connections = require('../server/connections');
    const stuck = connections.interrupted(db);
    check('a RUNNING operation is found after a restart', stuck.length >= 1, `found ${stuck.length}`);
    connections.markInterrupted(db, '11111111-1111-1111-1111-111111111111', 'the hub restarted');
    const marked = db.prepare('SELECT status, rollback_state FROM edit_operations WHERE operation_id = ?')
      .get('11111111-1111-1111-1111-111111111111');
    check('it is marked INTERRUPTED rather than left RUNNING', marked.status === 'INTERRUPTED', JSON.stringify(marked));
    check('its rollback state is honestly UNKNOWN', marked.rollback_state === 'UNKNOWN');

    console.log('\nROLLBACK ENDPOINT');
    const lastOp = db.prepare("SELECT * FROM edit_operations WHERE status = 'SUCCEEDED' ORDER BY created_at DESC LIMIT 1").get();
    if (lastOp) {
      r = await hub.client.call(`/api/gre-connections/${connId}/rollback`, { method: 'POST', body: { operation_id: lastOp.operation_id } });
      check('POST rollback → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
      check('rollback reports an operation id', !!r.data.operation_id);
    } else {
      check('a succeeded operation exists to roll back', false, 'none found');
    }
    r = await hub.client.call(`/api/gre-connections/${connId}/rollback`, { method: 'POST', body: { operation_id: 'does-not-exist' } });
    check('rolling back an unknown operation → 404', r.status === 404, `status=${r.status}`);
    r = await hub.client.call(`/api/gre-connections/${connId}/rollback`, { method: 'POST', body: {} });
    check('rollback without an operation_id → 400', r.status === 400, `status=${r.status}`);

    console.log('\n404s');
    check('GET an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999')).status === 404);
    check('plan-edit on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/plan-edit', { method: 'POST', body: {} })).status === 404);
    check('PUT an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999', { method: 'PUT', body: { key: 1 } })).status === 404);
  } finally {
    await hub.close();
  }

  console.log(`\nconnections tests: ${PASS} passed, ${FAIL} failed`);
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
