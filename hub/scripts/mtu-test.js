'use strict';

// Hub MTU diagnostics and tuning: two-sided diagnostics, recommendation, the
// transactional MTU change, rollback and the read-only guarantees.
//
// These run against a REAL gre-hub process over HTTP, with the ssh transport replaced
// by a stateful fake of the gre CLI (scripts/_fake-gre-ssh.js). The state matters: a
// `gre mtu set` has to be visible to the next `gre mtu diagnose` and readable back from
// the interface, otherwise the Hub's verification step would pass for the wrong reason.
//
// Run with: node scripts/mtu-test.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');

const PASSWORD = 'mtu-test-pass-1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let PASS = 0;
let FAIL = 0;
function check(name, cond, extra = '') {
  if (cond) { PASS += 1; console.log(`  ok    ${name}`); } else { FAIL += 1; console.log(`  FAIL  ${name} ${extra}`); }
}

const VERB = require('./_fake-gre-ssh').verbOf;
const TUNNEL_REBUILD_VERBS = require('./_fake-gre-ssh').TUNNEL_REBUILD_VERBS;

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
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-mtu-'));
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
    // The fake reads its seed when the module is first required, which happens on the
    // first SSH call, so this must be written before any request that talks to a server.
    seedFake(obj) { fs.writeFileSync(seedFile, JSON.stringify(obj)); },
    // What actually happened on the fake servers. Read through the hub, because the fake
    // lives inside that process.
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

// Node's fetch client serialises requests to one origin, which would make a
// concurrency test prove nothing. These go over independent agents so the two requests
// really are in flight together.
const http = require('http');
function rawMtuPut(port, cookie, csrf, id, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
    const req = http.request({ host: '127.0.0.1', port, method: 'PUT', path: `/api/gre-connections/${id}/mtu`, agent,
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

const IRAN_HOST = '94.182.134.126';
const FOREIGN_HOST = '178.105.185.80';

function mtuOf(state, host, name = 'de1') {
  const st = state[host] || {};
  const entry = (st.mtu || {})[name];
  return entry ? entry.gre_mtu : null;
}

function verbsOf(state, host) {
  // The fake records the verb it computed, not the raw command.
  return ((state[host] || {}).commands || []).slice();
}

const MTU_STAGES = [
  'CURRENT_STATE', 'READ_BOTH_ENDPOINTS', 'MTU_DIAGNOSTICS', 'RECOMMENDATION', 'USER_APPROVAL',
  'BACKUP_PREVIOUS_VALUES', 'APPLY_TO_BOTH_SIDES', 'VERIFY_INTERFACE_STATE', 'VERIFY_CONNECTIVITY',
  'COMMIT_OR_ROLLBACK',
];

function seedFor(greMtu, probe = { outer: 'PASS', inner: 'PASS' }) {
  return {
    [IRAN_HOST]: {
      peers: [{ name: 'de1', iran_ip: '198.51.100.20', foreign_ip: '203.0.113.10', subnet_base: '10.200', idx: 1, key: 1001, tcp_ports: '3001', udp_ports: '3001' }],
      mtu: { de1: { gre_mtu: greMtu, nic_mtu: 1500, overhead: 28 } },
      probe,
    },
    [FOREIGN_HOST]: {
      nodes: [{ name: 'de1', iran_ip: '198.51.100.20', subnet_base: '10.200', idx: 1, key: 1001 }],
      mtu: { de1: { gre_mtu: greMtu, nic_mtu: 1500, overhead: 28 } },
      probe,
    },
  };
}

async function main() {
  const hub = await bootHub();
  try {
    let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
    check('hub setup', r.status === 200, `status=${r.status}`);
    if (r.status !== 200) throw new Error('setup failed');

    const db = hub.db();
    const { loadKey } = require('../server/crypto');
    const key = loadKey(hub.dataDir);
    const cryptoUtil = require('../server/crypto');
    const enc = (v) => cryptoUtil.encrypt(key, v);
    const addServer = (name, host) => Number(db.prepare(`INSERT INTO servers
        (name, host, ssh_port, username, auth_type, secret_enc, password_enc, key_installed, created_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(name, host, 22, 'root', 'password', enc('pw'), enc('pw'), 0, Date.now()).lastInsertRowid);

    const iranId = addServer('IR01', IRAN_HOST);
    const foreignId = addServer('Het02', FOREIGN_HOST);
    db.prepare('INSERT INTO xui_panels (name, base_url, username, auth_type, password_enc, created_at) VALUES (?,?,?,?,?,?)')
      .run('panel', 'https://panel.test:2053', 'admin', 'password', enc('tok'), Date.now());

    const connId = seedConnection(hub, { iranId, foreignId });
    hub.seedFake(seedFor(1476));
    await sleep(150);

    console.log('\nMTU DIAGNOSTICS — BOTH SIDES');
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('GET /mtu → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    check('both sides answered', r.data.iran.ok === true && r.data.foreign.ok === true,
      JSON.stringify({ iran: r.data.iran.error, foreign: r.data.foreign.error }));
    check('Iran is identified as the Iran side', r.data.iran.data.side === 'iran', r.data.iran.data.side);
    check('the Foreign side reports the tunnel', r.data.foreign.data.gre.tun === 'gre-de1', r.data.foreign.data.gre.tun);
    check('the current GRE MTU is reported per side',
      r.data.iran.data.gre.mtu === 1476 && r.data.foreign.data.gre.mtu === 1476,
      `${r.data.iran.data.gre.mtu}/${r.data.foreign.data.gre.mtu}`);
    check('the NIC MTU is reported per side',
      r.data.iran.data.underlay.mtu === 1500 && r.data.foreign.data.underlay.mtu === 1500);
    check('the encapsulation overhead is reported', r.data.iran.data.gre.overhead === 28);
    check('the MSS clamp state is reported', r.data.iran.data.mss_clamp.enabled === true);
    check('the ten transaction stages are declared in order',
      (require('../server/connection-mtu').MTU_STAGES || []).join(',') === MTU_STAGES.join(','));

    const rec = r.data.recommendation;
    check('recommended MTU is the path capacity minus the overhead', rec.recommended_gre_mtu === 1472, String(rec.recommended_gre_mtu));
    check('the underlay capacity is the verified one', rec.underlay_mtu === 1500 && rec.underlay_source === 'outer_probe',
      `${rec.underlay_mtu}/${rec.underlay_source}`);
    check('the current MTU is named', rec.current_gre_mtu === 1476, String(rec.current_gre_mtu));
    check('confidence is high when both sides measured and agree', rec.confidence === 'high', rec.confidence);
    check('a change is required', rec.requires_change === true);
    check('the recommendation is safe to apply', rec.safe_to_apply === true);
    check('no asymmetry is claimed when the paths agree', rec.asymmetric === false && rec.asymmetry_detail === null);
    check('no safety margin is taken from a measured path', rec.safety_margin === 0, String(rec.safety_margin));
    check('the minimum legal MTU is the IPv4 floor', rec.min_legal_mtu === 576, String(rec.min_legal_mtu));
    check('the reason names the lower path', /lower underlay path/i.test(rec.reason), rec.reason);
    check('the combined view says both sides were read', r.data.combined.both_sides === true);
    check('the combined view sees no drift', r.data.combined.drift.detected === false,
      JSON.stringify(r.data.combined.drift));
    check('no credential leaks in the diagnostics payload', !/secret_enc|password_enc|"pw"/.test(JSON.stringify(r.data)));

    console.log('\nREAD-ONLY GUARANTEES — plan and GET take no lock and write nothing');
    const rowBefore = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
    const opsBefore = db.prepare('SELECT COUNT(*) AS n FROM edit_operations').get().n;
    const auditBefore = db.prepare('SELECT COUNT(*) AS n FROM action_log').get().n;
    await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    await hub.client.call(`/api/gre-connections/${connId}/mtu/nic`);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 1472 } });
    check('POST /mtu/plan → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    const plan = r.data;
    check('the plan is marked read-only', plan.read_only === true);
    check('the plan reports the current MTU of both sides',
      plan.current.iran === 1476 && plan.current.foreign === 1476, JSON.stringify(plan.current));
    check('the plan says the current values are live', plan.current.source === 'live', plan.current.source);
    check('the plan echoes the target', plan.target === 1472 && plan.target_valid === true, String(plan.target));
    check('the plan lists what will change', Array.isArray(plan.what_changes) && plan.what_changes.length >= 3, JSON.stringify(plan.what_changes));
    check('the plan says the interface is not recreated', plan.what_changes.some((c) => /not recreated/i.test(c)));
    check('the plan carries a risk level and reasons', ['low', 'medium', 'high'].includes(plan.risk.level) && Array.isArray(plan.risk.reasons));
    check('the plan lists verification checks', (plan.verification_checks || []).length >= 4);
    check('the plan lists rollback conditions', (plan.rollback_conditions || []).length >= 4);
    check('the plan can be applied when the target matches the recommendation', plan.can_apply === true, JSON.stringify(plan.hard_blocks));
    check('the plan includes the live recommendation', plan.recommendation && plan.recommendation.recommended_gre_mtu === 1472);
    check('the plan embeds the diagnostics it used', !!plan.diagnostics && plan.diagnostics.iran.ok === true);

    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 9000 } });
    check('a target above the underlay capacity cannot be applied', r.data.can_apply === false, JSON.stringify(r.data.hard_blocks));
    check('the refusal names the underlay capacity', /underlay capacity/i.test(String(r.data.blocked_reason)), String(r.data.blocked_reason));
    check('that plan is high risk', r.data.risk.level === 'high', r.data.risk.level);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 576 } });
    check('a target at the floor is still a legal plan', r.data.can_apply === true, JSON.stringify(r.data.hard_blocks));
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 500 } });
    check('a target below the legal floor is refused as a validation error',
      r.data.can_apply === false && (r.data.validation_errors || []).length === 1, JSON.stringify(r.data.validation_errors));
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: {} });
    check('a plan without an MTU is refused', r.data.can_apply === false && /required/.test(String(r.data.blocked_reason)), String(r.data.blocked_reason));
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 1472.5 } });
    check('a non-integer MTU is refused', r.data.can_apply === false);

    check('the plan and GETs mutated no route row',
      JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === rowBefore);
    check('the plan and GETs created no operation',
      db.prepare('SELECT COUNT(*) AS n FROM edit_operations').get().n === opsBefore);
    check('the plan and GETs wrote no audit entry',
      db.prepare('SELECT COUNT(*) AS n FROM action_log').get().n === auditBefore);
    check('no MTU journal row exists yet',
      db.prepare("SELECT COUNT(*) AS n FROM edit_operations WHERE kind = 'MTU_CHANGE'").get().n === 0);
    check('no connection is holding a lock',
      (await hub.client.call('/api/gre-connections')).data.every((c) => c.busy === false));

    console.log('\nWAN NIC ANALYSIS (read-only)');
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/nic`);
    check('GET /mtu/nic → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('both sides were analysed', r.data.iran.ok === true && r.data.foreign.ok === true);
    check('the WAN NIC risk is surfaced', r.data.combined.overall_risk === 'low', String(r.data.combined.overall_risk));
    check('the analysis names the interface', (r.data.iran.data.nics || [])[0] && r.data.iran.data.nics[0].iface === 'eth0');
    check('the NIC analysis mutated nothing',
      JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === rowBefore);

    console.log('\nAPPLY — BOTH SIDES, MTU ONLY, NEVER A TUNNEL REBUILD');
    let state = await hub.remoteState();
    const commandsBeforeApply = verbsOf(state, IRAN_HOST).length;
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1472, confirm: true } });
    check('PUT /mtu → 200', r.status === 200, JSON.stringify(r.data).slice(0, 250));
    const firstOpId = r.data.operation_id;
    check('the apply reports an operation id', !!firstOpId);
    check('the apply reports the applied values',
      r.data.applied.iran_mtu === 1472 && r.data.applied.foreign_mtu === 1472, JSON.stringify(r.data.applied));
    check('the apply reports the previous values',
      r.data.previous.iran_mtu === 1476 && r.data.previous.foreign_mtu === 1476, JSON.stringify(r.data.previous));
    check('the apply reports the interface verification', /at 1472 B/.test(String(r.data.verification.interface_mtu)), String(r.data.verification.interface_mtu));
    check('the apply reports connectivity', r.data.connectivity.state === 'PASS', JSON.stringify(r.data.connectivity));

    state = await hub.remoteState();
    check('Iran now reports the new MTU', mtuOf(state, IRAN_HOST) === 1472, String(mtuOf(state, IRAN_HOST)));
    check('the Foreign side now reports the new MTU', mtuOf(state, FOREIGN_HOST) === 1472, String(mtuOf(state, FOREIGN_HOST)));
    const iranVerbs = verbsOf(state, IRAN_HOST);
    const foreignVerbs = verbsOf(state, FOREIGN_HOST);
    check('no tunnel rebuild verb ran on Iran',
      iranVerbs.every((v) => !TUNNEL_REBUILD_VERBS.includes(v)), iranVerbs.join(','));
    check('no tunnel rebuild verb ran on the Foreign side',
      foreignVerbs.every((v) => !TUNNEL_REBUILD_VERBS.includes(v)), foreignVerbs.join(','));
    check('the MTU change drove gre mtu set', iranVerbs.includes('mtu_set') && foreignVerbs.includes('mtu_set'));
    check('the change read the state back with gre mtu diagnose',
      iranVerbs.filter((v) => v === 'mtu_diagnose').length >= 2, iranVerbs.join(','));
    check('the change verified reachability with gre tunnel diagnose',
      iranVerbs.includes('tunnel_diagnose') && foreignVerbs.includes('tunnel_diagnose'));
    check('only MTU and diagnose verbs ran during the apply',
      iranVerbs.slice(commandsBeforeApply).every((v) => ['mtu_diagnose', 'mtu_recommend', 'mtu_set', 'tunnel_diagnose'].includes(v)),
      iranVerbs.slice(commandsBeforeApply).join(','));

    const journal = db.prepare("SELECT * FROM edit_operations WHERE kind = 'MTU_CHANGE' ORDER BY created_at DESC LIMIT 1").get();
    check('the journal records an MTU_CHANGE', !!journal && journal.kind === 'MTU_CHANGE');
    check('the operation succeeded', journal.status === 'SUCCEEDED', journal.status);
    check('the journal holds no credential',
      !/secret_enc|password_enc|"pw"|PRIVATE KEY/.test(JSON.stringify(db.prepare('SELECT * FROM edit_operations').all())));
    check('the journal records the previous MTU for rollback',
      JSON.parse(journal.old_state_json).iran_mtu === 1476, journal.old_state_json);

    r = await hub.client.call(`/api/gre-connections/${connId}/events`);
    const stages = (r.data || []).map((e) => e.stage).filter((s) => MTU_STAGES.includes(s));
    const collapsed = stages.filter((s, i) => i === 0 || stages[i - 1] !== s);
    check('every transaction stage appears in the timeline', MTU_STAGES.every((s) => stages.includes(s)), stages.join(','));
    check('the stages appear in the mandatory order', collapsed.join(',') === MTU_STAGES.join(','), collapsed.join(','));
    check('the timeline reached COMMIT_OR_ROLLBACK with PASS',
      (r.data || []).some((e) => e.stage === 'COMMIT_OR_ROLLBACK' && e.status === 'PASS'));

    r = await hub.client.call(`/api/gre-connections/${connId}`);
    check('the connection detail now carries the MTU summary', !!r.data.mtu && r.data.mtu.known === true);
    check('the summary reports the applied MTU on both sides',
      r.data.mtu.iran_gre_mtu === 1472 && r.data.mtu.foreign_gre_mtu === 1472, JSON.stringify(r.data.mtu));
    check('the summary records when the MTU was last verified', !!r.data.mtu.last_verified_at);
    check('the summary reports the last test result', r.data.mtu.last_test.status === 'SUCCEEDED');
    check('the summary keeps the stored recommendation', r.data.mtu.recommended_gre_mtu === 1472, String(r.data.mtu.recommended_gre_mtu));
    check('the summary reports no drift after a verified change', r.data.mtu.drift.detected === false, JSON.stringify(r.data.mtu.drift));
    check('the list endpoint carries the same summary',
      (await hub.client.call('/api/gre-connections')).data.some((c) => Number(c.id) === connId && c.mtu && c.mtu.known === true));

    console.log('\nLOCKS — a concurrent apply is refused');
    const connUuid = (await hub.client.call(`/api/gre-connections/${connId}`)).data.connection_id;
    const hold = hub.client.call('/api/test/hold-lock', { method: 'POST', body: { key: connUuid, hold_ms: 2500 } });
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1460, confirm: true } });
    check('an MTU change is refused while the connection is locked', r.status === 409, `status=${r.status}`);
    check('the rejection names the running operation', /already running/i.test(String(r.data.error)), String(r.data.error));
    check('the locked connection shows as busy',
      (await hub.client.call('/api/gre-connections')).data.some((c) => c.busy === true));
    await hold;
    await sleep(150);
    check('the lock is released when the holder finishes',
      (await hub.client.call('/api/gre-connections')).data.every((c) => c.busy === false));

    // Two requests really in flight together, over independent agents. The fake is
    // slowed on mtu_set so the window the lock protects is a real one.
    hub.setFaults({ delay_ms: { IR01: { mtu_set: 250 }, Het02: { mtu_set: 250 } } });
    await sleep(150);
    let [p1, p2] = await Promise.all([
      rawMtuPut(hub.port, hub.client.cookie, hub.client.csrf, connId, { mtu: 1460, confirm: true }),
      rawMtuPut(hub.port, hub.client.cookie, hub.client.csrf, connId, { mtu: 1460, confirm: true }),
    ]);
    let statuses = [p1.status, p2.status].sort();
    check('two concurrent applies: exactly one succeeds', statuses[0] === 200 && statuses[1] === 409, statuses.join(','));
    hub.setFaults({});
    await sleep(150);
    const rowBeforeGates = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));

    console.log('\nAPPLY GATES');
    const opsBeforeGates = db.prepare("SELECT COUNT(*) AS n FROM edit_operations").get().n;
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1450 } });
    check('an MTU change without confirm is refused with 400', r.status === 400, `status=${r.status}`);
    check('the refusal explains the confirmation requirement', /confirm/i.test(String(r.data.error)), String(r.data.error));
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 100, confirm: true } });
    check('an MTU below the legal floor is refused', r.status === 400, `status=${r.status}`);
    check('a request refused before the transaction creates no operation',
      db.prepare("SELECT COUNT(*) AS n FROM edit_operations").get().n === opsBeforeGates);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 5000, confirm: true } });
    check('a target above the measured path is refused with 409', r.status === 409, `status=${r.status}`);
    check('the refusal names the underlay capacity', /underlay capacity/i.test(String(r.data.error)), String(r.data.error));
    const rejected = db.prepare("SELECT * FROM edit_operations WHERE kind = 'MTU_CHANGE' ORDER BY created_at DESC LIMIT 1").get();
    check('a refused change is journaled as REJECTED rather than silently dropped',
      rejected.status === 'REJECTED', rejected.status);

    // Inconclusive evidence: the NIC MTU is readable but neither path could be probed.
    // The Hub must not turn configuration into a measurement.
    hub.seedFake(seedFor(1472, { outer: 'UNKNOWN', inner: 'UNKNOWN' }));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('an unprobed path falls back to the configured NIC MTU',
      r.data.recommendation.underlay_source === 'configured_nic', String(r.data.recommendation.underlay_source));
    check('an unprobed path is sized down by a margin', r.data.recommendation.safety_margin === 8,
      String(r.data.recommendation.safety_margin));
    check('confidence is low with no probe at all', r.data.recommendation.confidence === 'low', r.data.recommendation.confidence);
    check('an unprobed recommendation is not safe to apply', r.data.recommendation.safe_to_apply === false);
    const liveBefore = mtuOf(await hub.remoteState(), IRAN_HOST);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1464, confirm: true } });
    check('an inconclusive recommendation blocks the apply with 409', r.status === 409, `status=${r.status}`);
    check('the refusal explains that the evidence is inconclusive', /inconclusive/i.test(String(r.data.error)), String(r.data.error));
    check('the refusal carries the recommendation', !!r.data.recommendation && r.data.recommendation.confidence === 'low');
    check('a blocked apply changed nothing on the servers', mtuOf(await hub.remoteState(), IRAN_HOST) === liveBefore);
    check('a blocked apply left the route row alone',
      JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === rowBeforeGates);

    console.log('\nONE-SIDED FAILURE ROLLS THE FIRST SIDE BACK');
    hub.seedFake(seedFor(1460));
    // The fake loads its seed on the next SSH call, so read the fixture through a
    // request rather than from the state the previous scenario left behind.
    await sleep(150);
    await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    const prePartial = await hub.remoteState();
    check('the fixture is at 1460 on both sides',
      mtuOf(prePartial, IRAN_HOST) === 1460 && mtuOf(prePartial, FOREIGN_HOST) === 1460,
      `${mtuOf(prePartial, IRAN_HOST)}/${mtuOf(prePartial, FOREIGN_HOST)}`);
    hub.setFaults({ fail: { Het02: ['mtu_set'] } });
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1440, confirm: true } });
    check('a one-sided failure is reported as a failure', r.status >= 400, `status=${r.status}`);
    check('the failure names the Foreign side', /Het02/.test(String(r.data.error)), String(r.data.error));
    check('the partial failure reports a clean rollback', r.data.rollback === 'CLEAN', String(r.data.rollback));
    const afterPartial = await hub.remoteState();
    check('the first side was put back', mtuOf(afterPartial, IRAN_HOST) === 1460, String(mtuOf(afterPartial, IRAN_HOST)));
    check('the failing side was never changed', mtuOf(afterPartial, FOREIGN_HOST) === 1460, String(mtuOf(afterPartial, FOREIGN_HOST)));
    const lastOp = db.prepare("SELECT * FROM edit_operations WHERE kind = 'MTU_CHANGE' ORDER BY created_at DESC LIMIT 1").get();
    check('the journal records the partial failure as rolled back', lastOp.status === 'ROLLED_BACK', lastOp.status);
    check('the journal records the rollback as clean', lastOp.rollback_state === 'CLEAN', String(lastOp.rollback_state));
    check('a clean rollback needs no manual recovery step', !r.data.manual_recovery);

    console.log('\nA ROLLBACK THAT CANNOT BE VERIFIED IS REPORTED AS ROLLBACK_FAILED');
    // The change itself goes through; the tunnel then fails reachability, and neither
    // the CLI restore nor an explicit set can bring the old MTU back.
    hub.setFaults({
      reset_calls: true,
      fail: { IR01: ['mtu_restore'], Het02: ['mtu_restore'] },
      fail_from: { IR01: { mtu_set: 2 }, Het02: { mtu_set: 2 } },
      reachability_fail: ['IR01', 'Het02'],
    });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1400, confirm: true } });
    check('a failed rollback is reported as an error', r.status >= 400, `status=${r.status}`);
    check('the failure names the reachability regression', /reachability/i.test(String(r.data.error)), String(r.data.error));
    check('the rollback is reported as FAILED', r.data.rollback === 'FAILED', String(r.data.rollback));
    check('manual recovery steps are provided for a failed rollback',
      typeof r.data.manual_recovery === 'string' && /gre mtu set/.test(r.data.manual_recovery),
      String(r.data.manual_recovery).slice(0, 120));
    const failedOp = db.prepare("SELECT * FROM edit_operations WHERE kind = 'MTU_CHANGE' ORDER BY created_at DESC LIMIT 1").get();
    check('the journal records ROLLBACK_FAILED', failedOp.status === 'ROLLBACK_FAILED', failedOp.status);
    check('the journal records the rollback state as FAILED', failedOp.rollback_state === 'FAILED', String(failedOp.rollback_state));
    check('the unrolled value is reported honestly',
      mtuOf(await hub.remoteState(), IRAN_HOST) === 1400, String(mtuOf(await hub.remoteState(), IRAN_HOST)));
    const summarised = (await hub.client.call(`/api/gre-connections/${connId}`)).data.mtu;
    check('the summary flags a failed rollback as drift',
      summarised.drift.detected === true && summarised.drift.reasons.some((x) => /rolled back/i.test(x)),
      JSON.stringify(summarised.drift));

    console.log('\nRESTORE PREVIOUS MTU');
    hub.setFaults({});
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/restore`, { method: 'POST', body: { operation_id: firstOpId } });
    check('POST /mtu/restore → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    check('the restore reports its own operation id', !!r.data.operation_id && r.data.operation_id !== firstOpId);
    check('the restore mode is reported', r.data.mode === 'restore', String(r.data.mode));
    check('the restore set the recorded previous values',
      r.data.applied.iran_mtu === 1476 && r.data.applied.foreign_mtu === 1476, JSON.stringify(r.data.applied));
    const restoredState = await hub.remoteState();
    check('both sides read back at the restored MTU',
      mtuOf(restoredState, IRAN_HOST) === 1476 && mtuOf(restoredState, FOREIGN_HOST) === 1476,
      `${mtuOf(restoredState, IRAN_HOST)}/${mtuOf(restoredState, FOREIGN_HOST)}`);
    check('a restore is journaled as an MTU_CHANGE too',
      db.prepare("SELECT COUNT(*) AS n FROM edit_operations WHERE kind = 'MTU_CHANGE' AND status = 'SUCCEEDED'").get().n >= 2);
    const restoreOp = db.prepare("SELECT * FROM edit_operations WHERE operation_id = ?").get(r.data.operation_id);
    check('the restore journal names the operation it restored',
      JSON.parse(restoreOp.requested_state_json).restored_from === firstOpId, restoreOp.requested_state_json);
    check('the restore did not recreate the tunnel either',
      verbsOf(await hub.remoteState(), IRAN_HOST).every((v) => !TUNNEL_REBUILD_VERBS.includes(v)));

    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/restore`, { method: 'POST', body: { operation_id: 'does-not-exist' } });
    check('restoring an unknown operation → 404', r.status === 404, `status=${r.status}`);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/restore`, { method: 'POST', body: {} });
    check('restore without an operation_id → 400', r.status === 400, `status=${r.status}`);
    db.prepare(`INSERT INTO edit_operations (operation_id, connection_uuid, kind, status, created_at)
      VALUES (?,?,?,?,?)`).run('22222222-2222-2222-2222-222222222222', 'other-connection-uuid', 'MTU_CHANGE', 'SUCCEEDED', Date.now());
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/restore`, { method: 'POST', body: { operation_id: '22222222-2222-2222-2222-222222222222' } });
    check("another connection's operation cannot be restored here → 404", r.status === 404, `status=${r.status}`);
    db.prepare(`INSERT INTO edit_operations (operation_id, connection_uuid, kind, status, created_at)
      VALUES (?,?,?,?,?)`).run('33333333-3333-3333-3333-333333333333', connUuid, 'EDIT', 'SUCCEEDED', Date.now());
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu/restore`, { method: 'POST', body: { operation_id: '33333333-3333-3333-3333-333333333333' } });
    check('a non-MTU operation cannot be restored through this endpoint → 404', r.status === 404, `status=${r.status}`);

    console.log('\nDRIFT — the live value disagreeing with the stored one');
    hub.seedFake(seedFor(1400));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('drift is detected when the servers disagree with the journal', r.data.combined.drift.detected === true,
      JSON.stringify(r.data.combined.drift));
    check('the drift reason names the recorded value',
      (r.data.combined.drift.reasons || []).some((x) => /last recorded/.test(x)),
      JSON.stringify(r.data.combined.drift.reasons));

    // Two sides at different MTUs is drift in its own right.
    hub.seedFake({
      [IRAN_HOST]: { ...seedFor(1476)[IRAN_HOST], mtu: { de1: { gre_mtu: 1476, nic_mtu: 1500, overhead: 28 } } },
      [FOREIGN_HOST]: { ...seedFor(1476)[FOREIGN_HOST], mtu: { de1: { gre_mtu: 1400, nic_mtu: 1500, overhead: 28 } } },
    });
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('a disagreement between the two sides is drift',
      r.data.combined.drift.reasons.some((x) => /different GRE MTUs/.test(x)),
      JSON.stringify(r.data.combined.drift.reasons));
    check('the recommendation refuses to average the two sides',
      r.data.recommendation.recommended_gre_mtu === 1472, String(r.data.recommendation.recommended_gre_mtu));
    check('the recommendation flags that the sides disagree', r.data.recommendation.sides_disagree === true);

    // One side unreachable makes the answer unknown rather than a guess.
    const foreignOnly = {
      [IRAN_HOST]: seedFor(1476)[IRAN_HOST],
      [FOREIGN_HOST]: seedFor(1476)[FOREIGN_HOST],
    };
    hub.seedFake(foreignOnly);
    hub.setFaults({ fail: { Het02: ['mtu_diagnose'] } });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('a side that cannot be read is reported per side', r.data.foreign.ok === false && !!r.data.foreign.error);
    check('the other side is still returned', r.data.iran.ok === true);
    check('confidence is unknown when a side is unreadable', r.data.recommendation.confidence === 'unknown',
      r.data.recommendation.confidence);
    check('no recommendation is invented from a failed probe', r.data.recommendation.recommended_gre_mtu === null);
    check('an unreadable side makes the recommendation unsafe to apply', r.data.recommendation.safe_to_apply === false);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`, { method: 'PUT', body: { mtu: 1472, confirm: true } });
    check('an apply with an unreadable side is refused with 409', r.status === 409, `status=${r.status}`);
    hub.setFaults({});
    await sleep(200);

    // A host that cannot be reached, or that answers with something unusable, must be
    // reported per side rather than throwing the request away.
    hub.setFaults({ unreachable: ['IR01'] });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/mtu`);
    check('an unreachable side is reported per side and never thrown',
      r.status === 200 && r.data.iran.ok === false && r.data.foreign.ok === true,
      JSON.stringify({ status: r.status, iran: r.data.iran && r.data.iran.error }));
    check('the per-side error carries the transport failure', /injected failure/.test(String(r.data.iran.error)), String(r.data.iran.error));
    check('a request with one dead side is not a 500', r.status === 200, `status=${r.status}`);
    hub.setFaults({});
    await sleep(200);

    console.log('\nSECRETS ARE NEVER EXPOSED');
    hub.seedFake(seedFor(1476));
    await sleep(150);
    const payloads = [
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/mtu`)).data),
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/mtu/nic`)).data),
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', body: { mtu: 1472 } })).data),
      JSON.stringify((await hub.client.call('/api/gre-connections')).data),
    ].join('\n');
    check('no secret column appears in any MTU payload', !/secret_enc|password_enc/.test(payloads));
    check('no stored password value appears in any MTU payload', !/"pw"/.test(payloads));
    check('the audit log leaks no credential',
      !/secret_enc|password_enc|"pw"/.test(JSON.stringify((await hub.client.call('/api/actions?kind=auth')).data)));

    console.log('\nAUTH AND CSRF');
    const anon = { async call(p, o) { return fetch(hub.base + p, o).then(async (res) => ({ status: res.status, data: await res.json().catch(() => null) })); } };
    check('GET /mtu without a session → 401', (await anon.call(`/api/gre-connections/${connId}/mtu`)).status === 401);
    check('GET /mtu/nic without a session → 401', (await anon.call(`/api/gre-connections/${connId}/mtu/nic`)).status === 401);
    check('POST /mtu/plan without a session → 401', (await anon.call(`/api/gre-connections/${connId}/mtu/plan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status === 401);
    const noSession = await fetch(`${hub.base}/api/gre-connections/${connId}/mtu`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{"mtu":1472,"confirm":true}', redirect: 'manual' });
    check('PUT /mtu without a session is rejected', noSession.status === 401 || noSession.status === 403, `status=${noSession.status}`);
    const noCsrf = await fetch(`${hub.base}/api/gre-connections/${connId}/mtu`, {
      method: 'PUT', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: hub.client.cookie },
      body: '{"mtu":1472,"confirm":true}',
    });
    check('PUT /mtu without a CSRF token is rejected', noCsrf.status === 403 || noCsrf.status === 401, `status=${noCsrf.status}`);
    const noCsrfRestore = await fetch(`${hub.base}/api/gre-connections/${connId}/mtu/restore`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: hub.client.cookie },
      body: '{"operation_id":"x"}',
    });
    check('POST /mtu/restore without a CSRF token is rejected', noCsrfRestore.status === 403 || noCsrfRestore.status === 401, `status=${noCsrfRestore.status}`);

    console.log('\n404s');
    check('GET /mtu on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/mtu')).status === 404);
    check('GET /mtu/nic on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/mtu/nic')).status === 404);
    check('POST /mtu/plan on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/mtu/plan', { method: 'POST', body: { mtu: 1472 } })).status === 404);
    check('PUT /mtu on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/mtu', { method: 'PUT', body: { mtu: 1472, confirm: true } })).status === 404);
    check('POST /mtu/restore on an unknown connection → 404', (await hub.client.call('/api/gre-connections/99999/mtu/restore', { method: 'POST', body: { operation_id: 'x' } })).status === 404);

    console.log('\nACTION REGISTRY');
    const actions = require('../server/actions');
    for (const name of ['mtu_list_json', 'mtu_diagnose', 'mtu_recommend', 'mtu_set', 'mtu_auto', 'mtu_restore', 'mtu_nic_list_json', 'mtu_nic_analyze']) {
      check(`${name} is a registered action`, actions.ACTION_NAMES.includes(name));
    }
    check('mtu_set always carries --yes', /--yes$/.test(actions.buildAction('mtu_set', { name: 'de1', mtu: 1472 })));
    check('mtu_set rejects an out-of-range MTU', (() => {
      try { actions.buildAction('mtu_set', { name: 'de1', mtu: 70000 }); return false; } catch { return true; }
    })());
    check('mtu_set rejects a non-integer MTU', (() => {
      try { actions.buildAction('mtu_set', { name: 'de1', mtu: '14 72' }); return false; } catch { return true; }
    })());
    check('mtu_diagnose rejects an unsafe name', (() => {
      try { actions.buildAction('mtu_diagnose', { name: 'de1; rm -rf /' }); return false; } catch { return true; }
    })());
    check('mtu_restore always carries --yes', /--yes$/.test(actions.buildAction('mtu_restore', { name: 'de1' })));
    check('mtu_diagnose is read-only', !/--yes/.test(actions.buildAction('mtu_diagnose', { name: 'de1' })));
    // A single-sided MTU change would skip the backup, the second side and the
    // verification, so the per-server action endpoint refuses it by name.
    r = await hub.client.call(`/api/servers/${iranId}/action`, { method: 'POST', body: { action: 'mtu_set', params: { name: 'de1', mtu: 1400 } } });
    check('the generic per-server action endpoint refuses mtu_set', r.status === 400, `status=${r.status}`);
    check('the refusal points at the connection MTU flow', /gre-connections/.test(String(r.data.error)), String(r.data.error));
    r = await hub.client.call(`/api/servers/${iranId}/action`, { method: 'POST', body: { action: 'mtu_restore', params: { name: 'de1' } } });
    check('the generic per-server action endpoint refuses mtu_restore', r.status === 400, `status=${r.status}`);
    r = await hub.client.call(`/api/servers/${iranId}/action`, { method: 'POST', body: { action: 'mtu_diagnose', params: { name: 'de1' } } });
    check('a read-only MTU verb is still allowed per server', r.status === 200, `status=${r.status}`);
  } finally {
    await hub.close();
  }

  console.log(`\nmtu tests: ${PASS} passed, ${FAIL} failed`);
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
