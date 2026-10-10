'use strict';

// Hub Full Network Health Check: the two-sided read-only diagnosis, its correlation
// into ONE connection verdict, the read-only repair preview and the verified repair.
//
// These run against a REAL gre-hub process over HTTP, with the ssh transport replaced
// by the stateful fake of the gre CLI (scripts/_fake-gre-ssh.js). The state matters: a
// repair has to be visible to the NEXT health check, or the Hub's verification step
// would pass for the wrong reason.
//
// Run with: node scripts/health-test.js

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const http = require('http');

const PASSWORD = 'health-test-pass-1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let PASS = 0;
let FAIL = 0;
function check(name, cond, extra = '') {
  if (cond) { PASS += 1; console.log(`  ok    ${name}`); } else { FAIL += 1; console.log(`  FAIL  ${name} ${extra}`); }
}

const MUTATING_VERBS = require('./_fake-gre-ssh').MUTATING_VERBS;

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
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-health-'));
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
    seedFake(obj) { fs.writeFileSync(seedFile, JSON.stringify(obj)); },
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
function rawHealthPost(port, cookie, csrf, id, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const agent = new http.Agent({ keepAlive: false, maxSockets: 1 });
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: `/api/gre-connections/${id}/health-check`, agent,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), Cookie: cookie, 'x-csrf-token': csrf },
    }, (res) => {
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

const CHECK_STAGES = ['HEALTH_CHECK_STARTED', 'READ_SIDE', 'DIAGNOSED'];
const REPAIR_STAGES = ['REPAIR_PREVIEW', 'REPAIR_APPLYING', 'REPAIR_VERIFIED'];

// A host's diagnosis, seeded explicitly: `health` is always written so a scenario
// cannot inherit the findings of the previous one.
function seedFor({
  iranFindings = [], foreignFindings = [], iranChecks = [], foreignChecks = [],
  completeness = null, greMtu = 1476,
} = {}) {
  return {
    [IRAN_HOST]: {
      peers: [{ name: 'de1', iran_ip: '198.51.100.20', foreign_ip: '203.0.113.10', subnet_base: '10.200', idx: 1, key: 1001, tcp_ports: '3001', udp_ports: '3001' }],
      mtu: { de1: { gre_mtu: greMtu, nic_mtu: 1500, overhead: 28 } },
      health: { de1: { findings: iranFindings, checks: iranChecks, completeness } },
    },
    [FOREIGN_HOST]: {
      nodes: [{ name: 'de1', iran_ip: '198.51.100.20', subnet_base: '10.200', idx: 1, key: 1001 }],
      mtu: { de1: { gre_mtu: greMtu, nic_mtu: 1500, overhead: 28 } },
      health: { de1: { findings: foreignFindings, checks: foreignChecks, completeness } },
    },
  };
}

const verbsOf = (state, host) => (((state[host] || {}).commands) || []).slice();
const findingsOf = (state, host, name = 'de1') => ((((state[host] || {}).health || {})[name] || {}).findings || []).map((f) => f.code);

async function main() {
  const hub = await bootHub();
  try {
    let r = await hub.client.call('/api/setup', { method: 'POST', body: { password: PASSWORD } });
    check('hub setup', r.status === 200, `status=${r.status}`);
    if (r.status !== 200) throw new Error('setup failed');

    const db = hub.db();
    const cryptoUtil = require('../server/crypto');
    const key = cryptoUtil.loadKey(hub.dataDir);
    const enc = (v) => cryptoUtil.encrypt(key, v);
    const addServer = (name, host) => Number(db.prepare(`INSERT INTO servers
        (name, host, ssh_port, username, auth_type, secret_enc, password_enc, key_installed, created_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(name, host, 22, 'root', 'password', enc('pw'), enc('pw'), 0, Date.now()).lastInsertRowid);

    const iranId = addServer('IR01', IRAN_HOST);
    const foreignId = addServer('Het02', FOREIGN_HOST);
    db.prepare('INSERT INTO xui_panels (name, base_url, username, auth_type, password_enc, created_at) VALUES (?,?,?,?,?,?)')
      .run('panel', 'https://panel.test:2053', 'admin', 'password', enc('tok'), Date.now());

    const connId = seedConnection(hub, { iranId, foreignId });
    const connUuid = () => db.prepare('SELECT connection_uuid FROM gre_routes WHERE id = ?').get(connId).connection_uuid;
    const countOps = (where = '') => db.prepare(`SELECT COUNT(*) AS n FROM edit_operations ${where}`).get().n;

    // ---------------------------------------------------------------- healthy
    hub.seedFake(seedFor({}));
    await sleep(150);

    console.log('\nHEALTHY — BOTH SIDES CHECKED AND MERGED');
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('POST /health-check → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    const firstCheckId = r.data.check_id;
    check('the run reports a check id', !!firstCheckId);
    check('the run names the connection', r.data.connection === 'de1', String(r.data.connection));
    check('the run reports the mode that was asked for', r.data.mode === 'quick', String(r.data.mode));
    check('both sides answered', r.data.combined.both_sides === true && r.data.combined.sides_readable === 2,
      JSON.stringify({ iran: r.data.iran.error, foreign: r.data.foreign.error }));
    check('the Iran column is named', r.data.combined.per_side.iran.server === 'IR01', String(r.data.combined.per_side.iran.server));
    check('the Foreign column is named', r.data.combined.per_side.foreign.server === 'Het02', String(r.data.combined.per_side.foreign.server));
    check('the two sides are identified as iran and foreign',
      r.data.iran.data.side === 'iran' && r.data.foreign.data.side === 'foreign');
    check('a healthy connection is HEALTHY', r.data.combined.overall_status === 'HEALTHY', r.data.combined.overall_status);
    check('a fully read connection has complete evidence',
      r.data.combined.evidence_completeness === 'complete', r.data.combined.evidence_completeness);
    check('no findings on a healthy connection', r.data.combined.findings.length === 0);
    check('every check id appears once in the merged table',
      new Set(r.data.combined.checks.map((c) => c.id)).size === r.data.combined.checks.length);
    const ifaceRow = r.data.combined.checks.find((c) => c.id === 'interface_exists');
    check('a merged check carries both columns', !!ifaceRow && !!ifaceRow.sides.iran && !!ifaceRow.sides.foreign,
      JSON.stringify(ifaceRow));
    check('a merged check names its category', ifaceRow.category === 'C_gre_config', ifaceRow.category);
    check('the merged table has categories for the UI',
      (r.data.combined.categories || []).length >= 6, JSON.stringify((r.data.combined.categories || []).map((c) => c.category)));
    check('the GRE configuration category holds its checks',
      ((r.data.combined.categories || []).find((c) => c.category === 'C_gre_config') || {}).check_ids.includes('interface_exists'));
    const skipped = r.data.combined.checks.find((c) => c.id === 'inner_ping');
    check('a quick check reports its skipped probes as SKIPPED, not as PASS',
      !!skipped && skipped.sides.iran.status === 'SKIPPED', JSON.stringify(skipped));
    check('the summary counts the skipped probes', r.data.combined.summary.skipped > 0, JSON.stringify(r.data.combined.summary));
    check('the per-side summary carries the raw counts',
      r.data.combined.per_side.iran.summary.pass > 0 && r.data.combined.per_side.iran.summary.skipped > 0);
    check('the per-side column lists its own checks', r.data.combined.per_side.iran.checks.length > 0);
    check('the run carries the raw per-side payload for evidence', !!r.data.iran.data && !!r.data.foreign.data);
    check('the first run has nothing to compare against', r.data.combined.previous === null, JSON.stringify(r.data.combined.previous));

    console.log('\nHISTORY — THE RUN IS STORED IN THE JOURNAL');
    const opsAfterFirst = countOps();
    check('the run created exactly one journal row',
      countOps("WHERE kind = 'HEALTH_CHECK'") === 1, String(countOps("WHERE kind = 'HEALTH_CHECK'")));
    check('the run did not create an EDIT or MTU_CHANGE row',
      countOps("WHERE kind NOT IN ('HEALTH_CHECK', 'HEALTH_REPAIR')") === 0);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-checks`);
    check('GET /health-checks → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('the history lists the run', r.data.count === 1 && r.data.checks.length === 1, JSON.stringify(r.data).slice(0, 200));
    check('the history entry names the verdict', r.data.checks[0].overall_status === 'HEALTHY', String(r.data.checks[0].overall_status));
    check('the history entry reports the run as SUCCEEDED', r.data.checks[0].status === 'SUCCEEDED', String(r.data.checks[0].status));
    check('the history entry carries its check id', r.data.checks[0].check_id === firstCheckId);
    check('the history entry carries both side outcomes', !!r.data.checks[0].sides && r.data.checks[0].sides.iran.ok === true);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-checks/${firstCheckId}`);
    check('GET one stored run → 200', r.status === 200, JSON.stringify(r.data).slice(0, 160));
    check('the stored run holds the merged view', r.data.run.combined.overall_status === 'HEALTHY');
    check('the stored run holds the two-sided checks', (r.data.run.combined.checks || []).length > 0);
    check('the stored run is identified by the check id', r.data.check_id === firstCheckId);
    check('an unknown check id → 404',
      (await hub.client.call(`/api/gre-connections/${connId}/health-checks/does-not-exist`)).status === 404);
    db.prepare(`INSERT INTO edit_operations (operation_id, connection_uuid, kind, status, created_at)
      VALUES (?,?,?,?,?)`).run('44444444-4444-4444-4444-444444444444', 'another-connection', 'HEALTH_CHECK', 'SUCCEEDED', Date.now());
    check("another connection's check id → 404",
      (await hub.client.call(`/api/gre-connections/${connId}/health-checks/44444444-4444-4444-4444-444444444444`)).status === 404);
    db.prepare(`INSERT INTO edit_operations (operation_id, connection_uuid, kind, status, created_at)
      VALUES (?,?,?,?,?)`).run('55555555-5555-5555-5555-555555555555', connUuid(), 'EDIT', 'SUCCEEDED', Date.now());
    check('a non-health operation is not readable through the check route',
      (await hub.client.call(`/api/gre-connections/${connId}/health-checks/55555555-5555-5555-5555-555555555555`)).status === 404);
    // Remove the two planted rows again: everything after this point counts journal rows.
    db.prepare("DELETE FROM edit_operations WHERE operation_id IN ('44444444-4444-4444-4444-444444444444', '55555555-5555-5555-5555-555555555555')").run();
    check('the planted rows are gone again', countOps() === opsAfterFirst, String(countOps() - opsAfterFirst));

    r = await hub.client.call(`/api/gre-connections/${connId}/events`);
    let stages = (r.data || []).map((e) => e.stage).filter((s) => CHECK_STAGES.includes(s));
    let collapsed = stages.filter((s, i) => i === 0 || stages[i - 1] !== s);
    check('the check stages appear in the timeline', CHECK_STAGES.every((s) => stages.includes(s)), stages.join(','));
    check('the check stages appear in the mandatory order', collapsed.join(',') === CHECK_STAGES.join(','), collapsed.join(','));
    check('the timeline records the diagnosis as PASS',
      (r.data || []).some((e) => e.stage === 'DIAGNOSED' && e.status === 'PASS'));

    console.log('\nA BROKEN VERDICT IS DATA, NOT A COMMAND FAILURE');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_MISSING', severity: 'critical' }] }));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('a BROKEN diagnosis is returned as 200, not as a failure', r.status === 200, `status=${r.status}`);
    check('the failing host is still reported as read', r.data.iran.ok === true, String(r.data.iran.error));
    check('the non-zero exit of the CLI is recorded as such', r.data.iran.rc === 1 && r.data.iran.broken_exit === true,
      JSON.stringify({ rc: r.data.iran.rc, broken_exit: r.data.iran.broken_exit }));
    check('the verdict is BROKEN', r.data.combined.overall_status === 'BROKEN', r.data.combined.overall_status);
    check('the critical finding is counted', r.data.combined.summary.critical_findings === 1,
      JSON.stringify(r.data.combined.summary));
    check('the failed check is counted', r.data.combined.summary.fail >= 1, JSON.stringify(r.data.combined.summary));
    check('the finding names the side it came from',
      r.data.combined.findings[0].sides.join(',') === 'iran', JSON.stringify(r.data.combined.findings[0].sides));
    check('the finding carries its repair key',
      r.data.combined.findings[0].repair_key === 'iface_up', String(r.data.combined.findings[0].repair_key));

    console.log('\nCORRELATION — A CODE ON BOTH SIDES IS ONE FINDING WITH TWO SIDES');
    hub.seedFake(seedFor({
      iranFindings: [{ code: 'GRE_KEY_MISMATCH', severity: 'critical', evidence: 'Iran key 2002' }],
      foreignFindings: [{ code: 'GRE_KEY_MISMATCH', severity: 'critical', evidence: 'Foreign key 3003' }],
      greMtu: 1476,
    }));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    const shared = (r.data.combined.findings || []).filter((f) => f.code === 'GRE_KEY_MISMATCH');
    check('a code present on both sides is reported exactly once', shared.length === 1, String(shared.length));
    check('the merged finding names both sides', shared[0].sides.join(',') === 'iran,foreign', JSON.stringify(shared[0].sides));
    check('the merged finding keeps each side\'s own evidence',
      shared[0].by_side.iran.evidence === 'Iran key 2002' && shared[0].by_side.foreign.evidence === 'Foreign key 3003',
      JSON.stringify(shared[0].by_side));
    check('the merged finding says which sides can repair it',
      shared[0].repairable_on.join(',') === 'iran,foreign', JSON.stringify(shared[0].repairable_on));
    check('the merged finding takes the worst risk of its sides', shared[0].risk === 'medium', String(shared[0].risk));
    check('a critical finding on both sides cannot be downgraded', shared[0].severity === 'critical', shared[0].severity);
    check('the connection verdict is BROKEN', r.data.combined.overall_status === 'BROKEN',
      r.data.combined.overall_status);

    console.log('\nCORRELATION — A CODE ON ONE SIDE ONLY');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_MTU_MISMATCH', severity: 'warning' }] }));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('a one-sided code produces one finding', r.data.combined.findings.length === 1, JSON.stringify(r.data.combined.findings));
    check('the finding names only the side that reported it',
      r.data.combined.findings[0].sides.join(',') === 'iran', JSON.stringify(r.data.combined.findings[0].sides));
    check('the other side reports no finding', r.data.combined.per_side.foreign.findings.length === 0);
    check('a warning alone is DEGRADED, not BROKEN', r.data.combined.overall_status === 'DEGRADED',
      r.data.combined.overall_status);
    check('the warning is counted separately from a critical',
      r.data.combined.summary.warning_findings === 1 && r.data.combined.summary.critical_findings === 0,
      JSON.stringify(r.data.combined.summary));
    check('the finding is offered for repair', r.data.combined.findings[0].safe_repair === true
      && r.data.combined.findings[0].repair_key === 'mtu_set', JSON.stringify(r.data.combined.findings[0]));

    console.log('\nONE SIDE UNREACHABLE — THE OTHER IS STILL REPORTED');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_TCP_MSS_PROBLEM', severity: 'warning' }] }));
    await sleep(150);
    hub.setFaults({ fail: { Het02: ['health_check'] } });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('a dead side is reported per side and never throws', r.status === 200 && r.data.foreign.ok === false,
      JSON.stringify({ status: r.status, foreign: r.data.foreign && r.data.foreign.error }));
    check('the per-side error carries the transport failure', /injected failure/.test(String(r.data.foreign.error)),
      String(r.data.foreign.error));
    check('the readable side is still returned', r.data.iran.ok === true, String(r.data.iran.error));
    check('the readable side keeps its own findings',
      r.data.combined.per_side.iran.findings.some((f) => f.code === 'GRE_TCP_MSS_PROBLEM'));
    check('the unreadable side is named', r.data.combined.sides_unreadable.join(',') === 'foreign');
    check('partial evidence is reported as partial', r.data.combined.evidence_completeness === 'partial',
      r.data.combined.evidence_completeness);
    check('a half-read connection is never HEALTHY', r.data.combined.overall_status === 'DEGRADED',
      r.data.combined.overall_status);
    const insufficient = r.data.combined.findings.find((f) => f.code === 'INSUFFICIENT_EVIDENCE');
    check('the unreadable side is recorded as an explicit finding',
      !!insufficient && insufficient.sides.join(',') === 'foreign' && insufficient.synthetic === true);
    check('that finding is not offered for repair', insufficient.safe_repair === false);
    hub.setFaults({});
    await sleep(200);

    console.log('\nREAD-ONLY GUARANTEE — NO MUTATING VERB IS EVER REACHED');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    const beforeRead = await hub.remoteState();
    const iranBefore = verbsOf(beforeRead, IRAN_HOST).length;
    const foreignBefore = verbsOf(beforeRead, FOREIGN_HOST).length;
    const rowBeforeRead = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
    const opsBeforeRead = countOps();
    let readOnlyRun = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    const afterRead = await hub.remoteState();
    const iranNew = verbsOf(afterRead, IRAN_HOST).slice(iranBefore);
    const foreignNew = verbsOf(afterRead, FOREIGN_HOST).slice(foreignBefore);
    check('the check drove gre health-check on Iran', iranNew.includes('health_check'), iranNew.join(','));
    check('the check drove gre health-check on the Foreign side', foreignNew.includes('health_check'), foreignNew.join(','));
    check('no mutating verb ran on Iran',
      iranNew.every((v) => !MUTATING_VERBS.includes(v)), iranNew.join(','));
    check('no mutating verb ran on the Foreign side',
      foreignNew.every((v) => !MUTATING_VERBS.includes(v)), foreignNew.join(','));
    check('the seeded finding was NOT repaired by a read-only check',
      findingsOf(afterRead, IRAN_HOST).includes('GRE_INTERFACE_DOWN'), findingsOf(afterRead, IRAN_HOST).join(','));
    check('the foreign diagnosis was not touched either', findingsOf(afterRead, FOREIGN_HOST).length === 0);
    check('the health check mutated no route row',
      JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === rowBeforeRead);
    check('the health check created exactly one journal row', countOps() === opsBeforeRead + 1, String(countOps() - opsBeforeRead));
    check('the health check created no operation of another kind',
      countOps("WHERE kind NOT IN ('HEALTH_CHECK', 'HEALTH_REPAIR')") === 0);
    check('the check released its lock', (await hub.client.call('/api/gre-connections')).data.every((c) => c.busy === false));
    check('the second run can see the previous one', readOnlyRun.data.combined.previous !== null,
      JSON.stringify(readOnlyRun.data.combined.previous));
    check('the previous run is the immediately preceding check',
      readOnlyRun.data.combined.previous.overall_status === 'DEGRADED'
      && readOnlyRun.data.combined.previous.evidence_completeness === 'partial',
      JSON.stringify(readOnlyRun.data.combined.previous));

    console.log('\nLOCKS — A CONCURRENT HEALTH CHECK IS REFUSED');
    const uuid = connUuid();
    let hold = hub.client.call('/api/test/hold-lock', { method: 'POST', body: { key: uuid, hold_ms: 2500 } });
    await sleep(150);
    const opsBeforeRefused = countOps();
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('a health check is refused while the connection is locked', r.status === 409, `status=${r.status}`);
    check('the refusal explains that something is already running', /already running/i.test(String(r.data.error)), String(r.data.error));
    check('a refused read-only run leaves no journal row behind', countOps() === opsBeforeRefused,
      String(countOps() - opsBeforeRefused));
    check('the locked connection shows as busy',
      (await hub.client.call('/api/gre-connections')).data.some((c) => c.busy === true));
    await hold;
    await sleep(200);
    check('the lock is released when the holder finishes',
      (await hub.client.call('/api/gre-connections')).data.every((c) => c.busy === false));

    // Two requests really in flight together. The fake is slowed on health_check so the
    // window the lock protects is a real one.
    hub.setFaults({ delay_ms: { IR01: { health_check: 300 }, Het02: { health_check: 300 } } });
    await sleep(200);
    const [h1, h2] = await Promise.all([
      rawHealthPost(hub.port, hub.client.cookie, hub.client.csrf, connId, { mode: 'quick' }),
      rawHealthPost(hub.port, hub.client.cookie, hub.client.csrf, connId, { mode: 'quick' }),
    ]);
    const statuses = [h1.status, h2.status].sort();
    check('two concurrent health checks: exactly one runs', statuses[0] === 200 && statuses[1] === 409, statuses.join(','));
    hub.setFaults({});
    await sleep(200);

    console.log('\nBOTH SIDES ARE CHECKED IN PARALLEL');
    hub.setFaults({ delay_ms: { IR01: { health_check: 600 }, Het02: { health_check: 600 } } });
    await sleep(200);
    const startedAt = Date.now();
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    const elapsedMs = Date.now() - startedAt;
    check('both slowed sides still answered', r.status === 200 && r.data.combined.both_sides === true, `status=${r.status}`);
    check('the two sides are read in parallel, not one after the other', elapsedMs < 1100, `${elapsedMs} ms`);
    hub.setFaults({});
    await sleep(200);

    console.log('\nREPAIR PREVIEW — READ-ONLY AND HONEST ABOUT WHAT IT CAN DO');
    hub.seedFake(seedFor({
      iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }],
      foreignFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }],
    }));
    await sleep(150);
    const rowBeforePreview = JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId));
    const opsBeforePreview = countOps();
    const stateBeforePreview = await hub.remoteState();
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN' } });
    check('POST /repairs/preview → 200', r.status === 200, JSON.stringify(r.data).slice(0, 200));
    check('the preview marks itself read-only', r.data.read_only === true);
    check('the preview echoes the code', r.data.code === 'GRE_INTERFACE_DOWN', String(r.data.code));
    check('the Iran side is reported as able to repair', r.data.sides.iran.can_repair === true, JSON.stringify(r.data.sides.iran));
    check('the Foreign side is reported as able to repair', r.data.sides.foreign.can_repair === true);
    check('both sides are listed as repairable', r.data.repairable_sides.join(',') === 'iran,foreign',
      JSON.stringify(r.data.repairable_sides));
    check('the preview states the risk of the repair', r.data.risk_level === 'low', String(r.data.risk_level));
    check('the preview states what the CLI would do',
      /interface up/i.test(String(r.data.sides.iran.recommended_action)), String(r.data.sides.iran.recommended_action));
    check('the preview names the repair key', r.data.repair_keys.join(',') === 'iface_up', JSON.stringify(r.data.repair_keys));
    check('the preview lists what will happen',
      Array.isArray(r.data.what_happens) && r.data.what_happens.length >= 2, JSON.stringify(r.data.what_happens));
    check('the preview states the scope is this connection only',
      r.data.what_happens.some((x) => /this connection only/i.test(x)), JSON.stringify(r.data.what_happens));
    check('the preview lists the verification that will run', (r.data.verification || []).length === 3);
    check('the verification is a fresh two-sided check',
      r.data.verification.some((v) => /no longer reports this code/.test(v.description)));
    check('the preview explains that a repair is not rolled back',
      (r.data.rollback_conditions || []).some((x) => /not rolled back/i.test(x)), JSON.stringify(r.data.rollback_conditions));
    check('the preview can be applied', r.data.can_apply === true, String(r.data.blocked_reason));
    check('the preview mutated no route row',
      JSON.stringify(db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(connId)) === rowBeforePreview);
    check('the preview created no operation', countOps() === opsBeforePreview, String(countOps() - opsBeforePreview));
    const stateAfterPreview = await hub.remoteState();
    check('the preview repaired nothing on Iran', findingsOf(stateAfterPreview, IRAN_HOST).includes('GRE_INTERFACE_DOWN'),
      findingsOf(stateAfterPreview, IRAN_HOST).join(','));
    check('the preview repaired nothing on the Foreign side',
      findingsOf(stateAfterPreview, FOREIGN_HOST).includes('GRE_INTERFACE_DOWN'));
    check('the preview ran no mutating verb',
      verbsOf(stateAfterPreview, IRAN_HOST).slice(verbsOf(stateBeforePreview, IRAN_HOST).length)
        .every((v) => !MUTATING_VERBS.includes(v)),
      verbsOf(stateAfterPreview, IRAN_HOST).slice(verbsOf(stateBeforePreview, IRAN_HOST).length).join(','));
    check('the preview asked each side what it can repair',
      verbsOf(stateAfterPreview, IRAN_HOST).slice(verbsOf(stateBeforePreview, IRAN_HOST).length).includes('repair_preview'),
      verbsOf(stateAfterPreview, IRAN_HOST).slice(verbsOf(stateBeforePreview, IRAN_HOST).length).join(','));

    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: { code: 'GRE_MODULE_MISSING' } });
    check('a code no side reports cannot be applied', r.data.can_apply === false, String(r.data.blocked_reason));
    check('the refusal says it is not repairable automatically', /not repairable/i.test(String(r.data.blocked_reason)),
      String(r.data.blocked_reason));
    check('the per-side reason is stated too', r.data.sides.iran.can_repair === false && /does not offer/i.test(String(r.data.sides.iran.reason)),
      String(r.data.sides.iran.reason));

    hub.seedFake(seedFor({ iranFindings: [{ code: 'FIREWALL_RULE_CONFLICT', severity: 'critical' }] }));
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: { code: 'FIREWALL_RULE_CONFLICT' } });
    check('a finding with no safe repair cannot be applied', r.data.can_apply === false, String(r.data.blocked_reason));
    check('the per-side reason says that end offers no safe repair',
      /does not offer a safe automated repair/i.test(String(r.data.sides.iran.reason)), String(r.data.sides.iran.reason));
    check('the preview lists no repairable code for that end', r.data.sides.iran.repairable_codes.length === 0,
      JSON.stringify(r.data.sides.iran.repairable_codes));
    // The unsafe finding is still fully described by the health check itself, which is
    // what the UI renders the reason from.
    const unsafeRun = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    const unsafe = unsafeRun.data.combined.findings.find((f) => f.code === 'FIREWALL_RULE_CONFLICT');
    check('the health check marks the finding unsafe and states its risk',
      !!unsafe && unsafe.safe_repair === false && unsafe.risk === 'high', JSON.stringify(unsafe));
    check('the unsafe finding still carries its remediation for a human',
      /by hand/i.test(String(unsafe.recommended_action)), String(unsafe.recommended_action));

    check('a malformed code is refused with 400',
      (await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: { code: 'drop; rm -rf /' } })).status === 400);
    check('a missing code is refused with 400',
      (await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: {} })).status === 400);
    check('a preview on an unknown connection → 404',
      (await hub.client.call('/api/gre-connections/99999/repairs/preview', { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN' } })).status === 404);

    console.log('\nREPAIR APPLY — GATES');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    let opsBeforeGates = countOps();
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN' } });
    check('a repair without confirm is refused with 400', r.status === 400, `status=${r.status}`);
    check('the refusal explains the confirmation requirement', /confirm/i.test(String(r.data.error)), String(r.data.error));
    check('a repair with a malformed code is refused with 400',
      (await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'nope', confirm: true } })).status === 400);
    check('a refused repair creates no operation', countOps() === opsBeforeGates, String(countOps() - opsBeforeGates));

    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_MODULE_MISSING', confirm: true } });
    check('a code no side can repair is refused with 409', r.status === 409, `status=${r.status}`);
    check('the refusal carries the read-only plan', !!r.data.plan && r.data.plan.read_only === true);
    check('a plan-refused repair creates no operation', countOps() === opsBeforeGates, String(countOps() - opsBeforeGates));

    hub.setFaults({ fail: { Het02: ['repair_preview'] } });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN', confirm: true } });
    check('an unreadable side blocks the repair rather than half-applying it', r.status === 409, `status=${r.status}`);
    check('the refusal says why the repair cannot be verified', /could not be read/i.test(String(r.data.error)), String(r.data.error));
    hub.setFaults({});
    await sleep(200);

    console.log('\nREPAIR APPLY — THE CONNECTION LOCK IS REQUIRED');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    let verbCountBeforeLock = verbsOf(await hub.remoteState(), IRAN_HOST).length;
    hold = hub.client.call('/api/test/hold-lock', { method: 'POST', body: { key: uuid, hold_ms: 2500 } });
    await sleep(150);
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN', confirm: true } });
    check('a repair is refused while the connection is locked', r.status === 409, `status=${r.status}`);
    check('the refusal names the running operation', /already running/i.test(String(r.data.error)), String(r.data.error));
    check('the refused attempt is journaled as REJECTED',
      db.prepare("SELECT * FROM edit_operations WHERE kind = 'HEALTH_REPAIR' ORDER BY created_at DESC LIMIT 1").get().status === 'REJECTED');
    const stateAfterRefusedApply = await hub.remoteState();
    check('the refused repair ran no repair verb',
      verbsOf(stateAfterRefusedApply, IRAN_HOST).slice(verbCountBeforeLock).every((v) => v !== 'repair_apply'),
      verbsOf(stateAfterRefusedApply, IRAN_HOST).slice(verbCountBeforeLock).join(','));
    check('the finding is still there after the refusal', findingsOf(stateAfterRefusedApply, IRAN_HOST).includes('GRE_INTERFACE_DOWN'));
    await hold;
    await sleep(200);

    console.log('\nREPAIR APPLY — SUCCESS IS VERIFIED BY A FRESH CHECK');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    const beforeRepair = await hub.remoteState();
    const iranVerbsBefore = verbsOf(beforeRepair, IRAN_HOST).length;
    const foreignVerbsBefore = verbsOf(beforeRepair, FOREIGN_HOST).length;
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN', confirm: true } });
    check('POST /repairs/apply → 200', r.status === 200, JSON.stringify(r.data).slice(0, 250));
    check('the repair reports success', r.data.ok === true);
    check('the repair is not partial', r.data.partial === false);
    check('the repair reports its operation id', !!r.data.operation_id);
    check('the repair reports which side it applied to', r.data.applied_sides.join(',') === 'iran',
      JSON.stringify(r.data.applied_sides));
    check('the repair reports the verification as verified', r.data.verification.verified === true,
      JSON.stringify(r.data.verification));
    check('the verification found the code gone', r.data.verification.still_reported_on.length === 0);
    check('the connection is HEALTHY after the repair', r.data.after.overall_status === 'HEALTHY', r.data.after.overall_status);
    check('the verification ran on both sides', r.data.after.sides_readable === 2);
    check('the response carries the connection projection', !!r.data.connection && r.data.connection.name === 'de1');
    const stateAfterRepair = await hub.remoteState();
    check('the finding is gone from the repaired host',
      !findingsOf(stateAfterRepair, IRAN_HOST).includes('GRE_INTERFACE_DOWN'), findingsOf(stateAfterRepair, IRAN_HOST).join(','));
    const iranRepairVerbs = verbsOf(stateAfterRepair, IRAN_HOST).slice(iranVerbsBefore);
    const foreignRepairVerbs = verbsOf(stateAfterRepair, FOREIGN_HOST).slice(foreignVerbsBefore);
    check('the repair drove gre repair apply on Iran', iranRepairVerbs.includes('repair_apply'), iranRepairVerbs.join(','));
    check('the repair was verified by a fresh health check',
      iranRepairVerbs.includes('health_check'), iranRepairVerbs.join(','));
    check('the verification ran after the repair',
      iranRepairVerbs.indexOf('repair_apply') < iranRepairVerbs.lastIndexOf('health_check'), iranRepairVerbs.join(','));
    check('the side that offered no repair was not touched by repair_apply',
      !foreignRepairVerbs.includes('repair_apply'), foreignRepairVerbs.join(','));
    check('the untouched side was still re-checked', foreignRepairVerbs.includes('health_check'), foreignRepairVerbs.join(','));
    check('the only mutating verb a repair reaches is repair_apply',
      iranRepairVerbs.filter((v) => MUTATING_VERBS.includes(v)).join(',') === 'repair_apply', iranRepairVerbs.join(','));

    const repairJournal = db.prepare("SELECT * FROM edit_operations WHERE kind = 'HEALTH_REPAIR' ORDER BY created_at DESC LIMIT 1").get();
    check('the repair is journaled as HEALTH_REPAIR', !!repairJournal && repairJournal.kind === 'HEALTH_REPAIR');
    check('the successful repair is journaled as SUCCEEDED', repairJournal.status === 'SUCCEEDED', repairJournal.status);
    check('the journal records the code that was repaired',
      JSON.parse(repairJournal.requested_state_json).code === 'GRE_INTERFACE_DOWN', repairJournal.requested_state_json);
    check('the journal records that nothing was rolled back', repairJournal.rollback_state === 'NONE',
      String(repairJournal.rollback_state));
    check('the journal holds no credential',
      !/secret_enc|password_enc|"pw"|PRIVATE KEY/.test(JSON.stringify(db.prepare('SELECT * FROM edit_operations').all())));

    r = await hub.client.call(`/api/gre-connections/${connId}/events`);
    stages = (r.data || []).map((e) => e.stage).filter((s) => REPAIR_STAGES.includes(s));
    collapsed = stages.filter((s, i) => i === 0 || stages[i - 1] !== s);
    check('every repair stage appears in the timeline', REPAIR_STAGES.every((s) => stages.includes(s)), stages.join(','));
    check('the repair stages appear in the mandatory order', collapsed.join(',') === REPAIR_STAGES.join(','), collapsed.join(','));
    check('the timeline records the verification as PASS',
      (r.data || []).some((e) => e.stage === 'REPAIR_VERIFIED' && e.status === 'PASS'));

    r = await hub.client.call(`/api/gre-connections/${connId}/health-checks`);
    check('the history now includes the repair', r.data.checks.some((c) => c.kind === 'HEALTH_REPAIR'),
      JSON.stringify(r.data.checks.map((c) => c.kind)));
    check('the history is newest first', r.data.checks[0].kind === 'HEALTH_REPAIR', r.data.checks[0].kind);
    check('the history entry records the code', r.data.checks[0].code === 'GRE_INTERFACE_DOWN', String(r.data.checks[0].code));
    const storedRepair = await hub.client.call(`/api/gre-connections/${connId}/health-checks/${repairJournal.operation_id}`);
    check('a stored repair is readable through the same route', storedRepair.status === 200, `status=${storedRepair.status}`);
    check('the stored repair keeps its verified outcome',
      storedRepair.data.run && storedRepair.data.run.verification && storedRepair.data.run.verification.verified === true);

    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } });
    check('a fresh check after the repair reports no findings', r.data.combined.findings.length === 0,
      JSON.stringify(r.data.combined.findings));
    check('a fresh check after the repair reports HEALTHY', r.data.combined.overall_status === 'HEALTHY',
      r.data.combined.overall_status);

    console.log('\nREPAIR APPLY — A REPAIR THAT CHANGED NOTHING IS A FAILURE');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    hub.setFaults({ repair_noop: ['IR01'] });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN', confirm: true } });
    check('a repair whose code survives is reported as an error', r.status >= 400, `status=${r.status}`);
    check('the failure is explicit that nothing was fixed', r.data.ok === false && /still report/i.test(String(r.data.error)),
      String(r.data.error));
    check('the failure names the side that still reports the code',
      (r.data.verification.still_reported_on || []).join(',') === 'iran', JSON.stringify(r.data.verification));
    check('the failure is not dressed up as a partial success', r.data.partial === false);
    check('the apply itself is reported honestly as having run',
      (r.data.applied || []).length === 1 && r.data.applied[0].ok === true, JSON.stringify(r.data.applied));
    const noopOp = db.prepare("SELECT * FROM edit_operations WHERE kind = 'HEALTH_REPAIR' ORDER BY created_at DESC LIMIT 1").get();
    check('an unverified repair is journaled as FAILED', noopOp.status === 'FAILED', noopOp.status);
    check('the finding is still present on the host', findingsOf(await hub.remoteState(), IRAN_HOST).includes('GRE_INTERFACE_DOWN'));
    hub.setFaults({});
    await sleep(200);

    console.log('\nREPAIR APPLY — ONE SIDE REPAIRED, THE OTHER FAILING IS PARTIAL');
    hub.seedFake(seedFor({
      iranFindings: [{ code: 'GRE_KEY_MISMATCH', severity: 'critical' }],
      foreignFindings: [{ code: 'GRE_KEY_MISMATCH', severity: 'critical' }],
    }));
    await sleep(150);
    hub.setFaults({ fail: { Het02: ['repair_apply'] } });
    await sleep(200);
    r = await hub.client.call(`/api/gre-connections/${connId}/repairs/apply`, { method: 'POST', body: { code: 'GRE_KEY_MISMATCH', confirm: true } });
    check('a one-sided repair failure is reported as an error', r.status >= 400, `status=${r.status}`);
    check('the outcome is reported as PARTIAL, never as success', r.data.partial === true && r.data.ok === false,
      JSON.stringify({ partial: r.data.partial, ok: r.data.ok }));
    check('the error says the repair did not reach everywhere', /not everywhere/i.test(String(r.data.error)), String(r.data.error));
    check('the side that worked is named', r.data.applied_sides.join(',') === 'iran', JSON.stringify(r.data.applied_sides));
    check('both sides are reported as attempted', r.data.attempted_sides.join(',') === 'iran,foreign',
      JSON.stringify(r.data.attempted_sides));
    check('the failing side is reported with its own failure',
      (r.data.applied || []).some((a) => a.side === 'foreign' && a.ok === false && /injected failure/.test(String(a.detail))),
      JSON.stringify(r.data.applied));
    check('the verification names the side the code survives on',
      (r.data.verification.still_reported_on || []).join(',') === 'foreign', JSON.stringify(r.data.verification));
    const partialState = await hub.remoteState();
    check('the repaired side really is repaired', !findingsOf(partialState, IRAN_HOST).includes('GRE_KEY_MISMATCH'),
      findingsOf(partialState, IRAN_HOST).join(','));
    check('the failing side still reports the code', findingsOf(partialState, FOREIGN_HOST).includes('GRE_KEY_MISMATCH'),
      findingsOf(partialState, FOREIGN_HOST).join(','));
    const partialOp = db.prepare("SELECT * FROM edit_operations WHERE kind = 'HEALTH_REPAIR' ORDER BY created_at DESC LIMIT 1").get();
    check('a partial repair is journaled as PARTIAL', partialOp.status === 'PARTIAL', partialOp.status);
    check('the partial journal entry records the partial flag',
      JSON.parse(partialOp.plan_json).partial === true, partialOp.plan_json);
    check('the partial journal entry holds no credential',
      !/secret_enc|password_enc|"pw"/.test(JSON.stringify(partialOp)));
    hub.setFaults({});
    await sleep(200);

    console.log('\nSECRETS ARE NEVER EXPOSED');
    hub.seedFake(seedFor({ iranFindings: [{ code: 'GRE_INTERFACE_DOWN', severity: 'critical' }] }));
    await sleep(150);
    const payloads = [
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick' } })).data),
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/health-checks`)).data),
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN' } })).data),
      JSON.stringify((await hub.client.call(`/api/gre-connections/${connId}`)).data),
      JSON.stringify((await hub.client.call('/api/gre-connections')).data),
    ].join('\n');
    check('no secret column appears in any health payload', !/secret_enc|password_enc/.test(payloads));
    check('no stored password value appears in any health payload', !/"pw"/.test(payloads));
    check('no private key material appears in any health payload', !/PRIVATE KEY/.test(payloads));
    check('the audit log leaks no credential',
      !/secret_enc|password_enc|"pw"/.test(JSON.stringify((await hub.client.call('/api/actions?kind=auth')).data)));

    console.log('\nAUTH AND CSRF');
    const anon = {
      async call(p, o) {
        return fetch(hub.base + p, o).then(async (res) => ({ status: res.status, data: await res.json().catch(() => null) }));
      },
    };
    check('POST /health-check without a session → 401',
      (await anon.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"mode":"quick"}' })).status === 401);
    check('GET /health-checks without a session → 401',
      (await anon.call(`/api/gre-connections/${connId}/health-checks`)).status === 401);
    check('GET one health check without a session → 401',
      (await anon.call(`/api/gre-connections/${connId}/health-checks/x`)).status === 401);
    check('POST /repairs/preview without a session → 401',
      (await anon.call(`/api/gre-connections/${connId}/repairs/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"code":"GRE_INTERFACE_DOWN"}' })).status === 401);
    const noSession = await fetch(`${hub.base}/api/gre-connections/${connId}/repairs/apply`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json' },
      body: '{"code":"GRE_INTERFACE_DOWN","confirm":true}',
    });
    check('POST /repairs/apply without a session is rejected', noSession.status === 401 || noSession.status === 403,
      `status=${noSession.status}`);
    const noCsrfCheck = await fetch(`${hub.base}/api/gre-connections/${connId}/health-check`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: hub.client.cookie },
      body: '{"mode":"quick"}',
    });
    check('POST /health-check without a CSRF token is rejected',
      noCsrfCheck.status === 403 || noCsrfCheck.status === 401, `status=${noCsrfCheck.status}`);
    const noCsrfPreview = await fetch(`${hub.base}/api/gre-connections/${connId}/repairs/preview`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: hub.client.cookie },
      body: '{"code":"GRE_INTERFACE_DOWN"}',
    });
    check('POST /repairs/preview without a CSRF token is rejected',
      noCsrfPreview.status === 403 || noCsrfPreview.status === 401, `status=${noCsrfPreview.status}`);
    const noCsrfApply = await fetch(`${hub.base}/api/gre-connections/${connId}/repairs/apply`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: hub.client.cookie },
      body: '{"code":"GRE_INTERFACE_DOWN","confirm":true}',
    });
    check('POST /repairs/apply without a CSRF token is rejected',
      noCsrfApply.status === 403 || noCsrfApply.status === 401, `status=${noCsrfApply.status}`);

    console.log('\n404s AND BAD REQUESTS');
    check('POST /health-check on an unknown connection → 404',
      (await hub.client.call('/api/gre-connections/99999/health-check', { method: 'POST', body: { mode: 'quick' } })).status === 404);
    check('GET /health-checks on an unknown connection → 404',
      (await hub.client.call('/api/gre-connections/99999/health-checks')).status === 404);
    check('POST /repairs/apply on an unknown connection → 404',
      (await hub.client.call('/api/gre-connections/99999/repairs/apply', { method: 'POST', body: { code: 'GRE_INTERFACE_DOWN', confirm: true } })).status === 404);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'bogus' } });
    check('an unknown mode is refused with 400', r.status === 400, `status=${r.status}`);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick', budget: 0 } });
    check('a zero budget is refused with 400', r.status === 400, `status=${r.status}`);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'quick', budget: 100000 } });
    check('an absurd budget is refused with 400', r.status === 400, `status=${r.status}`);
    r = await hub.client.call(`/api/gre-connections/${connId}/health-check`, { method: 'POST', body: { mode: 'full', budget: 40 } });
    check('a full check with an explicit budget runs', r.status === 200 && r.data.mode === 'full' && r.data.combined.budget_seconds === 40,
      JSON.stringify({ status: r.status, mode: r.data.mode, budget: r.data.combined.budget_seconds }));

    console.log('\nACTION REGISTRY');
    const actions = require('../server/actions');
    for (const name of ['health_check', 'repair_preview', 'repair_apply']) {
      check(`${name} is a registered action`, actions.ACTION_NAMES.includes(name));
    }
    check('health_check always asks for JSON', /--json/.test(actions.buildAction('health_check', { name: 'de1' })));
    check('health_check is read-only: it never carries --yes',
      !/--yes/.test(actions.buildAction('health_check', { name: 'de1', mode: 'quick' })));
    check('health_check can select the quick depth',
      /--quick/.test(actions.buildAction('health_check', { name: 'de1', mode: 'quick' })));
    check('health_check can select the full depth',
      /--full/.test(actions.buildAction('health_check', { name: 'de1', mode: 'full' })));
    check('health_check omits the depth when none was asked for',
      !/--quick|--full/.test(actions.buildAction('health_check', { name: 'de1' })));
    check('health_check passes a budget through',
      /--budget 30/.test(actions.buildAction('health_check', { name: 'de1', mode: 'full', budget: 30 })));
    check('health_check rejects an unknown mode', (() => {
      try { actions.buildAction('health_check', { name: 'de1', mode: 'thorough' }); return false; } catch { return true; }
    })());
    check('health_check rejects a non-integer budget', (() => {
      try { actions.buildAction('health_check', { name: 'de1', budget: '30; rm -rf /' }); return false; } catch { return true; }
    })());
    check('health_check rejects an unsafe name', (() => {
      try { actions.buildAction('health_check', { name: 'de1; rm -rf /' }); return false; } catch { return true; }
    })());
    check('repair_preview is read-only: it never carries --yes',
      !/--yes/.test(actions.buildAction('repair_preview', { name: 'de1' })));
    check('repair_preview always asks for JSON', /--json/.test(actions.buildAction('repair_preview', { name: 'de1' })));
    check('repair_apply always carries --yes',
      /--yes$/.test(actions.buildAction('repair_apply', { name: 'de1', code: 'GRE_INTERFACE_DOWN' })));
    check('repair_apply requires a code', (() => {
      try { actions.buildAction('repair_apply', { name: 'de1' }); return false; } catch { return true; }
    })());
    check('repair_apply rejects an unsafe code', (() => {
      try { actions.buildAction('repair_apply', { name: 'de1', code: 'x; rm -rf /' }); return false; } catch { return true; }
    })());

    // A one-sided health check or repair is exactly what this feature exists to avoid,
    // so the generic per-server action endpoint refuses all three by name.
    for (const [action, params] of [['health_check', { name: 'de1' }], ['repair_preview', { name: 'de1' }], ['repair_apply', { name: 'de1', code: 'GRE_INTERFACE_DOWN' }]]) {
      r = await hub.client.call(`/api/servers/${iranId}/action`, { method: 'POST', body: { action, params } });
      check(`the generic per-server action endpoint refuses ${action}`, r.status === 400, `status=${r.status}`);
      check(`the refusal for ${action} points at the connection health flow`,
        /gre-connections/.test(String(r.data.error)), String(r.data.error));
    }
  } finally {
    await hub.close();
  }

  console.log(`\nhealth tests: ${PASS} passed, ${FAIL} failed`);
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
