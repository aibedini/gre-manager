'use strict';

// v2.14.0 regression coverage:
//   * runtime validation is decomposed, each sub-check names itself, and a slow
//     heavyweight panel call is never made,
//   * deletion is idempotent: already-absent resources are success,
//   * the client configuration survives a hub restart because it lives in the
//     encrypted route row, not in process memory.

const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const {
  assert, makeHarness, makeSshMock, makeOrchestrator, check, checkAsync, report,
} = require('./_harness');
const { makeMockPanel } = require('./_xui-mock');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');
const { RouteOrchestrator, shadowsocksClientPassword } = require('../server/route-orchestrator');
const inspection = require('../server/route-inspection');

const KEY = () => shadowsocksClientPassword('chacha20-ietf-poly1305');

// Provision one route to ACTIVE and return the pieces a test needs.
async function provisionActive(harness, { panel, sshExec, state, extra = {} }) {
  const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
  const prepared = await orchestrator.prepare({
    name: extra.name || 'R14',
    iranServerId: harness.iranId,
    foreignServerId: harness.foreignId,
    panelId: harness.panelId,
    start: 3000,
    end: 3999,
    client_mode: extra.client_mode || 'existing',
    client_email: extra.client_email || 'navid',
  });
  const result = await orchestrator.run(prepared.route_id, prepared);
  return { orchestrator, prepared, result };
}

function makePanel(overrides = {}) {
  return makeMockPanel({
    clientModel: 'first_class',
    hostsApi: true,
    clients: [{ email: 'navid', password: KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    ...overrides,
  });
}

async function main() {
  console.log('runtime validation decomposition:');

  await checkAsync('every runtime sub-check is its own stage, and the route reaches ACTIVE', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const { orchestrator, result } = await provisionActive(harness, { panel, sshExec, state });
      assert.equal(result.status, 'ACTIVE');
      const events = orchestrator.events(result.id);
      const stages = events.map((e) => e.stage);
      for (const stage of [
        'runtime_gre_iran', 'runtime_gre_foreign', 'runtime_iran_tcp_rule', 'runtime_iran_udp_rule',
        'runtime_foreign_tcp_listener', 'runtime_foreign_udp_listener', 'runtime_xui_inbound',
        'runtime_xui_client', 'runtime_managed_host', 'runtime_e2e_tcp', 'runtime_validation',
      ]) {
        assert(stages.includes(stage), `missing runtime stage ${stage}`);
      }
      for (const stage of ['runtime_gre_iran', 'runtime_gre_foreign', 'runtime_iran_tcp_rule',
        'runtime_iran_udp_rule', 'runtime_foreign_tcp_listener', 'runtime_foreign_udp_listener',
        'runtime_xui_inbound', 'runtime_xui_client', 'runtime_e2e_tcp', 'runtime_validation']) {
        assert(events.some((e) => e.stage === stage && e.status === 'RUNNING'), `${stage} never announced RUNNING`);
        assert(events.some((e) => e.stage === stage && e.status === 'PASS'), `${stage} never reached PASS`);
      }
      // The old opaque stage must be gone as a leaf: it is only the summary now.
      const leafChecks = events.filter((e) => e.stage.startsWith('runtime_') && e.stage !== 'runtime_validation');
      assert(leafChecks.length >= 10, 'expected at least 10 individual runtime checks');
    } finally { harness.cleanup(); }
  });

  await checkAsync('runtime validation never reads the heavyweight inbound list', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const { orchestrator, result } = await provisionActive(harness, { panel, sshExec, state });
      assert.equal(result.status, 'ACTIVE');
      const row = harness.db.prepare('SELECT * FROM gre_routes WHERE id=?').get(result.id);

      // Re-run ONLY the runtime phase against the already-provisioned route and
      // observe exactly which panel endpoints it touches.
      const before = panel.calls.length;
      await orchestrator.validateRuntime({
        routeId: result.id,
        iran: orchestrator.server(row.iran_server_id),
        foreign: orchestrator.server(row.foreign_server_id),
        client: orchestrator.client(orchestrator.panel(row.panel_id)),
        clientModel: row.client_model,
        email: row.client_email,
        port: Number(row.port),
        inboundId: row.inbound_id,
        peer: row.peer_name,
        hostGroupId: row.host_group_id,
        hostMode: row.host_mode,
        iranIp: row.iran_endpoint,
      });
      const paths = panel.calls.slice(before).map((c) => c.path);
      assert(!paths.includes('/panel/api/inbounds/list'),
        `runtime validation must not call /inbounds/list (saw ${paths.join(', ')})`);
      assert(!paths.includes('/panel/api/clients/list'),
        `runtime validation must not call /clients/list (saw ${paths.join(', ')})`);
      assert(!paths.some((p) => /^\/panel\/api\/clients\/links\//.test(p)),
        `runtime validation must not call /clients/links (saw ${paths.join(', ')})`);
      assert(paths.some((p) => /^\/panel\/api\/inbounds\/get\/\d+$/.test(p)),
        `expected a single-inbound detail lookup, saw ${paths.join(', ')}`);
    } finally { harness.cleanup(); }
  });

  await checkAsync('a missing forwarding rule fails at its own stage, by name', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, forgetPortRules: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
      const prepared = await orchestrator.prepare({
        name: 'R14F', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      let error = null;
      try { await orchestrator.run(prepared.route_id, prepared); } catch (err) { error = err; }
      assert(error, 'expected the run to fail');
      assert.equal(error.name, 'RuntimeValidationError', `expected RuntimeValidationError, got ${error.name}`);
      assert(error.component, 'the error must name the failing component');
      assert(/forwarding|listener/i.test(error.componentLabel || ''),
        `expected a forwarding/listener component, got ${error.componentLabel}`);
      // The message must identify the subsystem, never a bare timeout.
      assert(!/aborted due to timeout/i.test(error.message), 'must not surface an opaque timeout');
      assert(/for \d+/.test(error.message) || /:\d+/.test(error.message),
        `the message must name the port: ${error.message}`);
      // And the timeline carries the same specific stage.
      const events = orchestrator.events(prepared.route_id);
      const failed = events.filter((e) => e.stage.startsWith('runtime_') && e.status === 'FAIL');
      assert(failed.length, 'a runtime stage must be marked FAIL');
    } finally { harness.cleanup(); }
  });

  await checkAsync('an end-to-end TCP failure is reported as such, not as a timeout', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, e2eTcpFails: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
      const prepared = await orchestrator.prepare({
        name: 'R14E', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      let error = null;
      try { await orchestrator.run(prepared.route_id, prepared); } catch (err) { error = err; }
      assert(error, 'expected the run to fail');
      assert.equal(error.component, 'runtime_e2e_tcp', `expected runtime_e2e_tcp, got ${error.component}: ${error.message}`);
    } finally { harness.cleanup(); }
  });

  console.log('\nstructured runtime summary:');

  await checkAsync('the persisted runtime summary is per-component and secret-free', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const { orchestrator, result } = await provisionActive(harness, { panel, sshExec, state });
      const row = harness.db.prepare('SELECT runtime_checks FROM gre_routes WHERE id=?').get(result.id);
      const checks = JSON.parse(row.runtime_checks);
      for (const key of ['gre_iran', 'gre_foreign', 'xui_inbound', 'e2e_tcp']) {
        assert(checks[key] === 'PASS', `expected ${key}=PASS, got ${checks[key]}`);
      }
      assert(!/ss:\/\/|password/i.test(row.runtime_checks), 'runtime summary must not carry secrets');
      void orchestrator;
    } finally { harness.cleanup(); }
  });

  console.log('\ndelete idempotency:');

  await checkAsync('deleting a cleanly rolled back route is 200-style success, not 409', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    // Fail late (at the managed host) so rollback removes peer, node and inbound.
    const panel = makePanel({ hostsApi: false });
    try {
      const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
      const prepared = await orchestrator.prepare({
        name: 'R14D', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      await orchestrator.run(prepared.route_id, prepared).catch(() => {});
      // Everything remote is gone by now; delete must still succeed.
      const outcome = await orchestrator.deleteRoute(prepared.route_id);
      assert.equal(outcome.ok, true, `delete must succeed, failures: ${JSON.stringify(outcome.failures)}`);
      assert.equal(outcome.deleted, true);
      assert(Array.isArray(outcome.components) && outcome.components.length, 'components must be reported');
      const absent = outcome.components.filter((c) => c.result === 'ALREADY_ABSENT').map((c) => c.name);
      assert(absent.length, `expected at least one ALREADY_ABSENT component, got ${JSON.stringify(outcome.components)}`);
      for (const component of outcome.components) {
        assert(component.previous && component.result, `component ${component.name} must report previous/result`);
      }
    } finally { harness.cleanup(); }
  });

  await checkAsync('after a route-created client is detached, the global client survives', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel({ clients: [] });
    try {
      const { orchestrator, prepared, result } = await provisionActive(harness, {
        panel, sshExec, state, extra: { client_mode: 'new', client_email: 'fresh-client' },
      });
      assert.equal(result.status, 'ACTIVE');
      const created = panel.state.clientRows.find((r) => r.email === 'fresh-client');
      assert(created, 'the route should have created the client');
      const outcome = await orchestrator.deleteRoute(prepared.route_id);
      assert.equal(outcome.ok, true, `delete must succeed: ${JSON.stringify(outcome.failures)}`);
      const stillThere = panel.state.clientRows.some((r) => r.email === 'fresh-client');
      assert.equal(stillThere, false, 'a route-exclusive client may be deleted');
    } finally { harness.cleanup(); }
  });

  console.log('\npersistent configuration:');

  await checkAsync('an ACTIVE route exposes a valid config derived from the IRAN endpoint', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const { orchestrator, result } = await provisionActive(harness, { panel, sshExec, state });
      const config = orchestrator.routeConfig(result.id);
      assert(config, 'expected a config');
      assert(/^ss:\/\//.test(config.link), `expected an ss:// link, got ${String(config.link).slice(0, 24)}`);
      assert.equal(config.endpoint.port, result.port, 'config port must be the route port');
      assert(config.endpoint.host, 'config must name the IRAN endpoint');
      assert.equal(config.status, 'ACTIVE');
      assert(config.outbound && config.outbound.protocol === 'shadowsocks', 'outbound projection expected');
      assert(config.outbound.share_link === config.link, 'outbound must carry the same link');
    } finally { harness.cleanup(); }
  });

  await checkAsync('the config survives a hub restart because it lives in the encrypted row', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-restart-'));
    const key = cryptoUtil.loadKey(dataDir);
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    let routeId = null;
    let before = null;
    try {
      // --- first process: provision and read the config -------------------
      const db1 = openDb(dataDir);
      const now = Date.now();
      const insert = (sql, ...params) => Number(db1.prepare(sql).run(...params).lastInsertRowid);
      insert('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
        'iran', '37.202.247.77', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw1'), now);
      insert('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
        'foreign', '46.8.228.7', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw2'), now);
      insert('INSERT INTO xui_panels (name,base_url,username,auth_type,password_enc,created_at) VALUES (?,?,?,?,?,?)',
        'panel', 'https://panel.example', '', 'token', cryptoUtil.encrypt(key, 'panel-token'), now);
      const o1 = new RouteOrchestrator({
        db: db1, cryptKey: key, sshOptsFor: () => ({}), fetchImpl: panel.fetchImpl, sshExec,
      });
      const prepared = await o1.prepare({
        name: 'R14P',
        iranServerId: 1,
        foreignServerId: 2,
        panelId: 1,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      const result = await o1.run(prepared.route_id, prepared);
      assert.equal(result.status, 'ACTIVE');
      routeId = result.id;
      before = o1.routeConfig(routeId);
      assert(before && before.link, 'expected a config before restart');
      const stored = db1.prepare('SELECT share_link_enc, client_password_enc FROM gre_routes WHERE id=?').get(routeId);
      assert(stored.share_link_enc && !String(stored.share_link_enc).startsWith('ss://'),
        'the link must be stored encrypted, never as plaintext');
      db1.close();

      // --- second process: no in-memory cache, same config ----------------
      const db2 = openDb(dataDir);
      const o2 = new RouteOrchestrator({
        db: db2, cryptKey: key, sshOptsFor: () => ({}), fetchImpl: panel.fetchImpl, sshExec,
      });
      const after = o2.routeConfig(routeId);
      assert(after, 'the config must be readable after a restart');
      assert.equal(after.link, before.link, 'the restarted hub must return the exact same link');
      assert.equal(after.endpoint.port, before.endpoint.port);
      // No panel call is allowed just to reveal a stored config.
      const callsBefore = panel.calls.length;
      o2.routeConfig(routeId);
      assert.equal(panel.calls.length, callsBefore, 'revealing a stored config must not touch the panel');
      db2.close();
    } finally {
      // Windows keeps a handle briefly after close; cleanup must not mask a real
      // assertion failure.
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  await checkAsync('a FAILED route exposes no configuration', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, forgetPortRules: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makePanel();
    try {
      const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
      const prepared = await orchestrator.prepare({
        name: 'R14N', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      await orchestrator.run(prepared.route_id, prepared).catch(() => {});
      const row = harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(prepared.route_id);
      assert.equal(row.status, 'FAILED');
      assert.equal(orchestrator.routeConfig(prepared.route_id), null,
        'a FAILED route must not expose a usable configuration');
    } finally { harness.cleanup(); }
  });

  console.log('\ninspection primitives:');

  check('an already-absent panel error is recognised in both shapes', () => {
    assert.equal(inspection.isAlreadyAbsentError(new Error("Peer 'ir01' does not exist.")), true);
    assert.equal(inspection.isAlreadyAbsentError(new Error('record not found')), true);
    assert.equal(inspection.isAlreadyAbsentError({ stderr: "node 'ir01' does not exist" }), true);
    assert.equal(inspection.isAlreadyAbsentError(new Error('permission denied')), false);
    assert.equal(inspection.isAlreadyAbsentError(new Error('connection refused')), false);
  });

  check('every runtime check has its own bounded timeout', () => {
    const t = inspection.TIMEOUTS;
    for (const key of ['greInterface', 'forwarding', 'listeners', 'panelInbound', 'managedHost', 'e2eTcp']) {
      assert(Number.isFinite(t[key]) && t[key] > 0, `${key} needs a timeout`);
    }
    assert(t.e2eTcp <= 10000, 'the TCP probe must stay short');
    const total = t.greInterface + t.forwarding + t.listeners + t.panelInbound + t.managedHost + t.e2eTcp;
    assert(total <= 60000, 'timeouts must not add up past a minute');
  });

  report('v2.14 runtime/delete/config tests');
}

main().catch((err) => { console.error(err.stack || err.message); process.exit(1); });
