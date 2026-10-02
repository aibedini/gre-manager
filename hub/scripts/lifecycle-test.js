'use strict';
// lifecycle-test.js â€” reconcile, edit, retry and delete against the
// behavioural 3x-ui mock, including the ownership promises that protect a
// pre-existing client.
//
// Run with: node scripts/lifecycle-test.js

const {
  assert, makeHarness, makeSshMock, makeOrchestrator, check, checkAsync, rejects, report,
} = require('./_harness');
const { normalizePanelVersion, extractPanelVersionFromHtml } = require('../server/xui');
const { shadowsocksClientPassword } = require('../server/route-orchestrator');
const { makeMockPanel, json } = require('./_xui-mock');

const MODERN_KEY = () => shadowsocksClientPassword('chacha20-ietf-poly1305');

// A deterministic mid-provisioning failure: the managed host is created AFTER
// the inbound, the client and both GRE ends, so failing it exercises the whole
// rollback path. It only fires on panels that actually expose the hosts API
// (hostMode === 'managed_hosts'), which is why those tests set hostsApi: true.
const failManagedHost = (panel) => async (url, opts) => {
  if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
  return panel.fetchImpl(url, opts);
};

const failInboundDelete = (panel) => async (url, opts) => {
  const path = new URL(String(url)).pathname;
  if (/^\/panel\/api\/inbounds\/del\/\d+$/.test(path)) throw new Error('simulated inbound delete failure');
  return panel.fetchImpl(url, opts);
};

const routeInput = (harness, extra = {}) => ({
  name: 'IR05-DE02',
  iranServerId: harness.iranId,
  foreignServerId: harness.foreignId,
  panelId: harness.panelId,
  start: 3000,
  end: 3999,
  ...extra,
});

// Provision one route end to end and return everything a test needs.
async function provision(harness, { panel, sshExec, state, extra = {} }) {
  const orchestrator = makeOrchestrator(harness, {
    fetchImpl: panel.fetchImpl,
    sshExec: async (...args) => {
      const result = await sshExec(...args);
      state.inboundCreated = panel.state.inbounds.length > 0;
      return result;
    },
  });
  const prepared = await orchestrator.prepare(routeInput(harness, extra));
  const result = await orchestrator.run(prepared.route_id, prepared);
  return { orchestrator, prepared, result };
}

async function main() {
  console.log('panel version detection:');

  check('normalizePanelVersion accepts real shapes and rejects noise', () => {
    assert.equal(normalizePanelVersion('v3.8.5'), '3.8.5');
    assert.equal(normalizePanelVersion('3.0.2'), '3.0.2');
    assert.equal(normalizePanelVersion(' 2.8.11 '), '2.8.11');
    assert.equal(normalizePanelVersion('v3.8.5-beta'), null);
    assert.equal(normalizePanelVersion('3.8'), null);
    assert.equal(normalizePanelVersion('xray'), null);
    assert.equal(normalizePanelVersion(''), null);
  });

  check('the HTML fallback never reports the Xray version as the panel version', () => {
    assert.equal(extractPanelVersionFromHtml('<title>3x-ui v3.8.5</title>'), '3.8.5');
    assert.equal(extractPanelVersionFromHtml('<div>Xray 25.9.11</div><div>3x-ui</div>'), null);
    assert.equal(extractPanelVersionFromHtml('<div>Xray 25.9.11</div><title>3x-ui v3.8.5</title>'), '3.8.5');
    assert.equal(extractPanelVersionFromHtml('<meta name="version" content="2.8.11">'), '2.8.11');
    assert.equal(extractPanelVersionFromHtml('<div>welcome</div>'), null);
  });

  await checkAsync('detectPanelVersion prefers getPanelUpdateInfo', async () => {
    const panel = makeMockPanel({ clientModel: 'first_class', panelVersion: 'v3.8.5' });
    const { XuiClient } = require('../server/xui');
    const client = new XuiClient({ baseUrl: 'https://panel.example', authType: 'token', token: 't', fetchImpl: panel.fetchImpl });
    const detected = await client.detectPanelVersion();
    assert.equal(detected.version, '3.8.5');
    assert.equal(detected.source, 'api');
  });

  await checkAsync('detectPanelVersion falls back to the panel HTML', async () => {
    const panel = makeMockPanel({ clientModel: 'first_class', reportVersionViaApi: false, htmlVersion: '2.8.11' });
    const { XuiClient } = require('../server/xui');
    const client = new XuiClient({ baseUrl: 'https://panel.example', authType: 'token', token: 't', fetchImpl: panel.fetchImpl });
    const detected = await client.detectPanelVersion();
    assert.equal(detected.version, '2.8.11');
    assert.equal(detected.source, 'html');
  });

  await checkAsync('detectPanelVersion returns null when the panel cannot say', async () => {
    const panel = makeMockPanel({ clientModel: 'first_class', reportVersionViaApi: false });
    const { XuiClient } = require('../server/xui');
    const client = new XuiClient({ baseUrl: 'https://panel.example', authType: 'token', token: 't', fetchImpl: panel.fetchImpl });
    const detected = await client.detectPanelVersion();
    assert.equal(detected.version, null);
    assert.equal(detected.source, null);
  });

  console.log('\nreconcile â€” ACTIVE route:');

  await checkAsync('all components present => healthy', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      state.inboundCreated = true;
      const report_ = await orchestrator.reconcile(result.id);
      const names = report_.components.map((c) => c.name);
      for (const required of ['registry', 'iran_peer', 'iran_forwarding', 'foreign_listener', 'xui_inbound',
        'inbound_port', 'inbound_protocol', 'client', 'client_attachment', 'managed_host']) {
        assert(names.includes(required), `missing component ${required} (got ${names.join(', ')})`);
      }
      assert.equal(report_.desiredState, 'ACTIVE');
      assert.equal(report_.status, 'ACTIVE');
      assert.equal(report_.healthy, true, `unexpected failures: ${JSON.stringify(report_.components.filter((c) => c.status === 'FAIL'))}`);
      const attachment = report_.components.find((c) => c.name === 'client_attachment');
      assert.equal(attachment.expected, 'ATTACHED');
      assert.equal(attachment.actual, 'ATTACHED');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a missing client attachment is reported as the exact failure', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      state.inboundCreated = true;
      // Simulate someone detaching the client behind our back.
      panel.findClient('navid').inboundIds = [];
      const found = panel.findInbound(result.inbound_id);
      found.settings.clients = [];
      const report_ = await orchestrator.reconcile(result.id);
      const attachment = report_.components.find((c) => c.name === 'client_attachment');
      assert.equal(attachment.status, 'FAIL');
      assert.equal(attachment.expected, 'ATTACHED');
      assert.equal(attachment.actual, 'DETACHED');
      assert.equal(report_.healthy, false);
      assert.equal(report_.status, 'NEEDS_REVIEW');
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(result.id).status, 'NEEDS_REVIEW');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a GRE peer that is not UP is a failure', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      state.inboundCreated = true;
      state.greUp = false;
      const report_ = await orchestrator.reconcile(result.id);
      const peer = report_.components.find((c) => c.name === 'iran_peer');
      assert.equal(peer.actual, 'ABSENT');
      assert.equal(report_.healthy, false);
    } finally { harness.cleanup(); }
  });

  console.log('\nreconcile â€” FAILED route:');

  await checkAsync('a clean rollback is healthy and NOT flagged for review', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const failingFetch = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: failingFetch,
      sshExec: async (...args) => { const r = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'existing', client_email: 'navid' }));
      await rejects('the run fails', () => orchestrator.run(prepared.route_id, prepared));
      const report_ = await orchestrator.reconcile(prepared.route_id);
      assert.equal(report_.desiredState, 'FAILED');
      assert.equal(report_.cleanup_complete, true, `leftovers: ${JSON.stringify(report_.leftovers)}`);
      assert.equal(report_.status, 'FAILED', 'a clean rollback must stay FAILED, not NEEDS_REVIEW');
      assert.deepEqual(report_.leftovers, []);
      assert(/rollback clean/i.test(report_.summary));
      // The pre-existing client must have been preserved.
      const client = report_.components.find((c) => c.name === 'client');
      assert.equal(client.expected, 'EXISTS');
      assert.equal(client.actual, 'EXISTS');
      assert(panel.findClient('navid'), 'the pre-existing client must still exist');
      // And it must be detached from the rolled-back inbound.
      const attachment = report_.components.find((c) => c.name === 'client_attachment');
      assert.equal(attachment.actual, 'DETACHED');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a leftover peer is reported as a leftover, not a silent pass', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const failingFetch = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    // Fail the IRAN peer removal so a real leftover remains.
    const sshWithStuckPeer = makeSshMock({
      getState: () => state,
      failCommandTest: (command) => command.startsWith('gre iran peer remove'),
    });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: failingFetch,
      sshExec: async (...args) => {
        const r = await sshWithStuckPeer.sshExec(...args);
        state.inboundCreated = panel.state.inbounds.length > 0;
        return r;
      },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'existing', client_email: 'navid' }));
      // The peer removal fails, so the tunnel survives the rollback.
      let caught = null;
      try { await orchestrator.run(prepared.route_id, prepared); } catch (err) { caught = err; }
      assert(caught, 'the run must fail');
      assert(caught.rollback.some((entry) => /failed/i.test(entry)), 'the failed rollback stage must be recorded');
      const report_ = await orchestrator.reconcile(prepared.route_id);
      assert.equal(report_.cleanup_complete, false, 'a leftover must be reported');
      assert(report_.leftovers.includes('iran_peer'), `leftovers: ${JSON.stringify(report_.leftovers)}`);
      assert.equal(report_.status, 'NEEDS_REVIEW');
      assert(/leftover/i.test(report_.summary));
    } finally { harness.cleanup(); }
  });

  await checkAsync('a leftover inbound is reported', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const failingHost = failManagedHost(panel);
    const fetchImpl = async (url, opts) => {
      const path = new URL(String(url)).pathname;
      // The inbound must survive the rollback for a real leftover to exist.
      if (/^\/panel\/api\/inbounds\/del\/\d+$/.test(path)) throw new Error('simulated inbound delete failure');
      return failingHost(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const r = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'new', client_email: 'leftover-probe' }));
      let caught = null;
      try { await orchestrator.run(prepared.route_id, prepared); } catch (err) { caught = err; }
      assert(caught);
      const report_ = await orchestrator.reconcile(prepared.route_id);
      assert(report_.leftovers.includes('xui_inbound'), `leftovers: ${JSON.stringify(report_.leftovers)}`);
      assert.equal(report_.cleanup_complete, false);
    } finally { harness.cleanup(); }
  });

  await checkAsync('STALE is read-only and never judged or destroyed', async () => {
    const harness = makeHarness();
    try {
      const now = Date.now();
      const routeId = harness.insert(`INSERT INTO gre_routes
        (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, client_mode, client_model, status, attempt_no, created_at, updated_at)
        VALUES ('stale-one', ?, ?, ?, 3099, 'chacha20-ietf-poly1305', 'navid', 'existing', 'first_class', 'STALE', 1, ?, ?)`,
      harness.iranId, harness.foreignId, harness.panelId, now, now);
      harness.insert(`INSERT INTO port_allocations (route_id, iran_server_id, foreign_server_id, port, protocols, status, created_at, updated_at)
        VALUES (?, ?, ?, 3099, 'tcp,udp', 'RESERVED', ?, ?)`, routeId, harness.iranId, harness.foreignId, now, now);
      const panel = makeMockPanel({ clientModel: 'first_class' });
      const state = { inboundCreated: false };
      const { sshExec } = makeSshMock({ getState: () => state });
      const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
      const before = harness.db.prepare('SELECT * FROM gre_routes WHERE id=?').get(routeId);
      const report_ = await orchestrator.reconcile(routeId);
      assert.equal(report_.desiredState, 'STALE');
      assert.equal(report_.status, 'STALE');
      assert.equal(report_.healthy, true);
      assert(report_.components.every((c) => c.expected === 'UNKNOWN'), 'STALE components must not be judged');
      assert(/read-only/i.test(report_.summary));
      // Nothing may have been deleted or released.
      const after = harness.db.prepare('SELECT * FROM gre_routes WHERE id=?').get(routeId);
      assert.equal(after.status, 'STALE');
      assert.equal(after.deleted_at, before.deleted_at);
      assert.equal(harness.db.prepare('SELECT status FROM port_allocations WHERE route_id=?').get(routeId).status, 'RESERVED');
    } finally { harness.cleanup(); }
  });

  console.log('\nedit:');

  await checkAsync('a FAILED route can be edited and nothing is provisioned', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const fetchImpl = failManagedHost(panel);
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const r = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'new', client_email: 'edit-me' }));
      await rejects('the run fails', () => orchestrator.run(prepared.route_id, prepared));
      const inboundCallsBefore = panel.inboundAddCalls().length;
      const edited = await orchestrator.editRoute(prepared.route_id, { name: 'IR05-DE99', port: 3088, method: 'aes-256-gcm' });
      assert.equal(edited.route.name, 'IR05-DE99');
      assert.equal(edited.route.port, 3088);
      assert.equal(edited.route.method, 'aes-256-gcm');
      assert.deepEqual(edited.changed.sort(), ['method', 'name', 'port'].sort());
      assert.equal(panel.inboundAddCalls().length, inboundCallsBefore, 'editing must not provision anything');
      assert.equal(edited.route.status, 'FAILED', 'editing must not change the status');
      assert.equal(harness.db.prepare('SELECT port FROM port_allocations WHERE route_id=?').get(prepared.route_id).port, 3088,
        'the allocation must follow the edited port');
    } finally { harness.cleanup(); }
  });

  await checkAsync('editing an ACTIVE route refuses infrastructure changes but allows a rename', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      state.inboundCreated = true;
      await rejects('a port change on a live route is refused', () => orchestrator.editRoute(result.id, { port: 3099 }),
        (err) => {
          assert.equal(err.status, 409);
          assert.match(err.message, /ACTIVE/);
          assert(err.fields.includes('port'));
        });
      await rejects('a server change on a live route is refused', () => orchestrator.editRoute(result.id, { iranServerId: harness.foreignId }),
        (err) => assert.equal(err.status, 409));
      const renamed = await orchestrator.editRoute(result.id, { name: 'IR05-DE07' });
      assert.equal(renamed.route.name, 'IR05-DE07');
      assert.deepEqual(renamed.changed, ['name']);
      assert.equal(renamed.route.port, result.port, 'the live port must be untouched');
    } finally { harness.cleanup(); }
  });

  await checkAsync('editing validates the client selection before writing', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      // Make the route editable again so infra changes are allowed.
      harness.db.prepare("UPDATE gre_routes SET status='FAILED' WHERE id=?").run(result.id);
      harness.db.prepare("UPDATE port_allocations SET status='RELEASED' WHERE route_id=?").run(result.id);
      await rejects('an unknown client is rejected', () => orchestrator.editRoute(result.id, { client_mode: 'existing', client_email: 'ghost' }),
        (err) => assert.match(err.message, /no longer exists/i));
      await rejects('a taken email is rejected for mode=new', () => orchestrator.editRoute(result.id, { client_mode: 'new', client_email: 'navid' }),
        (err) => assert.match(err.message, /already exists/i));
      const row = harness.db.prepare('SELECT client_email FROM gre_routes WHERE id=?').get(result.id);
      assert.equal(row.client_email, 'navid', 'the rejected edits must not have been written');
    } finally { harness.cleanup(); }
  });

  console.log('\nretry:');

  await checkAsync('retry increments attempt_no and preserves every previous event', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    let failHost = true;
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: async (url, opts) => {
        if (failHost && String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
        return panel.fetchImpl(url, opts);
      },
      // A real failure must actually roll back; model the GRE disappearing so
      // the retry pre-check sees a clean slate.
      sshExec: async (...args) => { const r = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'new', client_email: 'retry-me' }));
      await rejects('attempt #1 fails', () => orchestrator.run(prepared.route_id, prepared));
      const firstAttemptEvents = orchestrator.events(prepared.route_id);
      assert(firstAttemptEvents.length > 5);
      assert(firstAttemptEvents.every((e) => Number(e.attempt_no) === 1), 'attempt 1 rows must be stamped 1');

      failHost = false;
      const retryPrepared = await orchestrator.prepareForRetry(prepared.route_id);
      assert.equal(retryPrepared.attempt_no, 2);
      assert.equal(harness.db.prepare('SELECT attempt_no FROM gre_routes WHERE id=?').get(prepared.route_id).attempt_no, 2);

      const outcome = await orchestrator.startProvisioning(prepared.route_id, retryPrepared);
      assert.equal(outcome.ok, true, `unexpected failure: ${outcome.error && outcome.error.message}`);

      const all = orchestrator.events(prepared.route_id);
      assert(all.length > firstAttemptEvents.length, 'previous events must be preserved');
      assert(all.filter((e) => Number(e.attempt_no) === 1).length === firstAttemptEvents.length,
        'attempt 1 rows must not be rewritten');
      assert(all.some((e) => Number(e.attempt_no) === 2), 'attempt 2 rows must exist');
      assert(all.some((e) => e.stage === 'retry_started'));
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(prepared.route_id).status, 'ACTIVE');
    } finally { harness.cleanup(); }
  });

  await checkAsync('retry refuses to start when leftovers remain', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false, greEnabled: true };
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    // Two leftovers at once: the inbound cannot be deleted and the IRAN peer
    // cannot be removed.
    const fetchImpl = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return failInboundDelete(panel)(url, opts);
    };
    const sshWithStuckPeer = makeSshMock({
      getState: () => state,
      failCommandTest: (command) => command.startsWith('gre iran peer remove'),
    });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const r = await sshWithStuckPeer.sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'new', client_email: 'stuck' }));
      await rejects('the run fails', () => orchestrator.run(prepared.route_id, prepared));
      await rejects('retry is refused while leftovers exist', () => orchestrator.prepareForRetry(prepared.route_id),
        (err) => {
          assert.equal(err.status, 409);
          assert.match(err.message, /left resources behind/i);
          assert(err.leftover.length > 0);
        });
      assert.equal(harness.db.prepare('SELECT attempt_no FROM gre_routes WHERE id=?').get(prepared.route_id).attempt_no, 1,
        'a refused retry must not consume an attempt number');
    } finally { harness.cleanup(); }
  });

  console.log('\ndelete:');

  await checkAsync('delete of a route that REUSED a client never deletes that client globally', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'navid' } });
      state.inboundCreated = true;
      const preview = await orchestrator.deletePreview(result.id);
      assert(preview.preserves.some((line) => /WILL NOT BE DELETED/.test(line)), `preview: ${JSON.stringify(preview.preserves)}`);
      assert(preview.removes.some((line) => /attachment/.test(line)));

      const deletion = await orchestrator.deleteRoute(result.id);
      assert.equal(deletion.ok, true, `failures: ${JSON.stringify(deletion.failures)}`);
      assert.equal(deletion.failures.length, 0);
      assert.deepEqual(deletion.removed.sort(),
        ['client_attachment', 'foreign_node', 'inbound', 'iran_peer', 'managed_host', 'port_allocation'].sort());
      assert.equal(panel.deleteCalls().length, 0, 'the global client must NEVER be deleted');
      assert(panel.findClient('navid'), 'navid must still exist on the panel');
      const row = harness.db.prepare('SELECT deleted_at, status FROM gre_routes WHERE id=?').get(result.id);
      assert(row.deleted_at, 'the route must be soft-deleted');
      assert.equal(row.status, 'STALE');
      assert(orchestrator.events(result.id).length > 0, 'event history must be preserved');
      assert.equal(harness.db.prepare('SELECT status FROM port_allocations WHERE route_id=?').get(result.id).status, 'RELEASED');
      assert.equal(panel.state.inbounds.length, 0, 'the inbound must be gone');
    } finally { harness.cleanup(); }
  });

  await checkAsync('delete removes a route-created client that nothing else uses', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'new', client_email: 'owned-only' } });
      state.inboundCreated = true;
      assert(panel.findClient('owned-only'), 'the client was created');
      const deletion = await orchestrator.deleteRoute(result.id);
      assert.equal(deletion.ok, true, `failures: ${JSON.stringify(deletion.failures)}`);
      assert(deletion.removed.includes('client'), `removed: ${deletion.removed.join(', ')}`);
      assert.equal(panel.deleteCalls().length, 1);
      assert.equal(panel.findClient('owned-only'), undefined, 'the owned client must be removed');
    } finally { harness.cleanup(); }
  });

  await checkAsync('delete PRESERVES a route-created client that other inbounds still use', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      // Another inbound of another (or the same) route also carries this client.
      inbounds: [{ id: 900, port: 3999, remark: 'other-route', protocol: 'shadowsocks', clients: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'new', client_email: 'shared-client' } });
      state.inboundCreated = true;
      // Simulate a second attachment that belongs to something else.
      const row = panel.findClient('shared-client');
      row.inboundIds.push(900);
      panel.findInbound(900).settings.clients.push({ email: 'shared-client', password: row.password, method: row.method });
      const deletion = await orchestrator.deleteRoute(result.id);
      assert.equal(deletion.ok, true, `failures: ${JSON.stringify(deletion.failures)}`);
      assert.equal(panel.deleteCalls().length, 0, 'a shared client must not be deleted');
      assert(panel.findClient('shared-client'), 'the shared client must survive');
      assert.deepEqual(panel.findClient('shared-client').inboundIds, [900], 'only our attachment is removed');
      assert(deletion.removed.some((entry) => entry === 'client'), 'the detachment is still reported as handled');
    } finally { harness.cleanup(); }
  });

  await checkAsync('delete of a clean FAILED route just verifies cleanup and soft-deletes', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'navid', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const fetchImpl = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const r = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return r; },
    });
    try {
      const prepared = await orchestrator.prepare(routeInput(harness, { client_mode: 'existing', client_email: 'navid' }));
      await rejects('the run fails', () => orchestrator.run(prepared.route_id, prepared));
      const deletion = await orchestrator.deleteRoute(prepared.route_id);
      assert.equal(deletion.ok, true, `failures: ${JSON.stringify(deletion.failures)}`);
      assert(harness.db.prepare('SELECT deleted_at FROM gre_routes WHERE id=?').get(prepared.route_id).deleted_at);
      assert(panel.findClient('navid'), 'the pre-existing client must survive');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a partial delete failure leaves the route visible as NEEDS_REVIEW', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'new', client_email: 'half-deleted' } });
      state.inboundCreated = true;
      // Break the IRAN peer removal for the delete pass.
      const breakingSsh = makeSshMock({
        getState: () => state,
        failCommandTest: (command) => command.startsWith('gre iran peer remove'),
      });
      const failing = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec: breakingSsh.sshExec });
      const deletion = await failing.deleteRoute(result.id);
      assert.equal(deletion.ok, false);
      assert(deletion.failures.some((f) => f.name === 'iran_peer'), `failures: ${JSON.stringify(deletion.failures)}`);
      const row = harness.db.prepare('SELECT deleted_at, status, last_error FROM gre_routes WHERE id=?').get(result.id);
      assert.equal(row.deleted_at, null, 'a failed delete must not soft-delete');
      assert.equal(row.status, 'NEEDS_REVIEW');
      assert(/iran_peer/.test(row.last_error));
      const events = failing.events(result.id);
      assert(events.some((e) => e.stage === 'delete_iran_peer' && e.status === 'FAIL'));
      assert(events.some((e) => e.stage === 'deleted' && e.status === 'FAIL'));
      // The other cleanup steps still ran.
      assert(events.some((e) => e.stage === 'delete_inbound' && e.status === 'PASS'));
      assert(events.some((e) => e.stage === 'delete_foreign_node' && e.status === 'PASS'));
    } finally { harness.cleanup(); }
  });

  await checkAsync('delete preview never promises to delete an existing client', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    // A pre-existing client with no recorded ownership (legacy row).
    const panel = makeMockPanel({
      clientModel: 'first_class', hostsApi: true,
      clients: [{ email: 'legacy-owner', password: MODERN_KEY(), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    try {
      const { orchestrator, result } = await provision(harness, { panel, sshExec, state, extra: { client_mode: 'existing', client_email: 'legacy-owner' } });
      state.inboundCreated = true;
      harness.db.prepare('UPDATE gre_routes SET client_attached_by_route = NULL, client_created_by_route = NULL WHERE id=?').run(result.id);
      const preview = await orchestrator.deletePreview(result.id);
      assert(preview.preserves.some((line) => /never deleted/i.test(line)), JSON.stringify(preview.preserves));
      assert(!preview.removes.some((line) => /client "legacy-owner" \(created/.test(line)));
    } finally { harness.cleanup(); }
  });

  report('lifecycle tests');
}

main().catch((err) => { console.error(err); process.exit(1); });
