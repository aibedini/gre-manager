'use strict';

const assert = require('assert');
const { applyRouteLivePreflight, contextualError } = require('../server/route-live-preflight');

let assertions = 0;
function ok(value, message) { assert.ok(value, message); assertions++; }
function equal(actual, expected, message) { assert.strictEqual(actual, expected, message); assertions++; }

class FakeOrchestrator {
  constructor({ failXuiPortQuery = false, optionsUnavailable = false, slimUnavailable = false } = {}) {
    this.eventsLog = [];
    this.stageLog = [];
    this.clientCalls = 0;
    this.requestPaths = [];
    this.originalCalled = false;
    this._route = null;
    this._client = {
      timeoutMs: 20000,
      resolveCapabilities: async () => ({ clientModel: 'first_class', hostMode: 'managed_hosts', mode: 'managed_hosts' }),
      detectPanelVersion: async () => ({ version: '3.7.0', source: 'test' }),
      getFirstClassClient: async (email) => ({ client: { email }, inboundIds: [10] }),
      request: async (path) => {
        this.requestPaths.push(path);
        if (failXuiPortQuery && path === '/panel/api/inbounds/options') {
          throw new Error('The operation was aborted due to timeout');
        }
        if (path === '/panel/api/inbounds/options') {
          if (optionsUnavailable) return { ok: false, status: 404, data: null };
          return {
            ok: true,
            status: 200,
            data: { success: true, obj: [{ id: 10, remark: 'existing', protocol: 'shadowsocks', port: 3049 }] },
          };
        }
        if (path === '/panel/api/inbounds/list/slim') {
          if (slimUnavailable) return { ok: false, status: 404, data: null };
          // Some builds wrap the payload in `data` instead of `obj`.
          return { ok: true, status: 200, data: { success: true, data: [{ id: 11, port: 3051 }] } };
        }
        return { ok: false, status: 404, data: null };
      },
      listInbounds: async () => {
        this.requestPaths.push('/panel/api/inbounds/list');
        return [{ id: 10, port: 3049 }];
      },
    };
    this.db = {
      transaction: (fn) => () => fn(),
      prepare: () => ({ run: () => ({ changes: 1 }) }),
    };
  }

  server(id) {
    return Number(id) === 1
      ? { id: 1, name: 'iran', host: '193.24.120.23' }
      : { id: 2, name: 'foreign', host: '158.94.216.5' };
  }

  panel(id) { return { id: Number(id), name: 'panel' }; }
  registryConflict() { return null; }

  reserve(input, port, method, email, clientMode, clientModel) {
    this._route = {
      id: 77,
      name: input.name,
      iran_server_id: input.iranServerId,
      foreign_server_id: input.foreignServerId,
      panel_id: input.panelId,
      port,
      method,
      client_email: email,
      client_mode: clientMode,
      client_model: clientModel,
    };
    return 77;
  }

  event(routeId, stage, status, detail) {
    this.eventsLog.push({ routeId, stage, status, detail });
  }

  stage(routeId, name, detail) {
    this.stageLog.push({ routeId, name, status: 'RUNNING', detail });
    let done = false;
    return {
      pass: (text) => { if (!done) { done = true; this.stageLog.push({ routeId, name, status: 'PASS', detail: text }); } },
      fail: (text) => { if (!done) { done = true; this.stageLog.push({ routeId, name, status: 'FAIL', detail: text }); } },
    };
  }

  client() { this.clientCalls++; return this._client; }
  route() { return this._route; }
  ownership(routeId, patch) { Object.assign(this._route, patch); }
  reportPanelMetadata() {}
  inspectCandidate() { return { free: false, conflict_route: this._route.name, evidence: { iran: [], foreign: [], inbound: null } }; }
  async publicIp(server) { return server.host; }
  async remote() { return { rc: 0, stdout: 'reachable', stderr: '' }; }

  async run(routeId, prepared) {
    this.originalCalled = true;
    return { routeId, prepared };
  }
}

applyRouteLivePreflight(FakeOrchestrator);

async function prepare(orchestrator) {
  return orchestrator.prepare({
    name: 'irwebnavid-tr',
    iranServerId: 1,
    foreignServerId: 2,
    panelId: 9,
    port: 2983,
    client_mode: 'existing',
    client_email: 'navid',
  });
}

(async () => {
  const orchestrator = new FakeOrchestrator();
  const started = Date.now();
  const prepared = await prepare(orchestrator);

  equal(prepared.route_id, 77, 'prepare must reserve and return a route id');
  equal(prepared.status, 'RESERVED', 'prepare must return RESERVED');
  equal(orchestrator.clientCalls, 0, 'prepare must not touch 3x-ui/network');
  ok(Date.now() - started < 1000, 'prepare must return immediately');
  ok(orchestrator.eventsLog.some((e) => e.stage === 'port_reserved'), 'local reservation event must exist before background work');

  const result = await orchestrator.run(77, prepared);
  ok(orchestrator.originalCalled, 'original provisioning run must continue after preflight');
  equal(result.routeId, 77, 'original result should be returned');
  ok(orchestrator._client.timeoutMs >= 45000, '3x-ui timeout should be restored after bounded port query');

  for (const stage of [
    'panel_probe',
    'client_preflight',
    'port_check',
    'port_check_iran',
    'port_check_foreign',
    'port_check_xui',
    'public_ip_preflight',
    'connectivity_iran_to_foreign',
    'connectivity_foreign_to_iran',
  ]) {
    ok(orchestrator.stageLog.some((e) => e.name === stage && e.status === 'RUNNING'), `${stage} must emit RUNNING`);
    ok(orchestrator.stageLog.some((e) => e.name === stage && e.status === 'PASS'), `${stage} must emit PASS`);
  }

  ok(orchestrator.requestPaths.includes('/panel/api/inbounds/options'), 'port check must use the lightweight 3x-ui inbound options endpoint');
  ok(!orchestrator.requestPaths.includes('/panel/api/inbounds/list'), '3x-ui 3.7 port check must not fetch the heavyweight full inbound list');
  const xuiPass = orchestrator.stageLog.find((e) => e.name === 'port_check_xui' && e.status === 'PASS');
  ok(/\/panel\/api\/inbounds\/options/.test(xuiPass.detail), 'timeline must report which lightweight endpoint supplied the port inventory');

  ok(orchestrator.eventsLog.some((e) => e.stage === 'connectivity_preflight' && e.status === 'PASS'), 'bidirectional connectivity summary must be persisted');

  const abort = new Error('The operation was aborted due to timeout');
  const message = contextualError('3x-ui client preflight', abort, 45000);
  ok(message.includes('3x-ui client preflight timed out after 45s'), 'opaque AbortError must gain stage and timeout context');

  const failing = new FakeOrchestrator({ failXuiPortQuery: true });
  const failingPrepared = await prepare(failing);
  let failure = null;
  try {
    await failing.run(77, failingPrepared);
  } catch (err) {
    failure = err;
  }
  ok(failure, 'a failed lightweight 3x-ui port query must stop provisioning');
  ok(/3x-ui inbound-port query timed out after 12s/.test(failure.message), 'port failure must identify 3x-ui and the bounded 12s timeout');
  ok(failing.stageLog.some((e) => e.name === 'port_check_xui' && e.status === 'FAIL' && /12s/.test(e.detail)), 'timeline must mark port_check_xui FAIL with the exact timeout');
  ok(failing.stageLog.some((e) => e.name === 'port_check_iran' && e.status === 'PASS'), 'IRAN port inventory result remains visible when 3x-ui fails');
  ok(failing.stageLog.some((e) => e.name === 'port_check_foreign' && e.status === 'PASS'), 'FOREIGN port inventory result remains visible when 3x-ui fails');
  ok(!failing.originalCalled, 'no GRE mutation may start after a failed port inventory');

  // --- fallback chain ---------------------------------------------------
  // Panels that predate /options must still be checked, via /list/slim first and
  // the full list only as a last resort. These paths are what a legacy or
  // partially upgraded panel actually takes, so they need direct coverage.

  const slimOnly = new FakeOrchestrator({ optionsUnavailable: true });
  const slimPrepared = await prepare(slimOnly);
  await slimOnly.run(77, slimPrepared);
  ok(slimOnly.requestPaths.includes('/panel/api/inbounds/list/slim'),
    'a panel without /options must fall back to /panel/api/inbounds/list/slim');
  ok(!slimOnly.requestPaths.includes('/panel/api/inbounds/list'),
    'the slim fallback must not fall through to the heavyweight full list');
  const slimPass = slimOnly.stageLog.find((e) => e.name === 'port_check_xui' && e.status === 'PASS');
  ok(/\/panel\/api\/inbounds\/list\/slim/.test(slimPass.detail),
    'the timeline must name the slim endpoint as the source');
  ok(/1 inbound\(s\) read/.test(slimPass.detail),
    'a `data`-wrapped payload must be unwrapped and counted');

  const legacyOnly = new FakeOrchestrator({ optionsUnavailable: true, slimUnavailable: true });
  const legacyPrepared = await prepare(legacyOnly);
  await legacyOnly.run(77, legacyPrepared);
  ok(legacyOnly.requestPaths.includes('/panel/api/inbounds/list'),
    'when neither lightweight endpoint exists the full list is the legacy fallback');
  const legacyPass = legacyOnly.stageLog.find((e) => e.name === 'port_check_xui' && e.status === 'PASS');
  ok(/legacy fallback/.test(legacyPass.detail),
    'the timeline must say the legacy endpoint was used');

  console.log(`live-preflight-test: ${assertions} assertions passed`);
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});