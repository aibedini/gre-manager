'use strict';

const assert = require('assert');
const { applyRouteLivePreflight, contextualError } = require('../server/route-live-preflight');

let assertions = 0;
function ok(value, message) { assert.ok(value, message); assertions++; }
function equal(actual, expected, message) { assert.strictEqual(actual, expected, message); assertions++; }

class FakeOrchestrator {
  constructor() {
    this.eventsLog = [];
    this.stageLog = [];
    this.clientCalls = 0;
    this.originalCalled = false;
    this._route = null;
    this._client = {
      timeoutMs: 20000,
      resolveCapabilities: async () => ({ clientModel: 'first_class', hostMode: 'managed_hosts', mode: 'managed_hosts' }),
      detectPanelVersion: async () => ({ version: '3.7.0', source: 'test' }),
      getFirstClassClient: async (email) => ({ client: { email }, inboundIds: [10] }),
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
  async collectUsage() { return {}; }
  inspectCandidate() { return { free: false, conflict_route: this._route.name, evidence: { iran: [], foreign: [], inbound: null } }; }
  async publicIp(server) { return server.host; }
  async remote() { return { rc: 0, stdout: 'reachable', stderr: '' }; }

  async run(routeId, prepared) {
    this.originalCalled = true;
    return { routeId, prepared };
  }
}

applyRouteLivePreflight(FakeOrchestrator);

(async () => {
  const orchestrator = new FakeOrchestrator();
  const started = Date.now();
  const prepared = await orchestrator.prepare({
    name: 'irwebnavid-tr',
    iranServerId: 1,
    foreignServerId: 2,
    panelId: 9,
    port: 2983,
    client_mode: 'existing',
    client_email: 'navid',
  });

  equal(prepared.route_id, 77, 'prepare must reserve and return a route id');
  equal(prepared.status, 'RESERVED', 'prepare must return RESERVED');
  equal(orchestrator.clientCalls, 0, 'prepare must not touch 3x-ui/network');
  ok(Date.now() - started < 1000, 'prepare must return immediately');
  ok(orchestrator.eventsLog.some((e) => e.stage === 'port_reserved'), 'local reservation event must exist before background work');

  const result = await orchestrator.run(77, prepared);
  ok(orchestrator.originalCalled, 'original provisioning run must continue after preflight');
  equal(result.routeId, 77, 'original result should be returned');
  ok(orchestrator._client.timeoutMs >= 45000, '3x-ui timeout should be raised for slow panels');

  for (const stage of [
    'panel_probe',
    'client_preflight',
    'port_check',
    'public_ip_preflight',
    'connectivity_iran_to_foreign',
    'connectivity_foreign_to_iran',
  ]) {
    ok(orchestrator.stageLog.some((e) => e.name === stage && e.status === 'RUNNING'), `${stage} must emit RUNNING`);
    ok(orchestrator.stageLog.some((e) => e.name === stage && e.status === 'PASS'), `${stage} must emit PASS`);
  }

  ok(orchestrator.eventsLog.some((e) => e.stage === 'connectivity_preflight' && e.status === 'PASS'), 'bidirectional connectivity summary must be persisted');

  const abort = new Error('The operation was aborted due to timeout');
  const message = contextualError('3x-ui client preflight', abort, 45000);
  ok(message.includes('3x-ui client preflight timed out after 45s'), 'opaque AbortError must gain stage and timeout context');

  console.log(`live-preflight-test: ${assertions} assertions passed`);
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
