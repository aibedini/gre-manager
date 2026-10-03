'use strict';

const assert = require('assert');
const { parseShadowsocksLink } = require('../server/xui');
const { applyRouteCredentialFastPath } = require('../server/route-credential-fastpath');

let assertions = 0;
function ok(value, message) { assert.ok(value, message); assertions += 1; }
function equal(actual, expected, message) { assert.strictEqual(actual, expected, message); assertions += 1; }

class FakeOrchestrator {
  constructor() {
    this.originalCalls = 0;
    this.events = [];
    this.stageStarts = [];
    this.stagePasses = [];
  }

  stage(routeId, name, detail) {
    this.stageStarts.push({ routeId, name, detail });
    return {
      pass: (message) => this.stagePasses.push({ routeId, name, message }),
      fail: () => {},
    };
  }

  event(routeId, stage, status, detail) {
    this.events.push({ routeId, stage, status, detail });
  }

  async resolveClientCredential(args) {
    this.originalCalls += 1;
    return { link: 'legacy-result', password: 'legacy-password', args };
  }
}

applyRouteCredentialFastPath(FakeOrchestrator);

(async () => {
  // Real-world legacy Shadowsocks credentials in 3x-ui are not necessarily a
  // fixed-length base64 key. The first-class ClientRecord is authoritative and
  // must be used verbatim after attach.
  {
    const orchestrator = new FakeOrchestrator();
    let getCalls = 0;
    let linkCalls = 0;
    const client = {
      getFirstClassClient: async (email) => {
        getCalls += 1;
        equal(email, 'navid', 'must re-read the attached identity by email');
        return {
          client: { email: 'navid', password: 'lc9h0t96ylcfeuql' },
          inboundIds: [5],
        };
      },
      clientLinksFor: async () => { linkCalls += 1; throw new Error('must not enumerate global links'); },
    };

    const resolved = await orchestrator.resolveClientCredential({
      client,
      clientModel: 'first_class',
      inboundId: 5,
      email: 'navid',
      host: '193.24.120.23',
      port: 3001,
      method: 'chacha20-ietf-poly1305',
      createdByRoute: false,
      knownPassword: '',
    });

    equal(getCalls, 1, 'first-class client record must be read once');
    equal(linkCalls, 0, '/clients/links must not be called for an existing first-class client');
    equal(orchestrator.originalCalls, 0, 'slow legacy resolver must be bypassed');
    equal(resolved.source, 'first_class_client_record', 'source must identify the authoritative record');
    equal(resolved.password, 'lc9h0t96ylcfeuql', 'existing credential must be preserved exactly');
    const parsed = parseShadowsocksLink(resolved.link);
    equal(parsed.password, 'lc9h0t96ylcfeuql', 'locally built link must contain the real existing password');
    equal(parsed.method, 'chacha20-ietf-poly1305', 'link method must match the new inbound');
    equal(parsed.host, '193.24.120.23', 'link host must be the IRAN endpoint');
    equal(parsed.port, 3001, 'link port must be the new route port');
  }

  // A route-created first-class client already has an exact route-owned key.
  {
    const orchestrator = new FakeOrchestrator();
    let getCalls = 0;
    const client = { getFirstClassClient: async () => { getCalls += 1; return null; } };
    const resolved = await orchestrator.resolveClientCredential({
      client,
      clientModel: 'first_class',
      email: 'fresh',
      host: '193.24.120.23',
      port: 3002,
      method: 'chacha20-ietf-poly1305',
      createdByRoute: true,
      knownPassword: 'route-owned-secret',
    });
    equal(getCalls, 0, 'route-created credential must not require another panel query');
    equal(orchestrator.originalCalls, 0, 'route-created credential must bypass slow link enumeration');
    equal(parseShadowsocksLink(resolved.link).password, 'route-owned-secret', 'route-owned password must round-trip');
  }

  // Legacy embedded clients still use the original resolver and panel link path.
  {
    const orchestrator = new FakeOrchestrator();
    const resolved = await orchestrator.resolveClientCredential({
      client: {},
      clientModel: 'embedded',
      email: 'legacy',
      host: '193.24.120.23',
      port: 3003,
      method: 'chacha20-ietf-poly1305',
      createdByRoute: false,
      knownPassword: '',
    });
    equal(orchestrator.originalCalls, 1, 'embedded model must preserve the legacy resolver');
    equal(resolved.link, 'legacy-result', 'legacy resolver result must be returned unchanged');
  }

  // Never fabricate a first-class credential when 3x-ui has none.
  {
    const orchestrator = new FakeOrchestrator();
    const client = {
      getFirstClassClient: async () => ({ client: { email: 'navid', password: '' }, inboundIds: [5] }),
    };
    let error = null;
    try {
      await orchestrator.resolveClientCredential({
        client,
        clientModel: 'first_class',
        email: 'navid',
        host: '193.24.120.23',
        port: 3001,
        method: 'chacha20-ietf-poly1305',
        createdByRoute: false,
      });
    } catch (err) { error = err; }
    ok(error, 'missing password must fail');
    ok(/no Shadowsocks password/.test(error.message), 'failure must explain the missing credential');
    equal(orchestrator.originalCalls, 0, 'missing first-class password must not fall through and hang on links');
  }

  // Timeline copy must no longer claim every resolution came from /clients/links.
  {
    const orchestrator = new FakeOrchestrator();
    const stage = orchestrator.stage(7, 'link_fetch', 'Requesting the panel-issued share link for navid');
    equal(orchestrator.stageStarts[0].detail, 'Resolving Shadowsocks credential and share link for navid', 'link_fetch RUNNING copy must be source-neutral');
    stage.pass('Panel link received');
    equal(orchestrator.stagePasses[0].message, 'Client credential resolved; share link ready', 'link_fetch PASS copy must be source-neutral');
    orchestrator.event(7, 'link_validate', 'PASS', 'Endpoint, method and client credential validated against the panel-issued link');
    equal(orchestrator.events[0].detail, 'Endpoint, method and client credential validated', 'link_validate copy must be source-neutral');
  }

  console.log(`credential-fastpath-test: ${assertions} assertions passed`);
})().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
