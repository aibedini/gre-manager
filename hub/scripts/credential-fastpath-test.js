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
    this._client = null;
  }

  client() { return this._client; }

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
  // Production/live path: client_preflight already reads /clients/get before
  // any mutation. The decorated XuiClient captures that password, and link_fetch
  // consumes it without issuing ANY post-attach client detail/link request.
  {
    const orchestrator = new FakeOrchestrator();
    let getCalls = 0;
    let requestCalls = 0;
    let linkCalls = 0;
    orchestrator._client = {
      getFirstClassClient: async (email) => {
        getCalls += 1;
        equal(email, 'navid', 'preflight must read the selected identity by email');
        return {
          client: { email: 'navid', password: 'lc9h0t96ylcfeuql' },
          inboundIds: [],
        };
      },
      request: async () => { requestCalls += 1; throw new Error('post-attach request must not run'); },
      clientLinksFor: async () => { linkCalls += 1; throw new Error('must not enumerate global links'); },
    };

    const client = orchestrator.client({ id: 9 });
    await client.getFirstClassClient('navid'); // same call the live client_preflight performs

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

    equal(getCalls, 1, 'there must be exactly one /clients/get read: the preflight read');
    equal(requestCalls, 0, 'link_fetch must not issue a post-attach detail request when preflight captured the password');
    equal(linkCalls, 0, '/clients/links must never run for an existing first-class client');
    equal(orchestrator.originalCalls, 0, 'slow legacy resolver must be bypassed');
    equal(resolved.source, 'preflight_client_record', 'source must identify the preflight record');
    equal(resolved.password, 'lc9h0t96ylcfeuql', 'existing credential must be preserved exactly');
    const parsed = parseShadowsocksLink(resolved.link);
    equal(parsed.password, 'lc9h0t96ylcfeuql', 'locally built link must contain the real existing password');
    equal(parsed.method, 'chacha20-ietf-poly1305', 'link method must match the new inbound');
    equal(parsed.host, '193.24.120.23', 'link host must be the IRAN endpoint');
    equal(parsed.port, 3001, 'link port must be the new route port');
  }

  // If no preflight secret is available (legacy preflight mode or an initially
  // empty password), read exactly ONE inbound: the new inbound we just attached.
  // That endpoint's settings.clients[] is the final protocol-specific truth.
  {
    const orchestrator = new FakeOrchestrator();
    let getCalls = 0;
    let requestCalls = 0;
    orchestrator._client = {
      getFirstClassClient: async () => { getCalls += 1; return null; },
      request: async (path, options) => {
        requestCalls += 1;
        equal(path, '/panel/api/inbounds/get/6', 'fallback must fetch only the newly-created inbound');
        equal(options.allowFailure, true, 'single-inbound read must preserve HTTP status for diagnostics');
        return {
          ok: true,
          status: 200,
          data: {
            success: true,
            obj: {
              id: 6,
              protocol: 'shadowsocks',
              settings: {
                method: 'chacha20-ietf-poly1305',
                clients: [{ email: 'navid', password: 'attached-secret', method: 'chacha20-ietf-poly1305' }],
              },
            },
          },
        };
      },
    };
    const client = orchestrator.client({ id: 9 });
    const resolved = await orchestrator.resolveClientCredential({
      client,
      clientModel: 'first_class',
      inboundId: 6,
      email: 'navid',
      host: '193.24.120.23',
      port: 3001,
      method: 'chacha20-ietf-poly1305',
      createdByRoute: false,
    });
    equal(getCalls, 0, 'fallback must not call /clients/get after attach');
    equal(requestCalls, 1, 'fallback must issue exactly one bounded inbound read');
    equal(orchestrator.originalCalls, 0, 'fallback must still bypass /clients/links');
    equal(resolved.source, 'attached_inbound', 'fallback source must identify the attached inbound');
    equal(resolved.password, 'attached-secret', 'attached inbound credential must be used verbatim');
    equal(parseShadowsocksLink(resolved.link).password, 'attached-secret', 'attached credential must round-trip into the share link');
  }

  // A route-created first-class client already has an exact route-owned key.
  {
    const orchestrator = new FakeOrchestrator();
    let requestCalls = 0;
    orchestrator._client = {
      getFirstClassClient: async () => null,
      request: async () => { requestCalls += 1; return null; },
    };
    const client = orchestrator.client({ id: 9 });
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
    equal(requestCalls, 0, 'route-created credential must not require another panel query');
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

  // Never fabricate a first-class credential when the attached inbound does not
  // actually contain one. The error must be explicit and must not fall through
  // to /clients/get or /clients/links.
  {
    const orchestrator = new FakeOrchestrator();
    let requestCalls = 0;
    orchestrator._client = {
      getFirstClassClient: async () => null,
      request: async () => {
        requestCalls += 1;
        return {
          ok: true,
          status: 200,
          data: {
            success: true,
            obj: {
              id: 5,
              protocol: 'shadowsocks',
              settings: { method: 'chacha20-ietf-poly1305', clients: [{ email: 'navid', password: '' }] },
            },
          },
        };
      },
    };
    const client = orchestrator.client({ id: 9 });
    let error = null;
    try {
      await orchestrator.resolveClientCredential({
        client,
        clientModel: 'first_class',
        inboundId: 5,
        email: 'navid',
        host: '193.24.120.23',
        port: 3001,
        method: 'chacha20-ietf-poly1305',
        createdByRoute: false,
      });
    } catch (err) { error = err; }
    ok(error, 'missing password must fail');
    ok(/no Shadowsocks password/.test(error.message), 'failure must explain the missing attached credential');
    equal(requestCalls, 1, 'missing credential path must inspect only the new inbound once');
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
