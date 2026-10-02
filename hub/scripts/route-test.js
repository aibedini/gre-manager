'use strict';
// route-test.js — unit-level coverage of the route orchestrator's pure logic
// and its async lifecycle: payload building, credential resolution, event
// pagination/waits, background provisioning safety and abandoned-route sweeps.
//
// Run with: node scripts/route-test.js

const {
  assert, makeHarness, makeSshMock, makeOrchestrator, check, checkAsync, rejects, report,
} = require('./_harness');
const { XuiClient, parseShadowsocksLink, buildShadowsocksLink, selectShadowsocksLink, isValidShadowsocksPassword } = require('../server/xui');
const { inboundPayload, portEvidence, peerName, validatePort, parseClientIntent, shadowsocksClientPassword, ABANDONED_RESERVED_MS } = require('../server/route-orchestrator');
const { makeMockPanel } = require('./_xui-mock');

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });

async function main() {
  console.log('pure helpers:');

  check('portEvidence matches only the requested port', () => {
    assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3049\n', 3049).length, 1);
    assert.equal(portEvidence('tcp LISTEN 0 10 0.0.0.0:3050\n', 3049).length, 0);
    assert.equal(portEvidence('nft -A PREROUTING -p tcp --dport 3049\n', 3049).length, 1);
  });

  check('peerName is stable, short and shell-safe', () => {
    assert(peerName('Very-Long-Route-Name').length <= 11);
    assert.match(peerName('IR05 DE02!'), /^[a-z0-9_-]+$/);
    assert.equal(peerName('IR05-DE02'), peerName('IR05-DE02'));
  });

  check('Shadowsocks links round-trip method, password, host and port', () => {
    const link = buildShadowsocksLink({ method: 'chacha20-ietf-poly1305', password: 'secret', host: '1.2.3.4', port: 3049, remark: 'GRE' });
    assert.deepEqual(parseShadowsocksLink(link), { method: 'chacha20-ietf-poly1305', password: 'secret', host: '1.2.3.4', port: 3049 });
  });

  check('selectShadowsocksLink refuses endpoints, ports and ciphers that do not match', () => {
    const good = buildShadowsocksLink({ method: 'chacha20-ietf-poly1305', password: 'real', host: '1.2.3.4', port: 3049 });
    const wrongPort = buildShadowsocksLink({ method: 'chacha20-ietf-poly1305', password: 'real', host: '1.2.3.4', port: 9999 });
    const wrongHost = buildShadowsocksLink({ method: 'chacha20-ietf-poly1305', password: 'real', host: '5.6.7.8', port: 3049 });
    const wrongCipher = buildShadowsocksLink({ method: 'aes-256-gcm', password: 'real', host: '1.2.3.4', port: 3049 });
    const context = { host: '1.2.3.4', port: 3049, method: 'chacha20-ietf-poly1305' };
    assert(selectShadowsocksLink([wrongPort, wrongHost, wrongCipher, good], context));
    assert.equal(selectShadowsocksLink([wrongPort, wrongHost, wrongCipher], context), null);
    assert.equal(selectShadowsocksLink(['vmess://x', 'not a link'], context), null);
  });

  check('inboundPayload never invents a client for the caller', () => {
    const withoutClients = inboundPayload({ remark: 'GRE-test', port: 3049, method: 'chacha20-ietf-poly1305', inboundPassword: 'inbound-secret', externalProxy: { host: '37.202.247.77', port: 3049 } });
    const settings = JSON.parse(withoutClients.settings);
    assert.deepEqual(settings.clients, [], 'the generic builder must not create a client');
    assert.equal(settings.password, 'inbound-secret');
    assert.equal(JSON.parse(withoutClients.streamSettings).externalProxy[0].dest, '37.202.247.77');

    const withClient = inboundPayload({
      remark: 'GRE-test', port: 3049, method: 'chacha20-ietf-poly1305', inboundPassword: 'inbound-secret',
      clients: [{ email: 'navid', password: 'client-secret', method: 'chacha20-ietf-poly1305' }],
    });
    assert.equal(JSON.parse(withClient.settings).clients[0].password, 'client-secret');
    assert.notEqual(JSON.parse(withClient.settings).password, 'client-secret');
  });

  check('validatePort rejects privileged and out-of-range ports', () => {
    assert.equal(validatePort('3049'), 3049);
    assert.throws(() => validatePort(80));
    assert.throws(() => validatePort(70000));
    assert.throws(() => validatePort('abc'));
  });

  check('parseClientIntent requires an explicit, valid intent', () => {
    assert.deepEqual(parseClientIntent({ client_mode: 'existing', client_email: 'navid' }), { clientMode: 'existing', clientEmail: 'navid' });
    assert.deepEqual(parseClientIntent({ client_mode: 'new', client_email: ' navid ' }), { clientMode: 'new', clientEmail: 'navid' });
    assert.deepEqual(parseClientIntent({ client_name: 'legacy' }), { clientMode: 'new', clientEmail: 'legacy' });
    assert.throws(() => parseClientIntent({ client_mode: 'reuse', client_email: 'x' }), /client_mode/);
    assert.throws(() => parseClientIntent({ client_mode: 'new', client_email: '' }), /client email/);
    assert.throws(() => parseClientIntent({ client_mode: 'new', client_email: 'a b' }), /whitespace/);
  });

  check('shadowsocksClientPassword always produces an AEAD-valid key', () => {
    for (const method of ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm']) {
      for (let i = 0; i < 25; i++) {
        const key = shadowsocksClientPassword(method);
        assert(isValidShadowsocksPassword(method, key), `${method} rejected its own generated key: ${key}`);
      }
    }
  });

  console.log('\nXuiClient transport:');

  await checkAsync('cookie auth fetches CSRF once and sends it on mutations', async () => {
    const cookieCalls = [];
    let mutationSeen = 0;
    const cookieClient = new XuiClient({
      baseUrl: 'https://cookie.example', username: 'admin', password: 'secret',
      fetchImpl: async (url, opts = {}) => {
        cookieCalls.push({ url, opts });
        if (url.endsWith('/csrf-token')) return json({ success: true, obj: 'csrf-123' }, 200, { 'set-cookie': 'pre=one; Path=/' });
        if (url.endsWith('/login')) {
          assert.equal(opts.headers['x-csrf-token'], 'csrf-123', 'login must carry the CSRF token');
          return json({ success: true }, 200, { 'set-cookie': '3x-ui=session; Path=/' });
        }
        assert.match(opts.headers.cookie, /3x-ui=session/);
        if (String(opts.method).toUpperCase() === 'POST') {
          mutationSeen += 1;
          assert.equal(opts.headers['x-csrf-token'], 'csrf-123', 'mutations must carry the CSRF token');
        } else {
          assert.equal(opts.headers['x-csrf-token'], undefined, 'safe reads must not send a CSRF header');
        }
        return json({ success: true, obj: [] });
      },
    });
    await cookieClient.listInbounds();
    await cookieClient.request('/panel/api/inbounds/del/1', { method: 'POST' });
    assert.equal(cookieCalls.length, 4, 'CSRF must be fetched exactly once');
    assert.equal(mutationSeen, 1);
  });

  await checkAsync('token auth sends a bearer token and never logs in', async () => {
    const seen = [];
    const client = new XuiClient({
      baseUrl: 'https://token.example', authType: 'token', token: 'tok',
      fetchImpl: async (url, opts = {}) => {
        seen.push(url);
        assert.equal(opts.headers.authorization, 'Bearer tok');
        return json({ success: true, obj: [] });
      },
    });
    await client.listInbounds();
    assert.deepEqual(seen, ['https://token.example/panel/api/inbounds/list']);
  });

  await checkAsync('capabilities are probed once per client instance', async () => {
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const client = new XuiClient({ baseUrl: 'https://panel.example', authType: 'token', token: 't', fetchImpl: panel.fetchImpl });
    const first = await client.resolveCapabilities();
    const second = await client.resolveCapabilities();
    assert.equal(first, second, 'the capability object must be cached');
    assert.equal(panel.callsTo('/panel/api/clients/list').length, 1);
    assert.equal(panel.callsTo('/panel/api/hosts/list').length, 1);
  });

  await checkAsync('embedded first-class listing falls back to inbound settings', async () => {
    const panel = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{ id: 8, remark: 'SS-main', protocol: 'shadowsocks', clients: [{ email: 'navid' }, { email: 'navid' }, { email: 'sara' }] }],
    });
    const client = new XuiClient({ baseUrl: 'https://panel.example', authType: 'token', token: 't', fetchImpl: panel.fetchImpl });
    const clients = await client.listClients();
    assert.deepEqual(clients.map((item) => item.email), ['navid', 'sara']);
    assert.equal(clients[0].model, 'embedded');
    assert.deepEqual(clients[0].inbound_ids, [8]);
  });

  console.log('\nevent stream:');

  await checkAsync('events(after_id) returns only newer rows and rejects nonsense', async () => {
    const harness = makeHarness();
    try {
      harness.insert(`INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES ('R', ?, ?, ?, 3001, 'chacha20-ietf-poly1305', 'navid', 'RESERVED', 1, 1)`, harness.iranId, harness.foreignId, harness.panelId);
      const orchestrator = makeOrchestrator(harness, {});
      for (const stage of ['a', 'b', 'c']) orchestrator.event(1, stage, 'PASS', stage);
      const all = orchestrator.events(1);
      assert.equal(all.length, 3);
      const after = orchestrator.events(1, all[0].id);
      assert.deepEqual(after.map((e) => e.stage), ['b', 'c']);
      assert.deepEqual(orchestrator.events(1, all[2].id), []);
      assert.throws(() => orchestrator.events(1, 'nope'), /after_id/);
    } finally { harness.cleanup(); }
  });

  await checkAsync('waitForEvent resolves as soon as a new event lands', async () => {
    const harness = makeHarness();
    try {
      harness.insert(`INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES ('R', ?, ?, ?, 3001, 'chacha20-ietf-poly1305', 'navid', 'RESERVED', 1, 1)`, harness.iranId, harness.foreignId, harness.panelId);
      const orchestrator = makeOrchestrator(harness, {});
      const existing = orchestrator.event(1, 'first', 'PASS', '');
      const pending = orchestrator.waitForEvent(1, existing, 5000);
      assert.equal(orchestrator.waitersFor(1).size, 1, 'the waiter must be registered');
      setTimeout(() => orchestrator.event(1, 'second', 'PASS', 'later'), 20);
      const rows = await pending;
      assert.deepEqual(rows.map((e) => e.stage), ['second']);
      assert.equal(orchestrator.waitersFor(1), undefined, 'waiters must be cleaned up');
    } finally { harness.cleanup(); }
  });

  await checkAsync('waitForEvent returns immediately when new events already exist', async () => {
    const harness = makeHarness();
    try {
      harness.insert(`INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES ('R', ?, ?, ?, 3001, 'chacha20-ietf-poly1305', 'navid', 'RESERVED', 1, 1)`, harness.iranId, harness.foreignId, harness.panelId);
      const orchestrator = makeOrchestrator(harness, {});
      orchestrator.event(1, 'one', 'PASS', '');
      const rows = await orchestrator.waitForEvent(1, 0, 5000);
      assert.deepEqual(rows.map((e) => e.stage), ['one']);
    } finally { harness.cleanup(); }
  });

  console.log('\nbackground provisioning:');

  await checkAsync('startProvisioning always resolves — a failure never becomes an unhandled rejection', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({
      clientModel: 'first_class',
      hostsApi: true,
      clients: [{ email: 'navid', password: shadowsocksClientPassword('chacha20-ietf-poly1305'), inboundIds: [] }],
    });
    const failingFetch = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: failingFetch,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare({
        name: 'R', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      const outcome = await orchestrator.startProvisioning(prepared.route_id, prepared);
      assert.equal(outcome.ok, false, 'the outcome must report the failure instead of throwing');
      assert.match(outcome.error.message, /simulated failure/);
      const row = harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(prepared.route_id);
      assert.equal(row.status, 'FAILED');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a successful background run is observable through events only', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true, clients: [{ email: 'navid', password: shadowsocksClientPassword('chacha20-ietf-poly1305'), inboundIds: [] }] });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare({
        name: 'R2', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'existing', client_email: 'navid',
      });
      const outcome = await orchestrator.startProvisioning(prepared.route_id, prepared);
      assert.equal(outcome.ok, true, `unexpected failure: ${outcome.error && outcome.error.message}`);
      assert.equal(outcome.result.status, 'ACTIVE');
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(prepared.route_id).status, 'ACTIVE');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a successful run never leaves a secret in route_events', async () => {
    const harness = makeHarness();
    const state = { inboundCreated: false };
    const { sshExec } = makeSshMock({ getState: () => state });
    const key = shadowsocksClientPassword('chacha20-ietf-poly1305');
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare({
        name: 'R3', iranServerId: harness.iranId, foreignServerId: harness.foreignId, panelId: harness.panelId,
        start: 3000, end: 3999, client_mode: 'new', client_email: 'fresh',
      });
      const outcome = await orchestrator.startProvisioning(prepared.route_id, prepared);
      assert.equal(outcome.ok, true, `unexpected failure: ${outcome.error && outcome.error.message}`);
      const dump = JSON.stringify(orchestrator.events(prepared.route_id));
      assert(!dump.includes('ss://'), 'share link leaked into events');
      assert(!/password/i.test(dump) || /password created by this route/i.test(dump), 'a password was mentioned in events');
      assert(!dump.includes(key));
    } finally { harness.cleanup(); }
  });

  console.log('\nabandoned reservations:');

  await checkAsync('sweepAbandoned only flags long-RESERVED routes and never destroys state', async () => {
    const harness = makeHarness();
    try {
      const now = Date.now();
      const staleId = harness.insert(`INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES ('stale', ?, ?, ?, 3001, 'chacha20-ietf-poly1305', 'navid', 'RESERVED', ?, ?)`,
      harness.iranId, harness.foreignId, harness.panelId, now - ABANDONED_RESERVED_MS - 1000, now - ABANDONED_RESERVED_MS - 1000);
      const freshId = harness.insert(`INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES ('fresh', ?, ?, ?, 3002, 'chacha20-ietf-poly1305', 'navid', 'RESERVED', ?, ?)`,
      harness.iranId, harness.foreignId, harness.panelId, now, now);
      const orchestrator = makeOrchestrator(harness, {});
      const swept = orchestrator.sweepAbandoned(now);
      assert.deepEqual(swept, [staleId]);
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(staleId).status, 'STALE');
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(freshId).status, 'RESERVED');
      assert(/interrupted/i.test(harness.db.prepare('SELECT last_error FROM gre_routes WHERE id=?').get(staleId).last_error));
      assert(orchestrator.events(staleId).some((e) => /interrupted/i.test(e.detail)));
    } finally { harness.cleanup(); }
  });

  report('route orchestrator tests');
}

main().catch((err) => { console.error(err); process.exit(1); });
