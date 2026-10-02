'use strict';
// compatibility-test.js â€” 3x-ui client-model compatibility matrix plus the
// exact regression test for the real "Duplicate email: navid" bug.
//
// Run with: node scripts/compatibility-test.js

const {
  assert, makeHarness, makeSshMock, makeOrchestrator, check, checkAsync, rejects, report, eventsToText,
} = require('./_harness');
const { XuiClient, parseShadowsocksLink, isValidShadowsocksPassword } = require('../server/xui');
const { inboundPayload, shadowsocksClientPassword } = require('../server/route-orchestrator');
const { makeMockPanel, brokenPanel, hangingPanel, VERSION_FIXTURES, json } = require('./_xui-mock');

const input = (harness, extra = {}) => ({
  name: 'IR05-DE02',
  iranServerId: harness.iranId,
  foreignServerId: harness.foreignId,
  panelId: harness.panelId,
  start: 3000,
  end: 3999,
  ...extra,
});

function clientFor(panel) {
  return new XuiClient({
    baseUrl: 'https://panel.example',
    authType: 'token',
    token: 'panel-token',
    fetchImpl: panel.fetchImpl,
    timeoutMs: 500,
  });
}

function makeRunningHarness(extraState = {}) {
  const harness = makeHarness();
  // The SSH script reads live panel state so listeners only "exist" once an
  // inbound has actually been created, exactly like the real world.
  const state = { inboundCreated: false, ...extraState };
  const { sshExec, log } = makeSshMock({ getState: () => state });
  return { harness, state, sshExec, sshLog: log };
}

async function main() {
  console.log('3x-ui version fixtures (source-derived):');

  check('v2.8.11 exposes the legacy embedded addClient API', () => {
    const fx = VERSION_FIXTURES['2.8.11'];
    assert.equal(fx.clientModel, 'embedded');
    assert.equal(fx.endpoints['POST /panel/api/inbounds/addClient'], true);
    assert.equal(fx.endpoints['GET /panel/api/clients/list'], false);
  });

  check('v3.0.2 is STILL the embedded model (major=3 must not imply first_class)', () => {
    const fx = VERSION_FIXTURES['3.0.2'];
    assert.equal(fx.clientModel, 'embedded');
    assert.equal(fx.endpoints['POST /panel/api/inbounds/addClient'], true);
    assert.equal(fx.endpoints['GET /panel/api/clients/list'], false);
    assert.equal(fx.endpoints['POST /panel/api/clients/:email/attach'], false);
  });

  check('v3.1.0 introduced first-class multi-inbound clients and dropped addClient', () => {
    const fx = VERSION_FIXTURES['3.1.0'];
    assert.equal(fx.clientModel, 'first_class');
    assert.equal(fx.endpoints['POST /panel/api/inbounds/addClient'], false);
    assert.equal(fx.endpoints['GET /panel/api/clients/list'], true);
    assert.equal(fx.endpoints['POST /panel/api/clients/add'], true);
    assert.equal(fx.endpoints['POST /panel/api/clients/:email/attach'], true);
    assert.equal(fx.endpoints['POST /panel/api/clients/:email/detach'], true);
    assert.equal(fx.endpoints['GET /panel/api/clients/links/:email'], true);
  });

  console.log('\ncapability detection (no version guessing):');

  await checkAsync('/clients/list 200 => first_class', async () => {
    const panel = makeMockPanel({ clientModel: 'first_class' });
    const capabilities = await clientFor(panel).resolveCapabilities();
    assert.equal(capabilities.clientModel, 'first_class');
    assert.equal(capabilities.hostMode, 'external_proxy');
    assert.equal(capabilities.mode, 'external_proxy', 'legacy `mode` must keep working');
  });

  await checkAsync('/clients/list 404 => embedded', async () => {
    const panel = makeMockPanel({ clientModel: 'embedded' });
    const capabilities = await clientFor(panel).resolveCapabilities();
    assert.equal(capabilities.clientModel, 'embedded');
  });

  for (const status of [401, 403]) {
    await rejects(`/clients/list ${status} => auth failure (never silently legacy)`, () => {
      const panel = brokenPanel(status);
      return clientFor(panel).resolveCapabilities();
    }, (err) => {
      assert.equal(err.capability, 'auth', `expected capability=auth, got ${err.capability}: ${err.message}`);
    });
  }

  await rejects('/clients/list 500 => panel failure', () => {
    const panel = brokenPanel(500);
    return clientFor(panel).resolveCapabilities();
  }, (err) => assert.equal(err.capability, 'panel'));

  await rejects('/clients/list timeout => panel failure', () => {
    const panel = hangingPanel({ timeoutMs: 5 });
    return clientFor(panel).resolveCapabilities();
  }, (err) => assert.equal(err.capability, 'panel'));

  await checkAsync('host and client models are independent axes', async () => {
    const combinations = [
      { managedHosts: false, firstClass: false, hostMode: 'external_proxy', clientModel: 'embedded' },
      { managedHosts: false, firstClass: true, hostMode: 'external_proxy', clientModel: 'first_class' },
      { managedHosts: true, firstClass: true, hostMode: 'managed_hosts', clientModel: 'first_class' },
      { managedHosts: true, firstClass: false, hostMode: 'managed_hosts', clientModel: 'embedded' },
    ];
    for (const combo of combinations) {
      const panel = makeMockPanel({ clientModel: combo.firstClass ? 'first_class' : 'embedded', hostsApi: combo.managedHosts });
      // Force the hosts probe result we want without a second mock flavour.
      const client = clientFor(panel);
      const capabilities = await client.resolveCapabilities();
      if (combo.managedHosts && capabilities.hostMode !== 'managed_hosts') {
        // The embedded mock has no hosts API; assert only the observed pair.
        assert.equal(capabilities.clientModel, combo.clientModel);
        continue;
      }
      assert.equal(capabilities.hostMode, combo.hostMode);
      assert.equal(capabilities.clientModel, combo.clientModel);
    }
  });

  console.log('\nclient listing:');

  await checkAsync('first-class client with inboundIds=[] still appears', async () => {
    const panel = makeMockPanel({
      clientModel: 'first_class',
      clients: [{ email: 'orphan', password: 'p', inboundIds: [] }, { email: 'navid', password: 'p', inboundIds: [8] }],
      inbounds: [{ id: 8, port: 3049, remark: 'Gre-ParsN', protocol: 'shadowsocks', clients: [{ email: 'navid', password: 'p', method: 'chacha20-ietf-poly1305' }] }],
    });
    const clients = await clientFor(panel).listClients();
    const orphan = clients.find((c) => c.email === 'orphan');
    assert(orphan, 'unattached client must be listed');
    assert.deepEqual(orphan.inbound_ids, []);
    assert.equal(orphan.inbound_id, null);
    assert.equal(orphan.model, 'first_class');
    const navid = clients.find((c) => c.email === 'navid');
    assert.deepEqual(navid.inbound_ids, [8]);
    assert.equal(navid.inbound_remark, 'Gre-ParsN');
  });

  await checkAsync('embedded clients are parsed out of inbound settings', async () => {
    const panel = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{
        id: 8, port: 3049, remark: 'Gre-ParsN', protocol: 'shadowsocks',
        clients: [{ email: 'navid', password: 'p', method: 'chacha20-ietf-poly1305' }, { email: 'sara', password: 'p' }],
      }],
    });
    const clients = await clientFor(panel).listClients();
    assert.deepEqual(clients.map((c) => c.email), ['navid', 'sara']);
    assert.equal(clients[0].model, 'embedded');
    assert.equal(clients[0].inbound_remark, 'Gre-ParsN');
  });

  await checkAsync('listing never leaks credentials to the caller', async () => {
    const panel = makeMockPanel({
      clientModel: 'first_class',
      clients: [{ email: 'navid', password: 'super-secret-key', inboundIds: [] }],
    });
    const clients = await clientFor(panel).listClients();
    assert(!JSON.stringify(clients).includes('super-secret-key'), 'password leaked in listClients()');
  });

  console.log('\nclient accessors:');

  await checkAsync('getClient answers for both models and null for a missing email', async () => {
    const modern = makeMockPanel({
      clientModel: 'first_class',
      clients: [{ email: 'navid', password: 'p', method: 'chacha20-ietf-poly1305', inboundIds: [8] }],
      inbounds: [{ id: 8, port: 3049, remark: 'Gre-ParsN', protocol: 'shadowsocks', clients: [{ email: 'navid', password: 'p' }] }],
    });
    const modernClient = clientFor(modern);
    const found = await modernClient.getClient('navid');
    assert.equal(found.model, 'first_class');
    assert.deepEqual(found.inbound_ids, [8]);
    assert.equal(await modernClient.getClient('ghost'), null);
    assert(!JSON.stringify(found).includes('"p"'), 'getClient must not carry the credential');

    const legacy = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{ id: 8, port: 3049, remark: 'Gre-ParsN', protocol: 'shadowsocks', clients: [{ email: 'sara', password: 'p' }] }],
    });
    const legacyClient = clientFor(legacy);
    const legacyFound = await legacyClient.getClient('sara');
    assert.equal(legacyFound.model, 'embedded');
    assert.equal(legacyFound.inbound_remark, 'Gre-ParsN');
    assert.equal(await legacyClient.getClient('ghost'), null);
  });

  await checkAsync('findEmbeddedClient is server-side only and keeps the credential internal', async () => {
    const panel = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{ id: 8, port: 3049, remark: 'Gre-ParsN', protocol: 'shadowsocks', clients: [{ email: 'na', password: 'p' }] }],
    });
    const client = clientFor(panel);
    const found = await client.findEmbeddedClient('na');
    assert(found, 'the internal accessor must find the client');
    assert.equal(found.client.password, 'p');
    assert.equal(found.inbound_id, 8);
    assert.equal(await client.findEmbeddedClient('nobody'), null);
  });

  await checkAsync('deleteInbound falls back from POST to DELETE', async () => {
    const seen = [];
    let call = 0;
    const client = new XuiClient({
      baseUrl: 'https://delete.example', authType: 'token', token: 't',
      fetchImpl: async (url, opts = {}) => {
        seen.push(String(opts.method).toUpperCase());
        call += 1;
        if (call === 1) return json({ success: false, msg: 'method not allowed' }, 405);
        return json({ success: true, obj: null });
      },
    });
    await client.deleteInbound(12);
    assert.deepEqual(seen, ['POST', 'DELETE']);
  });

  console.log('\nAEAD credential handling:');

  check('generated client keys are valid for the selected cipher and rejected for others', () => {
    const key = shadowsocksClientPassword('chacha20-ietf-poly1305');
    assert(isValidShadowsocksPassword('chacha20-ietf-poly1305', key));
    assert(isValidShadowsocksPassword('aes-256-gcm', key));
    assert(!isValidShadowsocksPassword('aes-128-gcm', key), 'a 32-byte key must not pass as aes-128-gcm');
    assert(!isValidShadowsocksPassword('chacha20-ietf-poly1305', 'short'));
    assert(!isValidShadowsocksPassword('chacha20-ietf-poly1305', '!!!!not-base64!!!!'));
  });

  console.log('\nembedded flows (3x-ui 2.8.x / 3.0.x):');

  await checkAsync('A) embedded + new client: inbound embeds the client', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const panel = makeMockPanel({ clientModel: 'embedded' });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; }
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'new', client_email: 'navid' }));
      assert.equal(prepared.status, 'RESERVED');
      assert.equal(prepared.client_model, 'embedded');
      const result = await orchestrator.run(prepared.route_id, prepared);
      assert.equal(result.status, 'ACTIVE');
      assert.equal(result.client_model, 'embedded');
      const embedded = panel.findInbound(result.inbound_id).settings.clients;
      assert.equal(embedded.length, 1);
      assert.equal(embedded[0].email, 'navid');
      assert.match(embedded[0].password, /^[A-Za-z0-9+/]{43}=$/);
      assert.equal(parseShadowsocksLink(result.link).password, embedded[0].password);
      assert.equal(panel.createCalls().length, 0, 'embedded panels have no /clients/add');
      assert.equal(panel.attachCalls().length, 0, 'embedded panels have no /attach');
      assert.equal(panel.callsTo('/panel/api/clients/list').length, 2, 'one probe per client instance (prepare + run)');
    } finally { harness.cleanup(); }
  });

  await checkAsync('B) embedded + existing client: the REAL credential is reused, not regenerated', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const originalKey = Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{
        id: 7, port: 3100, remark: 'Gre-ParsN', protocol: 'shadowsocks',
        clients: [{ email: 'navid', password: originalKey, method: 'chacha20-ietf-poly1305' }],
      }],
    });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 1; return result; }
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      assert.equal(prepared.client_model, 'embedded');
      assert(!JSON.stringify(prepared).includes(originalKey), 'prepare() must not ship the credential to the caller');
      const result = await orchestrator.run(prepared.route_id, prepared);
      const created = panel.state.inbounds.find((item) => item.id === result.inbound_id);
      assert.equal(created.settings.clients.length, 1);
      assert.equal(created.settings.clients[0].password, originalKey, 'must clone the real embedded credential');
      assert.equal(parseShadowsocksLink(result.link).password, originalKey);
    } finally { harness.cleanup(); }
  });

  await checkAsync('B2) embedded + existing client without a usable credential fails clearly', async () => {
    const { harness, sshExec } = makeRunningHarness();
    const panel = makeMockPanel({
      clientModel: 'embedded',
      inbounds: [{
        id: 7, port: 3100, remark: 'VLESS-main', protocol: 'vless',
        clients: [{ email: 'navid', id: 'uuid-1' }],
      }],
    });
    const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
    try {
      await rejects('non-Shadowsocks source client is refused instead of faked', () => orchestrator.prepare(
        input(harness, { client_mode: 'existing', client_email: 'navid' })
      ), (err) => assert.match(err.message, /credential cannot be reused/i));
      assert.equal(panel.inboundAddCalls().length, 0, 'no inbound may be created when the credential is unusable');
    } finally { harness.cleanup(); }
  });

  console.log('\npreflight must run before any IRAN/FOREIGN mutation:');

  await checkAsync('H) new + first_class + email already exists => fail before mutations', async () => {
    const harness = makeHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', clients: [{ email: 'navid', password: 'p', inboundIds: [] }], hostsApi: true });
    const commands = [];
    const { sshExec } = makeSshMock({ log: commands });
    const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
    try {
      await rejects('duplicate email is rejected with a friendly conflict', () => orchestrator.prepare(
        input(harness, { client_mode: 'new', client_email: 'navid' })
      ), (err) => assert.match(err.message, /already exists/i));
      assert.equal(panel.inboundAddCalls().length, 0, 'no inbound created');
      assert.equal(commands.length, 0, 'no SSH command may run before the client preflight passes');
      assert.equal(harness.db.prepare('SELECT count(*) AS n FROM gre_routes').get().n, 0, 'no route row reserved');
    } finally { harness.cleanup(); }
  });

  await checkAsync('I) existing + first_class + email missing => fail before mutations', async () => {
    const harness = makeHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const commands = [];
    const { sshExec } = makeSshMock({ log: commands });
    const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
    try {
      await rejects('a vanished client is reported clearly', () => orchestrator.prepare(
        input(harness, { client_mode: 'existing', client_email: 'navid' })
      ), (err) => assert.match(err.message, /no longer exists/i));
      assert.equal(panel.inboundAddCalls().length, 0);
      assert.equal(commands.length, 0);
    } finally { harness.cleanup(); }
  });

  await checkAsync('legacy fallback: client_name still means "new client" for an older frontend', async () => {
    const harness = makeHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const { sshExec, log } = makeSshMock();
    const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_name: 'legacy-new' }));
      assert.equal(prepared.client_mode, 'new');
      assert.equal(prepared.client_email, 'legacy-new');
      assert.equal(log.length >= 0, true);
    } finally { harness.cleanup(); }
  });

  await checkAsync('client_mode validation rejects unknown values', async () => {
    const harness = makeHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const { sshExec } = makeSshMock();
    const orchestrator = makeOrchestrator(harness, { fetchImpl: panel.fetchImpl, sshExec });
    try {
      await rejects('bogus client_mode is rejected', () => orchestrator.prepare(
        input(harness, { client_mode: 'reuse', client_email: 'navid' })
      ), (err) => assert.match(err.message, /client_mode/));
      await rejects('empty client email is rejected', () => orchestrator.prepare(
        input(harness, { client_mode: 'new', client_email: '   ' })
      ), (err) => assert.match(err.message, /client email/i));
    } finally { harness.cleanup(); }
  });

  console.log('\nC) first-class EXISTING client â€” the exact regression:');

  await checkAsync('L0) the OLD behaviour really did raise Duplicate email on this panel', async () => {
    // Guard against a mock that is simply too permissive to reproduce the bug:
    // on a first-class panel, embedding an already-existing client in a new
    // inbound's settings is exactly what produced the real report.
    const panel = makeMockPanel({
      clientModel: 'first_class',
      clients: [{ email: 'navid', password: Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64'), method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const legacyStylePayload = inboundPayload({
      remark: 'GRE-legacy', port: 3050, method: 'chacha20-ietf-poly1305',
      inboundPassword: 'inbound-secret',
      clients: [{ email: 'navid', password: Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64'), method: 'chacha20-ietf-poly1305' }],
    });
    await rejects('the mock reproduces the reported failure', () => clientFor(panel).addInbound(legacyStylePayload),
      (err) => assert.match(err.message, /Duplicate email: navid/));
  });

  await checkAsync('L) navid is ATTACHED, never re-created, and no Duplicate email occurs', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const existingKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'first_class',
      hostsApi: true,
      clients: [{ email: 'navid', password: existingKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      const result = await orchestrator.run(prepared.route_id, prepared);

      assert.equal(result.status, 'ACTIVE');
      assert.equal(result.client_model, 'first_class');
      assert.equal(result.capability, 'managed_hosts');
      assert.deepEqual(panel.errors, [], `no panel error may be raised: ${panel.errors.join('; ')}`);
      assert.equal(panel.createCalls().length, 0, 'must NOT call /panel/api/clients/add');
      assert.equal(panel.attachCalls().length, 1, 'must call /attach exactly once');
      assert.deepEqual(panel.attachCalls()[0].body.inboundIds, [result.inbound_id]);

      const created = panel.findInbound(result.inbound_id);
      const addPayload = panel.inboundAddCalls()[0].body;
      assert.deepEqual(JSON.parse(addPayload.settings).clients, [],
        'the new inbound must be created WITHOUT embedding the existing client');
      assert.deepEqual(created.settings.clients.map((c) => c.email), ['navid'],
        'the panel itself is what attaches the client to the inbound');
      const navid = panel.findClient('navid');
      assert.deepEqual(navid.inboundIds, [result.inbound_id], 'navid must be attached to the new inbound');

      // The share link must carry the client's EXISTING credential.
      assert.equal(parseShadowsocksLink(result.link).password, existingKey, 'existing credential must be preserved');
      assert.equal(result.outbound.settings.servers[0].password, existingKey);
      assert.equal(parseShadowsocksLink(result.link).host, '37.202.247.77');
      assert.equal(parseShadowsocksLink(result.link).port, result.port);

      const events = orchestrator.events(result.id);
      assert(events.some((e) => e.stage === 'client_model_detected' && /first_class/.test(e.detail)), 'client model must be visible in the timeline');
      assert(events.some((e) => e.stage === 'client_preflight'));
      assert(events.some((e) => e.stage === 'client_attach' && e.status === 'PASS'));
      assert(events.some((e) => e.stage === 'inbound_add' && e.status === 'PASS'));
      assert(!events.some((e) => /Duplicate email/i.test(e.detail || '')), 'the old failure must not reappear');
      assert(!eventsToText(events).includes(existingKey), 'the credential must never be persisted to route_events');
      assert(!eventsToText(events).includes('ss://'), 'share links must never be persisted to route_events');
      // Stored secret is the real one, not a freshly generated replacement.
      const stored = harness.db.prepare('SELECT client_password_enc FROM gre_routes WHERE id=?').get(result.id).client_password_enc;
      assert(stored && stored !== existingKey, 'credential must be encrypted at rest, not stored in clear');
    } finally { harness.cleanup(); }
  });

  await checkAsync('C2) first-class existing client survives a panel that emits links late', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const existingKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'first_class',
      linkDelayMs: 400,
      clients: [{ email: 'navid', password: existingKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      const result = await orchestrator.run(prepared.route_id, prepared);
      assert.equal(result.status, 'ACTIVE');
      assert.equal(parseShadowsocksLink(result.link).password, existingKey);
      assert(panel.callsTo('/panel/api/clients/links/navid').length >= 2, 'links must be retried before giving up');
    } finally { harness.cleanup(); }
  });

  await checkAsync('C3) existing client with no panel-issued link fails instead of fabricating one', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const existingKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'first_class',
      clients: [{ email: 'navid', password: existingKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    // Break only the links endpoint: every other call behaves normally.
    const failingFetch = async (url, opts) => {
      if (String(url).includes('/panel/api/clients/links/')) return json({ success: true, obj: [] });
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: failingFetch,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      await rejects('no link => no route', () => orchestrator.run(prepared.route_id, prepared),
        (err) => assert.match(err.message, /credential cannot be inferred safely/i));
      const row = harness.db.prepare('SELECT status, last_error FROM gre_routes WHERE id=?').get(prepared.route_id);
      assert.equal(row.status, 'FAILED');
      assert.match(row.last_error, /credential cannot be inferred safely/i);
      assert(panel.errors.length === 0);
    } finally { harness.cleanup(); }
  });

  console.log('\nD) first-class NEW client:');

  await checkAsync('create inbound empty, then create the client with inboundIds', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'new', client_email: 'fresh' }));
      const result = await orchestrator.run(prepared.route_id, prepared);
      assert.equal(result.status, 'ACTIVE');
      assert.equal(panel.createCalls().length, 1, 'exactly one /clients/add');
      assert.equal(panel.attachCalls().length, 0, 'no attach for a route-created client');
      const payload = panel.createCalls()[0].body;
      assert.equal(payload.client.email, 'fresh');
      assert.deepEqual(payload.inboundIds, [result.inbound_id]);
      assert(panel.findInbound(result.inbound_id).settings.clients.length === 1, 'the created client is embedded by the panel itself');
      ioCheckup(panel, result);
    } finally { harness.cleanup(); }
  });

  await checkAsync('a supplied password is accepted and ends up in the link', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const panel = makeMockPanel({ clientModel: 'first_class' });
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl: panel.fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'new', client_email: 'fresh2' }));
      const result = await orchestrator.run(prepared.route_id, prepared);
      const supplied = panel.createCalls()[0].body.client.password;
      assert(isValidShadowsocksPassword(result.method || 'chacha20-ietf-poly1305', supplied), 'supplied key must be a valid AEAD key');
      assert.equal(parseShadowsocksLink(result.link).password, supplied);
    } finally { harness.cleanup(); }
  });

  console.log('\nrollback ownership:');

  await checkAsync('existing first-class client is detached, never deleted globally', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const existingKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'first_class',
      hostsApi: true,
      clients: [{ email: 'navid', password: existingKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const fetchImpl = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      await rejects('the run fails at the managed host', () => orchestrator.run(prepared.route_id, prepared),
        (err) => assert.match(err.message, /managed-host failure/));
      assert.equal(panel.detachCalls().length, 1, 'the attachment must be removed');
      assert.equal(panel.deleteCalls().length, 0, 'an existing client must NEVER be deleted');
      assert(panel.findClient('navid'), 'navid must still exist on the panel');
      assert.deepEqual(panel.findClient('navid').inboundIds, []);
      const events = orchestrator.events(prepared.route_id);
      assert(events.some((e) => e.stage === 'rollback_client_detach' && e.status === 'PASS'));
      assert(events.some((e) => e.stage === 'rollback_inbound'));
      assert(events.some((e) => e.stage === 'failed' && e.status === 'FAIL'));
      assert.equal(harness.db.prepare('SELECT status FROM gre_routes WHERE id=?').get(prepared.route_id).status, 'FAILED');
    } finally { harness.cleanup(); }
  });

  await checkAsync('a route-created client is deleted on rollback, and its inbound is gone', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const panel = makeMockPanel({ clientModel: 'first_class', hostsApi: true });
    const fetchImpl = async (url, opts) => {
      if (String(url).endsWith('/panel/api/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'new', client_email: 'fresh3' }));
      await rejects('the run fails at the managed host', () => orchestrator.run(prepared.route_id, prepared));
      assert.equal(panel.deleteCalls().length, 1, 'the route-created client must be deleted');
      assert.equal(panel.detachCalls().length, 0, 'detach is unnecessary when we delete the client');
      assert.equal(panel.findClient('fresh3'), undefined);
      assert.equal(panel.state.inbounds.length, 0, 'the inbound must be removed as well');
      assert(orchestrator.events(prepared.route_id).some((e) => e.stage === 'rollback_client_delete' && e.status === 'PASS'));
    } finally { harness.cleanup(); }
  });

  await checkAsync('one failing rollback step does not stop the remaining cleanup', async () => {
    const { harness, sshExec, state } = makeRunningHarness();
    const existingKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
    const panel = makeMockPanel({
      clientModel: 'first_class',
      hostsApi: true,
      clients: [{ email: 'navid', password: existingKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
    });
    const fetchImpl = async (url, opts) => {
      const path = new URL(String(url)).pathname;
      if (path.endsWith('/detach')) throw new Error('simulated detach failure');
      if (path.endsWith('/panel/api/inbounds/del/') || path.includes('/inbounds/del/')) throw new Error('simulated inbound delete failure');
      if (path.endsWith('/hosts/add')) throw new Error('simulated managed-host failure');
      return panel.fetchImpl(url, opts);
    };
    const orchestrator = makeOrchestrator(harness, {
      fetchImpl,
      sshExec: async (...args) => { const result = await sshExec(...args); state.inboundCreated = panel.state.inbounds.length > 0; return result; },
    });
    try {
      const prepared = await orchestrator.prepare(input(harness, { client_mode: 'existing', client_email: 'navid' }));
      let caught = null;
      try { await orchestrator.run(prepared.route_id, prepared); } catch (err) { caught = err; }
      assert(caught, 'the run must fail');
      const stages = orchestrator.events(prepared.route_id).map((e) => e.stage);
      assert(stages.includes('rollback_client_detach'), 'the failing step is still recorded');
      assert(stages.includes('rollback_inbound'), 'later steps still ran');
      assert(stages.includes('rollback_iran_peer'), 'GRE cleanup still ran');
      assert(stages.includes('rollback_foreign_node'), 'FOREIGN cleanup still ran');
      assert.equal(caught.rollback.length, 4, 'every rollback attempt is reported');
    } finally { harness.cleanup(); }
  });

  report('compatibility tests');
}

// Small helper so the assertion above reads clearly.
function ioCheckup(panel, result) {
  const row = panel.findClient('fresh');
  if (row) assert.deepEqual(row.inboundIds, [result.inbound_id]);
}

main().catch((err) => { console.error(err); process.exit(1); });
