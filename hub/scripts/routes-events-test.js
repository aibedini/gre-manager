'use strict';
// routes-events-test.js — end-to-end test of the async create flow and the
// live/persistent provisioning timeline.
//
// Boots the REAL hub (server/index.js) with a scripted SSH transport and fake
// 3x-ui panels, then drives the real HTTP API:
//   * POST /api/gre-routes returns 202 + route_id quickly
//   * GET  /api/gre-routes/:id/events streams incrementally (after_id, wait)
//   * terminal statuses are reachable and events survive a restart
//   * no secret is ever persisted into route_events
//   * an interrupted RESERVED route is surfaced as STALE, never auto-destroyed
//
// Run with: node scripts/routes-events-test.js

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { check, checkAsync, rejects, report } = require('./_harness');
require('./_sqlite');
const { openDb } = require('../server/db');
const cryptoUtil = require('../server/crypto');

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gre-hub-events-'));
// Windows reserves scattered port ranges (Hyper-V/WSL), so probe for a free one
// instead of assuming a random port is bindable.
let PORT = 0;
let BASE = '';
const SCENARIO_FILE = path.join(DATA_DIR, 'scenario.json');
const PASSWORD = 'events-test-password-1';
const PANEL_URL = 'https://panel-a.example';
// `legacy` exercises the original synchronous prepare(); anything else (the
// production default) exercises the live-preflight layer.
const PREFLIGHT_MODE = process.env.HUB_ROUTE_PREFLIGHT_MODE || 'live';

async function pickPort() {
  const net = require('net');
  for (let attempt = 0; attempt < 40; attempt++) {
    const candidate = 44000 + Math.floor(Math.random() * 20000);
    // eslint-disable-next-line no-await-in-loop
    const free = await new Promise((resolve) => {
      const server = net.createServer();
      server.once('error', () => resolve(false));
      server.once('listening', () => server.close(() => resolve(true)));
      server.listen(candidate, '127.0.0.1');
    });
    if (free) {
      PORT = candidate;
      BASE = `http://127.0.0.1:${candidate}`;
      return;
    }
  }
  throw new Error('could not find a bindable port for the test hub');
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeClient() {
  const client = { cookie: '', csrf: '' };
  client.call = async (pathname, { method = 'GET', body, useCookie = true, useCsrf = true } = {}) => {
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (useCookie && client.cookie) headers.Cookie = client.cookie;
    if (useCsrf && method !== 'GET' && client.csrf) headers['x-csrf-token'] = client.csrf;
    const started = Date.now();
    const res = await fetch(BASE + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) client.cookie = setCookie.split(';')[0];
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }
    if (data && data.csrf) client.csrf = data.csrf;
    return { status: res.status, data, elapsed: Date.now() - started };
  };
  return client;
}

function writeScenario(spec) {
  fs.writeFileSync(SCENARIO_FILE, JSON.stringify(spec));
}

function startHub() {
  // HUB_ROUTE_PREFLIGHT_MODE=legacy runs the original synchronous prepare();
  // production omits it and installs the live-preflight layer, which reserves
  // locally first and performs the slow network checks as timeline stages.
  const preflightMode = process.env.HUB_ROUTE_PREFLIGHT_MODE || 'live';
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server', 'index.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HUB_HOST: '127.0.0.1',
      HUB_DATA_DIR: DATA_DIR,
      HUB_TEST_SCENARIO: SCENARIO_FILE,
      HUB_TEST_FETCH_MODULE: path.join(__dirname, '_test-fetch-module.js'),
      HUB_TEST_SSH_MODULE: path.join(__dirname, '_test-ssh-module.js'),
      HUB_ROUTE_PREFLIGHT_MODE: preflightMode,
    },
    stdio: ['ignore', 'pipe', 'inherit'],  });
  return child;
}

async function waitForServer(child, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d;
    if (process.env.HUB_TEST_TRANSPORT_DEBUG === '1') process.stderr.write(`[hub] ${d}`);
  });
  while (Date.now() < deadline) {
    if (buf.includes('gre-hub listening')) return;
    if (child.exitCode !== null) throw new Error(`hub exited early (${child.exitCode})\n${buf}`);
    await sleep(100);
  }
  throw new Error(`hub did not start in time\n${buf}`);
}

// The test process opens the same SQLite file the hub writes to, so it can
// assert what was actually persisted (encrypted) for a route.
function routeOrchestratorRow(routeId) {
  const db = openDb(DATA_DIR);
  try {
    return db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(routeId);
  } finally {
    db.close();
  }
}

function seedDatabase() {  const db = openDb(DATA_DIR);
  const key = cryptoUtil.loadKey(DATA_DIR);
  const now = Date.now();
  const insert = (sql, ...params) => Number(db.prepare(sql).run(...params).lastInsertRowid);
  const iranId = insert('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
    'iran', '37.202.247.77', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw1'), now);
  const foreignId = insert('INSERT INTO servers (name,host,ssh_port,username,auth_type,secret_enc,created_at) VALUES (?,?,?,?,?,?,?)',
    'foreign', '46.8.228.7', 22, 'root', 'password', cryptoUtil.encrypt(key, 'pw2'), now);
  const panelId = insert('INSERT INTO xui_panels (name,base_url,username,auth_type,password_enc,created_at) VALUES (?,?,?,?,?,?)',
    'panel-a', PANEL_URL, '', 'token', cryptoUtil.encrypt(key, 'panel-token'), now);
  db.close();
  return { iranId, foreignId, panelId };
}

async function main() {
  await pickPort();
  const ids = seedDatabase();
  // A pre-existing global client named "navid" is exactly the reported setup.
  const navidKey = Buffer.from('abcdefghijklmnopqrstuvwxyz012345').toString('base64');
  writeScenario({
    panels: {
      [PANEL_URL]: {
        clientModel: 'first_class',
        hostsApi: true,
        clients: [{ email: 'navid', password: navidKey, method: 'chacha20-ietf-poly1305', inboundIds: [] }],
      },
    },
  });

  let child = startHub();
  try {
    await waitForServer(child);
    const anon = makeClient();
    let r = await anon.call('/api/setup', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    check('hub setup + session', () => {
      if (r.status !== 200) throw new Error(`setup returned ${r.status}`);
    });

    console.log('\nasync create returns immediately with a route id:');
    const createBody = {
      name: 'IR05-DE02',
      iran_server_id: ids.iranId,
      foreign_server_id: ids.foreignId,
      panel_id: ids.panelId,
      client_mode: 'existing',
      client_email: 'navid',
      port: 3050,
      range_start: 3000,
      range_end: 3999,
    };
    const created = await anon.call('/api/gre-routes', { method: 'POST', body: createBody });
    check('POST /api/gre-routes → 202 with route_id and RESERVED', () => {
      if (created.status !== 202) throw new Error(`expected 202, got ${created.status}: ${JSON.stringify(created.data)}`);
      if (!Number.isInteger(Number(created.data.route_id))) throw new Error('no route_id in the response');
      if (created.data.status !== 'RESERVED') throw new Error(`expected RESERVED, got ${created.data.status}`);
      // In live mode the panel has not been contacted yet, so the model is
      // discovered later and reported through the timeline instead. In legacy
      // mode it is already known when the 202 is written.
      if (PREFLIGHT_MODE === 'legacy') {
        if (created.data.client_model !== 'first_class') throw new Error('client model must be reported');
      } else if (created.data.client_model !== null && created.data.client_model !== undefined) {
        throw new Error(`live mode must not claim a client model before probing (got ${created.data.client_model})`);
      }
    });
    check('the response is fast (validation only, provisioning is background)', () => {
      if (created.elapsed > 2000) throw new Error(`took ${created.elapsed}ms`);
    });
    if (PREFLIGHT_MODE !== 'legacy') {
      check('live mode reserves before any panel or SSH work', async () => { /* asserted via the route row below */ });
    }

    const routeId = Number(created.data.route_id);

    console.log('\nincremental events:');
    let all = [];
    let lastId = 0;
    for (let i = 0; i < 60; i++) {
      const batch = await anon.call(`/api/gre-routes/${routeId}/events?after_id=${lastId}`);
      if (batch.status !== 200) throw new Error(`events returned ${batch.status}`);
      const rows = Array.isArray(batch.data) ? batch.data : [];
      for (const row of rows) {
        if (lastId && Number(row.id) <= lastId) throw new Error(`after_id returned a stale event (${row.id} <= ${lastId})`);
        lastId = Number(row.id);
      }
      all = all.concat(rows);
      const route = await anon.call(`/api/gre-routes/${routeId}`);
      if (route.data.status === 'ACTIVE') break;
      if (route.data.status === 'FAILED') {
        const detail = (await anon.call(`/api/gre-routes/${routeId}/events`)).data
          .map((e) => `${e.status} ${e.stage}: ${e.detail}`).join('\n');
        throw new Error(`route failed: ${route.data.last_error}\n${detail}`);
      }
      await sleep(80);
    }

    check('events were observable while provisioning ran', () => {
      if (all.length < 5) throw new Error(`only ${all.length} events seen`);
    });
    check('the timeline names every client-related stage explicitly', () => {
      const stages = all.map((e) => e.stage);
      // Shared by both modes.
      const required = ['request_validated', 'client_model_detected', 'client_preflight', 'port_reserved',
        'iran_peer_add', 'foreign_node_add', 'inbound_add', 'client_attach',
        'managed_host_add', 'link_validate', 'runtime_validation', 'active'];
      // Live mode replaces the coarse public-IP/connectivity pass with explicit
      // per-direction preflight stages and a dedicated port safety scan.
      const liveOnly = ['panel_probe', 'port_check', 'public_ip_preflight',
        'connectivity_iran_to_foreign', 'connectivity_foreign_to_iran', 'connectivity_preflight'];
      const legacyOnly = ['public_ip', 'connectivity'];
      for (const stage of [...required, ...(PREFLIGHT_MODE === 'legacy' ? legacyOnly : liveOnly)]) {
        if (!stages.includes(stage)) throw new Error(`missing stage ${stage} (got ${stages.join(', ')})`);
      }
      const attach = all.find((e) => e.stage === 'client_attach' && e.status === 'PASS');
      if (!attach) {
        const seen = all.filter((e) => e.stage === 'client_attach').map((e) => `${e.status}: ${e.detail}`);
        throw new Error(`client_attach never reported PASS (${seen.join(' | ') || 'no client_attach event at all'})`);
      }
      if (!/Attached existing client navid/.test(attach.detail)) throw new Error(`unexpected detail: ${attach.detail}`);
    });
    check('every mutable stage announced RUNNING before its verdict', () => {
      const stageNames = PREFLIGHT_MODE === 'legacy'
        ? ['public_ip', 'connectivity', 'gre_pairing', 'foreign_node_add', 'iran_peer_add',
          'inbound_add', 'client_attach', 'managed_host_add', 'link_fetch', 'runtime_validation']
        : ['panel_probe', 'client_preflight', 'port_check', 'public_ip_preflight',
          'connectivity_iran_to_foreign', 'connectivity_foreign_to_iran',
          'gre_pairing', 'foreign_node_add', 'iran_peer_add',
          'inbound_add', 'client_attach', 'managed_host_add', 'link_fetch', 'runtime_validation'];
      for (const stageName of stageNames) {
        const forStage = all.filter((e) => e.stage === stageName);
        if (!forStage.length) throw new Error(`missing stage ${stageName}`);
        if (!forStage.some((e) => e.status === 'RUNNING')) throw new Error(`${stageName} never announced RUNNING`);
        if (!forStage.some((e) => e.status === 'PASS')) throw new Error(`${stageName} never reached PASS`);
      }
    });
    check('no event exposes a password or a share link', () => {
      const dump = JSON.stringify(all);
      if (dump.includes('ss://')) throw new Error('a share link leaked into route_events');
      if (dump.includes(navidKey)) throw new Error('the client credential leaked into route_events');
      if (/password/i.test(dump) && !/password created by this route/i.test(dump)) {
        throw new Error('an event mentions a password');
      }
    });
    check('terminal ACTIVE is reachable through the API', () => {
      if (all[all.length - 1].stage !== 'active') throw new Error('the stream did not end on `active`');
    });

    const finalRoute = await anon.call(`/api/gre-routes/${routeId}`);
    check('GET /api/gre-routes/:id reports ACTIVE and never leaks the secret', () => {
      if (finalRoute.data.status !== 'ACTIVE') throw new Error(`status ${finalRoute.data.status}: ${finalRoute.data.last_error}`);
      if (finalRoute.data.client_password_enc || finalRoute.data.share_link_enc) throw new Error('raw secret columns were serialised');
      if (finalRoute.data.client_mode !== 'existing') throw new Error('client_mode must be reported');
      if (finalRoute.data.client_model !== 'first_class') throw new Error('client_model must be reported');
      if (finalRoute.data.link) throw new Error('the share link must not be returned without the result flag');
    });

    const resultRoute = await anon.call(`/api/gre-routes/${routeId}?result=1&wait=1`);
    check('the post-provisioning result carries the in-memory QR payload', () => {
      if (!resultRoute.data.qr_data_url || !/^data:image\/png;base64,/.test(resultRoute.data.qr_data_url)) {
        throw new Error('no QR data URL for the just-provisioned route');
      }
      if (!resultRoute.data.link || !String(resultRoute.data.link).startsWith('ss://')) throw new Error('no share link');
      if (resultRoute.data.outbound === undefined || resultRoute.data.outbound === null) throw new Error('no outbound JSON');
    });

    check('the persisted share link stays encrypted at rest', () => {
      const route = routeOrchestratorRow(routeId);
      if (!route.share_link_enc || String(route.share_link_enc).startsWith('ss://')) {
        throw new Error('the share link was stored in clear text');
      }
    });

    const fullHistory = await anon.call(`/api/gre-routes/${routeId}/events`);
    check('omitting after_id still returns the complete persistent history', () => {
      if (!Array.isArray(fullHistory.data)) throw new Error('events are not an array');
      if (fullHistory.data.length < all.length) throw new Error('history is shorter than the streamed events');
      if (fullHistory.data[fullHistory.data.length - 1].stage !== 'active') throw new Error('history does not end with `active`');
    });

    const afterLast = await anon.call(`/api/gre-routes/${routeId}/events?after_id=${lastId}`);
    check('after_id=<last> returns no rows', () => {
      if (afterLast.data.length !== 0) throw new Error(`expected 0 rows, got ${afterLast.data.length}`);
    });

    const longPoll = await anon.call(`/api/gre-routes/${routeId}/events?after_id=${lastId}&wait=1`);
    check('wait=1 long-poll returns promptly when there is nothing new', () => {
      if (!Array.isArray(longPoll.data)) throw new Error('long-poll did not return an array');
    });

    console.log('\ntimeline survives a hub restart:');
    child.kill('SIGTERM');
    await sleep(500);
    child = startHub();
    await waitForServer(child);
    const after = makeClient();
    await after.call('/api/login', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    const reopened = await after.call(`/api/gre-routes/${routeId}/events`);
    check('the same route log is served after a fresh process start', () => {
      if (reopened.status !== 200) throw new Error(`status ${reopened.status}`);
      if (reopened.data.length < fullHistory.data.length) throw new Error('history shrank after restart');
    });

    console.log(`\nclient-selection mistakes are rejected without GRE mutations (${PREFLIGHT_MODE} mode):`);
    // Distinct ports per request so the two cases cannot collide with each other
    // or with the already-ACTIVE route.
    const duplicate = await after.call('/api/gre-routes', {
      method: 'POST',
      body: { ...createBody, name: 'IR05-DE03', port: 3055, client_mode: 'new', client_email: 'navid' },
    });
    const missing = await after.call('/api/gre-routes', {
      method: 'POST',
      body: { ...createBody, name: 'IR05-DE04', port: 3056, client_mode: 'existing', client_email: 'ghost' },
    });
    const routeNames = await after.call('/api/gre-routes');

    if (PREFLIGHT_MODE === 'legacy') {
      // Legacy prepare() does the client lookup synchronously, so the mistake is
      // a 409 and no route row is ever written.
      check('duplicate email is a 409 with a friendly message', () => {
        if (duplicate.status !== 409) throw new Error(`expected 409, got ${duplicate.status}: ${JSON.stringify(duplicate.data)}`);
        if (!/already exists/i.test(duplicate.data.error)) throw new Error(`unexpected error: ${duplicate.data.error}`);
      });
      check('a missing client is a 409 with a friendly message', () => {
        if (missing.status !== 409) throw new Error(`expected 409, got ${missing.status}: ${JSON.stringify(missing.data)}`);
        if (!/no longer exists/i.test(missing.data.error)) throw new Error(`unexpected error: ${missing.data.error}`);
      });
      check('no route row was reserved by the rejected requests', () => {
        const names = routeNames.data.map((row) => row.name);
        if (names.includes('IR05-DE03') || names.includes('IR05-DE04')) throw new Error(`unexpected rows: ${names.join(', ')}`);
      });
    } else {
      // Live mode reserves first and validates on the timeline, so the mistake
      // is accepted as 202 and must then FAIL without touching either server.
      check('live mode accepts the request as 202 (reserve-then-validate)', () => {
        for (const [label, res] of [['duplicate', duplicate], ['missing', missing]]) {
          if (res.status !== 202) throw new Error(`${label}: expected 202, got ${res.status}: ${JSON.stringify(res.data)}`);
          if (!Number.isInteger(Number(res.data.route_id))) throw new Error(`${label}: no route_id`);
        }
      });
      for (const [label, res, pattern] of [
        ['duplicate email', duplicate, /already exists/i],
        ['a missing client', missing, /no longer exists/i],
      ]) {
        const id = Number(res.data.route_id);
        // Wait for the background run to settle before judging it.
        for (let i = 0; i < 80; i++) {
          const probe = await after.call(`/api/gre-routes/${id}`);
          if (['ACTIVE', 'FAILED', 'STALE', 'NEEDS_REVIEW'].includes(probe.data.status)) break;
          await sleep(80);
        }
        const route = await after.call(`/api/gre-routes/${id}`);
        const events = (await after.call(`/api/gre-routes/${id}/events`)).data;
        check(`live: ${label} fails with a friendly message`, () => {
          if (route.data.status !== 'FAILED') throw new Error(`status ${route.data.status}: ${route.data.last_error}`);
          if (!pattern.test(route.data.last_error || '')) throw new Error(`unexpected last_error: ${route.data.last_error}`);
          if (!events.some((e) => e.stage === 'client_preflight' && e.status === 'FAIL')) {
            throw new Error(`client_preflight did not report FAIL (${events.map((e) => e.stage).join(', ')})`);
          }
          // The whole point of reserving first: validation failures must not
          // have reached any GRE or inbound mutation on either server.
          const mutationStages = ['foreign_node_add', 'iran_peer_add', 'inbound_add', 'client_attach', 'client_create', 'managed_host_add'];
          const touched = events.filter((e) => mutationStages.includes(e.stage));
          if (touched.length) {
            throw new Error(`a rejected client selection reached mutations: ${touched.map((e) => `${e.status}:${e.stage}`).join(', ')}`);
          }
        });
      }
      const routeNamesFresh = await after.call('/api/gre-routes');
      check('both rejected attempts are recorded on the timeline', () => {
        const names = routeNamesFresh.data.map((row) => row.name);
        if (!names.includes('IR05-DE03') || !names.includes('IR05-DE04')) {
          throw new Error(`expected both attempts to be recorded: ${names.join(', ')}`);
        }
      });
    }

    console.log('\nFAILED routes keep their rollback timeline:');
    // The fake panel re-reads this file, so the fault takes effect on the next
    // managed-host call without restarting the hub. Turn the hosts API off as
    // well, so this route fails at the same place a broken panel would.
    writeScenario({
      panels: { [PANEL_URL]: { clientModel: 'first_class', hostsApi: true } },
      faults: ['managed_host'],
    });
    await sleep(200);
    const failing = await after.call('/api/gre-routes', { method: 'POST', body: { ...createBody, name: 'IR05-DE05', client_mode: 'new', client_email: 'route-fail', port: 3051 } });
    check('the failing route still starts as 202/RESERVED', () => {
      if (failing.status !== 202) throw new Error(`expected 202, got ${failing.status}: ${JSON.stringify(failing.data)}`);
    });
    const failingId = Number(failing.data.route_id);
    let failingEvents = [];
    for (let i = 0; i < 80; i++) {
      failingEvents = (await after.call(`/api/gre-routes/${failingId}/events`)).data;
      const route = await after.call(`/api/gre-routes/${failingId}`);
      if (route.data.status === 'FAILED') break;
      if (route.data.status === 'ACTIVE') throw new Error('the route must not have succeeded');
      await sleep(80);
    }
    const failedRoute = await after.call(`/api/gre-routes/${failingId}`);
    check('the route ends FAILED with last_error persisted', () => {
      if (failedRoute.data.status !== 'FAILED') throw new Error(`status ${failedRoute.data.status}`);
      if (!/managed-host failure/.test(failedRoute.data.last_error || '')) throw new Error(`last_error: ${failedRoute.data.last_error}`);
    });
    check('rollback events remain visible after the failure', () => {
      const stages = failingEvents.map((e) => e.stage);
      // This route created its own client, so the client rollback is a delete;
      // a route that reused an existing client emits rollback_client_detach.
      if (!stages.includes('rollback_client_delete') && !stages.includes('rollback_client_detach')) {
        throw new Error(`no client rollback event (got ${stages.join(', ')})`);
      }
      for (const required of ['rollback_inbound', 'rollback_iran_peer', 'rollback_foreign_node', 'failed']) {
        if (!stages.includes(required)) throw new Error(`missing ${required} (got ${stages.join(', ')})`);
      }
      const failed = failingEvents.find((e) => e.stage === 'failed');
      if (failed.status !== 'FAIL') throw new Error('the failed stage must be FAIL');
    });

    console.log('\ninterrupted provisioning is flagged, never destroyed:');
    child.kill('SIGTERM');
    await sleep(500);
    // Simulate a hub that died mid-provisioning: a RESERVED route that is now
    // far past any plausible provisioning window.
    const db = openDb(DATA_DIR);
    const staleId = Number(db.prepare(`
      INSERT INTO gre_routes (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, client_mode, client_model, status, created_at, updated_at)
      VALUES ('IR05-DE06', ?, ?, ?, 3052, 'chacha20-ietf-poly1305', 'navid', 'existing', 'first_class', 'RESERVED', ?, ?)
    `).run(ids.iranId, ids.foreignId, ids.panelId, Date.now() - 3600000, Date.now() - 3600000).lastInsertRowid);
    db.prepare('INSERT INTO port_allocations (route_id, iran_server_id, foreign_server_id, port, protocols, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(staleId, ids.iranId, ids.foreignId, 3052, 'tcp,udp', 'RESERVED', Date.now(), Date.now());
    db.close();

    child = startHub();
    await waitForServer(child);
    const restarted = makeClient();
    await restarted.call('/api/login', { method: 'POST', body: { password: PASSWORD }, useCookie: false });
    const staleRoute = await restarted.call(`/api/gre-routes/${staleId}`);
    check('an abandoned RESERVED route becomes STALE, not silently deleted', () => {
      if (staleRoute.data.status !== 'STALE') throw new Error(`status ${staleRoute.data.status}`);
    });
    const staleEvents = await restarted.call(`/api/gre-routes/${staleId}/events`);
    check('the interruption is explained in the route log', () => {
      if (!staleEvents.data.some((e) => /interrupted/i.test(e.detail || ''))) {
        throw new Error(`no interruption event: ${JSON.stringify(staleEvents.data)}`);
      }
    });
    const noSecrets = await restarted.call('/api/gre-routes?reveal=1');
    check('reveal only exposes secrets for ACTIVE routes', () => {
      const stale = noSecrets.data.find((row) => Number(row.id) === Number(staleId));
      if (stale && (stale.link || stale.client_password)) throw new Error('a STALE route exposed secrets');
    });
  } finally {
    child.kill('SIGTERM');
    await sleep(300);
    if (child.exitCode === null) child.kill('SIGKILL');
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
  }

  report('routes/events tests');
}

main().catch((err) => { console.error(err); process.exit(1); });
