'use strict';

// v2.15.1 regressions: the blank Overview and the discovery state handling.
//
// The Overview crash was an undefined identifier (`server` inside a function whose
// local is `s`). It threw before the drawer's innerHTML was assigned, so the panel
// and every handler below it silently disappeared.
//
// `renderOverview` is EXECUTED here against a minimal DOM shim, which is the only
// way to prove it cannot throw. A substring or regex audit cannot: the first
// attempt at one flagged English prose ("probe this server.") and missed the real
// bug because `server` legitimately appears as a parameter name elsewhere.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const { assert, check, report } = require('./_harness');

const PUBLIC = path.join(__dirname, '..', 'public');
const APP = path.join(PUBLIC, 'app.js');
const appSource = fs.readFileSync(APP, 'utf8');
const topology = require('../public/server-topology');
const responses = require('../public/discovery-response');
const discovery = require('../server/discovery');

// ---------------------------------------------------------------------------
// Minimal DOM: enough for the declaration block of app.js to evaluate and for
// renderOverview() to run. It records what was rendered so the test can assert on
// it rather than trusting that "no throw" means "rendered".
// ---------------------------------------------------------------------------
function fakeElement(id) {
  const el = {
    id,
    innerHTML: '',
    textContent: '',
    value: '',
    disabled: false,
    dataset: {},
    style: {},
    children: [],
    listeners: {},
    classList: {
      _set: new Set(),
      add(...c) { c.forEach((x) => this._set.add(x)); },
      remove(...c) { c.forEach((x) => this._set.delete(x)); },
      toggle(c, on) { if (on === undefined ? !this._set.has(c) : on) this._set.add(c); else this._set.delete(c); },
      contains(c) { return this._set.has(c); },
    },
    addEventListener(name, fn) { (this.listeners[name] = this.listeners[name] || []).push(fn); },
    removeEventListener() {},
    appendChild(child) { this.children.push(child); return child; },
    removeChild() {},
    setAttribute() {},
    getAttribute() { return null; },
    querySelector() { return fakeElement(`${id} > q`); },
    querySelectorAll() { return []; },
    focus() {},
    select() {},
    remove() {},
  };
  return el;
}

function makeDom() {
  const elements = new Map();
  const get = (selector) => {
    if (!elements.has(selector)) elements.set(selector, fakeElement(selector));
    return elements.get(selector);
  };
  const document = {
    body: fakeElement('body'),
    hidden: false,
    elements,
    getElementById: (id) => get(`#${id}`),
    querySelector: (sel) => get(sel),
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {},
    createElement: (tag) => fakeElement(tag),
    execCommand: () => true,
  };
  return { document, get, elements };
}

// Load the declaration block of app.js (everything before the bootstrap IIFE) in
// a sandbox, so the real renderOverview runs with the real shared modules.
function loadApp(serverState) {
  const dom = makeDom();
  // Cut at the explicit boot banner rather than guessing at an IIFE: everything
  // above it is declarations and event-listener registrations, everything below
  // performs network I/O on load.
  const bootAt = appSource.lastIndexOf('// ---------- boot');
  assert(bootAt > 0, 'expected the boot section banner in app.js');
  const declarations = appSource.slice(0, bootAt);

  const sandbox = {
    window: {},
    document: dom.document,
    console,
    fetch: () => Promise.reject(new Error('no network in this test')),
    setTimeout, clearTimeout, setInterval, clearInterval,
    URLSearchParams, URL, Date, Math, JSON, Object, Array, String, Number, Boolean, Promise, Map, Set,
    Symbol, Error, RegExp, Intl, isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent,
    navigator: { clipboard: { writeText: async () => {} } },
    confirm: () => true,
    alert: () => {},
    AbortController,
    location: { href: 'http://localhost/' },
    performance,
  };
  sandbox.window = sandbox;
  sandbox.window.ServerTopology = topology;
  sandbox.window.DiscoveryResponse = responses;
  sandbox.window.location = sandbox.location;
  sandbox.globalThis = sandbox;
  // `$`/`$$` are used at top level by the declaration block.
  sandbox.$ = (sel) => dom.get(sel);
  sandbox.$$ = () => [];

  const context = vm.createContext(sandbox);
  // The runner is appended to the SAME script, so it shares the lexical scope of
  // the declarations (`state` is a `const` and is not reachable from outside).
  const source = [
    declarations,
    ';globalThis.__renderOverview = renderOverview;',
    'globalThis.__setServer = (value) => { state.current = value; };',
    'globalThis.__renderWith = (value) => { state.current = value; renderOverview(); };',
  ].join('\n');
  vm.runInContext(source, context, { filename: 'app.js' });
  return {
    sandbox,
    dom,
    renderOverview: sandbox.__renderOverview,
    run: (code) => vm.runInContext(code, context),
    // Render the Overview exactly the way the drawer does, and hand back the HTML
    // that was written into #tab-overview.
    renderWith(server) {
      dom.get('#tab-overview').innerHTML = '';
      sandbox.__renderWith(server);
      return dom.get('#tab-overview').innerHTML;
    },
    setServer(server) { sandbox.__setServer(server); },
  };
}

const HEALTHY = { ok: true, checked_at: Date.now(), reason: null, error: null, error_class: null, stale_for_ms: 0 };
const FAILED = { ok: false, checked_at: Date.now(), reason: 'SSH timeout', error: 'command timed out', error_class: 'timeout', stale_for_ms: 0 };
const DISC_FAILED = { ok: false, checked_at: Date.now(), reason: 'gre status timed out', error: 'gre status --json timed out after 15s', error_class: 'timeout', stale_for_ms: 0 };

function serverFixture(overrides = {}) {
  return {
    id: 4,
    name: 'Hetz4',
    host: '10.0.0.4',
    ssh_port: 22,
    username: 'root',
    key_installed: true,
    has_secret: true,
    has_fallback_password: false,
    host_key_fp: 'SHA256:abc',
    snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString(), manager: { installed: true, version: '2.8.2' }, status: {}, legacy: {} },
    probe: { health: HEALTHY, discovery: { ok: true, checked_at: Date.now(), reason: null, error: null } },
    connectivity: [],
    ...overrides,
  };
}

function main() {
  console.log('TEST 1 — renderOverview() cannot blank the panel:');

  check('renders the toolbar, overview content and probe banner without throwing', () => {
    const server = serverFixture({ probe: { health: HEALTHY, discovery: DISC_FAILED } });
    const app = loadApp();
    const html = app.renderWith(server);
    assert(html.length > 0, 'the Overview element must have been populated');
    assert(/ov-discover/.test(html), 'the Run discovery button must be rendered');
    assert(/ov-test/.test(html), 'the Test connection button must be rendered');
    assert(/probe-banner/.test(html), 'a failed discovery must render its banner');
    assert(/SSH access/.test(html), 'the SSH section must be rendered');
    assert(/gre status timed out/.test(html), 'the exact failure reason must be shown');
  });

  check('a healthy server renders without a banner and without throwing', () => {
    const app = loadApp();
    const html = app.renderWith(serverFixture());
    assert(html.length > 0);
    assert(!/probe-banner/.test(html), 'no banner when both axes are healthy');
  });

  check('a server that has never been discovered renders TOPOLOGY UNKNOWN, not blank', () => {
    const server = serverFixture({ snapshot: null, probe: { health: HEALTHY, discovery: { ok: null } } });
    const app = loadApp();
    const html = app.renderWith(server);
    assert(/TOPOLOGY UNKNOWN/.test(html), `expected an explicit unknown topology, got: ${html.slice(0, 240)}`);
    assert(/ov-discover/.test(html), 'and it must still offer Run discovery');
  });

  check('the legacy failed-probe snapshot renders honestly', () => {
    const server = serverFixture({
      snapshot: { roles: [], error: 'command timed out after 60000ms', taken_at: new Date().toISOString() },
      probe: { health: HEALTHY, discovery: DISC_FAILED },
    });
    const app = loadApp();
    const html = app.renderWith(server);
    assert(/No authoritative snapshot/.test(html), 'the legacy shape must be explained');
    assert(/command timed out/.test(html), 'and its recorded error shown');
  });

  console.log('\nTEST 2 — the drawer reads the current server:');

  check('renderOverview reads the drawer local, so the probe banner cannot be skipped', () => {
    const start = appSource.indexOf('function renderOverview');
    let depth = 0;
    let i = appSource.indexOf('{', start);
    let end = i;
    for (; i < appSource.length; i += 1) {
      if (appSource[i] === '{') depth += 1;
      else if (appSource[i] === '}') { depth -= 1; if (depth === 0) { end = i; break; } }
    }
    const body = appSource.slice(start, end);
    assert(/const s = state\.current/.test(body), 'renderOverview must bind its local `s`');
    assert(/const drawerProbe = s\.probe/.test(body), 'the probe must come from `s`, not an undefined `server`');
    assert(/el\.innerHTML\s*=/.test(body), 'renderOverview must assign its innerHTML');
  });

  console.log('\nTEST 3/4 — drawer discovery response handling:');

  check('a success envelope yields data.snapshot, and syncs the list row', () => {
    const server = { id: 1, snapshot: null };
    const servers = [server];
    const data = {
      ok: true,
      snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString() },
      probe: { health: HEALTHY, discovery: { ok: true } },
    };
    const result = responses.apply(server, data, servers);
    assert.equal(result.ok, true);
    assert.deepEqual(server.snapshot.roles, ['FOREIGN']);
    assert.deepEqual(servers[0].snapshot.roles, ['FOREIGN']);
    assert.equal(server.probe.health.ok, true);
  });

  check('a failure envelope preserves the last good snapshot and never becomes one', () => {
    const previous = { roles: ['FOREIGN'], taken_at: new Date().toISOString() };
    const server = { id: 2, snapshot: previous };
    const data = { ok: false, error: 'gre status timed out', probe: { health: HEALTHY, discovery: DISC_FAILED }, snapshot: previous };
    const result = responses.apply(server, data, [server]);
    assert.equal(result.ok, false);
    assert.equal(server.snapshot, previous, 'the snapshot object must not be replaced');
    assert.deepEqual(server.snapshot.roles, ['FOREIGN']);
    assert.equal(server.probe.discovery.ok, false, 'the discovery failure must be recorded');
    assert.equal(result.reason, 'gre status timed out');
    assert.equal(server.snapshot.ok, undefined, 'the envelope leaked into the snapshot');
    assert.equal(server.snapshot.probe, undefined, 'the envelope leaked into the snapshot');
  });

  check('a legacy flat snapshot is still accepted', () => {
    const server = { id: 3, snapshot: null };
    const legacy = { roles: ['IRAN'], taken_at: new Date().toISOString(), manager: { installed: true } };
    const result = responses.apply(server, legacy, [server]);
    assert.equal(result.verdict, false);
    assert.equal(result.ok, true);
    assert.deepEqual(server.snapshot.roles, ['IRAN']);
  });

  check('the card and the drawer share one implementation', () => {
    assert(/window\.DiscoveryResponse/.test(appSource), 'app.js must consume the shared response module');
    assert(/applyDiscoverResult\(server, data\)/.test(appSource), 'the card handler must use the shared helper');
    assert(/applyDiscoverResult\(s, data\)/.test(appSource), 'the drawer handler must use the shared helper');
    assert(!/s\.snapshot = snap;/.test(appSource), 'the unsafe direct assignment must be gone');
  });

  console.log('\nTEST 5/6/7 — gre status outcomes are classified, not assumed:');

  function probeBody({ statusRaw = '', statusRc = 0, statusErr = '' } = {}) {
    return [
      '@@BEGIN gre@@', 'installed=1', 'gre-manager v2.8.2', `status_rc=${statusRc}`,
      '@@BEGIN status_json@@', statusRaw, '@@END status_json@@',
      '@@BEGIN status_stderr@@', statusErr, '@@END status_stderr@@',
      '@@END gre@@', '@@BEGIN tunnels@@', '@@END tunnels@@',
      '@@BEGIN managed_tuns@@', '@@END managed_tuns@@',
      '@@BEGIN legacy@@', '@@END legacy@@', '',
    ].join('\n');
  }

  check('gre status timeout is a discovery FAILURE naming the timeout', () => {
    const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ statusRc: 124 }), stderr: '' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.errorClass, 'timeout');
    assert(/timed out/i.test(verdict.reason), verdict.reason);
  });

  check('gre installed with empty status output is a FAILURE', () => {
    const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ statusRaw: '', statusRc: 0 }), stderr: '' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.errorClass, 'malformed');
  });

  check('gre installed with malformed status JSON is a FAILURE', () => {
    const verdict = discovery.classifyProbeResult({ rc: 0, stdout: probeBody({ statusRaw: '{oops', statusRc: 0 }), stderr: '' });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.errorClass, 'malformed');
  });

  console.log('\nTEST 8 — older status schemas still yield roles:');

  check('roles, role, mode and topology evidence are all understood', () => {
    assert.deepEqual(discovery.extractRoles({ roles: ['IRAN'] }).roles, ['IRAN']);
    assert.deepEqual(discovery.extractRoles({ role: 'foreign' }).roles, ['FOREIGN']);
    assert.deepEqual(discovery.extractRoles({ mode: 'IRAN' }).roles, ['IRAN']);
    assert.deepEqual(discovery.extractRoles({ role: 'both' }).roles.sort(), ['FOREIGN', 'IRAN']);
    assert.deepEqual(discovery.extractRoles({ is_iran: true }).roles, ['IRAN']);
    assert.deepEqual(discovery.extractRoles({ nodes: [{}] }).roles, ['FOREIGN']);
    assert.deepEqual(discovery.extractRoles({ iran_peers: [{}] }).roles, ['IRAN']);
    assert.deepEqual(discovery.extractRoles({ foreign_ip: '1.2.3.4' }).roles, ['FOREIGN']);
    assert.deepEqual(discovery.extractRoles(null).roles, []);
    assert(discovery.extractRoles({ role: 'both' }).evidence.length, 'the evidence used must be reported');
  });

  console.log('\nTEST 9 — a health success cannot erase a discovery failure:');

  check('the two axes are independent in the model', () => {
    const server = {
      snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString() },
      probe: { health: HEALTHY, discovery: DISC_FAILED },
    };
    assert.equal(topology.healthState(server), 'healthy');
    assert.equal(topology.discoveryState(server), 'failed');
    assert.equal(topology.roleGroup(server), 'foreign');
    assert.equal(topology.healthLabel(server), 'SSH HEALTHY');
    assert.equal(topology.discoveryLabel(server), 'DISCOVERY FAILED');
  });

  check('the probe writer branches so one axis cannot clear the other', () => {
    const routes = fs.readFileSync(path.join(__dirname, '..', 'server', 'routes.js'), 'utf8');
    assert(/health_ok=/.test(routes) && /discovery_ok=/.test(routes),
      'health and discovery must be written to separate columns');
    assert(/kind === 'health'/.test(routes), 'the writer must branch on the probe kind');
  });

  check('the migration adds the split columns additively', () => {
    const db = fs.readFileSync(path.join(__dirname, '..', 'server', 'db.js'), 'utf8');
    for (const col of ['health_ok', 'health_checked_at', 'discovery_ok', 'discovery_checked_at',
      'discovery_error_class', 'discovery_error_message']) {
      assert(new RegExp(`ensureColumn\\(db, 'server_probe_state', '${col}'`).test(db),
        `missing additive migration for ${col}`);
    }
    assert(/CREATE TABLE IF NOT EXISTS server_probe_state/.test(db), 'the base table must stay');
  });

  console.log('\nTEST 10 — NO MANAGER only from a successful discovery:');

  check('a failed probe never claims the manager is absent', () => {
    const failed = discovery.classifyProbeResult({ rc: -1, stdout: '', stderr: 'command timed out' });
    assert.equal(failed.ok, false);
    assert(!failed.snapshot, 'a failure must not produce a snapshot at all');

    const absent = discovery.classifyProbeResult({
      rc: 0,
      stdout: ['@@BEGIN gre@@', 'installed=0', '@@END gre@@', '@@BEGIN tunnels@@', '@@END tunnels@@',
        '@@BEGIN managed_tuns@@', '@@END managed_tuns@@', '@@BEGIN legacy@@', '@@END legacy@@', ''].join('\n'),
      stderr: '',
    });
    assert.equal(absent.ok, true, 'a completed probe may legitimately report absence');
    assert.equal(absent.snapshot.manager.installed, false);
    assert.deepEqual(absent.snapshot.roles, []);
  });

  console.log('\nTEST 11 — one SSH operation per server:');

  check('health and discovery share a queue key so they cannot overlap', () => {
    const routes = fs.readFileSync(path.join(__dirname, '..', 'server', 'routes.js'), 'utf8');
    assert(/discoveryQueue\.run\(row\.id/.test(routes), 'full discovery must key on the server id');
    assert(!/discoveryQueue\.run\(`health:/.test(routes), 'health must not use a different key');
    assert(/if \(isBusy\(row\.id\)\)/.test(routes), 'a health probe must skip a server being discovered');
  });

  console.log('\nTEST 12 — topology survives a discovery timeout:');

  check('a FOREIGN server stays FOREIGN when the status read times out', () => {
    const previous = { roles: ['FOREIGN'], taken_at: new Date().toISOString(), manager: { installed: true } };
    const server = { id: 9, snapshot: previous };
    responses.apply(server, {
      ok: false, error: 'gre status --json timed out after 15s',
      probe: { health: HEALTHY, discovery: DISC_FAILED }, snapshot: previous,
    }, [server]);
    assert.equal(topology.roleGroup(server), 'foreign');
    assert.equal(topology.discoveryState(server), 'failed');
    assert.equal(topology.healthState(server), 'healthy');
  });

  console.log('\nTEST 13 — a successful rediscovery restores a lost role:');

  check('a historical failed-probe snapshot is replaced by a real one', () => {
    const broken = { roles: [], error: 'command timed out after 60000ms', taken_at: new Date().toISOString() };
    const server = { id: 11, snapshot: broken };
    assert.equal(topology.roleGroup(server), 'unconfigured', 'the legacy snapshot shows as unconfigured');
    responses.apply(server, {
      ok: true,
      snapshot: { roles: ['FOREIGN'], taken_at: new Date().toISOString(), manager: { installed: true } },
      probe: { health: HEALTHY, discovery: { ok: true } },
    }, [server]);
    assert.equal(topology.roleGroup(server), 'foreign', 'a successful rediscovery must restore the role');
    assert.equal(server.snapshot.error, undefined, 'the stale error must be gone');
  });

  report('overview + discovery regression tests');
}

main();
