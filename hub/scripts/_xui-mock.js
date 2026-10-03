'use strict';
// _xui-mock.js — a behavioural fake of a 3x-ui panel used by the hub test
// suite. It models the parts of upstream that gre-manager actually depends on,
// including the difference that caused the real "Duplicate email" bug:
//
//   * embedded panels keep client credentials inside each inbound's
//     settings.clients array and enforce a GLOBAL email uniqueness rule;
//   * first-class panels keep one client row per email plus attachment rows,
//     expose /panel/api/clients/* and reject a second /clients/add for an
//     email that already exists.
//
// Fixtures are also exposed as plain JSON so a test can assert that a mock's
// own behaviour matches what upstream source says (for example that POST
// /panel/api/inbounds/addClient does not exist from v3.1.0 on).

const FIRST_CLASS = 'first_class';
const EMBEDDED = 'embedded';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function ok(obj, msg = '') {
  return json({ success: true, msg, obj });
}

function fail(msg, status = 200) {
  return json({ success: false, msg }, status);
}

function parseBody(opts) {
  if (!opts || !opts.body) return {};
  try { return JSON.parse(opts.body); } catch { return {}; }
}

// Static, source-derived endpoint fixture per release tag.
const VERSION_FIXTURES = {
  '2.8.11': {
    clientModel: EMBEDDED,
    hostsApi: false,
    endpoints: {
      'POST /panel/api/inbounds/addClient': true,
      'POST /panel/api/inbounds/updateClient/:clientId': true,
      'POST /panel/api/inbounds/:id/delClient/:clientId': true,
      'GET /panel/api/inbounds/getClientLinks/:id/:email': false,
      'GET /panel/api/inbounds/get/:id': true,
      'POST /panel/api/inbounds/add': true,
      'GET /panel/api/inbounds/list': true,
      'GET /panel/api/hosts/list': false,
      'GET /panel/api/clients/list': false,
      'POST /panel/api/clients/add': false,
      'POST /panel/api/clients/:email/attach': false,
      'POST /panel/api/clients/:email/detach': false,
    },
  },
  '3.0.2': {
    clientModel: EMBEDDED,
    hostsApi: false,
    endpoints: {
      'POST /panel/api/inbounds/addClient': true,
      'POST /panel/api/inbounds/updateClient/:clientId': true,
      'POST /panel/api/inbounds/:id/delClient/:clientId': true,
      'GET /panel/api/inbounds/getClientLinks/:id/:email': true,
      'GET /panel/api/inbounds/get/:id': true,
      'POST /panel/api/inbounds/add': true,
      'GET /panel/api/inbounds/list': true,
      'GET /panel/api/hosts/list': false,
      'GET /panel/api/clients/list': false,
      'POST /panel/api/clients/add': false,
      'POST /panel/api/clients/:email/attach': false,
      'POST /panel/api/clients/:email/detach': false,
    },
  },
  '3.1.0': {
    clientModel: FIRST_CLASS,
    hostsApi: false,
    endpoints: {
      'POST /panel/api/inbounds/addClient': false,
      'GET /panel/api/inbounds/get/:id': true,
      'POST /panel/api/inbounds/add': true,
      'GET /panel/api/inbounds/list': true,
      'GET /panel/api/hosts/list': false,
      'GET /panel/api/clients/list': true,
      'GET /panel/api/clients/get/:email': true,
      'GET /panel/api/clients/links/:email': true,
      'POST /panel/api/clients/add': true,
      'POST /panel/api/clients/update/:email': true,
      'POST /panel/api/clients/del/:email': true,
      'POST /panel/api/clients/:email/attach': true,
      'POST /panel/api/clients/:email/detach': true,
    },
  },
  '3.8.0': {
    clientModel: FIRST_CLASS,
    hostsApi: true,
    endpoints: {
      'POST /panel/api/inbounds/addClient': false,
      'GET /panel/api/inbounds/get/:id': true,
      'POST /panel/api/inbounds/add': true,
      'GET /panel/api/inbounds/list': true,
      'GET /panel/api/hosts/list': true,
      'POST /panel/api/hosts/add': true,
      'GET /panel/api/clients/list': true,
      'GET /panel/api/clients/get/:email': true,
      'GET /panel/api/clients/links/:email': true,
      'POST /panel/api/clients/add': true,
      'POST /panel/api/clients/del/:email': true,
      'POST /panel/api/clients/:email/attach': true,
      'POST /panel/api/clients/:email/detach': true,
    },
  },
};

// A panel whose auth layer rejects every request with the given status.
function brokenPanel(status) {
  return {
    calls: [],
    fetchImpl: async (url) => {
      if (String(url).endsWith('/csrf-token')) return json({ success: false }, 404);
      if (String(url).endsWith('/login')) return json({ success: true }, 200, { 'set-cookie': '3x-ui=s; Path=/' });
      return json({ success: false, msg: `HTTP ${status}` }, status);
    },
  };
}

function hangingPanel({ timeoutMs = 30 } = {}) {
  return {
    calls: [],
    fetchImpl: (url, opts = {}) => new Promise((resolve, reject) => {
      const signal = opts.signal;
      if (!signal) return; // never resolves on purpose
      const onAbort = () => {
        const err = new Error('The operation was aborted due to timeout');
        err.name = 'TimeoutError';
        reject(err);
      };
      if (signal.aborted) return onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
      setTimeout(() => { if (!signal.aborted) reject(new Error('mock timeout')); }, timeoutMs);
      return undefined;
    }),
  };
}

/**
 * Build a fake panel.
 *
 * @param {object} options
 * @param {'first_class'|'embedded'} options.clientModel
 * @param {boolean} options.hostsApi        expose /panel/api/hosts/*
 * @param {string}  options.host            public host the panel emits in links
 * @param {Array}   options.clients         seed clients: { email, password?, method? }
 * @param {Array}   options.inbounds        seed inbounds: { id, port, remark, protocol, clients }
 * @param {number}  options.linkDelayMs     delay links until attach/create settles
 */
function makeMockPanel(options = {}) {
  const clientModel = options.clientModel === FIRST_CLASS ? FIRST_CLASS : EMBEDDED;
  const hostname = options.host || '37.202.247.77';
  let hostsApi = !!options.hostsApi;
  // Panel version reporting: the API route exists from 3.0 on; older panels
  // only expose the version in their authenticated HTML.
  const panelVersion = options.panelVersion || '3.8.0';
  const reportVersionViaApi = options.reportVersionViaApi !== false;
  const htmlVersion = options.htmlVersion || null;
  const linkDelayMs = Number(options.linkDelayMs ?? 0);
  const linksPaused = { value: linkDelayMs > 0 };
  // Set false to model a panel that predates /clients/list/paged.
  const pagedClients = options.pagedClients !== false;

  const state = {
    nextInboundId: 100,
    nextClientRowId: 1,
    inbounds: [],
    // first-class client rows: { id, email, password, method, inboundIds: [] }
    clientRows: [],
    hosts: new Map(),
  };

  for (const inbound of options.inbounds || []) {
    state.inbounds.push({
      id: Number(inbound.id),
      port: Number(inbound.port),
      remark: String(inbound.remark || ''),
      protocol: String(inbound.protocol || 'shadowsocks'),
      settings: { clients: (inbound.clients || []).map((c) => ({ ...c })) },
    });
    state.nextInboundId = Math.max(state.nextInboundId, Number(inbound.id) + 1);
  }
  for (const client of options.clients || []) {
    state.clientRows.push({
      id: state.nextClientRowId++,
      email: String(client.email),
      password: String(client.password || ''),
      method: String(client.method || 'chacha20-ietf-poly1305'),
      inboundIds: (client.inboundIds || []).map(Number),
    });
  }

  const calls = [];
  const errors = [];

  const findInbound = (id) => state.inbounds.find((item) => Number(item.id) === Number(id));
  const findClient = (email) => state.clientRows.find((row) => row.email === String(email));

  function settingsClientsFor(clientRow) {
    return {
      email: clientRow.email,
      password: clientRow.password,
      method: clientRow.method,
      enable: true,
      limitIp: 0,
      totalGB: 0,
      expiryTime: 0,
    };
  }

  function record(url, opts) {
    const method = String((opts && opts.method) || 'GET').toUpperCase();
    const parsed = new URL(String(url));
    const entry = { url: String(url), path: parsed.pathname, method, body: parseBody(opts) };
    calls.push(entry);
    return entry;
  }

  function callsTo(fragment) {
    // Exact path OR exact path with a query string; avoids '/inbounds/add'
    // accidentally matching '/inbounds/addClient'.
    return calls.filter((call) => call.path === fragment || call.path.startsWith(`${fragment}/`));
  }

  function callsMatching(regex) {
    return calls.filter((call) => regex.test(call.path));
  }

  // Resolve a link the way upstream does for the inbound the client is on.
  function linksFor(email) {
    const row = findClient(email);
    if (!row) return [];
    const links = [];
    for (const inboundId of row.inboundIds) {
      const inbound = findInbound(inboundId);
      if (!inbound) continue;
      const auth = Buffer.from(`${row.method}:${row.password}`).toString('base64');
      links.push(`ss://${auth}@${hostname}:${inbound.port}#${encodeURIComponent(inbound.remark)}`);
    }
    return links;
  }

  const fetchImpl = async (url, opts = {}) => {
    const call = record(url, opts);
    const path = call.path;
    const lower = path;
    const query = new URL(String(url)).searchParams;

    // --- auth ---------------------------------------------------------
    if (lower === '/csrf-token') return json({ success: false }, 404);
    if (lower === '/login') return json({ success: true }, 200, { 'set-cookie': '3x-ui=session; Path=/' });

    // --- panel version diagnostics ------------------------------------
    if (lower === '/panel/api/server/getPanelUpdateInfo') {
      if (!reportVersionViaApi) return fail('update check unavailable');
      return ok({ currentVersion: panelVersion, latestVersion: panelVersion, updateAvailable: false });
    }
    // The authenticated index page, used only by the HTML version fallback.
    if (lower === '/' || lower === '/index.html' || lower === '/panel' || lower === '/panel/') {
      const title = htmlVersion ? `<title>3x-ui v${htmlVersion}</title>` : '<title>3x-ui</title>';
      return new Response(`<!doctype html><html><head>${title}</head><body>Xray 25.9.11<div id="app"></div></body></html>`,
        { status: 200, headers: { 'content-type': 'text/html' } });
    }

    // --- capability probes -------------------------------------------
    if (lower === '/panel/api/hosts/list') {
      return hostsApi ? ok([]) : json({ msg: 'not found' }, 404);
    }
    if (lower === '/panel/api/clients/list') {
      if (clientModel !== FIRST_CLASS) return json({ msg: 'not found' }, 404);
      return ok(state.clientRows.map((row) => ({
        id: row.id,
        email: row.email,
        password: row.password,
        method: row.method,
        inboundIds: [...row.inboundIds],
      })));
    }
    // Lightweight paged search (3x-ui v3.7). Returns the ClientSlim projection:
    // no password/auth/flow, just what a picker needs. `pagedClients: false`
    // models an older panel that only has the full listing.
    if (lower === '/panel/api/clients/list/paged') {
      if (clientModel !== FIRST_CLASS || pagedClients === false) return json({ msg: 'not found' }, 404);
      const page = Math.max(Number(query.get('page') || 1), 1);
      const size = Math.min(Math.max(Number(query.get('pageSize') || 20), 1), 200);
      const term = String(query.get('search') || '').trim().toLowerCase();
      const matched = term
        ? state.clientRows.filter((row) => String(row.email).toLowerCase().includes(term))
        : state.clientRows.slice();
      const start = (page - 1) * size;
      return ok({
        items: matched.slice(start, start + size).map((row) => ({
          id: row.id,
          email: row.email,
          method: row.method,
          inboundIds: [...row.inboundIds],
        })),
        total: matched.length,
        page,
        pageSize: size,
      });
    }

    // --- inbounds -----------------------------------------------------
    // Metadata-only projections. These exist so the client picker never has to
    // pull /inbounds/list (which serializes every inbound's full settings blob).
    if (lower === '/panel/api/inbounds/list/slim' || lower === '/panel/api/inbounds/options') {
      return ok(state.inbounds.map((inbound) => ({
        id: inbound.id,
        port: inbound.port,
        remark: inbound.remark,
        protocol: inbound.protocol,
      })));
    }
    if (lower === '/panel/api/inbounds/list') {
      return ok(state.inbounds.map((inbound) => ({
        id: inbound.id,
        port: inbound.port,
        remark: inbound.remark,
        protocol: inbound.protocol,
        settings: JSON.stringify(inbound.settings),
      })));
    }
    const getInbound = lower.match(/^\/panel\/api\/inbounds\/get\/(\d+)$/);
    if (getInbound) {
      const inbound = findInbound(Number(getInbound[1]));
      if (!inbound) return fail('record not found');
      // Upstream GetInboundDetail returns one full inbound and keeps the full
      // settings.clients[] objects. Return a detached copy so a caller cannot
      // mutate panel state through the mock response object.
      return ok({
        id: inbound.id,
        port: inbound.port,
        remark: inbound.remark,
        protocol: inbound.protocol,
        settings: JSON.stringify({
          ...inbound.settings,
          clients: (inbound.settings.clients || []).map((client) => ({ ...client })),
        }),
      });
    }
    if (lower === '/panel/api/inbounds/add') {
      const payload = call.body || {};
      let settings;
      try { settings = JSON.parse(payload.settings || '{}'); } catch { settings = {}; }
      const embedded = Array.isArray(settings.clients) ? settings.clients : [];
      // Email uniqueness across inbounds only exists from v3.1.0 on. There,
      // InboundService.checkEmailsExistForClients unions the global clients
      // table with every inbound's settings.clients and rejects any email that
      // already appears — even an unattached global client. That is precisely
      // what produced "Duplicate email: navid" when gre-manager re-created a
      // client the panel already owned. 2.8.x and 3.0.x have no such check, so
      // one embedded identity can be cloned onto a second inbound there.
      for (const candidate of embedded) {
        const elsewhere = clientModel === FIRST_CLASS && (
          state.clientRows.some((row) => row.email === candidate.email) ||
          state.inbounds.some((inbound) => (inbound.settings.clients || []).some((c) => c.email === candidate.email))
        );
        if (elsewhere) {
          errors.push(`Duplicate email: ${candidate.email}`);
          return fail(`something went wrong (Duplicate email: ${candidate.email})`);
        }
      }
      const inbound = {
        id: state.nextInboundId++,
        port: Number(payload.port),
        remark: String(payload.remark || ''),
        protocol: String(payload.protocol || 'shadowsocks'),
        method: settings.method,
        settings: { ...settings, clients: embedded.map((c) => ({ ...c })) },
      };
      state.inbounds.push(inbound);
      if (settings.password) inbound.password = settings.password;
      return ok({ id: inbound.id });
    }
    const delInbound = lower.match(/^\/panel\/api\/inbounds\/del\/(\d+)$/);
    if (delInbound) {
      const id = Number(delInbound[1]);
      state.inbounds = state.inbounds.filter((item) => Number(item.id) !== id);
      for (const row of state.clientRows) row.inboundIds = row.inboundIds.filter((x) => x !== id);
      return ok(id);
    }
    const legacyAddClient = lower.match(/^\/panel\/api\/inbounds\/addClient$/);
    if (legacyAddClient && clientModel === EMBEDDED) {
      return ok(null, 'client added');
    }

    // --- legacy per-inbound client links ------------------------------
    const legacyLinks = lower.match(/^\/panel\/api\/inbounds\/getClientLinks\/(\d+)\/(.+)$/);
    if (legacyLinks) {
      if (clientModel === FIRST_CLASS) return json({ msg: 'not found' }, 404);
      const inboundId = Number(legacyLinks[1]);
      const email = decodeURIComponent(legacyLinks[2]);
      const inbound = findInbound(inboundId);
      if (!inbound) return fail('record not found');
      const client = (inbound.settings.clients || []).find((c) => c.email === email);
      if (!client) return fail('record not found');
      const auth = Buffer.from(`${client.method || inbound.method}:${client.password}`).toString('base64');
      return ok([`ss://${auth}@${hostname}:${inbound.port}#${encodeURIComponent(inbound.remark)}`]);
    }

    // --- hosts --------------------------------------------------------
    if (lower === '/panel/api/hosts/add') {
      if (!hostsApi) return json({ msg: 'not found' }, 404);
      const groupId = `host-group-${state.hosts.size + 1}`;
      state.hosts.set(groupId, call.body);
      return ok({ groupId });
    }
    const delHost = lower.match(/^\/panel\/api\/hosts\/del\/(.+)$/);
    if (delHost) {
      state.hosts.delete(decodeURIComponent(delHost[1]));
      return ok(null);
    }

    // --- first-class clients -----------------------------------------
    if (lower.startsWith('/panel/api/clients/')) {
      if (clientModel !== FIRST_CLASS) return json({ msg: 'not found' }, 404);

      if (lower === '/panel/api/clients/add') {
        const payload = call.body || {};
        const client = payload.client || {};
        if (!client.email) return fail('client email is required');
        if (findClient(client.email)) {
          // Upstream message for a second create of the same email.
          errors.push(`email already in use: ${client.email}`);
          return fail(`something went wrong (email already in use: ${client.email})`);
        }
        const row = {
          id: state.nextClientRowId++,
          email: String(client.email),
          password: String(client.password || 'generated-by-panel'),
          method: String(client.method || 'chacha20-ietf-poly1305'),
          inboundIds: [],
        };
        state.clientRows.push(row);
        for (const inboundId of (payload.inboundIds || []).map(Number)) {
          const inbound = findInbound(inboundId);
          if (!inbound) return fail('record not found');
          row.inboundIds.push(inboundId);
          inbound.settings.clients = [...(inbound.settings.clients || []), settingsClientsFor(row)];
        }
        if (linksPaused.value) setTimeout(() => { linksPaused.value = false; }, linkDelayMs);
        return ok(null, 'client added');
      }

      const getMatch = lower.match(/^\/panel\/api\/clients\/get\/(.+)$/);
      if (getMatch) {
        const email = decodeURIComponent(getMatch[1]);
        const row = findClient(email);
        if (!row) return fail('record not found');
        return ok({
          client: {
            id: row.id,
            email: row.email,
            password: row.password,
            method: row.method,
            enable: true,
            inboundIds: [...row.inboundIds],
          },
          inboundIds: [...row.inboundIds],
        });
      }

      const linksMatch = lower.match(/^\/panel\/api\/clients\/links\/(.+)$/);
      if (linksMatch) {
        const email = decodeURIComponent(linksMatch[1]);
        if (linksPaused.value) return ok([]);
        const links = linksFor(email);
        if (!links.length) return fail('record not found');
        return ok(links);
      }

      const attachMatch = lower.match(/^\/panel\/api\/clients\/(.+)\/attach$/);
      if (attachMatch) {
        const email = decodeURIComponent(attachMatch[1]);
        const row = findClient(email);
        if (!row) return fail('record not found');
        for (const inboundId of (call.body.inboundIds || []).map(Number)) {
          const inbound = findInbound(inboundId);
          if (!inbound) return fail('record not found');
          if (row.inboundIds.includes(inboundId)) continue;
          // Upstream refuses when this inbound already embeds that email.
          if ((inbound.settings.clients || []).some((c) => c.email === email)) {
            errors.push(`Duplicate email: ${email}`);
            return fail(`something went wrong (Duplicate email: ${email})`);
          }
          row.inboundIds.push(inboundId);
          inbound.settings.clients = [...(inbound.settings.clients || []), settingsClientsFor(row)];
        }
        if (linksPaused.value) setTimeout(() => { linksPaused.value = false; }, linkDelayMs);
        return ok(null, 'attached');
      }

      const detachMatch = lower.match(/^\/panel\/api\/clients\/(.+)\/detach$/);
      if (detachMatch) {
        const email = decodeURIComponent(detachMatch[1]);
        const row = findClient(email);
        if (!row) return fail('record not found');
        for (const inboundId of (call.body.inboundIds || []).map(Number)) {
          row.inboundIds = row.inboundIds.filter((x) => x !== inboundId);
          const inbound = findInbound(inboundId);
          if (inbound) inbound.settings.clients = (inbound.settings.clients || []).filter((c) => c.email !== email);
        }
        return ok(null, 'detached');
      }

      const delMatch = lower.match(/^\/panel\/api\/clients\/del\/(.+)$/);
      if (delMatch) {
        const email = decodeURIComponent(delMatch[1]);
        const row = findClient(email);
        if (!row) return fail('record not found');
        for (const inboundId of [...row.inboundIds]) {
          const inbound = findInbound(inboundId);
          if (inbound) inbound.settings.clients = (inbound.settings.clients || []).filter((c) => c.email !== email);
        }
        state.clientRows = state.clientRows.filter((item) => item.email !== email);
        return ok(null, 'deleted');
      }
    }

    throw new Error(`mock panel: unexpected request ${call.method} ${path}`);
  };

  return {
    clientModel,
    hostname,
    fetchImpl,
    calls,
    errors,
    callsTo,
    callsMatching,
    state,
    // Mutable capability knob so a harness can flip a panel's behaviour
    // without rebuilding (and losing) its accumulated state.
    get hostsApiEnabled() { return hostsApi; },
    set hostsApiEnabled(value) { hostsApi = !!value; },
    findClient,
    findInbound,
    linksFor,
    createCalls: () => callsTo('/panel/api/clients/add'),
    attachCalls: () => callsMatching(/\/attach$/),
    detachCalls: () => callsMatching(/\/detach$/),
    deleteCalls: () => callsMatching(/^\/panel\/api\/clients\/del\//),
    inboundAddCalls: () => callsTo('/panel/api/inbounds/add'),
  };
}

module.exports = { makeMockPanel, brokenPanel, hangingPanel, VERSION_FIXTURES, FIRST_CLASS, EMBEDDED, json, ok, fail };
