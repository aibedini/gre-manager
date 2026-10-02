'use strict';

const crypto = require('crypto');
const QRCode = require('qrcode');
const ssh = require('./ssh');
const actions = require('./actions');
const {
  XuiClient, parseShadowsocksLink, buildShadowsocksLink, selectShadowsocksLink, isValidShadowsocksPassword,
} = require('./xui');
const { encrypt, decrypt } = require('./crypto');

const DEFAULT_RANGE = [3000, 3999];
const AVOID_PORTS = new Set([22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2053, 3000, 3306, 5432, 6379, 8080, 8443]);
const ROUTE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$/;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const SS_METHODS = ['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm'];
const CLIENT_MODES = new Set(['existing', 'new']);
const EMAIL_RE = /^[^\s@]{1,80}$/;

// A RESERVED route that is older than this was almost certainly abandoned by a
// hub process that died mid-provisioning; it is surfaced for review, never
// auto-destroyed, because the real remote state is unknown.
const ABANDONED_RESERVED_MS = 15 * 60 * 1000;
const EVENT_WAITERS_MS = 30000;
// Provisioning keeps the request handler free; this is the hard ceiling on a
// single route run before the promise is considered hung.
const RUN_TIMEOUT_MS = 15 * 60 * 1000;

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function securePassword(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// ShadowSocks client keys are cipher-length base64, not arbitrary passwords:
// upstream silently replaces anything else, which would break the credential
// we hand back to the user.
function shadowsocksClientPassword(method) {
  const size = method === 'aes-128-gcm' ? 16 : 32;
  return crypto.randomBytes(size).toString('base64');
}

function peerName(routeName) {
  const clean = String(routeName).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const hash = crypto.createHash('sha256').update(routeName).digest('hex').slice(0, 4);
  return `${clean.slice(0, 6)}-${hash}`.slice(0, 11);
}

function probeCommand() {
  return [
    "echo '---listeners---'", 'ss -H -lntup 2>/dev/null || true',
    "echo '---nft---'", 'nft list ruleset 2>/dev/null || true',
    "echo '---iptables---'", 'iptables-save 2>/dev/null || true',
    "echo '---docker---'", "docker ps --format '{{.Ports}}' 2>/dev/null || true",
  ].join('; ');
}

function portEvidence(output, port) {
  const p = String(port);
  const patterns = [
    new RegExp(`(?:\\]|\\.|:|\\s)${p}(?:\\s|$|[-/,])`),
    new RegExp(`(?:dport|sport|dports|sports)\\s+(?:\\{[^}]*\\b)?${p}\\b`),
    new RegExp(`(?:--dport|--sport)\\s+${p}\\b`),
  ];
  return String(output || '').split(/\r?\n/).filter((line) => patterns.some((re) => re.test(line))).slice(0, 20);
}

function validatePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('port must be an integer 1024-65535');
  return port;
}

function parseSuggestion(output) {
  let value;
  try { value = JSON.parse(String(output || '').trim()); } catch { throw new Error('remote gre returned invalid suggestion JSON; update gre on both servers'); }
  const item = Array.isArray(value) ? value[0] : (Array.isArray(value.suggestions) ? value.suggestions[0] : value);
  if (!item || !item.name || !item.subnet_base || !Number.isInteger(Number(item.idx)) || !item.key) {
    throw new Error('remote gre returned an incomplete pairing suggestion; update gre on both servers');
  }
  return { name: String(item.name), subnet_base: String(item.subnet_base), idx: Number(item.idx), key: String(item.key) };
}

// Resolve the client intent from a request body. The explicit contract is
// client_mode + client_email; client_name is accepted only so an older
// frontend keeps working (it meant "new client" back then).
function parseClientIntent(body = {}) {
  const explicitMode = body.client_mode === undefined || body.client_mode === null || body.client_mode === ''
    ? null
    : String(body.client_mode);
  if (explicitMode && !CLIENT_MODES.has(explicitMode)) {
    throw new Error('client_mode must be one of: existing, new');
  }
  const clientEmail = String(
    body.client_email !== undefined && body.client_email !== null && body.client_email !== ''
      ? body.client_email
      : (body.clientName !== undefined && body.clientName !== null && body.clientName !== ''
        ? body.clientName
        : (body.client_name || ''))
  ).trim();
  const clientMode = explicitMode || 'new';
  if (!clientEmail) throw new Error('a 3x-ui client email is required');
  if (!EMAIL_RE.test(clientEmail)) throw new Error('client email must be 1-80 characters with no whitespace');
  return { clientMode, clientEmail };
}

function inboundPayload({ remark, port, method, inboundPassword, clients = [], externalProxy }) {
  const settings = {
    method,
    password: inboundPassword,
    network: 'tcp,udp',
    clients: Array.isArray(clients) ? clients : [],
  };
  const streamSettings = { network: 'tcp', security: 'none' };
  if (externalProxy) {
    streamSettings.externalProxy = [{ forceTls: 'same', dest: externalProxy.host, port: externalProxy.port, remark: '' }];
  }
  return {
    enable: true,
    remark,
    listen: '',
    port,
    protocol: 'shadowsocks',
    settings: JSON.stringify(settings),
    streamSettings: JSON.stringify(streamSettings),
    sniffing: JSON.stringify({ enabled: false, destOverride: ['http', 'tls', 'quic', 'fakedns'] }),
    allocate: JSON.stringify({ strategy: 'always', refresh: 5, concurrency: 3 }),
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class RouteOrchestrator {
  constructor({ db, cryptKey, sshOptsFor, fetchImpl = global.fetch, sshExec = ssh.exec, runTimeoutMs = RUN_TIMEOUT_MS }) {    this.db = db;
    this.cryptKey = cryptKey;
    this.sshOptsFor = sshOptsFor;
    this.fetchImpl = fetchImpl;
    this.sshExec = sshExec;
    this.runTimeoutMs = runTimeoutMs;
    // route_id -> Set(resolve) for long-poll / SSE-style incremental event reads.
    this.eventWaiters = new Map();
  }

  server(id) {
    const row = this.db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
    if (!row) throw new Error(`server ${id} not found`);
    return row;
  }

  panel(id) {
    const row = this.db.prepare('SELECT * FROM xui_panels WHERE id = ?').get(id);
    if (!row) throw new Error(`3x-ui panel ${id} not found`);
    return row;
  }

  secret(server) {
    return server.secret_enc ? decrypt(this.cryptKey, server.secret_enc) : '';
  }

  client(panel) {
    const credential = decrypt(this.cryptKey, panel.password_enc);
    return new XuiClient({
      baseUrl: panel.base_url,
      authType: panel.auth_type || 'password',
      username: panel.username,
      password: panel.auth_type === 'token' ? '' : credential,
      token: panel.auth_type === 'token' ? credential : '',
      fetchImpl: this.fetchImpl,
    });
  }

  async remote(server, command, timeoutMs = 30000) {
    const result = await this.sshExec(server, this.secret(server), command, { timeoutMs, ...this.sshOptsFor(server) });
    if (result.hostkey_mismatch) {
      const err = new Error(`host key mismatch for ${server.name}`);
      err.hostkey_mismatch = true;
      err.presented_fp = result.presented_fp;
      throw err;
    }
    return result;
  }

  async publicIp(server) {
    if (IPV4_RE.test(server.host)) return server.host;
    const result = await this.remote(server,
      'curl -4fsS --max-time 8 https://api.ipify.org || curl -4fsS --max-time 8 https://ifconfig.me/ip');
    const ip = String(result.stdout || '').trim();
    if (result.rc !== 0 || !IPV4_RE.test(ip)) throw new Error(`could not detect public IPv4 for ${server.name}`);
    return ip;
  }

  async collectUsage(iran, foreign, panelClient) {
    const [iranProbe, foreignProbe, inbounds] = await Promise.all([
      this.remote(iran, probeCommand()),
      this.remote(foreign, probeCommand()),
      panelClient.listInbounds(),
    ]);
    if (iranProbe.rc !== 0) throw new Error(`could not inspect ${iran.name}: ${iranProbe.stderr || `rc=${iranProbe.rc}`}`);
    if (foreignProbe.rc !== 0) throw new Error(`could not inspect ${foreign.name}: ${foreignProbe.stderr || `rc=${foreignProbe.rc}`}`);
    return { iranOutput: iranProbe.stdout, foreignOutput: foreignProbe.stdout, inbounds };
  }

  registryConflict(iranId, foreignId, port, excludeRouteId = null) {
    return this.db.prepare(`
      SELECT p.*, r.name AS route_name FROM port_allocations p
      JOIN gre_routes r ON r.id = p.route_id
      WHERE p.status != 'RELEASED' AND p.port = ?
        AND (p.iran_server_id IN (?, ?) OR p.foreign_server_id IN (?, ?))
        AND (? IS NULL OR p.route_id != ?)
      LIMIT 1
    `).get(port, iranId, foreignId, iranId, foreignId, excludeRouteId, excludeRouteId);
  }

  inspectCandidate(usage, iranId, foreignId, port) {
    const iranEvidence = portEvidence(usage.iranOutput, port);
    const foreignEvidence = portEvidence(usage.foreignOutput, port);
    const xui = usage.inbounds.find((item) => Number(item.port) === port);
    const registry = this.registryConflict(iranId, foreignId, port);
    return {
      port,
      free: !registry && !iranEvidence.length && !foreignEvidence.length && !xui,
      tcp: iranEvidence.length || foreignEvidence.length ? 'IN_USE' : 'FREE',
      udp: iranEvidence.length || foreignEvidence.length ? 'IN_USE' : 'FREE',
      xui: xui ? 'IN_USE' : 'FREE',
      gre: registry ? 'IN_USE' : 'FREE',
      evidence: { iran: iranEvidence, foreign: foreignEvidence, inbound: xui && { id: xui.id, remark: xui.remark } },
      conflict_route: registry && registry.route_name,
    };
  }

  async recommend({ iranServerId, foreignServerId, panelId, start = DEFAULT_RANGE[0], end = DEFAULT_RANGE[1], preferredPort }) {
    const iran = this.server(iranServerId);
    const foreign = this.server(foreignServerId);
    const panel = this.panel(panelId);
    const client = this.client(panel);
    start = validatePort(start);
    end = validatePort(end);
    if (start > end || end - start > 10000) throw new Error('invalid or excessively large port range');
    const usage = await this.collectUsage(iran, foreign, client);
    const candidates = [];
    if (preferredPort !== undefined && preferredPort !== null && preferredPort !== '') candidates.push(validatePort(preferredPort));
    for (let p = start; p <= end; p++) if (!AVOID_PORTS.has(p) && !candidates.includes(p)) candidates.push(p);
    const occupied = [];
    let recommendation = null;
    for (const port of candidates) {
      const result = this.inspectCandidate(usage, iran.id, foreign.id, port);
      if (result.free && !recommendation) recommendation = result;
      if (!result.free) occupied.push(port);
    }
    if (recommendation) return { ...recommendation, occupied_ports: occupied, occupied_count: occupied.length };
    throw new Error(`no free TCP+UDP port found in ${start}-${end}`);
  }

  // --- events -------------------------------------------------------------

  event(routeId, stage, status, detail = '') {
    const safe = String(detail || '').replace(/ss:\/\/\S+/gi, '[redacted-link]').slice(0, 4000);
    const info = this.db.prepare('INSERT INTO route_events (route_id, stage, status, detail, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(routeId, stage, status, safe, Date.now());
    // A promise-based waiter is enough for the in-process SSE endpoint and
    // costs nothing when nobody is watching.
    const waiters = this.eventWaiters.get(Number(routeId));
    if (waiters) {
      for (const waiter of [...waiters]) {
        try { waiter(); } catch { /* waiter already gone */ }
      }
    }
    return Number(info.lastInsertRowid);
  }

  events(routeId, afterId = null) {
    const id = Number(routeId);
    if (afterId === null || afterId === undefined || afterId === '') {
      return this.db.prepare('SELECT id, stage, status, detail, created_at FROM route_events WHERE route_id=? ORDER BY id').all(id);
    }
    const after = Number(afterId);
    if (!Number.isFinite(after)) throw new Error('after_id must be a number');
    return this.db.prepare('SELECT id, stage, status, detail, created_at FROM route_events WHERE route_id=? AND id > ? ORDER BY id').all(id, after);
  }

  waitForEvent(routeId, afterId, timeoutMs = EVENT_WAITERS_MS) {
    const key = Number(routeId);
    const immediate = this.events(key, afterId);
    if (immediate.length) return Promise.resolve(immediate);
    return new Promise((resolve) => {
      const waiters = this.eventWaiters.get(key) || new Set();
      this.eventWaiters.set(key, waiters);
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        waiters.delete(onEvent);
        if (!waiters.size) this.eventWaiters.delete(key);
        resolve(this.events(key, afterId));
      };
      const onEvent = () => finish();
      const timer = setTimeout(finish, Math.max(0, Number(timeoutMs) || 0));
      if (typeof timer.unref === 'function') timer.unref();
      waiters.add(onEvent);
    });
  }

  waitersFor(routeId) {
    return this.eventWaiters.get(Number(routeId));
  }

  // --- routes -------------------------------------------------------------

  route(routeId) {
    return this.db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(Number(routeId));
  }

  // Safe single-route view. Secrets are never included here: the share link is
  // only ever served through the explicit reveal path (GET /api/gre-routes
  // ?reveal=1) or the in-memory completed-result path of a run this hub made.
  safeRoute(routeId) {
    const row = this.route(routeId);
    if (!row) return null;
    const { client_password_enc, share_link_enc, ...safe } = row;
    safe.client_model = row.client_model || null;
    safe.client_mode = row.client_mode || null;
    return safe;
  }

  async pairing(iran, foreign) {
    const suggested = await this.remote(iran, 'gre iran peer suggest --json', 30000);
    if (suggested.rc !== 0) throw new Error(`could not allocate GRE pairing values: ${suggested.stderr || suggested.stdout || `rc=${suggested.rc}`}`);
    const pair = parseSuggestion(suggested.stdout);
    const check = await this.remote(foreign, `gre node suggest --json --base ${shellQuote(pair.subnet_base)}`, 30000);
    if (check.rc !== 0) throw new Error(`could not validate GRE allocation on FOREIGN: ${check.stderr || check.stdout || `rc=${check.rc}`}`);
    const foreignPair = parseSuggestion(check.stdout);
    if (foreignPair.idx !== pair.idx || foreignPair.key !== pair.key) {
      throw new Error('IRAN and FOREIGN allocation pools disagree; reconcile existing GRE nodes before retrying');
    }
    return pair;
  }

  reserve(input, port, method, email, clientMode, clientModel) {
    const now = Date.now();
    const tx = this.db.transaction(() => {
      if (this.registryConflict(input.iranServerId, input.foreignServerId, port)) throw new Error(`port ${port} is already reserved in the registry`);
      const result = this.db.prepare(`
        INSERT INTO gre_routes
          (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, client_mode, client_model, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)
      `).run(input.name, input.iranServerId, input.foreignServerId, input.panelId, port, method, email, clientMode, clientModel, now, now);
      const routeId = Number(result.lastInsertRowid);
      this.db.prepare(`
        INSERT INTO port_allocations
          (route_id, iran_server_id, foreign_server_id, port, protocols, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'tcp,udp', 'RESERVED', ?, ?)
      `).run(routeId, input.iranServerId, input.foreignServerId, port, now, now);
      return routeId;
    });
    return tx();
  }

  // ------------------------------------------------------------------
  // Phase 1 — validate everything we can validate read-only, reserve the
  // route row, and hand back a route id. No IRAN/FOREIGN mutation happens
  // here, so a bad client selection never costs a GRE tunnel.
  // ------------------------------------------------------------------

  async prepare(input) {
    const body = input || {};
    if (!ROUTE_NAME_RE.test(String(body.name || ''))) throw new Error('route name must be 1-40 letters, digits, _ or -');
    const iranServerId = Number(body.iranServerId);
    const foreignServerId = Number(body.foreignServerId);
    const panelId = Number(body.panelId);
    const iran = this.server(iranServerId);
    const foreign = this.server(foreignServerId);
    if (iran.id === foreign.id) throw new Error('IRAN and FOREIGN servers must be different');
    const panel = this.panel(panelId);
    const method = body.method || 'chacha20-ietf-poly1305';
    if (!SS_METHODS.includes(method)) throw new Error('unsupported Shadowsocks method');
    const { clientMode, clientEmail } = parseClientIntent(body);
    const client = this.client(panel);

    const capabilities = await client.resolveCapabilities();
    const clientModel = capabilities.clientModel;

    // Preflight the client BEFORE any mutation. For a first-class panel we can
    // ask the panel directly; for an embedded panel we can only look at the
    // clients that currently live inside some inbound's settings. Only
    // booleans leave this scope — a legacy source credential is re-read inside
    // run() so it never travels through a return value.
    if (clientModel === 'first_class') {
      const existing = await client.getFirstClassClient(clientEmail);
      if (clientMode === 'existing' && !existing) {
        throw new Error(`Selected 3x-ui client '${clientEmail}' no longer exists. Refresh clients and retry.`);
      }
      if (clientMode === 'new' && existing) {
        throw new Error(`A 3x-ui client with email '${clientEmail}' already exists. Select it from Existing clients instead of creating it again.`);
      }
    } else {
      const embedded = await client.findEmbeddedClient(clientEmail);
      if (clientMode === 'existing') {
        if (!embedded) {
          throw new Error(`Selected 3x-ui client '${clientEmail}' no longer exists. Refresh clients and retry.`);
        }
        if (embedded.protocol !== 'shadowsocks') {
          throw new Error(`3x-ui client '${clientEmail}' belongs to a ${embedded.protocol || 'non-Shadowsocks'} inbound; its credential cannot be reused for a Shadowsocks route.`);
        }
        const password = String((embedded.client && embedded.client.password) || '');
        if (!isValidShadowsocksPassword(method, password)) {
          throw new Error(`3x-ui did not expose a reusable Shadowsocks credential for existing client '${clientEmail}'; select another client or create a new one.`);
        }
      } else if (embedded) {
        throw new Error(`A 3x-ui client with email '${clientEmail}' already exists. Select it from Existing clients instead of creating it again.`);
      }
    }

    const recommendation = await this.recommend({ ...body, preferredPort: body.port });
    const port = recommendation.port;
    const routeId = this.reserve({ ...body, iranServerId, foreignServerId, panelId }, port, method, clientEmail, clientMode, clientModel);

    this.event(routeId, 'request_validated', 'PASS', `${clientMode === 'new' ? 'new' : 'existing'} client '${clientEmail}'; method ${method}`);
    this.event(routeId, 'client_model_detected', 'PASS', `client=${clientModel}; hosts=${capabilities.hostMode}`);
    this.event(routeId, 'xui_capability', 'PASS', `client=${clientModel}; hosts=${capabilities.hostMode}`);
    this.event(routeId, 'client_preflight', 'PASS', clientMode === 'existing'
      ? `client '${clientEmail}' exists on the panel (${clientModel})`
      : `email '${clientEmail}' is free on the panel (${clientModel})`);
    this.event(routeId, 'port_reserved', 'PASS', `TCP+UDP port ${port} reserved`);

    return {
      route_id: routeId,
      status: 'RESERVED',
      name: String(body.name),
      port,
      method,
      client_email: clientEmail,
      client_mode: clientMode,
      client_model: clientModel,
      host_mode: capabilities.hostMode,
      panel,
    };
  }

  // Legacy first-class client credential resolution is unsafe only when the
  // panel page a link was generated for is not the endpoint we just built.
  credentialFromLinks(links, context) {
    const match = selectShadowsocksLink(links, context);
    if (!match) return null;
    return { link: match.link, password: match.parsed.password, method: match.parsed.method };
  }

  async resolveClientCredential({ client, clientModel, inboundId, email, host, port, method, createdByRoute, knownPassword }) {
    const matches = (links) => this.credentialFromLinks(links, { host, port, method });
    let links = [];
    let linkError = null;
    try {
      links = await client.clientLinksFor({ email, inboundId, clientModel });
    } catch (err) {
      linkError = err;
    }
    let found = matches(links);
    if (!found && clientModel === 'first_class') {
      // Upstream fans a client change out to nodes and regenerates links
      // asynchronously; give it a moment before deciding.
      for (const delay of [500, 1500]) {
        await sleep(delay);
        try { links = await client.clientLinksFor({ email, inboundId, clientModel }); } catch (err) { linkError = err; continue; }
        found = matches(links);
        if (found) break;
      }
    }
    if (found) return found;

    if (createdByRoute && knownPassword) {
      // Only a credential this route created may be reconstructed locally.
      return { link: buildShadowsocksLink({ method, password: knownPassword, host, port, remark: '' }), password: knownPassword, rebuilt: true };
    }
    const detail = linkError ? ` (${linkError.message})` : '';
    throw new Error(`3x-ui did not return a Shadowsocks link for the existing client '${email}' on ${host}:${port}; credential cannot be inferred safely.${detail}`);
  }

  // ------------------------------------------------------------------
  // Phase 2 — the actual provisioning run. Always called through
  // startProvisioning() so a rejection can never escape as an unhandled
  // promise rejection.
  // ------------------------------------------------------------------

  async run(routeId, prepared = {}) {
    const route = this.route(routeId);
    if (!route) throw new Error(`route ${routeId} not found`);
    const iran = this.server(route.iran_server_id);
    const foreign = this.server(route.foreign_server_id);
    const panel = this.panel(route.panel_id);
    const client = this.client(panel);
    const method = route.method;
    const port = route.port;
    const email = String(route.client_email || '');
    const clientMode = route.client_mode || prepared.client_mode || 'new';
    const routeName = route.name;

    let capabilities;
    try {
      capabilities = await client.resolveCapabilities();
    } catch (err) {
      capabilities = {
        mode: prepared.host_mode || 'external_proxy',
        hostMode: prepared.host_mode || 'external_proxy',
        clientModel: route.client_model || prepared.client_model || 'embedded',
      };
      this.event(routeId, 'client_model_detected', 'INFO', `using reserved capability (${err.message})`);
    }
    const clientModel = capabilities.clientModel;
    const hostMode = capabilities.hostMode;

    const inboundPassword = securePassword();
    const newClientPassword = clientMode === 'new' ? shadowsocksClientPassword(method) : '';
    const clientCreatedByRoute = clientMode === 'new';
    let inboundId = null;
    let hostGroupId = null;
    let clientAttached = false;
    let clientCreated = false;
    let iranCreated = false;
    let foreignCreated = false;
    let peer = null;
    let effectivePassword = newClientPassword;

    try {
      if (clientModel !== (route.client_model || clientModel)) {
        this.event(routeId, 'client_model_detected', 'INFO', `panel client model changed to ${clientModel}`);
      }

      const [iranIp, foreignIp] = await Promise.all([this.publicIp(iran), this.publicIp(foreign)]);
      this.event(routeId, 'public_ip', 'PASS', `IRAN ${iranIp}; FOREIGN ${foreignIp}`);
      const connectivity = await Promise.all([
        this.remote(iran, `ping -c 1 -W 3 ${shellQuote(foreignIp)}`, 10000),
        this.remote(foreign, `ping -c 1 -W 3 ${shellQuote(iranIp)}`, 10000),
      ]);
      if (connectivity.some((result) => result.rc !== 0)) throw new Error('IRAN and FOREIGN servers are not reachable in both directions');
      this.event(routeId, 'connectivity', 'PASS', 'Bidirectional public-IP reachability passed');

      const allocation = await this.pairing(iran, foreign);
      peer = allocation.name || peerName(routeName);
      const nodeCommand = actions.buildAction('node_add', {
        name: peer, ip: iranIp, idx: allocation.idx, key: allocation.key, subnet_base: allocation.subnet_base,
      });
      const nodeResult = await this.remote(foreign, nodeCommand, 300000);
      if (nodeResult.rc !== 0) throw new Error(`FOREIGN GRE setup failed: ${nodeResult.stderr || nodeResult.stdout || `rc=${nodeResult.rc}`}`);
      foreignCreated = true;
      this.event(routeId, 'foreign_node_add', 'PASS', `${foreign.name}: ${peer} (${allocation.subnet_base}/${allocation.idx})`);

      const greCommand = actions.buildAction('peer_add', {
        name: peer,
        foreign_ip: foreignIp,
        iran_ip: iranIp,
        idx: allocation.idx,
        key: allocation.key,
        subnet_base: allocation.subnet_base,
        tcp_ports: String(port),
        udp_ports: String(port),
      });
      const greResult = await this.remote(iran, greCommand, 300000);
      if (greResult.rc !== 0) throw new Error(`GRE setup failed: ${greResult.stderr || greResult.stdout || `rc=${greResult.rc}`}`);
      iranCreated = true;
      this.event(routeId, 'iran_peer_add', 'PASS', `${iran.name}: ${peer}; TCP+UDP ${port}`);

      // The inbound itself NEVER embeds a client for a first-class panel.
      // Embedding one would make upstream reject the inbound with
      // "Duplicate email" or resurrect a shadow copy of a global client.
      let embeddedClients = [];
      if (clientModel === 'embedded' && clientMode === 'new') {
        embeddedClients = [{
          email, password: newClientPassword, method, enable: true, limitIp: 0, totalGB: 0, expiryTime: 0,
        }];
      } else if (clientModel === 'embedded' && clientMode === 'existing') {
        const source = await client.findEmbeddedClient(email);
        if (!source) throw new Error(`Selected 3x-ui client '${email}' no longer exists. Refresh clients and retry.`);
        if (source.protocol !== 'shadowsocks') {
          throw new Error(`3x-ui client '${email}' is not a Shadowsocks client; its credential cannot be reused for this route.`);
        }
        const password = String((source.client && source.client.password) || '');
        if (!isValidShadowsocksPassword(method, password)) {
          throw new Error(`3x-ui did not expose a reusable Shadowsocks credential for existing client '${email}'; select another client or create a new one.`);
        }
        embeddedClients = [{ ...source.client, email, password, method }];
        effectivePassword = password;
      }

      const payload = inboundPayload({
        remark: `GRE-${routeName}`,
        port,
        method,
        inboundPassword,
        clients: embeddedClients,
        externalProxy: hostMode === 'external_proxy' ? { host: iranIp, port } : null,
      });
      inboundId = await client.addInbound(payload);
      this.event(routeId, 'inbound_add', 'PASS', `Shadowsocks inbound ${inboundId}`);

      if (clientModel === 'first_class' && clientMode === 'existing') {
        try {
          await client.attachClient(email, [inboundId]);
        } catch (err) {
          this.event(routeId, 'client_attach', 'FAIL', err.message);
          throw new Error(`attaching existing 3x-ui client '${email}' to inbound ${inboundId} failed: ${err.message}`);
        }
        clientAttached = true;
        this.event(routeId, 'client_attach', 'PASS', `Attached existing client ${email} to inbound ${inboundId}`);
      } else if (clientModel === 'first_class' && clientMode === 'new') {
        try {
          await client.createClient({ email, password: newClientPassword, method, enable: true }, [inboundId]);
        } catch (err) {
          this.event(routeId, 'client_create', 'FAIL', err.message);
          throw new Error(`creating 3x-ui client '${email}' failed: ${err.message}`);
        }
        clientCreated = true;
        this.event(routeId, 'client_create', 'PASS', `Created client ${email} on inbound ${inboundId}`);
      } else {
        this.event(routeId, clientMode === 'new' ? 'client_create' : 'client_attach', 'PASS',
          clientMode === 'new'
            ? `Embedded client ${email} created inside inbound ${inboundId}`
            : `Embedded client ${email} credential reused inside inbound ${inboundId}`);
      }

      if (hostMode === 'managed_hosts') {
        const response = await client.addHost({
          inboundIds: [inboundId], remark: `GRE-${routeName}`, hosts: [iranIp], port, security: 'same', tags: [],
        });
        const host = response && (response.obj || response.data || response);
        hostGroupId = host && (host.groupId || host.id) || null;
        this.event(routeId, 'managed_host_add', 'PASS', `${iranIp}:${port}`);
      } else {
        this.event(routeId, 'external_proxy', 'PASS', `${iranIp}:${port}`);
      }

      const credential = await this.resolveClientCredential({
        client,
        clientModel,
        inboundId,
        email,
        host: iranIp,
        port,
        method,
        createdByRoute: clientCreatedByRoute,
        knownPassword: newClientPassword,
      });
      effectivePassword = credential.password;
      const link = credential.link;
      this.event(routeId, 'link_validate', 'PASS', credential.rebuilt
        ? 'Endpoint and method validated; credential rebuilt from the password created by this route'
        : 'Endpoint, method and client credential validated against the panel-issued link');

      const greHealth = await this.remote(iran, `ip link show ${shellQuote(`gre-${peer}`)} 2>/dev/null | grep -q '<[^>]*UP'`, 15000);
      if (greHealth.rc !== 0) throw new Error('GRE tunnel was created but its link is not UP');
      const runtime = await this.collectUsage(iran, foreign, client);
      const iranRules = portEvidence(runtime.iranOutput, port);
      const foreignListeners = portEvidence(runtime.foreignOutput, port);
      const hasTcp = foreignListeners.some((line) => /^tcp\b/i.test(line));
      const hasUdp = foreignListeners.some((line) => /^udp\b/i.test(line));
      const liveInbound = runtime.inbounds.some((item) => Number(item.id) === inboundId && Number(item.port) === port);
      if (!iranRules.length || !hasTcp || !hasUdp || !liveInbound) {
        throw new Error('runtime validation failed: expected GRE forwarding, TCP+UDP listeners, and 3x-ui inbound were not all present');
      }
      const tcpProbe = await this.remote(foreign,
        `timeout 8 bash -c ${shellQuote(`exec 3<>/dev/tcp/${iranIp}/${port}`)}`, 15000);
      if (tcpProbe.rc !== 0) throw new Error(`end-to-end TCP probe to ${iranIp}:${port} failed`);
      this.event(routeId, 'runtime_validation', 'PASS', 'GRE UP; TCP+UDP listeners; inbound; end-to-end TCP');

      const now = Date.now();
      this.db.transaction(() => {
        this.db.prepare(`UPDATE gre_routes SET inbound_id=?, capability=?, client_model=?, client_password_enc=?, share_link_enc=?, status='ACTIVE', last_error=NULL, updated_at=? WHERE id=?`)
          .run(inboundId, hostMode, clientModel, encrypt(this.cryptKey, effectivePassword), encrypt(this.cryptKey, link), now, routeId);
        this.db.prepare(`UPDATE port_allocations SET status='ACTIVE', updated_at=? WHERE route_id=?`).run(now, routeId);
      })();
      this.event(routeId, 'active', 'PASS', 'Route marked ACTIVE');

      const outbound = {
        tag: `gre-${String(routeName).toLowerCase()}`,
        protocol: 'shadowsocks',
        settings: { servers: [{ address: iranIp, port, method, password: effectivePassword }] },
      };
      const qr_data_url = await QRCode.toDataURL(link, { errorCorrectionLevel: 'M', margin: 2, width: 320 });
      return {
        id: routeId,
        name: routeName,
        status: 'ACTIVE',
        port,
        capability: hostMode,
        client_model: clientModel,
        client_mode: clientMode,
        inbound_id: inboundId,
        iran_endpoint: iranIp,
        link,
        outbound,
        qr_data_url,
        events: this.events(routeId),
        checks: { gre: 'UP', tcp: 'PASS', udp: 'LISTENING', xui: 'PASS', link: 'PASS' },
      };
    } catch (err) {
      const rollback = await this.rollback({
        routeId, client, clientModel, inboundId, hostGroupId, email,
        clientAttached, clientCreated, iranCreated, foreignCreated, peer, iran, foreign,
      });
      const now = Date.now();
      this.db.transaction(() => {
        this.db.prepare(`UPDATE gre_routes SET inbound_id=?, status='FAILED', last_error=?, updated_at=? WHERE id=?`)
          .run(inboundId, err.message, now, routeId);
        this.db.prepare(`UPDATE port_allocations SET status='RELEASED', updated_at=? WHERE route_id=?`).run(now, routeId);
      })();
      this.event(routeId, 'failed', 'FAIL', err.message);
      err.rollback = rollback;
      err.routeId = routeId;
      err.events = this.events(routeId);
      throw err;
    }
  }

  // Best-effort, idempotent, and strictly ownership-scoped: this never deletes
  // a client it did not create, and one failing stage never stops the rest.
  async rollback(ctx) {
    const {
      routeId, client, clientModel, inboundId, hostGroupId, email,
      clientAttached, clientCreated, iranCreated, foreignCreated, peer, iran, foreign,
    } = ctx;
    const rollback = [];
    const step = async (name, stage, fn) => {
      try {
        const detail = await fn();
        rollback.push(name);
        if (stage) this.event(routeId, stage, 'PASS', `${name} removed${detail ? `: ${detail}` : ''}`);
        return true;
      } catch (err) {
        rollback.push(`${name} failed: ${err.message}`);
        if (stage) this.event(routeId, stage, 'FAIL', `${name} removal failed: ${err.message}`);
        return false;
      }
    };

    // Ownership first: a modern first-class client this route created is
    // global state, so it must be deleted explicitly. A pre-existing client
    // is only ever detached from the inbound we just made.
    if (clientCreated && clientModel === 'first_class') {
      await step(`client ${email}`, 'rollback_client_delete', () => client.deleteClient(email));
    } else if (clientAttached && clientModel === 'first_class' && inboundId) {
      await step(`client ${email} attachment`, 'rollback_client_detach', () => client.detachClient(email, [inboundId]));
    }
    if (hostGroupId) await step('managed host', 'rollback_managed_host', () => client.deleteHost(hostGroupId));
    // Deleting the inbound also removes any embedded (legacy) client entry.
    if (inboundId) await step('inbound', 'rollback_inbound', () => client.deleteInbound(inboundId));
    if (iranCreated && peer && iran) {
      await step('IRAN peer', 'rollback_iran_peer', async () => {
        const result = await this.remote(iran, actions.buildAction('peer_remove', { name: peer }), 300000);
        if (result.rc !== 0) throw new Error(result.stderr || result.stdout || `rc=${result.rc}`);
        return peer;
      });
    }
    if (foreignCreated && peer && foreign) {
      await step('FOREIGN node', 'rollback_foreign_node', async () => {
        const result = await this.remote(foreign, actions.buildAction('node_remove', { name: peer }), 300000);
        if (result.rc !== 0) throw new Error(result.stderr || result.stdout || `rc=${result.rc}`);
        return peer;
      });
    }
    return rollback;
  }

  // Fire-and-forget with a guaranteed catch and a hard timeout. Returns a
  // promise that ALWAYS resolves to a result/error record, never rejects.
  startProvisioning(routeId, prepared = {}) {
    const guarded = Promise.race([
      this.run(routeId, prepared),
      new Promise((_, reject) => {
        const timer = setTimeout(() => reject(new Error('provisioning timed out')), this.runTimeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      }),
    ]);
    const task = guarded
      .then((result) => ({ ok: true, result }))
      .catch(async (err) => {
        // run() already rolled back and persisted FAILED for its own errors.
        // Anything that got here before that (route deleted, timeout) still
        // needs a terminal status and a persisted event.
        try {
          const row = this.route(routeId);
          if (row && row.status === 'RESERVED') {
            const now = Date.now();
            this.db.transaction(() => {
              this.db.prepare(`UPDATE gre_routes SET status='FAILED', last_error=?, updated_at=? WHERE id=?`).run(err.message, now, routeId);
              this.db.prepare(`UPDATE port_allocations SET status='RELEASED', updated_at=? WHERE route_id=?`).run(now, routeId);
            })();
            this.event(routeId, 'failed', 'FAIL', err.message);
          }
        } catch { /* route already gone */ }
        return { ok: false, error: err };
      });
    this.running = this.running || new Map();
    this.running.set(Number(routeId), task);
    task.finally(() => { if (this.running) this.running.delete(Number(routeId)); });
    return task;
  }

  // Routes left RESERVED by a hub restart are never auto-destroyed: the real
  // remote state is unknown, so they are surfaced for review.
  sweepAbandoned(now = Date.now()) {
    const stale = this.db.prepare(`
      SELECT id, name FROM gre_routes
      WHERE status = 'RESERVED' AND updated_at < ?
    `).all(now - ABANDONED_RESERVED_MS);
    for (const row of stale) {
      this.db.prepare(`UPDATE gre_routes SET status='STALE', last_error=?, updated_at=? WHERE id=?`)
        .run('provisioning was interrupted (hub restart or crash); remote state is unknown, run Reconcile to inspect', now, row.id);
      this.event(row.id, 'failed', 'FAIL', 'Provisioning was interrupted before it finished; remote state is unknown. Run Reconcile before retrying.');
    }
    return stale.map((row) => row.id);
  }

  // Legacy synchronous entry point (kept for scripts/reconcile tooling): runs
  // prepare() and run() back to back and returns the same ACTIVE payload.
  async create(input) {
    const prepared = await this.prepare(input);
    return this.run(prepared.route_id, prepared);
  }

  listRoutes(includeSecrets = false) {
    const rows = this.db.prepare(`
      SELECT r.*, i.name AS iran_name, i.host AS iran_host, f.name AS foreign_name,
             p.name AS panel_name, p.base_url AS panel_url
      FROM gre_routes r JOIN servers i ON i.id=r.iran_server_id
      JOIN servers f ON f.id=r.foreign_server_id JOIN xui_panels p ON p.id=r.panel_id
      ORDER BY r.created_at DESC
    `).all();
    return rows.map((row) => {
      const { client_password_enc, share_link_enc, ...safe } = row;
      if (includeSecrets && row.status === 'ACTIVE') {
        safe.client_password = decrypt(this.cryptKey, client_password_enc);
        safe.link = decrypt(this.cryptKey, share_link_enc);
      }
      return safe;
    });
  }

  async reconcile(routeId) {    const route = this.db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(routeId);
    if (!route) throw new Error('route not found');
    const iran = this.server(route.iran_server_id);
    const foreign = this.server(route.foreign_server_id);
    const client = this.client(this.panel(route.panel_id));
    const usage = await this.collectUsage(iran, foreign, client);
    const iranEvidence = portEvidence(usage.iranOutput, route.port);
    const foreignEvidence = portEvidence(usage.foreignOutput, route.port);
    const inbound = usage.inbounds.find((item) => Number(item.id) === Number(route.inbound_id) && Number(item.port) === route.port);
    const healthy = iranEvidence.length > 0 && foreignEvidence.length > 0 && !!inbound;
    const status = healthy ? 'ACTIVE' : 'NEEDS_REVIEW';
    const detail = healthy ? null : JSON.stringify({
      iran_forwarding: iranEvidence.length > 0,
      foreign_listener: foreignEvidence.length > 0,
      xui_inbound: !!inbound,
    });
    const now = Date.now();
    this.db.transaction(() => {
      this.db.prepare('UPDATE gre_routes SET status=?, last_error=?, updated_at=? WHERE id=?').run(status, detail, now, route.id);
      this.db.prepare('UPDATE port_allocations SET status=?, updated_at=? WHERE route_id=?').run(status, now, route.id);
    })();
    return { id: route.id, status, healthy, iran_forwarding: !!iranEvidence.length, foreign_listener: !!foreignEvidence.length, xui_inbound: !!inbound };
  }
}

module.exports = {
  RouteOrchestrator,
  DEFAULT_RANGE,
  AVOID_PORTS,
  SS_METHODS,
  ABANDONED_RESERVED_MS,
  inboundPayload,
  portEvidence,
  peerName,
  validatePort,
  parseClientIntent,
  shadowsocksClientPassword,
};
