'use strict';

const crypto = require('crypto');
const QRCode = require('qrcode');
const ssh = require('./ssh');
const actions = require('./actions');
const {
  XuiClient, parseShadowsocksLink, buildShadowsocksLink, selectShadowsocksLink, isValidShadowsocksPassword,
} = require('./xui');
const { encrypt, decrypt } = require('./crypto');
const inspection = require('./route-inspection');
const {
  isAlreadyAbsentError,
  inspectGreInterface,
  inspectForwarding,
  inspectListeners,
  inspectInbound,
  clientInInbound,
  inspectManagedHost,
  inspectPortAllocation,
  probeTcpConnect,
} = inspection;

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

// The client-facing Shadowsocks outbound. Stored encrypted alongside the share
// link so the configuration survives a hub restart without any panel call.
function buildOutbound({ link, host, port, method, password, name }) {
  return {
    tag: `gre-${String(name || 'route').toLowerCase()}`,
    protocol: 'shadowsocks',
    settings: {
      servers: [{ address: host, port: Number(port), method, password, uot: false }],
    },
    streamSettings: { network: 'tcp' },
    share_link: link,
  };
}

// A runtime validation failure that names the exact component, so the UI never
// has to say "The operation was aborted due to timeout" again.
const RUNTIME_LABELS = {
  runtime_gre_iran: 'IRAN GRE interface',
  runtime_gre_foreign: 'FOREIGN GRE interface',
  runtime_iran_tcp_rule: 'IRAN TCP forwarding rule',
  runtime_iran_udp_rule: 'IRAN UDP forwarding rule',
  runtime_foreign_tcp_listener: 'FOREIGN TCP listener',
  runtime_foreign_udp_listener: 'FOREIGN UDP listener',
  runtime_xui_inbound: '3x-ui inbound',
  runtime_xui_client: '3x-ui client attachment',
  runtime_managed_host: 'managed host',
  runtime_e2e_tcp: 'end-to-end TCP',
};

class RuntimeValidationError extends Error {
  constructor(component, detail, checks) {
    super(detail);
    this.name = 'RuntimeValidationError';
    this.component = component;
    this.componentLabel = RUNTIME_LABELS[component] || component;
    this.checks = checks || {};
  }
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

  // Everything written to route_events goes through this. It must remove the
  // things that would let someone reconstruct a working client, while keeping the
  // operational facts an operator needs: route name, client email, inbound id,
  // IP, port, stage and panel version all survive.
  static redact(text) {
    return String(text === null || text === undefined ? '' : text)
      // Whole share links first, before the password inside them is considered.
      .replace(/ss:\/\/\S+/gi, '[redacted-link]')
      .replace(/vmess:\/\/\S+/gi, '[redacted-link]')
      .replace(/vless:\/\/\S+/gi, '[redacted-link]')
      .replace(/trojan:\/\/\S+/gi, '[redacted-link]')
      // Credentials in prose or in JSON.
      .replace(/("?(?:password|passwd|pass|secret|private_key|privateKey)"?\s*[:=]\s*")([^"]+)(")/gi,
        '$1[redacted]$3')
      .replace(/("?(?:password|passwd|pass|secret|private_key|privateKey)"?\s*[:=]\s*)([^\s,;}"']+)/gi,
        '$1[redacted]')
      // Auth headers and tokens.
      .replace(/(authorization\s*:\s*bearer\s+)\S+/gi, '$1[redacted]')
      .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, '$1[redacted]')
      .replace(/(cookie\s*:\s*)\S+/gi, '$1[redacted]')
      .replace(/((?:^|[^A-Za-z0-9])x-csrf-token\s*[:=]\s*)\S+/gi, '$1[redacted]')
      // PEM blocks.
      .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
        '[redacted-private-key]')
      // 3x-ui session tokens look like a bare long hex/base64 blob in a JSON body.
      .replace(/("?(?:token|session|cookie)"?\s*[:=]\s*")([^"]{8,})(")/gi, '$1[redacted]$3')
      .slice(0, 4000);
  }

  event(routeId, stage, status, detail = '') {
    const safe = RouteOrchestrator.redact(detail);
    // Stamp every row with the attempt it belongs to, so a retried route keeps
    // every previous attempt in the same persistent log and the UI can group
    // and label them instead of showing one confusing stream.
    let attempt = 1;
    try {
      const row = this.db.prepare('SELECT attempt_no FROM gre_routes WHERE id = ?').get(Number(routeId));
      if (row && Number(row.attempt_no) > 0) attempt = Number(row.attempt_no);
    } catch { /* fall back to attempt 1 */ }
    const info = this.db.prepare('INSERT INTO route_events (route_id, stage, status, detail, created_at, attempt_no) VALUES (?, ?, ?, ?, ?, ?)')
      .run(routeId, stage, status, safe, Date.now(), attempt);
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
      return this.db.prepare('SELECT id, stage, status, detail, created_at, attempt_no FROM route_events WHERE route_id=? ORDER BY id').all(id);
    }
    const after = Number(afterId);
    if (!Number.isFinite(after)) throw new Error('after_id must be a number');
    return this.db.prepare('SELECT id, stage, status, detail, created_at, attempt_no FROM route_events WHERE route_id=? AND id > ? ORDER BY id').all(id, after);
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

  // --- ownership + progress tracking --------------------------------------
  //
  // A route must be able to answer "which remote objects did I create, and
  // which step am I on?" long after the process that created it is gone. These
  // helpers keep that metadata current; every one of them is best-effort so a
  // tracking failure can never abort provisioning itself.
  ownership(routeId, patch = {}) {
    const fields = Object.keys(patch);
    if (!fields.length) return;
    try {
      this.db.prepare(`UPDATE gre_routes SET ${fields.map((f) => `${f} = ?`).join(', ')}, updated_at = ? WHERE id = ?`)
        .run(...fields.map((f) => patch[f]), Date.now(), Number(routeId));
    } catch { /* tracking is not allowed to break provisioning */ }
  }

  // Emit RUNNING, remember the stage as current, and hand back a completion
  // callback that writes PASS/FAIL and clears current_stage on success.
  stage(routeId, name, detail = '') {
    this.event(routeId, name, 'RUNNING', detail);
    try {
      this.db.prepare('UPDATE gre_routes SET current_stage = ?, updated_at = ? WHERE id = ?')
        .run(name, Date.now(), Number(routeId));
    } catch { /* see above */ }
    let done = false;
    return {
      pass: (text = '') => {
        if (done) return;
        done = true;
        this.event(routeId, name, 'PASS', text || detail);
        try { this.db.prepare('UPDATE gre_routes SET current_stage = NULL WHERE id = ?').run(Number(routeId)); } catch { /* ignore */ }
      },
      fail: (text = '') => {
        if (done) return;
        done = true;
        // Keep current_stage set to the failing stage: Reconcile and the UI
        // use it to say exactly where provisioning stopped.
        this.event(routeId, name, 'FAIL', text || detail);
      },
      info: (text = '') => {
        if (done) return;
        done = true;
        this.event(routeId, name, 'INFO', text || detail);
      },
    };
  }

  safeRoute(routeId) {
    const row = this.route(routeId);
    if (!row) return null;
    // Every ciphertext column stays server-side; the dedicated /config endpoint
    // is the only way to obtain the configuration.
    const { client_password_enc, share_link_enc, outbound_enc, ...safe } = row;
    safe.client_model = row.client_model || null;
    safe.client_mode = row.client_mode || null;
    safe.has_config = row.status === 'ACTIVE' && !!row.share_link_enc;
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
    // Diagnostic only, and never allowed to fail the preflight: the exact panel
    // version is nice to have, the API-derived capability is authoritative.
    const panelVersion = await client.detectPanelVersion().catch(() => null);
    const versionText = panelVersion && panelVersion.version ? `3x-ui v${panelVersion.version}` : '3x-ui version unknown';

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
    this.event(routeId, 'panel_probe', 'PASS', `${versionText}; client=${clientModel}; hosts=${capabilities.hostMode}`);
    this.event(routeId, 'client_model_detected', 'PASS', `client=${clientModel}; hosts=${capabilities.hostMode}`);
    this.event(routeId, 'xui_capability', 'PASS', `client=${clientModel}; hosts=${capabilities.hostMode}`);
    this.event(routeId, 'client_preflight', 'PASS', clientMode === 'existing'
      ? `client '${clientEmail}' exists on the panel (${clientModel})`
      : `email '${clientEmail}' is free on the panel (${clientModel})`);
    this.event(routeId, 'port_reserved', 'PASS', `TCP+UDP port ${port} reserved`);

    // Freeze what the panel looked like when this route was created.
    this.ownership(routeId, { panel_version_snapshot: panelVersion && panelVersion.version ? panelVersion.version : null });
    this.reportPanelMetadata(panel, { version: panelVersion, clientModel, hostMode: capabilities.hostMode });

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
      panel_version: panelVersion && panelVersion.version ? panelVersion.version : null,
      panel,
    };
  }

  // Keep the panel row's diagnostics current whenever we talk to it. Best
  // effort: this is display metadata, never a precondition for provisioning.
  reportPanelMetadata(panel, { version, clientModel, hostMode }) {
    try {
      const current = this.db.prepare('SELECT last_probe_at FROM xui_panels WHERE id = ?').get(panel.id);
      const fresh = current && current.last_probe_at && (Date.now() - current.last_probe_at) < 5 * 60 * 1000;
      if (fresh) return;
      this.db.prepare(`
        UPDATE xui_panels
           SET panel_version = COALESCE(?, panel_version),
               panel_version_source = COALESCE(?, panel_version_source),
               client_model = ?, host_mode = ?, capability = ?, last_probe_at = ?, last_probe_error = NULL
         WHERE id = ?
      `).run(
        version && version.version ? version.version : null,
        version && version.source ? version.source : null,
        clientModel, hostMode, hostMode, Date.now(), panel.id
      );
    } catch { /* display metadata only */ }
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
      const attempt = Number(route.attempt_no) || 1;
      if (attempt > 1) this.event(routeId, 'attempt', 'INFO', `Attempt #${attempt}`);

      const ipStage = this.stage(routeId, 'public_ip', 'Detecting public IPv4 on both sides');
      const [iranIp, foreignIp] = await Promise.all([this.publicIp(iran), this.publicIp(foreign)]);
      ipStage.pass(`IRAN ${iranIp}; FOREIGN ${foreignIp}`);

      const connStage = this.stage(routeId, 'connectivity', 'Checking bidirectional reachability');
      const connectivity = await Promise.all([
        this.remote(iran, `ping -c 1 -W 3 ${shellQuote(foreignIp)}`, 10000),
        this.remote(foreign, `ping -c 1 -W 3 ${shellQuote(iranIp)}`, 10000),
      ]);
      if (connectivity.some((result) => result.rc !== 0)) {
        connStage.fail('IRAN and FOREIGN servers are not reachable in both directions');
        throw new Error('IRAN and FOREIGN servers are not reachable in both directions');
      }
      connStage.pass('Bidirectional public-IP reachability passed');

      const pairStage = this.stage(routeId, 'gre_pairing', 'Allocating a collision-free GRE identity');
      const allocation = await this.pairing(iran, foreign);
      pairStage.pass(`${allocation.subnet_base}/${allocation.idx}`);
      peer = allocation.name || peerName(routeName);
      // Persist the GRE identity before creating anything: rollback, reconcile
      // and delete all need to find these objects later.
      this.ownership(routeId, { peer_name: peer });

      const nodeStage = this.stage(routeId, 'foreign_node_add', `${foreign.name}`);
      const nodeCommand = actions.buildAction('node_add', {
        name: peer, ip: iranIp, idx: allocation.idx, key: allocation.key, subnet_base: allocation.subnet_base,
      });
      const nodeResult = await this.remote(foreign, nodeCommand, 300000);
      if (nodeResult.rc !== 0) {
        nodeStage.fail(nodeResult.stderr || nodeResult.stdout || `rc=${nodeResult.rc}`);
        throw new Error(`FOREIGN GRE setup failed: ${nodeResult.stderr || nodeResult.stdout || `rc=${nodeResult.rc}`}`);
      }
      foreignCreated = true;
      this.ownership(routeId, { rollback_state: 'NONE' });
      nodeStage.pass(`${foreign.name}: ${peer} (${allocation.subnet_base}/${allocation.idx})`);

      const peerStage = this.stage(routeId, 'iran_peer_add', `${iran.name}; TCP+UDP ${port}`);
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
      if (greResult.rc !== 0) {
        peerStage.fail(greResult.stderr || greResult.stdout || `rc=${greResult.rc}`);
        throw new Error(`GRE setup failed: ${greResult.stderr || greResult.stdout || `rc=${greResult.rc}`}`);
      }
      iranCreated = true;
      peerStage.pass(`${iran.name}: ${peer}; TCP+UDP ${port}`);

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
      const inboundStage = this.stage(routeId, 'inbound_add', `Shadowsocks on ${port}`);
      try {
        inboundId = await client.addInbound(payload);
      } catch (err) {
        inboundStage.fail(err.message);
        throw err;
      }
      this.ownership(routeId, { inbound_id: inboundId });
      inboundStage.pass(`Shadowsocks inbound ${inboundId}`);

      if (clientModel === 'first_class' && clientMode === 'existing') {
        const attachStage = this.stage(routeId, 'client_attach', `Attaching existing client ${email} to inbound ${inboundId}`);
        try {
          await client.attachClient(email, [inboundId]);
        } catch (err) {
          attachStage.fail(err.message);
          throw new Error(`attaching existing 3x-ui client '${email}' to inbound ${inboundId} failed: ${err.message}`);
        }
        clientAttached = true;
        this.ownership(routeId, { client_attached_by_route: 1, client_created_by_route: 0 });
        attachStage.pass(`Attached existing client ${email} to inbound ${inboundId}`);
      } else if (clientModel === 'first_class' && clientMode === 'new') {
        const createStage = this.stage(routeId, 'client_create', `Creating client ${email} on inbound ${inboundId}`);
        try {
          await client.createClient({ email, password: newClientPassword, method, enable: true }, [inboundId]);
        } catch (err) {
          createStage.fail(err.message);
          throw new Error(`creating 3x-ui client '${email}' failed: ${err.message}`);
        }
        clientCreated = true;
        this.ownership(routeId, { client_created_by_route: 1, client_attached_by_route: 0 });
        createStage.pass(`Created client ${email} on inbound ${inboundId}`);
      } else {
        this.event(routeId, clientMode === 'new' ? 'client_create' : 'client_attach', 'PASS',
          clientMode === 'new'
            ? `Embedded client ${email} created inside inbound ${inboundId}`
            : `Embedded client ${email} credential reused inside inbound ${inboundId}`);
      }

      if (hostMode === 'managed_hosts') {
        const hostStage = this.stage(routeId, 'managed_host_add', `${iranIp}:${port}`);
        let response;
        try {
          response = await client.addHost({
            inboundIds: [inboundId], remark: `GRE-${routeName}`, hosts: [iranIp], port, security: 'same', tags: [],
          });
        } catch (err) {
          hostStage.fail(err.message);
          throw err;
        }
        const host = response && (response.obj || response.data || response);
        hostGroupId = host && (host.groupId || host.id) || null;
        this.ownership(routeId, { host_group_id: hostGroupId, host_mode: hostMode });
        hostStage.pass(`${iranIp}:${port}${hostGroupId ? ` (${hostGroupId})` : ''}`);
      } else {
        this.ownership(routeId, { host_mode: hostMode });
        this.event(routeId, 'external_proxy', 'PASS', `${iranIp}:${port}`);
      }

      const linkStage = this.stage(routeId, 'link_fetch', `Requesting the panel-issued share link for ${email}`);
      let credential;
      try {
        credential = await this.resolveClientCredential({
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
      } catch (err) {
        linkStage.fail(err.message);
        throw err;
      }
      effectivePassword = credential.password;
      const link = credential.link;
      linkStage.pass(credential.rebuilt ? 'Credential rebuilt from the password this route created' : 'Panel link received');
      this.event(routeId, 'link_validate', 'PASS', credential.rebuilt
        ? 'Endpoint and method validated; credential rebuilt from the password created by this route'
        : 'Endpoint, method and client credential validated against the panel-issued link');

      const runtime = await this.validateRuntime({
        routeId, iran, foreign, client, clientModel, email, port, inboundId,
        peer, hostGroupId, hostMode, iranIp,
      });

      const outbound = buildOutbound({ link, host: iranIp, port, method, password: effectivePassword, name: routeName });

      const now = Date.now();
      this.db.transaction(() => {
        this.db.prepare(`UPDATE gre_routes SET inbound_id=?, capability=?, host_mode=?, client_model=?, client_password_enc=?, share_link_enc=?, outbound_enc=?, config_updated_at=?, runtime_checks=?, iran_endpoint=?, status='ACTIVE', last_error=NULL, current_stage=NULL, rollback_state='NONE', updated_at=? WHERE id=?`)
          .run(inboundId, hostMode, hostMode, clientModel, encrypt(this.cryptKey, effectivePassword), encrypt(this.cryptKey, link), encrypt(this.cryptKey, JSON.stringify(outbound)), now, JSON.stringify(runtime.checks), iranIp, now, routeId);
        this.db.prepare(`UPDATE port_allocations SET status='ACTIVE', updated_at=? WHERE route_id=?`).run(now, routeId);
      })();
      this.event(routeId, 'active', 'PASS', 'Route marked ACTIVE');

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
        checks: runtime.checks,
      };
    } catch (err) {
      const failedStage = (() => {
        try {
          const row = this.db.prepare('SELECT current_stage FROM gre_routes WHERE id = ?').get(Number(routeId));
          return row ? row.current_stage : null;
        } catch { return null; }
      })();
      const rollback = await this.rollback({
        routeId, client, clientModel, inboundId, hostGroupId, email,
        clientAttached, clientCreated, iranCreated, foreignCreated, peer, iran, foreign,
      });
      const rollbackFailed = rollback.some((entry) => /failed/i.test(String(entry)));
      const now = Date.now();
      this.db.transaction(() => {
        this.db.prepare(`UPDATE gre_routes SET inbound_id=?, status='FAILED', last_error=?, current_stage=?, rollback_state=?, updated_at=? WHERE id=?`)
          .run(inboundId, err.message, failedStage, rollbackFailed ? 'PARTIAL' : 'CLEAN', now, routeId);
        this.db.prepare(`UPDATE port_allocations SET status='RELEASED', updated_at=? WHERE route_id=?`).run(now, routeId);
      })();
      // Lead with the exact step: "failed at inbound_add: Duplicate email: navid"
      // is far more useful than a bare "failed" at the end of the log.
      this.event(routeId, 'failed', 'FAIL', failedStage
        ? `Failed at ${failedStage}: ${err.message}`
        : err.message);
      err.rollback = rollback;
      err.routeId = routeId;
      err.failedStage = failedStage;
      err.attemptNo = Number(route.attempt_no) || 1;
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
    const warnings = [];

    // Never interpolate a raw result object: panel helpers return envelopes, and
    // `${obj}` produced the production artefact "attachment removed: [object Object]".
    const describe = (value, fallback) => {
      if (value === null || value === undefined) return fallback;
      if (typeof value === 'string') return value.trim() || fallback;
      if (typeof value === 'number' || typeof value === 'boolean') return String(value);
      const candidate = value.message || value.msg || value.detail || value.status;
      return candidate ? String(candidate) : fallback;
    };

    const step = async (label, stage, fn) => {
      try {
        const detail = await fn();
        rollback.push(label);
        if (stage) this.event(routeId, stage, 'PASS', `${label} removed: ${describe(detail, 'done')}`);
        return true;
      } catch (err) {
        // A resource rollback removes may already be gone (the failing step could
        // have been the creation itself). That is a successful end state.
        if (isAlreadyAbsentError(err)) {
          rollback.push(`${label} (already absent)`);
          if (stage) this.event(routeId, stage, 'PASS', `${label} already absent`);
          return true;
        }
        const detail = describe(err, 'unknown error');
        rollback.push(`${label} failed: ${detail}`);
        warnings.push(`${label}: ${detail}`);
        if (stage) this.event(routeId, stage, 'FAIL', `${label} removal failed: ${detail}`);
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
    if (hostGroupId) await step(`managed host ${hostGroupId}`, 'rollback_managed_host', () => client.deleteHost(hostGroupId));
    // Deleting the inbound also removes any embedded (legacy) client entry.
    if (inboundId) await step(`inbound #${inboundId}`, 'rollback_inbound', () => client.deleteInbound(inboundId));
    if (iranCreated && peer && iran) {
      await step(`IRAN peer ${peer}`, 'rollback_iran_peer', async () => {
        const result = await this.remote(iran, actions.buildAction('peer_remove', { name: peer }), 300000);
        if (result.rc !== 0) {
          const err = new Error(result.stderr || result.stdout || `rc=${result.rc}`);
          err.stderr = result.stderr;
          throw err;
        }
        return `peer ${peer}`;
      });
    }
    if (foreignCreated && peer && foreign) {
      await step(`FOREIGN node ${peer}`, 'rollback_foreign_node', async () => {
        const result = await this.remote(foreign, actions.buildAction('node_remove', { name: peer }), 300000);
        if (result.rc !== 0) {
          const err = new Error(result.stderr || result.stdout || `rc=${result.rc}`);
          err.stderr = result.stderr;
          throw err;
        }
        return `node ${peer}`;
      });
    }
    rollback.warnings = warnings;
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
             p.name AS panel_name, p.base_url AS panel_url,
             p.panel_version AS panel_version, p.client_model AS panel_client_model
      FROM gre_routes r JOIN servers i ON i.id=r.iran_server_id
      JOIN servers f ON f.id=r.foreign_server_id JOIN xui_panels p ON p.id=r.panel_id
      WHERE r.deleted_at IS NULL
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

  // ------------------------------------------------------------------
  // Reconciliation
  //
  // Desired-state, component by component. The expected state depends on what
  // the route is supposed to be, not on what happens to exist:
  //   ACTIVE / RESERVED  -> every component must be PRESENT
  //   FAILED             -> every route-owned component must be ABSENT
  //                         (rollback ran). A surviving object is a leftover.
  //   STALE              -> read-only discovery; never judged, never touched.
  // Reconcile never deletes anything: unknown remote state is reported, not
  // destroyed.
  // ------------------------------------------------------------------

  component(name, expected, actual, detail = '') {
    const pass = String(expected) === String(actual);
    return { name, expected: String(expected), actual: String(actual), status: pass ? 'PASS' : 'FAIL', detail: String(detail || '') };
  }

  // ------------------------------------------------------------------
  // Editing the desired specification
  //
  // Editing never provisions. It rewrites what the route is *supposed* to be,
  // so a later Retry (or a fresh Create) uses the new values. While a route is
  // ACTIVE only purely cosmetic fields may move; anything that describes remote
  // infrastructure is refused, because the database would then disagree with
  // the tunnel that is actually running.
  // ------------------------------------------------------------------

  static EDITABLE_INFRA_FIELDS = ['iran_server_id', 'foreign_server_id', 'panel_id', 'port', 'method', 'client_mode', 'client_email', 'client_model'];
  static EDITABLE_COSMETIC_FIELDS = ['name'];

  async editRoute(routeId, patch = {}) {
    const id = Number(routeId);
    const route = this.route(id);
    if (!route) {
      const err = new Error('route not found');
      err.status = 404;
      throw err;
    }
    if (route.deleted_at) {
      const err = new Error('route is deleted');
      err.status = 409;
      throw err;
    }
    if (this.running && this.running.has(id)) {
      const err = new Error('route is provisioning right now; wait for it to finish before editing');
      err.status = 409;
      throw err;
    }

    const next = {};
    const changed = [];
    const want = (value) => value !== undefined && value !== null && value !== '';

    // Cosmetic first: always allowed.
    if (want(patch.name)) {
      const name = String(patch.name).trim();
      if (!ROUTE_NAME_RE.test(name)) {
        const err = new Error('route name must be 1-40 letters, digits, _ or -');
        err.status = 400;
        throw err;
      }
      if (name !== route.name) { next.name = name; changed.push('name'); }
    }

    // Infrastructure.
    const infraTouched = [];
    if (want(patch.iranServerId)) infraTouched.push('iran_server_id');
    if (want(patch.foreignServerId)) infraTouched.push('foreign_server_id');
    if (want(patch.panelId)) infraTouched.push('panel_id');
    if (want(patch.port)) infraTouched.push('port');
    if (want(patch.method)) infraTouched.push('method');
    if (want(patch.client_mode) || want(patch.client_email) || want(patch.client_name)) {
      infraTouched.push('client');
    }

    if (infraTouched.length && route.status === 'ACTIVE') {
      const err = new Error('this route is ACTIVE: its servers, panel, port, method and client cannot be changed while the tunnel is live. Delete or reconcile it first, then create a new route.');
      err.status = 409;
      err.locked = route.status;
      err.fields = infraTouched;
      throw err;
    }

    // Validate the resulting specification before writing anything.
    const iranServerId = want(patch.iranServerId) ? Number(patch.iranServerId) : route.iran_server_id;
    const foreignServerId = want(patch.foreignServerId) ? Number(patch.foreignServerId) : route.foreign_server_id;
    const panelId = want(patch.panelId) ? Number(patch.panelId) : route.panel_id;
    const port = want(patch.port) ? validatePort(patch.port) : route.port;
    const method = want(patch.method) ? String(patch.method) : route.method;
    if (!SS_METHODS.includes(method)) {
      const err = new Error('unsupported Shadowsocks method');
      err.status = 400;
      throw err;
    }
    const iran = this.server(iranServerId);
    const foreign = this.server(foreignServerId);
    if (iran.id === foreign.id) {
      const err = new Error('IRAN and FOREIGN servers must be different');
      err.status = 400;
      throw err;
    }
    const panel = this.panel(panelId);

    let clientMode = route.client_mode || 'new';
    let clientEmail = route.client_email;
    if (want(patch.client_mode) || want(patch.client_email) || want(patch.client_name)) {
      const intent = parseClientIntent({
        client_mode: want(patch.client_mode) ? patch.client_mode : route.client_mode,
        client_email: want(patch.client_email) ? patch.client_email : (want(patch.client_name) ? patch.client_name : route.client_email),
      });
      clientMode = intent.clientMode;
      clientEmail = intent.clientEmail;
    }

    // Re-run the read-only preflight for whatever the edit implies, so a bad
    // selection is rejected here instead of at the next Retry.
    const client = this.client(panel);
    const capabilities = await client.resolveCapabilities();
    const clientModel = capabilities.clientModel;
    if (clientModel === 'first_class') {
      const existing = await client.getFirstClassClient(clientEmail);
      if (clientMode === 'existing' && !existing) {
        const err = new Error(`Selected 3x-ui client '${clientEmail}' no longer exists. Refresh clients and retry.`);
        err.status = 409;
        throw err;
      }
      if (clientMode === 'new' && existing) {
        const err = new Error(`A 3x-ui client with email '${clientEmail}' already exists. Select it from Existing clients instead of creating it again.`);
        err.status = 409;
        throw err;
      }
    } else if (clientMode === 'existing') {
      const embedded = await client.findEmbeddedClient(clientEmail);
      if (!embedded) {
        const err = new Error(`Selected 3x-ui client '${clientEmail}' no longer exists. Refresh clients and retry.`);
        err.status = 409;
        throw err;
      }
    } else if (await client.findEmbeddedClient(clientEmail)) {
      const err = new Error(`A 3x-ui client with email '${clientEmail}' already exists. Select it from Existing clients instead of creating it again.`);
      err.status = 409;
      throw err;
    }

    if (iranServerId !== route.iran_server_id) { next.iran_server_id = iranServerId; changed.push('iran_server_id'); }
    if (foreignServerId !== route.foreign_server_id) { next.foreign_server_id = foreignServerId; changed.push('foreign_server_id'); }
    if (panelId !== route.panel_id) { next.panel_id = panelId; changed.push('panel_id'); }
    if (port !== route.port) {
      // A port change on a non-ACTIVE route must not silently steal a port that
      // another non-released route already holds.
      const conflict = this.registryConflict(iranServerId, foreignServerId, port, id);
      if (conflict) {
        const err = new Error(`port ${port} is already reserved by route '${conflict.route_name}'`);
        err.status = 409;
        throw err;
      }
      next.port = port;
      changed.push('port');
    }
    if (method !== route.method) { next.method = method; changed.push('method'); }
    if (clientEmail !== route.client_email) { next.client_email = clientEmail; changed.push('client_email'); }
    if (clientMode !== (route.client_mode || 'new')) { next.client_mode = clientMode; changed.push('client_mode'); }
    if (clientModel !== route.client_model) { next.client_model = clientModel; changed.push('client_model'); }

    if (changed.length) {
      next.updated_at = Date.now();
      const fields = Object.keys(next);
      this.db.prepare(`UPDATE gre_routes SET ${fields.map((f) => `${f} = ?`).join(', ')} WHERE id = ?`)
        .run(...fields.map((f) => next[f]), id);
      // Keep the allocation row consistent with the spec it mirrors.
      if (next.port !== undefined || next.iran_server_id !== undefined || next.foreign_server_id !== undefined) {
        this.db.prepare('UPDATE port_allocations SET iran_server_id = ?, foreign_server_id = ?, port = ?, updated_at = ? WHERE route_id = ?')
          .run(next.iran_server_id || route.iran_server_id, next.foreign_server_id || route.foreign_server_id,
            next.port || route.port, Date.now(), id);
      }
      this.event(id, 'edited', 'INFO', `specification updated: ${changed.join(', ')}`);
    }

    return { route: this.safeRoute(id), changed };
  }

  // ------------------------------------------------------------------
  // Retry
  // ------------------------------------------------------------------

  async prepareForRetry(routeId) {
    const id = Number(routeId);
    const route = this.route(id);
    if (!route) throw new Error('route not found');

    // Step 1: find out what is actually left over before touching anything.
    const reconciled = await this.reconcile(id);
    const leftovers = (reconciled.components || [])
      .filter((item) => item.status === 'FAIL' && !/^client$/.test(item.name))
      .map((item) => item.name);

    // A leftover that belongs to THIS route would collide with the new attempt.
    // The exception is the client: an existing client is supposed to survive.
    const blocking = leftovers.filter((name) => name !== 'client' && name !== 'client_attachment');
    if (blocking.length) {
      const err = new Error(`previous attempt left resources behind (${blocking.join(', ')}); clean them up with Reconcile before retrying`);
      err.status = 409;
      err.leftover = blocking;
      throw err;
    }

    // Step 2: free the previous reservation so the port can be re-chosen.
    const now = Date.now();
    this.db.prepare("UPDATE port_allocations SET status = 'RELEASED', updated_at = ? WHERE route_id = ?").run(now, id);

    const attempt = (Number(route.attempt_no) || 1) + 1;
    const recommendation = await this.recommend({
      iranServerId: route.iran_server_id,
      foreignServerId: route.foreign_server_id,
      panelId: route.panel_id,
      start: DEFAULT_RANGE[0],
      end: DEFAULT_RANGE[1],
      preferredPort: route.port,
    });
    const port = recommendation.port;

    this.db.transaction(() => {
      this.db.prepare(`
        UPDATE gre_routes
           SET status = 'RESERVED', port = ?, last_error = NULL, inbound_id = NULL,
               attempt_no = ?, current_stage = NULL, rollback_state = 'NONE',
               updated_at = ?
         WHERE id = ?
      `).run(port, attempt, now, id);
      this.db.prepare(`
        INSERT INTO port_allocations (route_id, iran_server_id, foreign_server_id, port, protocols, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'tcp,udp', 'RESERVED', ?, ?)
        ON CONFLICT(route_id) DO UPDATE SET port = excluded.port, status = 'RESERVED', updated_at = excluded.updated_at
      `).run(id, route.iran_server_id, route.foreign_server_id, port, now, now);
    })();

    this.event(id, 'retry_started', 'INFO', `Attempt #${attempt} (attempt #${attempt - 1} ended ${route.status})`);

    return {
      route_id: id,
      status: 'RESERVED',
      name: route.name,
      port,
      method: route.method,
      client_email: route.client_email,
      client_mode: route.client_mode || 'new',
      client_model: route.client_model,
      host_mode: route.host_mode || route.capability || null,
      attempt_no: attempt,
      leftover: [],
      panel: this.panel(route.panel_id),
    };
  }

  // ------------------------------------------------------------------
  // Delete
  // ------------------------------------------------------------------

  // What WOULD be removed, and what is preserved. Used by the confirmation
  // dialog so the operator sees the client-safety promise before committing.
  async deletePreview(routeId) {
    const route = this.route(Number(routeId));
    if (!route) throw new Error('route not found');
    const removes = [];
    const preserves = [];
    const clientModel = route.client_model || null;

    if (route.client_attached_by_route) {
      removes.push(`3x-ui client "${route.client_email}" attachment to inbound ${route.inbound_id || '(none)'}`);
      preserves.push(`3x-ui client "${route.client_email}" — WILL NOT BE DELETED`);
    } else if (route.client_created_by_route) {
      removes.push(`3x-ui client "${route.client_email}" (created by this route)`);
      preserves.push('any other client on the panel');
    } else {
      preserves.push(`3x-ui client "${route.client_email}" — ownership unknown, so it is never deleted`);
    }
    if (route.host_group_id) removes.push(`managed host ${route.host_group_id}`);
    if (route.inbound_id) removes.push(`3x-ui inbound ${route.inbound_id}`);
    if (route.peer_name) {
      removes.push(`IRAN GRE peer "${route.peer_name}"`);
      removes.push(`FOREIGN GRE node "${route.peer_name}"`);
    }
    removes.push(`port allocation ${route.port}`);
    removes.push('the route row (soft delete; its event history is kept)');
    preserves.push('all route_events / timeline history');

    return {
      routeId: route.id,
      name: route.name,
      status: route.status,
      clientModel,
      removes,
      preserves,
      requiresConfirmation: true,
      warning: route.status === 'ACTIVE'
        ? 'This route is ACTIVE: its tunnel, inbound and host will be torn down.'
        : 'This route is not ACTIVE; delete verifies the cleanup that was already attempted.',
    };
  }

  /**
   * Delete a route: remove exactly the resources this route owns, in a safe
   * order, then soft-delete the row. Soft delete keeps the event history.
   *
   * NEVER deletes a pre-existing client globally: for an attached client only
   * the attachment to this route's inbound is removed. A route-created client
   * is removed only when no other inbound still uses it.
   */
  // ------------------------------------------------------------------
  // Delete
  //
  // Idempotent by design: the desired end state is "resource absent", so a
  // resource that is already gone is SUCCESS, not an error. Production hit the
  // opposite behaviour — rollback had already removed peer/node, Delete then
  // re-issued the removal, the CLI answered "Peer 'ir01' does not exist" and the
  // whole delete returned 409.
  //
  // Each component is therefore:
  //   1. inspected read-only (cheap, bounded) to learn the actual state,
  //   2. PASSed as ALREADY_ABSENT when it is already gone,
  //   3. deleted when present,
  //   4. still tolerated as ALREADY_ABSENT if the delete races and reports
  //      "does not exist",
  //   5. only a real, unexpected error is a failure.
  //
  // The globally existing client is never deleted: for client_mode=existing we
  // only ever remove this route's attachment.
  // ------------------------------------------------------------------
  async deleteRoute(routeId) {
    const id = Number(routeId);
    const route = this.route(id);
    if (!route) throw new Error('route not found');
    const iran = this.server(route.iran_server_id);
    const foreign = this.server(route.foreign_server_id);
    const client = this.client(this.panel(route.panel_id));
    const failures = [];
    const components = [];
    const clientModel = route.client_model || null;

    // A component result is recorded for every step, including the happy path,
    // so the UI can show "already absent" as a success.
    const record = (name, previous, result, detail) => {
      components.push({ name, previous, result, detail });
      const status = result === 'FAILED' ? 'FAIL' : 'PASS';
      this.event(id, `delete_${name}`, status, detail);
      if (result === 'FAILED') failures.push({ name, error: detail });
    };

    // Run a delete step that tolerates "already absent" answers from the CLI.
    const tolerant = async (name, previous, fn) => {
      try {
        const detail = await fn();
        record(name, previous, 'DELETED', detail || name);
      } catch (err) {
        if (isAlreadyAbsentError(err)) {
          record(name, previous, 'ALREADY_ABSENT', `${name} was already absent (${err.message})`);
          return;
        }
        record(name, previous, 'FAILED', err.message);
      }
    };

    // ---- 1. Client relationship -------------------------------------
    if (clientModel === 'first_class' && route.client_attached_by_route && !route.client_created_by_route) {
      if (!route.inbound_id) {
        record('client_attachment', 'ABSENT', 'ALREADY_ABSENT', 'no inbound recorded; nothing to detach');
      } else {
        // Ask the inbound itself (one bounded read) instead of /clients/get.
        const inbound = await inspectInbound(this, client, route.inbound_id);
        const attached = inbound.present ? clientInInbound(inbound, route.client_email) : false;
        if (!inbound.present || !attached) {
          this.ownership(id, { client_attached_by_route: 0 });
          record('client_attachment', 'ABSENT', 'ALREADY_ABSENT',
            inbound.present
              ? `${route.client_email} is not attached to inbound ${route.inbound_id}`
              : `inbound ${route.inbound_id} is already gone, so the attachment is gone`);
        } else {
          await tolerant('client_attachment', 'PRESENT', async () => {
            await client.detachClient(route.client_email, [route.inbound_id]);
            this.ownership(id, { client_attached_by_route: 0 });
            return `${route.client_email} detached from inbound ${route.inbound_id} (global client preserved)`;
          });
        }
      }
    } else if (clientModel === 'first_class' && route.client_created_by_route) {
      // Route-owned client. It is GLOBAL state, so before deleting it we must be
      // sure nothing else still references it. One /clients/get is acceptable
      // here: this is the delete path, not provisioning, and refusing to delete a
      // shared identity is far more important than saving a request.
      let otherAttachments = [];
      try {
        const record = await client.getFirstClassClient(route.client_email);
        const ids = record ? (record.inboundIds || []).map(Number) : [];
        otherAttachments = ids.filter((inboundId) => Number(inboundId) !== Number(route.inbound_id));
      } catch { otherAttachments = []; }

      if (otherAttachments.length) {
        // Preserve the client; remove only this route's attachment.
        if (route.inbound_id) {
          await tolerant('client', 'PRESENT', async () => {
            await client.detachClient(route.client_email, [route.inbound_id]);
            this.ownership(id, { client_attached_by_route: 0 });
            return `${route.client_email} is still used by inbound(s) ${otherAttachments.join(', ')}; detached from ${route.inbound_id} instead of deleting`;
          });
        } else {
          record('client', 'PRESENT', 'ALREADY_ABSENT', `${route.client_email} shared with inbound(s) ${otherAttachments.join(', ')}; preserved`);
        }
        components.push({
          name: 'client_preserved',
          previous: 'PRESENT',
          result: 'PRESERVED',
          detail: `${route.client_email} kept because inbound(s) ${otherAttachments.join(', ')} still use it`,
        });
      } else {
        await tolerant('client', 'PRESENT', async () => {
          await client.deleteClient(route.client_email);
          this.ownership(id, { client_created_by_route: 0 });
          return `deleted route-created client ${route.client_email}`;
        });
      }
    }

    // ---- 2. Managed host --------------------------------------------
    if (route.host_group_id) {
      await tolerant('managed_host', 'PRESENT', async () => {
        await client.deleteHost(route.host_group_id);
        this.ownership(id, { host_group_id: null });
        return `removed host ${route.host_group_id}`;
      });
    } else {
      record('managed_host', 'ABSENT', 'ALREADY_ABSENT', 'no managed host recorded');
    }

    // ---- 3. Inbound -------------------------------------------------
    if (route.inbound_id) {
      const inbound = await inspectInbound(this, client, route.inbound_id);
      if (!inbound.present) {
        record('inbound', 'ABSENT', 'ALREADY_ABSENT', `inbound ${route.inbound_id} already absent`);
      } else {
        await tolerant('inbound', 'PRESENT', async () => {
          await client.deleteInbound(route.inbound_id);
          return `removed inbound ${route.inbound_id}`;
        });
      }
    } else {
      record('inbound', 'ABSENT', 'ALREADY_ABSENT', 'no inbound recorded');
    }

    // ---- 4. GRE -----------------------------------------------------
    if (route.peer_name) {
      const [iranGre, foreignGre] = await Promise.all([
        inspectGreInterface(this, iran, route.peer_name, 'IRAN'),
        inspectGreInterface(this, foreign, route.peer_name, 'FOREIGN'),
      ]);
      if (!iranGre.present) {
        record('iran_peer', 'ABSENT', 'ALREADY_ABSENT', `IRAN peer ${route.peer_name} already absent`);
      } else {
        await tolerant('iran_peer', 'PRESENT', async () => {
          const result = await this.remote(iran, actions.buildAction('peer_remove', { name: route.peer_name }), 300000);
          if (result.rc !== 0) throw new Error(result.stderr || result.stdout || `rc=${result.rc}`);
          return `removed IRAN peer ${route.peer_name}`;
        });
      }
      if (!foreignGre.present) {
        record('foreign_node', 'ABSENT', 'ALREADY_ABSENT', `FOREIGN node ${route.peer_name} already absent`);
      } else {
        await tolerant('foreign_node', 'PRESENT', async () => {
          const result = await this.remote(foreign, actions.buildAction('node_remove', { name: route.peer_name }), 300000);
          if (result.rc !== 0) throw new Error(result.stderr || result.stdout || `rc=${result.rc}`);
          return `removed FOREIGN node ${route.peer_name}`;
        });
      }
    } else {
      record('iran_peer', 'ABSENT', 'ALREADY_ABSENT', 'no peer recorded');
      record('foreign_node', 'ABSENT', 'ALREADY_ABSENT', 'no peer recorded');
    }

    // ---- 5. Port allocation (local, always safe) --------------------
    const allocation = inspectPortAllocation(this.db, id);
    await tolerant('port_allocation', allocation.present ? 'PRESENT' : 'ABSENT', async () => {
      this.db.prepare("UPDATE port_allocations SET status = 'RELEASED', updated_at = ? WHERE route_id = ?").run(Date.now(), id);
      return allocation.port ? `released port ${allocation.port}` : 'allocation released';
    });

    const now = Date.now();
    const ok = failures.length === 0;
    if (ok) {
      this.db.prepare("UPDATE gre_routes SET deleted_at = ?, status = 'STALE', current_stage = NULL, rollback_state = 'CLEAN', share_link_enc = NULL, outbound_enc = NULL, config_updated_at = NULL, updated_at = ? WHERE id = ?")
        .run(now, now, id);
      this.event(id, 'deleted', 'PASS', 'Route removed; event history is preserved');
    } else {
      this.db.prepare("UPDATE gre_routes SET status = 'NEEDS_REVIEW', last_error = ?, updated_at = ? WHERE id = ?")
        .run(JSON.stringify({ deleteFailures: failures }), now, id);
      this.event(id, 'deleted', 'FAIL',
        `Deletion incomplete: ${failures.map((f) => `${f.name} (${f.error})`).join('; ')}`);
    }

    return {
      ok,
      route_id: id,
      name: route.name,
      deleted: ok,
      components,
      failures,
      removed: components.filter((c) => c.result === 'DELETED').map((c) => c.name),
      already_absent: components.filter((c) => c.result === 'ALREADY_ABSENT').map((c) => c.name),
      preserved: route.client_attached_by_route || route.client_mode === 'existing'
        ? [`3x-ui client "${route.client_email}" (global client preserved; only this route's attachment was removed)`]
        : [],
    };
  }

  // ------------------------------------------------------------------
  // Runtime validation
  //
  // Production proved that one opaque promise covering "everything after
  // provisioning" can consume the entire request budget and then fail with
  // "The operation was aborted due to timeout" and no idea which subsystem was
  // at fault. So this is a set of small, independently timed checks:
  //
  //   * every check has its own bounded timeout,
  //   * they run in parallel via allSettled, so one slow subsystem cannot
  //     cancel a sibling that already succeeded,
  //   * each emits its own RUNNING then PASS/FAIL stage,
  //   * the thrown error names the exact component,
  //   * the only panel read is the single-inbound detail lookup. No
  //     /inbounds/list, no /clients/list, no /clients/links, and no /clients/get.
  // ------------------------------------------------------------------
  async validateRuntime({ routeId, iran, foreign, client, clientModel, email, port, inboundId, peer, hostGroupId, hostMode, iranIp }) {
    const stages = [
      ['runtime_gre_iran', `IRAN interface gre-${peer} state`],
      ['runtime_gre_foreign', `FOREIGN interface gre-${peer} state`],
      ['runtime_iran_tcp_rule', `IRAN TCP forwarding rule for ${port}`],
      ['runtime_iran_udp_rule', `IRAN UDP forwarding rule for ${port}`],
      ['runtime_foreign_tcp_listener', `FOREIGN TCP listener on :${port}`],
      ['runtime_foreign_udp_listener', `FOREIGN UDP listener on :${port}`],
      ['runtime_xui_inbound', `3x-ui inbound #${inboundId}`],
      ['runtime_xui_client', `client ${email} membership in inbound #${inboundId}`],
      ['runtime_managed_host', hostGroupId ? `managed host ${hostGroupId}` : 'managed host'],
      ['runtime_e2e_tcp', `TCP connect to ${iranIp}:${port}`],
    ];

    // Announce every check first so the timeline has a stable, predictable shape
    // even though the checks themselves finish out of order in parallel.
    const handles = new Map();
    for (const [name, detail] of stages) {
      handles.set(name, this.stage(routeId, name, detail));
    }

    const [greIran, greForeign, forwarding, listeners, inbound, managedHost] = await Promise.all([
      inspectGreInterface(this, iran, peer, 'IRAN'),
      inspectGreInterface(this, foreign, peer, 'FOREIGN'),
      inspectForwarding(this, iran, port, portEvidence),
      inspectListeners(this, foreign, port, portEvidence),
      inspectInbound(this, client, inboundId),
      hostMode === 'managed_hosts'
        ? inspectManagedHost(this, client, hostGroupId)
        : Promise.resolve({ present: null, optional: true, detail: 'external proxy mode; no managed host expected' }),
    ]);

    // Membership is answered from the single-inbound response we already hold, so
    // first-class panels are never asked for /clients/get after attach.
    const attached = inbound.present ? clientInInbound(inbound, email) : false;

    // The published endpoint is only worth probing once the pieces that carry it
    // are known to exist; probing a dead path just burns the TCP budget.
    const pathReady = !!(greIran.up && greForeign.up && forwarding.tcp && listeners.tcp);
    const e2e = pathReady
      ? await probeTcpConnect(this, foreign, iranIp, port)
      : { connected: null, skipped: true, detail: 'skipped: forwarding path was not confirmed' };

    // component -> check result. `optional` failures WARN instead of failing the
    // route: panel metadata that does not affect forwarding must not destroy a
    // working tunnel.
    const results = {
      runtime_gre_iran: { pass: greIran.up === true, detail: greIran.detail, required: true, value: greIran.up ? 'PASS' : 'FAIL' },
      runtime_gre_foreign: { pass: greForeign.up === true, detail: greForeign.detail, required: true, value: greForeign.up ? 'PASS' : 'FAIL' },
      runtime_iran_tcp_rule: { pass: forwarding.tcp === true, detail: forwarding.detail, required: true },
      runtime_iran_udp_rule: { pass: forwarding.udp === true, detail: forwarding.detail, required: true },
      runtime_foreign_tcp_listener: { pass: listeners.tcp === true, detail: listeners.detail, required: true },
      runtime_foreign_udp_listener: { pass: listeners.udp === true, detail: listeners.detail, required: true },
      runtime_xui_inbound: { pass: inbound.present === true, detail: inbound.detail, required: true },
      runtime_xui_client: { pass: attached === true, detail: attached ? `${email} attached to inbound #${inboundId}` : (inbound.present ? `${email} is not present in inbound #${inboundId}` : `inbound #${inboundId} absent, so the attachment is absent`), required: true },
      runtime_managed_host: hostMode === 'managed_hosts'
        ? { pass: managedHost.present === true, detail: managedHost.detail, required: true }
        : { pass: true, optional: true, detail: managedHost.detail, value: 'N/A' },
      runtime_e2e_tcp: { pass: e2e.connected === true, detail: e2e.detail, required: true, skipped: !!e2e.skipped },
    };

    // Emit verdicts in declaration order for a readable timeline.
    const failures = [];
    const warnings = [];
    for (const [name] of stages) {
      const handle = handles.get(name);
      const result = results[name];
      if (!result) continue;
      if (result.pass) {
        handle.pass(result.detail);
      } else if (result.optional) {
        // Honest WARN: recorded as a failure event but compensated below so the
        // route is not torn down for metadata that does not carry traffic.
        handle.fail(`WARN: ${result.detail}`);
        warnings.push(`${RUNTIME_LABELS[name]}: ${result.detail}`);
      } else {
        handle.fail(result.detail);
        failures.push({ name, label: RUNTIME_LABELS[name], detail: result.detail });
      }
    }

    const checks = {};
    for (const [name, result] of Object.entries(results)) {
      const key = name.replace(/^runtime_/, '');
      checks[key] = result.pass ? 'PASS' : (result.optional ? 'WARN' : 'FAIL');
    }

    const summary = this.stage(routeId, 'runtime_validation', 'All runtime checks');
    if (failures.length) {
      const first = failures[0];
      const more = failures.length > 1 ? ` (+${failures.length - 1} more)` : '';
      summary.fail(`${first.label}: ${first.detail}${more}`);
      const err = new RuntimeValidationError(first.name, `Runtime validation failed at ${first.label}: ${first.detail}`, checks);
      err.failures = failures;
      throw err;
    }
    summary.pass(warnings.length
      ? `all runtime checks passed (${warnings.length} warning: ${warnings[0]})`
      : 'all runtime checks passed');

    return { checks, warnings };
  }

  // ------------------------------------------------------------------
  // Persistent configuration
  //
  // The share link is stored encrypted on the route row, so Copy Config keeps
  // working after a browser refresh and after a hub restart. The in-memory
  // cache is never required.
  //
  // An ACTIVE route from an older release may have an encrypted credential but no
  // stored link. That case is reconstructed locally from method + credential +
  // IRAN endpoint + port and then persisted — no 3x-ui call, and never an
  // invented credential.
  // ------------------------------------------------------------------
  routeConfig(routeId) {
    const route = this.route(Number(routeId));
    if (!route || route.deleted_at) return null;
    if (route.status !== 'ACTIVE') return null;

    const host = route.iran_endpoint || this.iranEndpointFor(route);
    const port = Number(route.port);
    const method = route.method;

    let link = null;
    let outbound = null;

    if (route.share_link_enc) {
      try { link = decrypt(this.cryptKey, route.share_link_enc); } catch { link = null; }
    }
    if (route.outbound_enc) {
      try { outbound = JSON.parse(decrypt(this.cryptKey, route.outbound_enc)); } catch { outbound = null; }
    }

    if (!link) {
      // Reconstruct from the encrypted credential we already own.
      let password = null;
      if (route.client_password_enc) {
        try { password = decrypt(this.cryptKey, route.client_password_enc); } catch { password = null; }
      }
      if (!password || !host || !Number.isInteger(port) || !method) {
        throw new Error('Configuration cannot be reconstructed safely; Reconcile/Retry is required.');
      }
      link = buildShadowsocksLink({ method, password, host, port, remark: route.name || '' });
      const rebuilt = buildOutbound({ link, host, port, method, password, name: route.name });
      const now = Date.now();
      this.db.prepare('UPDATE gre_routes SET share_link_enc=?, outbound_enc=?, config_updated_at=?, updated_at=? WHERE id=?')
        .run(encrypt(this.cryptKey, link), encrypt(this.cryptKey, JSON.stringify(rebuilt)), now, now, route.id);
      outbound = rebuilt;
    }

    if (!outbound) {
      // Link exists but the outbound projection was never stored: derive it from
      // the link we hold rather than making one up.
      let parsed = null;
      try { parsed = parseShadowsocksLink(link); } catch { parsed = null; }
      if (parsed && parsed.password) {
        outbound = buildOutbound({ link, host: parsed.host || host, port: parsed.port || port, method: parsed.method || method, password: parsed.password, name: route.name });
      }
    }

    return {
      route_id: route.id,
      name: route.name,
      status: route.status,
      client_mode: route.client_mode || null,
      client_email: route.client_email || null,
      method,
      link,
      outbound,
      endpoint: { host, port },
      inbound_id: route.inbound_id != null ? Number(route.inbound_id) : null,
      updated_at: route.config_updated_at || null,
    };
  }

  // Stored endpoint for routes created before iran_endpoint was captured.
  iranEndpointFor(route) {
    try {
      const server = this.server(route.iran_server_id);
      return server && server.publicIp ? server.publicIp : null;
    } catch { return null; }
  }

  async reconcile(routeId) {
    const route = this.db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(routeId);
    if (!route) throw new Error('route not found');
    const iran = this.server(route.iran_server_id);
    const foreign = this.server(route.foreign_server_id);
    const panel = this.panel(route.panel_id);
    const client = this.client(panel);
    const desiredState = route.status;
    const components = [];
    const notes = [];

    // --- read-only gathering -------------------------------------------
    let usage = null;
    let probeError = null;
    try {
      usage = await this.collectUsage(iran, foreign, client);
    } catch (err) {
      probeError = err.message;
    }

    const port = Number(route.port);
    const iranEvidence = usage ? portEvidence(usage.iranOutput, port) : [];
    const foreignEvidence = usage ? portEvidence(usage.foreignOutput, port) : [];
    const inbounds = usage ? usage.inbounds : [];
    const inbound = inbounds.find((item) => Number(item.id) === Number(route.inbound_id));
    const registry = this.db.prepare(`
      SELECT p.*, r.name AS route_name FROM port_allocations p
      JOIN gre_routes r ON r.id = p.route_id
      WHERE p.route_id = ?
    `).get(route.id);

    // GRE interface state uses the same read-only primitive as runtime
    // validation and delete, so "is the peer there" can never be answered two
    // different ways depending on which code path asks.
    let greUp = null;
    let greDetail = null;
    if (route.peer_name) {
      const gre = await inspectGreInterface(this, iran, route.peer_name, 'IRAN');
      greUp = gre.present === null ? null : (gre.present && gre.up);
      greDetail = gre.detail;
    }

    // Client relationship, asked of the panel itself where the API allows it.
    let clientPresent = null;
    let clientAttached = null;
    let clientAttachedToInbound = null;
    try {
      if ((route.client_model || '') === 'first_class') {
        const record = await client.getFirstClassClient(route.client_email);
        clientPresent = !!record;
        if (record) {
          const ids = (record.inboundIds || []).map(Number);
          clientAttached = ids.length > 0;
          clientAttachedToInbound = route.inbound_id ? ids.includes(Number(route.inbound_id)) : false;
        } else {
          clientAttached = false;
          clientAttachedToInbound = false;
        }
      } else if (inbound) {
        const settings = XuiClient.normalizeSettings(inbound.settings);
        const embedded = (settings && Array.isArray(settings.clients) ? settings.clients : [])
          .some((c) => String(c && c.email || '') === String(route.client_email));
        clientPresent = embedded;
        clientAttached = embedded;
        clientAttachedToInbound = embedded;
      }
    } catch (err) {
      notes.push(`client probe failed: ${err.message}`);
    }

    const hasHost = !!route.host_group_id;
    const hostMode = route.host_mode || route.capability || null;

    // --- build the component table -------------------------------------
    const isCleanupState = desiredState === 'FAILED';
    const isReadOnly = desiredState === 'STALE';

    if (isReadOnly) {
      components.push(this.component('registry', 'UNKNOWN', registry ? registry.status : 'ABSENT',
        registry ? `allocation ${registry.port} is ${registry.status}` : 'no allocation row'));
      components.push(this.component('iran_peer', 'UNKNOWN', greUp === null ? 'UNKNOWN' : (greUp ? 'PRESENT' : 'ABSENT'),
        route.peer_name ? `gre-${route.peer_name}` : 'peer name not recorded'));
      components.push(this.component('foreign_node', 'UNKNOWN', iranEvidence.length ? 'PRESENT' : 'UNKNOWN', 'read-only discovery'));
      components.push(this.component('xui_inbound', 'UNKNOWN', inbound ? 'PRESENT' : 'ABSENT',
        route.inbound_id ? `inbound ${route.inbound_id}` : 'no inbound recorded'));
      components.push(this.component('client', 'UNKNOWN', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'EXISTS' : 'ABSENT'),
        route.client_email));
    } else if (isCleanupState) {
      // Rollback ran, so route-owned objects are EXPECTED to be gone. Their
      // absence is success, not a reason to cry NEEDS_REVIEW.
      components.push(this.component('port_allocation', 'RELEASED', registry ? registry.status : 'RELEASED',
        registry ? `allocation ${registry.port}` : 'no allocation row'));
      components.push(this.component('iran_peer', 'ABSENT', greUp === null ? 'UNKNOWN' : (greUp ? 'PRESENT' : 'ABSENT'),
        route.peer_name ? `gre-${route.peer_name}` : 'no peer recorded'));
      components.push(this.component('iran_forwarding', 'ABSENT', iranEvidence.length ? 'PRESENT' : 'ABSENT', 'IRAN nat rules'));
      components.push(this.component('foreign_listener', 'ABSENT', foreignEvidence.length ? 'LISTENING' : 'ABSENT', 'FOREIGN listeners'));
      components.push(this.component('xui_inbound', 'ABSENT', inbound ? 'PRESENT' : 'ABSENT',
        route.inbound_id ? `inbound ${route.inbound_id}` : 'no inbound recorded'));
      // A client that pre-existed this route MUST still exist. One this route
      // created should have been removed with the rollback.
      if (route.client_attached_by_route) {
        components.push(this.component('client', 'EXISTS', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'EXISTS' : 'ABSENT'),
          `${route.client_email} (pre-existing: must never be deleted)`));
        components.push(this.component('client_attachment', 'DETACHED', clientAttachedToInbound ? 'ATTACHED' : 'DETACHED',
          'detached from the rolled-back inbound only'));
      } else if (route.client_created_by_route) {
        components.push(this.component('client', 'ABSENT', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'EXISTS' : 'ABSENT'),
          `${route.client_email} was created by this route`));
      } else {
        components.push(this.component('client', 'KEEP', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'EXISTS' : 'ABSENT'),
          `${route.client_email} (ownership not recorded)`));
      }
      if (hasHost) {
        components.push(this.component('managed_host', 'ABSENT', 'UNKNOWN',
          `host ${route.host_group_id} could not be verified remotely`));
      }
    } else {
      // ACTIVE / RESERVED: everything must be present.
      components.push(this.component('registry', 'ACTIVE', registry ? registry.status : 'ABSENT',
        registry ? `allocation ${registry.port}` : 'no allocation row'));
      components.push(this.component('iran_peer', 'PRESENT', greUp === null ? 'UNKNOWN' : (greUp ? 'PRESENT' : 'ABSENT'),
        route.peer_name ? `gre-${route.peer_name} link state` : 'peer name not recorded'));
      components.push(this.component('iran_forwarding', 'PRESENT', iranEvidence.length ? 'PRESENT' : 'ABSENT', 'IRAN nat rules'));
      components.push(this.component('foreign_listener', 'LISTENING', foreignEvidence.length ? 'LISTENING' : 'ABSENT', 'FOREIGN TCP+UDP listeners'));
      components.push(this.component('xui_inbound', 'PRESENT', inbound ? 'PRESENT' : 'ABSENT',
        route.inbound_id ? `inbound ${route.inbound_id}` : 'no inbound recorded'));
      if (inbound) {
        components.push(this.component('inbound_port', String(port), String(inbound.port), `inbound ${inbound.id}`));
        components.push(this.component('inbound_protocol', 'shadowsocks', String(inbound.protocol || ''), 'protocol'));
      }
      if ((route.client_model || '') === 'first_class') {
        components.push(this.component('client', 'EXISTS', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'EXISTS' : 'ABSENT'),
          route.client_email));
        components.push(this.component('client_attachment', 'ATTACHED', clientAttachedToInbound ? 'ATTACHED' : 'DETACHED',
          `inbound ${route.inbound_id}`));
      } else {
        components.push(this.component('client_embedded', 'PRESENT', clientPresent === null ? 'UNKNOWN' : (clientPresent ? 'PRESENT' : 'ABSENT'),
          `${route.client_email} in inbound settings`));
      }
      if (hostMode === 'managed_hosts') {
        components.push(this.component('managed_host', 'RECORDED', hasHost ? 'RECORDED' : 'ABSENT',
          route.host_group_id || 'no host group recorded'));
      } else {
        components.push(this.component('external_proxy', 'CONFIGURED', inbound ? 'CONFIGURED' : 'UNKNOWN',
          'streamSettings.externalProxy'));
      }
    }

    const failed = components.filter((item) => item.status === 'FAIL');
    const unknown = components.filter((item) => item.actual === 'UNKNOWN');
    let healthy;
    if (isReadOnly) healthy = true;
    else if (isCleanupState) healthy = failed.length === 0;
    else healthy = failed.length === 0 && unknown.length === 0;

    const leftovers = isCleanupState ? failed.map((item) => item.name) : [];
    const summary = isReadOnly
      ? 'Read-only discovery; no judgement is made about unknown remote state.'
      : isCleanupState
        ? (healthy ? 'FAILED — rollback clean. No remote leftovers detected.' : `FAILED with leftovers: ${leftovers.join(', ')}`)
        : (healthy ? 'All expected components are present.' : `Missing or mismatched: ${failed.map((item) => item.name).join(', ') || 'unknown state'}`);

    const nextStatus = isReadOnly
      ? 'STALE'
      : (healthy ? (desiredState === 'RESERVED' ? 'RESERVED' : (isCleanupState ? 'FAILED' : 'ACTIVE')) : 'NEEDS_REVIEW');

    const now = Date.now();
    const detail = {
      desiredState,
      summary,
      leftovers,
      failedStage: route.current_stage || null,
      probedAt: now,
      probeError: probeError || undefined,
    };
    this.db.transaction(() => {
      this.db.prepare('UPDATE gre_routes SET status=?, last_error=?, updated_at=? WHERE id=?')
        .run(nextStatus, JSON.stringify(detail), now, route.id);
      if (!isReadOnly) {
        const allocationStatus = isCleanupState ? 'RELEASED' : nextStatus;
        this.db.prepare('UPDATE port_allocations SET status=?, updated_at=? WHERE route_id=?')
          .run(allocationStatus, now, route.id);
      }
    })();

    return {
      id: route.id,
      name: route.name,
      desiredState,
      status: nextStatus,
      healthy,
      cleanup_complete: isCleanupState ? healthy : null,
      leftovers,
      failedStage: route.current_stage || null,
      attemptNo: Number(route.attempt_no) || 1,
      summary,
      notes,
      probeError,
      components,
      // Kept for backward compatibility with the previous flat response.
      iran_forwarding: iranEvidence.length > 0,
      foreign_listener: foreignEvidence.length > 0,
      xui_inbound: !!inbound,
    };
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
