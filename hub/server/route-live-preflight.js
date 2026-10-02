'use strict';

// Keeps Auto Route creation responsive: reserve a route locally first so the
// browser gets a route_id immediately, then run every slow/network preflight as
// persisted timeline stages before any GRE mutation starts.

const { isValidShadowsocksPassword } = require('./xui');

const ROUTE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$/;
const EMAIL_RE = /^[^\s@]{1,80}$/;
const METHODS = new Set(['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm']);
const AVOID_PORTS = new Set([22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2053, 3000, 3306, 5432, 6379, 8080, 8443]);
const DEFAULT_START = 3000;
const DEFAULT_END = 3999;
const XUI_TIMEOUT_MS = Math.max(20000, Number(process.env.HUB_XUI_TIMEOUT_MS || 45000));

function timeoutLike(err) {
  const text = String(err && (err.message || err.name) || '').toLowerCase();
  return text.includes('timeout') || text.includes('timed out') || text.includes('aborted');
}

function contextualError(label, err, timeoutMs = null) {
  const detail = String(err && err.message || err || 'unknown error');
  if (timeoutLike(err)) {
    const seconds = timeoutMs ? ` after ${Math.round(timeoutMs / 1000)}s` : '';
    return `${label} timed out${seconds}: ${detail}`;
  }
  return `${label} failed: ${detail}`;
}

function validatePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('port must be an integer 1024-65535');
  return port;
}

function parseClientIntent(body = {}) {
  const mode = String(body.client_mode || '').trim() || 'new';
  if (mode !== 'existing' && mode !== 'new') throw new Error('client_mode must be one of: existing, new');
  const email = String(body.client_email || body.clientName || body.client_name || '').trim();
  if (!email) throw new Error('a 3x-ui client email is required');
  if (!EMAIL_RE.test(email)) throw new Error('client email must be 1-80 characters with no whitespace');
  return { clientMode: mode, clientEmail: email };
}

function localPort(orchestrator, body, iranId, foreignId) {
  if (body.port !== undefined && body.port !== null && body.port !== '') {
    const port = validatePort(body.port);
    const conflict = orchestrator.registryConflict(iranId, foreignId, port);
    if (conflict) throw new Error(`port ${port} is already reserved by route '${conflict.route_name}'`);
    return port;
  }
  const start = body.start === undefined || body.start === null || body.start === '' ? DEFAULT_START : validatePort(body.start);
  const end = body.end === undefined || body.end === null || body.end === '' ? DEFAULT_END : validatePort(body.end);
  if (start > end || end - start > 10000) throw new Error('invalid or excessively large port range');
  for (let port = start; port <= end; port++) {
    if (AVOID_PORTS.has(port)) continue;
    if (!orchestrator.registryConflict(iranId, foreignId, port)) return port;
  }
  throw new Error(`no registry-free TCP+UDP port found in ${start}-${end}`);
}

function remoteEvidence(result) {
  const evidence = result && result.evidence || {};
  return !!(
    (Array.isArray(evidence.iran) && evidence.iran.length) ||
    (Array.isArray(evidence.foreign) && evidence.foreign.length) ||
    evidence.inbound
  );
}

async function verifyPort(orchestrator, route, client) {
  const iran = orchestrator.server(route.iran_server_id);
  const foreign = orchestrator.server(route.foreign_server_id);
  const usage = await orchestrator.collectUsage(iran, foreign, client);

  const preferred = orchestrator.inspectCandidate(usage, iran.id, foreign.id, route.port);
  const otherRegistryConflict = orchestrator.registryConflict(iran.id, foreign.id, route.port, route.id);
  if (!remoteEvidence(preferred) && !otherRegistryConflict) return { port: route.port, changed: false };

  for (let port = DEFAULT_START; port <= DEFAULT_END; port++) {
    if (port === route.port || AVOID_PORTS.has(port)) continue;
    const candidate = orchestrator.inspectCandidate(usage, iran.id, foreign.id, port);
    if (!candidate.free) continue;
    const now = Date.now();
    orchestrator.db.transaction(() => {
      const conflict = orchestrator.registryConflict(iran.id, foreign.id, port, route.id);
      if (conflict) throw new Error(`port ${port} became reserved by route '${conflict.route_name}'`);
      orchestrator.db.prepare('UPDATE gre_routes SET port=?, updated_at=? WHERE id=?').run(port, now, route.id);
      orchestrator.db.prepare("UPDATE port_allocations SET port=?, status='RESERVED', updated_at=? WHERE route_id=?").run(port, now, route.id);
    })();
    return { port, changed: true, previous: route.port };
  }
  throw new Error(`port ${route.port} is occupied and no free TCP+UDP port was found in ${DEFAULT_START}-${DEFAULT_END}`);
}

async function checkDirection(orchestrator, routeId, stageName, source, sourceIp, destination, destinationIp, sourceLabel, destinationLabel) {
  const stage = orchestrator.stage(routeId, stageName,
    `${sourceLabel} ${source.name} (${sourceIp}) -> ${destinationLabel} ${destination.name} (${destinationIp})`);
  try {
    const result = await orchestrator.remote(source, `ping -4 -c 2 -W 2 ${destinationIp}`, 15000);
    if (result.rc !== 0) {
      const detail = String(result.stderr || result.stdout || `ping exited ${result.rc}`).trim().slice(0, 1000);
      stage.fail(`${sourceLabel} -> ${destinationLabel} unreachable: ${detail}`);
      throw new Error(`${sourceLabel} cannot reach ${destinationLabel} public IP ${destinationIp}: ${detail}`);
    }
    stage.pass(`${sourceLabel} ${sourceIp} -> ${destinationLabel} ${destinationIp}: reachable`);
  } catch (err) {
    if (!String(err.message || '').includes('cannot reach')) {
      stage.fail(contextualError(`${sourceLabel} -> ${destinationLabel} reachability check`, err, 15000));
    }
    throw err;
  }
}

function applyRouteLivePreflight(RouteOrchestrator) {
  if (!RouteOrchestrator || !RouteOrchestrator.prototype) throw new Error('RouteOrchestrator class is required');
  const proto = RouteOrchestrator.prototype;
  if (proto.__liveRoutePreflightApplied) return;
  Object.defineProperty(proto, '__liveRoutePreflightApplied', { value: true });

  const originalClient = proto.client;
  const originalRun = proto.run;

  // A slow 3x-ui panel should not fail with the browser's opaque AbortError.
  // Re-use the authenticated client briefly so the background run also reuses
  // the capability result obtained during the timeline preflight.
  proto.client = function clientWithTimeout(panel) {
    this.__xuiLiveCache = this.__xuiLiveCache || new Map();
    const key = Number(panel.id);
    const cached = this.__xuiLiveCache.get(key);
    if (cached && Date.now() - cached.at < 60000) return cached.client;
    const client = originalClient.call(this, panel);
    client.timeoutMs = Math.max(Number(client.timeoutMs) || 0, XUI_TIMEOUT_MS);
    this.__xuiLiveCache.set(key, { at: Date.now(), client });
    return client;
  };

  // IMPORTANT: no network request happens here. The HTTP handler can therefore
  // return 202 + route_id immediately and the UI can open the live timeline.
  proto.prepare = async function livePrepare(input) {
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
    if (!METHODS.has(method)) throw new Error('unsupported Shadowsocks method');
    const { clientMode, clientEmail } = parseClientIntent(body);
    const port = localPort(this, body, iranServerId, foreignServerId);
    const routeId = this.reserve({ ...body, iranServerId, foreignServerId, panelId }, port, method, clientEmail, clientMode, null);

    this.event(routeId, 'request_validated', 'PASS', `${clientMode} client '${clientEmail}'; method ${method}`);
    this.event(routeId, 'port_reserved', 'PASS', `TCP+UDP port ${port} reserved locally; remote safety check queued`);

    return {
      route_id: routeId,
      status: 'RESERVED',
      name: String(body.name),
      port,
      method,
      client_email: clientEmail,
      client_mode: clientMode,
      client_model: null,
      host_mode: null,
      panel_version: null,
      panel,
    };
  };

  proto.run = async function liveRun(routeId, prepared = {}) {
    let route = this.route(routeId);
    if (!route) throw new Error(`route ${routeId} not found`);
    const panel = this.panel(route.panel_id);
    const iran = this.server(route.iran_server_id);
    const foreign = this.server(route.foreign_server_id);
    const client = this.client(panel);

    let capabilities;
    let version = null;
    const panelStage = this.stage(routeId, 'panel_probe', `Probing ${panel.name} 3x-ui capabilities`);
    try {
      capabilities = await client.resolveCapabilities({ refresh: true });
      version = await client.detectPanelVersion().catch(() => null);
      panelStage.pass(`${version && version.version ? `3x-ui v${version.version}` : 'version unknown'}; client=${capabilities.clientModel}; hosts=${capabilities.hostMode}`);
      this.ownership(routeId, {
        client_model: capabilities.clientModel,
        host_mode: capabilities.hostMode,
        panel_version_snapshot: version && version.version ? version.version : null,
      });
      this.reportPanelMetadata(panel, { version, clientModel: capabilities.clientModel, hostMode: capabilities.hostMode });
    } catch (err) {
      const message = contextualError('3x-ui panel capability probe', err, XUI_TIMEOUT_MS);
      panelStage.fail(message);
      throw new Error(message);
    }

    const clientStage = this.stage(routeId, 'client_preflight', `Validating ${route.client_mode || 'new'} client '${route.client_email}'`);
    try {
      if (capabilities.clientModel === 'first_class') {
        const existing = await client.getFirstClassClient(route.client_email);
        if (route.client_mode === 'existing' && !existing) {
          throw new Error(`selected client '${route.client_email}' no longer exists`);
        }
        if (route.client_mode === 'new' && existing) {
          throw new Error(`client '${route.client_email}' already exists; select it as Existing instead`);
        }
      } else {
        const embedded = await client.findEmbeddedClient(route.client_email);
        if (route.client_mode === 'existing') {
          if (!embedded) throw new Error(`selected client '${route.client_email}' no longer exists`);
          if (embedded.protocol !== 'shadowsocks') throw new Error(`client '${route.client_email}' is attached to ${embedded.protocol || 'a non-Shadowsocks'} inbound`);
          const password = String(embedded.client && embedded.client.password || '');
          if (!isValidShadowsocksPassword(route.method, password)) {
            throw new Error(`3x-ui did not expose a reusable Shadowsocks credential for '${route.client_email}'`);
          }
        } else if (embedded) {
          throw new Error(`client '${route.client_email}' already exists; select it as Existing instead`);
        }
      }
      clientStage.pass(`${route.client_mode || 'new'} client '${route.client_email}' validated (${capabilities.clientModel})`);
    } catch (err) {
      const message = contextualError('3x-ui client preflight', err, XUI_TIMEOUT_MS);
      clientStage.fail(message);
      throw new Error(message);
    }

    route = this.route(routeId);
    const portStage = this.stage(routeId, 'port_check', `Checking port ${route.port} on IRAN, FOREIGN, firewall, Docker and 3x-ui`);
    try {
      const checked = await verifyPort(this, route, client);
      if (checked.changed) {
        portStage.pass(`port ${checked.previous} was occupied; switched reservation to free TCP+UDP port ${checked.port}`);
      } else {
        portStage.pass(`TCP+UDP port ${checked.port} is free on IRAN, FOREIGN, firewall, Docker, 3x-ui and registry`);
      }
    } catch (err) {
      const message = contextualError('port safety scan', err, Math.max(XUI_TIMEOUT_MS, 30000));
      portStage.fail(message);
      throw new Error(message);
    }

    const ipStage = this.stage(routeId, 'public_ip_preflight', 'Resolving public IPv4 for IRAN and FOREIGN');
    let iranIp;
    let foreignIp;
    try {
      [iranIp, foreignIp] = await Promise.all([this.publicIp(iran), this.publicIp(foreign)]);
      ipStage.pass(`IRAN ${iranIp}; FOREIGN ${foreignIp}`);
    } catch (err) {
      const message = contextualError('public IPv4 detection', err, 30000);
      ipStage.fail(message);
      throw new Error(message);
    }

    // Explicit per-direction checks. These are before originalRun(), therefore
    // no GRE node/peer/inbound can be created when either public path is blocked.
    await Promise.all([
      checkDirection(this, routeId, 'connectivity_iran_to_foreign', iran, iranIp, foreign, foreignIp, 'IRAN', 'FOREIGN'),
      checkDirection(this, routeId, 'connectivity_foreign_to_iran', foreign, foreignIp, iran, iranIp, 'FOREIGN', 'IRAN'),
    ]);
    this.event(routeId, 'connectivity_preflight', 'PASS', 'IRAN -> FOREIGN and FOREIGN -> IRAN public reachability passed');

    // Re-read the route because port_check may have safely moved the reserved
    // port. The original v2.12.2 provisioning code then performs all mutations,
    // rollback and ownership tracking unchanged.
    route = this.route(routeId);
    return originalRun.call(this, routeId, {
      ...prepared,
      port: route.port,
      client_model: capabilities.clientModel,
      host_mode: capabilities.hostMode,
      panel_version: version && version.version ? version.version : null,
    });
  };
}

module.exports = { applyRouteLivePreflight, contextualError, timeoutLike };