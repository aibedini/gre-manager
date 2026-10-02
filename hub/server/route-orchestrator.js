'use strict';

const crypto = require('crypto');
const QRCode = require('qrcode');
const ssh = require('./ssh');
const actions = require('./actions');
const { XuiClient, parseShadowsocksLink, buildShadowsocksLink } = require('./xui');
const { encrypt, decrypt } = require('./crypto');

const DEFAULT_RANGE = [3000, 3999];
const AVOID_PORTS = new Set([22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2053, 3000, 3306, 5432, 6379, 8080, 8443]);
const ROUTE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$/;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function securePassword(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
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

function inboundPayload({ remark, port, method, inboundPassword, clientPassword, email, externalProxy }) {
  const settings = {
    method,
    password: inboundPassword,
    network: 'tcp,udp',
    clients: [{ email, password: clientPassword, method }],
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

class RouteOrchestrator {
  constructor({ db, cryptKey, sshOptsFor, fetchImpl = global.fetch, sshExec = ssh.exec }) {
    this.db = db;
    this.cryptKey = cryptKey;
    this.sshOptsFor = sshOptsFor;
    this.fetchImpl = fetchImpl;
    this.sshExec = sshExec;
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

  event(routeId, stage, status, detail = '') {
    const safe = String(detail || '').replace(/ss:\/\/\S+/gi, '[redacted-link]').slice(0, 4000);
    this.db.prepare('INSERT INTO route_events (route_id, stage, status, detail, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(routeId, stage, status, safe, Date.now());
  }

  events(routeId) {
    return this.db.prepare('SELECT id, stage, status, detail, created_at FROM route_events WHERE route_id=? ORDER BY id').all(routeId);
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

  reserve(input, port, method, email) {
    const now = Date.now();
    const tx = this.db.transaction(() => {
      if (this.registryConflict(input.iranServerId, input.foreignServerId, port)) throw new Error(`port ${port} is already reserved in the registry`);
      const result = this.db.prepare(`
        INSERT INTO gre_routes
          (name, iran_server_id, foreign_server_id, panel_id, port, method, client_email, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)
      `).run(input.name, input.iranServerId, input.foreignServerId, input.panelId, port, method, email, now, now);
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

  async create(input) {
    if (!ROUTE_NAME_RE.test(String(input.name || ''))) throw new Error('route name must be 1-40 letters, digits, _ or -');
    const iran = this.server(input.iranServerId);
    const foreign = this.server(input.foreignServerId);
    if (iran.id === foreign.id) throw new Error('IRAN and FOREIGN servers must be different');
    const panel = this.panel(input.panelId);
    const client = this.client(panel);
    const method = input.method || 'chacha20-ietf-poly1305';
    if (!['chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm'].includes(method)) throw new Error('unsupported Shadowsocks method');
    const email = String(input.clientName || `gre-${input.name}`).trim();
    if (!email || email.length > 80) throw new Error('client name must be 1-80 characters');
    const recommendation = await this.recommend({ ...input, preferredPort: input.port });
    const port = recommendation.port;
    const routeId = this.reserve(input, port, method, email);
    this.event(routeId, 'port_reserved', 'PASS', `TCP+UDP port ${port} reserved`);
    const inboundPassword = securePassword();
    const clientPassword = securePassword();
    let foreignCreated = false;
    let iranCreated = false;
    let peer = null;
    let inboundId = null;
    let hostGroupId = null;
    try {
      const [iranIp, foreignIp] = await Promise.all([this.publicIp(iran), this.publicIp(foreign)]);
      this.event(routeId, 'public_ip', 'PASS', `IRAN ${iranIp}; FOREIGN ${foreignIp}`);
      const connectivity = await Promise.all([
        this.remote(iran, `ping -c 1 -W 3 ${shellQuote(foreignIp)}`, 10000),
        this.remote(foreign, `ping -c 1 -W 3 ${shellQuote(iranIp)}`, 10000),
      ]);
      if (connectivity.some((result) => result.rc !== 0)) throw new Error('IRAN and FOREIGN servers are not reachable in both directions');
      this.event(routeId, 'connectivity', 'PASS', 'Bidirectional public-IP reachability passed');
      const capability = await client.detectCapabilities();
      this.event(routeId, 'xui_capability', 'PASS', capability.mode);
      const allocation = await this.pairing(iran, foreign);
      peer = allocation.name || peerName(input.name);
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

      const payload = inboundPayload({
        remark: `GRE-${input.name}`,
        port,
        method,
        inboundPassword,
        clientPassword,
        email,
        externalProxy: capability.mode === 'external_proxy' ? { host: iranIp, port } : null,
      });
      inboundId = await client.addInbound(payload);
      this.event(routeId, 'inbound_add', 'PASS', `Shadowsocks inbound ${inboundId}`);
      if (capability.mode === 'managed_hosts') {
        const response = await client.addHost({
          inboundIds: [inboundId], remark: `GRE-${input.name}`, hosts: [iranIp], port, security: 'same', tags: [],
        });
        const host = response && (response.obj || response.data || response);
        hostGroupId = host && (host.groupId || host.id) || null;
        this.event(routeId, 'managed_host_add', 'PASS', `${iranIp}:${port}`);
      } else {
        this.event(routeId, 'external_proxy', 'PASS', `${iranIp}:${port}`);
      }

      const links = await client.clientLinks(email);
      const shadowsocksLinks = links.filter((item) => typeof item === 'string' && item.startsWith('ss://'));
      const link = shadowsocksLinks.length
        ? shadowsocksLinks.find((item) => {
          try {
            const candidate = parseShadowsocksLink(item);
            return candidate.host === iranIp && candidate.port === port &&
              candidate.method === method && candidate.password === clientPassword;
          } catch { return false; }
        })
        : buildShadowsocksLink({ method, password: clientPassword, host: iranIp, port, remark: `GRE-${input.name}` });
      if (!link) {
        throw new Error('generated Shadowsocks link does not match the IRAN endpoint, selected port, method, or client password');
      }
      this.event(routeId, 'link_validate', 'PASS', 'Endpoint, method and client credential validated');
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
        this.db.prepare(`UPDATE gre_routes SET inbound_id=?, capability=?, client_password_enc=?, share_link_enc=?, status='ACTIVE', updated_at=? WHERE id=?`)
          .run(inboundId, capability.mode, encrypt(this.cryptKey, clientPassword), encrypt(this.cryptKey, link), now, routeId);
        this.db.prepare(`UPDATE port_allocations SET status='ACTIVE', updated_at=? WHERE route_id=?`).run(now, routeId);
      })();
      this.event(routeId, 'active', 'PASS', 'Route marked ACTIVE');
      const outbound = {
        tag: `gre-${String(input.name).toLowerCase()}`,
        protocol: 'shadowsocks',
        settings: { servers: [{ address: iranIp, port, method, password: clientPassword }] },
      };
      const qr_data_url = await QRCode.toDataURL(link, { errorCorrectionLevel: 'M', margin: 2, width: 320 });
      return {
        id: routeId, name: input.name, status: 'ACTIVE', port, capability: capability.mode,
        inbound_id: inboundId, iran_endpoint: iranIp, link, outbound, qr_data_url,
        events: this.events(routeId),
        checks: { gre: 'UP', tcp: 'PASS', udp: 'LISTENING', xui: 'PASS', link: 'PASS' },
      };
    } catch (err) {
      const rollback = [];
      if (hostGroupId) {
        try { await client.deleteHost(hostGroupId); rollback.push('host'); } catch (rollbackErr) { rollback.push(`host failed: ${rollbackErr.message}`); }
      }
      if (inboundId) {
        try { await client.deleteInbound(inboundId); rollback.push('inbound'); } catch (rollbackErr) { rollback.push(`inbound failed: ${rollbackErr.message}`); }
      }
      if (iranCreated) {
        try {
          const result = await this.remote(iran, actions.buildAction('peer_remove', { name: peer }), 300000);
          rollback.push(result.rc === 0 ? 'iran peer' : `iran peer failed: ${result.stderr || result.stdout}`);
          this.event(routeId, 'rollback_iran_peer', result.rc === 0 ? 'PASS' : 'FAIL', result.rc === 0 ? 'removed' : 'remove failed');
        } catch (rollbackErr) { rollback.push(`iran peer failed: ${rollbackErr.message}`); }
      }
      if (foreignCreated) {
        try {
          const result = await this.remote(foreign, actions.buildAction('node_remove', { name: peer }), 300000);
          rollback.push(result.rc === 0 ? 'foreign node' : `foreign node failed: ${result.stderr || result.stdout}`);
          this.event(routeId, 'rollback_foreign_node', result.rc === 0 ? 'PASS' : 'FAIL', result.rc === 0 ? 'removed' : 'remove failed');
        } catch (rollbackErr) { rollback.push(`foreign node failed: ${rollbackErr.message}`); }
      }
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

  async reconcile(routeId) {
    const route = this.db.prepare('SELECT * FROM gre_routes WHERE id = ?').get(routeId);
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

module.exports = { RouteOrchestrator, DEFAULT_RANGE, AVOID_PORTS, inboundPayload, portEvidence, peerName, validatePort };
