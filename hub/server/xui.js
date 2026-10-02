'use strict';

const { URL } = require('url');

const CLIENT_MODELS = new Set(['first_class', 'embedded']);
const HOST_MODES = new Set(['managed_hosts', 'external_proxy']);

// ShadowSocks AEAD ciphers use a 32-byte key, which upstream encodes as a
// 43-character base64url / 44-character base64 string. Accepting only
// credential shapes the installed panel itself would accept keeps us from
// pushing a key that 3x-ui silently replaces behind our back.
const SS_KEY_LENGTHS = { 'aes-128-gcm': 16, 'aes-256-gcm': 32, 'chacha20-ietf-poly1305': 32 };

function isValidShadowsocksPassword(method, password) {
  const expected = SS_KEY_LENGTHS[String(method || '')];
  if (!expected) return false;
  const value = String(password || '');
  if (!value) return false;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]+$/.test(normalized)) return false;
  let decoded;
  try { decoded = Buffer.from(normalized, 'base64'); } catch { return false; }
  if (decoded.length !== expected) return false;
  // Reject strings that merely decode to the right length after lossy padding.
  return decoded.toString('base64').replace(/=+$/, '') === normalized;
}

function normalizeBaseUrl(value) {
  const url = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('panel URL must use http or https');
  url.search = '';
  url.hash = '';
  // Users often paste the visible /panel or /panel/inbounds URL. API and
  // login routes are rooted one level above it, after any custom web base.
  url.pathname = url.pathname.replace(/\/panel(?:\/.*)?\/?$/, '') || '/';
  return url.toString().replace(/\/$/, '');
}

function setCookieValues(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const raw = headers.get('set-cookie') || '';
  return raw ? raw.split(/,(?=[^;,]+=)/) : [];
}

function responseData(text) {
  try { return text ? JSON.parse(text) : null; } catch { return text; }
}

function unwrap(data) {
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    if (data.obj !== undefined) return data.obj;
    if (data.data !== undefined) return data.data;
  }
  return data;
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.links)) return value.links;
  if (typeof value === 'string' && value) return [value];
  return [];
}

function errorStatus(err) {
  return Number(err && err.status) || 0;
}

// 3x-ui panel versions look like "3.8.5" (optionally tagged "v3.8.5").
// Xray-core versions also look like semver, which is exactly why the HTML
// fallback must only accept a version that is presented as the PANEL version.
const PANEL_VERSION_RE = /^v?(\d{1,3}\.\d{1,3}\.\d{1,3})$/;

function normalizePanelVersion(value) {
  const text = String(value === undefined || value === null ? '' : value).trim();
  if (!text) return null;
  const match = text.match(PANEL_VERSION_RE);
  return match ? match[1] : null;
}

// Conservative HTML scan. Anything we cannot attribute to the panel itself
// returns null: reporting the Xray-core version as the panel version would be
// worse than reporting nothing.
function extractPanelVersionFromHtml(html) {
  const text = String(html || '');
  // Drop Xray version hints so they can never be mistaken for the panel's.
  const scrub = (chunk) => chunk
    .replace(/xray[\s\S]{0,60}?v?\d{1,3}\.\d{1,3}\.\d{1,3}/gi, ' ')
    .replace(/v?\d{1,3}\.\d{1,3}\.\d{1,3}[\s\S]{0,40}?xray/gi, ' ');

  const patterns = [
    // <title>3x-ui v3.8.5</title> / "3x-ui" followed by a version
    /3x[\s-]?ui[^0-9v]{0,40}v?(\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    // a dedicated panel-version element or JSON field
    /(?:panelVersion|panel_version|currentVersion|current_version)["'\s:=]{1,12}v?(\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    // <meta name="version" content="3.8.5"> / data-version="3.8.5"
    // The version must be the value of the attribute, not merely nearby.
    /(?:name|id|data-[\w-]*version)\s*=\s*["']?[^"'>]{0,24}?version["']?[^>]{0,80}?\b(?:content|value)\s*=\s*["']v?(\d{1,3}\.\d{1,3}\.\d{1,3})["']/i,
    /(?:name|id|data-[\w-]*version)\s*=\s*["']v?(\d{1,3}\.\d{1,3}\.\d{1,3})["']/i,
  ];

  const head = scrub(text.slice(0, 200000));
  for (const pattern of patterns) {
    const match = head.match(pattern);
    if (match) {
      const version = normalizePanelVersion(match[1]);
      if (version) return version;
    }
  }
  return null;
}

function capabilityError(kind, path, detail) {
  const err = new Error(`3x-ui capability probe for ${path} failed: ${detail}`);
  err.capability = kind;
  return err;
}

class XuiClient {
  constructor({ baseUrl, authType = 'password', username = '', password = '', token = '', fetchImpl = global.fetch, timeoutMs = 20000 }) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.authType = authType;
    this.username = username;
    this.password = password;
    this.token = token;
    this.fetch = fetchImpl;
    this.timeoutMs = Number(timeoutMs) > 0 ? Number(timeoutMs) : 20000;
    this.cookies = new Map();
    this.csrf = '';
    this.authenticated = false;
    this.capabilitiesCache = null;
  }

  absorbCookies(headers) {
    for (const value of setCookieValues(headers)) {
      const pair = value.split(';', 1)[0];
      const at = pair.indexOf('=');
      if (at > 0) this.cookies.set(pair.slice(0, at).trim(), pair.slice(at + 1).trim());
    }
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  async raw(path, { method = 'GET', body, headers = {} } = {}) {
    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        accept: 'application/json',
        'x-requested-with': 'XMLHttpRequest',
        ...(this.cookieHeader() ? { cookie: this.cookieHeader() } : {}),
        ...headers,
      },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    this.absorbCookies(res.headers);
    const text = await res.text();
    return { res, text, data: responseData(text) };
  }

  async authenticate() {
    if (this.authenticated) return;
    if (this.authType === 'token') {
      if (!this.token) throw new Error('3x-ui API token is missing');
      this.authenticated = true;
      return;
    }

    // 3.x protects login and cookie-authenticated mutations with CSRF.
    // 2.x has no endpoint here; a 404 simply selects the legacy flow.
    const csrf = await this.raw('/csrf-token').catch(() => null);
    if (csrf && csrf.res.ok && csrf.data && csrf.data.success !== false) {
      this.csrf = String(csrf.data.obj || csrf.data.token || '');
    }
    const login = await this.raw('/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(this.csrf ? { 'x-csrf-token': this.csrf } : {}),
      },
      body: JSON.stringify({ username: this.username, password: this.password }),
    });
    if (!login.res.ok || (login.data && login.data.success === false) || !this.cookieHeader()) {
      const detail = login.data && (login.data.msg || login.data.error) || `HTTP ${login.res.status}`;
      throw new Error(`3x-ui login failed: ${detail}`);
    }
    this.authenticated = true;
  }

  async request(path, { method = 'GET', body, allow404 = false, allowFailure = false } = {}) {
    await this.authenticate();
    const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
    const { res, text, data } = await this.raw(path, {
      method,
      headers: {
        ...(this.authType === 'token' ? { authorization: `Bearer ${this.token}` } : {}),
        ...(unsafe && this.authType !== 'token' && this.csrf ? { 'x-csrf-token': this.csrf } : {}),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (allow404 && (res.status === 404 || res.status === 405)) return null;
    if (allowFailure) return { ok: res.ok, status: res.status, data };
    if (!res.ok || (data && data.success === false)) {
      const detail = data && (data.msg || data.error) || String(text).slice(0, 300);
      const err = new Error(`3x-ui ${method} ${path} failed (HTTP ${res.status}): ${detail}`);
      err.status = res.status;
      err.panelMsg = data && data.msg ? String(data.msg) : '';
      throw err;
    }
    return data;
  }

  // ---------------------------------------------------------------------
  // Capability detection
  //
  // Two INDEPENDENT axes. `hostMode` is about share-link hosting (managed
  // hosts API vs. streamSettings.externalProxy) and `clientModel` is about
  // where client identities live. Version numbers are deliberately never
  // consulted: upstream changed the client model in v3.1.0, not v3.0.x, and
  // forks/backports shift that boundary around.
  // ---------------------------------------------------------------------

  async probeExtension(path) {
    let result;
    try {
      result = await this.request(path, { allowFailure: true });
    } catch (err) {
      const status = errorStatus(err);
      if (status === 401 || status === 403) throw capabilityError('auth', path, `HTTP ${status}`);
      if (status >= 500) throw capabilityError('panel', path, `HTTP ${status}`);
      // Network errors, DNS failures, resets and 2-connection refusals are the
      // same class as a 5xx: the panel is broken, not old.
      throw capabilityError('panel', path, err.message);
    }
    const { ok, status } = result;
    if (ok) return true;
    if (status === 404 || status === 405) return false;
    if (status === 401 || status === 403) throw capabilityError('auth', path, `HTTP ${status}`);
    if (status >= 500) throw capabilityError('panel', path, `HTTP ${status}`);
    throw capabilityError('panel', path, `unexpected HTTP ${status}`);
  }

  async resolveCapabilities({ refresh = false } = {}) {
    if (this.capabilitiesCache && !refresh) return this.capabilitiesCache;
    const [managedHosts, firstClassClients] = await Promise.all([
      this.probeExtension('/panel/api/hosts/list'),
      this.probeExtension('/panel/api/clients/list'),
    ]);
    const capabilities = {
      // `mode` is kept for existing callers/tests; hostMode is the real name.
      mode: managedHosts ? 'managed_hosts' : 'external_proxy',
      hostMode: managedHosts ? 'managed_hosts' : 'external_proxy',
      clientModel: firstClassClients ? 'first_class' : 'embedded',
    };
    this.capabilitiesCache = capabilities;
    return capabilities;
  }

  // Backwards-compatible alias used by older call sites.
  detectCapabilities(opts) {
    return this.resolveCapabilities(opts);
  }

  // ---------------------------------------------------------------------
  // Inbounds
  // ---------------------------------------------------------------------

  async listInbounds() {
    const data = await this.request('/panel/api/inbounds/list');
    const obj = unwrap(data);
    return Array.isArray(obj) ? obj : [];
  }

  async addInbound(payload) {
    const data = await this.request('/panel/api/inbounds/add', { method: 'POST', body: payload });
    const obj = unwrap(data);
    const id = Number(obj && (obj.id || obj.inboundId));
    if (!Number.isInteger(id) || id <= 0) throw new Error('3x-ui created the inbound but returned no inbound id');
    return id;
  }

  deleteInbound(id) {
    return this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'POST' })
      .catch(() => this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'DELETE' }));
  }

  // ---------------------------------------------------------------------
  // Hosts (share-link hosting capability)
  // ---------------------------------------------------------------------

  addHost(payload) {
    return this.request('/panel/api/hosts/add', { method: 'POST', body: payload });
  }

  deleteHost(groupId) {
    if (!groupId) return Promise.resolve();
    return this.request(`/panel/api/hosts/del/${encodeURIComponent(groupId)}`, { method: 'POST' });
  }

  // ---------------------------------------------------------------------
  // Panel version — DIAGNOSTIC ONLY.
  //
  // The capability axes above stay API-driven and never consult a version
  // number. This method exists purely so the UI can show "3x-ui v3.8.5"
  // next to a panel and so a support report can quote it.
  //
  // Order: /panel/api/server/getPanelUpdateInfo (3.0+) then, for older
  // panels, a conservative scan of the authenticated index HTML.
  // Anything ambiguous resolves to null rather than a wrong version.
  // ---------------------------------------------------------------------

  async detectPanelVersion() {
    const viaApi = await this.panelVersionFromUpdateInfo();
    if (viaApi && viaApi.version) return viaApi;
    const viaHtml = await this.panelVersionFromHtml();
    if (viaHtml && viaHtml.version) return viaHtml;
    return { version: null, source: null, latestVersion: (viaApi && viaApi.latestVersion) || null };
  }

  async panelVersionFromUpdateInfo() {
    let data;
    try {
      data = await this.request('/panel/api/server/getPanelUpdateInfo', { allowFailure: true });
    } catch {
      // 2.x has no such route; 3.x older builds answer success:false.
      return null;
    }
    if (!data || !data.ok) return null;
    const body = data.data;
    if (!body || body.success === false) return null;
    const obj = unwrap(body);
    if (!obj || typeof obj !== 'object') return null;
    const current = normalizePanelVersion(obj.currentVersion);
    const latest = normalizePanelVersion(obj.latestVersion);
    if (!current) return { version: null, source: null, latestVersion: latest };
    return { version: current, source: 'api', latestVersion: latest };
  }

  async panelVersionFromHtml() {
    let res;
    let text = '';
    try {
      await this.authenticate();
      res = await this.raw('/', {
        headers: {
          accept: 'text/html',
          ...(this.authType === 'token' ? { authorization: `Bearer ${this.token}` } : {}),
          // Ask for the panel page, not an XHR JSON response.
          'x-requested-with': '',
        },
      });
      text = String(res.text || '');
    } catch {
      return null;
    }
    if (!res || !res.res || !res.res.ok || !text) return null;
    const found = extractPanelVersionFromHtml(text);
    return found ? { version: found, source: 'html', latestVersion: null } : null;
  }

  // ---------------------------------------------------------------------
  // Clients — public (never exposes credentials to the browser)
  // ---------------------------------------------------------------------

  static normalizeSettings(settings) {
    if (typeof settings === 'string') {
      try { return JSON.parse(settings); } catch { return null; }
    }
    return settings && typeof settings === 'object' ? settings : null;
  }

  async listEmbeddedClients() {
    const inbounds = await this.listInbounds();
    const seen = new Set();
    const clients = [];
    for (const inbound of inbounds) {
      const settings = XuiClient.normalizeSettings(inbound && inbound.settings);
      for (const client of (settings && Array.isArray(settings.clients) ? settings.clients : [])) {
        const email = String(client && (client.email || client.name) || '').trim();
        if (!email || seen.has(email)) continue;
        seen.add(email);
        clients.push({
          email,
          inbound_ids: [Number(inbound.id) || null].filter(Boolean),
          inbound_id: Number(inbound.id) || null,
          inbound_remark: String(inbound.remark || ''),
          protocol: String(inbound.protocol || ''),
          model: 'embedded',
        });
      }
    }
    return clients;
  }

  async listFirstClassClients() {
    const data = await this.request('/panel/api/clients/list');
    const rows = asArray(unwrap(data));
    if (!rows.length) return [];
    // inboundIds alone is not enough for the UI: resolve remark/protocol for
    // the first attachment so the dropdown can show where a client lives.
    let inbounds = [];
    try { inbounds = await this.listInbounds(); } catch { inbounds = []; }
    const byId = new Map(inbounds.map((item) => [Number(item.id), item]));
    return rows.map((row) => {
      const email = String(row && (row.email || row.name) || '').trim();
      const inboundIds = asArray(row && (row.inboundIds || row.inbound_ids || row.inbounds))
        .map(Number).filter((n) => Number.isInteger(n) && n > 0);
      const first = byId.get(inboundIds[0]) || null;
      return {
        email,
        inbound_ids: inboundIds,
        inbound_id: inboundIds.length ? inboundIds[0] : null,
        inbound_remark: first ? String(first.remark || '') : '',
        protocol: first ? String(first.protocol || '') : '',
        model: 'first_class',
      };
    }).filter((item) => item.email);
  }

  async listClients() {
    const capabilities = await this.resolveCapabilities();
    return capabilities.clientModel === 'first_class'
      ? this.listFirstClassClients()
      : this.listEmbeddedClients();
  }

  // Public single-client read. Returns the normalized UI shape or null.
  async getClient(email) {
    const capabilities = await this.resolveCapabilities();
    const wanted = String(email || '').trim();
    if (!wanted) return null;
    if (capabilities.clientModel === 'first_class') {
      const payload = await this.getFirstClassClient(wanted);
      if (!payload) return null;
      const inboundIds = asArray(payload.inboundIds || payload.inbound_ids).map(Number).filter(Boolean);
      const record = payload.client || payload.record || payload;
      return {
        email: String(record.email || wanted),
        inbound_ids: inboundIds,
        inbound_id: inboundIds.length ? inboundIds[0] : null,
        inbound_remark: '',
        protocol: '',
        model: 'first_class',
        found: true,
      };
    }
    const embedded = await this.findEmbeddedClient(wanted);
    if (!embedded) return null;
    return {
      email: wanted,
      inbound_ids: [embedded.inbound_id].filter(Boolean),
      inbound_id: embedded.inbound_id,
      inbound_remark: embedded.inbound_remark,
      protocol: embedded.protocol,
      model: 'embedded',
      found: true,
    };
  }

  // ---------------------------------------------------------------------
  // Clients — internal credential access (server side only)
  // ---------------------------------------------------------------------

  // Raw first-class record: { client, inboundIds }. null when absent.
  async getFirstClassClient(email) {
    const payload = await this.getFirstClassClientRaw(email);
    if (!payload) return null;
    const record = payload.client || payload.record || payload;
    if (!record || typeof record !== 'object' || !String(record.email || '').trim()) return null;
    return payload;
  }

  async getFirstClassClientRaw(email) {
    const data = await this.request(`/panel/api/clients/get/${encodeURIComponent(email)}`, { allowFailure: true });
    if (!data) return null;
    if (data.status === 404 || data.status === 405) return null;
    if (!data.ok) {
      if (data.status === 401 || data.status === 403) throw capabilityError('auth', '/panel/api/clients/get', `HTTP ${data.status}`);
      if (data.status >= 500) throw capabilityError('panel', '/panel/api/clients/get', `HTTP ${data.status}`);
      // A success:false envelope is how upstream reports "record not found".
      return null;
    }
    const body = data.data;
    if (!body || body.success === false) return null;
    const obj = unwrap(body);
    if (!obj || typeof obj !== 'object') return null;
    return obj;
  }

  // Full client object (with the real protocol credential) as stored inside an
  // inbound's settings.clients array. Never exposed to the browser.
  async findEmbeddedClient(email) {
    const wanted = String(email || '').trim();
    if (!wanted) return null;
    const inbounds = await this.listInbounds();
    for (const inbound of inbounds) {
      const settings = XuiClient.normalizeSettings(inbound && inbound.settings);
      const clients = settings && Array.isArray(settings.clients) ? settings.clients : [];
      for (const client of clients) {
        if (String(client && client.email || '').trim() !== wanted) continue;
        return {
          email: wanted,
          client: { ...client },
          inbound_id: Number(inbound.id) || null,
          inbound_remark: String(inbound.remark || ''),
          protocol: String(inbound.protocol || ''),
          settings,
        };
      }
    }
    return null;
  }

  createClient(client, inboundIds) {
    return this.request('/panel/api/clients/add', {
      method: 'POST',
      body: { client, inboundIds: asArray(inboundIds).map(Number) },
    });
  }

  attachClient(email, inboundIds) {
    return this.request(`/panel/api/clients/${encodeURIComponent(email)}/attach`, {
      method: 'POST',
      body: { inboundIds: asArray(inboundIds).map(Number) },
    });
  }

  detachClient(email, inboundIds) {
    return this.request(`/panel/api/clients/${encodeURIComponent(email)}/detach`, {
      method: 'POST',
      body: { inboundIds: asArray(inboundIds).map(Number) },
    });
  }

  deleteClient(email) {
    return this.request(`/panel/api/clients/del/${encodeURIComponent(email)}`, { method: 'POST' });
  }

  async clientLinks(email) {
    const data = await this.request(`/panel/api/clients/links/${encodeURIComponent(email)}`, { allow404: true });
    if (data === null) return [];
    return asArray(unwrap(data)).filter((item) => typeof item === 'string');
  }

  // Legacy panels expose links per (inbound, client) pair instead of globally.
  async embeddedClientLinks(inboundId, email) {
    if (!inboundId) return [];
    const data = await this.request(
      `/panel/api/inbounds/getClientLinks/${Number(inboundId)}/${encodeURIComponent(email)}`,
      { allow404: true }
    );
    if (data === null) return [];
    return asArray(unwrap(data)).filter((item) => typeof item === 'string');
  }

  async clientLinksFor({ email, inboundId, clientModel }) {
    if (clientModel === 'first_class') return this.clientLinks(email);
    return this.embeddedClientLinks(inboundId, email);
  }
}

function parseShadowsocksLink(link) {
  if (typeof link !== 'string' || !link.startsWith('ss://')) throw new Error('not a Shadowsocks link');
  const withoutFragment = link.slice(5).split('#')[0];
  const at = withoutFragment.lastIndexOf('@');
  if (at < 0) throw new Error('unsupported Shadowsocks link format');
  let userInfo = withoutFragment.slice(0, at);
  const endpoint = withoutFragment.slice(at + 1).split('?')[0];
  const decoded = Buffer.from(userInfo.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  if (decoded.includes(':')) userInfo = decoded;
  else userInfo = decodeURIComponent(userInfo);
  const split = userInfo.indexOf(':');
  const endpointMatch = endpoint.match(/^\[?([^\]]+)\]?:(\d+)$/);
  if (split < 1 || !endpointMatch) throw new Error('invalid Shadowsocks link');
  return { method: userInfo.slice(0, split), password: userInfo.slice(split + 1), host: endpointMatch[1], port: Number(endpointMatch[2]) };
}

function buildShadowsocksLink({ method, password, host, port, remark }) {
  const userInfo = Buffer.from(`${method}:${password}`).toString('base64');
  return `ss://${userInfo}@${host}:${port}#${encodeURIComponent(remark || '')}`;
}

// An existing client's credential may only be taken from a link the panel
// itself produced and that provably maps to the endpoint we just built.
function selectShadowsocksLink(links, { host, port, method }) {
  for (const item of Array.isArray(links) ? links : []) {
    if (typeof item !== 'string' || !item.startsWith('ss://')) continue;
    let parsed;
    try { parsed = parseShadowsocksLink(item); } catch { continue; }
    if (parsed.host !== host) continue;
    if (Number(parsed.port) !== Number(port)) continue;
    if (method && parsed.method !== method) continue;
    return { link: item, parsed };
  }
  return null;
}

module.exports = {
  XuiClient,
  normalizeBaseUrl,
  parseShadowsocksLink,
  buildShadowsocksLink,
  selectShadowsocksLink,
  isValidShadowsocksPassword,
  normalizePanelVersion,
  extractPanelVersionFromHtml,
  unwrap,
  CLIENT_MODELS,
  HOST_MODES,
};
