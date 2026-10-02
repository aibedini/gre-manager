'use strict';

const { URL } = require('url');

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

class XuiClient {
  constructor({ baseUrl, authType = 'password', username = '', password = '', token = '', fetchImpl = global.fetch }) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.authType = authType;
    this.username = username;
    this.password = password;
    this.token = token;
    this.fetch = fetchImpl;
    this.cookies = new Map();
    this.csrf = '';
    this.authenticated = false;
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
      signal: AbortSignal.timeout(20000),
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

  async request(path, { method = 'GET', body, allow404 = false } = {}) {
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
    if (!res.ok || (data && data.success === false)) {
      const detail = data && (data.msg || data.error) || String(text).slice(0, 300);
      const err = new Error(`3x-ui ${method} ${path} failed (HTTP ${res.status}): ${detail}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async detectCapabilities() {
    // This single read-only probe is the authoritative capability boundary:
    // 3.4+ exposes it; older releases return 404/405.
    const hosts = await this.request('/panel/api/hosts/list', { allow404: true });
    return hosts === null
      ? { mode: 'external_proxy' }
      : { mode: 'managed_hosts' };
  }

  async listInbounds() {
    const data = await this.request('/panel/api/inbounds/list');
    return Array.isArray(data) ? data : (data && Array.isArray(data.obj) ? data.obj : []);
  }

  async listClients() {
    const inbounds = await this.listInbounds();
    const seen = new Set();
    const clients = [];
    for (const inbound of inbounds) {
      let settings = inbound && inbound.settings;
      try { if (typeof settings === 'string') settings = JSON.parse(settings); } catch { settings = null; }
      for (const client of (settings && Array.isArray(settings.clients) ? settings.clients : [])) {
        const email = String(client && (client.email || client.name) || '').trim();
        if (!email || seen.has(email)) continue;
        seen.add(email);
        clients.push({
          email,
          inbound_id: Number(inbound.id) || null,
          inbound_remark: String(inbound.remark || ''),
          protocol: String(inbound.protocol || ''),
        });
      }
    }
    return clients;
  }

  async addInbound(payload) {
    const data = await this.request('/panel/api/inbounds/add', { method: 'POST', body: payload });
    const obj = data && (data.obj || data.data || data);
    const id = Number(obj && (obj.id || obj.inboundId));
    if (!Number.isInteger(id) || id <= 0) throw new Error('3x-ui created the inbound but returned no inbound id');
    return id;
  }

  deleteInbound(id) {
    return this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'POST' })
      .catch(() => this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'DELETE' }));
  }

  addHost(payload) {
    return this.request('/panel/api/hosts/add', { method: 'POST', body: payload });
  }

  deleteHost(groupId) {
    if (!groupId) return Promise.resolve();
    return this.request(`/panel/api/hosts/del/${encodeURIComponent(groupId)}`, { method: 'POST' });
  }

  async clientLinks(email) {
    const data = await this.request(`/panel/api/clients/links/${encodeURIComponent(email)}`, { allow404: true });
    if (data === null) return [];
    const obj = data && (data.obj || data.data || data);
    if (Array.isArray(obj)) return obj;
    if (obj && Array.isArray(obj.links)) return obj.links;
    return typeof obj === 'string' ? [obj] : [];
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

module.exports = { XuiClient, normalizeBaseUrl, parseShadowsocksLink, buildShadowsocksLink };
