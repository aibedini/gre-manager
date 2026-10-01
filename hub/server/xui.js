'use strict';

const { URL } = require('url');

function normalizeBaseUrl(value) {
  const url = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('panel URL must use http or https');
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function cookieFrom(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie().map((v) => v.split(';')[0]).join('; ');
  const raw = headers.get('set-cookie') || '';
  return raw.split(/,(?=[^;,]+=)/).map((v) => v.split(';')[0]).join('; ');
}

class XuiClient {
  constructor({ baseUrl, username, password, fetchImpl = global.fetch }) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.username = username;
    this.password = password;
    this.fetch = fetchImpl;
    this.cookie = '';
  }

  async login() {
    const body = new URLSearchParams({ username: this.username, password: this.password });
    const res = await this.fetch(`${this.baseUrl}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      redirect: 'manual',
    });
    this.cookie = cookieFrom(res.headers);
    if ((!res.ok && ![301, 302, 303].includes(res.status)) || !this.cookie) {
      throw new Error(`3x-ui login failed (HTTP ${res.status})`);
    }
  }

  async request(path, { method = 'GET', body, allow404 = false } = {}) {
    if (!this.cookie) await this.login();
    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        cookie: this.cookie,
        accept: 'application/json',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (allow404 && res.status === 404) return null;
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok || (data && data.success === false)) {
      const detail = data && (data.msg || data.error) || String(text).slice(0, 300);
      const err = new Error(`3x-ui ${method} ${path} failed (HTTP ${res.status}): ${detail}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async detectCapabilities() {
    const docs = await this.request('/docs/openapi.json', { allow404: true }).catch(() => null) ||
      await this.request('/panel/api/docs/openapi.json', { allow404: true }).catch(() => null);
    if (docs && docs.paths && Object.keys(docs.paths).some((p) => p.startsWith('/panel/api/hosts'))) {
      return { mode: 'managed_hosts', evidence: 'openapi' };
    }
    for (const path of ['/panel/api/hosts', '/panel/api/hosts/list']) {
      try {
        const response = await this.request(path, { allow404: true });
        if (response !== null) return { mode: 'managed_hosts', evidence: path };
      } catch (err) {
        if (err.status !== 404 && err.status !== 405) throw err;
      }
    }
    return { mode: 'external_proxy', evidence: 'managed hosts API unavailable' };
  }

  async listInbounds() {
    const data = await this.request('/panel/api/inbounds/list');
    return Array.isArray(data) ? data : (data && Array.isArray(data.obj) ? data.obj : []);
  }

  async addInbound(payload) {
    const data = await this.request('/panel/api/inbounds/add', { method: 'POST', body: payload });
    const obj = data && (data.obj || data.data || data);
    const id = Number(obj && (obj.id || obj.inboundId));
    if (!Number.isInteger(id) || id <= 0) throw new Error('3x-ui created the inbound but returned no inbound id');
    return id;
  }

  deleteInbound(id) {
    return this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'DELETE' })
      .catch(() => this.request(`/panel/api/inbounds/del/${Number(id)}`, { method: 'POST' }));
  }

  addHost(payload) {
    return this.request('/panel/api/hosts/add', { method: 'POST', body: payload });
  }

  deleteHost(id) {
    if (!id) return Promise.resolve();
    return this.request(`/panel/api/hosts/delete/${Number(id)}`, { method: 'DELETE' }).catch(() => undefined);
  }

  async clientLinks(email) {
    const data = await this.request(`/panel/api/clients/links/${encodeURIComponent(email)}`);
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
  try { userInfo = Buffer.from(userInfo.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); } catch { /* plain SIP002 */ }
  if (!userInfo.includes(':')) userInfo = decodeURIComponent(userInfo);
  const split = userInfo.indexOf(':');
  const endpointMatch = endpoint.match(/^\[?([^\]]+)\]?:(\d+)$/);
  if (split < 1 || !endpointMatch) throw new Error('invalid Shadowsocks link');
  return { method: userInfo.slice(0, split), password: userInfo.slice(split + 1), host: endpointMatch[1], port: Number(endpointMatch[2]) };
}

module.exports = { XuiClient, normalizeBaseUrl, parseShadowsocksLink };
