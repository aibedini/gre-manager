'use strict';

// 3x-ui v3.1+ keeps first-class client credentials in a global ClientRecord.
// Route provisioning has two useful bounded sources for an existing credential:
//
// 1. The client preflight already calls /panel/api/clients/get/:email before any
//    mutation. Capture the password from that successful read and reuse it after
//    attach instead of issuing a second detail request while the panel is busy.
// 2. If no preflight credential is available (legacy preflight mode, or an empty
//    global password), read only the newly-created inbound and extract the exact
//    client entry 3x-ui attached there.
//
// Never fall back to /panel/api/clients/links/:email: that expands every link for
// every attachment. Also avoid a second post-attach /clients/get/:email request:
// upstream's client detail endpoint builds traffic/attachment/tunnel metadata and
// can block long enough to exhaust the hub request timeout on a busy panel.

const { XuiClient, buildShadowsocksLink, unwrap } = require('./xui');

const CREDENTIAL_CACHE = Symbol('greFirstClassCredentialCache');
const CREDENTIAL_CAPTURED = Symbol('greFirstClassCredentialCaptureInstalled');
const CREDENTIAL_TTL_MS = 2 * 60 * 1000;

function firstClassRecord(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const record = payload.client || payload.record || payload;
  return record && typeof record === 'object' ? record : null;
}

function required(value, label) {
  if (value === undefined || value === null || value === '') {
    throw new Error(`${label} is required to resolve the Shadowsocks credential`);
  }
  return value;
}

function credentialCache(client) {
  if (!client || typeof client !== 'object') return null;
  if (!client[CREDENTIAL_CACHE]) {
    Object.defineProperty(client, CREDENTIAL_CACHE, {
      value: new Map(),
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }
  return client[CREDENTIAL_CACHE];
}

function captureFirstClassCredential(client, email, payload, now = Date.now()) {
  const key = String(email || '').trim();
  if (!key) return '';
  const cache = credentialCache(client);
  if (!cache) return '';
  // Always clear the previous value first. If a new preflight read throws or
  // returns no password, an earlier route must never donate a stale secret.
  cache.delete(key);
  const record = firstClassRecord(payload);
  const password = String(record && record.password || '');
  if (!password) return '';
  cache.set(key, { password, at: now });
  return password;
}

function consumeFirstClassCredential(client, email, now = Date.now()) {
  const key = String(email || '').trim();
  const cache = client && client[CREDENTIAL_CACHE];
  if (!key || !(cache instanceof Map)) return '';
  const entry = cache.get(key);
  cache.delete(key);
  if (!entry || !entry.password) return '';
  if (!Number.isFinite(entry.at) || now - entry.at > CREDENTIAL_TTL_MS) return '';
  return String(entry.password);
}

function decorateCredentialCapture(client) {
  if (!client || typeof client !== 'object' || client[CREDENTIAL_CAPTURED]) return client;
  if (typeof client.getFirstClassClient !== 'function') return client;

  const originalGet = client.getFirstClassClient.bind(client);
  Object.defineProperty(client, CREDENTIAL_CAPTURED, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });

  client.getFirstClassClient = async function capturedFirstClassClient(email) {
    const key = String(email || '').trim();
    const cache = credentialCache(client);
    if (cache && key) cache.delete(key);
    const payload = await originalGet(email);
    captureFirstClassCredential(client, email, payload);
    return payload;
  };
  return client;
}

async function attachedInboundCredential(client, inboundId, email, expectedMethod) {
  const id = Number(inboundId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new Error('the newly-created inbound id is missing');
  }
  if (!client || typeof client.request !== 'function') {
    throw new Error('3x-ui client does not support a single-inbound read');
  }

  let result;
  try {
    result = await client.request(`/panel/api/inbounds/get/${id}`, { allowFailure: true });
  } catch (err) {
    throw new Error(`GET /panel/api/inbounds/get/${id} failed: ${err.message}`);
  }
  if (!result) throw new Error(`GET /panel/api/inbounds/get/${id} returned no response`);
  if (!result.ok) {
    const body = result.data;
    const detail = body && (body.msg || body.error) || `HTTP ${result.status}`;
    throw new Error(`GET /panel/api/inbounds/get/${id} failed: ${detail}`);
  }

  const body = result.data;
  if (!body || body.success === false) {
    const detail = body && (body.msg || body.error) || 'unsuccessful response';
    throw new Error(`GET /panel/api/inbounds/get/${id} failed: ${detail}`);
  }
  const inbound = unwrap(body);
  if (!inbound || typeof inbound !== 'object') {
    throw new Error(`GET /panel/api/inbounds/get/${id} returned no inbound object`);
  }
  if (inbound.protocol && String(inbound.protocol) !== 'shadowsocks') {
    throw new Error(`inbound ${id} is ${inbound.protocol}, not Shadowsocks`);
  }

  const settings = XuiClient.normalizeSettings(inbound.settings);
  const clients = settings && Array.isArray(settings.clients) ? settings.clients : [];
  const wanted = String(email || '').trim();
  const row = clients.find((item) => String(item && item.email || '').trim() === wanted);
  if (!row) {
    throw new Error(`attached client '${wanted}' is not present in inbound ${id}`);
  }
  const password = String(row.password || '');
  if (!password) {
    throw new Error(`attached client '${wanted}' has no Shadowsocks password in inbound ${id}`);
  }
  const method = String(row.method || (settings && settings.method) || '');
  if (method && expectedMethod && method !== expectedMethod) {
    throw new Error(`attached inbound ${id} uses Shadowsocks method '${method}', expected '${expectedMethod}'`);
  }
  return { password, inbound, client: row };
}

function applyRouteCredentialFastPath(RouteOrchestrator) {
  if (!RouteOrchestrator || !RouteOrchestrator.prototype) {
    throw new Error('RouteOrchestrator class is required');
  }
  const proto = RouteOrchestrator.prototype;
  if (proto.__routeCredentialFastPathApplied) return;
  Object.defineProperty(proto, '__routeCredentialFastPathApplied', { value: true });

  const original = proto.resolveClientCredential;
  if (typeof original !== 'function') {
    throw new Error('RouteOrchestrator.resolveClientCredential is required');
  }

  // Live preflight and the core provisioning run intentionally reuse the same
  // authenticated XuiClient for a short window. Decorate that instance so the
  // successful pre-mutation /clients/get read becomes a one-shot, in-memory
  // credential source. The cache is non-enumerable, never persisted, and is
  // consumed/deleted as soon as link_fetch runs.
  if (typeof proto.client === 'function') {
    const originalClientFactory = proto.client;
    proto.client = function credentialCapturingClient(panel) {
      return decorateCredentialCapture(originalClientFactory.call(this, panel));
    };
  }

  // The core orchestrator predates this fast path and describes link_fetch as
  // a panel-link request. Keep the timeline truthful regardless of whether the
  // credential came from preflight, the attached inbound, a route-owned key, or
  // a legacy panel-issued link.
  if (typeof proto.stage === 'function') {
    const originalStage = proto.stage;
    proto.stage = function credentialAwareStage(routeId, name, detail) {
      const startDetail = name === 'link_fetch'
        ? String(detail || '').replace(/^Requesting the panel-issued share link for /, 'Resolving Shadowsocks credential and share link for ')
        : detail;
      const stage = originalStage.call(this, routeId, name, startDetail);
      if (name === 'link_fetch' && stage && typeof stage.pass === 'function') {
        const originalPass = stage.pass.bind(stage);
        stage.pass = (message) => originalPass(
          message === 'Panel link received' ? 'Client credential resolved; share link ready' : message
        );
      }
      return stage;
    };
  }

  if (typeof proto.event === 'function') {
    const originalEvent = proto.event;
    proto.event = function credentialAwareEvent(routeId, stage, status, detail) {
      let safeDetail = detail;
      if (stage === 'link_validate' && status === 'PASS' &&
          detail === 'Endpoint, method and client credential validated against the panel-issued link') {
        safeDetail = 'Endpoint, method and client credential validated';
      }
      return originalEvent.call(this, routeId, stage, status, safeDetail);
    };
  }

  proto.resolveClientCredential = async function resolveClientCredentialFast(args = {}) {
    const {
      client,
      clientModel,
      inboundId,
      email,
      host,
      port,
      method,
      createdByRoute,
      knownPassword,
    } = args;

    required(host, 'Shadowsocks host');
    required(port, 'Shadowsocks port');
    required(method, 'Shadowsocks method');

    // If this route created the identity, it already owns the exact credential
    // sent to 3x-ui. Do not perform another panel query merely to rediscover it.
    if (createdByRoute && String(knownPassword || '')) {
      const password = String(knownPassword);
      return {
        link: buildShadowsocksLink({ method, password, host, port, remark: '' }),
        password,
        rebuilt: true,
        source: 'route_created_credential',
      };
    }

    if (clientModel === 'first_class') {
      // Production/live path: /clients/get already succeeded in client_preflight
      // before any mutation. For the legacy Shadowsocks methods supported by
      // gre-hub, 3x-ui preserves any existing non-empty password when attaching
      // the ClientRecord to a Shadowsocks inbound, so this is the exact secret
      // copied into the new inbound. Crucially there is NO post-attach detail
      // request here.
      const cachedPassword = consumeFirstClassCredential(client, email);
      if (cachedPassword) {
        return {
          link: buildShadowsocksLink({ method, password: cachedPassword, host, port, remark: '' }),
          password: cachedPassword,
          rebuilt: false,
          source: 'preflight_client_record',
        };
      }

      // Legacy-preflight / edge case: read only the inbound we just created.
      // This is bounded by one inbound and returns settings.clients[], including
      // the exact credential after 3x-ui applied protocol defaults. Do NOT call
      // /clients/get or /clients/links here.
      let attached;
      try {
        attached = await attachedInboundCredential(client, inboundId, email, method);
      } catch (err) {
        throw new Error(`3x-ui could not resolve existing client '${email}' from attached inbound ${inboundId}: ${err.message}`);
      }
      return {
        link: buildShadowsocksLink({ method, password: attached.password, host, port, remark: '' }),
        password: attached.password,
        rebuilt: false,
        source: 'attached_inbound',
      };
    }

    // Embedded/legacy existing clients keep using the original resolver and
    // per-inbound panel link path because their credential source is already the
    // inbound settings object.
    return original.call(this, args);
  };
}

module.exports = {
  applyRouteCredentialFastPath,
  firstClassRecord,
  captureFirstClassCredential,
  consumeFirstClassCredential,
  decorateCredentialCapture,
  attachedInboundCredential,
};
