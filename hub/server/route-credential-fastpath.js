'use strict';

// 3x-ui v3.1+ stores first-class client credentials in the global client row.
// `/panel/api/clients/links/:email` expands links across *every* inbound the
// client is attached to; on a busy real panel that can take tens of seconds or
// time out. Route provisioning does not need that enumeration: after attach,
// `/panel/api/clients/get/:email` is the authoritative record and contains the
// exact password 3x-ui copied into the newly-created Shadowsocks inbound.
//
// Keep this as a small compatibility layer so the core orchestrator remains
// usable by legacy fixtures. Production applies it from server/index.js.

const { buildShadowsocksLink } = require('./xui');

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

  // The core orchestrator predates this fast path and describes link_fetch as
  // a panel-link request. Keep the timeline truthful regardless of whether the
  // credential came from a first-class client record, a route-owned key, or a
  // legacy panel-issued link.
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
    // sent to 3x-ui. Do not block on the global link-expansion endpoint merely
    // to rediscover the same value.
    if (createdByRoute && String(knownPassword || '')) {
      const password = String(knownPassword);
      return {
        link: buildShadowsocksLink({ method, password, host, port, remark: '' }),
        password,
        rebuilt: true,
        source: 'route_created_credential',
      };
    }

    // Existing first-class client: the POST /attach path in 3x-ui copies the
    // global ClientRecord into the target inbound. Reading that record *after*
    // attach therefore gives the credential actually used by the new inbound.
    // Legacy AEAD Shadowsocks passwords are allowed to be arbitrary non-empty
    // strings in 3x-ui, so do not reject real credentials merely because they
    // are not fixed-length base64 keys.
    if (clientModel === 'first_class' && client && typeof client.getFirstClassClient === 'function') {
      let payload;
      try {
        payload = await client.getFirstClassClient(String(email || ''));
      } catch (err) {
        throw new Error(`3x-ui could not read the first-class client '${email}' after attachment: ${err.message}`);
      }
      const record = firstClassRecord(payload);
      if (!record) {
        throw new Error(`3x-ui first-class client '${email}' disappeared after attachment`);
      }
      const password = String(record.password || '');
      if (!password) {
        throw new Error(`3x-ui first-class client '${email}' has no Shadowsocks password after attachment; refusing to fabricate a credential`);
      }
      return {
        link: buildShadowsocksLink({ method, password, host, port, remark: '' }),
        password,
        rebuilt: false,
        source: 'first_class_client_record',
      };
    }

    // Embedded/legacy existing clients keep using the original panel-issued
    // link path because their credential source is the inbound settings object.
    return original.call(this, args);
  };
}

module.exports = { applyRouteCredentialFastPath, firstClassRecord };
