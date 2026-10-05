/* discovery-response.js — one interpretation of a discovery API response.
 *
 * Loaded as a plain script by the dashboard and required directly by the tests,
 * so the card and the drawer cannot drift apart again. They were written
 * separately, and that is how the drawer ended up storing the response envelope
 * as if it were the server's snapshot.
 *
 * The rule this file exists to enforce: a failure verdict NEVER becomes a
 * snapshot. The caller keeps whatever topology it already had.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DiscoveryResponse = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Does this payload carry an explicit verdict (v2.15+) or is it a legacy flat
  // snapshot?
  function isVerdict(data) {
    return !!(data && (data.ok !== undefined || data.snapshot !== undefined || data.probe !== undefined));
  }

  // The reason to show an operator, preferring the discovery axis and falling back
  // through the older flat shapes.
  function failureReason(data) {
    var probe = data && data.probe;
    var axis = probe && probe.discovery ? probe.discovery : probe;
    return (axis && (axis.reason || axis.error))
      || (data && data.error)
      || 'probe failed';
  }

  // Returns { verdict, ok, snapshot, probe, reason }.
  // `snapshot` is a REAL authoritative snapshot or null — never an envelope.
  function read(data) {
    if (!isVerdict(data)) {
      // Legacy hub: the payload was the snapshot itself.
      return {
        verdict: false,
        ok: !(data && data.error),
        snapshot: data || null,
        probe: null,
        reason: (data && data.error) || null,
      };
    }
    if (data.ok === false) {
      return { verdict: true, ok: false, snapshot: null, probe: data.probe || null, reason: failureReason(data) };
    }
    return {
      verdict: true,
      ok: true,
      snapshot: data.snapshot || null,
      probe: data.probe || null,
      reason: null,
    };
  }

  // Apply a result to one server and, when a list is supplied, to the matching row
  // in it, so the card and the drawer never disagree.
  function apply(server, data, servers) {
    var result = read(data);
    // The discover payload exposes the axes both top-level and under `probe`; keep
    // whichever it actually sent so the next render does not read a stale value.
    if (result.probe) {
      server.probe = result.probe;
      if (data && data.health) server.health = data.health;
      if (data && data.discovery) server.discovery = data.discovery;
    }
    if (result.ok && result.snapshot) server.snapshot = result.snapshot;
    if (Array.isArray(servers)) {
      var listed = servers.find(function (item) { return Number(item.id) === Number(server.id); });
      if (listed) {
        if (result.probe) {
          listed.probe = result.probe;
          if (data && data.health) listed.health = data.health;
          if (data && data.discovery) listed.discovery = data.discovery;
        }
        if (result.ok && result.snapshot) listed.snapshot = result.snapshot;
      }
    }
    return result;
  }

  return { isVerdict: isVerdict, failureReason: failureReason, read: read, apply: apply };
}));
