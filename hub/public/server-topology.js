/* server-topology.js — how a server is grouped, and how its probe health reads.
 *
 * Loaded as a plain script by the dashboard and required directly by the tests, so
 * the rule that decides "which group is this server in" has exactly ONE
 * implementation. That matters: the production bug being fixed here was a server
 * sliding from FOREIGN to UNCONFIGURED, and a rule with two copies could drift
 * back into disagreeing.
 *
 * The central invariant: TOPOLOGY and AVAILABILITY are separate axes.
 *
 *   roleGroup()      -> comes only from the authoritative snapshot (the last
 *                       discovery that genuinely succeeded)
 *   probeHealth()    -> comes only from the most recent probe attempt
 *
 * A failed probe therefore cannot move a server between groups.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ServerTopology = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // A snapshot older than this is reported as stale: still the best available
  // topology, but demonstrably not fresh. Six hours is deliberately short because
  // topology changes are rare but consequential — a tunnel that was rerouted this
  // morning should not read as current this evening.
  var PROBE_STALE_MS = 6 * 60 * 60 * 1000;

  var PROBE_HEALTH_CLASS = { healthy: 'green', failed: 'red', unknown: 'gray' };

  function rolesOf(server) {
    var snap = server && server.snapshot;
    if (!snap || !Array.isArray(snap.roles)) return [];
    return snap.roles.map(function (role) { return String(role).toUpperCase(); });
  }

  // Group from the authoritative snapshot alone.
  function roleGroup(server) {
    var snap = server && server.snapshot;
    // Nothing has ever been discovered successfully, so nothing is known.
    if (!snap) return 'unconfigured';
    var roles = rolesOf(server);
    if (roles.indexOf('IRAN') !== -1 && roles.indexOf('FOREIGN') !== -1) return 'dual';
    if (roles.indexOf('IRAN') !== -1) return 'iran';
    if (roles.indexOf('FOREIGN') !== -1) return 'foreign';
    // Empty roles, but only because a successful discovery said so: this host has
    // no manager and no role. That is a real finding, not an outage.
    return 'unconfigured';
  }

  function groupLabel(key) {
    return ({ iran: 'IRAN', foreign: 'FOREIGN', dual: 'DUAL ROLE', unconfigured: 'UNCONFIGURED' })[key] || 'UNCONFIGURED';
  }

  // Availability, independent of the group above.
  function probeHealth(server) {
    var probe = server && server.probe;
    if (!probe || probe.ok === null || probe.ok === undefined) return 'unknown';
    return probe.ok ? 'healthy' : 'failed';
  }

  function probeHealthLabel(server) {
    var health = probeHealth(server);
    if (health === 'healthy') return 'HEALTHY';
    if (health === 'failed') return 'PROBE FAILED';
    return 'PROBE UNKNOWN';
  }

  // Sanitised human reason, supplied by the hub (it never carries secrets).
  function probeReason(server) {
    var probe = server && server.probe;
    if (!probe || probe.ok !== false) return '';
    return probe.reason || 'Probe failed';
  }

  // Freshness of the authoritative snapshot, which is a third axis: a topology can
  // be correct-but-old, and the UI must say so rather than implying it is current.
  function snapshotFreshness(server, now) {
    var at = now === undefined ? Date.now() : now;
    var snap = server && server.snapshot;
    if (!snap || !snap.taken_at) return { known: false, stale: true, ageMs: null, text: 'never verified' };
    var taken = new Date(snap.taken_at).getTime();
    if (!isFinite(taken)) return { known: false, stale: true, ageMs: null, text: 'never verified' };
    var ageMs = Math.max(0, at - taken);
    return { known: true, stale: ageMs > PROBE_STALE_MS, ageMs: ageMs, takenAt: taken };
  }

  return {
    PROBE_STALE_MS: PROBE_STALE_MS,
    PROBE_HEALTH_CLASS: PROBE_HEALTH_CLASS,
    rolesOf: rolesOf,
    roleGroup: roleGroup,
    groupLabel: groupLabel,
    probeHealth: probeHealth,
    probeHealthLabel: probeHealthLabel,
    probeReason: probeReason,
    snapshotFreshness: snapshotFreshness,
  };
}));
