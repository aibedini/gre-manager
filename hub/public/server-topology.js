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

  // Read one probe axis.
  //
  // The hub exposes the two axes BOTH as top-level `health`/`discovery` keys and
  // nested under `probe`, so all three of these are live in the field at once:
  //   server.discovery            — current hub
  //   server.probe.discovery      — hub from the previous release
  //   server.probe.ok             — flat single-axis shape, older still
  // Checking each in turn means neither a cached app.js nor a hub mid-upgrade
  // renders every server as "unknown".
  function probeAxis(server, axis) {
    if (!server) return null;
    var direct = server[axis];
    if (direct && typeof direct === 'object') return direct;
    var probe = server.probe;
    if (!probe || typeof probe !== 'object') return null;
    if (probe[axis] && typeof probe[axis] === 'object') return probe[axis];
    // Pre-split flat shape: `probe` WAS the discovery axis.
    if (axis === 'discovery' && probe.ok !== undefined) return probe;
    return null;
  }

  function healthState(server) {
    var axis = probeAxis(server, 'health');
    if (!axis || axis.ok === null || axis.ok === undefined) return 'unknown';
    return axis.ok ? 'healthy' : 'failed';
  }

  function discoveryState(server) {
    var axis = probeAxis(server, 'discovery');
    if (!axis || axis.ok === null || axis.ok === undefined) return 'unknown';
    return axis.ok ? 'ok' : 'failed';
  }

  function healthLabel(server) {
    var state = healthState(server);
    if (state === 'healthy') return 'SSH HEALTHY';
    if (state === 'failed') return 'SSH UNREACHABLE';
    return 'SSH UNKNOWN';
  }

  function discoveryLabel(server) {
    var state = discoveryState(server);
    if (state === 'ok') return 'DISCOVERY OK';
    if (state === 'failed') return 'DISCOVERY FAILED';
    return 'DISCOVERY UNKNOWN';
  }

  // The message an operator should see. `error` is the specific cause recorded by
  // the probe ("gre status --json timed out after 15s"); `reason` is the generic
  // class label ("SSH timeout"). Prefer the specific one — it is the difference
  // between a tooltip that helps and one that just restates the badge.
  function probeReason(server, axis) {
    var which = axis || (discoveryState(server) === 'failed' ? 'discovery' : 'health');
    var found = probeAxis(server, which);
    if (!found || found.ok !== false) return '';
    return found.error || found.reason || 'Probe failed';
  }

  // Does this server still need a successful discovery before it can be grouped?
  // True when nothing authoritative has been read AND the transport is reachable,
  // which is exactly the "SSH fine, topology unknown" state.
  function needsDiscovery(server) {
    var snap = server && server.snapshot;
    if (snap && Array.isArray(snap.roles) && snap.roles.length) return false;
    if (!snap) return true;
    return false;
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
    healthState: healthState,
    discoveryState: discoveryState,
    healthLabel: healthLabel,
    discoveryLabel: discoveryLabel,
    probeReason: probeReason,
    needsDiscovery: needsDiscovery,
    snapshotFreshness: snapshotFreshness,
  };
}));
