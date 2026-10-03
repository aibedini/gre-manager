'use strict';

// Shared read-only inspection primitives.
//
// One implementation for "what does the world actually look like right now",
// reused by:
//   - runtime validation (expects PRESENT)
//   - ACTIVE reconcile  (expects PRESENT)
//   - FAILED reconcile  (expects ABSENT, so absence is success)
//   - delete            (drives actual state to ABSENT, tolerating races)
//
// Design rules learned from production:
//   * NEVER call /panel/api/inbounds/list here. It serializes every inbound's
//     full settings blob and has repeatedly stalled long enough to consume the
//     whole request budget. The only inbound read is the single-inbound detail
//     lookup, and only for the inbound the route already recorded.
//   * Every probe is bounded by its own timeout, so one slow subsystem can never
//     swallow the budget of the others.
//   * Inspection never mutates anything.

const { XuiClient, unwrap } = require('./xui');

// Kept local on purpose: this module must stay independent of the orchestrator
// and of provision.js so both can depend on it without a cycle.
function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// Per-probe budgets. Deliberately small: these are state reads, not transfers.
const TIMEOUTS = {
  greInterface: 10000,
  hostState: 10000,
  listeners: 10000,
  forwarding: 10000,
  panelInbound: 10000,
  managedHost: 10000,
  e2eTcp: 5000,
};

const ABSENT_PATTERNS = [
  'does not exist',
  'not exist',
  'not found',
  'no such',
  'record not found',
  'unknown peer',
  'unknown node',
  'no peer',
  'no node',
];

// A panel/CLI error that means "the thing is already gone". Deleting something
// that is already absent is success, so callers treat this as idempotent.
function isAlreadyAbsentError(err) {
  const text = String(
    (err && (err.panelMsg || err.stderr || err.message)) || err || ''
  ).toLowerCase();
  return ABSENT_PATTERNS.some((pattern) => text.includes(pattern));
}

function timeoutLike(err) {
  const text = String((err && (err.message || err.name)) || '').toLowerCase();
  return text.includes('timeout') || text.includes('timed out') || text.includes('aborted');
}

// Bounded wrapper: resolves to { ok, value } or { ok:false, error } and NEVER
// rejects, so Promise.allSettled callers cannot lose sibling results.
async function bounded(label, timeoutMs, fn) {
  try {
    const value = await fn();
    return { ok: true, value };
  } catch (err) {
    const detail = timeoutLike(err)
      ? `${label} timed out after ${Math.round(timeoutMs / 1000)}s`
      : `${label} failed: ${err && err.message ? err.message : err}`;
    return { ok: false, error: detail, raw: err };
  }
}

// Remote command with an explicit timeout. The orchestrator's remote() accepts
// one, and a timeout is reported by ssh as rc=-1 with a stderr message.
async function runRemote(orchestrator, server, command, timeoutMs) {
  const result = await orchestrator.remote(server, command, timeoutMs);
  const stdout = String((result && result.stdout) || '');
  const stderr = String((result && result.stderr) || '');
  if (!result || result.rc !== 0) {
    const err = new Error(stderr.trim() || stdout.trim() || `rc=${result && result.rc}`);
    err.stderr = stderr;
    err.stdout = stdout;
    throw err;
  }
  return { stdout, stderr };
}

// ---------------------------------------------------------------------------
// GRE
// ---------------------------------------------------------------------------

async function inspectGreInterface(orchestrator, server, peerName, side) {
  const label = `${side} GRE interface`;
  if (!peerName) {
    return { present: false, detail: `${side} has no recorded peer name`, absent: true };
  }
  return bounded(label, TIMEOUTS.greInterface, async () => {
    const device = `gre-${peerName}`;
    // ONE `ip link` invocation. Two things matter here and both come from this
    // single bounded command: whether the device exists at all, and whether the
    // kernel reports it UP.
    const { stdout } = await runRemote(orchestrator, server,
      `ip link show ${shellQuote(device)} 2>/dev/null || echo MISSING`, TIMEOUTS.greInterface);

    const text = String(stdout || '').trim();
    if (!text || text === 'MISSING') {
      return { present: false, up: false, detail: `${device} is absent on ${server.name}` };
    }
    // `ip link show` prints "<POINTOPOINT,NOARP,UP,LOWER_UP>" when the link is up.
    const up = /<[^>]*\bUP\b[^>]*>/.test(text) || text === 'UP';
    const address = (text.match(/\b(\d+\.\d+\.\d+\.\d+\/\d+)\b/) || [])[1] || '';
    return {
      present: true,
      up,
      address,
      detail: up
        ? `${device} UP${address ? `; ${address}` : ''}`
        : `${device} exists but is not UP`,
    };
  }).then((r) => (r.ok ? r.value : { present: null, up: null, detail: r.error, error: r.error }));
}

// ---------------------------------------------------------------------------
// IRAN forwarding + FOREIGN listeners
//
// Both come from ONE bounded SSH read per side rather than a panel inventory.
// ---------------------------------------------------------------------------

// The host probe shape used for port checks. Deliberately identical to
// RouteOrchestrator.probeCommand() (it is not exported, and importing the
// orchestrator here would create a cycle): reusing it means runtime validation
// costs one command the pre-flight already issues, and every test double that
// models the pre-flight models this too.
function hostProbeCommand() {
  return [
    "echo '---listeners---'", 'ss -H -lntup 2>/dev/null || true',
    "echo '---nft---'", 'nft list ruleset 2>/dev/null || true',
    "echo '---iptables---'", 'iptables-save 2>/dev/null || true',
    "echo '---docker---'", "docker ps --format '{{.Ports}}' 2>/dev/null || true",
  ].join('; ');
}

// Extract the port from a matched evidence line. Handles the iptables/nft forms
// ("--dport 3001") and the ss forms ("0.0.0.0:3001", "[::]:3001").
function portOfEvidenceLine(line) {
  const dport = String(line).match(/(?:--dport|dport|sport)\s+\{?\s*(\d+)/i);
  if (dport) return Number(dport[1]);
  const lastNumber = String(line).match(/\d+(?!.*\d)/);
  return lastNumber ? Number(lastNumber[0]) : null;
}

// Split matched lines into "a rule/listener for THIS port exists" + the exact
// evidence, so the timeline and the failure message can quote what was seen.
function evidenceForPort(lines, port) {
  const rows = Array.isArray(lines) ? lines : [];
  const forThisPort = rows.filter((line) => portOfEvidenceLine(line) === Number(port));
  return { found: forThisPort.length > 0, lines: forThisPort.slice(0, 6) };
}

// A rule/listener dump is matched with the project's canonical `portEvidence`,
// passed in by the orchestrator which owns it. One matcher therefore serves
// pre-flight port checks, runtime validation, reconcile and delete.
async function inspectForwarding(orchestrator, server, port, portEvidence) {
  return bounded('IRAN forwarding rules', TIMEOUTS.forwarding, async () => {
    const { stdout } = await runRemote(orchestrator, server, hostProbeCommand(), TIMEOUTS.forwarding);
    const evidence = evidenceForPort(portEvidence(stdout, port), port);
    return {
      tcp: evidence.found,
      udp: evidence.found,
      lines: evidence.lines,
      detail: evidence.found
        ? `IRAN forwarding rule for ${port} present`
        : `no IRAN forwarding rule for ${port}`,
    };
  }).then((r) => (r.ok ? r.value : { tcp: null, udp: null, detail: r.error, error: r.error }));
}

async function inspectListeners(orchestrator, server, port, portEvidence) {
  return bounded('FOREIGN listeners', TIMEOUTS.listeners, async () => {
    const { stdout } = await runRemote(orchestrator, server, hostProbeCommand(), TIMEOUTS.listeners);
    const evidence = evidenceForPort(portEvidence(stdout, port), port);
    return {
      tcp: evidence.found,
      udp: evidence.found,
      lines: evidence.lines,
      detail: evidence.found
        ? `FOREIGN listener on :${port} present`
        : `nothing listening on :${port} on ${server.name}`,
    };
  }).then((r) => (r.ok ? r.value : { tcp: null, udp: null, detail: r.error, error: r.error }));
}

// ---------------------------------------------------------------------------
// 3x-ui: one inbound, and client membership inside it
//
// The route already knows its inbound id, so the only panel read is the
// single-inbound detail. Membership is answered from settings.clients[] of that
// same response, which keeps first-class panels off /clients/list,
// /clients/links and /clients/get entirely.
// ---------------------------------------------------------------------------

async function inspectInbound(orchestrator, client, inboundId) {
  const id = Number(inboundId);
  if (!Number.isInteger(id) || id <= 0) {
    return { present: false, detail: 'no inbound id recorded', absent: true, protocol: null, port: null };
  }
  return bounded('3x-ui inbound lookup', TIMEOUTS.panelInbound, async () => {
    const result = await client.request(`/panel/api/inbounds/get/${id}`, { allowFailure: true });
    if (!result || !result.ok) {
      if (result && (result.status === 404 || result.status === 405)) {
        return { present: false, detail: `inbound #${id} is absent`, protocol: null, port: null, settings: null };
      }
      const body = result && result.data;
      const detail = body && (body.msg || body.error) || `HTTP ${result && result.status}`;
      throw new Error(detail);
    }
    const inbound = unwrap(result.data);
    if (!inbound || typeof inbound !== 'object') throw new Error('panel returned no inbound object');
    return {
      present: true,
      protocol: inbound.protocol ? String(inbound.protocol) : null,
      port: Number.isFinite(Number(inbound.port)) ? Number(inbound.port) : null,
      remark: inbound.remark ? String(inbound.remark) : '',
      settings: XuiClient.normalizeSettings(inbound.settings),
      detail: `inbound #${id} protocol=${inbound.protocol || '?'} port=${inbound.port || '?'}`,
    };
  }).then((r) => (r.ok ? r.value : { present: null, detail: r.error, error: r.error, protocol: null, port: null, settings: null }));
}

// Membership from the inbound we already fetched. `inbound` is the resolved
// inspection result so this costs nothing extra.
function clientInInbound(inbound, email) {
  const wanted = String(email || '').trim();
  if (!inbound || !inbound.settings || !Array.isArray(inbound.settings.clients)) return false;
  return inbound.settings.clients.some((c) => String((c && c.email) || '').trim() === wanted);
}

// Independent membership read for callers that do not already hold the inbound.
async function inspectClientAttachment(orchestrator, client, inboundId, email) {
  const inbound = await inspectInbound(orchestrator, client, inboundId);
  if (inbound.error) return { attached: null, detail: inbound.error, error: inbound.error };
  if (!inbound.present) return { attached: false, detail: `inbound #${inboundId} is absent, so the attachment is absent` };
  const attached = clientInInbound(inbound, email);
  return {
    attached,
    detail: attached
      ? `${email} attached to inbound #${inboundId}`
      : `${email} is not present in inbound #${inboundId}`,
  };
}

// ---------------------------------------------------------------------------
// Managed host
// ---------------------------------------------------------------------------

async function inspectManagedHost(orchestrator, client, hostGroupId) {
  if (!hostGroupId) {
    return { present: false, detail: 'no managed host recorded', absent: true };
  }
  return bounded('managed host lookup', TIMEOUTS.managedHost, async () => {
    if (typeof client.listHosts !== 'function') {
      return { present: true, verified: false, detail: `managed host ${hostGroupId} recorded (no narrow lookup available)` };
    }
    const hosts = await client.listHosts();
    const rows = Array.isArray(hosts) ? hosts : [];
    // An empty listing is not evidence of absence: panel builds differ in what
    // /hosts/list returns, and some report nothing for host groups created
    // through the API. Treating that as ABSENT would tear down a route whose
    // host is working. Report it as an unverified WARN instead.
    if (!rows.length) {
      return {
        present: true,
        verified: false,
        detail: `managed host ${hostGroupId} recorded; panel returned no host list to confirm it`,
      };
    }
    const found = rows.some((h) => String((h && (h.groupId || h.id)) || '') === String(hostGroupId));
    if (!found) {
      return {
        present: true,
        verified: false,
        detail: `managed host ${hostGroupId} recorded but not listed by the panel (${rows.length} host(s) returned)`,
      };
    }
    return { present: true, verified: true, detail: `public endpoint host ${hostGroupId} present` };
  }).then((r) => (r.ok ? r.value : { present: null, detail: r.error, error: r.error }));
}

// ---------------------------------------------------------------------------
// Port allocation registry (always local, never remote)
// ---------------------------------------------------------------------------

function inspectPortAllocation(db, routeId) {
  const row = db.prepare(`
    SELECT p.*, r.name AS route_name FROM port_allocations p
    JOIN gre_routes r ON r.id = p.route_id
    WHERE p.route_id = ?
  `).get(Number(routeId));
  if (!row) return { present: false, port: null, status: null, detail: 'no allocation row' };
  return {
    present: true,
    port: Number(row.port),
    status: String(row.status || ''),
    detail: `allocation ${row.port} is ${row.status}`,
  };
}

// ---------------------------------------------------------------------------
// End-to-end TCP
//
// Proves the published endpoint accepts a connection. Deliberately does NOT
// attempt a Shadowsocks handshake: a successful TCP connect through
// client -> IRAN forwarding -> GRE -> FOREIGN listener is what we can honestly
// assert, and a half-implemented protocol probe would be worse than none.
// ---------------------------------------------------------------------------

async function probeTcpConnect(orchestrator, server, host, port) {
  return bounded('end-to-end TCP', TIMEOUTS.e2eTcp, async () => {
    // No remote `timeout` wrapper: the SSH-level timeout is what bounds this, and
    // running both at once makes the outcome depend on which fires first, which
    // turned a working path into an occasional false failure. Closing the session
    // also tears down the remote bash, so a hung connect cannot leak.
    await runRemote(orchestrator, server, `bash -c ${shellQuote(`exec 3<>/dev/tcp/${host}/${port}`)}`, TIMEOUTS.e2eTcp);
    return { connected: true, detail: `${host}:${port} accepted TCP` };
  }).then((r) => (r.ok ? r.value : { connected: null, detail: r.error, error: r.error }));
}

module.exports = {
  TIMEOUTS,
  isAlreadyAbsentError,
  timeoutLike,
  bounded,
  runRemote,
  inspectGreInterface,
  inspectForwarding,
  inspectListeners,
  inspectInbound,
  clientInInbound,
  inspectClientAttachment,
  inspectManagedHost,
  inspectPortAllocation,
  probeTcpConnect,
};
