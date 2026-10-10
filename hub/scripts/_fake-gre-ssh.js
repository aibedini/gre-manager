'use strict';
// _fake-gre-ssh.js — a scripted, STATEFUL fake of the `gre` CLI surface the Hub
// drives during a connection edit, a migration or an MTU change.
//
// Unlike the provisioning fake, this one has to hold real state: a peer_edit on
// one server must be visible to the next `peer list --json` on that same server, and
// a `gre mtu set` must be visible to the next `gre mtu diagnose` and readable back
// from the interface, or the Hub's verification step would be meaningless and its
// tests would pass for the wrong reason.
//
// The health layer needs one more kind of state than a parameter change does: a
// DIAGNOSIS. A finding seeded on a host must survive until a repair removes it, and
// that removal has to be visible to the next `gre health-check` — otherwise the Hub's
// "verify with a fresh check" step would pass for the wrong reason.
//
// Faults are injected through HUB_TEST_GRE_FAULT (a JSON file, re-read on every
// call so one process can drive several scenarios):
//   { "fail": { "<server name>": ["peer_edit", "doctor", "mtu_set", "health_check"] },
//     "ping_fail": ["<server name>"],
//     "reachability_fail": ["<server name>"],
//     "repair_noop": ["<server name>"],
//     "unreachable": ["<server name>"] }
//
// Loaded via HUB_TEST_SSH_MODULE.

const fs = require('fs');

const FAULT_FILE = process.env.HUB_TEST_GRE_FAULT || '';
let faultCache = { loadedAt: 0, faults: {} };
let faultStamp = -1;

function faults() {
  if (!FAULT_FILE) return {};
  const now = Date.now();
  if (now - faultCache.loadedAt < 80) return faultCache.faults;
  faultCache = { loadedAt: now, faults: {} };
  let stamp = now;
  try { stamp = fs.statSync(FAULT_FILE).mtimeMs; } catch { stamp = now; }
  try {
    faultCache.faults = JSON.parse(fs.readFileSync(FAULT_FILE, 'utf8'));
  } catch { faultCache.faults = {}; }
  // `reset_calls` zeroes the per-verb call counters, and it has to happen exactly ONCE
  // per written fault set: the cache expires every 80ms, so clearing on every reload
  // would reset a counter in the middle of the scenario that depends on it and make
  // "the second mtu_set fails" silently become "the first one does not".
  if (stamp !== faultStamp) {
    faultStamp = stamp;
    if (faultCache.faults && faultCache.faults.reset_calls) {
      for (const st of state.values()) st.calls = {};
    }
  }
  return faultCache.faults;
}

// Per-server state, keyed by host so it survives across requests.
const state = new Map();

// Optional initial state, so a test can present servers that ALREADY carry the
// connection being edited. Without this, an edit would be applied to a host that
// never had the peer, and the test would prove nothing about editing.
//
// This is loaded LAZILY rather than at require time: the hub requires its
// transport override while starting up, which is before a test has had a chance to
// write the seed. Reading on first use (and re-reading when the file changes) makes
// the seed reliable regardless of that ordering.
const SEED_FILE = process.env.HUB_TEST_GRE_SEED || '';
let seedStamp = 0;
let seedLoaded = false;

function loadSeed(force) {
  if (!SEED_FILE) return;
  let stat;
  try { stat = fs.statSync(SEED_FILE); } catch { return; }
  if (!force && seedLoaded && stat.mtimeMs === seedStamp) return;
  seedStamp = stat.mtimeMs;
  seedLoaded = true;
  let seed;
  try { seed = JSON.parse(fs.readFileSync(SEED_FILE, 'utf8')); } catch { return; }
  for (const [host, value] of Object.entries(seed)) {
    const existing = state.get(host) || emptyHost();
    // An explicitly seeded host replaces its list; anything a test already did
    // through the API is preserved for hosts the seed does not mention.
    state.set(host, {
      peers: value.peers || existing.peers,
      nodes: value.nodes || existing.nodes,
      events: existing.events,
      commands: existing.commands,
      calls: existing.calls,
      nic_mtu: value.nic_mtu || existing.nic_mtu,
      probe: value.probe || existing.probe,
      mtu: { ...existing.mtu, ...(value.mtu || {}) },
      health: value.health !== undefined ? value.health : existing.health,
    });
  }
}

function emptyHost() {
  return { peers: [], nodes: [], events: [], commands: [], calls: {}, nic_mtu: 1500, probe: {}, mtu: {}, health: {} };
}

function forServer(server) {
  loadSeed(false);
  const key = server.host || server.name;
  if (!state.has(key)) state.set(key, emptyHost());
  return state.get(key);
}

function parseArgs(command) {
  const tokens = command.match(/'[^']*'|\S+/g) || [];
  const out = { _: [] };
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.startsWith('--')) {
      const name = t.slice(2);
      const next = tokens[i + 1];
      if (next && !next.startsWith('--')) { out[name] = next.replace(/^'|'$/g, ''); i += 1; } else { out[name] = true; }
    } else {
      out._.push(t.replace(/^'|'$/g, ''));
    }
  }
  return out;
}

function faulted(server, verb) {
  const f = faults();
  const list = (f.fail && f.fail[server.name]) || [];
  if (list.includes(verb)) return true;
  // fail_from lets a scenario fail a verb only after N successful calls, which is how a
  // rollback is made to fail without also breaking the change that needs rolling back.
  const from = (f.fail_from && f.fail_from[server.name]) || {};
  const threshold = from[verb];
  if (threshold !== undefined) {
    const st = state.get(server.host || server.name);
    const count = st && st.calls ? (st.calls[verb] || 0) : 0;
    if (count >= Number(threshold)) return true;
  }
  if ((f.unreachable || []).includes(server.name)) return true;
  return false;
}

function fail(verb, server) {
  return { rc: 1, stdout: '', stderr: `injected failure: ${verb} on ${server.name}` };
}

// Which verb a command is, for fault injection and for the "did anything recreate the
// tunnel?" assertion an MTU test needs.
function verbOf(command) {
  if (/gre health-check/.test(command)) return 'health_check';
  if (/gre repair apply/.test(command)) return 'repair_apply';
  if (/gre repair preview/.test(command)) return 'repair_preview';
  if (/gre mtu nic analyze/.test(command)) return 'mtu_nic_analyze';
  if (/gre mtu nic list/.test(command)) return 'mtu_nic_list_json';
  if (/gre mtu diagnose/.test(command)) return 'mtu_diagnose';
  if (/gre mtu recommend/.test(command)) return 'mtu_recommend';
  if (/gre mtu auto/.test(command)) return 'mtu_auto';
  if (/gre mtu restore/.test(command)) return 'mtu_restore';
  if (/gre mtu set/.test(command)) return 'mtu_set';
  if (/gre mtu list/.test(command)) return 'mtu_list_json';
  if (/gre tunnel diagnose/.test(command)) return 'tunnel_diagnose';
  if (/gre tunnel (add|del|recreate|rebuild|apply)/.test(command)) return 'tunnel_rebuild';
  if (/gre iran peer edit/.test(command)) return 'peer_edit';
  if (/gre iran peer add/.test(command)) return 'peer_add';
  if (/gre iran peer remove/.test(command)) return 'peer_remove';
  if (/gre node edit/.test(command)) return 'node_edit';
  if (/gre node add/.test(command)) return 'node_add';
  if (/gre node remove/.test(command)) return 'node_remove';
  if (/gre iran peer list/.test(command)) return 'peer_list_json';
  if (/gre node list/.test(command)) return 'node_list_json';
  if (/gre status/.test(command)) return 'status_json';
  if (/gre doctor/.test(command)) return 'doctor';
  if (/ping -c/.test(command)) return 'ping';
  return 'other';
}

// The verbs that would rebuild a tunnel rather than adjust a parameter. An MTU change
// must never appear as one of these.
const TUNNEL_REBUILD_VERBS = ['peer_edit', 'node_edit', 'peer_add', 'node_add', 'peer_remove', 'node_remove', 'tunnel_rebuild'];

// Everything that writes to a host. A read-only health check must not appear as one of
// these, which is what the read-only guarantee is asserted against.
const MUTATING_VERBS = [...TUNNEL_REBUILD_VERBS, 'repair_apply', 'mtu_set', 'mtu_restore'];

// ---------------------------------------------------------------- health state
//
// The repair table mirrors the CLI's own: a code maps to the repair it offers, and the
// repair's safety and risk come from that key. Seeding just { code, severity } is
// therefore enough to model a real finding.
const HEALTH_REPAIR_TABLE = {
  mtu_set: { safe: true, risk: 'low', action: "Set this connection's tunnel MTU from the measured path" },
  rule_restore: { safe: true, risk: 'low', action: 'Reinstall the missing rule this connection owns' },
  iface_up: { safe: true, risk: 'low', action: 'Bring the configured tunnel interface up' },
  peer_apply: { safe: true, risk: 'medium', action: 'Reapply this connection (rebuilds its tunnel and rules)' },
  mss_clamp: { safe: true, risk: 'low', action: 'Reinstall the TCP MSS clamp for the measured MTU' },
  endpoint: { safe: false, risk: 'high', action: 'The public endpoint must be corrected on both servers by hand' },
  wan_mtu: { safe: false, risk: 'high', action: 'A WAN NIC MTU change is not automated: it can sever SSH' },
  provider: { safe: false, risk: 'high', action: 'Nothing on this host can fix an upstream filter' },
};

const HEALTH_CODE_REPAIR = {
  GRE_MODULE_MISSING: 'provider',
  GRE_ROUTE_LOOP: 'peer_apply',
  UNDERLAY_UNREACHABLE: 'provider',
  UNDERLAY_PACKET_LOSS: 'provider',
  GRE_INTERFACE_MISSING: 'iface_up',
  GRE_INTERFACE_DOWN: 'iface_up',
  GRE_LOCAL_ENDPOINT_MISMATCH: 'peer_apply',
  GRE_REMOTE_ENDPOINT_MISMATCH: 'peer_apply',
  GRE_KEY_MISMATCH: 'peer_apply',
  GRE_TUNNEL_ADDRESS_MISSING: 'peer_apply',
  GRE_ROUTE_MISSING: 'peer_apply',
  GRE_PROTOCOL47_SUSPECTED_BLOCKED: 'rule_restore',
  GRE_ONE_WAY_TRAFFIC: 'mtu_set',
  GRE_INNER_PING_FAILED: 'peer_apply',
  IP_FORWARD_DISABLED: 'rule_restore',
  FIREWALL_RULE_MISSING: 'rule_restore',
  FIREWALL_RULE_CONFLICT: 'endpoint',
  GRE_MTU_MISMATCH: 'mtu_set',
  GRE_TCP_MSS_PROBLEM: 'mss_clamp',
  SERVICE_LISTENER_MISSING: 'endpoint',
  XUI_INBOUND_MISSING: 'endpoint',
};

// The check a finding degrades, so a seeded finding is consistent with the check table
// the Hub renders instead of only appearing in the findings list.
const HEALTH_CODE_CHECK = {
  GRE_MODULE_MISSING: 'gre_module',
  GRE_ROUTE_LOOP: 'no_route_loop',
  UNDERLAY_UNREACHABLE: 'underlay_ping',
  UNDERLAY_PACKET_LOSS: 'underlay_ping',
  GRE_INTERFACE_MISSING: 'interface_exists',
  GRE_INTERFACE_DOWN: 'interface_up',
  GRE_LOCAL_ENDPOINT_MISMATCH: 'local_endpoint',
  GRE_REMOTE_ENDPOINT_MISMATCH: 'remote_endpoint',
  GRE_KEY_MISMATCH: 'gre_key',
  GRE_TUNNEL_ADDRESS_MISSING: 'tunnel_address',
  GRE_SUBNET_MISMATCH: 'tunnel_address',
  GRE_ROUTE_MISSING: 'inner_route',
  GRE_PROTOCOL47_SUSPECTED_BLOCKED: 'gre47_local_policy',
  GRE_ONE_WAY_TRAFFIC: 'inner_ping',
  GRE_INNER_PING_FAILED: 'inner_ping',
  IP_FORWARD_DISABLED: 'ip_forward',
  FIREWALL_RULE_MISSING: 'owned_rules',
  FIREWALL_RULE_CONFLICT: 'port_conflicts',
  GRE_MTU_MISMATCH: 'mtu_recommendation',
  GRE_TCP_MSS_PROBLEM: 'mss_clamp',
  GRE_PMTUD_BLACKHOLE_SUSPECTED: 'pmtud',
  SERVICE_LISTENER_MISSING: 'service_layer',
  XUI_INBOUND_MISSING: 'service_port',
};

function healthEntry(st, name) {
  if (!st.health || typeof st.health !== 'object') st.health = {};
  if (!st.health[name]) st.health[name] = { findings: [], checks: [], completeness: null };
  const entry = st.health[name];
  if (!Array.isArray(entry.findings)) entry.findings = [];
  if (!Array.isArray(entry.checks)) entry.checks = [];
  return entry;
}

function healthFinding(raw, serverName) {
  const repair = raw.repair_key !== undefined ? raw.repair_key : (HEALTH_CODE_REPAIR[raw.code] || '');
  const table = HEALTH_REPAIR_TABLE[repair] || null;
  return {
    code: raw.code,
    severity: raw.severity || 'warning',
    server: raw.server || serverName,
    connection: raw.connection || '',
    confidence: raw.confidence || 'high',
    evidence: raw.evidence || `${raw.code} was observed on ${serverName}`,
    probable_cause: raw.probable_cause || 'the condition this code names was observed',
    recommended_action: raw.recommended_action || (table ? table.action : ''),
    safe_repair: raw.safe_repair === undefined ? !!(table && table.safe) : raw.safe_repair === true,
    risk: raw.risk || (table ? table.risk : 'none'),
    repair_key: repair,
  };
}

// The health check reads the CURRENT state of this host, so a repair that removed a
// finding is immediately visible here — which is the whole point of the Hub's
// verification step.
function healthBuild(st, name, mode, serverName) {
  const side = sideOf(st, name);
  if (!side) return null;
  const entry = healthEntry(st, name);
  const mtuE = st.mtu[name] || {};
  const nic = mtuE.nic_mtu === undefined ? (st.nic_mtu || 1500) : mtuE.nic_mtu;
  const greMtu = mtuE.gre_mtu === undefined ? MTU_DEFAULTS.gre_mtu : mtuE.gre_mtu;
  const quick = mode === 'quick';
  const peer = st.peers.find((p) => p.name === name) || null;
  const mssOn = !(peer && peer.mss_clamp === 'off');

  const checks = [
    { id: 'control_plane', category: 'A_ssh_and_server', status: 'PASS', detail: `ran on ${serverName}` },
    { id: 'privilege', category: 'A_ssh_and_server', status: 'PASS', detail: 'running as root' },
    { id: 'gre_module', category: 'A_ssh_and_server', status: 'PASS', detail: 'ip_gre is loaded' },
    { id: 'sshd_listening', category: 'A_ssh_and_server', status: quick ? 'SKIPPED' : 'PASS', detail: quick ? 'quick check' : 'sshd is listening' },
    { id: 'route_to_peer', category: 'B_underlay', status: 'PASS', detail: '198.51.100.1 via 192.0.2.1 dev eth0' },
    { id: 'no_route_loop', category: 'B_underlay', status: 'PASS', detail: 'the peer route does not use the tunnel' },
    { id: 'underlay_ping', category: 'B_underlay', status: 'PASS', detail: 'reachable, 4.2 ms average, no loss', evidence: 'loss=0 rtt=4.2' },
    { id: 'policy_routing', category: 'B_underlay', status: 'PASS', detail: 'only the default routing rules are present' },
    { id: 'interface_exists', category: 'C_gre_config', status: 'PASS', detail: `gre-${name} is present` },
    { id: 'interface_up', category: 'C_gre_config', status: 'PASS', detail: `gre-${name} is up` },
    { id: 'local_endpoint', category: 'C_gre_config', status: 'PASS', detail: '198.51.100.20' },
    { id: 'remote_endpoint', category: 'C_gre_config', status: 'PASS', detail: '203.0.113.10' },
    { id: 'gre_key', category: 'C_gre_config', status: 'PASS', detail: `${(peer && peer.key) || 1001}` },
    { id: 'tunnel_address', category: 'C_gre_config', status: 'PASS', detail: side === 'iran' ? '10.200.1.2/30' : '10.200.1.1/30' },
    { id: 'inner_route', category: 'C_gre_config', status: quick ? 'SKIPPED' : 'PASS', detail: quick ? 'quick check' : `the peer's tunnel address routes via gre-${name}` },
    { id: 'gre47_local_policy', category: 'D_gre_protocol47', status: 'PASS', detail: 'the local firewall does not drop this peer\'s GRE' },
    { id: 'gre47_traffic', category: 'D_gre_protocol47', status: quick ? 'SKIPPED' : 'PASS', detail: quick ? 'quick check' : 'GRE packets were observed on this host' },
    { id: 'inner_ping', category: 'E_tunnel_connectivity', status: quick ? 'SKIPPED' : 'PASS', detail: quick ? 'quick check' : 'the peer tunnel address replies, 4.6 ms average', evidence: 'loss=0 rtt=4.6' },
    { id: 'ip_forward', category: 'F_routing_and_firewall', status: 'PASS', detail: 'net.ipv4.ip_forward=1' },
    { id: 'owned_rules', category: 'F_routing_and_firewall', status: 'PASS', detail: 'every rule this connection owns is installed' },
    { id: 'port_conflicts', category: 'F_routing_and_firewall', status: 'PASS', detail: 'no other connection claims these ports' },
    { id: 'underlay_mtu', category: 'G_mtu_and_mss', status: 'PASS', detail: `eth0 mtu ${nic}` },
    { id: 'tunnel_mtu', category: 'G_mtu_and_mss', status: 'PASS', detail: `gre-${name} mtu ${greMtu}` },
    { id: 'mtu_recommendation', category: 'G_mtu_and_mss', status: 'PASS', detail: 'the current MTU matches the path' },
    { id: 'mss_clamp', category: 'G_mtu_and_mss', status: mssOn ? 'PASS' : 'SKIPPED', detail: mssOn ? 'MSS clamped to 1436' : 'MSS clamping is disabled for this connection' },
    { id: 'pmtud', category: 'G_mtu_and_mss', status: quick ? 'SKIPPED' : 'PASS', detail: quick ? 'quick check' : 'DF probing worked' },
    { id: 'service_layer', category: 'H_service', status: 'SKIPPED', detail: 'this connection has no panel configured' },
    { id: 'service_port', category: 'H_service', status: 'SKIPPED', detail: 'no TCP port, or ss is unavailable' },
  ];

  const merge = (row) => {
    const at = checks.findIndex((c) => c.id === row.id);
    if (at === -1) checks.push({ category: 'Z_diagnostic', ...row });
    else checks[at] = { ...checks[at], ...row };
  };

  const findings = entry.findings.map((f) => healthFinding({ connection: name, ...f }, serverName));

  // A finding degrades the check it came from, so the counts and the findings agree.
  for (const finding of findings) {
    const id = HEALTH_CODE_CHECK[finding.code];
    if (!id) continue;
    const at = checks.findIndex((c) => c.id === id);
    const status = finding.severity === 'critical' ? 'FAIL' : finding.severity === 'warning' ? 'WARN' : 'UNKNOWN';
    if (at !== -1 && checks[at].status !== 'FAIL') checks[at] = { ...checks[at], status };
  }
  for (const override of entry.checks) merge(override);

  const counts = { pass: 0, warn: 0, fail: 0, unknown: 0, skipped: 0, critical_findings: 0 };
  for (const check of checks) {
    if (check.status === 'PASS') counts.pass += 1;
    else if (check.status === 'WARN') counts.warn += 1;
    else if (check.status === 'FAIL') counts.fail += 1;
    else if (check.status === 'SKIPPED') counts.skipped += 1;
    else counts.unknown += 1;
  }
  counts.critical_findings = findings.filter((f) => f.severity === 'critical').length;

  let overall = 'HEALTHY';
  if (counts.fail > 0 || counts.critical_findings > 0) overall = 'BROKEN';
  else if (counts.warn > 0 || counts.unknown > 0 || findings.length > 0) overall = 'DEGRADED';

  const completeness = entry.completeness || (counts.unknown > 0 ? 'partial' : 'complete');

  return {
    connection: name,
    side,
    server: serverName,
    mode: quick ? 'quick' : 'full',
    overall_status: overall,
    evidence_completeness: completeness,
    budget_seconds: quick ? 20 : 75,
    elapsed_seconds: quick ? 2 : 5,
    summary: counts,
    checks,
    findings,
    tested_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------- MTU state

const MTU_DEFAULTS = { gre_mtu: 1476, overhead: 28 };

function mtuEntry(st, name) {
  if (!st.mtu[name]) {
    st.mtu[name] = { nic_mtu: st.nic_mtu || 1500, overhead: MTU_DEFAULTS.overhead, gre_mtu: MTU_DEFAULTS.gre_mtu, previous: null, history: [] };
  }
  const entry = st.mtu[name];
  if (entry.nic_mtu === undefined || entry.nic_mtu === null) entry.nic_mtu = st.nic_mtu || 1500;
  if (entry.overhead === undefined || entry.overhead === null) entry.overhead = MTU_DEFAULTS.overhead;
  if (entry.gre_mtu === undefined || entry.gre_mtu === null) entry.gre_mtu = MTU_DEFAULTS.gre_mtu;
  if (!Array.isArray(entry.history)) entry.history = [];
  return entry;
}

function sideOf(st, name) {
  if (st.peers.some((p) => p.name === name)) return 'iran';
  if (st.nodes.some((n) => n.name === name)) return 'foreign';
  return null;
}

function mtuDiagnose(st, name) {
  const side = sideOf(st, name);
  if (!side) return null;
  const entry = mtuEntry(st, name);
  const peer = st.peers.find((p) => p.name === name) || null;
  const node = st.nodes.find((n) => n.name === name) || null;
  const idx = (peer && peer.idx) || (node && node.idx) || 1;
  const key = (peer && peer.key) || (node && node.key) || 0;
  const nic = entry.nic_mtu;
  const gre = entry.gre_mtu;
  const overhead = entry.overhead;
  const innerCidr = side === 'iran' ? `10.200.${idx}.2/30` : `10.200.${idx}.1/30`;
  const local = side === 'iran' ? '198.51.100.20' : '203.0.113.10';
  const remote = side === 'iran' ? '203.0.113.10' : '198.51.100.20';
  const outerState = st.probe && st.probe.outer ? st.probe.outer : 'PASS';
  const innerState = st.probe && st.probe.inner ? st.probe.inner : 'PASS';
  const mssOn = !(peer && peer.mss_clamp === 'off');
  const checks = [
    { id: 'underlay_mtu', status: 'PASS', detail: `eth0 mtu ${nic}` },
    { id: 'tunnel_mtu', status: 'PASS', detail: `gre-${name} mtu ${gre}` },
    { id: 'encapsulation_overhead', status: 'PASS', detail: `${overhead} bytes` },
    { id: 'mss_clamp', status: mssOn ? 'PASS' : 'WARN', detail: mssOn ? 'clamped to pmtu' : 'not clamped' },
    { id: 'inner_pmtu', status: innerState, detail: innerState === 'PASS' ? 'probe found a working size' : 'probe could not run' },
  ];
  const counts = { pass: 0, warn: 0, fail: 0, unknown: 0 };
  for (const c of checks) {
    if (c.status === 'PASS') counts.pass += 1;
    else if (c.status === 'WARN') counts.warn += 1;
    else if (c.status === 'FAIL') counts.fail += 1;
    else counts.unknown += 1;
  }
  const recommended = nic - overhead;
  return {
    name,
    side,
    tunnel: `gre-${name}`,
    generated_at: new Date().toISOString(),
    summary: counts,
    checks,
    underlay: {
      iface: 'eth0', mtu: nic, route: `${remote} via 192.0.2.1 dev eth0 src ${local}`,
      src: local, dst: remote, route_mtu: null, icmp_frag_needed: 'seen',
    },
    gre: {
      tun: `gre-${name}`, encap: 'gre', key: Number(key), flags: [], outer_ipv: 4,
      local, remote, mtu: gre, inner_cidr: innerCidr, overhead,
      counters: { rx_bytes: 1024, tx_bytes: 2048, rx_errors: 0, tx_errors: 0, rx_dropped: 0 },
    },
    pmtu: {
      inner_probe: innerState === 'PASS'
        ? { state: 'PASS', max_ok: gre, frag_needed_at: gre + 1, probes_sent: 9 }
        : { state: innerState, max_ok: null, frag_needed_at: null, probes_sent: 0 },
      outer_probe: outerState === 'PASS'
        ? { state: 'PASS', max_ok: nic, frag_needed_at: null, probes_sent: 9 }
        : { state: outerState, max_ok: null, frag_needed_at: null, probes_sent: 0 },
    },
    mss_clamp: { enabled: mssOn, mode: mssOn ? 'pmtu' : 'absent', value: null, scoped_to_connection: true },
    recommendation: {
      connection: name, underlay_mtu: nic, encapsulation_overhead: overhead, current_gre_mtu: gre,
      recommended_gre_mtu: recommended, confidence: 'high', requires_change: gre !== recommended,
      reason: 'underlay capacity minus encapsulation overhead',
      safe_to_apply: true, safety_margin: 0, margin_reason: '', min_legal_mtu: 576, asymmetric: false,
    },
  };
}

// `gre iran peer list --json` / `gre node list --json` are what the Hub verifies
// against, so the output shape has to match the real CLI's.
function listJson(entries, kind) {
  return JSON.stringify(entries.map((e) => (kind === 'peer'
    ? {
      name: e.name, iran_ip: e.iran_ip, foreign_ip: e.foreign_ip,
      subnet_base: e.subnet_base, idx: Number(e.idx), key: Number(e.key),
      tun: `gre-${e.name}`, tcp_ports: e.tcp_ports || '', udp_ports: e.udp_ports || '',
    }
    : {
      name: e.name, iran_ip: e.iran_ip, subnet_base: e.subnet_base,
      idx: Number(e.idx), key: Number(e.key), tun: `gre-${e.name}`,
    })));
}

const exec = async (server, secret, command, opts = {}) => {
  const st = forServer(server);
  const ok = (stdout) => ({ rc: 0, stdout, stderr: '' });

  // Every command is recorded: an MTU test has to be able to assert that no tunnel
  // rebuild verb was ever called, which a state diff alone cannot show. The call
  // counter is per verb, and it is taken AFTER a fault reload so `reset_calls` and
  // `fail_from` describe this very command.
  const verb = verbOf(command);
  faults();
  st.calls = st.calls || {};
  st.calls[verb] = (st.calls[verb] || 0) + 1;
  st.commands.push(verb);
  if (st.commands.length > 400) st.commands.splice(0, st.commands.length - 400);

  // Tests that need a real overlap (a lock being held while a second caller arrives)
  // slow one verb down rather than hoping two requests interleave.
  const delay = ((faults().delay_ms || {})[server.name] || {})[verb];
  if (Number(delay) > 0) await new Promise((r) => setTimeout(r, Math.min(Number(delay), 3000)));

  if (faulted(server, 'any')) return fail('any', server);

  // --- read-only verbs the Hub verifies with -------------------------------
  if (/gre iran peer list --json/.test(command)) {
    if (faulted(server, 'peer_list_json')) return fail('peer_list_json', server);
    return ok(listJson(st.peers, 'peer'));
  }
  if (/gre node list --json/.test(command)) {
    if (faulted(server, 'node_list_json')) return fail('node_list_json', server);
    return ok(listJson(st.nodes, 'node'));
  }
  if (/gre status --json/.test(command)) {
    if (faulted(server, 'status_json')) return fail('status_json', server);
    return ok(JSON.stringify({ roles: st.peers.length ? ['IRAN'] : (st.nodes.length ? ['FOREIGN'] : []), tunnels_up: st.peers.length + st.nodes.length }));
  }
  if (/gre doctor/.test(command)) {
    if (faulted(server, 'doctor')) return { rc: 2, stdout: 'FAIL something is wrong', stderr: '' };
    return ok('PASS all checks');
  }
  if (/ping -c/.test(command)) {
    if ((faults().ping_fail || []).includes(server.name)) return { rc: 1, stdout: '', stderr: 'ping: unreachable' };
    return ok('2 packets transmitted, 2 received');
  }

  // --- MTU verbs -----------------------------------------------------------
  //
  // Read-only verbs report the CURRENT state of this host, so a set on either side is
  // immediately visible to the next diagnose — that is what makes the Hub's
  // verification step meaningful rather than decorative.
  let m = command.match(/gre mtu nic list(.*)$/);
  if (m) {
    if (faulted(server, 'mtu_nic_list_json')) return fail('mtu_nic_list_json', server);
    return ok(JSON.stringify([{ iface: 'eth0', role: 'wan', mtu: st.nic_mtu || 1500, up: true }]));
  }
  m = command.match(/gre mtu nic analyze (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_nic_analyze')) return fail('mtu_nic_analyze', server);
    const a = parseArgs(m[1]);
    return ok(JSON.stringify({
      name: a.name,
      risk: 'low',
      nics: [{ iface: 'eth0', mtu: st.nic_mtu || 1500, wan: true, risk: 'low', notes: ['no VLAN or tunnel stacked on the WAN interface'] }],
      checks: [{ id: 'wan_mtu_standard', status: 'PASS', detail: `${st.nic_mtu || 1500} bytes` }],
    }));
  }
  m = command.match(/gre mtu list(.*)$/);
  if (m) {
    if (faulted(server, 'mtu_list_json')) return fail('mtu_list_json', server);
    const names = [...st.peers.map((p) => p.name), ...st.nodes.map((n) => n.name)];
    return ok(JSON.stringify(names.map((name) => {
      const e = mtuEntry(st, name);
      return { name, tun: `gre-${name}`, mtu: e.gre_mtu, nic_mtu: e.nic_mtu, overhead: e.overhead };
    })));
  }
  m = command.match(/gre mtu diagnose (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_diagnose')) return fail('mtu_diagnose', server);
    const a = parseArgs(m[1]);
    const diag = mtuDiagnose(st, a.name);
    if (!diag) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    return ok(JSON.stringify(diag));
  }
  m = command.match(/gre mtu recommend (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_recommend')) return fail('mtu_recommend', server);
    const a = parseArgs(m[1]);
    const e = st.mtu[a.name];
    if (!e) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    const nic = e.nic_mtu || 1500;
    const recommended = nic - (e.overhead === undefined ? 28 : e.overhead);
    return ok(JSON.stringify({
      connection: a.name, underlay_mtu: nic, encapsulation_overhead: e.overhead === undefined ? 28 : e.overhead,
      current_gre_mtu: e.gre_mtu, recommended_gre_mtu: recommended, confidence: 'high',
      requires_change: e.gre_mtu !== recommended, reason: 'underlay capacity minus encapsulation overhead',
      safe_to_apply: true, safety_margin: 0, margin_reason: '', min_legal_mtu: 576, asymmetric: false,
    }));
  }
  m = command.match(/gre mtu auto (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_auto')) return fail('mtu_auto', server);
    const a = parseArgs(m[1]);
    const e = st.mtu[a.name];
    if (!e) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    const nic = e.nic_mtu || 1500;
    const recommended = nic - (e.overhead === undefined ? 28 : e.overhead);
    return ok(JSON.stringify({ connection: a.name, recommended_gre_mtu: recommended, confidence: 'high', apply_command: `gre mtu set --name ${a.name} --mtu ${recommended} --yes` }));
  }
  m = command.match(/gre tunnel diagnose (.*)$/);
  if (m) {
    if (faulted(server, 'tunnel_diagnose')) return fail('tunnel_diagnose', server);
    const a = parseArgs(m[1]);
    const side = sideOf(st, a.name);
    if (!side) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    const bad = (faults().reachability_fail || []).includes(server.name);
    return ok(JSON.stringify({
      name: a.name,
      side,
      generated_at: new Date().toISOString(),
      summary: { pass: bad ? 6 : 7, warn: 0, fail: bad ? 1 : 0, unknown: 0 },
      checks: [
        { id: 'interface_exists', status: 'PASS', detail: `gre-${a.name} is present` },
        { id: 'local_endpoint', status: 'PASS', detail: 'local endpoint set' },
        { id: 'remote_endpoint', status: 'PASS', detail: 'remote endpoint set' },
        { id: 'tunnel_address', status: 'PASS', detail: 'tunnel address set' },
        { id: 'underlay_route', status: 'PASS', detail: 'route to the peer exists' },
        { id: 'gre_47_permitted', status: 'PASS', detail: 'protocol 47 permitted' },
        { id: 'tunnel_reachable', status: bad ? 'FAIL' : 'PASS', detail: bad ? 'no reply from the peer' : 'peer replies' },
      ],
    }));
  }

  // --- health and repair verbs ---------------------------------------------
  //
  // The health check is READ-ONLY: it reads state and never writes it. Its exit code
  // mirrors the CLI's — non-zero only for BROKEN, which is a diagnosis and not a
  // failure of the command.
  let h = command.match(/gre health-check (.*)$/);
  if (h) {
    if (faulted(server, 'health_check')) return fail('health_check', server);
    const a = parseArgs(h[1]);
    const mode = a.quick ? 'quick' : 'full';
    const result = healthBuild(st, a.name, mode, server.name);
    if (!result) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    // An explicit budget is what the host reports it was given.
    if (a.budget !== undefined) result.budget_seconds = Number(a.budget);
    return { rc: result.overall_status === 'BROKEN' ? 1 : 0, stdout: `${JSON.stringify(result)}\n`, stderr: '' };
  }
  h = command.match(/gre repair preview (.*)$/);
  if (h) {
    if (faulted(server, 'repair_preview')) return fail('repair_preview', server);
    const a = parseArgs(h[1]);
    const result = healthBuild(st, a.name, 'full', server.name);
    if (!result) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    return ok(JSON.stringify({
      connection: a.name,
      read_only: true,
      repairable: result.findings.filter((f) => f.safe_repair),
    }));
  }

  // --- mutating verbs ------------------------------------------------------

  // `gre repair apply` re-applies this connection's own configuration, so the code it
  // fixes stops being reported. Removing the finding IS the state change: the checks
  // are derived from the findings, exactly as they are on a real host.
  h = command.match(/gre repair apply (.*)$/);
  if (h) {
    if (faulted(server, 'repair_apply')) return fail('repair_apply', server);
    const a = parseArgs(h[1]);
    const result = healthBuild(st, a.name, 'quick', server.name);
    if (!result) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    const finding = result.findings.find((f) => f.code === a.code);
    if (!finding || !finding.safe_repair) {
      return { rc: 1, stdout: '', stderr: `No automated repair exists for '${a.code}' on this host.` };
    }
    // A repair that ran but changed nothing is exactly the outcome the Hub must not
    // report as a success, so it has to be injectable.
    if ((faults().repair_noop || []).includes(server.name)) {
      return ok(`Repair ${a.code} ran; the condition is unchanged.\n`);
    }
    const entry = healthEntry(st, a.name);
    entry.findings = entry.findings.filter((f) => f.code !== a.code);
    return ok(`Repaired: ${a.code} is no longer reported for '${a.name}'.\n`);
  }

  // `gre mtu set` adjusts the interface MTU IN PLACE. Nothing in this handler touches
  // peers, nodes or tunnels, which is exactly the property the Hub's MTU flow relies
  // on and the MTU test asserts.
  m = command.match(/gre mtu set (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_set')) return fail('mtu_set', server);
    const a = parseArgs(m[1]);
    if (!sideOf(st, a.name)) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    const want = Number(a.mtu);
    if (!Number.isInteger(want) || want < 576 || want > 65535) return { rc: 1, stdout: '', stderr: `Invalid MTU: ${a.mtu}` };
    const entry = mtuEntry(st, a.name);
    const from = entry.gre_mtu;
    if (entry.previous === null || entry.previous === undefined) entry.previous = from;
    entry.gre_mtu = want;
    entry.history.push({ at: Date.now(), from, to: want });
    return ok(`Connection '${a.name}' MTU set to ${want} in place; the tunnel was not recreated.\n`);
  }
  m = command.match(/gre mtu restore (.*)$/);
  if (m) {
    if (faulted(server, 'mtu_restore')) return fail('mtu_restore', server);
    const a = parseArgs(m[1]);
    const entry = st.mtu[a.name];
    if (!entry) return { rc: 1, stdout: '', stderr: `No connection named '${a.name}' is configured on this host.` };
    if (entry.previous === null || entry.previous === undefined) return { rc: 1, stdout: '', stderr: 'Nothing to restore for this connection.' };
    const from = entry.gre_mtu;
    entry.gre_mtu = entry.previous;
    entry.history.push({ at: Date.now(), from, to: entry.gre_mtu, restore: true });
    return ok(`Connection '${a.name}' MTU restored to ${entry.gre_mtu} in place.\n`);
  }

  let p = command.match(/gre iran peer add (.*)$/);
  if (p) {
    if (faulted(server, 'peer_add')) return fail('peer_add', server);
    const a = parseArgs(p[1]);
    st.peers.push({
      name: a.name, iran_ip: a['iran-ip'] || '', foreign_ip: a['foreign-ip'],
      subnet_base: a['subnet-base'], idx: a.idx, key: a.key,
      tcp_ports: a['tcp-ports'] || '', udp_ports: a['udp-ports'] || '',
    });
    return ok("Foreign peer added.\n");
  }
  p = command.match(/gre iran peer edit (.*)$/);
  if (p) {
    if (faulted(server, 'peer_edit')) return fail('peer_edit', server);
    const a = parseArgs(p[1]);
    const peer = st.peers.find((x) => x.name === a.name);
    if (!peer) return { rc: 1, stdout: '', stderr: `Peer '${a.name}' does not exist.` };
    // A rename rewrites the entry under the new name, exactly as the CLI does.
    if (a['new-name']) peer.name = a['new-name'];
    for (const [flag, field] of [['foreign-ip', 'foreign_ip'], ['iran-ip', 'iran_ip'], ['subnet-base', 'subnet_base'], ['idx', 'idx'], ['key', 'key'], ['tcp-ports', 'tcp_ports'], ['udp-ports', 'udp_ports'], ['mss-clamp', 'mss_clamp']]) {
      if (a[flag] !== undefined) peer[field] = a[flag];
    }
    return ok(`Connection '${peer.name}' updated (A: rule-only update).\n`);
  }
  p = command.match(/gre iran peer remove (.*)$/);
  if (p) {
    if (faulted(server, 'peer_remove')) return fail('peer_remove', server);
    const a = parseArgs(p[1]);
    const before = st.peers.length;
    st.peers = st.peers.filter((x) => x.name !== a.name);
    if (st.peers.length === before) return { rc: 1, stdout: '', stderr: `Peer '${a.name}' does not exist.` };
    return ok(`Peer '${a.name}' removed.\n`);
  }
  p = command.match(/gre node add (.*)$/);
  if (p) {
    if (faulted(server, 'node_add')) return fail('node_add', server);
    const a = parseArgs(p[1]);
    st.nodes.push({ name: a.name, iran_ip: a.ip, subnet_base: a['subnet-base'], idx: a.idx, key: a.key });
    return ok('Node added.\n');
  }
  p = command.match(/gre node edit (.*)$/);
  if (p) {
    if (faulted(server, 'node_edit')) return fail('node_edit', server);
    const a = parseArgs(p[1]);
    const node = st.nodes.find((x) => x.name === a.name);
    if (!node) return { rc: 1, stdout: '', stderr: `Node '${a.name}' does not exist.` };
    if (a['new-name']) node.name = a['new-name'];
    for (const [flag, field] of [['ip', 'iran_ip'], ['subnet-base', 'subnet_base'], ['idx', 'idx'], ['key', 'key']]) {
      if (a[flag] !== undefined) node[field] = a[flag];
    }
    return ok(`Node '${node.name}' updated (B: tunnel recreation required).\n`);
  }
  p = command.match(/gre node remove (.*)$/);
  if (p) {
    if (faulted(server, 'node_remove')) return fail('node_remove', server);
    const a = parseArgs(p[1]);
    const before = st.nodes.length;
    st.nodes = st.nodes.filter((x) => x.name !== a.name);
    if (st.nodes.length === before) return { rc: 1, stdout: '', stderr: `Node '${a.name}' does not exist.` };
    return ok(`Node '${a.name}' removed.\n`);
  }

  // Anything else the Hub asks for (installer probes, suggestions) is a no-op
  // success: this fake exists to model the connection verbs, not the whole CLI.
  return ok('ok\n');
};

module.exports = exec;
module.exports.exec = exec;
module.exports.state = state;
module.exports.reset = () => state.clear();
module.exports.verbOf = verbOf;
module.exports.TUNNEL_REBUILD_VERBS = TUNNEL_REBUILD_VERBS;
module.exports.MUTATING_VERBS = MUTATING_VERBS;
module.exports.healthBuild = healthBuild;
