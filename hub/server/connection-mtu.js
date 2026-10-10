'use strict';
// connection-mtu.js — two-sided MTU diagnostics, recommendation and the
// transactional MTU change.
//
// DESIGN NOTES, because the shape of this file is deliberate:
//
//  * An MTU change is a PARAMETER change, never a tunnel rebuild. The Hub drives
//    `gre mtu set` only, which is the CLI's own in-place setter: the interface, the
//    peer, the key, the addressing and the rules are all left untouched. Rebuilding
//    the tunnel would drop every session through it, and an MTU tweak is exactly the
//    operation that must never do that.
//
//  * A GRE tunnel is only as large as the SMALLER of its two underlay paths, so the
//    recommendation takes the lower verified capacity and never an average. Averaging
//    produces a value one end cannot carry, and that fails in the direction of silent
//    packet loss rather than a visible error.
//
//  * The recommendation is built from probes. With no measurement the confidence is
//    reported honestly and safe_to_apply is false, because the cost of guessing is a
//    dead tunnel rather than a wrong number in a table.
//
//  * Nothing here reimplements interface handling. Every mutation is one SSH command
//    built by actions.buildAction, and every verification reads the CLI's own JSON.
//    The journal is the existing edit_operations table, with kind MTU_CHANGE.

const actions = require('./actions');
const { RouteOrchestrator } = require('./route-orchestrator');
const {
  acquireLock, releaseLock, ensureUuid, journalStart, journalStage, journalFinish, journalGet,
} = require('./connections');

// The legal MTU window. The CLI enforces the same range; validating here means an
// invalid value never becomes a remote command at all.
const MTU_MIN = actions.MTU_MIN;
const MTU_MAX = actions.MTU_MAX;
// The inner network's own floor. IPv6 requires 1280 and cannot be fragmented by
// routers, so a tunnel carrying IPv6 must not be sized below it.
const MTU_MIN_V6 = 1280;
// Two ends that report capacities more than this far apart disagree about the path
// (a lost encapsulation option, or a PMTU black hole), not about jitter.
const ASYMMETRY_TOLERANCE = 8;
// A side whose capacity came from the CONFIGURED NIC MTU rather than a probe is sized
// down by this much, so an unmeasured encapsulation option cannot push the tunnel
// over the path.
const CONFIGURED_MARGIN = 8;

// The transaction stages. The order is the contract: a reader of the timeline must be
// able to see that evidence was gathered before anything was written, and that the
// result was verified and only then committed.
const MTU_STAGES = [
  'CURRENT_STATE',
  'READ_BOTH_ENDPOINTS',
  'MTU_DIAGNOSTICS',
  'RECOMMENDATION',
  'USER_APPROVAL',
  'BACKUP_PREVIOUS_VALUES',
  'APPLY_TO_BOTH_SIDES',
  'VERIFY_INTERFACE_STATE',
  'VERIFY_CONNECTIVITY',
  'COMMIT_OR_ROLLBACK',
];

const REACHABILITY_CHECK_ID = 'tunnel_reachable';

// -------------------------------------------------------------------- helpers

const num = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

function parseJson(text) {
  try {
    const value = JSON.parse(String(text === undefined || text === null ? '' : text).trim());
    return value && typeof value === 'object' ? value : null;
  } catch { return null; }
}

const redact = (text) => RouteOrchestrator.redact(String(text === undefined || text === null ? '' : text));

// Key names that must never survive into an API payload, whatever the remote CLI
// happens to print. The MTU verbs have no credential parameters, so this is a
// backstop rather than a filter the feature depends on.
const DENY_KEY_RE = /secret|password|passwd|passphrase|credential|private/i;

function sanitize(value, depth = 0) {
  if (depth > 6) return null;
  if (value === null) return null;
  if (value === undefined) return null;
  if (typeof value === 'string') return redact(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => sanitize(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (DENY_KEY_RE.test(k)) continue;
      out[k] = sanitize(v, depth + 1);
    }
    return out;
  }
  return null;
}

// Run one CLI verb for a side. Mirrors connections.runEdit: a thrown transport error
// keeps its own message, because losing it turns a diagnosable failure into
// "rc=undefined".
async function runVerb(remote, server, action, params, timeoutMs = 120000) {
  const command = actions.buildAction(action, params);
  let result;
  try {
    result = await remote(server, command, timeoutMs);
  } catch (err) {
    return {
      ok: false, rc: null, command, stdout: '', stderr: '',
      detail: redact(err.message), hostkey_mismatch: !!err.hostkey_mismatch, presented_fp: err.presented_fp,
    };
  }
  if (!result || typeof result !== 'object') {
    return { ok: false, rc: null, command, stdout: '', stderr: '', detail: 'the transport returned nothing' };
  }
  const detail = String(result.stderr || result.stdout || `rc=${result.rc}`).trim().slice(0, 500);
  return {
    ok: result.rc === 0,
    rc: result.rc,
    command,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    detail: redact(detail),
  };
}

// Read one side with a read-only verb against an already resolved server.
async function readSideByServer({ remote, server, side, action, params, timeoutMs = 120000 }) {
  const label = side === 'iran' ? 'Iran' : 'Foreign';
  const res = await runVerb(remote, server, action, params, timeoutMs);
  if (!res.ok) {
    return { side, label, server_id: server.id, server: server.name, ok: false, rc: res.rc, error: res.detail, hostkey_mismatch: res.hostkey_mismatch, data: null };
  }
  const data = parseJson(res.stdout);
  if (!data) {
    return {
      side, label, server_id: server.id, server: server.name, ok: false, rc: res.rc,
      error: `${server.name} returned output that is not JSON`, data: null,
    };
  }
  return { side, label, server_id: server.id, server: server.name, ok: true, rc: res.rc, error: null, data: sanitize(data) };
}

// Read one side of a connection. Never throws and never returns undefined data: a host
// that is down, or that answers with a non-JSON banner, is reported per side so the
// other side's evidence still reaches the operator.
async function runReadSide({ row, remote, resolveServer, side, action, params, timeoutMs = 120000 }) {
  const label = side === 'iran' ? 'Iran' : 'Foreign';
  const serverId = side === 'iran' ? row.iran_server_id : row.foreign_server_id;
  let server = null;
  try { server = resolveServer(serverId); } catch { server = null; }
  if (!server) {
    return { side, label, server_id: serverId, server: null, ok: false, rc: null, error: `${label} server is not configured`, data: null };
  }
  return readSideByServer({ remote, server, side, action, params, timeoutMs });
}

// ------------------------------------------------------------- side normalisation

// Turn one side's diagnostic JSON into the small set of facts the recommendation and
// the UI actually reason about. Idempotent: a view that is already normalised is
// returned unchanged, so recommend() accepts both a read result and a view.
function normalizeSide(input, fallbackSide) {
  if (input && input.normalized) return input;
  const side = (input && input.side) || fallbackSide || 'unknown';
  const label = side === 'iran' ? 'Iran' : side === 'foreign' ? 'Foreign' : 'Unknown';
  const base = {
    normalized: true,
    side,
    label,
    server: (input && input.server) || null,
    server_id: input ? input.server_id : null,
    ok: !!(input && input.ok),
    error: (input && input.error) || null,
    data: null,
    generated_at: null,
    tunnel: null,
    nic_mtu: null,
    gre_mtu: null,
    overhead: null,
    overhead_source: 'none',
    capacity: null,
    capacity_source: 'none',
    measured: false,
    ipv6_inner: false,
    min_legal_mtu: MTU_MIN,
    checks: [],
    summary: null,
    mss_clamp: null,
    icmp_frag_needed: null,
    inner_probe: null,
    outer_probe: null,
  };
  if (!base.ok) return base;

  const d = (input && input.data) || {};
  const underlay = d.underlay || {};
  const gre = d.gre || {};
  const pmtu = d.pmtu || {};
  const mss = d.mss_clamp || {};
  const outer = pmtu.outer_probe || {};
  const inner = pmtu.inner_probe || {};

  const nicMtu = num(underlay.mtu);
  const greMtu = num(gre.mtu);
  // The CLI reports the encapsulation overhead. When it does not, the difference
  // between the NIC MTU and the configured tunnel MTU is the same quantity as long as
  // the tunnel MTU is not itself the misconfiguration being hunted — which is why the
  // derived value is labelled as such rather than passed off as measured.
  const reportedOverhead = num(gre.overhead);
  const derivedOverhead = reportedOverhead === null && nicMtu !== null && greMtu !== null && nicMtu > greMtu
    ? nicMtu - greMtu
    : null;
  const overhead = reportedOverhead !== null ? reportedOverhead : derivedOverhead;

  const ipv6Inner = (typeof gre.inner_cidr === 'string' && gre.inner_cidr.includes(':'))
    || Number(gre.inner_ipv) === 6
    || Number(d.inner_ipv) === 6;

  const outerState = String(outer.state || 'UNKNOWN').toUpperCase();
  const innerState = String(inner.state || 'UNKNOWN').toUpperCase();
  const outerMax = num(outer.max_ok);
  const innerMax = num(inner.max_ok);

  // A PASSed outer probe measured the underlay path directly, which is the strongest
  // evidence available. A PASSed inner probe measures the same path from inside the
  // tunnel, so the encapsulation overhead has to be added back. Only in the absence of
  // both does the configured NIC MTU stand in — and then it is not "measured".
  let capacity = null;
  let capacitySource = 'none';
  let measured = false;
  if (outerState === 'PASS' && outerMax !== null) {
    capacity = outerMax; capacitySource = 'outer_probe'; measured = true;
  } else if (innerState === 'PASS' && innerMax !== null && overhead !== null) {
    capacity = innerMax + overhead; capacitySource = 'inner_probe'; measured = true;
  } else if (nicMtu !== null) {
    capacity = nicMtu; capacitySource = 'configured_nic';
  }

  return {
    ...base,
    data: d,
    generated_at: d.generated_at || null,
    tunnel: gre.tun || d.tunnel || null,
    nic_mtu: nicMtu,
    gre_mtu: greMtu,
    overhead,
    overhead_source: reportedOverhead !== null ? 'reported' : derivedOverhead !== null ? 'derived' : 'none',
    capacity,
    capacity_source: capacitySource,
    measured,
    ipv6_inner: ipv6Inner,
    min_legal_mtu: ipv6Inner ? MTU_MIN_V6 : MTU_MIN,
    checks: Array.isArray(d.checks) ? d.checks : [],
    summary: d.summary || null,
    mss_clamp: {
      enabled: mss.enabled === true,
      mode: mss.mode || null,
      value: num(mss.value),
      scoped_to_connection: mss.scoped_to_connection === true,
    },
    icmp_frag_needed: underlay.icmp_frag_needed || null,
    inner_probe: { state: innerState, max_ok: innerMax, frag_needed_at: num(inner.frag_needed_at), probes_sent: num(inner.probes_sent) },
    outer_probe: { state: outerState, max_ok: outerMax, frag_needed_at: num(outer.frag_needed_at), probes_sent: num(outer.probes_sent) },
  };
}

function sideFacts(view) {
  return {
    side: view.side,
    label: view.label,
    server: view.server,
    ok: view.ok,
    error: view.error,
    tunnel: view.tunnel,
    nic_mtu: view.nic_mtu,
    gre_mtu: view.gre_mtu,
    overhead: view.overhead,
    capacity: view.capacity,
    capacity_source: view.capacity_source,
    measured: view.measured,
    ipv6_inner: view.ipv6_inner,
    min_legal_mtu: view.min_legal_mtu,
    mss_clamp: view.mss_clamp,
    inner_probe: view.inner_probe,
    outer_probe: view.outer_probe,
    icmp_frag_needed: view.icmp_frag_needed,
    summary: view.summary,
  };
}

// --------------------------------------------------------------- the two sides

// Run `gre mtu diagnose` on both ends of the connection. Never throws: a server that
// is unreachable, or that answers with something that is not JSON, is reported as a
// per-side error and the other side is still returned.
async function diagnoseBothSides({ db, row, remote, resolveServer }) {
  const name = row.peer_name || row.name;
  const [iran, foreign] = await Promise.all([
    runReadSide({ row, remote, resolveServer, side: 'iran', action: 'mtu_diagnose', params: { name } }),
    runReadSide({ row, remote, resolveServer, side: 'foreign', action: 'mtu_diagnose', params: { name } }),
  ]);
  const a = normalizeSide(iran, 'iran');
  const b = normalizeSide(foreign, 'foreign');
  return {
    name,
    connection_id: row.connection_uuid || null,
    iran,
    foreign,
    combined: combineSides(a, b, db ? mtuSummary(db, row) : null, name),
  };
}

function combineSides(a, b, stored, name) {
  const reasons = [];
  if (a.ok && b.ok) {
    if (a.gre_mtu !== null && b.gre_mtu !== null && a.gre_mtu !== b.gre_mtu) {
      reasons.push(`the two sides report different GRE MTUs (${a.label} ${a.gre_mtu} B, ${b.label} ${b.gre_mtu} B)`);
    }
    if (a.nic_mtu !== null && b.nic_mtu !== null && a.nic_mtu !== b.nic_mtu) {
      reasons.push(`the two sides report different NIC MTUs (${a.label} ${a.nic_mtu} B, ${b.label} ${b.nic_mtu} B)`);
    }
  } else {
    const down = [a, b].filter((s) => !s.ok).map((s) => `${s.label}${s.error ? ` (${s.error})` : ''}`);
    reasons.push(`only one side could be read: ${down.join(', ')} did not answer`);
  }
  // The journal is the Hub's own record of what it last left behind. A live value that
  // disagrees with it means something changed outside the Hub.
  if (stored && stored.known) {
    for (const [view, recorded] of [[a, stored.iran_gre_mtu], [b, stored.foreign_gre_mtu]]) {
      if (view.ok && view.gre_mtu !== null && recorded !== null && view.gre_mtu !== recorded) {
        reasons.push(`${view.label} reports ${view.gre_mtu} B but the Hub last recorded ${recorded} B`);
      }
    }
  }
  const mssModes = [a, b].filter((s) => s.ok).map((s) => (s.mss_clamp && s.mss_clamp.enabled ? 'on' : 'off'));
  const mssMode = !mssModes.length ? 'unknown' : (mssModes.every((m) => m === mssModes[0]) ? mssModes[0] : 'mixed');
  return {
    name: name || null,
    both_sides: a.ok && b.ok,
    reachable_sides: [a, b].filter((s) => s.ok).length,
    iran_gre_mtu: a.gre_mtu,
    foreign_gre_mtu: b.gre_mtu,
    iran_nic_mtu: a.nic_mtu,
    foreign_nic_mtu: b.nic_mtu,
    iran_capacity: a.capacity,
    foreign_capacity: b.capacity,
    overhead: a.overhead !== null ? a.overhead : b.overhead,
    mss_clamp: mssMode,
    drift: { detected: reasons.length > 0, reasons },
  };
}

// --------------------------------------------------------------------------------
// NIC analysis (read-only). The shape of the CLI's payload is not part of the
// contract, so the per-side data is passed through sanitised and the combined view
// only states what can be read defensively.
async function analyzeNicBothSides({ db, row, remote, resolveServer }) {
  const name = row.peer_name || row.name;
  const [iran, foreign] = await Promise.all([
    runReadSide({ row, remote, resolveServer, side: 'iran', action: 'mtu_nic_analyze', params: { name } }),
    runReadSide({ row, remote, resolveServer, side: 'foreign', action: 'mtu_nic_analyze', params: { name } }),
  ]);
  const riskOf = (side) => {
    const d = (side && side.data) || {};
    const r = d.risk !== undefined ? d.risk : (d.risk_level !== undefined ? d.risk_level : (d.summary && d.summary.risk));
    if (typeof r === 'string') return r.toLowerCase();
    if (r && typeof r === 'object' && typeof r.level === 'string') return r.level.toLowerCase();
    return null;
  };
  const RANK = { low: 0, medium: 1, high: 2 };
  const risks = [riskOf(iran), riskOf(foreign)].filter((r) => r && RANK[r] !== undefined);
  const overall = risks.length ? risks.reduce((m, r) => (RANK[r] > RANK[m] ? r : m)) : null;
  return {
    name,
    connection_id: row.connection_uuid || null,
    iran,
    foreign,
    combined: {
      both_sides: iran.ok && foreign.ok,
      overall_risk: overall,
      risk_by_side: { iran: riskOf(iran), foreign: riskOf(foreign) },
    },
  };
}

// ------------------------------------------------------------------ recommend
//
// Combine the two sides into one value.
//
// The tunnel can only be as large as its smaller underlay path, so the LOWER
// capacity wins. Confidence is stated from the evidence rather than from optimism:
// a side that could not be read makes the answer unknown, one measured side makes it
// medium, and two measured sides that agree make it high.
function recommend({ iran, foreign } = {}) {
  const a = normalizeSide(iran, 'iran');
  const b = normalizeSide(foreign, 'foreign');
  const sides = [a, b];
  const name = (a.ok && a.data && a.data.name) || (b.ok && b.data && b.data.name) || null;

  const unreadable = sides.filter((s) => !s.ok);
  const measured = sides.filter((s) => s.ok && s.measured);
  const capped = sides.filter((s) => s.ok && s.capacity !== null);
  const lower = capped.length ? capped.reduce((m, s) => (s.capacity < m.capacity ? s : m)) : null;
  const minLegal = (a.ipv6_inner || b.ipv6_inner) ? MTU_MIN_V6 : MTU_MIN;

  // The overhead comes from the side whose path is being sized against; the other
  // side's value is only a fallback for the case where the sizing side omitted it.
  let overhead = lower ? lower.overhead : null;
  if (overhead === null) {
    const withOverhead = sides.find((s) => s.ok && s.overhead !== null);
    overhead = withOverhead ? withOverhead.overhead : null;
  }

  const asymmetric = !!(a.ok && b.ok && a.capacity !== null && b.capacity !== null
    && Math.abs(a.capacity - b.capacity) > ASYMMETRY_TOLERANCE);
  const asymmetryDetail = asymmetric
    ? `the two underlay paths differ (${a.label} ${a.capacity} B, ${b.label} ${b.capacity} B)`
    : null;

  let confidence = 'unknown';
  if (!unreadable.length) {
    if (measured.length === 2) confidence = asymmetric ? 'medium' : 'high';
    else if (measured.length === 1) confidence = 'medium';
    else confidence = 'low';
  }

  const margin = lower && lower.capacity_source === 'configured_nic' ? CONFIGURED_MARGIN : 0;
  let recommended = null;
  let pathTooSmall = false;
  let reason = '';
  if (unreadable.length) {
    reason = `no recommendation: ${unreadable.map((s) => `${s.label} could not be read${s.error ? ` (${s.error})` : ''}`).join('; ')}`;
  } else if (lower === null) {
    reason = 'no recommendation: neither side reported an underlay capacity';
  } else if (overhead === null) {
    reason = 'no recommendation: the encapsulation overhead was not reported by either side';
  } else {
    const want = lower.capacity - margin - overhead;
    if (want < minLegal) {
      // The path cannot even carry the smallest legal inner MTU, so there is no value
      // to recommend: shrinking below the floor would produce an interface the stack
      // refuses to use.
      pathTooSmall = true;
      reason = `the ${lower.label} path capacity (${lower.capacity} B, ${lower.capacity_source}) cannot carry the ${minLegal} B minimum plus ${overhead} B of encapsulation`;
    } else {
      recommended = want;
      reason = `sized from the lower underlay path (${lower.label} ${lower.capacity} B, ${lower.capacity_source})`
        + ` minus ${overhead} B of encapsulation`
        + (margin ? ` minus a ${margin} B margin because that path was not probed` : '');
      if (asymmetric) reason += `; ${asymmetryDetail}, so the lower path wins`;
    }
  }

  const safe = recommended !== null && (confidence === 'high' || confidence === 'medium');
  if (recommended !== null && !safe) {
    reason += '; the evidence is inconclusive, so this value must not be applied unattended';
  }

  const currentSame = a.gre_mtu !== null && b.gre_mtu !== null && a.gre_mtu === b.gre_mtu;
  const current = currentSame ? a.gre_mtu : null;
  const requiresChange = recommended !== null
    && (!currentSame || a.gre_mtu !== recommended || b.gre_mtu !== recommended);

  return {
    connection: name,
    underlay_mtu: lower ? lower.capacity : null,
    underlay_source: lower ? lower.capacity_source : null,
    encapsulation_overhead: overhead,
    current_gre_mtu: current,
    current_by_side: { iran: a.gre_mtu, foreign: b.gre_mtu },
    recommended_gre_mtu: recommended,
    confidence,
    requires_change: requiresChange,
    reason,
    safe_to_apply: safe,
    safety_margin: margin,
    margin_reason: margin
      ? 'the lower path was not probed, so a small margin absorbs an unmeasured encapsulation option'
      : '',
    min_legal_mtu: minLegal,
    asymmetric,
    asymmetry_detail: asymmetryDetail,
    sides_disagree: !!(a.ok && b.ok && a.gre_mtu !== null && b.gre_mtu !== null && a.gre_mtu !== b.gre_mtu),
    path_too_small: pathTooSmall,
    unreadable_sides: unreadable.map((s) => ({ side: s.side, server: s.server, error: s.error })),
    sides: { iran: sideFacts(a), foreign: sideFacts(b) },
  };
}

// --------------------------------------------------------------- the journal
//
// Same table and same helpers as a connection edit (edit_operations, kind
// MTU_CHANGE). Only the two JSON columns need a targeted update here: the previous
// MTU is not known until the endpoints have actually been read.
function journalBackup(db, operationId, previous) {
  try {
    db.prepare('UPDATE edit_operations SET old_state_json = ? WHERE operation_id = ?')
      .run(JSON.stringify(previous || {}), operationId);
  } catch { /* journaling must never break an operation */ }
}

function journalPlan(db, operationId, plan) {
  try {
    db.prepare('UPDATE edit_operations SET plan_json = ? WHERE operation_id = ?')
      .run(JSON.stringify(plan || {}), operationId);
  } catch { /* see above */ }
}

const mssMode = (row) => {
  const v = row ? row.mss_clamp : null;
  if (v === null || v === undefined) return 'unknown';
  return Number(v) === 1 ? 'on' : 'off';
};

// What the Hub last knew about this connection's MTU, from the journal only. No SSH,
// no lock, no mutation: this is what the connections table can afford on every load.
function mtuSummary(db, row) {
  const empty = {
    known: false,
    source: 'journal',
    iran_gre_mtu: null,
    foreign_gre_mtu: null,
    previous: { iran_mtu: null, foreign_mtu: null },
    underlay_mtu: null,
    encapsulation_overhead: null,
    recommended_gre_mtu: null,
    confidence: null,
    safe_to_apply: null,
    min_legal_mtu: null,
    mss_clamp: mssMode(row),
    last_test: null,
    last_verified_at: null,
    drift: { detected: false, reasons: [] },
  };
  if (!db || !row || !row.connection_uuid) return empty;
  let ops = [];
  try {
    ops = db.prepare("SELECT * FROM edit_operations WHERE connection_uuid = ? AND kind = 'MTU_CHANGE' ORDER BY created_at DESC LIMIT 20")
      .all(row.connection_uuid);
  } catch { return empty; }
  if (!ops.length) return empty;

  const parsed = (json) => {
    try {
      const v = JSON.parse(json || '{}');
      return v && typeof v === 'object' ? v : {};
    } catch { return {}; }
  };
  const last = ops[0];
  const lastOk = ops.find((o) => o.status === 'SUCCEEDED') || null;
  const applied = lastOk ? parsed(lastOk.requested_state_json) : {};
  const plan = parsed((lastOk || last).plan_json);
  const previous = lastOk ? parsed(lastOk.old_state_json) : {};
  const rec = plan.recommendation || {};

  const iranMtu = num(applied.iran_mtu);
  const foreignMtu = num(applied.foreign_mtu);
  const reasons = [];
  if (iranMtu !== null && foreignMtu !== null && iranMtu !== foreignMtu) {
    reasons.push(`the last change left the two sides at different MTUs (${iranMtu} B / ${foreignMtu} B)`);
  }
  if (last.status === 'ROLLBACK_FAILED') {
    reasons.push('the last MTU change could not be rolled back, so the live value is unknown');
  } else if (last.status === 'INTERRUPTED') {
    reasons.push('the last MTU change was interrupted, so the live value is unknown');
  } else if (last.status === 'ROLLED_BACK') {
    reasons.push('the last MTU change was rolled back');
  }

  return {
    known: true,
    source: 'journal',
    iran_gre_mtu: iranMtu,
    foreign_gre_mtu: foreignMtu,
    previous: { iran_mtu: num(previous.iran_mtu), foreign_mtu: num(previous.foreign_mtu) },
    underlay_mtu: num(rec.underlay_mtu),
    encapsulation_overhead: num(rec.encapsulation_overhead),
    recommended_gre_mtu: num(rec.recommended_gre_mtu),
    confidence: rec.confidence || null,
    safe_to_apply: rec.safe_to_apply === undefined ? null : rec.safe_to_apply === true,
    min_legal_mtu: num(rec.min_legal_mtu),
    mss_clamp: mssMode(row),
    last_test: {
      operation_id: last.operation_id,
      status: last.status,
      stage: last.current_stage,
      rollback: last.rollback_state,
      detail: last.detail,
      at: last.created_at,
      completed_at: last.completed_at,
      restore: parsed(last.requested_state_json).restore === true,
    },
    last_verified_at: lastOk ? (lastOk.completed_at || lastOk.created_at) : null,
    drift: { detected: reasons.length > 0, reasons },
  };
}

// ------------------------------------------------------------------- planning
//
// Read-only. Creates no operation and opens no lock, so the wizard can call it while
// the operator is still typing. Given live diagnostics it names the CURRENT MTU of
// both sides exactly; without them it falls back to what the journal recorded, and
// says so.
function planMtuChange({ db, row, target, diagnostics = null }) {
  const stored = mtuSummary(db, row);
  const rec = diagnostics ? recommend({ iran: diagnostics.iran, foreign: diagnostics.foreign }) : null;
  const a = diagnostics ? normalizeSide(diagnostics.iran, 'iran') : null;
  const b = diagnostics ? normalizeSide(diagnostics.foreign, 'foreign') : null;

  const errors = [];
  const desired = Number(target);
  if (target === undefined || target === null || target === '') {
    errors.push('mtu is required');
  } else if (!Number.isInteger(desired) || desired < MTU_MIN || desired > MTU_MAX) {
    errors.push(`mtu must be an integer ${MTU_MIN}-${MTU_MAX}`);
  }
  const valid = errors.length === 0;
  const targetValue = valid ? desired : null;

  const currentIran = a && a.ok ? a.gre_mtu : stored.iran_gre_mtu;
  const currentForeign = b && b.ok ? b.gre_mtu : stored.foreign_gre_mtu;
  const capacity = rec ? rec.underlay_mtu : stored.underlay_mtu;
  const overhead = rec ? rec.encapsulation_overhead : stored.encapsulation_overhead;
  const minLegal = rec ? rec.min_legal_mtu : (stored.min_legal_mtu || MTU_MIN);
  const confidence = rec ? rec.confidence : (stored.confidence || 'unknown');

  const hardBlocks = [];
  const riskReasons = [];
  let riskLevel = 'low';
  if (valid) {
    if (targetValue < minLegal) {
      hardBlocks.push(`target ${targetValue} B is below the minimum legal MTU (${minLegal} B) for this tunnel`);
      riskLevel = 'high';
    }
    if (capacity !== null && overhead !== null && targetValue + overhead > capacity) {
      hardBlocks.push(`target ${targetValue} B plus ${overhead} B of encapsulation exceeds the ${capacity} B underlay capacity`);
      riskLevel = 'high';
    }
    if (!rec) {
      hardBlocks.push('the live diagnostics could not be read, so this plan is based on the journal only');
      riskLevel = riskLevel === 'high' ? 'high' : 'medium';
    } else if (!rec.safe_to_apply) {
      hardBlocks.push(`the diagnostics are inconclusive (confidence ${rec.confidence})`);
      riskLevel = riskLevel === 'high' ? 'high' : 'medium';
    }
    if (riskLevel === 'low') riskReasons.push(`both underlay paths were measured and the target fits them (confidence ${confidence})`);
  }
  if (currentIran !== null && currentForeign !== null && currentIran !== currentForeign) {
    riskReasons.push(`the two sides currently disagree (${currentIran} B / ${currentForeign} B); both will be set to the target`);
    if (riskLevel === 'low') riskLevel = 'medium';
  }
  if (rec && rec.asymmetric && rec.asymmetry_detail) riskReasons.push(rec.asymmetry_detail);
  if (valid && capacity !== null && overhead !== null && targetValue + overhead <= capacity) {
    riskReasons.push(`target ${targetValue} B plus ${overhead} B of encapsulation fits the ${capacity} B underlay capacity`);
  }

  const whatChanges = [];
  if (valid) {
    whatChanges.push(`${a ? a.label : 'Iran'} GRE MTU: ${currentIran === null ? 'unknown' : `${currentIran} B`} → ${targetValue} B`);
    whatChanges.push(`${b ? b.label : 'Foreign'} GRE MTU: ${currentForeign === null ? 'unknown' : `${currentForeign} B`} → ${targetValue} B`);
    whatChanges.push('the GRE interface is not recreated: only the interface MTU changes, so the peer, key, addressing and rules stay as they are');
    if (rec && rec.recommended_gre_mtu !== null && rec.recommended_gre_mtu !== targetValue) {
      whatChanges.push(`the diagnostics recommend ${rec.recommended_gre_mtu} B rather than ${targetValue} B`);
    }
  }

  return {
    read_only: true,
    connection_id: row.connection_uuid || null,
    route_id: row.id,
    name: row.peer_name || row.name,
    target: targetValue,
    target_valid: valid,
    current: { iran: currentIran, foreign: currentForeign, source: diagnostics ? 'live' : 'journal' },
    recommended_mtu: rec ? rec.recommended_gre_mtu : stored.recommended_gre_mtu,
    confidence,
    underlay_mtu: capacity,
    encapsulation_overhead: overhead,
    min_legal_mtu: minLegal,
    what_changes: whatChanges,
    risk: { level: riskLevel, reasons: riskReasons },
    risk_level: riskLevel,
    risk_reasons: riskReasons,
    verification_checks: [
      { id: 'interface_mtu_iran', description: 'the Iran GRE interface reads back at the target MTU, from the interface itself rather than from a successful command' },
      { id: 'interface_mtu_foreign', description: 'the Foreign GRE interface reads back at the target MTU as well' },
      { id: 'tunnel_reachable_iran', description: 'gre tunnel diagnose does not report reachability FAIL on Iran' },
      { id: 'tunnel_reachable_foreign', description: 'gre tunnel diagnose does not report reachability FAIL on the Foreign side' },
      { id: 'rollback_available', description: 'the MTU each side had before the change is recorded before anything is written, so it can be restored' },
    ],
    rollback_conditions: [
      'either side cannot be set to the target: the value already applied to the other side is put back',
      'either interface does not read back as the target: the previous values are restored on both sides',
      'reachability goes from PASS to FAIL, or from PASS to unconfirmed, on either side: the previous values are restored',
      'a restore that cannot be verified is reported as ROLLBACK_FAILED together with the exact manual commands',
    ],
    can_apply: valid && hardBlocks.length === 0,
    blocked_reason: hardBlocks.length ? hardBlocks[0] : (valid ? null : errors[0]),
    validation_errors: errors,
    hard_blocks: hardBlocks,
    recommendation: rec,
  };
}

// ------------------------------------------------------------- verification

// Compare what each interface reports against the value it must have. An interface
// that merely EXISTS proves nothing, so the reported MTU is part of the check.
function verifyValues({ iran, foreign, want, only = null }) {
  const pairs = [
    ['iran', 'Iran', iran, num(want.iran_mtu)],
    ['foreign', 'Foreign', foreign, num(want.foreign_mtu)],
  ];
  const checks = [];
  for (const [key, label, view, expected] of pairs) {
    if (only && !only.includes(key)) continue;
    if (!view || !view.ok) {
      checks.push({ side: key, ok: false, detail: `${label}: could not be read${view && view.error ? ` (${view.error})` : ''}` });
      continue;
    }
    if (expected === null) {
      checks.push({ side: key, ok: false, detail: `${label}: no MTU was recorded to verify against` });
      continue;
    }
    if (!view.tunnel) {
      checks.push({ side: key, ok: false, detail: `${label}: no GRE interface is present for this connection` });
      continue;
    }
    if (view.gre_mtu === null) {
      checks.push({ side: key, ok: false, detail: `${label}: the CLI did not report an interface MTU` });
      continue;
    }
    if (view.gre_mtu !== expected) {
      checks.push({ side: key, ok: false, detail: `${label}: interface reports ${view.gre_mtu} B, expected ${expected} B` });
      continue;
    }
    checks.push({ side: key, ok: true, detail: `${label}: ${view.tunnel} at ${view.gre_mtu} B` });
  }
  const ok = checks.length > 0 && checks.every((c) => c.ok);
  return { ok, checks, detail: checks.map((c) => c.detail).join('; ') };
}

// Reachability BEFORE the change, taken from the diagnostics the MTU stage already
// ran. Keeping it lets a healthy tunnel that can no longer prove itself afterwards be
// treated as a regression rather than as an inconclusive probe.
function innerReachability(diagnostics) {
  const one = (side) => {
    // Accepts either a read result (the verb output under `data`) or an already
    // normalised view, because both are passed around this module.
    const d = side && side.data ? side.data : side;
    const st = d && d.pmtu && d.pmtu.inner_probe ? String(d.pmtu.inner_probe.state || 'UNKNOWN').toUpperCase() : 'UNKNOWN';
    return ['PASS', 'WARN', 'FAIL'].includes(st) ? st : 'UNKNOWN';
  };
  return {
    iran: one(diagnostics && diagnostics.iran),
    foreign: one(diagnostics && diagnostics.foreign),
  };
}

const reachabilityFromChecks = (data) => {
  if (!data || !Array.isArray(data.checks)) return null;
  const c = data.checks.find((x) => x && x.id === REACHABILITY_CHECK_ID);
  if (!c) return null;
  const state = String(c.status || '').toUpperCase();
  return {
    state: ['PASS', 'WARN', 'FAIL'].includes(state) ? state : 'UNKNOWN',
    detail: String(c.detail || '').slice(0, 300),
  };
};

const commandUnknown = (text) => /unknown (argument|option|command)|not a gre command|no such command/i.test(String(text || ''));

// Reachability AFTER the change. `gre tunnel diagnose` is the CLI's own read-only
// check; an older remote that does not know the verb falls back to the MTU
// diagnostics' inner probe, which measures the same path, so an old host is not
// reported as a broken tunnel.
async function readConnectivity({ remote, iran, foreign, peerName, before, diagnose }) {
  const defs = [
    ['iran', 'Iran', iran, diagnose ? normalizeSide(diagnose.iran, 'iran') : null],
    ['foreign', 'Foreign', foreign, diagnose ? normalizeSide(diagnose.foreign, 'foreign') : null],
  ];
  const sides = {};
  for (const [key, label, server, view] of defs) {
    const res = await runVerb(remote, server, 'tunnel_diagnose', { name: peerName }, 120000);
    const data = res.ok ? parseJson(res.stdout) : null;
    const reach = reachabilityFromChecks(data);
    if (reach) {
      sides[key] = { ...reach, label, server: server.name, source: 'tunnel_diagnose' };
      continue;
    }
    if (!res.ok && commandUnknown(`${res.stdout}\n${res.stderr}`)) {
      const state = (view && view.inner_probe && view.inner_probe.state) || 'UNKNOWN';
      sides[key] = {
        state, label, server: server.name, source: 'mtu_inner_probe',
        detail: 'the remote CLI has no tunnel diagnose; the MTU inner probe was used instead',
      };
      continue;
    }
    if (!res.ok) {
      sides[key] = { state: 'FAIL', label, server: server.name, source: 'tunnel_diagnose', detail: res.detail };
      continue;
    }
    sides[key] = {
      state: 'UNKNOWN', label, server: server.name, source: 'tunnel_diagnose',
      detail: 'the tunnel diagnose output carried no reachability result',
    };
  }

  const regressions = [];
  for (const key of ['iran', 'foreign']) {
    const after = sides[key];
    const wasBefore = (before && before[key]) || 'UNKNOWN';
    if (after.state === 'FAIL') {
      regressions.push(`${after.label}: reachability FAIL${after.detail ? ` (${after.detail})` : ''}`);
    } else if (after.state !== 'PASS' && wasBefore === 'PASS') {
      // The only thing that changed is the MTU, so a tunnel that was reachable and now
      // cannot demonstrate it is a regression, not an unknown.
      regressions.push(`${after.label}: reachability could not be confirmed although it was PASS before the change`);
    }
  }

  let state = 'UNKNOWN';
  if (regressions.length) state = 'FAIL';
  else if (sides.iran.state === 'PASS' && sides.foreign.state === 'PASS') state = 'PASS';
  else if ([sides.iran.state, sides.foreign.state].includes('WARN')) state = 'WARN';
  const detail = `Iran ${sides.iran.state} (${sides.iran.source}) / Foreign ${sides.foreign.state} (${sides.foreign.source})`;
  return { state, detail, regressions, iran: sides.iran, foreign: sides.foreign };
}

// What a human must do when the Hub could not put the MTU back.
function manualMtuRecovery({ iran, foreign, peerName, previous }) {
  const lines = [
    'The Hub could not verify that the previous MTU was restored.',
    'The connection MTU may be in an unknown state. Inspect both servers:',
    `  ssh ${iran.username}@${iran.host}  gre mtu diagnose --name ${peerName}; gre tunnel diagnose --name ${peerName}`,
    `  ssh ${foreign.username}@${foreign.host}  gre mtu diagnose --name ${peerName}; gre tunnel diagnose --name ${peerName}`,
    'To restore by hand:',
    `  gre mtu set --name ${peerName} --mtu ${previous.iran_mtu === null || previous.iran_mtu === undefined ? '<previous Iran MTU>' : previous.iran_mtu} --yes    # on ${iran.name}`,
    `  gre mtu set --name ${peerName} --mtu ${previous.foreign_mtu === null || previous.foreign_mtu === undefined ? '<previous Foreign MTU>' : previous.foreign_mtu} --yes    # on ${foreign.name}`,
    'Then confirm with `gre tunnel diagnose` on both sides before trusting the tunnel.',
  ];
  return lines.join('\n');
}

// Put both ends back to the values this operation recorded before it started.
//
// `gre mtu restore` is tried first, because that re-applies what the CLI itself
// recorded. When it cannot be verified, the value the Hub recorded is set explicitly:
// a CLI with no backup to restore is not a reason to give up before trying. An
// unverified restore is not a rollback, so the result is verified either way.
async function restoreValues({ remote, iran, foreign, peerName, previous, stage, only = null }) {
  const pairs = [
    ['iran', 'Iran', iran, num(previous.iran_mtu)],
    ['foreign', 'Foreign', foreign, num(previous.foreign_mtu)],
  ].filter(([key]) => !only || only.includes(key));

  const restored = [];
  for (const [key, label, server, want] of pairs) {
    const res = await runVerb(remote, server, 'mtu_restore', { name: peerName });
    stage(`ROLLBACK_${key.toUpperCase()}`, res.ok ? 'PASS' : 'FAIL',
      `${server.name}: ${res.ok ? `gre mtu restore applied (target ${want === null ? 'unknown' : `${want} B`})` : res.detail}`);
    restored.push({ key, label, server, want });
  }

  const readBack = async () => verifyValues({
    iran: normalizeSide(await readSideByServer({ remote, server: iran, side: 'iran', action: 'mtu_diagnose', params: { name: peerName } }), 'iran'),
    foreign: normalizeSide(await readSideByServer({ remote, server: foreign, side: 'foreign', action: 'mtu_diagnose', params: { name: peerName } }), 'foreign'),
    want: previous,
    only,
  });

  let verify = await readBack();
  if (!verify.ok) {
    // A CLI with no backup to restore cannot be helped by `restore`, so the value the
    // Hub recorded is set explicitly before the rollback is called failed.
    for (const entry of restored) {
      if (entry.want === null) continue;
      const res = await runVerb(remote, entry.server, 'mtu_set', { name: peerName, mtu: entry.want });
      stage(`ROLLBACK_${entry.key.toUpperCase()}`, res.ok ? 'PASS' : 'FAIL',
        `${entry.server.name}: ${res.ok ? `set explicitly to ${entry.want} B` : res.detail}`);
    }
    verify = await readBack();
  }
  return { ok: verify.ok, detail: verify.detail, checks: verify.checks };
}

// -------------------------------------------------------------------- applying

async function crossCheckRecommend({ remote, server, name }) {
  const res = await runVerb(remote, server, 'mtu_recommend', { name }, 120000);
  const data = res.ok ? parseJson(res.stdout) : null;
  if (!data) return { server: server.name, ok: false, error: res.detail };
  return { server: server.name, ok: true, data: sanitize(data) };
}

// The transactional MTU change.
//
// Stage order is the contract, and it is not cosmetic: CURRENT_STATE -> read both ends
// -> diagnostics -> recommendation -> operator approval -> BACKUP the previous values
// -> apply to both sides -> verify the interfaces -> verify connectivity ->
// commit or roll back. Nothing is written before the previous values are recorded, and
// no success is claimed from an interface merely existing.
async function runMtuTransaction({
  db, row, mode, target, previous, restoredFrom, emit, remote, resolveServer,
}) {
  const uuid = ensureUuid(db, row);
  const peerName = row.peer_name || row.name;
  const restoreMode = mode === 'restore';
  const desired = restoreMode ? null : Number(target);
  const iran = resolveServer(row.iran_server_id);
  const foreign = resolveServer(row.foreign_server_id);
  if (!iran || !foreign) {
    const err = new Error('both endpoints of this connection must exist before an MTU can be changed');
    err.status = 409;
    throw err;
  }

  if (!restoreMode && (!Number.isInteger(desired) || desired < MTU_MIN || desired > MTU_MAX)) {
    const err = new Error(`target MTU must be an integer ${MTU_MIN}-${MTU_MAX}`);
    err.status = 400;
    throw err;
  }

  const operationId = journalStart(db, {
    uuid,
    routeId: row.id,
    kind: 'MTU_CHANGE',
    oldState: restoreMode ? { ...(previous || {}) } : { iran_mtu: null, foreign_mtu: null },
    requestedState: restoreMode
      ? { iran_mtu: num(previous && previous.iran_mtu), foreign_mtu: num(previous && previous.foreign_mtu), restore: true, restored_from: restoredFrom || null }
      : { target: desired, iran_mtu: desired, foreign_mtu: desired, restore: false },
    plan: { mode: restoreMode ? 'restore' : 'apply', target: desired, restored_from: restoredFrom || null, stages: MTU_STAGES },
  });

  const acquired = acquireLock([
    { kind: 'connection', id: uuid },
    { kind: 'server', id: row.iran_server_id },
    { kind: 'server', id: row.foreign_server_id },
  ], operationId);
  if (!acquired.ok) {
    journalFinish(db, operationId, 'REJECTED', 'another operation holds this connection or one of its servers', 'NONE');
    const err = new Error('another edit or MTU change is already running for this connection or one of its servers');
    err.status = 409;
    err.operation_id = operationId;
    throw err;
  }

  const stage = (name, status, detail) => {
    journalStage(db, operationId, name, status, detail);
    if (typeof emit === 'function') {
      try { emit(name, status, detail); } catch { /* the journal is the durable record */ }
    }
  };
  const abort = (message, status, extra = {}) => {
    const err = new Error(message);
    err.status = status;
    Object.assign(err, extra);
    return err;
  };

  let appliedAny = false;
  let before = null;
  let rec = null;
  let currentValues = { iran_mtu: null, foreign_mtu: null };

  try {
    stage('CURRENT_STATE', 'PASS', `${iran.name} <-> ${foreign.name} (connection ${uuid}${restoreMode ? `, restoring operation ${restoredFrom}` : ''})`);

    stage('READ_BOTH_ENDPOINTS', 'RUNNING', `reading the current MTU on ${iran.name} and ${foreign.name}`);
    before = await diagnoseBothSides({ db, row, remote, resolveServer });
    const a0 = normalizeSide(before.iran, 'iran');
    const b0 = normalizeSide(before.foreign, 'foreign');
    if (!a0.ok || !b0.ok) {
      const why = [a0.ok ? null : `${a0.label}: ${a0.error}`, b0.ok ? null : `${b0.label}: ${b0.error}`].filter(Boolean).join('; ');
      stage('READ_BOTH_ENDPOINTS', 'FAIL', why);
      // Without the previous value on both sides the change could not be undone, so it
      // must not start.
      throw abort(`the current MTU of both sides must be readable before it can be changed (${why})`, 409, { diagnostics: before });
    }
    currentValues = { iran_mtu: a0.gre_mtu, foreign_mtu: b0.gre_mtu };
    const desiredValues = restoreMode
      ? { iran_mtu: num(previous && previous.iran_mtu), foreign_mtu: num(previous && previous.foreign_mtu) }
      : { iran_mtu: desired, foreign_mtu: desired };
    if (restoreMode && desiredValues.iran_mtu === null && desiredValues.foreign_mtu === null) {
      stage('READ_BOTH_ENDPOINTS', 'FAIL', 'that operation recorded no previous MTU');
      throw abort('that operation did not record a previous MTU to restore', 409);
    }
    stage('READ_BOTH_ENDPOINTS', 'PASS',
      `${a0.label} ${a0.gre_mtu === null ? 'unknown' : `${a0.gre_mtu} B`} / ${b0.label} ${b0.gre_mtu === null ? 'unknown' : `${b0.gre_mtu} B`}`);
    journalBackup(db, operationId, currentValues);

    stage('MTU_DIAGNOSTICS', 'RUNNING', 'probing the underlay path on both sides');
    const crossChecks = await Promise.all([
      crossCheckRecommend({ remote, server: iran, name: peerName }),
      crossCheckRecommend({ remote, server: foreign, name: peerName }),
    ]);
    rec = recommend({ iran: before.iran, foreign: before.foreign });
    const crossSummary = crossChecks.map((c) => `${c.server} ${c.ok ? 'answered' : `did not answer (${c.error})`}`).join(', ');
    stage('MTU_DIAGNOSTICS', rec.confidence === 'unknown' ? 'WARN' : 'PASS',
      `confidence ${rec.confidence}; ${rec.reason} (cross-check: ${crossSummary})`);
    journalPlan(db, operationId, {
      mode: restoreMode ? 'restore' : 'apply',
      target: desired,
      recommendation: rec,
      current: currentValues,
      cli_recommendations: crossChecks,
    });

    stage('RECOMMENDATION', rec.recommended_gre_mtu === null ? 'FAIL' : 'PASS',
      rec.recommended_gre_mtu === null
        ? rec.reason
        : `recommended GRE MTU ${rec.recommended_gre_mtu} B (${rec.confidence} confidence, ${rec.underlay_source})`);

    if (!restoreMode && rec.safe_to_apply !== true) {
      // Applying from inconclusive evidence is the failure this whole flow exists to
      // prevent: a wrong MTU breaks the tunnel without an error to point at.
      throw abort(`the MTU change was not applied: ${rec.reason}. Both sides must be measured before the Hub changes an MTU; use the CLI directly to override.`,
        409, { recommendation: rec, diagnostics: before });
    }

    // A target that cannot fit the measured path is refused even though the operator
    // asked for it explicitly: the honest answer is that this value breaks the tunnel,
    // not a silent interface change followed by packet loss.
    if (!restoreMode) {
      const violations = [];
      if (desired < rec.min_legal_mtu) {
        violations.push(`target ${desired} B is below the minimum legal MTU (${rec.min_legal_mtu} B) for this tunnel`);
      }
      if (rec.underlay_mtu !== null && rec.encapsulation_overhead !== null
        && desired + rec.encapsulation_overhead > rec.underlay_mtu) {
        violations.push(`target ${desired} B plus ${rec.encapsulation_overhead} B of encapsulation exceeds the ${rec.underlay_mtu} B underlay capacity`);
      }
      if (violations.length) {
        throw abort(`the MTU change was not applied: ${violations.join('; ')}`, 409,
          { recommendation: rec, diagnostics: before });
      }
    }

    stage('USER_APPROVAL', 'PASS', restoreMode
      ? `restore of operation ${restoredFrom} requested by the operator`
      : `target ${desired} B confirmed by the operator`);

    stage('BACKUP_PREVIOUS_VALUES', 'PASS',
      `Iran ${currentValues.iran_mtu === null ? 'unknown' : `${currentValues.iran_mtu} B`} / Foreign ${currentValues.foreign_mtu === null ? 'unknown' : `${currentValues.foreign_mtu} B`} recorded (operation ${operationId})`);

    stage('APPLY_TO_BOTH_SIDES', 'RUNNING', `${iran.name} first, then ${foreign.name}`);
    const applySide = (server, key) => (restoreMode
      ? runVerb(remote, server, 'mtu_restore', { name: peerName })
      : runVerb(remote, server, 'mtu_set', { name: peerName, mtu: desiredValues[`${key}_mtu`] }));

    const iranApply = await applySide(iran, 'iran');
    if (!iranApply.ok) {
      stage('APPLY_TO_BOTH_SIDES', 'FAIL', `${iran.name}: ${iranApply.detail}`);
      throw abort(`${restoreMode ? 'the restore' : 'the MTU change'} failed on ${iran.name}: ${iranApply.detail}`,
        502, { diagnostics: before, recommendation: rec });
    }
    appliedAny = true;

    const foreignApply = await applySide(foreign, 'foreign');
    if (!foreignApply.ok) {
      // PARTIAL FAILURE: one end was resized and the other was not, which is worse than
      // either end alone. Put the first side back before reporting anything.
      stage('APPLY_TO_BOTH_SIDES', 'FAIL', `${foreign.name} failed after ${iran.name} was changed: ${foreignApply.detail}`);
      stage('ROLLBACK_STARTED', 'RUNNING', `putting ${iran.name} back before reporting the partial failure`);
      const partial = await restoreValues({ remote, iran, foreign, peerName, previous: currentValues, stage, only: ['iran'] });
      stage('ROLLBACK_COMPLETE', partial.ok ? 'PASS' : 'FAIL', partial.detail);
      stage('COMMIT_OR_ROLLBACK', partial.ok ? 'WARN' : 'FAIL',
        partial.ok
          ? `${foreign.name} could not be changed, so ${iran.name} was put back to ${currentValues.iran_mtu} B`
          : `${foreign.name} could not be changed and ${iran.name} could not be put back: ${partial.detail}`);
      journalFinish(db, operationId, partial.ok ? 'ROLLED_BACK' : 'ROLLBACK_FAILED',
        `${restoreMode ? 'restore' : 'MTU change'} failed on ${foreign.name}: ${foreignApply.detail}`, partial.ok ? 'CLEAN' : 'FAILED');
      const out = abort(`${restoreMode ? 'the restore' : 'the MTU change'} failed on ${foreign.name}: ${foreignApply.detail}`, 502, {
        rollback_outcome: partial.ok ? 'CLEAN' : 'FAILED',
        rollback: partial.ok ? 'CLEAN' : 'FAILED',
        operation_id: operationId,
        diagnostics: before,
        recommendation: rec,
        previous: currentValues,
        manual_recovery: partial.ok ? null : manualMtuRecovery({ iran, foreign, peerName, previous: currentValues }),
      });
      throw out;
    }
    stage('APPLY_TO_BOTH_SIDES', 'PASS', restoreMode
      ? `both sides restored (Iran ${desiredValues.iran_mtu === null ? 'unknown' : `${desiredValues.iran_mtu} B`} / Foreign ${desiredValues.foreign_mtu === null ? 'unknown' : `${desiredValues.foreign_mtu} B`})`
      : `both sides set to ${desired} B`);

    stage('VERIFY_INTERFACE_STATE', 'RUNNING', 'reading the interface MTU back from both sides');
    let after = await diagnoseBothSides({ db, row, remote, resolveServer });
    let a1 = normalizeSide(after.iran, 'iran');
    let b1 = normalizeSide(after.foreign, 'foreign');
    let verify = verifyValues({ iran: a1, foreign: b1, want: desiredValues });
    if (!verify.ok && restoreMode) {
      // `gre mtu restore` re-applies what the CLI recorded, which can be older than the
      // value THIS operation recorded (a restore of an older operation, or a host whose
      // CLI backup was rewritten). Setting the recorded value explicitly is the second
      // attempt — and it is verified like the first.
      stage('VERIFY_INTERFACE_STATE', 'RUNNING', `the CLI restore did not match the recorded value; setting it explicitly (${verify.detail})`);
      const failed = [];
      for (const [key, server] of [['iran', iran], ['foreign', foreign]]) {
        const want = desiredValues[`${key}_mtu`];
        if (want === null) continue;
        const res = await runVerb(remote, server, 'mtu_set', { name: peerName, mtu: want });
        if (!res.ok) failed.push(`${server.name}: ${res.detail}`);
      }
      after = await diagnoseBothSides({ db, row, remote, resolveServer });
      a1 = normalizeSide(after.iran, 'iran');
      b1 = normalizeSide(after.foreign, 'foreign');
      verify = verifyValues({ iran: a1, foreign: b1, want: desiredValues });
      if (failed.length && !verify.ok) {
        verify = { ...verify, detail: `${verify.detail}; the explicit set also failed (${failed.join('; ')})` };
      }
    }
    if (!verify.ok) {
      stage('VERIFY_INTERFACE_STATE', 'FAIL', verify.detail);
      throw abort(`the new MTU could not be verified on both sides: ${verify.detail}`, 502,
        { diagnostics: after, recommendation: rec });
    }
    // A probe that could not run is reported, not smoothed over: the interface is at
    // the target, but the CLI's own diagnosis may still be unhappy about something
    // else on the host.
    const fails = [a1, b1].filter((v) => v.summary && Number(v.summary.fail) > 0)
      .map((v) => `${v.label} reports ${v.summary.fail} failed check(s)`);
    stage('VERIFY_INTERFACE_STATE', fails.length ? 'WARN' : 'PASS',
      `${verify.detail}${fails.length ? `; ${fails.join('; ')}` : ''}`);

    stage('VERIFY_CONNECTIVITY', 'RUNNING', 'checking reachability across the tunnel');
    const connectivity = await readConnectivity({
      remote, iran, foreign, peerName, before: innerReachability(before), diagnose: after,
    });
    if (connectivity.regressions.length) {
      stage('VERIFY_CONNECTIVITY', 'FAIL', connectivity.regressions.join('; '));
      throw abort(`the tunnel did not survive the change: ${connectivity.regressions.join('; ')}`, 502,
        { diagnostics: after, recommendation: rec });
    }
    stage('VERIFY_CONNECTIVITY', connectivity.state === 'PASS' ? 'PASS' : 'WARN', connectivity.detail);

    const now = Date.now();
    db.prepare('UPDATE gre_routes SET last_verified_at = ?, updated_at = ? WHERE id = ?').run(now, now, row.id);
    stage('COMMIT_OR_ROLLBACK', 'PASS', restoreMode
      ? `previous MTU restored on both sides; interfaces and reachability verified (${connectivity.state})`
      : `MTU ${desired} B on both sides; interfaces and reachability verified (${connectivity.state})`);
    journalFinish(db, operationId, 'SUCCEEDED',
      `${restoreMode ? 'restored' : `MTU ${desired}`}; connectivity ${connectivity.state}; ${verify.detail}`, 'NONE');

    return {
      ok: true,
      mode: restoreMode ? 'restore' : 'apply',
      operation_id: operationId,
      connection_id: uuid,
      target: restoreMode ? null : desired,
      applied: desiredValues,
      previous: currentValues,
      recommendation: rec,
      verification: { interface_mtu: verify.detail, checks: verify.checks },
      connectivity: { state: connectivity.state, iran: connectivity.iran, foreign: connectivity.foreign },
      cross_checks: crossChecks,
    };
  } catch (err) {
    // A partial-failure handler above has already rolled back and journaled, and knows
    // more than this handler does: rethrow rather than rolling back twice.
    if (err && err.rollback_outcome) throw err;

    let outcome = 'NONE';
    let detail = 'nothing had been applied yet, so there was nothing to undo';
    if (appliedAny) {
      stage('ROLLBACK_STARTED', 'RUNNING', 'restoring the MTU the two sides had before this change');
      const rb = await restoreValues({ remote, iran, foreign, peerName, previous: currentValues, stage });
      outcome = rb.ok ? 'CLEAN' : 'FAILED';
      detail = rb.detail;
    }

    if (outcome === 'FAILED') {
      stage('ROLLBACK_COMPLETE', 'FAIL', detail);
      stage('COMMIT_OR_ROLLBACK', 'FAIL', `${err.message}; rollback failed: ${detail}`);
      journalFinish(db, operationId, 'ROLLBACK_FAILED', `${err.message}; rollback: ${detail}`, 'FAILED');
    } else if (outcome === 'CLEAN') {
      stage('ROLLBACK_COMPLETE', 'PASS', detail || 'the previous MTU is back and verified');
      stage('COMMIT_OR_ROLLBACK', 'WARN', `${err.message}; the previous MTU was restored and verified`);
      journalFinish(db, operationId, 'ROLLED_BACK', err.message, 'CLEAN');
    } else {
      stage('COMMIT_OR_ROLLBACK', 'WARN', `${err.message}; nothing was changed`);
      journalFinish(db, operationId, 'REJECTED', err.message, 'NONE');
    }

    const out = new Error(err.message);
    out.status = err.status || 500;
    out.operation_id = operationId;
    out.rollback = outcome;
    out.rollback_state = outcome;
    out.previous = currentValues;
    out.recommendation = rec || err.recommendation || null;
    out.diagnostics = err.diagnostics || before || null;
    out.manual_recovery = outcome === 'FAILED'
      ? manualMtuRecovery({ iran, foreign, peerName, previous: currentValues })
      : null;
    throw out;
  } finally {
    releaseLock(acquired);
  }
}

async function applyMtu({ db, row, target, emit, remote, resolveServer, confirm }) {
  // Refuse an unconfirmed change before the journal exists: the journal is for
  // operations that were actually attempted. The approval gate is still recorded as a
  // stage once the evidence has been gathered.
  if (confirm !== true) {
    const err = new Error('an MTU change requires explicit confirmation');
    err.status = 400;
    throw err;
  }
  return runMtuTransaction({ db, row, mode: 'apply', target, emit, remote, resolveServer });
}

// Undo an MTU_CHANGE by re-applying the values it recorded. This goes through the same
// transactional path as a change, so a restore is verified exactly the way the original
// change was.
async function restoreMtu({ db, row, operationId, emit, remote, resolveServer }) {
  const op = journalGet(db, operationId);
  if (!op || op.connection_uuid !== row.connection_uuid || op.kind !== 'MTU_CHANGE') {
    const err = new Error('that operation does not belong to this connection');
    err.status = 404;
    throw err;
  }
  if (op.status === 'RUNNING') {
    const err = new Error('that operation is still running');
    err.status = 409;
    throw err;
  }
  let previous = {};
  try { previous = JSON.parse(op.old_state_json || '{}'); } catch { previous = {}; }
  if (num(previous.iran_mtu) === null && num(previous.foreign_mtu) === null) {
    const err = new Error('that operation has no recorded previous MTU to restore');
    err.status = 409;
    throw err;
  }
  return runMtuTransaction({
    db, row, mode: 'restore', target: null, previous, restoredFrom: operationId, emit, remote, resolveServer,
  });
}

module.exports = {
  MTU_MIN,
  MTU_MAX,
  MTU_MIN_V6,
  MTU_STAGES,
  diagnoseBothSides,
  analyzeNicBothSides,
  recommend,
  planMtuChange,
  applyMtu,
  restoreMtu,
  mtuSummary,
  normalizeSide,
  // Exported for the tests: the two pieces of the safety logic that are worth
  // exercising directly rather than through a whole transaction.
  verifyValues,
  innerReachability,
};
