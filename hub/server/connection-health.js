'use strict';
// connection-health.js — the two-sided Full Network Health Check: the correlation
// layer that turns two per-host answers into ONE diagnosis of a connection, and the
// verified repair that only claims success when a fresh check agrees.
//
// DESIGN NOTES, because the shape of this file is deliberate:
//
//  * `gre health-check` is READ-ONLY and it exits non-zero when the verdict is BROKEN.
//    That exit code is DATA, not a command failure: a host that answers "BROKEN" has
//    answered the question. Treating it as a transport failure would throw away
//    exactly the diagnosis the operator asked for, so a non-zero rc WITH parseable
//    JSON is a successful read.
//
//  * A connection is ONE thing with two ends. Two independent per-host lists would
//    make the operator do the correlation by hand, and would report a single broken
//    tunnel twice — once per side. Findings are therefore grouped by CODE: a code
//    seen on both sides is reported once, with both sides named.
//
//  * The verdict can never be better than the evidence. A side that cannot be read
//    produces an explicit INSUFFICIENT_EVIDENCE finding (a code the CLI itself emits)
//    and `evidence_completeness` becomes partial, rather than a HEALTHY verdict
//    standing in for a host nobody managed to ask.
//
//  * A repair is only reported as done when a FRESH health check no longer reports
//    the code on ANY side. One end fixed and the other still broken is a PARTIAL
//    outcome, and it is reported as a partial outcome. Nothing is rolled back: a
//    repair converges a host onto its own configuration, so undoing it would put the
//    fault back.

const actions = require('./actions');
const { RouteOrchestrator } = require('./route-orchestrator');
// The redaction and the command runner are shared with the MTU layer on purpose: a
// payload that leaves this module must be redacted exactly the way an MTU payload is,
// and a transport failure must keep its own message rather than become "rc=undefined".
const { sanitize, runVerb } = require('./connection-mtu');
const {
  acquireLock, releaseLock, ensureUuid, journalStart, journalStage, journalFinish, journalGet,
} = require('./connections');

// The stage order is the contract a reader of the timeline relies on: the check is
// started, each side is read, the verdict is derived — and for a repair, what was
// offered is stated before anything is applied, and the result is verified before it
// is ever called a success.
const HEALTH_STAGES = ['HEALTH_CHECK_STARTED', 'READ_SIDE', 'DIAGNOSED'];
const REPAIR_STAGES = ['REPAIR_PREVIEW', 'REPAIR_APPLYING', 'REPAIR_VERIFIED'];
const HEALTH_CHECK_KIND = 'HEALTH_CHECK';
const HEALTH_REPAIR_KIND = 'HEALTH_REPAIR';

// A side that has stopped answering must not hold the request open forever. The CLI
// bounds itself with its own budget; this is the hard ceiling above it.
const SIDE_TIMEOUT_CAP_MS = 180000;
const HEALTH_BUDGET_DEFAULT = { quick: 20, full: 75 };
const HEALTH_BUDGET_MAX = 600;

const STATUSES = ['PASS', 'WARN', 'FAIL', 'UNKNOWN', 'SKIPPED'];
const STATUS_RANK = { PASS: 0, SKIPPED: 1, UNKNOWN: 2, WARN: 3, FAIL: 4 };
const SEVERITIES = ['critical', 'warning', 'info'];
const SEVERITY_RANK = { critical: 3, warning: 2, info: 1 };
const RISK_RANK = { none: 0, low: 1, medium: 2, high: 3 };

const CATEGORY_ORDER = [
  'A_ssh_and_server', 'B_underlay', 'C_gre_config', 'D_gre_protocol47',
  'E_tunnel_connectivity', 'F_routing_and_firewall', 'G_mtu_and_mss', 'H_service',
  'Z_diagnostic',
];

// A repair code is an identifier, never free text: it becomes `--code <value>` on a
// remote command, so anything that is not shaped like a code is refused before a
// command exists. Which codes are repairable is the remote CLI's own decision.
const CODE_RE = /^[A-Z][A-Z0-9_]{0,40}$/;

const num = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

const redact = (text) => RouteOrchestrator.redact(String(text === undefined || text === null ? '' : text));

function parseJson(text) {
  try {
    const value = JSON.parse(String(text === undefined || text === null ? '' : text).trim());
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

// A health check prints ONE JSON object, but a host may print a banner or a trailing
// warning line around it. Losing a complete diagnosis because of a stray line would be
// the wrong kind of strict, so the last braced line is tried as a fallback.
function parseHealthJson(text) {
  const raw = String(text === undefined || text === null ? '' : text).trim();
  if (!raw) return null;
  const whole = parseJson(raw);
  if (whole) return whole;
  const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith('{') && l.endsWith('}'));
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const value = parseJson(lines[i]);
    if (value) return value;
  }
  return null;
}

// Bound a promise even when the transport ignores its own timeout, so one dead host
// cannot hold a request (and a lock) open indefinitely.
function withTimeout(promise, ms, onTimeout) {
  let timer = null;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(onTimeout()), ms);
      // Never let a pending guard keep the hub process alive.
      if (timer && typeof timer.unref === 'function') timer.unref();
    }),
  ]).finally(() => { if (timer) clearTimeout(timer); });
}

function sideTimeoutMs(mode, budget) {
  const wanted = num(budget);
  const base = wanted !== null && wanted > 0 ? wanted : (mode === 'full' ? HEALTH_BUDGET_DEFAULT.full : HEALTH_BUDGET_DEFAULT.quick);
  return Math.min(SIDE_TIMEOUT_CAP_MS, Math.round(base * 1000) + 20000);
}

const SIDE_LABELS = { iran: 'Iran', foreign: 'Foreign' };

const emptySummary = () => ({ pass: 0, warn: 0, fail: 0, unknown: 0, skipped: 0, critical_findings: 0 });

function normalizeSummary(input) {
  const s = input && typeof input === 'object' ? input : {};
  const out = emptySummary();
  for (const key of Object.keys(out)) out[key] = num(s[key]) === null ? 0 : Number(s[key]);
  return out;
}

function normalizeCheck(raw, fallbackCategory) {
  const status = String((raw && raw.status) || '').toUpperCase();
  const category = String((raw && raw.category) || fallbackCategory || 'Z_diagnostic');
  return {
    id: String((raw && raw.id) || '').slice(0, 80),
    category: CATEGORY_ORDER.includes(category) ? category : 'Z_diagnostic',
    status: STATUSES.includes(status) ? status : 'UNKNOWN',
    detail: redact((raw && raw.detail) || '').slice(0, 500),
    evidence: redact((raw && raw.evidence) || '').slice(0, 1000),
  };
}

function normalizeFinding(raw, side, serverName) {
  const severity = String((raw && raw.severity) || '').toLowerCase();
  const code = String((raw && raw.code) || '').slice(0, 64);
  return {
    code,
    severity: SEVERITIES.includes(severity) ? severity : 'info',
    server: String((raw && raw.server) || serverName || '').slice(0, 80),
    connection: String((raw && raw.connection) || '').slice(0, 80),
    confidence: String((raw && raw.confidence) || 'unknown').slice(0, 20),
    evidence: redact((raw && raw.evidence) || '').slice(0, 2000),
    probable_cause: redact((raw && raw.probable_cause) || '').slice(0, 1000),
    recommended_action: redact((raw && raw.recommended_action) || '').slice(0, 500),
    safe_repair: (raw && raw.safe_repair) === true,
    risk: String((raw && raw.risk) || 'none').toLowerCase().slice(0, 20),
    repair_key: String((raw && raw.repair_key) || '').slice(0, 40),
    side,
  };
}

// One side, as the rest of this module and the UI want to read it. Always present,
// never partially filled: a side that could not be read carries the reason instead of
// a missing key.
function normalizeHealthSide(input, side, { data = null, rc = null, error = null } = {}) {
  const raw = data || {};
  const server = (input && input.server) || null;
  const checks = (Array.isArray(raw.checks) ? raw.checks : []).map((c) => normalizeCheck(c));
  const findings = (Array.isArray(raw.findings) ? raw.findings : [])
    .map((f) => normalizeFinding(f, side, server))
    .filter((f) => f.code);
  const overallRaw = String(raw.overall_status || '').toUpperCase();
  const completeness = String(raw.evidence_completeness || '').toLowerCase();
  return {
    normalized: true,
    side,
    label: SIDE_LABELS[side] || side,
    server,
    server_id: (input && input.server_id) || null,
    ok: error === null,
    rc,
    error,
    // A non-zero exit carrying a parseable diagnosis is the CLI reporting BROKEN.
    broken_exit: rc !== null && rc !== 0 && error === null,
    mode: raw.mode || null,
    overall_status: ['HEALTHY', 'DEGRADED', 'BROKEN'].includes(overallRaw) ? overallRaw : 'UNKNOWN',
    evidence_completeness: completeness === 'partial' ? 'partial' : completeness === 'complete' ? 'complete' : 'unknown',
    budget_seconds: num(raw.budget_seconds),
    elapsed_seconds: num(raw.elapsed_seconds),
    tested_at: raw.tested_at || null,
    summary: normalizeSummary(raw.summary),
    checks,
    findings,
    data: error === null ? sanitize(raw) : null,
  };
}

// ---------------------------------------------------------------- one side

async function checkSide({ row, remote, resolveServer, side, mode, budget }) {
  const label = SIDE_LABELS[side] || side;
  const serverId = side === 'iran' ? row.iran_server_id : row.foreign_server_id;
  let server = null;
  try { server = resolveServer(serverId); } catch { server = null; }
  const base = { server: server ? server.name : null, server_id: serverId };
  if (!server) {
    return normalizeHealthSide(base, side, { error: `${label} server is not configured` });
  }

  const params = { name: row.peer_name || row.name };
  if (mode === 'quick' || mode === 'full') params.mode = mode;
  if (num(budget) !== null) params.budget = Number(budget);

  const bound = sideTimeoutMs(mode, budget);
  let res;
  try {
    res = await withTimeout(
      runVerb(remote, server, 'health_check', params, bound),
      bound + 10000,
      () => ({ ok: false, rc: null, command: '', stdout: '', stderr: '', detail: `no answer within ${bound + 10000} ms`, timed_out: true }),
    );
  } catch (err) {
    // runVerb already absorbs a thrown transport error; this only fires if the runner
    // itself failed, and the reason must survive.
    return normalizeHealthSide(base, side, { error: redact(err.message) });
  }
  if (!res || res.timed_out) {
    return normalizeHealthSide(base, side, { rc: res ? res.rc : null, error: (res && res.detail) || 'the health check did not answer' });
  }

  const data = parseHealthJson(res.stdout);
  if (!data) {
    // No usable diagnosis. The remote's own message is the most useful thing to say,
    // and a host whose CLI does not know the verb lands here too.
    const detail = String(res.stderr || res.stdout || res.detail || `rc=${res.rc}`).trim().slice(0, 500);
    return normalizeHealthSide(base, side, { rc: res.rc, error: redact(detail || 'the health check returned output that is not JSON') });
  }
  return normalizeHealthSide(base, side, { data, rc: res.rc, error: null });
}

// Run the health check on BOTH ends, in parallel, each with its own bound. Never
// throws: a side that fails, times out or answers with something that is not JSON is
// reported per side, and the other side's evidence still reaches the operator.
async function checkBothSides({ db: _db, row, remote, resolveServer, mode = 'quick', budget, stage, previous = null }) {
  const wanted = mode === 'full' ? 'full' : 'quick';
  if (typeof stage === 'function') stage('READ_SIDE', 'RUNNING', `reading both sides (${wanted} mode)`);
  const [iran, foreign] = await Promise.all([
    checkSide({ row, remote, resolveServer, side: 'iran', mode: wanted, budget }),
    checkSide({ row, remote, resolveServer, side: 'foreign', mode: wanted, budget }),
  ]);
  for (const side of [iran, foreign]) {
    if (typeof stage === 'function') {
      stage('READ_SIDE', side.ok ? 'PASS' : 'FAIL',
        `${side.label}${side.ok ? `: ${side.overall_status} (${side.checks.length} checks, ${side.findings.length} findings)` : `: ${side.error}`}`);
    }
  }
  const combined = mergeFindings(iran, foreign);
  return {
    name: row.peer_name || row.name,
    connection_id: row.connection_uuid || null,
    requested_mode: wanted,
    iran,
    foreign,
    combined: { ...combined, previous },
  };
}

// ------------------------------------------------------- the correlation layer

const worstStatus = (statuses) => statuses.reduce((worst, s) => (STATUS_RANK[s] > STATUS_RANK[worst] ? s : worst), 'PASS');

const findingScore = (f) => SEVERITY_RANK[f.severity] * 10 + (f.safe_repair ? 1 : 0);

// The two sides are ONE connection, so findings are correlated rather than
// concatenated: a code seen on both ends is one problem with two ends named.
function mergeFindings(iranInput, foreignInput) {
  const sides = [
    iranInput && iranInput.normalized ? iranInput : normalizeHealthSide(iranInput || {}, 'iran'),
    foreignInput && foreignInput.normalized ? foreignInput : normalizeHealthSide(foreignInput || {}, 'foreign'),
  ];

  const byCode = new Map();
  const order = [];
  for (const side of sides) {
    for (const finding of side.findings || []) {
      if (!byCode.has(finding.code)) {
        byCode.set(finding.code, { ...finding, sides: [], by_side: {} });
        order.push(finding.code);
      }
      const merged = byCode.get(finding.code);
      if (!merged.sides.includes(side.side)) merged.sides.push(side.side);
      merged.by_side[side.side] = {
        server: finding.server,
        severity: finding.severity,
        confidence: finding.confidence,
        evidence: finding.evidence,
        probable_cause: finding.probable_cause,
        recommended_action: finding.recommended_action,
        safe_repair: finding.safe_repair,
        risk: finding.risk,
        repair_key: finding.repair_key,
      };
      // The representative finding is the most severe one, so a warning reported by
      // one end can never downgrade a critical reported by the other.
      if (findingScore(finding) > findingScore(merged)) {
        const kept = { sides: merged.sides, by_side: merged.by_side };
        Object.assign(merged, finding, kept);
      }
      if (finding.safe_repair) merged.safe_repair = true;
      if (RISK_RANK[finding.risk] > RISK_RANK[merged.risk]) merged.risk = finding.risk;
      if (!merged.repair_key && finding.repair_key) merged.repair_key = finding.repair_key;
      if (!merged.recommended_action && finding.recommended_action) merged.recommended_action = finding.recommended_action;
      merged.severity = SEVERITY_RANK[finding.severity] > SEVERITY_RANK[merged.severity] ? finding.severity : merged.severity;
    }
  }

  // A side nobody could read is not evidence of health. Recording it as a finding —
  // the CLI's own code for exactly this — keeps the verdict rule honest and gives the
  // UI something concrete to show instead of a silently missing column.
  for (const side of sides) {
    if (side.ok) continue;
    const code = 'INSUFFICIENT_EVIDENCE';
    if (!byCode.has(code)) {
      byCode.set(code, {
        code,
        severity: 'info',
        server: side.server,
        connection: null,
        confidence: 'low',
        evidence: side.error || `${side.label} did not answer`,
        probable_cause: `${side.label} could not be read, so nothing about that end of the connection is known`,
        recommended_action: `restore access to ${side.server || side.label} and run the health check again`,
        safe_repair: false,
        risk: 'none',
        repair_key: '',
        sides: [],
        by_side: {},
        synthetic: true,
      });
      order.push(code);
    }
    const merged = byCode.get(code);
    if (!merged.sides.includes(side.side)) merged.sides.push(side.side);
    if (!merged.server) merged.server = side.server;
  }

  const findings = order.map((code) => {
    const merged = byCode.get(code);
    return {
      ...merged,
      repairable_on: merged.sides.filter((s) => merged.by_side[s] && merged.by_side[s].safe_repair),
    };
  });

  // Per-side check rows, so the UI can render `Check | Iran | Foreign` without
  // re-deriving anything: the same check id is one row with two columns.
  const checkRows = new Map();
  const checkOrder = [];
  for (const side of sides) {
    for (const check of side.checks || []) {
      if (!checkRows.has(check.id)) {
        checkRows.set(check.id, { id: check.id, category: check.category, sides: {} });
        checkOrder.push(check.id);
      }
      const row = checkRows.get(check.id);
      if (row.category === 'Z_diagnostic' && check.category !== 'Z_diagnostic') row.category = check.category;
      row.sides[side.side] = { status: check.status, detail: check.detail, evidence: check.evidence };
    }
  }
  const checks = checkOrder.map((id) => {
    const row = checkRows.get(id);
    const statuses = Object.values(row.sides).map((s) => s.status);
    return { ...row, status: worstStatus(statuses.length ? statuses : ['SKIPPED']) };
  });

  const categories = CATEGORY_ORDER
    .map((category) => {
      const list = checks.filter((c) => c.category === category);
      if (!list.length) return null;
      const counts = { iran: emptySummary(), foreign: emptySummary() };
      for (const check of list) {
        for (const side of ['iran', 'foreign']) {
          const cell = check.sides[side];
          if (!cell) continue;
          const key = cell.status.toLowerCase();
          if (Object.prototype.hasOwnProperty.call(counts[side], key)) counts[side][key] += 1;
        }
      }
      return { category, check_ids: list.map((c) => c.id), counts };
    })
    .filter(Boolean);

  const readable = sides.filter((s) => s.ok);
  const anyCritical = findings.some((f) => f.severity === 'critical');
  const anyBrokenSide = readable.some((s) => s.overall_status === 'BROKEN');
  const anyDegradedSide = readable.some((s) => s.overall_status === 'DEGRADED');

  let overall = 'HEALTHY';
  if (anyBrokenSide || anyCritical) overall = 'BROKEN';
  else if (anyDegradedSide || findings.length) overall = 'DEGRADED';

  const partial = sides.some((s) => !s.ok || s.evidence_completeness === 'partial');

  const summary = emptySummary();
  for (const side of sides) {
    for (const key of Object.keys(summary)) {
      if (key === 'critical_findings') continue;
      summary[key] += side.summary[key];
    }
  }
  summary.critical_findings = findings.filter((f) => f.severity === 'critical').length;
  summary.findings = findings.length;
  summary.warning_findings = findings.filter((f) => f.severity === 'warning').length;
  summary.info_findings = findings.filter((f) => f.severity === 'info').length;
  summary.repairable_findings = findings.filter((f) => f.safe_repair).length;

  const testedAt = sides.map((s) => s.tested_at).filter(Boolean).sort().pop() || null;
  const elapsed = sides.map((s) => s.elapsed_seconds).filter((v) => v !== null);
  const budgets = sides.map((s) => s.budget_seconds).filter((v) => v !== null);

  return {
    connection: sides.find((s) => s.ok && s.data && s.data.connection) ? sides.find((s) => s.ok && s.data.connection).data.connection : null,
    connection_id: null,
    mode: (readable.find((s) => s.mode) || {}).mode || null,
    overall_status: overall,
    evidence_completeness: partial ? 'partial' : 'complete',
    tested_at: testedAt,
    budget_seconds: budgets.length ? Math.max(...budgets) : null,
    elapsed_seconds: elapsed.length ? Math.max(...elapsed) : null,
    both_sides: sides.every((s) => s.ok),
    sides_readable: readable.length,
    sides_unreadable: sides.filter((s) => !s.ok).map((s) => s.side),
    summary,
    checks,
    categories,
    findings,
    per_side: {
      iran: sideColumn(sides[0]),
      foreign: sideColumn(sides[1]),
    },
  };
}

function sideColumn(side) {
  return {
    side: side.side,
    label: side.label,
    server: side.server,
    server_id: side.server_id,
    ok: side.ok,
    error: side.error,
    overall_status: side.overall_status,
    evidence_completeness: side.evidence_completeness,
    mode: side.mode,
    tested_at: side.tested_at,
    elapsed_seconds: side.elapsed_seconds,
    budget_seconds: side.budget_seconds,
    summary: side.summary,
    findings: (side.findings || []).map((f) => ({ code: f.code, severity: f.severity, confidence: f.confidence, safe_repair: f.safe_repair, risk: f.risk, repair_key: f.repair_key })),
    checks: (side.checks || []).map((c) => ({ id: c.id, category: c.category, status: c.status, detail: c.detail })),
  };
}

// ------------------------------------------------------------------- history

function summaryField(row, key, fallback = null) {
  const plan = parseJson(row.plan_json) || {};
  return Object.prototype.hasOwnProperty.call(plan, key) ? plan[key] : fallback;
}

// One journal row, as the history list wants it. Small on purpose: the full run stays
// in requested_state_json and is only read when a single run is opened.
function summarizeRun(row) {
  return {
    check_id: row.operation_id,
    connection_id: row.connection_uuid,
    route_id: row.route_id,
    kind: row.kind,
    mode: summaryField(row, 'mode'),
    overall_status: summaryField(row, 'overall_status'),
    evidence_completeness: summaryField(row, 'evidence_completeness'),
    summary: summaryField(row, 'summary', null),
    sides: summaryField(row, 'sides', null),
    code: summaryField(row, 'code'),
    partial: summaryField(row, 'partial'),
    status: row.status,
    current_stage: row.current_stage,
    rollback_state: row.rollback_state,
    detail: row.detail,
    created_at: row.created_at,
    completed_at: row.completed_at,
  };
}

// The diagnostic history of one connection: health checks and the repairs that
// followed them, newest first, so the operator can see what was tried and what it did.
function healthHistory(db, uuid, limit = 25) {
  if (!db || !uuid) return [];
  const capped = Math.max(1, Math.min(100, Number(limit) || 25));
  let rows = [];
  try {
    rows = db.prepare(`SELECT * FROM edit_operations
        WHERE connection_uuid = ? AND kind IN (?, ?)
        ORDER BY created_at DESC LIMIT ?`).all(uuid, HEALTH_CHECK_KIND, HEALTH_REPAIR_KIND, capped);
  } catch { return []; }
  return rows.map(summarizeRun);
}

// One stored run, by check id. Scoped to this connection on purpose: an id from
// another connection must not be readable through this route.
function storedRun(db, uuid, checkId) {
  const row = journalGet(db, checkId);
  if (!row || row.connection_uuid !== uuid) return null;
  if (row.kind !== HEALTH_CHECK_KIND && row.kind !== HEALTH_REPAIR_KIND) return null;
  const stored = parseJson(row.requested_state_json) || {};
  return { ...summarizeRun(row), run: stored.run || stored.result || null, payload: stored };
}

// The last completed run of this connection, so a new check can say whether the
// verdict moved. Journal-only: no SSH, no lock.
function previousCheck(db, uuid) {
  if (!db || !uuid) return null;
  try {
    const row = db.prepare(`SELECT * FROM edit_operations
        WHERE connection_uuid = ? AND kind = ? AND status != 'RUNNING'
        ORDER BY created_at DESC LIMIT 1`).get(uuid, HEALTH_CHECK_KIND);
    if (!row) return null;
    return {
      check_id: row.operation_id,
      overall_status: summaryField(row, 'overall_status'),
      evidence_completeness: summaryField(row, 'evidence_completeness'),
      created_at: row.created_at,
    };
  } catch { return null; }
}

// ---------------------------------------------------------------- the journal

function journalPatch(db, operationId, column, value) {
  try {
    db.prepare(`UPDATE edit_operations SET ${column} = ? WHERE operation_id = ?`)
      .run(JSON.stringify(value || {}), operationId);
  } catch { /* journaling must never break an operation */ }
}

// ------------------------------------------------------- the read-only check

// Take the connection lock, run the check, record it, release. The check itself
// mutates nothing, but it does run commands on two hosts, so two runs must not overlap
// on one connection — and a run that is refused leaves no journal row behind, because
// an operation that never started is not a record worth keeping.
async function runHealthCheck({ db, row, mode = 'quick', budget, emit, remote, resolveServer }) {
  const uuid = ensureUuid(db, row);
  const wanted = mode === 'full' ? 'full' : 'quick';
  const previous = previousCheck(db, uuid);
  const acquired = acquireLock([
    { kind: 'connection', id: uuid },
    { kind: 'server', id: row.iran_server_id },
    { kind: 'server', id: row.foreign_server_id },
  ], 'health-check');
  if (!acquired.ok) {
    const err = new Error('a health check or another operation is already running for this connection');
    err.status = 409;
    err.held = acquired.held;
    throw err;
  }

  const operationId = journalStart(db, {
    uuid,
    routeId: row.id,
    kind: HEALTH_CHECK_KIND,
    oldState: {},
    requestedState: { mode: wanted, budget: num(budget) },
    plan: { mode: wanted, budget_seconds: num(budget), stages: HEALTH_STAGES },
  });

  const stage = (name, status, detail) => {
    journalStage(db, operationId, name, status, detail);
    if (typeof emit === 'function') {
      try { emit(name, status, detail); } catch { /* the journal is the durable record */ }
    }
  };

  try {
    stage('HEALTH_CHECK_STARTED', 'RUNNING',
      `read-only check of ${row.peer_name || row.name} on both endpoints (${wanted} mode)`);
    const result = await checkBothSides({ db, row, remote, resolveServer, mode: wanted, budget, stage, previous });
    const combined = { ...result.combined, connection_id: uuid, route_id: row.id };
    const run = {
      check_id: operationId,
      connection_id: uuid,
      route_id: row.id,
      connection: combined.connection || row.peer_name || row.name,
      mode: wanted,
      iran: result.iran,
      foreign: result.foreign,
      combined,
    };
    journalPatch(db, operationId, 'requested_state_json', { mode: wanted, budget: num(budget), run });
    journalPatch(db, operationId, 'plan_json', {
      mode: wanted,
      budget_seconds: combined.budget_seconds,
      overall_status: combined.overall_status,
      evidence_completeness: combined.evidence_completeness,
      summary: combined.summary,
      sides: {
        iran: { ok: result.iran.ok, overall_status: result.iran.overall_status, error: result.iran.error },
        foreign: { ok: result.foreign.ok, overall_status: result.foreign.overall_status, error: result.foreign.error },
      },
      previous_check_id: previous ? previous.check_id : null,
      stages: HEALTH_STAGES,
    });

    const detail = `${combined.overall_status} (${combined.evidence_completeness} evidence); `
      + `read ${combined.sides_readable}/2 sides, ${combined.summary.fail} failed checks, `
      + `${combined.summary.findings} finding(s), ${combined.summary.critical_findings} critical`;
    stage('DIAGNOSED', combined.overall_status === 'BROKEN' ? 'FAIL' : combined.overall_status === 'HEALTHY' ? 'PASS' : 'WARN', detail);
    // The run itself succeeded whenever a side answered: a BROKEN verdict is a
    // diagnosis, not a failure of the check.
    journalFinish(db, operationId, combined.sides_readable > 0 ? 'SUCCEEDED' : 'FAILED', detail, 'NONE');
    return run;
  } catch (err) {
    stage('DIAGNOSED', 'FAIL', redact(err.message));
    journalFinish(db, operationId, 'FAILED', err.message, 'NONE');
    // The caller turns this into an audit entry and an HTTP error; naming the operation
    // is what lets an operator find the stored row afterwards.
    if (!err.operation_id) err.operation_id = operationId;
    throw err;
  } finally {
    releaseLock(acquired);
  }
}

// ------------------------------------------------------------------- planning

const requireCode = (value) => {
  const code = String(value === undefined || value === null ? '' : value).trim();
  if (!CODE_RE.test(code)) {
    const err = new Error('code must be an uppercase finding code such as GRE_INTERFACE_DOWN');
    err.status = 400;
    throw err;
  }
  return code;
};

async function readPreviewSide({ row, remote, resolveServer, side }) {
  const label = SIDE_LABELS[side] || side;
  const serverId = side === 'iran' ? row.iran_server_id : row.foreign_server_id;
  let server = null;
  try { server = resolveServer(serverId); } catch { server = null; }
  const base = {
    side, label, server_id: serverId, server: server ? server.name : null,
    ok: false, error: null, read_only: null, repairable: [], detail: null,
  };
  if (!server) return { ...base, error: `${label} server is not configured` };
  const bound = SIDE_TIMEOUT_CAP_MS;
  const res = await withTimeout(
    runVerb(remote, server, 'repair_preview', { name: row.peer_name || row.name }, bound),
    bound + 10000,
    () => ({ ok: false, rc: null, stdout: '', stderr: '', detail: `no answer within ${bound + 10000} ms`, timed_out: true }),
  );
  if (!res || res.timed_out) {
    return { ...base, error: (res && res.detail) || 'the repair preview did not answer' };
  }
  const data = parseHealthJson(res.stdout);
  if (!data) {
    const detail = String(res.stderr || res.stdout || res.detail || `rc=${res.rc}`).trim().slice(0, 500);
    return { ...base, error: redact(detail || 'the repair preview returned output that is not JSON') };
  }
  const repairable = (Array.isArray(data.repairable) ? data.repairable : [])
    .map((f) => normalizeFinding(f, side, server.name))
    .filter((f) => f.code);
  return {
    ...base,
    ok: true,
    detail: res.detail,
    // The CLI states this itself; it is reported rather than assumed.
    read_only: data.read_only === true,
    repairable,
  };
}

// Read-only. Creates no operation and opens no lock, so the UI can ask what a repair
// would do while the operator is still deciding. It READS both hosts, because which
// end can repair a code is a fact only the hosts know.
async function planRepair({ db: _db, row, code, remote, resolveServer }) {
  const wanted = requireCode(code);
  const sides = await Promise.all([
    readPreviewSide({ row, remote, resolveServer, side: 'iran' }),
    readPreviewSide({ row, remote, resolveServer, side: 'foreign' }),
  ]);

  const perSide = {};
  for (const side of sides) {
    const offer = (side.repairable || []).find((f) => f.code === wanted) || null;
    perSide[side.side] = {
      side: side.side,
      label: side.label,
      server: side.server,
      server_id: side.server_id,
      ok: side.ok,
      error: side.error,
      read_only: side.read_only,
      can_repair: !!offer,
      safe_repair: !!(offer && offer.safe_repair),
      severity: offer ? offer.severity : null,
      confidence: offer ? offer.confidence : null,
      risk: offer ? offer.risk : null,
      repair_key: offer ? offer.repair_key : '',
      recommended_action: offer ? offer.recommended_action : '',
      probable_cause: offer ? offer.probable_cause : '',
      evidence: offer ? offer.evidence : '',
      repairable_codes: (side.repairable || []).map((f) => f.code),
      reason: !side.ok
        ? `could not be read: ${side.error}`
        : offer
          ? null
          : 'this end does not offer a safe automated repair for that code',
    };
  }

  const offering = sides.filter((s) => s.ok && (s.repairable || []).some((f) => f.code === wanted)).map((s) => s.side);
  const unreadable = sides.filter((s) => !s.ok).map((s) => s.side);
  const risks = offering
    .map((key) => perSide[key].risk || 'none')
    .filter((r) => r !== 'none');
  const riskLevel = risks.length ? risks.reduce((worst, r) => (RISK_RANK[r] > RISK_RANK[worst] ? r : worst), 'none') : 'none';
  const repairKeys = [...new Set(offering.map((key) => perSide[key].repair_key).filter(Boolean))];

  const whatHappens = offering.map((key) => {
    const s = perSide[key];
    return `${s.label} (${s.server}): ${s.recommended_action || 'run the repair the CLI reports for this code'}`;
  });
  if (!offering.length) {
    whatHappens.push('nothing: neither end offers a safe automated repair for this code');
  } else {
    whatHappens.push('the scope is this connection only: no other connection and no NIC is touched');
  }

  const blocked = [];
  if (!offering.length) blocked.push(`${wanted} is not repairable automatically on either end of this connection`);
  for (const side of sides) {
    if (side.ok) continue;
    // The verification below requires the code to be gone from EVERY side. A side that
    // cannot be read cannot be verified, so applying a half-blind repair is refused
    // rather than reported as a success that was never checked.
    blocked.push(`${side.label} could not be read (${side.error}), so a repair cannot be verified across the connection`);
  }

  return {
    read_only: true,
    connection: row.peer_name || row.name,
    connection_id: row.connection_uuid || null,
    route_id: row.id,
    code: wanted,
    sides: perSide,
    repairable_sides: offering,
    unreadable_sides: unreadable,
    repair_keys: repairKeys,
    // The repair is a convergence onto this host's own configuration, so the honest
    // recovery is to run the check again, not to undo a repair.
    verification: [
      { id: 'code_absent_on_iran', description: 'a fresh health check on the Iran side no longer reports this code' },
      { id: 'code_absent_on_foreign', description: 'a fresh health check on the Foreign side no longer reports this code' },
      { id: 'both_sides_readable', description: 'both ends answered the verification check, so "gone" means observed gone' },
    ],
    rollback_conditions: [
      'the repair is not rolled back: it re-applies the connection\'s own configuration, so undoing it would restore the fault',
      'a repair whose code is still reported afterwards is reported as a failure, and nothing is claimed to be fixed',
      'one end repaired while the other fails is reported as a PARTIAL outcome, never as a success',
    ],
    what_happens: whatHappens,
    risk: { level: riskLevel, reasons: risks.length ? [] : ['no side offered a repair'] },
    risk_level: riskLevel,
    can_apply: blocked.length === 0,
    blocked_reason: blocked.length ? blocked[0] : null,
    blocked_reasons: blocked,
  };
}

// ------------------------------------------------------------------ applying

// Apply ONE named repair on each side that offered it, then RE-RUN the health check on
// both sides. Success is claimed only when the code is gone from every side: an
// unverified repair is not a repaired tunnel.
async function applyRepair({
  db, row, code, emit, remote, resolveServer, confirm,
}) {
  // Refuse an unconfirmed repair before a journal row exists: the journal is for
  // operations that were actually attempted.
  if (confirm !== true) {
    const err = new Error('applying a repair requires explicit confirmation');
    err.status = 400;
    throw err;
  }
  const wanted = requireCode(code);

  // The plan is read-only, so it is taken before the lock: it is the evidence that
  // decides whether anything should be attempted at all.
  const plan = await planRepair({ db, row, code: wanted, remote, resolveServer });
  if (!plan.can_apply) {
    const err = new Error(plan.blocked_reason || 'this repair cannot be applied');
    err.status = 409;
    err.plan = plan;
    throw err;
  }

  const uuid = ensureUuid(db, row);
  const name = row.peer_name || row.name;
  const servers = {
    iran: resolveServer(row.iran_server_id),
    foreign: resolveServer(row.foreign_server_id),
  };
  if (!servers.iran || !servers.foreign) {
    const err = new Error('both endpoints of this connection must exist before a repair can be applied');
    err.status = 409;
    throw err;
  }

  const operationId = journalStart(db, {
    uuid,
    routeId: row.id,
    kind: HEALTH_REPAIR_KIND,
    oldState: {},
    requestedState: { code: wanted, sides: plan.repairable_sides, repair_keys: plan.repair_keys },
    plan: {
      code: wanted,
      sides: plan.sides,
      repairable_sides: plan.repairable_sides,
      verification: plan.verification,
      stages: REPAIR_STAGES,
    },
  });

  const acquired = acquireLock([
    { kind: 'connection', id: uuid },
    { kind: 'server', id: row.iran_server_id },
    { kind: 'server', id: row.foreign_server_id },
  ], operationId);
  if (!acquired.ok) {
    journalFinish(db, operationId, 'REJECTED', 'another operation holds this connection or one of its servers', 'NONE');
    const err = new Error('another edit, MTU change or repair is already running for this connection or one of its servers');
    err.status = 409;
    err.operation_id = operationId;
    throw err;
  }

  const stage = (stageName, status, detail) => {
    journalStage(db, operationId, stageName, status, detail);
    if (typeof emit === 'function') {
      try { emit(stageName, status, detail); } catch { /* the journal is the durable record */ }
    }
  };

  try {
    const offeringDetail = plan.repairable_sides
      .map((key) => `${plan.sides[key].label}: ${plan.sides[key].recommended_action || wanted}`)
      .join('; ');
    stage('REPAIR_PREVIEW', 'PASS', `${wanted} is repairable on ${plan.repairable_sides.join(', ')} — read-only preview: ${offeringDetail}`);
    stage('REPAIR_APPLYING', 'RUNNING', `${wanted} on ${plan.repairable_sides.map((k) => servers[k].name).join(' and ')}`);

    const applied = [];
    for (const key of ['iran', 'foreign']) {
      if (!plan.repairable_sides.includes(key)) continue;
      const server = servers[key];
      const res = await runVerb(remote, server, 'repair_apply', { name, code: wanted }, SIDE_TIMEOUT_CAP_MS);
      applied.push({
        side: key, label: plan.sides[key].label, server: server.name,
        ok: res.ok, rc: res.rc, detail: res.detail, repair_key: plan.sides[key].repair_key,
      });
      stage('REPAIR_APPLYING', res.ok ? 'PASS' : 'FAIL',
        `${server.name}: ${res.ok ? `${plan.sides[key].repair_key || 'repair'} applied` : res.detail}`);
    }

    // The only evidence that may claim success: a FRESH check, on both ends.
    stage('REPAIR_APPLYING', applied.every((a) => a.ok) ? 'PASS' : 'FAIL',
      applied.map((a) => `${a.server} ${a.ok ? 'applied' : `failed (${a.detail})`}`).join('; '));
    const after = await checkBothSides({ db, row, remote, resolveServer, mode: 'quick', stage, previous: null });

    const still = {};
    for (const key of ['iran', 'foreign']) {
      const side = after[key];
      const finding = (side.findings || []).find((f) => f.code === wanted) || null;
      still[key] = side.ok
        ? (finding ? { present: true, severity: finding.severity, evidence: finding.evidence } : { present: false })
        : { present: null, error: side.error };
    }
    const unreadable = ['iran', 'foreign'].filter((key) => !after[key].ok);
    const remaining = ['iran', 'foreign'].filter((key) => still[key].present === true);
    const failedApplies = applied.filter((a) => !a.ok);
    // A side counts as REPAIRED only when its own repair succeeded AND a fresh check
    // confirms the code is gone from it. Everything else is unresolved.
    const repairedSides = ['iran', 'foreign'].filter((key) => applied.some((a) => a.side === key && a.ok)
      && still[key].present === false);
    const unresolvedSides = ['iran', 'foreign'].filter((key) => !repairedSides.includes(key)
      && (applied.some((a) => a.side === key) || still[key].present !== false));
    const partial = repairedSides.length > 0 && unresolvedSides.length > 0;
    const verified = unreadable.length === 0 && remaining.length === 0;

    const combined = { ...after.combined, connection_id: uuid, route_id: row.id };
    const result = {
      ok: verified,
      status: verified ? 'SUCCEEDED' : (partial ? 'PARTIAL' : 'FAILED'),
      partial,
      operation_id: operationId,
      connection_id: uuid,
      connection: name,
      code: wanted,
      repair_keys: plan.repair_keys,
      applied_sides: applied.filter((a) => a.ok).map((a) => a.side),
      attempted_sides: applied.map((a) => a.side),
      repaired_sides: repairedSides,
      unresolved_sides: unresolvedSides,
      applied,
      plan_sides: plan.sides,
      before: { repairable_sides: plan.repairable_sides, risk_level: plan.risk_level },
      after: combined,
      verification: {
        method: `gre health-check --name ${name} --quick on both sides`,
        code: wanted,
        still_reported_on: remaining,
        unreadable_sides: unreadable,
        verified,
      },
    };

    journalPatch(db, operationId, 'requested_state_json', { code: wanted, result });
    journalPatch(db, operationId, 'plan_json', {
      code: wanted,
      mode: 'quick',
      partial: result.partial,
      overall_status: combined.overall_status,
      evidence_completeness: combined.evidence_completeness,
      summary: combined.summary,
      sides: {
        iran: { ok: after.iran.ok, overall_status: after.iran.overall_status, error: after.iran.error, applied: applied.some((a) => a.side === 'iran' && a.ok) },
        foreign: { ok: after.foreign.ok, overall_status: after.foreign.overall_status, error: after.foreign.error, applied: applied.some((a) => a.side === 'foreign' && a.ok) },
      },
      stages: REPAIR_STAGES,
    });

    if (verified) {
      stage('REPAIR_VERIFIED', 'PASS',
        `${wanted} is no longer reported on either side (verification check ${combined.overall_status})`);
      journalFinish(db, operationId, 'SUCCEEDED',
        `${wanted} repaired on ${result.applied_sides.join(', ')} and gone from every side`, 'NONE');
      return result;
    }

    // Honest failure reporting. A one-sided success is the most dangerous outcome to
    // dress up as a success: the operator would stop looking at the other end.
    const reasons = [];
    for (const failure of failedApplies) reasons.push(`${failure.server} could not apply the repair: ${failure.detail}`);
    for (const key of remaining) reasons.push(`${after[key].label} still reports ${wanted}`);
    for (const key of unreadable) reasons.push(`${after[key].label} could not be re-read (${after[key].error}), so the repair could not be verified there`);
    const reasonText = reasons.join('; ') || `${wanted} could not be verified as repaired`;
    stage('REPAIR_FAILED', 'FAIL', reasonText);
    journalFinish(db, operationId, result.status, reasonText, 'NONE');

    const err = new Error(result.partial
      ? `the repair was applied on ${repairedSides.join(', ')} but not everywhere: ${reasonText}`
      : `the repair did not fix ${wanted}: ${reasonText}`);
    Object.assign(err, result, { ok: false, reasons, operation_id: operationId });
    // `result.status` is the OUTCOME (PARTIAL / FAILED), not an HTTP status: copying it
    // onto the error would turn the response into an invalid status code.
    err.outcome = result.status;
    err.status = 502;
    throw err;
  } finally {
    releaseLock(acquired);
  }
}

module.exports = {
  HEALTH_STAGES,
  REPAIR_STAGES,
  HEALTH_CHECK_KIND,
  HEALTH_REPAIR_KIND,
  HEALTH_BUDGET_DEFAULT,
  HEALTH_BUDGET_MAX,
  CATEGORY_ORDER,
  checkBothSides,
  mergeFindings,
  normalizeHealthSide,
  parseHealthJson,
  planRepair,
  applyRepair,
  runHealthCheck,
  healthHistory,
  storedRun,
  previousCheck,
  requireCode,
  // Exported so the repair gate can be reasoned about without a whole transaction.
  sideTimeoutMs,
};
