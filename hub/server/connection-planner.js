'use strict';
// connection-planner.js — what would an edit actually change?
//
// This is the single planner for the Hub. It deliberately mirrors the semantics of
// the v2.16.0 CLI planner (see PLAN_* in gre-manager.sh) rather than inventing a
// second set of rules: a ports-only edit is Class A there and here, an endpoint or
// tunnel-parameter change is Class B, and a change of parent server is Class C.
//
// It is PURE: it reads no database and touches no server. Everything it needs is
// passed in, which is what makes plan-edit safe to call on production and trivial
// to test.

const CLASS_RULE_ONLY = 'A';
const CLASS_RECREATE = 'B';
const CLASS_MIGRATION = 'C';

// Fields whose change forces the tunnel to be rebuilt. Same set the CLI uses.
const TUNNEL_FIELDS = new Set(['key', 'subnet_base', 'idx', 'iran_ip', 'foreign_ip', 'name']);
// Fields that only affect rules.
const RULE_FIELDS = new Set(['tcp_ports', 'udp_ports', 'mss_clamp']);

const FIELD_LABELS = {
  name: 'Connection name',
  iran_server_id: 'Iran server',
  foreign_server_id: 'Foreign server',
  iran_ip: 'Iran IP',
  foreign_ip: 'Foreign IP',
  subnet_base: 'Subnet base',
  idx: 'Index',
  key: 'GRE key',
  tcp_ports: 'TCP ports',
  udp_ports: 'UDP ports',
  mss_clamp: 'MSS clamp',
};

const PORT_LIST_RE = /^[0-9,:-]*$/;

function normalize(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function sameValue(a, b) {
  if (a === undefined || a === null) return normalize(b) === '';
  return normalize(a) === normalize(b);
}

function mssLabel(value) {
  return Number(value) === 1 ? 'on' : 'off';
}

// Diff the requested state against the current one.
//
// Only fields actually PRESENT in `requested` are considered: an untouched field
// keeps its current value, which is what "Enter means keep" needs.
function planEdit(current, requested) {
  const changes = [];
  const seen = new Set();
  for (const field of Object.keys(FIELD_LABELS)) {
    if (!Object.prototype.hasOwnProperty.call(requested, field)) continue;
    if (requested[field] === undefined || requested[field] === null) continue;
    seen.add(field);
    const before = normalize(current[field]);
    const after = normalize(requested[field]);
    let changed;
    if (field === 'mss_clamp') {
      changed = Number(before || 0) !== Number(after || 0);
    } else {
      changed = before !== after;
    }
    if (!changed) continue;
    changes.push({
      field,
      label: FIELD_LABELS[field],
      from: field === 'mss_clamp' ? mssLabel(before) : before,
      to: field === 'mss_clamp' ? mssLabel(after) : after,
    });
  }

  // Classify. A server change dominates: it is a migration whatever else moved.
  const serverChanged = changes.some((c) => c.field === 'iran_server_id' || c.field === 'foreign_server_id');
  const tunnelChanged = changes.some((c) => TUNNEL_FIELDS.has(c.field));
  let code = null;
  if (changes.length) {
    if (serverChanged) code = CLASS_MIGRATION;
    else if (tunnelChanged) code = CLASS_RECREATE;
    else code = CLASS_RULE_ONLY;
  }

  return {
    class: code,
    class_label: classLabel(code),
    changes,
    impact: impactFor(code, changes),
    fields: [...seen],
  };
}

function classLabel(code) {
  switch (code) {
    case CLASS_RULE_ONLY: return 'rule-only update (the tunnel is not rebuilt)';
    case CLASS_RECREATE: return 'transactional recreate (the tunnel is rebuilt)';
    case CLASS_MIGRATION: return 'server migration (make-before-break)';
    default: return 'no changes';
  }
}

function impactFor(code, changes) {
  const impact = [];
  if (code === CLASS_MIGRATION) {
    impact.push('Migration to a different server');
    impact.push('A new path is built and verified before the old one is removed');
  }
  if (code === CLASS_RECREATE) {
    impact.push('GRE tunnel recreation required');
  }
  for (const c of changes) {
    switch (c.field) {
      case 'iran_server_id': impact.push('Iran-side configuration will change'); break;
      case 'foreign_server_id': impact.push('Foreign-side configuration will change'); break;
      case 'iran_ip': case 'foreign_ip': impact.push('Endpoint addressing will change'); break;
      case 'subnet_base': case 'idx': impact.push('Tunnel subnet will change'); break;
      case 'key': impact.push('GRE key will change'); break;
      case 'name': impact.push('Connection renamed (config file, tunnel and rule comments)'); break;
      case 'tcp_ports': impact.push('NAT TCP rules will change'); break;
      case 'udp_ports': impact.push('NAT UDP rules will change'); break;
      case 'mss_clamp': impact.push('MSS clamping will change'); break;
      default: break;
    }
  }
  if (changes.length) {
    impact.push('Watchdog preserved');
    impact.push('Other connections are not touched');
  }
  return impact;
}

// How disruptive is this, in plain words?
function estimateDisruption(code) {
  switch (code) {
    case CLASS_RULE_ONLY:
      return 'None expected: the tunnel stays up and only the rule set is replaced.';
    case CLASS_RECREATE:
      return 'Brief: this one tunnel is rebuilt and re-verified. Other connections are unaffected.';
    case CLASS_MIGRATION:
      return 'Brief: the new path is built and verified before the old one is removed, so the connection is not torn down first.';
    default:
      return 'None: nothing to apply.';
  }
}

// ------------------------------------------------------------------ validation
//
// Shape validation only. Anything that needs to look at the server or at another
// connection is a preflight check, because it needs I/O.

function validateRequest(requested, current) {
  const errors = [];
  const req = requested || {};

  if (req.name !== undefined && !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,10}$/.test(String(req.name))) {
    errors.push('Connection name must be 1-11 letters, digits, _ or -, starting with a letter or digit');
  }
  for (const ipField of ['iran_ip', 'foreign_ip']) {
    const v = req[ipField];
    if (v === undefined) continue;
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(String(v))) errors.push(`${FIELD_LABELS[ipField]} is not a valid IPv4 address`);
  }
  if (req.subnet_base !== undefined && !/^\d{1,3}\.\d{1,3}$/.test(String(req.subnet_base))) {
    errors.push('Subnet base must look like A.B (e.g. 10.212)');
  }
  if (req.idx !== undefined) {
    const n = Number(req.idx);
    if (!Number.isInteger(n) || n < 1 || n > 254) errors.push('Index must be an integer 1-254');
  }
  if (req.key !== undefined) {
    const n = Number(req.key);
    if (!Number.isInteger(n) || n < 0) errors.push('GRE key must be a non-negative integer');
  }
  for (const pf of ['tcp_ports', 'udp_ports']) {
    const v = req[pf];
    if (v === undefined) continue;
    if (v === '' || v === null) continue;
    if (!PORT_LIST_RE.test(String(v))) errors.push(`${FIELD_LABELS[pf]} must be a comma-separated port list (ranges with - or :)`);
  }
  if (req.mss_clamp !== undefined && req.mss_clamp !== null && req.mss_clamp !== '') {
    const v = String(req.mss_clamp);
    if (!['on', 'off', '1', '0', 'true', 'false'].includes(v)) errors.push('MSS clamp must be on or off');
  }
  if (req.iran_server_id !== undefined && current && req.iran_server_id !== null) {
    if (Number(req.iran_server_id) === Number(current.foreign_server_id)) {
      errors.push('Iran server cannot be the same host as the Foreign server');
    }
  }
  if (req.foreign_server_id !== undefined && current && req.foreign_server_id !== null) {
    if (Number(req.foreign_server_id) === Number(current.iran_server_id)) {
      errors.push('Foreign server cannot be the same host as the Iran server');
    }
  }
  return errors;
}

// ------------------------------------------------------------------- preflight
//
// Pure checks that need only the data already on hand: which servers exist, what
// other connections hold. Everything requiring SSH is the caller's job, and its
// results are merged in by the route so one response describes the whole picture.

function preflight(requested, current, context) {
  const {
    servers = [],
    connections = [],
    currentId = null,
  } = context || {};
  const req = requested || {};
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail: detail || '' });

  const byId = new Map(servers.map((s) => [Number(s.id), s]));
  const other = connections.filter((c) => Number(c.id) !== Number(currentId));

  const iranId = Number(req.iran_server_id !== undefined ? req.iran_server_id : current.iran_server_id);
  const foreignId = Number(req.foreign_server_id !== undefined ? req.foreign_server_id : current.foreign_server_id);

  const iran = byId.get(iranId);
  const foreign = byId.get(foreignId);
  add('Iran server exists', !!iran, iran ? iran.name : `no server #${iranId}`);
  add('Foreign server exists', !!foreign, foreign ? foreign.name : `no server #${foreignId}`);
  add('Iran and Foreign are different hosts', iranId !== foreignId, iranId === foreignId ? 'the same server was selected twice' : '');

  // Subnet + index ownership must not collide with a DIFFERENT connection.
  const subnetBase = req.subnet_base !== undefined ? String(req.subnet_base) : normalize(current.subnet_base);
  const idx = req.idx !== undefined ? String(req.idx) : normalize(current.idx);
  const subnetOwner = other.find((c) => normalize(c.subnet_base) === subnetBase && normalize(c.idx) === idx);
  add('Subnet and index are free', !subnetOwner,
    subnetOwner ? `${subnetBase}.${idx} is already used by '${subnetOwner.name}'` : `${subnetBase}.${idx}`);

  // Port ownership: the same (server, protocol, port) may belong to one connection.
  for (const proto of ['tcp_ports', 'udp_ports']) {
    if (req[proto] === undefined) continue;
    const requestedPorts = normalize(req[proto]);
    if (!requestedPorts) {
      add(`${proto === 'tcp_ports' ? 'TCP' : 'UDP'} ports freed`, true, 'list cleared');
      continue;
    }
    const conflict = other.find((c) => portsOverlap(requestedPorts, normalize(c[proto])));
    add(`${proto === 'tcp_ports' ? 'TCP' : 'UDP'} ${requestedPorts} available`, !conflict,
      conflict ? `already owned by '${conflict.name}'` : '');
  }

  // Name ownership.
  if (req.name !== undefined) {
    const nameOwner = other.find((c) => normalize(c.name) === normalize(req.name));
    add('Connection name is free', !nameOwner, nameOwner ? `already used by '${nameOwner.name}'` : normalize(req.name));
  }

  // Server reachability is reported here but resolved over SSH by the caller; an
  // unreachable target is a hard stop for a migration.
  for (const [label, srv] of [['Iran', iran], ['Foreign', foreign]]) {
    if (!srv) continue;
    add(`${label} server has credentials`, !!srv.has_secret,
      srv.has_secret ? '' : 'no password or key stored for this server');
  }

  return checks;
}

// Range-aware overlap, matching the CLI's port_lists_overlap semantics.
function portsOverlap(a, b) {
  if (!a || !b) return false;
  const expand = (list) => {
    const out = new Set();
    for (const part of String(list).split(',')) {
      const p = part.trim();
      if (!p) continue;
      const m = p.match(/^(\d+)[-:](\d+)$/);
      if (m) {
        const lo = Number(m[1]); const hi = Number(m[2]);
        if (Number.isFinite(lo) && Number.isFinite(hi) && hi - lo <= 4096) {
          for (let n = lo; n <= hi; n += 1) out.add(n);
        }
        continue;
      }
      if (/^\d+$/.test(p)) out.add(Number(p));
    }
    return out;
  };
  const A = expand(a);
  for (const n of expand(b)) if (A.has(n)) return true;
  return false;
}

module.exports = {
  planEdit,
  validateRequest,
  preflight,
  portsOverlap,
  classLabel,
  estimateDisruption,
  CLASS_RULE_ONLY,
  CLASS_RECREATE,
  CLASS_MIGRATION,
  TUNNEL_FIELDS,
  RULE_FIELDS,
  FIELD_LABELS,
};
