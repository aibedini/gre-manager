'use strict';
// discovery.js — probe a server over SSH and build a status snapshot.
//
// The probe is a single bash script that prints marker-delimited sections:
//   @@BEGIN name@@ ... @@END name@@
// Sections:
//   gre           — whether the manager is installed + `gre --version`
//   status_json   — `gre status --json` (only when installed)
//   tunnels       — `ip -d tunnel show`
//   managed_tuns  — TUN= values from /etc/multi-gre (manager-owned tunnels)
//   legacy        — vatanhost-era artifact counters
//
// Unmanaged GRE tunnels = GRE interfaces present in `ip -d tunnel show` that
// are neither kernel dummy devices (gre0/gretap0/erspan0) nor listed in the
// manager config (managed_tuns).

const ssh = require('./ssh');

// Kernel-created dummy GRE devices, never manager-managed.
const SYSTEM_DEVICES = new Set(['gre0', 'gretap0', 'erspan0', 'ip6gre0', 'ip6tnl0', 'tunl0', 'sit0']);

const PROBE = [
  'echo "@@BEGIN gre@@"',
  'if command -v gre >/dev/null 2>&1; then',
  '  echo "installed=1"',
  '  gre --version 2>/dev/null | head -n 1',
  '  echo "@@BEGIN status_json@@"',
  '  timeout 15 gre status --json 2>/dev/null',
  '  echo "@@END status_json@@"',
  'else',
  '  echo "installed=0"',
  'fi',
  'echo "@@END gre@@"',
  'echo "@@BEGIN tunnels@@"',
  'ip -d tunnel show 2>/dev/null',
  'echo "@@END tunnels@@"',
  'echo "@@BEGIN managed_tuns@@"',
  "grep -rh '^TUN=' /etc/multi-gre/ 2>/dev/null | cut -d= -f2 | sort -u",
  'echo "@@END managed_tuns@@"',
  'echo "@@BEGIN legacy@@"',
  'if ip -d tunnel show 2>/dev/null | grep -q \'^vatan-m2:\'; then echo "vatan_m2=1"; else echo "vatan_m2=0"; fi',
  'echo "nat_132=$(iptables -t nat -S 2>/dev/null | grep -c \'132\\.168\\.30\\.\')"',
  'echo "masq_broad=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep \'MASQUERADE\' | grep -vc \' -d \')"',
  'echo "icmp_drop=$(iptables -S INPUT 2>/dev/null | grep icmp | grep -c \'DROP\')"',
  'echo "@@END legacy@@"',
].join('\n');

// Split probe stdout into { sectionName: text }. Sections may be nested
// (status_json lives inside the gre block), so recurse into each body.
function parseSections(output) {
  const sections = {};
  const walk = (text) => {
    const re = /@@BEGIN ([\w]+)@@\n([\s\S]*?)@@END \1@@/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!(m[1] in sections)) sections[m[1]] = m[2].trim();
      walk(m[2]);
    }
  };
  walk(output);
  return sections;
}

// Names of GRE tunnels from `ip -d tunnel show` output.
function parseGreTunnelNames(text) {
  const names = [];
  for (const line of text.split('\n')) {
    // Entry header looks like: "gre-foo: ip/gre remote 1.2.3.4 ..." or "gre0: gre/ip ..."
    const m = line.match(/^([\w.-]+):\s+(?:ip\/gre|gre\/ip|gre6\/ip|ip6\/gre|ip6gre\/ip|any\/gre)/);
    if (m) names.push(m[1]);
  }
  return names;
}

function parseKeyVals(text) {
  const out = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^(\w+)=(.*)$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function parseProbe(stdout) {
  const sections = parseSections(stdout);

  const greInfo = parseKeyVals(sections.gre || '');
  const installed = greInfo.installed === '1';
  let version = null;
  if (installed) {
    const versionLine = (sections.gre || '').split('\n').find((l) => /gre-manager/i.test(l));
    const vm = versionLine && versionLine.match(/v?([\d]+\.[\d]+\.[\d]+)/);
    version = vm ? vm[1] : (versionLine || 'unknown');
  }

  let status = null;
  if (installed && sections.status_json) {
    try {
      status = JSON.parse(sections.status_json);
    } catch {
      status = { parse_error: true, raw: sections.status_json.slice(0, 2000) };
    }
  }

  const managed = new Set(
    (sections.managed_tuns || '').split('\n').map((s) => s.trim()).filter(Boolean)
  );
  const greTunnels = parseGreTunnelNames(sections.tunnels || '');
  const unmanaged = greTunnels.filter((n) => !SYSTEM_DEVICES.has(n) && !managed.has(n));

  const legacyKv = parseKeyVals(sections.legacy || '');
  const legacy = {
    vatan_m2: legacyKv.vatan_m2 === '1',
    nat_132_168_30_rules: Number(legacyKv.nat_132 || 0),
    broad_masquerade_rules: Number(legacyKv.masq_broad || 0),
    input_icmp_drop_rules: Number(legacyKv.icmp_drop || 0),
  };
  legacy.present =
    legacy.vatan_m2 ||
    legacy.nat_132_168_30_rules > 0 ||
    legacy.broad_masquerade_rules > 0 ||
    legacy.input_icmp_drop_rules > 0;

  const roles = (status && Array.isArray(status.roles) ? status.roles : []).map((r) => String(r).toUpperCase());

  return {
    taken_at: new Date().toISOString(),
    manager: { installed, version },
    roles,
    status,
    tunnels_up: status && typeof status.tunnels_up === 'number' ? status.tunnels_up : null,
    service: status ? status.service || null : null,
    watchdog: status ? status.watchdog || null : null,
    gre_tunnels: greTunnels,
    unmanaged_tunnels: unmanaged,
    legacy,
  };
}

// ---------------------------------------------------------------------------
// Outcome classification
//
// The whole point of this module's contract: "the hub could not reach the
// server" and "the server genuinely has no manager configured" are DIFFERENT
// answers, and only the second one may change topology. A probe failure is an
// availability fact; it must never be stored as a role of [].
// ---------------------------------------------------------------------------

const ERROR_CLASSES = {
  timeout: { reason: 'SSH timeout', retryable: true },
  auth: { reason: 'Authentication failed', retryable: false },
  refused: { reason: 'Connection refused', retryable: true },
  hostkey: { reason: 'Host key mismatch', retryable: false },
  transport: { reason: 'Unknown transport error', retryable: true },
  malformed: { reason: 'Malformed probe output', retryable: true },
  remote: { reason: 'Remote command failed', retryable: true },
  nocreds: { reason: 'No credentials stored', retryable: false },
};

// Anything that could carry a credential or a URL goes through this before it is
// stored or displayed. The probe never prints secrets, but an SSH library error
// echoing a connection string must not become a stored message either.
function sanitizeMessage(text) {
  return String(text === null || text === undefined ? '' : text)
    .replace(/ss:\/\/\S+/gi, '[redacted]')
    .replace(/vmess:\/\/\S+/gi, '[redacted]')
    .replace(/vless:\/\/\S+/gi, '[redacted]')
    .replace(/trojan:\/\/\S+/gi, '[redacted]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[redacted-key]')
    // JSON form first: the quoted key AND the quoted value must both be covered.
    // Matching only up to the quote would leave the value behind.
    .replace(/("[a-z_]*(?:password|passwd|pass|secret|private_?key|passphrase|token)"\s*:\s*")([^"]*)(")/gi,
      '$1[redacted]$3')
    .replace(/('[a-z_]*(?:password|passwd|pass|secret|private_?key|passphrase|token)'\s*:\s*')([^']*)(')/gi,
      "$1[redacted]$3")
    // Unquoted / prose form.
    .replace(/((?:password|passwd|pass|secret|private_?key|passphrase)\s*[:=]\s*)\S+/gi, '$1[redacted]')
    .replace(/(authorization\s*:\s*bearer\s+)\S+/gi, '$1[redacted]')
    .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[redacted]')
    // A bare user:pass@host form.
    .replace(/\b[\w.-]+:([^\s@/]{4,})@/g, '[redacted]@')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300);
}

// Classify an ssh.exec result into a probe outcome.
//
// Returns one of:
//   { ok: true,  snapshot }                       — usable authoritative state
//   { ok: false, errorClass, reason, detail }     — availability failure
//   { ok: false, errorClass: 'hostkey', ... }     — security failure, never downgraded
function classifyProbeResult(result) {
  if (!result || typeof result !== 'object') {
    return { ok: false, errorClass: 'transport', reason: ERROR_CLASSES.transport.reason, detail: 'no result from the SSH transport' };
  }
  if (result.hostkey_mismatch) {
    return {
      ok: false,
      errorClass: 'hostkey',
      reason: ERROR_CLASSES.hostkey.reason,
      detail: 'the presented host key does not match the pinned fingerprint',
      presented_fp: result.presented_fp,
    };
  }

  const stderr = String(result.stderr || '');
  const stdout = String(result.stdout || '');
  const detail = sanitizeMessage(stderr);

  // A transport-level failure never produced markers, so it can never be a state.
  if (result.rc !== 0 && !stdout.includes('@@BEGIN')) {
    if (/timed out|timeout/i.test(stderr)) {
      return { ok: false, errorClass: 'timeout', reason: ERROR_CLASSES.timeout.reason, detail };
    }
    if (/no credentials stored/i.test(stderr)) {
      return { ok: false, errorClass: 'nocreds', reason: ERROR_CLASSES.nocreds.reason, detail };
    }
    if (/authentication|auth methods failed|permission denied|publickey/i.test(stderr)) {
      return { ok: false, errorClass: 'auth', reason: ERROR_CLASSES.auth.reason, detail };
    }
    if (/econnrefused|connection refused/i.test(stderr)) {
      return { ok: false, errorClass: 'refused', reason: ERROR_CLASSES.refused.reason, detail };
    }
    if (/econnreset|ehostunreach|enetunreach|etimedout|socket hang up|connection lost|no route to host/i.test(stderr)) {
      return { ok: false, errorClass: 'transport', reason: ERROR_CLASSES.transport.reason, detail };
    }
    return { ok: false, errorClass: 'remote', reason: ERROR_CLASSES.remote.reason, detail: detail || `probe exited with rc=${result.rc}` };
  }

  // The command reported success-ish, but the marker structure is unusable. A
  // truncated probe (for example a timeout mid-script that still emitted one
  // section) must NOT be mistaken for "no manager installed".
  const sections = parseSections(stdout);
  const hasGreSection = Object.prototype.hasOwnProperty.call(sections, 'gre');
  if (!hasGreSection) {
    return {
      ok: false,
      errorClass: 'malformed',
      reason: ERROR_CLASSES.malformed.reason,
      detail: stdout.trim() ? 'the probe output contained no usable sections' : 'the probe produced no output',
    };
  }

  const snapshot = parseProbe(stdout);
  if (result.stderr && result.stderr.trim() && snapshot.manager.installed) {
    // Informational only: the structured sections are authoritative, and the
    // manager being installed means the probe itself completed.
    snapshot.probe_stderr = sanitizeMessage(result.stderr).slice(0, 1000);
  }
  return { ok: true, snapshot };
}

function errorReason(errorClass) {
  const known = ERROR_CLASSES[errorClass];
  return known ? known.reason : ERROR_CLASSES.transport.reason;
}

function isRetryable(errorClass) {
  const known = ERROR_CLASSES[errorClass];
  return known ? known.retryable : true;
}

// Run the probe on a server and return the parsed snapshot.
//
// Kept for backward compatibility: it always resolves to a snapshot-shaped
// object, and on a transport failure the snapshot carries `error` and empty roles
// (the old contract). Callers that must not destroy topology should use
// discoverOutcome() instead, which tells the two cases apart.
async function discover(server, secret, sshOpts = {}) {
  const outcome = await discoverOutcome(server, secret, sshOpts);
  if (outcome.ok) return outcome.snapshot;
  if (outcome.errorClass === 'hostkey') {
    return { hostkey_mismatch: true, presented_fp: outcome.presented_fp };
  }
  return {
    taken_at: new Date().toISOString(),
    manager: { installed: false, version: null },
    roles: [],
    status: null,
    tunnels_up: null,
    service: null,
    watchdog: null,
    gre_tunnels: [],
    unmanaged_tunnels: [],
    legacy: { present: false },
    error: outcome.detail || outcome.reason,
    error_class: outcome.errorClass,
  };
}

// Full probe with an explicit verdict. This is the call that decides whether a
// snapshot may replace the authoritative one: only `ok: true` may.
async function discoverOutcome(server, secret, sshOpts = {}) {
  const started = Date.now();
  let result;
  try {
    result = await ssh.exec(server, secret, `bash -s <<'GRE_HUB_PROBE_EOF'\n${PROBE}\nGRE_HUB_PROBE_EOF`,
      { timeoutMs: 60000, ...sshOpts });
  } catch (err) {
    return {
      ok: false,
      errorClass: 'transport',
      reason: errorReason('transport'),
      detail: sanitizeMessage(err && err.message),
      durationMs: Date.now() - started,
      checkedAt: Date.now(),
    };
  }
  const verdict = classifyProbeResult(result);
  verdict.durationMs = Date.now() - started;
  verdict.checkedAt = Date.now();
  return verdict;
}

// Lightweight availability check: prove the hub can authenticate and run a
// command, without collecting any topology. Cheap enough to run on a short
// cadence for every server, which is what makes a full discovery every few
// seconds unnecessary.
const HEALTH_PROBE = 'echo hub-health-ok';
const HEALTH_MARKER = 'hub-health-ok';

async function probeHealth(server, secret, sshOpts = {}) {
  const started = Date.now();
  let result;
  try {
    result = await ssh.exec(server, secret, HEALTH_PROBE, { timeoutMs: 15000, ...sshOpts });
  } catch (err) {
    return {
      ok: false,
      errorClass: 'transport',
      reason: errorReason('transport'),
      detail: sanitizeMessage(err && err.message),
      durationMs: Date.now() - started,
      checkedAt: Date.now(),
    };
  }
  const checkedAt = Date.now();
  const durationMs = checkedAt - started;

  if (result.hostkey_mismatch) {
    return {
      ok: false,
      errorClass: 'hostkey',
      reason: errorReason('hostkey'),
      detail: 'the presented host key does not match the pinned fingerprint',
      presented_fp: result.presented_fp,
      durationMs,
      checkedAt,
    };
  }
  // The transport is healthy only if the marker came back: a zero exit code with
  // no output means something interfered with the session.
  if (result.rc === 0 && String(result.stdout || '').includes(HEALTH_MARKER)) {
    return { ok: true, durationMs, checkedAt };
  }
  const verdict = classifyProbeResult({
    rc: result.rc,
    stdout: result.stdout,
    stderr: result.stderr || (result.rc === 0 ? 'health probe returned no marker' : ''),
  });
  return {
    ok: false,
    errorClass: verdict.errorClass,
    reason: verdict.reason,
    detail: verdict.detail,
    durationMs,
    checkedAt,
  };
}

module.exports = {
  discover,
  discoverOutcome,
  classifyProbeResult,
  probeHealth,
  parseProbe,
  parseGreTunnelNames,
  sanitizeMessage,
  errorReason,
  isRetryable,
  ERROR_CLASSES,
  HEALTH_PROBE,
  HEALTH_MARKER,
  PROBE,
};

