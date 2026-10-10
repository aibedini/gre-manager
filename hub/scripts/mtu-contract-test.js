'use strict';
// Does the real CLI produce the JSON shape the Hub parses?
//
// The Hub layer was written against a fake. This runs the REAL `gre mtu` commands
// through the test harness and checks every field connection-mtu.js reads.
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const SH = process.env.GRE_TEST_BASH || 'bash';
const R = fs.mkdtempSync(path.join(os.tmpdir(), 'mtuverify-'));
const STUBS = path.join(R, 'stubs');
fs.mkdirSync(STUBS, { recursive: true });
fs.mkdirSync(path.join(R, 'state', 'tunnels'), { recursive: true });
fs.mkdirSync(path.join(R, 'var', 'log'), { recursive: true });
fs.mkdirSync(path.join(R, 'etc', 'multi-gre'), { recursive: true });
fs.mkdirSync(path.join(R, 'usr', 'local', 'sbin'), { recursive: true });
fs.mkdirSync(path.join(R, 'etc', 'systemd', 'system'), { recursive: true });
fs.mkdirSync(path.join(R, 'etc', 'sysctl.d'), { recursive: true });

let src = fs.readFileSync(path.join(REPO, 'gre-manager.sh'), 'utf8');
src = src.replace(/\/etc\/multi-gre/g, `${R.replace(/\\/g, '/')}/etc/multi-gre`);
src = src.replace(/if \[\[ \$\{EUID:-\$\(id -u\)\} -ne 0 \]\]; then/, 'if false; then');
fs.writeFileSync(path.join(R, 'sut.sh'), src);
for (const s of ['ip', 'iptables', 'systemctl', 'ping', 'ss', 'sysctl', 'logger']) {
  fs.copyFileSync(path.join(REPO, 'tests', 'stubs', s), path.join(STUBS, s));
}
const env = { ...process.env, TEST_ROOT: R, PATH: `${STUBS}:${process.env.PATH}` };
const run = (...args) => execFileSync(SH, [path.join(R, 'sut.sh'), ...args], { env, encoding: 'utf8' });

run('foreign-setup', '--foreign-ip', '203.0.113.10', '--yes');
run('iran', 'peer', 'add', '--name', 'de1', '--foreign-ip', '203.0.113.10',
  '--iran-ip', '198.51.100.20', '--subnet-base', '10.200', '--idx', '1', '--key', '1001',
  '--tcp-ports', '80,443', '--udp-ports', '443', '--yes');

let pass = 0; let fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) { pass += 1; console.log(`  ok    ${name}`); } else { fail += 1; console.log(`  FAIL  ${name} ${extra}`); }
};

console.log('\n=== gre mtu list --json ===');
const list = JSON.parse(run('mtu', 'list', '--json'));
check('list parses as JSON', true);
check('list has connections[]', Array.isArray(list.connections), JSON.stringify(list).slice(0, 120));
check('list reports count', typeof list.count === 'number');
const lc = list.connections[0] || {};
for (const f of ['name', 'side', 'tunnel', 'tunnel_mtu', 'override', 'egress_iface', 'egress_mtu', 'overhead', 'mss_mode']) {
  check(`list entry has ${f}`, Object.prototype.hasOwnProperty.call(lc, f), JSON.stringify(lc).slice(0, 160));
}

console.log('\n=== gre mtu diagnose --json ===');
const diag = JSON.parse(run('mtu', 'diagnose', '--name', 'de1', '--json'));
check('diagnose has name/side/tunnel', !!diag.name && !!diag.side && !!diag.tunnel);
check('diagnose has summary', !!diag.summary && typeof diag.summary.pass === 'number');
check('diagnose has checks[]', Array.isArray(diag.checks) && diag.checks.length > 0);
check('each check has id/status/detail', diag.checks.every((c) => c.id && c.status && typeof c.detail === 'string'));
check('statuses are the contract set', diag.checks.every((c) => ['PASS', 'WARN', 'FAIL', 'UNKNOWN', 'SKIPPED'].includes(c.status)));
check('diagnose has underlay{}', !!diag.underlay);
for (const f of ['iface', 'mtu', 'route', 'src', 'dst', 'route_mtu', 'icmp_frag_needed']) {
  check(`underlay.${f} present`, Object.prototype.hasOwnProperty.call(diag.underlay, f));
}
check('diagnose has gre{}', !!diag.gre);
for (const f of ['tun', 'encap', 'key', 'flags', 'outer_ipv', 'local', 'remote', 'mtu', 'inner_cidr', 'overhead']) {
  check(`gre.${f} present`, Object.prototype.hasOwnProperty.call(diag.gre, f));
}
check('gre.flags is an array', Array.isArray(diag.gre.flags));
check('diagnose has pmtu.inner_probe{}', !!(diag.pmtu && diag.pmtu.inner_probe));
check('pmtu.inner_probe has state/max_ok/frag_needed_at/probes_sent',
  ['state', 'max_ok', 'frag_needed_at', 'probes_sent'].every((k) => Object.prototype.hasOwnProperty.call(diag.pmtu.inner_probe, k)));
check('diagnose has mss_clamp{}', !!diag.mss_clamp);
check('mss_clamp has enabled/mode/value/scoped_to_connection',
  ['enabled', 'mode', 'value', 'scoped_to_connection'].every((k) => Object.prototype.hasOwnProperty.call(diag.mss_clamp, k)));
check('diagnose embeds a recommendation', !!diag.recommendation);

console.log('\n=== gre mtu recommend --json ===');
const rec = JSON.parse(run('mtu', 'recommend', '--name', 'de1', '--json'));
for (const f of ['connection', 'underlay_mtu', 'encapsulation_overhead', 'current_gre_mtu',
  'recommended_gre_mtu', 'confidence', 'requires_change', 'reason', 'safe_to_apply',
  'safety_margin', 'margin_reason', 'min_legal_mtu']) {
  check(`recommendation has ${f}`, Object.prototype.hasOwnProperty.call(rec, f), JSON.stringify(rec).slice(0, 200));
}
check('confidence is the contract set', ['high', 'medium', 'low', 'unknown'].includes(rec.confidence));
check('requires_change is boolean', typeof rec.requires_change === 'boolean');
check('safe_to_apply is boolean', typeof rec.safe_to_apply === 'boolean');
check('overhead is 28 for keyed IPv4 GRE', rec.encapsulation_overhead === 28, String(rec.encapsulation_overhead));
check('recommendation is capacity minus overhead', rec.recommended_gre_mtu === rec.underlay_mtu - rec.encapsulation_overhead,
  `${rec.recommended_gre_mtu} vs ${rec.underlay_mtu}-${rec.encapsulation_overhead}`);

console.log('\n=== gre mtu auto --json ===');
// Snapshot the live MTU BEFORE auto, so the assertion is "auto changed nothing" rather
// than "no MTU exists" (a peer add legitimately applies the default MTU).
const mtuFile = path.join(R, 'state', 'mtu.gre-de1');
const beforeAuto = fs.existsSync(mtuFile) ? fs.readFileSync(mtuFile, 'utf8') : 'none';
const auto = JSON.parse(run('mtu', 'auto', '--name', 'de1', '--json'));
const afterAuto = fs.existsSync(mtuFile) ? fs.readFileSync(mtuFile, 'utf8') : 'none';
check('auto reports applied:false', auto.applied === false);
check('auto offers an apply_command', typeof auto.apply_command === 'string');
check('auto did not change the interface MTU', beforeAuto === afterAuto, `${beforeAuto} -> ${afterAuto}`);

console.log('\n=== gre mtu nic list --json ===');
const nics = JSON.parse(run('mtu', 'nic', 'list', '--json'));
check('nic list has nics[]', Array.isArray(nics.nics), JSON.stringify(nics).slice(0, 140));
check('nic entries have iface/mtu/carries_control_plane',
  nics.nics.every((n) => n.iface && typeof n.mtu === 'number' && typeof n.carries_control_plane === 'boolean'));
check('the underlay is marked as control plane', nics.nics.some((n) => n.iface === 'eth0' && n.carries_control_plane === true));

console.log('\n=== gre mtu nic analyze --name de1 --json ===');
const nic = JSON.parse(run('mtu', 'nic', 'analyze', '--name', 'de1', '--json'));
check('nic analyze has iface/risk', !!nic.iface && !!nic.risk, JSON.stringify(nic).slice(0, 160));
check('nic analyze reports applied:false', nic.applied === false);
check('nic analyze flags the control-plane risk', nic.risk === 'high', String(nic.risk));

console.log('\n=== gre health-check --json ===');
// The Hub treats a non-zero exit WITH parseable JSON as data (the diagnosis succeeded and
// found the connection broken), so the runner has to survive a non-zero exit.
const runAllowFail = (...args) => {
  try { return { out: run(...args), rc: 0 }; } catch (e) { return { out: String(e.stdout || ''), rc: e.status || 1 }; }
};
const hc = runAllowFail('health-check', '--name', 'de1', '--quick', '--json');
let health;
try { health = JSON.parse(hc.out); } catch { health = null; }
check('health-check emits parseable JSON (even when it exits non-zero)', !!health, `rc=${hc.rc} out=${hc.out.slice(0, 120)}`);
if (health) {
  for (const f of ['connection', 'side', 'server', 'mode', 'overall_status', 'evidence_completeness',
    'budget_seconds', 'elapsed_seconds', 'summary', 'checks', 'findings', 'tested_at']) {
    check(`health-check has ${f}`, Object.prototype.hasOwnProperty.call(health, f), JSON.stringify(health).slice(0, 200));
  }
  check('overall_status is the contract set',
    ['HEALTHY', 'DEGRADED', 'BROKEN'].includes(health.overall_status), String(health.overall_status));
  check('evidence_completeness is the contract set',
    ['complete', 'partial'].includes(health.evidence_completeness), String(health.evidence_completeness));
  check('mode is echoed', health.mode === 'quick', String(health.mode));
  check('summary has every counter',
    ['pass', 'warn', 'fail', 'unknown', 'skipped', 'critical_findings'].every((k) => Object.prototype.hasOwnProperty.call(health.summary, k)),
    JSON.stringify(health.summary));
  check('checks is a non-empty array', Array.isArray(health.checks) && health.checks.length > 0);
  check('every check has id/category/status/detail/evidence',
    health.checks.every((c) => c.id && c.category && c.status && typeof c.detail === 'string' && typeof c.evidence === 'string'));
  check('every check status is in the contract set',
    health.checks.every((c) => ['PASS', 'WARN', 'FAIL', 'UNKNOWN', 'SKIPPED'].includes(c.status)),
    JSON.stringify([...new Set(health.checks.map((c) => c.status))]));
  check('every category is one the Hub groups by',
    health.checks.every((c) => /^[A-HZ]_[a-z0-9_]+$/.test(c.category)),
    JSON.stringify([...new Set(health.checks.map((c) => c.category))]));
  check('findings is an array', Array.isArray(health.findings));
  check('every finding carries the fields the Hub renders',
    health.findings.every((f) => f.code && f.severity && typeof f.evidence === 'string'
      && typeof f.probable_cause === 'string' && typeof f.recommended_action === 'string'
      && typeof f.safe_repair === 'boolean' && typeof f.confidence === 'string'),
    JSON.stringify(health.findings).slice(0, 220));
  check('every finding severity is in the contract set',
    health.findings.every((f) => ['critical', 'warning', 'info'].includes(f.severity)),
    JSON.stringify([...new Set(health.findings.map((f) => f.severity))]));
  check('a non-zero exit corresponds to BROKEN, not to a crash',
    hc.rc === 0 || health.overall_status === 'BROKEN', `rc=${hc.rc} status=${health.overall_status}`);
  check('health-check leaked no secret', !/password|secret|PRIVATE KEY/i.test(hc.out));
}

console.log('\n=== gre repair preview --json ===');
const prev = runAllowFail('repair', 'preview', '--name', 'de1', '--json');
let preview;
try { preview = JSON.parse(prev.out); } catch { preview = null; }
check('repair preview emits parseable JSON', !!preview, prev.out.slice(0, 160));
if (preview) {
  check('preview marks itself read-only', preview.read_only === true);
  check('preview names the connection', preview.connection === 'de1');
  check('preview has a repairable array', Array.isArray(preview.repairable));
  check('every repairable entry is a finding the Hub can render',
    preview.repairable.every((f) => f.code && f.safe_repair === true && f.risk && f.recommended_action),
    JSON.stringify(preview.repairable).slice(0, 200));
}

console.log('\n=== gre repair apply (the code must actually be repairable) ===');
// Break the connection so a repairable finding exists, then repair it for real.
fs.rmSync(path.join(R, 'state', 'tunnels', 'gre-de1'), { force: true });
fs.rmSync(path.join(R, 'state', 'mtu.gre-de1'), { force: true });
const hcBroken = runAllowFail('health-check', '--name', 'de1', '--quick', '--json');
let broken = null;
try { broken = JSON.parse(hcBroken.out); } catch { /* reported below */ }
check('a broken connection reports BROKEN', !!broken && broken.overall_status === 'BROKEN',
  broken ? broken.overall_status : hcBroken.out.slice(0, 120));
check('the broken connection exits non-zero', hcBroken.rc !== 0, `rc=${hcBroken.rc}`);
check('the break produced a machine-readable code',
  !!broken && broken.findings.some((f) => f.code === 'GRE_INTERFACE_MISSING'),
  broken ? JSON.stringify(broken.findings.map((f) => f.code)) : '');
check('the finding is offered as a safe repair',
  !!broken && broken.findings.some((f) => f.code === 'GRE_INTERFACE_MISSING' && f.safe_repair === true));

const applyRes = runAllowFail('repair', 'apply', '--name', 'de1', '--code', 'GRE_INTERFACE_MISSING', '--yes');
check('repair apply exits 0 when it fixed and verified', applyRes.rc === 0, `rc=${applyRes.rc} ${applyRes.out.slice(0, 160)}`);
const hcAfter = runAllowFail('health-check', '--name', 'de1', '--quick', '--json');
let afterRepair = null;
try { afterRepair = JSON.parse(hcAfter.out); } catch { /* reported below */ }
check('the repair is confirmed by a fresh check',
  !!afterRepair && !afterRepair.findings.some((f) => f.code === 'GRE_INTERFACE_MISSING'),
  afterRepair ? JSON.stringify(afterRepair.findings.map((f) => f.code)) : '');
check('the connection is no longer BROKEN',
  !!afterRepair && afterRepair.overall_status !== 'BROKEN',
  afterRepair ? afterRepair.overall_status : '');

console.log('\n=== gre repair apply refuses what it cannot verify ===');
const badCode = runAllowFail('repair', 'apply', '--name', 'de1', '--code', 'NOT_A_REAL_CODE', '--yes');
check('an unknown code is refused', badCode.rc !== 0, `rc=${badCode.rc}`);

console.log('\n=== secrets ===');
const all = JSON.stringify({ diag, rec, auto, nics, nic, health, preview, broken, afterRepair });
check('no credential material in any payload', !/password|secret|PRIVATE KEY/i.test(all));

fs.rmSync(R, { recursive: true, force: true });
console.log(`\nCLI/Hub contract: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
