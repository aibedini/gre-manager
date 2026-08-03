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

// Run the probe on a server and return the parsed snapshot.
async function discover(server, secret) {
  const result = await ssh.exec(server, secret, `bash -s <<'GRE_HUB_PROBE_EOF'\n${PROBE}\nGRE_HUB_PROBE_EOF`, { timeoutMs: 60000 });
  if (result.rc !== 0 && !result.stdout.includes('@@BEGIN')) {
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
      error: (result.stderr || `probe exited with rc=${result.rc}`).slice(0, 2000),
    };
  }
  const snapshot = parseProbe(result.stdout);
  if (result.stderr && result.stderr.trim()) snapshot.probe_stderr = result.stderr.slice(0, 1000);
  return snapshot;
}

module.exports = { discover, parseProbe, parseGreTunnelNames, PROBE };
