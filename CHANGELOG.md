# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.0] - 2026-08-03

### Added
- **`gre iran peer suggest [--json]`** — prints collision-free suggested values
  for a new foreign peer: generic free name, next subnet base, index, GRE key,
  and free TCP/UDP ports (skipping ports/ranges used by other peers and local
  listeners). Powers the "Suggest" auto-fill button in gre-hub's
  Peer-add / Configure-as-IRAN forms.

## [2.6.1] - 2026-08-03

### Fixed
- gre-hub release package now includes the "Configure as FOREIGN / IRAN"
  actions (added after v2.6.0 was tagged); reinstalling the hub with
  `gre hub install` upgrades an existing installation in place (dashboard
  data is preserved).

## [2.6.0] - 2026-08-03

### Added
- **`gre foreign-setup` — non-interactive FOREIGN setup** (mirrors `iran-setup`
  for the foreign side): `gre foreign-setup [--foreign-ip IP] [--gre-whitelist
  on|off] [--icmp-drop on|off] [--downtime MIN] [--yes]` writes the foreign
  config, applies watchdog settings and installs the systemd service; refuses
  when already configured and points to `gre node add`. This also powers the
  new "Configure as FOREIGN / Configure as IRAN" actions in gre-hub.

## [2.5.0] - 2026-08-03

### Added
- **Smart defaults in the interactive peer-add wizard**: the TCP/UDP port
  prompts now suggest a port that collides with nothing — skipping every port
  and range already used by other peers (per protocol) and any locally
  listened-on port, starting from 3001. Subnet base, index and GRE key were
  already auto-suggested (next free in pool); now all four values can be
  accepted with Enter end-to-end. Test added: full wizard run asserts the
  suggested base/ports are the expected non-colliding ones.

## [2.4.0] - 2026-08-03

### Added
- **`gre hub domain` — one-command web exposure with free HTTPS**: asks for the
  domain (menu option 14 → 5, or `gre hub domain [DOMAIN]`), sanity-checks DNS
  against the server's IP, auto-installs Caddy (official static binary,
  amd64/arm64) when missing, writes the reverse-proxy site into
  `/etc/caddy/sites/gre-hub.caddy` (non-destructive import into the main
  Caddyfile), enables `HUB_SECURE=1` via a systemd drop-in (Secure cookies +
  HSTS), and starts everything. `gre hub unexpose` (menu option 6) cleanly
  reverts to localhost-only. `gre hub install` now also offers the domain
  setup at the end. Port 80/443 conflicts are detected before touching anything.

## [2.3.0] - 2026-08-03

### Added
- **`gre hub` — one-command gre-hub installation** (menu option 14, CLI
  `gre hub install|status|start|stop|restart|uninstall`): installs Node.js 22
  automatically when missing (NodeSource, apt/dnf/yum), downloads the pinned
  `gre-hub.tar.gz` release asset (with latest-release and main-tarball
  fallbacks), runs `npm install` (auto-installs build tools and retries on
  failure), creates and starts the `gre-hub.service` systemd unit, and prints
  local + SSH-tunnel access instructions. Works on any server that already
  has any gre-manager version installed.
- Release workflow now also publishes `gre-hub.tar.gz` (+ sha256) with every tag.

## [2.2.3] - 2026-08-03

### Fixed
- **`gre update` resilience**: the GitHub releases API and release-asset
  downloads are flaky from some networks (intermittent throttling), which made
  updates silently fall back to the unchecksummed main branch. Both steps now
  retry once with a short pause, print a distinct message for API vs. asset
  failure, and only fall back after retries are exhausted. Timeouts added to
  all update curl calls.

## [2.2.2] - 2026-08-03

### Fixed
- **False "unmanaged GRE tunnel" warnings in doctor** (and three similar latent
  spots): `producer | grep -q …` under `set -o pipefail` is a footgun — when
  `grep -q` exits on an early match, the producer dies of SIGPIPE and pipefail
  flips the pipeline to failure. With 2+ managed tunnels this made
  `gre doctor` wrongly report a managed tunnel as unmanaged (and warn it was
  blocked by the whitelist when it was not). All four sites
  (`unmanaged_gre_tunnels`, `port_in_use`, `subnet_route_conflict`, the
  IRAN_IP interface check in doctor) now use herestrings instead of pipes.
- Regression test added: 2 managed tunnels → doctor must not warn.

## [2.2.1] - 2026-08-02

### Added
- **Doctor: GRE-filtering diagnosis on failed tunnel pings** — when a tunnel
  peer does not answer ping, doctor now explains the likely cause (far side
  down vs. GRE proto 47 filtered, often one-way) and prints the exact
  two-sided `tcpdump -n proto 47` test, including the reminder that plain ICMP
  ping can still work while proto 47 is blocked.

## [2.2.0] - 2026-08-02

### Added
- **Current-nodes list before adding**: menu option 2 (FOREIGN) now prints the
  existing Iran nodes (name, IP, subnet, key) before the add-node prompts, so
  you always see what is already configured before adding the next one. The
  Iran-side peers menu already listed peers before add/remove/apply.

## [2.1.0] - 2026-08-02

### Added
- **Coexistence with other GRE tunnels**: during FOREIGN setup, if GRE tunnels
  not managed by gre-manager already exist, enabling the GRE whitelist now
  prints an explicit warning that those tunnels will be blocked.
- **Doctor coexistence check**: `gre doctor` detects unmanaged GRE tunnels —
  reports them as WARN (and warns they are blocked when the GRE whitelist is
  active), so gre-manager never silently kills or fights another tool's tunnel.
- **Pairing fingerprint in status**: `gre status` prints an identical
  `pair: IRAN_IP <-> FOREIGN_IP · SUBNET.IDX.0/30 · key N` line on both sides
  of a tunnel, so operators can visually confirm which Iran node is linked to
  which foreign peer (matching names on both sides is recommended but not
  required — the link is established by IP + subnet base + index + key).

## [2.0.1] - 2026-08-02

### Fixed
- **Installer progress bars**: the "Downloading gre-manager" bar jumped from
  40% to the next step without completing and the "Latest release" line was
  printed mid-bar; every stage now completes its own bar to 100% in order
  (download → checksum → install).
- **Menu clarity**: menu option 1 was renamed from the confusing
  "Foreigns connected to this Iran" to "Configure this server as IRAN
  (add / manage foreign peers)", and a fresh server now shows a
  `Start here → IRAN? press 1 · FOREIGN? press 2` hint under the status line.

## [2.0.0] - 2026-08-01

### Added
- **Multi-foreign support (IRAN side)** — one Iran server can now connect to
  **multiple foreign servers** at once. Each foreign is an independent peer
  with its own tunnel, `/30` subnet, GRE key, forwarded ports and health
  state. Peer configs live in `/etc/multi-gre/foreigns/<name>.conf`;
  `/etc/multi-gre/iran.conf` becomes a manifest (`SCHEMA_VERSION=2`).
- **Per-peer subnets** — tunnel addresses become `<subnet-base>.<idx>.1/.2`
  with an automatic pool of `10.200`–`10.254` (first peer and migrated legacy
  configs keep `10.200`). Duplicate `(SUBNET_BASE, IDX)` pairs, peer names and
  tunnel names are rejected before anything is written or applied.
- **New Iran CLI**:
  - `gre iran peer list [--json]`
  - `gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP]
    [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
    [--udp-ports LIST] [--mss-clamp on|off] [--yes]` (re-running with
    identical values is idempotent; different values are rejected)
  - `gre iran peer remove --name NAME [--yes]` (touches only that peer)
  - `gre iran peer apply --name NAME`
- **Port splitting between foreigns** — every (protocol, port) tuple belongs
  to exactly one peer; overlaps (including range overlaps like `80:90` vs
  `85`) are rejected with an error naming the conflicting peer. TCP and UDP
  are independent (the same port number may go to different peers on
  different protocols). No shared-port failover/load-balancing yet (v2.1+).
- **Foreign-side `--subnet-base`** — `gre node add` and `gre iran-setup`
  accept `--subnet-base`; node confs store `SUBNET_BASE` (default `10.200`
  when absent) and the pairing output prints the full `gre iran peer add`
  command for the Iran side.
- **Automatic v1→v2 migration** — a legacy v1 `iran.conf` is converted to an
  equivalent peer (`SUBNET_BASE=10.200`) plus manifest on the first
  operational command; the original is kept as `iran.conf.v1.bak` (mode 0600)
  for rollback. Migration is atomic and idempotent; an inconsistent mixed
  old+new layout aborts instead of silently overwriting.
- **JSON schema v2** — `gre status --json` now reports `"schema_version": 2`
  and an `iran_peers[]` array (name, foreign IP, subnet base, idx, key,
  tunnel, ports, reachability). A deprecated legacy `iran` field is still
  emitted for single-peer setups; new consumers must read `iran_peers`.
- **Per-peer watchdog & doctor** — the watchdog pings every peer and
  re-applies only dead ones (log lines name the peer, tunnel and foreign IP);
  doctor checks every peer and reports duplicate subnet/tunnel and port
  overlaps as FAIL.
- **Test suite + CI** — new bash test harness (`tests/run.sh`, stubbed
  `ip`/`iptables`/`systemctl`/`ping`/… with redirected config roots, runs on
  Linux and Git Bash) covering migration, idempotency, port/subnet collision
  rejection, peer isolation, watchdog, doctor, JSON, export/import and
  foreign-side regression; CI runs it on every push/PR.

### Changed
- **Menu option 1** is now a peers flow — "Foreigns connected to this Iran
  (add / manage peers)" with list/add/remove; the banner shows
  `IRAN (peers: N/M up)`. Peer iptables rules carry per-peer comments
  (`multi-gre-iran-<name>-*`) so exact removal is possible; `gre purge`
  patterns match the new comments.
- `gre iran-setup` stays for backward compatibility: it creates the first
  peer on an empty server and refuses to overwrite on multi-peer servers
  (pointing to `gre iran peer add`). Accepts `--subnet-base`.
- `gre node remove` now tells the user to remove the matching peer on the
  Iran side instead of uninstalling.
- Export/import handle both v1 and v2 layouts (v1 archives migrate on
  import); ambiguous mixed archives are rejected.

## [1.5.0] - 2026-08-01

### Added
- **`gre purge` — scorched-earth cleanup** (menu option 13, CLI `gre purge [--yes]`):
  removes EVERYTHING GRE-related from the server, including artifacts left by
  older gre-manager versions or other tools:
  - every GRE/GRETAP tunnel, even ones not present in the config (`vatan-m2`,
    hand-made tunnels, old `gre-*` interfaces)
  - every iptables rule in `filter`/`nat`/`mangle` mentioning multi-gre, GRE
    interfaces, proto 47, `10.200.0.0/16` or `132.168.30.0/30`, plus the legacy
    vatanhost broad rules (unscoped MASQUERADE, broad ICMP DROP)
  - all systemd units (`multi-gre.service`, `multi-gre-watchdog.*`)
  - `/etc/multi-gre`, the sysctl file, audit log, bash completion, and the
    `gre` / `multi-gre-manager` commands themselves
  - requires an explicit confirmation (or `--yes`) with a full warning about
    what will be touched

## [1.4.0] - 2026-08-01

### Added
- **Downtime tolerance question during setup**: the installer now asks how many
  minutes of tunnel downtime are acceptable and derives the watchdog check
  interval from the answer (interval = tolerance / 2, min 1 min; `0` disables
  auto-heal). Stored in `/etc/multi-gre/global.conf`.
- **Watchdog settings menu** (menu option 7): view state, change the downtime
  tolerance, enable or disable the watchdog at any time — cancellable whenever
  the user wants. CLI: `gre watchdog interval <1-60>` plus the existing
  `enable|disable|status`.
- **WARP-Manager-inspired menu UX**: grouped sections (Tunnels / Monitoring /
  Maintenance), live state indicators (`● ON` / `○ OFF`) for tunnels and the
  watchdog directly in the menu, node counter, new interactive submenus for
  Watchdog and Backup/restore, and Ctrl+C now returns to the menu instead of
  killing the program.
- **Installer progress bars** (`install.sh`), styled step-by-step output.
- `gre iran-setup --downtime MIN` flag for non-interactive setups.

### Changed
- Doctor and Backup/restore are now reachable from the interactive menu
  (options 8 and 9).

## [1.3.0] - 2026-07-31

### Added
- **CI (GitHub Actions)**: ShellCheck (`-S warning`), `bash -n`, smoke tests and a
  version-consistency check (VERSION file == script == CHANGELOG) on every push/PR.
- **Pinned, verifiable installs**: `install.sh` now downloads the latest GitHub
  *release* asset and verifies its SHA-256 checksum before installing
  (`GRE_EDGE=1` opts into the bleeding-edge main branch).
- **Verifiable self-update**: `gre update` prefers the latest release asset and
  verifies `gre.sha256`; refuses to install on checksum mismatch; falls back to
  the main branch (with a warning) only when release assets are unavailable.
- **Release automation**: pushing a `v*` tag builds `gre` + `gre.sha256` and
  publishes the GitHub release automatically.
- **bash completion** for `gre` (`completion/gre.bash`, installed to
  `/etc/bash_completion.d/` by the installer when available).

## [1.2.0] - 2026-07-31

### Added
- **Non-interactive CLI** for automation/Ansible:
  - `gre node list [--json]` — list configured Iran nodes (foreign side).
  - `gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]` —
    non-interactive equivalent of the menu's add-node flow; defaults
    `idx = next free`, `key = 1000 + idx`, keeps the GRE whitelist rule
    ordering intact and prints the values to enter on the Iran server.
  - `gre node remove --name NAME [--yes]` — deletes the tunnel, its whitelist
    ACCEPT rule and the node config.
  - `gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
    [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
    [--mss-clamp on|off] [--yes]` — full non-interactive Iran setup;
    auto-detects the public IP/WAN interface when omitted. A TCP list covering
    port 22 aborts unless `--yes` is passed.
  - All mutating CLI commands ask for confirmation unless `--yes` is passed;
    unknown flags error out with usage.
- **JSON status**: `gre status --json` / `gre --status --json` prints pure-bash
  JSON (no jq needed): version, roles, service/watchdog state, tunnel count,
  per-node reachability and the Iran-side config.
- **`gre doctor`**: diagnostics with PASS/WARN/FAIL per check and a non-zero
  exit code on any FAIL — required binaries, `ip_forward`, WAN interface and
  Iran IP assignment, tunnel existence + peer ping, NAT DNAT rules, GRE
  whitelist rules, systemd service/watchdog state, and local port conflicts.
- **Backup/restore**: `gre export [path]` writes a mode-600 tar.gz of
  `/etc/multi-gre` (default `./gre-backup-<timestamp>.tar.gz`);
  `gre import <file> [--yes]` verifies the archive (gzip tar, must contain
  `etc/multi-gre`, no absolute/`..` paths), stops tunnels, restores, and
  re-applies everything.
- **Port-conflict warning**: the interactive Iran setup now warns (non-fatally)
  when a forwarded port is already listened on by a local service.

## [1.1.0] - 2026-07-31

### Added
- **Watchdog**: `multi-gre-watchdog.timer` checks every tunnel every minute
  (existence + ICMP reachability of the tunnel peer) and re-applies dead
  tunnels automatically; actions are logged to the systemd journal
  (`journalctl -t gre-watchdog`). Manage with `gre watchdog enable|disable|status`.
- **Firewall hardening (FOREIGN)**: optional GRE (proto 47) whitelist — only
  known Iran node IPs may establish GRE to the foreign server; all other GRE
  traffic is dropped. Per-node ACCEPT rules carry iptables comments
  (`multi-gre-node-<name>`) and are kept correctly ordered before the block rule.
- **TCP MSS clamping (IRAN)**: optional `TCPMSS --clamp-mss-to-pmtu` on the
  tunnel interface (mangle/POSTROUTING) to prevent broken-PMTU stalls.
- **Audit log**: node add/remove, setups, restarts, cleanup, updates and
  uninstalls are appended to `/var/log/gre-manager.log` with timestamp and user.
- Config files under `/etc/multi-gre/` are now created with mode `0600`.
- Watchdog state shown in the menu banner and in `gre --status`.

### Changed
- ICMP drop on FOREIGN now keeps tunnel subnets (`10.200.0.0/16`) pingable so
  the watchdog and `gre --status` health checks keep working; old v1.0.0
  un-commented ICMP DROP rules are migrated automatically on re-apply.

## [1.0.0] - 2026-07-31

### Added
- Interactive `gre` command: menu-driven management of multiple GRE tunnels
  (many IRAN servers -> one FOREIGN server).
- Per-node isolation: each Iran node gets its own tunnel (`gre-<name>`),
  `/30` subnet (`10.200.<idx>.0/30`) and GRE key (`1000 + idx`).
- IRAN side setup: DNAT of selected TCP/UDP ports (multiport, ranges
  supported) from the public IP into the tunnel, plus SNAT on the tunnel.
  Port 22 (SSH) is never forwarded silently — an explicit confirmation is
  required.
- FOREIGN side setup: add/remove Iran nodes, automatic free tunnel-index
  allocation, optional inbound ICMP drop.
- systemd integration: `multi-gre.service` (oneshot) re-applies all tunnels
  and NAT rules after reboot; `gre --apply` / `gre --stop` are the service
  entry points.
- Idempotent iptables handling: rules are only added when missing and only
  removed when present (safe to re-run any action).
- Legacy cleanup: removes everything the original `vatanhost/gre` script
  created (`vatan-m2`, `132.168.30.0/30`, its broad NAT rules, ICMP drop).
- Self-update: `gre update` pulls the latest version from GitHub (with
  version comparison and a syntax check before replacing the binary).
- CLI: `gre --status`, `gre --version`, `gre --help`.
- One-line installer: `install.sh` installs the `gre` command to
  `/usr/local/sbin/gre`.

[1.0.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.0.0
[1.1.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.1.0
[1.2.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.2.0
[1.3.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.3.0
[1.4.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.4.0
[1.5.0]: https://github.com/aibedini/gre-manager/releases/tag/v1.5.0
[2.0.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.0.0
[2.0.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.0.1
[2.1.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.1.0
[2.2.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.0
[2.2.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.1
[2.2.2]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.2
[2.2.3]: https://github.com/aibedini/gre-manager/releases/tag/v2.2.3
[2.3.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.3.0
[2.4.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.4.0
[2.5.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.5.0
[2.6.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.6.0
[2.6.1]: https://github.com/aibedini/gre-manager/releases/tag/v2.6.1
[2.7.0]: https://github.com/aibedini/gre-manager/releases/tag/v2.7.0
