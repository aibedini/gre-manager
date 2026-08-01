# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
