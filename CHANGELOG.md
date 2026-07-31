# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
