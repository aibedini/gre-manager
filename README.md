# Multi-GRE Tunnel Manager

<p>
  <a href="https://github.com/aibedini/gre-manager/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/aibedini/gre-manager/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/aibedini/gre-manager/releases"><img alt="Version" src="https://img.shields.io/github/v/release/aibedini/gre-manager?display_name=tag"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg"></a>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-blue">
  <img alt="Shell" src="https://img.shields.io/badge/shell-bash-lightgrey">
</p>

Menu-driven manager for **multiple GRE tunnels**: connect **many IRAN servers** to **one FOREIGN server**,
with per-node isolation, port forwarding (DNAT/SNAT), and systemd persistence — all through a single `gre` command.

```mermaid
flowchart TD
    F["FOREIGN server<br/>(Xray / services listen on 0.0.0.0)"]
    I1["IRAN node 1"]
    I2["IRAN node 2"]
    I3["IRAN node 3"]

    I1 -->|"gre-ir01 · 10.200.1.0/30 · key 1001"| F
    I2 -->|"gre-ir02 · 10.200.2.0/30 · key 1002"| F
    I3 -->|"gre-ir03 · 10.200.3.0/30 · key 1003"| F
```

---

## Features

- **One command** — after install, just run `sudo gre` and the menu loads.
- **Multi-node** — each Iran server gets its own tunnel name, `/30` subnet and GRE key; up to 254 nodes.
- **Port forwarding** — forward only the TCP/UDP ports you choose from each Iran public IP to the foreign server (multiport + ranges, SSH port 22 protected by an explicit confirmation).
- **systemd persistence** — tunnels and NAT rules are re-applied automatically after reboot (`multi-gre.service`).
- **Watchdog** — a systemd timer re-checks every tunnel and revives dead ones (`journalctl -t gre-watchdog`); the check interval comes from **your** acceptable-downtime answer at setup and can be changed or cancelled anytime.
- **Firewall hardening** — optional GRE (proto 47) whitelist on the foreign server: only known Iran node IPs can connect.
- **MSS clamping** — optional TCPMSS clamp on the tunnel to avoid broken-PMTU stalls.
- **Audit log** — every change is appended to `/var/log/gre-manager.log`.
- **Idempotent & safe** — re-running any action never duplicates iptables rules; deletions check existence first.
- **Self-update** — `gre update` pulls the latest release from GitHub (with a syntax check before replacing).
- **Legacy cleanup** — one menu option removes everything the old `vatanhost/gre` script left behind.
- **Status & diagnostics** — per-node ping tests, tunnel list, NAT rules, service state.
- **Non-interactive CLI** — every setup step can be scripted (`gre node add`, `gre iran-setup`, …) for Ansible & co.
- **JSON status** — `gre status --json` for monitoring and automation (pure bash, no `jq` needed).
- **Doctor** — `gre doctor` runs health checks (tunnels, NAT rules, firewall, systemd, port conflicts) and exits non-zero on failure.
- **Backup & restore** — `gre export` / `gre import` move the whole configuration between servers as a single tar.gz.

## Install

On **every** server (foreign and all Iran nodes):

```bash
curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | sudo bash
```

The installer downloads the latest **pinned release** and verifies its **SHA-256 checksum**
before installing (`gre` + bash completion). For the bleeding-edge main branch instead:

```bash
curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | sudo GRE_EDGE=1 bash
```

Then run:

```bash
sudo gre
```

```
   __________  ____     __  ___
  / ____/ __ \/ __ \   /  |/  /__ _____  ____ _____ ____  _____
 / / __/ /_/ / /_/ /  / /|_/ / _ `/ _ \/ _ `/ _ `/ -_) __/
 \____/_/ |_/_____/  /_/  /_/\_,_/_//_/\_,_/\_, /\__/_/
                                           /____/
  Multi-GRE Tunnel Manager  v1.4.0  ·  github.com/aibedini/gre-manager
  ═════════════════════════════════════════════════════════════
  Role: FOREIGN   Tunnels: ● 3 up   Watchdog: ● ON · every 1m
  ── Tunnels ─────────────────────────────────────────────────
  1) Configure this server as an IRAN node
  2) Configure this server as FOREIGN / add an Iran node
  3) Remove an Iran node from FOREIGN                  [3 nodes]
  4) Restart all configured tunnels
  5) Stop all configured tunnels
  ── Monitoring ──────────────────────────────────────────────
  6) Status & health
  7) Auto-heal watchdog                                ● ON · every 1m
  8) Doctor (diagnostics)
  ── Maintenance ─────────────────────────────────────────────
  9) Backup / restore (export / import)
 10) Clean up original vatanhost gre.sh (vatan-m2)
 11) Update gre-manager to the latest version
 12) Uninstall from this server
 13) PURGE: remove EVERYTHING GRE (danger)
  0) Exit
  ═════════════════════════════════════════════════════════════
```

During setup you are asked **how many minutes of tunnel downtime are acceptable** —
the watchdog check interval is derived from your answer (`tolerance / 2`), and `0`
disables auto-heal. You can change or cancel it anytime from menu option **7**
or with `gre watchdog interval N` / `gre watchdog disable`.

## Quick start

1. **FOREIGN server** — run `sudo gre`, choose **2**. On first run it registers the foreign IP,
   then adds one Iran node per run. After each node it prints the exact values to enter on the Iran side.
2. **Each IRAN server** — run `sudo gre`, choose **1**, enter the values from step 1
   (node name, tunnel index, GRE key must match) plus the ports you want to forward.
3. Verify: from Iran `ping 10.200.<idx>.1`, from foreign `ping 10.200.<idx>.2` — or use menu option **6**.

| Node   | Tunnel     | Foreign side    | Iran side       | GRE key |
| ------ | ---------- | --------------- | --------------- | ------- |
| `ir01` | `gre-ir01` | `10.200.1.1/30` | `10.200.1.2/30` | `1001`  |
| `ir02` | `gre-ir02` | `10.200.2.1/30` | `10.200.2.2/30` | `1002`  |
| `ir03` | `gre-ir03` | `10.200.3.1/30` | `10.200.3.2/30` | `1003`  |

## CLI reference

| Command        | Description                                              |
| -------------- | -------------------------------------------------------- |
| `gre`          | Interactive menu                                         |
| `gre --status` | Show roles, tunnels, NAT rules, per-node ping, service   |
| `gre status --json` | Same as `--status`, but machine-readable JSON       |
| `gre doctor`   | Diagnostics: PASS/WARN/FAIL per check, non-zero exit on FAIL |
| `gre node list [--json]` | List configured Iran nodes (FOREIGN)            |
| `gre node add` | Add an Iran node (FOREIGN): `--name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]` |
| `gre node remove` | Remove an Iran node (FOREIGN): `--name NAME [--yes]`  |
| `gre iran-setup` | Non-interactive Iran setup: `--foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on\|off] [--downtime MIN] [--yes]` |
| `gre export [path]` | Back up `/etc/multi-gre` to a tar.gz (mode 600)     |
| `gre import <file>` | Restore a backup created by `gre export`            |
| `gre update`   | Self-update to the latest version                        |
| `gre watchdog` | Watchdog: `enable` / `disable` / `status` / `interval <1-60>` |
| `gre purge` | Remove EVERYTHING GRE-related from the server (incl. old versions' artifacts); `--yes` skips confirmation |
| `gre --apply`  | Bring up all configured tunnels (used by systemd)        |
| `gre --stop`   | Tear down all tunnels, keep config (used by systemd)     |
| `gre --version`| Print version                                            |

All mutating commands ask for confirmation unless `--yes` is passed.

### Automation example

```bash
# FOREIGN server (run 'sudo gre' -> option 2 once first for the initial setup):
gre node add --name ir01 --ip 5.6.7.8 --yes          # idx/key default to 1/1001
gre node list --json

# IRAN server:
gre iran-setup --foreign-ip 1.2.3.4 --name ir01 --idx 1 --key 1001 \
    --tcp-ports 80,443,8443 --udp-ports 443 --yes

# Monitoring / config management:
gre status --json
gre doctor                                           # exit code != 0 if anything FAILs
gre export /root/gre-backup.tar.gz --yes
```

## How it works

- **IRAN node**: packets arriving on the public IP at the configured ports are DNAT-ed into the tunnel
  towards `10.200.<idx>.1` (the foreign end) and SNAT-ed to `10.200.<idx>.2`, so replies flow back
  through conntrack automatically. `net.ipv4.ip_forward` is enabled and persisted.
- **FOREIGN node**: one GRE tunnel per Iran node. Services listening on `0.0.0.0`
  (e.g. Xray) are reachable through every tunnel at once.
- **Config** lives in `/etc/multi-gre/` — `/etc/multi-gre/nodes/<name>.conf` per Iran node (foreign side),
  `iran.conf` on each Iran node. The systemd unit runs `gre --apply` at boot.

## Notes & security

- GRE is **not encrypted** — it is a transport/tunnel, not a VPN. Run your real service (e.g. Xray/TLS) on top.
- The GRE `key` only separates tunnels; it is not authentication.
- Only the ports you list are forwarded — SSH access to each Iran server stays local unless you explicitly forward port 22.
- If the foreign server's IP gets blocked, all nodes lose connectivity: the foreign host is a single point of failure.
- Works on systemd-based Debian/Ubuntu (and most RHEL-likes); requires `iproute2`, `iptables`, `curl`.

## Uninstall

```bash
sudo gre   # -> option 12 (Uninstall)
```

Removes tunnels, NAT rules, the systemd service, the sysctl file, `/etc/multi-gre` and the `gre` command itself.

### Full purge (scorched earth)

To remove **everything GRE-related** — including tunnels and rules left by older
gre-manager versions, the legacy vatanhost script, or hand-made tunnels:

```bash
sudo gre purge        # asks for confirmation; menu option 13 does the same
sudo gre purge --yes  # non-interactive
```

This deletes every GRE/GRETAP tunnel, every iptables rule mentioning GRE artifacts
(`multi-gre`, GRE interfaces, proto 47, `10.200.0.0/16`, `132.168.30.0/30`), the
systemd units, all config, and the `gre` command itself.

## Versioning

This project uses [Semantic Versioning](https://semver.org/). See [CHANGELOG.md](CHANGELOG.md) and the
[releases page](https://github.com/aibedini/gre-manager/releases).

## License

[MIT](LICENSE)

---

## راهنمای فارسی

این ابزار چند سرور **ایران** را از طریق تونل GRE به **یک سرور خارج** وصل می‌کند؛ هر سرور ایران تونل، ساب‌نت و کلید اختصاصی خودش را دارد.

**نصب (روی همهٔ سرورها):**

```bash
curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | sudo bash
sudo gre
```

**ترتیب راه‌اندازی:**

1. روی سرور **خارج**: گزینهٔ `2` — برای هر سرور ایران یک بار اجرا کنید؛ آخر کار مقادیری می‌دهد (نام نود، index، key).
2. روی هر سرور **ایران**: گزینهٔ `1` — همان مقادیر را وارد کنید و پورت‌هایی که باید به خارج منتقل شوند را بدهید (مثلاً `80,443,8443`).
3. تست: گزینهٔ `6` یا `ping 10.200.<idx>.1` از سمت ایران.

- پورت ۲۲ (SSH) به‌صورت پیش‌فرض منتقل نمی‌شود؛ اگر واردش کنید هشدار می‌گیرید.
- تنظیمات بعد از reboot خودکار برمی‌گردند (سرویس `multi-gre.service`).
- به‌روزرسانی: `sudo gre update`
- حذف کامل: گزینهٔ `7` در منو
- پاک‌سازی اسکریپت قدیمی vatanhost: گزینهٔ `8`
- GRE رمزنگاری ندارد؛ سرویس اصلی (مثل Xray) باید روی آن امن باشد.
