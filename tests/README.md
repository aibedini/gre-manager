# gre-manager test suite

Bash-only test harness for `gre-manager.sh`. Runs on **Linux** and in
**Git Bash** (Windows) — no root needed, the real system is never touched.

## How to run

```bash
bash tests/run.sh        # from the repo root (or from anywhere)
```

Exit code is `0` when every assertion passes, non-zero otherwise
(the last line prints `PASS=<n> FAIL=<n>`).

Requirements: `bash`, `sed`, `awk`, `grep`, `tar`, `mktemp`.
Optional: `python` or `python3` — used to validate JSON output precisely;
without it, JSON assertions fall back to grep-based structural checks
(marked `(structural)` in the output).

## How it works

1. `gre-manager.sh` is copied to a temp *script under test* with every
   absolute system path sed-redirected into a per-test temp root
   (`/etc/multi-gre`, the systemd unit files, `/usr/local/sbin/gre`,
   `/var/log/gre-manager.log`, `/etc/sysctl.d/99-multi-gre.conf`).
   `require_root` is neutralized.
2. `tests/stubs/` contains fake `ip`, `iptables`, `systemctl`, `ping`,
   `ss`, `sysctl` and `logger` binaries that are put first on `PATH`.
   They keep their state (tunnels, addresses, iptables rules per table,
   dead-ping list, logger output) as plain files under
   `$TEST_ROOT/state/`, so tests can assert on exact rules and simulate
   failures (e.g. echo an IP into `state/dead` to make its ping fail).
3. Each `gre` invocation fails the suite automatically if bash reports an
   `unbound variable`.

## What is covered

| Section | Spec matrix item |
| ------- | ---------------- |
| 1 | Fresh-server CLI sweep — every command on an unconfigured server, no unbound variables |
| 2 | v1→v2 migration: peer file, manifest, `iran.conf.v1.bak`, legacy rule replacement, idempotent re-run, mixed-layout abort |
| 3 | Three peers: independent tunnels/subnets/rules, no duplicates on re-apply, idempotent re-add, duplicate name/(base,idx) rejection |
| 4 | Port splitting: TCP/UDP range overlap rejected, TCP independent of UDP, boundary ports |
| 5 | SSH port 22 protection (`--yes` required) |
| 6 | Middle-peer removal isolation (tunnels, rules, conf, shared service kept) |
| 7 | Watchdog repairs only the dead/missing peer; log names peer, tunnel and foreign IP |
| 8 | JSON status for 0/1/3 peers, `schema_version: 2`, deprecated legacy `iran` field |
| 9 | Doctor exit codes: healthy, missing tunnel, missing DNAT, artificial (base,idx) conflict |
| 10 | `iran-setup` backward compatibility (first peer ok, refuses on multi-peer) |
| 11 | Export/import roundtrips: v2, v1 (migrates on import), mixed archive rejected, unsafe archive rejected |
| 12 | Purge removes per-peer comment-tagged rules and legacy leftovers |
| 13 | FOREIGN regression: nodes, GRE whitelist ordering, `--subnet-base`, 10.200 fallback for legacy node confs |
| 14 | Legacy v1 `--stop` works without triggering migration |

Not covered here (by design): real end-to-end traffic — that needs Linux
network namespaces or VMs on real servers (spec matrix item 14, manual).

## CI

`.github/workflows/ci.yml` runs this suite on `ubuntu-latest` on every
push/PR, next to ShellCheck, `bash -n` and the version-consistency check.
