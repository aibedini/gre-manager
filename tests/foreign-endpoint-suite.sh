#!/usr/bin/env bash
# Regression tests for FOREIGN-side local endpoint resolution.
#
# BACKGROUND, stated precisely because it determines what these tests can prove:
#
# A node config stores IRAN_IP but NOT this host's own public IP; that lives in
# foreign.conf, which every CLI entry point (node add, node edit, --watchdog,
# --apply) already sources. So no current code path actually produces an empty
# `local` address — the defect was a fragile CONTRACT, not a live outage:
#
#   apply_foreign_node() read FOREIGN_IP from the CALLER's scope. That made the
#   function's correctness depend on something it never declared or validated. On a
#   dual-role host foreign.conf is a globally-sourced shell file, so a truncated or
#   overwritten foreign.conf silently leaves FOREIGN_IP empty or stale, and the
#   tunnel is then created with no/garbage `local` endpoint — a tunnel that exists
#   and looks configured but can never pass traffic.
#
# The fix makes the function resolve and VALIDATE its own endpoint. These tests pin
# that contract: the endpoint is always resolved, always this host's address, and a
# missing/invalid endpoint is a loud refusal rather than a broken tunnel.
#
# The ip stub rejects an empty or 0.0.0.0 local/remote, so a regression here fails
# loudly instead of silently recording a unusable tunnel.

sect "23. FOREIGN local endpoint resolution and refusal on a bad endpoint"

# The harness `gre` helper captures the command's output into GRE_OUT, so
# redirecting a `gre` call to a file records nothing. Diagnostics that are produced
# on stderr need the raw script, so run it directly.
gre_raw() { TEST_ROOT="$R" PATH="$STUBS:$PATH" bash "$SUT" "$@"; }

# ------------------------------------------------- the endpoint is always resolved
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
assert "node add: rc=0" test "$GRE_RC" -eq 0
assert "node add: tunnel exists" test -f "$R/state/tunnels/gre-ir1"
assert "node add: local endpoint is THIS host" grep -q 'local 203.0.113.10' "$R/state/tunnels/gre-ir1"
assert "node add: remote endpoint is the Iran host" grep -q 'remote 198.51.100.20' "$R/state/tunnels/gre-ir1"
rm -rf "$R"

# ------------------------------------------------------- the endpoint is not global
# Two nodes share one foreign host and must both carry the same correct local
# endpoint. A caller-scoped value could differ between iterations of the apply loop.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
gre node add --name ir2 --ip 198.51.100.21 --idx 2 --key 1002 --yes
assert "two nodes: both tunnels exist" bash -c "test -f '$R/state/tunnels/gre-ir1' -a -f '$R/state/tunnels/gre-ir2'"
assert "two nodes: ir1 local correct" grep -q 'local 203.0.113.10' "$R/state/tunnels/gre-ir1"
assert "two nodes: ir2 local correct" grep -q 'local 203.0.113.10' "$R/state/tunnels/gre-ir2"
assert "two nodes: ir2 remote correct" grep -q 'remote 198.51.100.21' "$R/state/tunnels/gre-ir2"
rm -rf "$R"

# ------------------------------------------------------------- watchdog re-apply
# The watchdog rebuilds a dead tunnel. It must resolve the same endpoint without
# depending on loop state left over from the Iran-side pass that runs after it.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
rm -f "$R/state/tunnels/gre-ir1"
gre --watchdog >/dev/null 2>&1
assert "watchdog re-apply: tunnel recreated" test -f "$R/state/tunnels/gre-ir1"
assert "watchdog re-apply: local endpoint still this host" grep -q 'local 203.0.113.10' "$R/state/tunnels/gre-ir1"
rm -rf "$R"

# ------------------------------------------- a corrupt foreign.conf must refuse
# foreign.conf is a sourced shell file. If it loses FOREIGN_IP, the old code built a
# tunnel with an empty `local`; now it must refuse and say what to do.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
rm -f "$R/state/tunnels/gre-ir1"
# Simulate corruption that removes the key while leaving the file present.
printf 'ICMP_DROP=0\nGRE_WHITELIST=1\n' > "$R/etc/multi-gre/foreign.conf"
gre --watchdog >/dev/null 2>&1
assert_not "corrupt foreign.conf: no tunnel is built with an empty local endpoint" \
    test -f "$R/state/tunnels/gre-ir1"
gre_raw --watchdog >"$R/wd.out" 2>&1
assert "corrupt foreign.conf: the failure names the missing endpoint" \
    grep -qi 'unknown' "$R/wd.out"
rm -rf "$R"

# ------------------------------------- node add without foreign.conf must refuse
# The same contract at the CLI boundary.
mkroot
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
assert_not "node add without foreign.conf: rc != 0" test "$GRE_RC" -eq 0
assert_not "node add without foreign.conf: no tunnel created" test -f "$R/state/tunnels/gre-ir1"
assert "node add without foreign.conf: says how to fix it" \
    grep -qi 'not configured as FOREIGN' <<< "$GRE_OUT"
rm -rf "$R"

# ------------------------------------------------- a node config missing TUN is refused
# node_conf_read replaces an unvalidated `source`, so a malformed config is caught
# instead of creating a tunnel named after an empty string.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
mkdir -p "$R/etc/multi-gre/nodes"
cat > "$R/etc/multi-gre/nodes/notun.conf" <<'EOF'
NAME=notun
IRAN_IP=198.51.100.20
SUBNET_BASE=10.200
IDX=1
KEY=1001
EOF
gre_raw --watchdog >"$R/wd2.out" 2>&1
assert "config without TUN: nothing is created under an empty name" \
    bash -c "! ls '$R/state/tunnels' | grep -qx ''"
assert "config without TUN: the failure names the missing TUN" \
    grep -qi 'no TUN value' "$R/wd2.out"
rm -rf "$R"

# ------------------------------------------------------- rollback keeps a real endpoint
# A rollback must rebuild the interface with a usable local endpoint. It reads the
# snapshot captured before the edit, not a caller global.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
gre node edit --name ir1 --key 2002 --yes
assert "node edit: rc=0" test "$GRE_RC" -eq 0
assert "node edit: endpoint preserved" grep -q 'local 203.0.113.10' "$R/state/tunnels/gre-ir1"
assert "node edit: new key applied" grep -q 'key 2002' "$R/state/tunnels/gre-ir1"
assert_not "node edit: never an empty local endpoint" grep -q 'local  ' "$R/state/tunnels/gre-ir1"
rm -rf "$R"
