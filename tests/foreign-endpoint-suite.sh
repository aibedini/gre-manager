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

# ======================================================================
sect "24. gre tunnel diagnose is read-only and reports honestly"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 3001 --udp-ports 3001 --yes >/dev/null

# It must change nothing: no new interface, no new rule.
tuns_before="$(ls "$R/state/tunnels" 2>/dev/null | sort | tr '\n' ' ')"
rules_before="$(cat "$R/state/iptables.nat" "$R/state/iptables.filter" 2>/dev/null | md5sum)"

gre tunnel diagnose --name de1
assert "diagnose: rc=0 on a healthy connection" test "$GRE_RC" -eq 0
assert "diagnose: reports the interface present" grep -qE '\[PASS\][[:space:]]+interface_exists' <<< "$GRE_OUT"
assert "diagnose: reports the local endpoint" grep -qE '\[PASS\][[:space:]]+local_endpoint' <<< "$GRE_OUT"
assert "diagnose: reports the remote endpoint" grep -qE '\[PASS\][[:space:]]+remote_endpoint' <<< "$GRE_OUT"
assert "diagnose: reports the tunnel address" grep -qE '\[PASS\][[:space:]]+tunnel_address' <<< "$GRE_OUT"
assert "diagnose: reports the underlay route" grep -qE '\[PASS\][[:space:]]+underlay_route' <<< "$GRE_OUT"
assert "diagnose: reports GRE protocol 47" grep -qE '\[PASS\][[:space:]]+gre_47_permitted' <<< "$GRE_OUT"
assert "diagnose: reports reachability" grep -qE '\[PASS\][[:space:]]+tunnel_reachable' <<< "$GRE_OUT"
assert "diagnose: prints a summary line" grep -qE '^pass=[0-9]+ warn=[0-9]+ fail=[0-9]+ unknown=[0-9]+$' <<< "$GRE_OUT"

assert "diagnose is read-only: no interface added" \
    test "$tuns_before" = "$(ls "$R/state/tunnels" 2>/dev/null | sort | tr '\n' ' ')"
assert "diagnose is read-only: no rule changed" \
    test "$rules_before" = "$(cat "$R/state/iptables.nat" "$R/state/iptables.filter" 2>/dev/null | md5sum)"

# JSON form must be valid for a parser, and must expose every check.
gre tunnel diagnose --name de1 --json
assert "diagnose --json: rc=0" test "$GRE_RC" -eq 0
json_valid "diagnose --json: valid JSON"
assert "diagnose --json: names the side" grep -q '"side":"iran"' <<< "$GRE_OUT"
assert "diagnose --json: has a summary" grep -q '"summary":{' <<< "$GRE_OUT"
assert "diagnose --json: has a checks array" grep -q '"checks":\[' <<< "$GRE_OUT"
assert "diagnose --json: includes the reachability check" grep -q 'tunnel_reachable' <<< "$GRE_OUT"
assert_not "diagnose --json: leaks no secret" grep -qi 'password\|secret' <<< "$GRE_OUT"

# A missing interface is a FAIL with an actionable fix, and a non-zero exit.
rm -f "$R/state/tunnels/gre-de1"
gre tunnel diagnose --name de1
assert_not "diagnose: rc != 0 when the interface is gone" test "$GRE_RC" -eq 0
assert "diagnose: names the missing interface" grep -qE '\[FAIL\][[:space:]]+interface_exists' <<< "$GRE_OUT"
assert "diagnose: says how to create it" grep -qi 'peer apply\|node add' <<< "$GRE_OUT"
assert "diagnose: unknowns the checks it cannot run" grep -qE '\[UNKNOWN\][[:space:]]+interface_up' <<< "$GRE_OUT"
assert_not "diagnose: does not claim the tunnel is reachable" grep -qE '\[PASS\][[:space:]]+tunnel_reachable' <<< "$GRE_OUT"

# An unknown connection is refused, not reported as healthy.
gre tunnel diagnose --name nope
assert_not "diagnose: rc != 0 for an unknown connection" test "$GRE_RC" -eq 0
assert "diagnose: says the connection is not configured here" grep -qi 'No connection named' <<< "$GRE_OUT"
gre tunnel diagnose
assert_not "diagnose: rc != 0 without --name" test "$GRE_RC" -eq 0
gre tunnel --help
assert "tunnel --help: rc=0" test "$GRE_RC" -eq 0
assert "tunnel --help: documents diagnose" grep -q 'tunnel diagnose' <<< "$GRE_OUT"
gre --help
assert "gre --help: lists tunnel diagnose" grep -q 'tunnel diagnose' <<< "$GRE_OUT"
rm -rf "$R"

# ------------------------------------------- a GRE route that loops into the tunnel
# The classic self-inflicted outage: a route that sends the GRE packets themselves
# back out of the GRE interface, so the tunnel can never come up.
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 3001 --yes >/dev/null
gre tunnel diagnose --name de1
assert "loop fixture: clean route set reports no loop" grep -qE '\[PASS\][[:space:]]+no_gre_loop_route' <<< "$GRE_OUT"
rm -rf "$R"

# ---------------------------------------------------------------- tunnel rules
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre tunnel rules
assert "tunnel rules: rc=0" test "$GRE_RC" -eq 0
gre tunnel rules --json
assert "tunnel rules --json: rc=0" test "$GRE_RC" -eq 0
json_valid "tunnel rules --json: valid JSON"
rm -rf "$R"
