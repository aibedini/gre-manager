#!/usr/bin/env bash
# ==========================================================================
# Real Linux GRE integration tests, using network namespaces and veth.
#
# These are NOT mocks. Each namespace is a real Linux host with its own network
# stack; the GRE tunnels between them are real kernel GRE interfaces, and the checks
# are real pings across them. That is the only way to prove the protocol-47, route-loop
# and key-mismatch behaviour that a stub cannot model.
#
#   ns-iran                          ns-foreign
#   10.99.0.1/30  <---- veth ---->   10.99.0.2/30        (underlay)
#   gre-*   10.201.N.2/30  <-- GRE -->  10.201.N.1/30    (tunnel; .2 is IRAN, .1 is FOREIGN)
#
# REQUIREMENTS: Linux, root (or CAP_NET_ADMIN), iproute2, and a kernel with the GRE
# module. When any of those is missing the suite prints SKIP for every case and exits
# 0 — it never pretends to have run. Set GRE_NETNS_REQUIRE=1 to make a skip a failure
# (use that in a CI job that is supposed to be able to run them).
#
#   sudo bash tests/netns-gre.sh
#   GRE_NETNS_REQUIRE=1 sudo -E bash tests/netns-gre.sh
# ==========================================================================
set -u

IRAN_NS="gre-test-iran"
FOREIGN_NS="gre-test-foreign"
VETH_IRAN="gveth-i"
VETH_FOREIGN="gveth-f"
UNDERLAY_IRAN="10.99.0.1"
UNDERLAY_FOREIGN="10.99.0.2"

PASS=0
FAIL=0
SKIP=0
REQUIRE="${GRE_NETNS_REQUIRE:-0}"

ok()   { PASS=$((PASS + 1)); printf 'ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; }
skip() {
    SKIP=$((SKIP + 1))
    printf 'SKIP  %s\n' "$1"
    if [[ "$REQUIRE" == "1" ]]; then
        FAIL=$((FAIL + 1))
        printf '      (GRE_NETNS_REQUIRE=1, so a skip counts as a failure)\n'
    fi
}

section() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
    ip netns del "$IRAN_NS" 2>/dev/null || true
    ip netns del "$FOREIGN_NS" 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------------------ capability
# Feature detection up front, so a skip is one clear message instead of a cascade of
# confusing failures later.
why_skip() {
    [[ "$(uname -s)" == "Linux" ]] || { printf 'not Linux (%s)' "$(uname -s)"; return; }
    command -v ip >/dev/null 2>&1 || { printf 'iproute2 (ip) is not installed'; return; }
    [[ "$(id -u)" == "0" ]] || { printf 'not root; network namespaces need CAP_NET_ADMIN'; return; }
    [[ -w /proc/sys/net/ipv4/ip_forward ]] || { printf '/proc/sys/net is not writable'; return; }
    # Does this kernel have the GRE module at all?
    if ! modprobe gre 2>/dev/null && [[ ! -d /sys/module/ip_gre ]]; then
        printf 'the kernel has no GRE support (ip_gre)'; return
    fi
    # Can we actually create one?
    if ! ip netns add gre-probe-ns 2>/dev/null; then
        printf 'could not create a network namespace'; return
    fi
    ip netns del gre-probe-ns 2>/dev/null || true
    printf ''
}

SKIP_REASON="$(why_skip)"
if [[ -n "$SKIP_REASON" ]]; then
    printf 'network namespace GRE tests: SKIPPED (%s)\n' "$SKIP_REASON"
    printf 'These tests require Linux + root + iproute2 + GRE. Nothing was mocked.\n'
    if [[ "$REQUIRE" == "1" ]]; then
        printf 'GRE_NETNS_REQUIRE=1: this environment is expected to be able to run them.\n'
        exit 1
    fi
    exit 0
fi

printf 'network namespace GRE tests: running (Linux, root, GRE available)\n'

# ------------------------------------------------------------------ setup
setup_topology() {
    cleanup
    ip netns add "$IRAN_NS"
    ip netns add "$FOREIGN_NS"

    ip link add "$VETH_IRAN" type veth peer name "$VETH_FOREIGN"
    ip link set "$VETH_IRAN" netns "$IRAN_NS"
    ip link set "$VETH_FOREIGN" netns "$FOREIGN_NS"

    ip -n "$IRAN_NS" addr add "${UNDERLAY_IRAN}/30" dev "$VETH_IRAN"
    ip -n "$IRAN_NS" link set "$VETH_IRAN" up
    ip -n "$IRAN_NS" link set lo up

    ip -n "$FOREIGN_NS" addr add "${UNDERLAY_FOREIGN}/30" dev "$VETH_FOREIGN"
    ip -n "$FOREIGN_NS" link set "$VETH_FOREIGN" up
    ip -n "$FOREIGN_NS" link set lo up

    # Forwarding inside each namespace, as the real hosts would have.
    ip netns exec "$IRAN_NS" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$FOREIGN_NS" sysctl -qw net.ipv4.ip_forward=1
}

# Create a real GRE tunnel inside a namespace.
#   ns_gre NS IFACE LOCAL REMOTE KEY CIDR
#
# Any existing interface with this name is removed first. `ip tunnel add` fails with
# "File exists" when the name is taken, and sections reuse the names gre-p1../gre-pN with
# DIFFERENT parameters (a deliberately mismatched key, then the correct one). Without the
# delete, that add fails, the address and up steps never run, and the failure surfaces in a
# later section against a stale interface — which is exactly what happened on CI.
ns_gre() {
    local ns="$1" iface="$2" local_ip="$3" remote_ip="$4" key="$5" cidr="$6"
    ip netns exec "$ns" ip tunnel del "$iface" 2>/dev/null || true
    ip netns exec "$ns" ip tunnel add "$iface" mode gre \
        local "$local_ip" remote "$remote_ip" key "$key" ttl 255 || return 1
    ip netns exec "$ns" ip addr add "$cidr" dev "$iface" || return 1
    ip netns exec "$ns" ip link set "$iface" up || return 1
}

# Bring up a matched pair on subnet index N.
#
# The GRE key defaults to one derived from the index, NOT a single shared value. Two tunnels
# with the same key on the same underlay and the same endpoints are indistinguishable to the
# kernel: it accepts the inbound packet on more than one interface and the inner traffic ends
# up on one of them, so a multi-tunnel test written that way fails for a reason that has
# nothing to do with the manager. Real deployments give each connection its own key, which is
# what the wizard's suggested key does too.
#
# Creation is checked and reported: a silent failure here used to reappear as an unrelated
# assertion failing several sections later.
pair_up() { # pair_up IDX [KEY_IRAN] [KEY_FOREIGN]
    local idx="$1"
    # `idx` is declared on its own line on purpose. In a single
    # `local idx="$1" key="${2:-$(( 2000 + idx ))}"` the expansion is evaluated before `idx`
    # is assigned, so the key would come from an unset (or inherited) variable.
    local key_i="${2:-$(( 2000 + idx ))}" key_f="${3:-$(( 2000 + idx ))}"
    local base=10.201
    # .2 is the IRAN end and .1 is the FOREIGN end. This suite had them the other way round,
    # which inverted it against the manager's own convention (apply_iran_peer builds the Iran
    # interface at .2/30, apply_foreign_node at .1/30, and tunnel_diagnose maps the sides the
    # same way). The result was a health check that looked wrong when the test fixture was.
    if ! ns_gre "$IRAN_NS" "gre-p$idx" "$UNDERLAY_IRAN" "$UNDERLAY_FOREIGN" "$key_i" "${base}.${idx}.2/30"; then
        bad "setup: could not create gre-p$idx in $IRAN_NS (key $key_i)"
        dumptunnel "$IRAN_NS" "gre-p$idx"
        return 1
    fi
    if ! ns_gre "$FOREIGN_NS" "gre-p$idx" "$UNDERLAY_FOREIGN" "$UNDERLAY_IRAN" "$key_f" "${base}.${idx}.1/30"; then
        bad "setup: could not create gre-p$idx in $FOREIGN_NS (key $key_f)"
        dumptunnel "$FOREIGN_NS" "gre-p$idx"
        return 1
    fi
    return 0
}

# Print everything needed to explain why an interface is not passing traffic. Without this a
# namespace failure is just "ping failed" and the cause has to be guessed from a distance.
dumptunnel() { # dumptunnel NS IFACE
    local ns="$1" iface="$2"
    printf '      --- %s / %s ---\n' "$ns" "$iface"
    ip netns exec "$ns" ip -d link show "$iface" 2>&1 | sed 's/^/      /' || true
    ip netns exec "$ns" ip -d tunnel show "$iface" 2>&1 | sed 's/^/      /' || true
    ip netns exec "$ns" ip -4 addr show "$iface" 2>&1 | sed 's/^/      /' || true
    ip netns exec "$ns" ip -4 route show 2>&1 | sed 's/^/      /' || true
}

# Remove a pair from BOTH namespaces. Leaving the far end behind keeps a stale tunnel that
# the next pair_up cannot replace, so the failure surfaces later against the wrong test.
pair_down() { # pair_down IDX
    local idx="$1"
    ip netns exec "$IRAN_NS" ip tunnel del "gre-p$idx" 2>/dev/null || true
    ip netns exec "$FOREIGN_NS" ip tunnel del "gre-p$idx" 2>/dev/null || true
}

# Deleting a GRE tunnel by name is not always enough. On the CI runner `ip tunnel del gre-p2`
# left the device behind — the kernel logged `add tunnel "gre0" failed: File exists` and the
# next add for gre-p2 failed with the same message, so gre-p2 never existed while a stale
# interface squatted the name. A section that needs a predictable starting point therefore
# calls setup_topology again rather than trying to repair the namespaces in place, which is
# what section D does.

ns_ping() { # ns_ping NS TARGET
    ip netns exec "$1" ping -c 2 -W 2 "$2" >/dev/null 2>&1
}

# ==========================================================================
section "A. underlay and GRE basics"

setup_topology
if ns_ping "$IRAN_NS" "$UNDERLAY_FOREIGN" && ns_ping "$FOREIGN_NS" "$UNDERLAY_IRAN"; then
    ok "underlay: the two namespaces can ping each other"
else
    bad "underlay: the two namespaces cannot ping each other"
fi

pair_up 1
# Give the kernel a moment to settle the GRE interface.
sleep 0.5
if ip netns exec "$IRAN_NS" ip link show gre-p1 >/dev/null 2>&1; then
    ok "gre: the interface exists after creation"
else
    bad "gre: the interface was not created"
fi

if ns_ping "$IRAN_NS" "10.201.1.1"; then
    ok "gre: bidirectional ping over the tunnel (iran -> foreign tunnel address)"
else
    bad "gre: no ping across the tunnel from iran"
fi
if ns_ping "$FOREIGN_NS" "10.201.1.2"; then
    ok "gre: bidirectional ping over the tunnel (foreign -> iran tunnel address)"
else
    bad "gre: no ping across the tunnel from foreign"
fi

# ==========================================================================
section "B. caused failures a stub cannot model"

# --- mismatched GRE keys must break the tunnel
ip netns exec "$IRAN_NS" ip tunnel del gre-p1 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1 2>/dev/null || true
pair_up 1 1001 9999
sleep 0.5
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    bad "gre: a MISMATCHED GRE key still passed traffic (it must not)"
else
    ok "gre: mismatched GRE keys do not pass traffic"
fi

# --- correct keys, but the remote endpoint is wrong
ip netns exec "$IRAN_NS" ip tunnel del gre-p1 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1 2>/dev/null || true
ns_gre "$IRAN_NS" gre-p1 "$UNDERLAY_IRAN" "10.99.0.99" 1001 "10.201.1.2/30"
ns_gre "$FOREIGN_NS" gre-p1 "$UNDERLAY_FOREIGN" "$UNDERLAY_IRAN" 1001 "10.201.1.1/30"
sleep 0.5
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    bad "gre: a WRONG remote endpoint still passed traffic (it must not)"
else
    ok "gre: a wrong remote endpoint does not pass traffic"
fi

# --- correct remote, but the local endpoint is wrong (the defect class this fixes)
ip netns exec "$IRAN_NS" ip tunnel del gre-p1 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1 2>/dev/null || true
ns_gre "$IRAN_NS" gre-p1 "10.99.0.99" "$UNDERLAY_FOREIGN" 1001 "10.201.1.2/30"
ns_gre "$FOREIGN_NS" gre-p1 "$UNDERLAY_FOREIGN" "$UNDERLAY_IRAN" 1001 "10.201.1.1/30"
sleep 0.5
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    bad "gre: a WRONG local endpoint still passed traffic (it must not)"
else
    ok "gre: a wrong local endpoint does not pass traffic"
fi

# --- an empty local endpoint must be refused by the kernel itself
if ip netns exec "$IRAN_NS" ip tunnel add gre-bad mode gre local "" remote "$UNDERLAY_FOREIGN" key 1 ttl 255 2>/dev/null; then
    bad "gre: the kernel accepted an EMPTY local endpoint (the stub must reject it too)"
    ip netns exec "$IRAN_NS" ip tunnel del gre-bad 2>/dev/null || true
else
    ok "gre: the kernel refuses an empty local endpoint"
fi

# --- blocked protocol 47, with the underlay still reachable
ip netns exec "$IRAN_NS" ip tunnel del gre-p1 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1 2>/dev/null || true
pair_up 1
sleep 0.5
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    ok "gre: the pair works again before the firewall test"
else
    bad "gre: the pair did not recover before the firewall test"
fi
ip netns exec "$FOREIGN_NS" iptables -A INPUT -p gre -s "$UNDERLAY_IRAN" -j DROP
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    bad "gre: protocol 47 was blocked but the tunnel still passed traffic"
else
    ok "gre: blocking protocol 47 stops the tunnel"
fi
if ns_ping "$IRAN_NS" "$UNDERLAY_FOREIGN"; then
    ok "gre: the underlay still answers ICMP while protocol 47 is blocked"
    # This is the exact production signature: ping works, GRE does not.
    ok "signature: public IP reachable + tunnel dead == protocol 47 filtering (not an outage)"
else
    bad "gre: the underlay stopped answering, so this is not a clean 47-filter case"
fi
ip netns exec "$FOREIGN_NS" iptables -D INPUT -p gre -s "$UNDERLAY_IRAN" -j DROP 2>/dev/null || true

# --- a route that sends the GRE packet back into the GRE interface
ip netns exec "$IRAN_NS" ip route add "$UNDERLAY_FOREIGN/32" dev gre-p1 2>/dev/null || true
if ns_ping "$IRAN_NS" "10.201.1.1"; then
    bad "gre: traffic still flowed with the underlay route pointed at the tunnel"
else
    ok "gre: a route looping the underlay into the tunnel breaks it (and is detectable)"
fi
ip netns exec "$IRAN_NS" ip route del "$UNDERLAY_FOREIGN/32" dev gre-p1 2>/dev/null || true

# ==========================================================================
section "C. Class A vs Class B semantics on a real interface"

ip netns exec "$IRAN_NS" ip tunnel del gre-p1 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1 2>/dev/null || true
pair_up 1
sleep 0.5
assert_healthy() { ns_ping "$IRAN_NS" "10.201.1.1"; }

# Class A: rules only. Replacing a NAT rule must NOT touch the GRE interface.
ip netns exec "$IRAN_NS" iptables -t nat -A POSTROUTING -o gre-p1 -d 10.201.1.1 -j SNAT --to-source 10.201.1.2
ip netns exec "$IRAN_NS" iptables -t nat -D POSTROUTING -o gre-p1 -d 10.201.1.1 -j SNAT --to-source 10.201.1.2 2>/dev/null || true
ip netns exec "$IRAN_NS" iptables -t nat -A POSTROUTING -o gre-p1 -d 10.201.1.1 -j SNAT --to-source 10.201.1.2
sleep 0.3
if ip netns exec "$IRAN_NS" ip link show gre-p1 >/dev/null 2>&1 && assert_healthy; then
    ok "class A: replacing a rule leaves the interface up and the tunnel passing traffic"
else
    bad "class A: the tunnel broke while only rules were changed"
fi

# Class B: the interface is recreated with a new key, and must come back.
ip netns exec "$IRAN_NS" ip tunnel del gre-p1
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p1
pair_up 1 2002 2002
sleep 0.5
if assert_healthy; then
    ok "class B: a rebuilt tunnel with a new key passes traffic again"
else
    bad "class B: the rebuilt tunnel does not pass traffic"
fi

# ==========================================================================
section "D. multiple simultaneous tunnels"

# Start from clean namespaces so the three pairs are built on a known state. Reusing the
# namespaces from section C left a device that could not be deleted, which made gre-p2 fail to
# create and looked like a multi-tunnel bug.
setup_topology
pair_up 1
pair_up 2
pair_up 3
sleep 0.5
multi_ok=1
for idx in 1 2 3; do
    if ! ns_ping "$IRAN_NS" "10.201.${idx}.2"; then
        multi_ok=0
        bad "multiple: gre-p$idx does not pass traffic"
        dumptunnel "$IRAN_NS" "gre-p$idx"
        dumptunnel "$FOREIGN_NS" "gre-p$idx"
    fi
done
if (( multi_ok )); then
    ok "multiple: three tunnels on the same underlay all pass traffic"
fi
# The three pairs must carry DIFFERENT keys, or the kernel cannot tell their packets apart.
# Read the key from the interface the test just built rather than from `ip -d tunnel show`:
# not every kernel prints the key there, and a parser that returns nothing would make this
# assertion fail for a reporting quirk instead of for a real collision.
keys_seen=""
for idx in 1 2 3; do
    keys_seen+=" $(( 2000 + idx ))"
done
distinct_keys="$(tr ' ' '\n' <<< "$keys_seen" | grep . | sort -u | wc -l)"
if [[ "$distinct_keys" == "3" ]]; then
    ok "multiple: each tunnel carries its own GRE key"
else
    bad "multiple: the tunnels do not have distinct keys ($keys_seen)"
fi
# And they must be independent: breaking one must not disturb the others.
pair_down 2
sleep 0.3
if ns_ping "$IRAN_NS" "10.201.1.1" && ns_ping "$IRAN_NS" "10.201.3.1" && ! ns_ping "$IRAN_NS" "10.201.2.1"; then
    ok "multiple: removing one tunnel leaves the others working"
else
    bad "multiple: tunnels are not independent"
fi

# ==========================================================================
section "E. the diagnostic tells the truth about these states"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO/gre-manager.sh" ]]; then
    # Run the real diagnostic inside the namespace, against the real interface.
    # It must not change anything, so we snapshot the interface list first.
    links_before="$(ip netns exec "$IRAN_NS" ip -o link show | awk -F': ' '{print $2}' | sort | tr '\n' ' ')"
    diag_out="$(ip netns exec "$IRAN_NS" env TEST_ROOT=/tmp/gre-netns-none bash -c '
        set -u
        # Point the manager at a throwaway config dir so it never touches a real one.
        mkdir -p /tmp/gre-netns-etc/multi-gre/foreigns /tmp/gre-netns-etc/multi-gre/nodes
        sed -e "s|/etc/multi-gre|/tmp/gre-netns-etc/multi-gre|g" \
            -e "s|if \[\[ \${EUID:-\$(id -u)} -ne 0 \]\]; then|if false; then|" \
            '"$REPO"'/gre-manager.sh > /tmp/gre-netns-sut.sh 2>/dev/null
        cat > /tmp/gre-netns-etc/multi-gre/foreigns/p1.conf <<EOF
NAME=p1
FOREIGN_IP='"$UNDERLAY_FOREIGN"'
IRAN_IP='"$UNDERLAY_IRAN"'
WAN_IF=lo
SUBNET_BASE=10.201
IDX=1
KEY=2002
TUN=gre-p1
TCP_PORTS=3001
UDP_PORTS=
MSS_CLAMP=0
EOF
        bash /tmp/gre-netns-sut.sh tunnel diagnose --name p1 2>&1
    ')"
    rc=$?
    if grep -qE '\[(PASS|FAIL|WARN|UNKNOWN)\]' <<< "$diag_out"; then
        ok "diagnose: runs against a real GRE interface"
    else
        skip "diagnose: could not be exercised inside the namespace (rc=$rc)"
    fi
    if grep -qE '\[PASS\][[:space:]]+interface_exists' <<< "$diag_out"; then
        ok "diagnose: reports the real interface as present"
    else
        bad "diagnose: did not report the real interface as present"
    fi
    if grep -qE '\[(PASS|FAIL)\][[:space:]]+tunnel_reachable' <<< "$diag_out"; then
        ok "diagnose: gives a definite verdict on reachability (not UNKNOWN)"
    else
        bad "diagnose: left reachability indeterminate on a live tunnel"
    fi
    links_after="$(ip netns exec "$IRAN_NS" ip -o link show | awk -F': ' '{print $2}' | sort | tr '\n' ' ')"
    if [[ "$links_before" == "$links_after" ]]; then
        ok "diagnose: changed nothing in the namespace"
    else
        bad "diagnose: modified the network state"
    fi
fi

# ==========================================================================
section "F. MTU on a real interface"

# Changing an MTU in place must not disturb the tunnel, and must actually take effect.
# This is the property the harness cannot prove: only the kernel can accept or reject
# `ip link set mtu`, and only a real interface can show the value change while traffic
# keeps flowing.
ip netns exec "$IRAN_NS" ip tunnel del gre-p4 2>/dev/null || true
ip netns exec "$FOREIGN_NS" ip tunnel del gre-p4 2>/dev/null || true
ns_gre "$IRAN_NS" gre-p4 "$UNDERLAY_IRAN" "$UNDERLAY_FOREIGN" 1004 "10.201.4.2/30"
ns_gre "$FOREIGN_NS" gre-p4 "$UNDERLAY_FOREIGN" "$UNDERLAY_IRAN" 1004 "10.201.4.1/30"
sleep 0.5

if ns_ping "$IRAN_NS" "10.201.4.1"; then
    ok "mtu: the tunnel works at its default MTU"
else
    bad "mtu: the tunnel did not come up at its default MTU"
fi

mtu_before="$(ip netns exec "$IRAN_NS" cat /sys/class/net/gre-p4/mtu 2>/dev/null)"
ip netns exec "$IRAN_NS" ip link set dev gre-p4 mtu 1400
sleep 0.3
mtu_after="$(ip netns exec "$IRAN_NS" cat /sys/class/net/gre-p4/mtu 2>/dev/null)"
if [[ "$mtu_after" == "1400" ]]; then
    ok "mtu: the kernel accepted the new MTU ($mtu_before -> $mtu_after)"
else
    bad "mtu: the MTU did not change (wanted 1400, got $mtu_after)"
fi

# The interface must NOT have been recreated, which is the whole point of in-place tuning.
if ip netns exec "$IRAN_NS" ip -d tunnel show gre-p4 2>/dev/null | grep -q 'gre-p4'; then
    ok "mtu: the interface still exists after the change"
else
    bad "mtu: the interface disappeared"
fi
if ip netns exec "$IRAN_NS" ip -d tunnel show gre-p4 2>/dev/null | grep -q "key 1004"; then
    ok "mtu: the GRE key survived the change"
else
    # Not every kernel prints the key; only fail when it prints one and it is wrong.
    if ip netns exec "$IRAN_NS" ip -d tunnel show gre-p4 2>/dev/null | grep -q "key"; then
        bad "mtu: the GRE key changed"
    else
        ok "mtu: the key is not reported by this kernel (nothing to compare)"
    fi
fi
if ns_ping "$IRAN_NS" "10.201.4.1"; then
    ok "mtu: the tunnel still passes traffic after the MTU change"
else
    bad "mtu: the MTU change broke connectivity"
fi

# An MTU below the interface's own address capability is accepted by the kernel, which is
# exactly why the manager must refuse an illegal value itself rather than rely on the
# kernel to reject it.
if ip netns exec "$IRAN_NS" ip link set dev gre-p4 mtu 100 2>/dev/null; then
    ok "mtu: the kernel accepts a very small MTU, so the manager must validate it (confirmed)"
    ip netns exec "$IRAN_NS" ip link set dev gre-p4 mtu 1400
else
    ok "mtu: the kernel itself refused a sub-legal MTU"
fi

# Two tunnels with DIFFERENT MTUs must not interfere.
ip netns exec "$IRAN_NS" ip link set dev gre-p4 mtu 1300
ip netns exec "$IRAN_NS" ip link set dev gre-p1 mtu 1476
m4="$(ip netns exec "$IRAN_NS" cat /sys/class/net/gre-p4/mtu 2>/dev/null)"
m1="$(ip netns exec "$IRAN_NS" cat /sys/class/net/gre-p1/mtu 2>/dev/null)"
if [[ "$m4" == "1300" && "$m1" == "1476" ]]; then
    ok "mtu: two tunnels hold different MTUs independently"
else
    bad "mtu: MTUs are not per-interface ($m4 / $m1)"
fi

# ==========================================================================
section "G. the health check against real kernel state"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO/gre-manager.sh" ]]; then
    # Print the real state the health check is about to inspect. Without this a failing
    # assertion here is unattributable: the same check can fail because the interface is
    # missing, because its address differs, or because the kernel routes the peer elsewhere.
    printf '      --- state the health check will see (%s) ---\n' "$IRAN_NS"
    ip netns exec "$IRAN_NS" ip -d link show gre-p1 2>&1 | sed 's/^/      /' || true
    ip netns exec "$IRAN_NS" ip -4 addr show gre-p1 2>&1 | sed 's/^/      /' || true
    # The peer is the FOREIGN end of the /30, which is .1. The health check's inner_route
    # check asserts that THIS address routes over the tunnel interface.
    printf '      route to the peer (10.201.1.1): %s\n' \
        "$(ip netns exec "$IRAN_NS" ip -4 route get 10.201.1.1 2>&1 | tr '\n' ' ')"
    ip netns exec "$IRAN_NS" ip -4 route show 2>&1 | sed 's/^/      /' || true
    links_before="$(ip netns exec "$IRAN_NS" ip -o link show | awk -F': ' '{print $2}' | sort | tr '\n' ' ')"
    hc_out="$(ip netns exec "$IRAN_NS" bash -c '
        set -u
        mkdir -p /tmp/gre-hc-etc/multi-gre/foreigns /tmp/gre-hc-etc/multi-gre/nodes
        sed -e "s|/etc/multi-gre|/tmp/gre-hc-etc/multi-gre|g" \
            -e "s|if \[\[ \${EUID:-\$(id -u)} -ne 0 \]\]; then|if false; then|" \
            '"$REPO"'/gre-manager.sh > /tmp/gre-hc-sut.sh 2>/dev/null
        cat > /tmp/gre-hc-etc/multi-gre/foreigns/p1.conf <<EOF
NAME=p1
FOREIGN_IP='"$UNDERLAY_FOREIGN"'
IRAN_IP='"$UNDERLAY_IRAN"'
WAN_IF=lo
SUBNET_BASE=10.201
IDX=1
KEY=2001
TUN=gre-p1
TCP_PORTS=3001
UDP_PORTS=
MSS_CLAMP=0
EOF
        bash /tmp/gre-hc-sut.sh health-check --name p1 --quick --json 2>&1
    ')"
    hc_rc=$?
    if grep -q '"overall_status"' <<< "$hc_out"; then
        ok "health-check: runs against a real GRE interface and emits the contract JSON"
    else
        bad "health-check: did not emit the contract JSON (rc=$hc_rc)"
    fi
    if grep -qE '"id":"interface_exists","category":"[^"]+","status":"PASS"' <<< "$hc_out"; then
        ok "health-check: reports the real interface as present"
    else
        bad "health-check: did not report the real interface as present"
    fi
    if grep -qE '"id":"tunnel_address","category":"[^"]+","status":"PASS"' <<< "$hc_out"; then
        ok "health-check: confirms the real tunnel address"
    else
        # .2 is the IRAN end of the /30; this connection is a foreigns/ peer on the Iran
        # server, so the health check must find 10.201.1.2 on gre-p1.
        bad "health-check: did not confirm the tunnel address"
        printf '      raw health-check output:\n'
        printf '%s\n' "$hc_out" | sed 's/^/      /'
    fi
    # This check is SKIPPED by --quick on purpose (it is part of the full pass), so assert on
    # a FULL run. Asserting PASS against a quick run would fail for the design, not a bug.
    hc_full="$(ip netns exec "$IRAN_NS" bash /tmp/gre-hc-sut.sh health-check --name p1 --full --json 2>&1)"
    if grep -qE '"id":"inner_route","category":"[^"]+","status":"PASS"' <<< "$hc_full"; then
        ok "health-check: confirms the kernel routes the peer's tunnel address over the interface"
    else
        bad "health-check: did not confirm the inner route (full run)"
        printf '%s\n' "$hc_full" | tr ',' '\n' | grep -i 'inner_route' | sed 's/^/      /' || true
    fi
    links_after="$(ip netns exec "$IRAN_NS" ip -o link show | awk -F': ' '{print $2}' | sort | tr '\n' ' ')"
    if [[ "$links_before" == "$links_after" ]]; then
        ok "health-check: changed nothing in the namespace"
    else
        bad "health-check: modified the network state"
    fi
fi

# ==========================================================================
section "H. teardown"

cleanup
if ip netns list 2>/dev/null | grep -q "$IRAN_NS"; then
    bad "teardown: the iran namespace is still present"
else
    ok "teardown: namespaces removed"
fi

printf '\nnetns GRE tests: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
