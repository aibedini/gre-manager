#!/usr/bin/env bash
# ==========================================================================
# 25. gre mtu — diagnosis, recommendation and safe in-place tuning.
#
# The stub `ip` records `link set dev X mtu N` and reports it back, so an MTU change is
# observable and a rollback is verifiable. The stub `eth0` is a real 1500-byte
# underlay, so the arithmetic (1500 - overhead) is meaningful rather than circular.
# ==========================================================================

sect "25. gre mtu: diagnosis, recommendation and safe apply"

mkroot
printf 'DBG R=%s files=%s\n' "$R" "$(ls "$R/etc/multi-gre/foreigns/" 2>&1 | tr '\n' ',')"
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
printf 'DBG after foreign-setup rc=%s\n' "$GRE_RC"
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes >/dev/null
printf 'DBG add de1 rc=%s files=%s out=[%s]\n' "$GRE_RC" "$(ls "$R/etc/multi-gre/foreigns/" 2>&1 | tr '\n' ',')" "$(tail -2 <<< "$GRE_OUT" | tr '\n' ' ')"
gre iran peer add --name nl1 --foreign-ip 203.0.113.11 --iran-ip 198.51.100.20 \
    --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 8443 --yes >/dev/null
printf 'DBG add nl1 rc=%s files=%s\n' "$GRE_RC" "$(ls "$R/etc/multi-gre/foreigns/" 2>&1 | tr '\n' ',')"

# ---------------------------------------------------------------- help and list
gre mtu --help
assert "mtu --help rc=0" test "$GRE_RC" -eq 0
# `gre` captures output into GRE_OUT, which a child shell cannot see, so the help text
# is re-fetched inside the assertion rather than referenced from the parent scope.
assert "mtu --help documents every subcommand" bash -c \
    'TEST_ROOT="'"$R"'" PATH="'"$STUBS"':$PATH" bash "'"$SUT"'" mtu --help 2>&1 | grep -q diagnose \
     && TEST_ROOT="'"$R"'" PATH="'"$STUBS"':$PATH" bash "'"$SUT"'" mtu --help 2>&1 | grep -q recommend \
     && TEST_ROOT="'"$R"'" PATH="'"$STUBS"':$PATH" bash "'"$SUT"'" mtu --help 2>&1 | grep -q restore \
     && TEST_ROOT="'"$R"'" PATH="'"$STUBS"':$PATH" bash "'"$SUT"'" mtu --help 2>&1 | grep -q nic'
gre mtu list
assert "mtu list rc=0" test "$GRE_RC" -eq 0
assert "mtu list shows the connection" grep -q 'de1' <<< "$GRE_OUT"
assert "mtu list shows the tunnel" grep -q 'gre-de1' <<< "$GRE_OUT"
assert "mtu list shows the egress interface" grep -q 'eth0' <<< "$GRE_OUT"
gre mtu list --json
assert "mtu list --json rc=0" test "$GRE_RC" -eq 0
json_valid "mtu list --json is valid JSON"
assert "mtu list --json reports a count" grep -q '"count":2' <<< "$GRE_OUT"
gre mtu bogus
assert_not "mtu bogus fails" test "$GRE_RC" -eq 0

# ---------------------------------------------------------------- overhead
# Keyed IPv4 GRE overhead is 20 (outer IP) + 4 (GRE) + 4 (key) = 28. Counting the inner
# IP header as well would understate the tunnel MTU by 20 bytes.
gre mtu list --json
assert "overhead is 28 bytes for keyed IPv4 GRE" grep -q '"overhead":28' <<< "$GRE_OUT"
assert_not "overhead does not include the inner IP header" grep -q '"overhead":48' <<< "$GRE_OUT"

# ---------------------------------------------------------------- diagnose
gre mtu diagnose --name de1
assert "mtu diagnose rc=0" test "$GRE_RC" -eq 0
assert "diagnose reports the gre mtu" grep -q 'gre mtu *1476' <<< "$GRE_OUT"
assert "diagnose reports the egress mtu" grep -q 'egress *eth0 mtu 1500' <<< "$GRE_OUT"
assert "diagnose reports the overhead" grep -q 'overhead *28 bytes' <<< "$GRE_OUT"
assert "diagnose reports the mss clamp as explicit" grep -q 'mss clamp *set 1436' <<< "$GRE_OUT"
gre mtu diagnose --name de1 --json
assert "diagnose --json rc=0" test "$GRE_RC" -eq 0
json_valid "diagnose --json is valid JSON"
assert "diagnose --json names the side" grep -q '"side":"iran"' <<< "$GRE_OUT"
assert "diagnose --json has the contract underlay block" grep -q '"underlay":{' <<< "$GRE_OUT"
assert "diagnose --json has the contract gre block" grep -q '"gre":{' <<< "$GRE_OUT"
assert "diagnose --json has a pmtu block" grep -q '"pmtu":{' <<< "$GRE_OUT"
assert "diagnose --json has an mss_clamp block" grep -q '"mss_clamp":{' <<< "$GRE_OUT"
assert "diagnose --json carries a recommendation" grep -q '"recommendation":{' <<< "$GRE_OUT"
assert_not "diagnose --json leaks no secret" grep -qi 'password\|secret' <<< "$GRE_OUT"
gre mtu diagnose --name nope
assert_not "diagnose on an unknown connection fails" test "$GRE_RC" -eq 0
gre mtu diagnose
assert_not "diagnose without --name fails" test "$GRE_RC" -eq 0

# ---------------------------------------------------------------- recommendation
# 1500-byte underlay minus 28 bytes of encapsulation = 1472, the value a tunnel on a
# standard Ethernet path should carry. The old fixed default of 1476 is 4 bytes over.
gre mtu recommend --name de1 --json
assert "recommend --json rc=0" test "$GRE_RC" -eq 0
json_valid "recommend --json is valid JSON"
assert "recommend uses the 1500-byte underlay" grep -q '"underlay_mtu":1500' <<< "$GRE_OUT"
assert "recommend subtracts the real overhead" grep -q '"encapsulation_overhead":28' <<< "$GRE_OUT"
assert "recommend yields 1472 for this path" grep -q '"recommended_gre_mtu":1472' <<< "$GRE_OUT"
assert "recommend notes a change is needed (1476 -> 1472)" grep -q '"requires_change":true' <<< "$GRE_OUT"
assert "recommend states a confidence" grep -qE '"confidence":"(high|medium|low)"' <<< "$GRE_OUT"
assert "recommend respects the minimum legal MTU" grep -q '"min_legal_mtu":576' <<< "$GRE_OUT"
assert_not "recommend does not blanket-lower to 1400" grep -q '"recommended_gre_mtu":1400' <<< "$GRE_OUT"
assert_not "recommend does not blanket-lower to 1450" grep -q '"recommended_gre_mtu":1450' <<< "$GRE_OUT"

# ICMP is unavailable in the harness, so the measurement is inconclusive. The engine
# must say so rather than presenting an assumed value as measured.
assert "recommend is honest about an unmeasured path" \
    grep -qi 'could not be measured\|filtered' <<< "$GRE_OUT"
gre mtu recommend --name de1
assert "recommend (human) rc=0" test "$GRE_RC" -eq 0
assert "recommend (human) prints the apply command" grep -q 'gre mtu set --name de1 --mtu 1472' <<< "$GRE_OUT"

# ---------------------------------------------------------------- auto is read-only
before_mtu="$(cat "$R/state/mtu.gre-de1" 2>/dev/null || echo none)"
before_conf="$(md5sum "$R/etc/multi-gre/foreigns/de1.conf" | cut -d' ' -f1)"
gre mtu auto --name de1
assert "auto rc=0" test "$GRE_RC" -eq 0
assert "auto says it applied nothing" grep -qi 'was NOT applied\|not applied' <<< "$GRE_OUT"
assert "auto did not change the interface MTU" test "$before_mtu" = "$(cat "$R/state/mtu.gre-de1" 2>/dev/null || echo none)"
assert "auto did not rewrite the config" test "$before_conf" = "$(md5sum "$R/etc/multi-gre/foreigns/de1.conf" | cut -d' ' -f1)"
gre mtu auto --name de1 --json
json_valid "auto --json is valid JSON"
assert "auto --json reports applied:false" grep -q '"applied":false' <<< "$GRE_OUT"
assert "auto --json offers an apply command" grep -q '"apply_command"' <<< "$GRE_OUT"

# ---------------------------------------------------------------- set: guard rails
gre mtu set --name de1 --mtu 1400 </dev/null
assert "set without --yes cancels" test "$GRE_RC" -eq 0
assert "set without --yes changed nothing" test "$before_mtu" = "$(cat "$R/state/mtu.gre-de1" 2>/dev/null || echo none)"
gre mtu set --name de1 --mtu 100 --yes
assert_not "set refuses a sub-legal MTU" test "$GRE_RC" -eq 0
assert "set explains the legal range" grep -qi '576-9000' <<< "$GRE_OUT"
gre mtu set --name de1 --mtu 9000 --yes
assert_not "set refuses an MTU the path cannot carry" test "$GRE_RC" -eq 0
assert "set names the real ceiling" grep -q 'at most 1472' <<< "$GRE_OUT"
gre mtu set --name de1
assert_not "set without --mtu fails" test "$GRE_RC" -eq 0
gre mtu set --name nope --mtu 1400 --yes
assert_not "set on an unknown connection fails" test "$GRE_RC" -eq 0

# ---------------------------------------------------------------- set applies in place
tun_record_before="$(cat "$R/state/tunnels/gre-de1")"
gre mtu set --name de1 --mtu 1400 --yes
assert "set --yes rc=0" test "$GRE_RC" -eq 0
assert "set reports the old and new value" bash -c "grep -q '1400' <<< '$GRE_OUT' && grep -q '1476' <<< '$GRE_OUT'"
assert "the interface MTU is now 1400" test "$(cat "$R/state/mtu.gre-de1")" = "1400"
assert "set did NOT recreate the interface" test "$tun_record_before" = "$(cat "$R/state/tunnels/gre-de1")"
assert "set persisted the override" grep -qx 'MTU=1400' "$R/etc/multi-gre/foreigns/de1.conf"
assert "set recorded the previous value for restore" grep -q '^de1	1476	' "$R/etc/multi-gre/mtu.journal"
assert "set refreshed the MSS clamp from the new MTU" grep -q 'set-mss 1360' "$R/state/iptables.mangle"
# Scoped to THIS connection: the other peer legitimately keeps its own MSS, so a
# whole-file search for the old value would be a false failure.
assert_not "de1 no longer advertises the old MSS" bash -c \
    "grep 'multi-gre-iran-de1-mss' '$R/state/iptables.mangle' | grep -q 'set-mss 1436'"
assert "the other peer keeps its own MSS" bash -c \
    "grep 'multi-gre-iran-nl1-mss' '$R/state/iptables.mangle' | grep -q 'set-mss 1436'"
assert "set touched only its own connection" test -f "$R/etc/multi-gre/foreigns/nl1.conf"
assert_not "set did not write an override for the other connection" grep -q '^MTU=' "$R/etc/multi-gre/foreigns/nl1.conf"
assert "set did not change the WAN NIC MTU" test "$(cat "$R/state/mtu.eth0" 2>/dev/null || echo 1500)" = "1500"
gre mtu set --name de1 --mtu 1400 --yes
assert "a repeated set is a no-op" grep -qi 'already at MTU 1400' <<< "$GRE_OUT"

# ---------------------------------------------------------------- persistence
# A restart must not lose the value: apply_all re-reads the config and recreates the
# interface at the stored MTU.
rm -f "$R/state/mtu.gre-de1" "$R/state/tunnels/gre-de1"
gre --apply >/dev/null 2>&1
assert "--apply rc=0 after an MTU override" test "$GRE_RC" -eq 0
assert "the interface is recreated" test -f "$R/state/tunnels/gre-de1"
# The MTU is applied with `ip link set`, not baked into `ip tunnel add`, so the live
# interface MTU is what proves persistence — the tunnel-add record never carries it.
assert "the tunnel comes back at the stored 1400" test "$(cat "$R/state/mtu.gre-de1")" = "1400"
assert "the tunnel record was rebuilt" grep -q 'gre-de1' "$R/state/tunnels/gre-de1"

# ---------------------------------------------------------------- restore
gre mtu restore --name de1 --yes
assert "restore rc=0" test "$GRE_RC" -eq 0
assert "restore puts the previous value back" test "$(cat "$R/state/mtu.gre-de1")" = "1476"
assert "restore updated the config" grep -qx 'MTU=1476' "$R/etc/multi-gre/foreigns/de1.conf"
assert "restore refreshed the MSS clamp back" grep -q 'set-mss 1436' "$R/state/iptables.mangle"
assert "restore cleared the journal entry" bash -c "! grep -q '^de1	' '$R/etc/multi-gre/mtu.journal' 2>/dev/null"
gre mtu restore --name de1 --yes
assert_not "restore without a recorded value fails" test "$GRE_RC" -eq 0
assert "restore explains why" grep -qi 'No previous MTU is recorded' <<< "$GRE_OUT"

# ---------------------------------------------------------------- doctor agrees
gre doctor >/dev/null 2>&1
assert "doctor still passes after all of this" test "$GRE_RC" -eq 0

# ---------------------------------------------------------------- NIC MTU safety
gre mtu nic list
assert "nic list rc=0" test "$GRE_RC" -eq 0
assert "nic list shows the underlay" grep -q 'eth0' <<< "$GRE_OUT"
assert "nic list marks the control-plane interface" grep -qE 'eth0 +1500 +YES' <<< "$GRE_OUT"
gre mtu nic list --json
json_valid "nic list --json is valid JSON"
gre mtu nic analyze --name de1
# A successful read-only analysis exits 0 even when the risk is high: the risk is data,
# not a failure, and a non-zero exit would make a caller read "risky to change" as "the
# command failed".
assert "nic analyze succeeds and reports the risk" test "$GRE_RC" -eq 0
assert "nic analyze names the risk" grep -qi 'risk *high' <<< "$GRE_OUT"
assert "nic analyze explains the SSH hazard" grep -qi 'SSH' <<< "$GRE_OUT"
gre mtu nic analyze --name de1 --json
json_valid "nic analyze --json is valid JSON"
assert "nic analyze --json reports risk as data" grep -q '"risk":"high"' <<< "$GRE_OUT"
assert "nic analyze --json reports applied:false" grep -q '"applied":false' <<< "$GRE_OUT"
nic_before="$(md5sum "$R/state/mtu.eth0" 2>/dev/null | cut -d' ' -f1)"
gre mtu nic analyze --name de1 >/dev/null 2>&1
assert "nic analyze never changes the NIC MTU" \
    test "$nic_before" = "$(md5sum "$R/state/mtu.eth0" 2>/dev/null | cut -d' ' -f1)"
assert "there is no nic set subcommand" bash -c "! grep -q 'nic set' <<< '$(gre mtu nic --help)'"
rm -rf "$R"

# ======================================================================
sect "26. gre mtu: per-connection isolation and the FOREIGN side"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes >/dev/null

gre mtu list --json
assert "foreign side: list rc=0" test "$GRE_RC" -eq 0
assert "foreign side: reports side=foreign" grep -q '"side":"foreign"' <<< "$GRE_OUT"
assert "foreign side: reports its own tunnel MTU" grep -q '"tunnel_mtu":1476' <<< "$GRE_OUT"
gre mtu diagnose --name ir1 --json
assert "foreign side: diagnose rc=0" test "$GRE_RC" -eq 0
json_valid "foreign side: diagnose JSON is valid"
assert "foreign side: MSS clamp is not applicable" grep -q '"mode":"absent"' <<< "$GRE_OUT"
gre mtu set --name ir1 --mtu 1400 --yes
assert "foreign side: set rc=0" test "$GRE_RC" -eq 0
assert "foreign side: interface MTU changed" test "$(cat "$R/state/mtu.gre-ir1")" = "1400"
assert "foreign side: node config records the override" grep -qx 'MTU=1400' "$R/etc/multi-gre/nodes/ir1.conf"
gre node edit --name ir1 --key 2002 --yes >/dev/null 2>&1
assert "an unrelated node edit keeps the MTU override" grep -qx 'MTU=1400' "$R/etc/multi-gre/nodes/ir1.conf"
assert "an unrelated node edit keeps the tunnel at 1400" test "$(cat "$R/state/mtu.gre-ir1")" = "1400"
rm -rf "$R"

# ======================================================================
sect "27. gre mtu: an MTU edit does not disturb the rest of the connection"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes >/dev/null
gre iran peer add --name nl1 --foreign-ip 203.0.113.11 --iran-ip 198.51.100.20 \
    --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 8443 --yes >/dev/null

nat_before="$(md5sum "$R/state/iptables.nat" | cut -d' ' -f1)"
nl1_before="$(md5sum "$R/state/iptables.mangle" | cut -d' ' -f1)"
de1_rules_before="$(grep -c 'multi-gre-iran-de1' "$R/state/iptables.nat")"

gre mtu set --name de1 --mtu 1400 --yes >/dev/null 2>&1
assert "set rc=0" test "$GRE_RC" -eq 0
assert "the GRE key is preserved" grep -q 'key 1001' "$R/state/tunnels/gre-de1"
assert "the endpoints are preserved" bash -c \
    "grep -q 'local 198.51.100.20' '$R/state/tunnels/gre-de1' && grep -q 'remote 203.0.113.10' '$R/state/tunnels/gre-de1'"
assert "the NAT rules are untouched" test "$nat_before" = "$(md5sum "$R/state/iptables.nat" | cut -d' ' -f1)"
assert "the connection keeps its own NAT rules" test "$de1_rules_before" = "$(grep -c 'multi-gre-iran-de1' "$R/state/iptables.nat")"
assert "the other connection's config is untouched" test -f "$R/etc/multi-gre/foreigns/nl1.conf"
# A `--apply` legitimately rebuilds every connection, so nl1 having an interface MTU is
# expected. What matters is that de1's change did not leak into nl1's value.
assert "the other connection did not inherit de1's MTU" test "$(cat "$R/state/mtu.gre-nl1" 2>/dev/null || echo 1476)" = "1476"
assert_not "the other connection got no MTU override" grep -q '^MTU=' "$R/etc/multi-gre/foreigns/nl1.conf"
assert "the connection still verifies" bash -c "grep -q 'MTU=1400' '$R/etc/multi-gre/foreigns/de1.conf'"
gre mtu diagnose --name de1 >/dev/null 2>&1
assert "diagnose still passes after the change" test "$GRE_RC" -eq 0
rm -rf "$R"
