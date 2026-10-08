# ======================================================================
# Connection editing tests (sourced from run.sh, which provides the harness:
# gre(), assert(), sect(), mkroot(), nat_has(), tun_there(), json_valid()).
#
# The properties that matter, and that a blind remove+add would fail:
#   * a port-only change never rebuilds the tunnel
#   * other connections are untouched, in config and in iptables
#   * a failure restores the previous connection
#   * the connection keeps its identity across a rename and an endpoint change
#   * the list shows BOTH endpoints, wide and narrow
#   * bad input is refused before anything is mutated
#   * the pre-existing commands still behave exactly as before
# ======================================================================

# Local fixtures: unlike the older add_de1/add_nl1 helpers these always pass
# --iran-ip, so they do not depend on public-IP detection inside the test root.
edit_add_de1() { gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
                  --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes; }
edit_add_nl1() { gre iran peer add --name nl1 --foreign-ip 203.0.113.11 --iran-ip 198.51.100.20 \
                  --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 8443 --yes; }

sect "19. transactional connection editing (edit in place)"
mkroot
edit_add_de1; edit_add_nl1
assert "two peers configured" test "$(ls "$R/etc/multi-gre/foreigns"/*.conf 2>/dev/null | wc -l | tr -d " ")" = "2"

# ---------------------------------------------------------------- class A
de1_tun_before="$(ls "$R/state/tunnels" | sort | tr '\n' ' ')"
nl1_tcp_before="$(grep -E '^TCP_PORTS=' "$R/etc/multi-gre/foreigns/nl1.conf")"

gre iran peer edit --name de1 --tcp-ports 3049 --udp-ports 3049 --yes
assert "edit ports: rc=0" test "$GRE_RC" -eq 0
assert "edit ports: tcp config updated" grep -q '^TCP_PORTS=3049' "$R/etc/multi-gre/foreigns/de1.conf"
assert "edit ports: udp config updated" grep -q '^UDP_PORTS=3049' "$R/etc/multi-gre/foreigns/de1.conf"
assert "edit ports: new TCP rule installed" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 3049 -m comment --comment multi-gre-iran-de1-dnat-tcp -j DNAT --to-destination 10.200.1.1"
assert "edit ports: old TCP rule removed" bash -c "! grep -q 'dports 80,443' '$R/state/iptables.nat'"
assert "edit ports: SNAT rule still present" nat_has "POSTROUTING -o gre-de1 -d 10.200.1.1 -m comment --comment multi-gre-iran-de1-snat -j SNAT --to-source 10.200.1.2"
# A rule-only change must NOT rebuild the tunnel.
assert "edit ports: tunnel still present" test -f "$R/state/tunnels/gre-de1"
assert "edit ports: tunnel set unchanged" test "$(ls "$R/state/tunnels" | sort | tr '\n' ' ')" = "$de1_tun_before"
assert "edit ports: other peer config untouched" test "$(grep -E '^TCP_PORTS=' "$R/etc/multi-gre/foreigns/nl1.conf")" = "$nl1_tcp_before"
assert "edit ports: other peer rule untouched" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 8443 -m comment --comment multi-gre-iran-nl1-dnat-tcp -j DNAT --to-destination 10.201.1.1"

# ---------------------------------------------------------------- MSS
gre iran peer edit --name de1 --mss-clamp off --yes
assert "edit mss off: rc=0" test "$GRE_RC" -eq 0
assert "edit mss off: config updated" grep -q '^MSS_CLAMP=0' "$R/etc/multi-gre/foreigns/de1.conf"
assert "edit mss off: mangle rule removed" bash -c "! grep -q 'multi-gre-iran-de1-mss' '$R/state/iptables.mangle'"
gre iran peer edit --name de1 --mss-clamp on --yes
assert "edit mss on: mangle rule restored" grep -q 'multi-gre-iran-de1-mss' "$R/state/iptables.mangle"

# ---------------------------------------------------------------- class B
gre iran peer edit --name de1 --key 4321 --yes
assert "edit key: rc=0" test "$GRE_RC" -eq 0
assert "edit key: config updated" grep -q '^KEY=4321' "$R/etc/multi-gre/foreigns/de1.conf"
assert "edit key: tunnel carries the new key" grep -q '4321' "$R/state/tunnels/gre-de1"
assert "edit key: rules reinstalled" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 3049 -m comment --comment multi-gre-iran-de1-dnat-tcp -j DNAT --to-destination 10.200.1.1"
assert "key change prints the FOREIGN command" grep -q 'gre node edit' <<< "$GRE_OUT"

# ---------------------------------------------------------------- rename
gre iran peer edit --name de1 --new-name Germany01 --yes
assert "rename: rc=0" test "$GRE_RC" -eq 0
assert "rename: new config exists" test -f "$R/etc/multi-gre/foreigns/Germany01.conf"
assert "rename: old config gone" bash -c "! test -f '$R/etc/multi-gre/foreigns/de1.conf'"
assert "rename: tunnel renamed" test -f "$R/state/tunnels/gre-Germany01"
assert "rename: old tunnel gone" bash -c "! test -f '$R/state/tunnels/gre-de1'"
assert "rename: rule comment follows the new name" grep -q 'multi-gre-iran-Germany01-dnat-tcp' "$R/state/iptables.nat"
assert "rename: no stale rule comment" bash -c "! grep -q 'multi-gre-iran-de1-' '$R/state/iptables.nat'"
assert "rename: other peer intact" test -f "$R/etc/multi-gre/foreigns/nl1.conf"
assert "rename: prints the FOREIGN command" grep -q 'gre node edit' <<< "$GRE_OUT"

# ---------------------------------------------------------------- identity
assert "identity map written" test -f "$R/etc/multi-gre/connections.identity"
assert "identity map has one entry" test "$(grep -c '^conn-' "$R/etc/multi-gre/connections.identity")" -eq 1
id_before="$(awk -F'\t' '{print $1}' "$R/etc/multi-gre/connections.identity" | head -n1)"
gre iran peer edit --name Germany01 --subnet-base 10.220 --idx 5 --key 5005 --yes
assert "endpoint change: rc=0" test "$GRE_RC" -eq 0
id_after="$(awk -F'\t' '{print $1}' "$R/etc/multi-gre/connections.identity" | head -n1)"
assert "identity survives an endpoint change" test "$id_before" = "$id_after"
assert "identity map still one entry" test "$(grep -c '^conn-' "$R/etc/multi-gre/connections.identity")" -eq 1

# ---------------------------------------------------------------- collisions
before_conf="$(cat "$R/etc/multi-gre/foreigns/Germany01.conf")"
before_nat="$(grep 'multi-gre-iran-Germany01' "$R/state/iptables.nat")"
gre iran peer edit --name Germany01 --tcp-ports 8443 --yes
assert_not "edit onto another peer's TCP port is refused" test "$GRE_RC" -eq 0
assert "collision: config unchanged" test "$(cat "$R/etc/multi-gre/foreigns/Germany01.conf")" = "$before_conf"
assert "collision: the peer's own rules unchanged" test "$(grep 'multi-gre-iran-Germany01' "$R/state/iptables.nat")" = "$before_nat"
# The connection's own current ports are not a collision with itself.
gre iran peer edit --name Germany01 --tcp-ports 3049 --yes
assert "own current port is not a self-collision" test "$GRE_RC" -eq 0

gre iran peer edit --name Germany01 --new-name nl1 --yes
assert_not "rename onto an existing name is refused" test "$GRE_RC" -eq 0
assert "rename collision: target untouched" grep -q '^NAME=nl1' "$R/etc/multi-gre/foreigns/nl1.conf"
assert "rename collision: source untouched" grep -q '^NAME=Germany01' "$R/etc/multi-gre/foreigns/Germany01.conf"

# ---------------------------------------------------------------- --plan
plan_conf="$(cat "$R/etc/multi-gre/foreigns/Germany01.conf")"
plan_nat="$(grep 'multi-gre-iran-Germany01' "$R/state/iptables.nat")"
gre iran peer edit --name Germany01 --tcp-ports 9999 --plan
assert "--plan rc=0" test "$GRE_RC" -eq 0
assert "--plan shows the diff" grep -q '3049 -> 9999' <<< "$GRE_OUT"
assert "--plan names the change class" grep -q 'Change class: A' <<< "$GRE_OUT"
assert "--plan changed no config" test "$(cat "$R/etc/multi-gre/foreigns/Germany01.conf")" = "$plan_conf"
assert "--plan changed no rule" test "$(grep 'multi-gre-iran-Germany01' "$R/state/iptables.nat")" = "$plan_nat"

# ---------------------------------------------------------------- validation
gre iran peer edit --name Germany01 --subnet-base "not-a-subnet" --yes
assert_not "invalid subnet base is refused" test "$GRE_RC" -eq 0
assert "invalid input left the config alone" test "$(cat "$R/etc/multi-gre/foreigns/Germany01.conf")" = "$plan_conf"
assert "invalid input left the rules alone" test "$(grep 'multi-gre-iran-Germany01' "$R/state/iptables.nat")" = "$plan_nat"

# ---------------------------------------------------------------- no-op
gre iran peer edit --name Germany01 --tcp-ports 3049 --yes
assert "identical values are a successful no-op" test "$GRE_RC" -eq 0
assert "no-op says so" grep -qi 'no changes' <<< "$GRE_OUT"

# ---------------------------------------------------------------- usage
gre iran peer edit; assert_not "edit without --name fails" test "$GRE_RC" -eq 0
gre iran peer edit --name nope --tcp-ports 1 --yes; assert_not "edit of a missing peer fails" test "$GRE_RC" -eq 0
gre iran peer edit --bogus x; assert_not "edit rejects unknown options" test "$GRE_RC" -eq 0
gre iran peer edit --help; assert "edit --help rc=0" test "$GRE_RC" -eq 0
gre iran peer --help; assert "iran peer --help mentions edit" grep -q 'edit' <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "20. connection list shows both endpoints (wide and narrow)"
mkroot
edit_add_de1
gre iran peer list
assert "list rc=0" test "$GRE_RC" -eq 0
assert "list shows the IRAN ip" grep -q '198.51.100.20' <<< "$GRE_OUT"
assert "list shows the FOREIGN ip" grep -q '203.0.113.10' <<< "$GRE_OUT"
assert "list shows the tunnel" grep -q 'gre-de1' <<< "$GRE_OUT"
assert "list shows the subnet" grep -q '10.200.1.0/30' <<< "$GRE_OUT"
assert "list shows the ports" grep -q '80,443' <<< "$GRE_OUT"
COLUMNS=60 gre iran peer list
assert "narrow list rc=0" test "$GRE_RC" -eq 0
assert "narrow list still shows the IRAN ip" grep -q '198.51.100.20' <<< "$GRE_OUT"
assert "narrow list still shows the FOREIGN ip" grep -q '203.0.113.10' <<< "$GRE_OUT"
assert "narrow list uses the compact form" grep -q '198.51.100.20 -> 203.0.113.10' <<< "$GRE_OUT"
gre iran peer list --json; assert "list --json rc=0" test "$GRE_RC" -eq 0
json_valid "list --json is still valid JSON"
rm -rf "$R"

# ======================================================================
sect "21. FOREIGN-side node edit"
mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre node add --name ir1 --ip 198.51.100.20 --idx 1 --key 1001 --yes
assert "node added" test "$GRE_RC" -eq 0
gre node edit --name ir1 --key 2002 --yes
assert "node edit key: rc=0" test "$GRE_RC" -eq 0
assert "node edit key: config updated" grep -q '^KEY=2002' "$R/etc/multi-gre/nodes/ir1.conf"
assert "node edit key: tunnel carries the new key" grep -q '2002' "$R/state/tunnels/gre-ir1"
gre node edit --name ir1 --new-name ir2 --yes
assert "node rename: rc=0" test "$GRE_RC" -eq 0
assert "node rename: new conf exists" test -f "$R/etc/multi-gre/nodes/ir2.conf"
assert "node rename: old conf gone" bash -c "! test -f '$R/etc/multi-gre/nodes/ir1.conf'"
assert "node rename: old tunnel gone" bash -c "! test -f '$R/state/tunnels/gre-ir1'"
assert "node edit prints the IRAN-side command" grep -q 'gre iran peer edit' <<< "$GRE_OUT"
gre node edit --name ir2 --plan; assert "node edit --plan rc=0" test "$GRE_RC" -eq 0
gre node list; assert "node list rc=0" test "$GRE_RC" -eq 0
assert "node list shows the IRAN ip" grep -q '198.51.100.20' <<< "$GRE_OUT"
gre node edit; assert_not "node edit without --name fails" test "$GRE_RC" -eq 0
gre node --help; assert "node --help mentions edit" grep -q 'edit' <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "22. edit is not a blind remove+add, and old commands still work"
mkroot
edit_add_de1; edit_add_nl1
cp "$R/state/tunnels/gre-de1" "$R/tunnel-record-before"
gre iran peer edit --name de1 --tcp-ports 7000 --yes
assert "rule-only edit leaves the tunnel record untouched" diff -q "$R/tunnel-record-before" "$R/state/tunnels/gre-de1"
rm -f "$R/tunnel-record-before"
gre iran peer add --name extra --foreign-ip 203.0.113.99 --iran-ip 198.51.100.20 --subnet-base 10.240 --idx 1 --key 1240 --tcp-ports 5555 --yes
assert "peer add still works" test "$GRE_RC" -eq 0
gre iran peer apply --name extra; assert "peer apply still works" test "$GRE_RC" -eq 0
gre iran peer remove --name extra --yes; assert "peer remove still works" test "$GRE_RC" -eq 0
assert "peer remove left the others alone" test "$(ls "$R/etc/multi-gre/foreigns"/*.conf 2>/dev/null | wc -l | tr -d " ")" = "2"
gre status >/dev/null; assert "gre status still works" test "$GRE_RC" -eq 0
gre doctor >/dev/null 2>&1
assert "gre doctor still runs (0 or 1, never a crash)" test "$GRE_RC" -le 1
rm -rf "$R"
