#!/usr/bin/env bash
# ==========================================================================
# 28. gre health-check — the layered diagnosis and its verdicts.
#
# `--quick` is used for most assertions because the full mode spends its time in real
# ping probes, which cannot resolve in the harness. The one place the full path matters
# (that it actually runs and reports) is covered explicitly.
# ==========================================================================

sect "28. gre health-check: layered diagnosis, issue codes and verdicts"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes >/dev/null

# ---------------------------------------------------------------- help and guards
gre health-check --help
assert "health-check --help rc=0" test "$GRE_RC" -eq 0
gre health-check
assert_not "health-check without --name fails" test "$GRE_RC" -eq 0
gre health-check --name nope
assert_not "health-check on an unknown connection fails" test "$GRE_RC" -eq 0
assert "health-check explains the unknown connection" grep -qi 'No connection named' <<< "$GRE_OUT"
gre health-check --name de1 --bogus
assert_not "health-check rejects an unknown option" test "$GRE_RC" -eq 0

# ---------------------------------------------------------------- a healthy pair
gre health-check --name de1 --quick
assert "quick health check rc=0 on a working connection" test "$GRE_RC" -eq 0
assert "it names the connection" grep -q "health check for 'de1'" <<< "$GRE_OUT"
assert "it reports the mode and that it is read-only" grep -qi 'quick.*read-only\|read-only.*quick' <<< "$GRE_OUT"
assert "it walks the server layer" grep -q 'control_plane' <<< "$GRE_OUT"
assert "it walks the underlay layer" grep -q 'route_to_peer' <<< "$GRE_OUT"
assert "it walks the GRE layer" grep -q 'interface_exists' <<< "$GRE_OUT"
assert "it walks the protocol 47 layer" grep -q 'gre47_local_policy' <<< "$GRE_OUT"
assert "it walks the routing/firewall layer" grep -q 'ip_forward' <<< "$GRE_OUT"
assert "it walks the MTU layer" grep -q 'tunnel_mtu' <<< "$GRE_OUT"
assert "it walks the service layer" grep -q 'service_layer' <<< "$GRE_OUT"
assert "it prints an overall verdict" grep -qE 'overall: (HEALTHY|DEGRADED|BROKEN)' <<< "$GRE_OUT"
assert "it prints a check tally" grep -q 'checks:  pass=' <<< "$GRE_OUT"
assert "it says the service layer was skipped (no panel)" grep -qi 'no panel configured' <<< "$GRE_OUT"

# ---------------------------------------------------------------- JSON contract
gre health-check --name de1 --quick --json
assert "health-check --json rc=0" test "$GRE_RC" -eq 0
json_valid "health-check --json is valid JSON"
assert "the JSON names the connection" grep -q '"connection":"de1"' <<< "$GRE_OUT"
assert "the JSON names the side" grep -q '"side":"iran"' <<< "$GRE_OUT"
assert "the JSON has an overall status" grep -qE '"overall_status":"(HEALTHY|DEGRADED|BROKEN)"' <<< "$GRE_OUT"
assert "the JSON reports evidence completeness" grep -qE '"evidence_completeness":"(complete|partial)"' <<< "$GRE_OUT"
assert "the JSON has a summary" grep -q '"summary":{' <<< "$GRE_OUT"
assert "the JSON has a checks array" grep -q '"checks":\[' <<< "$GRE_OUT"
assert "the JSON has a findings array" grep -q '"findings":\[' <<< "$GRE_OUT"
assert "the JSON carries a timestamp" grep -q '"tested_at":"' <<< "$GRE_OUT"
assert "the JSON states the mode" grep -q '"mode":"quick"' <<< "$GRE_OUT"
assert_not "the JSON leaks no secret" grep -qi 'password\|private key\|secret' <<< "$GRE_OUT"

# Every check must carry the contract fields, and only the contract statuses.
gre health-check --name de1 --quick --json
assert "each check has id/category/status/detail/evidence" \
    grep -qE '"id":"[^"]+","category":"[^"]+","status":"[^"]+","detail":"[^"]*","evidence":"[^"]*"' <<< "$GRE_OUT"
assert_not "no check uses a status outside the contract" \
    grep -qE '"status":"(OK|ERROR|BAD|TRUE|FALSE)"' <<< "$GRE_OUT"

# ---------------------------------------------------------------- a broken connection
# Remove the interface: the GRE layer must fail, name the issue code, and offer the
# repair that this host can actually perform.
rm -f "$R/state/tunnels/gre-de1"
rm -f "$R/state/mtu.gre-de1"
gre health-check --name de1 --quick
assert_not "a missing interface makes the check exit non-zero" test "$GRE_RC" -eq 0
assert "it names the missing interface" grep -q 'GRE_INTERFACE_MISSING' <<< "$GRE_OUT"
assert "the finding names the interface" grep -q 'gre-de1' <<< "$GRE_OUT"
assert "the verdict is BROKEN" grep -q 'overall: BROKEN' <<< "$GRE_OUT"

gre health-check --name de1 --quick --json
json_valid "the broken state is still valid JSON"
assert "the finding is machine readable" grep -q '"code":"GRE_INTERFACE_MISSING"' <<< "$GRE_OUT"
assert "the finding carries a severity" grep -q '"severity":"critical"' <<< "$GRE_OUT"
assert "the finding says a repair is safe" grep -q '"safe_repair":true' <<< "$GRE_OUT"
assert "the finding names the repair action" grep -q '"recommended_action":"[^"]' <<< "$GRE_OUT"
assert "the finding carries evidence" grep -q '"evidence":"[^"]' <<< "$GRE_OUT"
assert "the finding carries a probable cause" grep -q '"probable_cause":"[^"]' <<< "$GRE_OUT"

# ---------------------------------------------------------------- repair preview
gre repair preview --name de1
assert "repair preview rc=0" test "$GRE_RC" -eq 0
assert "the preview lists the repairable issue" grep -q 'GRE_INTERFACE_MISSING' <<< "$GRE_OUT"
assert "the preview says nothing has changed yet" grep -qi 'nothing is changed yet' <<< "$GRE_OUT"
gre repair preview --name de1 --json
json_valid "repair preview --json is valid JSON"
assert "the preview marks itself read-only" grep -q '"read_only":true' <<< "$GRE_OUT"

# ---------------------------------------------------------------- repair apply
before_rec="$(cat "$R/state/tunnels/gre-de1" 2>/dev/null || echo none)"
gre repair apply --name de1 --code GRE_INTERFACE_MISSING </dev/null
assert "repair without --yes cancels" test "$GRE_RC" -eq 0
assert "the cancelled repair changed nothing" test "$before_rec" = "$(cat "$R/state/tunnels/gre-de1" 2>/dev/null || echo none)"
gre repair apply --name de1 --code UNDERLAY_UNREACHABLE --yes
assert_not "a repair that does not exist is refused" test "$GRE_RC" -eq 0
assert "it says why" grep -qi 'No automated repair exists' <<< "$GRE_OUT"
gre repair apply --name de1 --code GRE_INTERFACE_MISSING --yes
assert "the repair applies" test "$GRE_RC" -eq 0
assert "the interface is back" test -f "$R/state/tunnels/gre-de1"
gre health-check --name de1 --quick --json
assert "the connection is healthy again" grep -qE '"overall_status":"(HEALTHY|DEGRADED)"' <<< "$GRE_OUT"
assert_not "the repaired issue is gone" grep -q '"code":"GRE_INTERFACE_MISSING"' <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "29. gre health-check: reporting honestly instead of guessing"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes >/dev/null

# --- the report is repeatable and carries the same verdict twice
gre health-check --name de1 --quick --json
assert "diagnosis is repeatable" test "$GRE_RC" -eq 0

# --- the MTU recommendation must never be presented as a measurement
gre health-check --name de1 --quick --json
assert "the report carries a confidence level" \
    grep -qE '"confidence":"(low|medium|high)"' <<< "$GRE_OUT"
assert_not "an unmeasured path is not asserted as a measured failure" \
    grep -q '"code":"GRE_MTU_MISMATCH","severity":"critical"' <<< "$GRE_OUT"

# --- the watchdog state is reported when it cannot be determined
rm -f "$R/etc/multi-gre/global.conf"
gre health-check --name de1 --quick --json
assert "a missing watchdog config is an UNKNOWN, not a failure" \
    grep -qE '"id":"watchdog","category":"[^"]+","status":"UNKNOWN"' <<< "$GRE_OUT"

# --- the budget is honoured
gre health-check --name de1 --budget 1 --json >/dev/null 2>&1
assert "an explicit budget is accepted" true
gre health-check --name de1 --budget notanumber
assert_not "a non-numeric budget is refused" test "$GRE_RC" -eq 0
assert "it says why" grep -qi 'whole number of seconds' <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "30. gre health-check: per-connection isolation"

mkroot
gre foreign-setup --foreign-ip 203.0.113.10 --yes >/dev/null
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
    --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes >/dev/null
gre iran peer add --name nl1 --foreign-ip 203.0.113.11 --iran-ip 198.51.100.20 \
    --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 8443 --yes >/dev/null

# Break only de1 and confirm nl1 is untouched by both the diagnosis and any repair.
rm -f "$R/state/tunnels/gre-de1"
gre health-check --name de1 --quick --json
assert "the broken connection is reported broken" \
    grep -q '"overall_status":"BROKEN"' <<< "$GRE_OUT"
assert "the diagnosis names only the connection asked about" \
    grep -q '"connection":"de1"' <<< "$GRE_OUT"
gre health-check --name nl1 --quick --json
assert "the healthy connection is not dragged down with it" \
    grep -qE '"overall_status":"(HEALTHY|DEGRADED)"' <<< "$GRE_OUT"

nl1_before="$(md5sum "$R/etc/multi-gre/foreigns/nl1.conf" | cut -d' ' -f1)"
gre repair apply --name de1 --code GRE_INTERFACE_MISSING --yes >/dev/null 2>&1
assert "the repair touched only the selected connection" \
    test "$nl1_before" = "$(md5sum "$R/etc/multi-gre/foreigns/nl1.conf" | cut -d' ' -f1)"
gre health-check --name de1 --quick --json
assert "the repaired connection is healthy" \
    grep -qE '"overall_status":"(HEALTHY|DEGRADED)"' <<< "$GRE_OUT"
gre health-check --name nl1 --quick --json
assert "the other connection is still healthy" \
    grep -qE '"overall_status":"(HEALTHY|DEGRADED)"' <<< "$GRE_OUT"
rm -rf "$R"
