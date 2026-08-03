#!/usr/bin/env bash
# gre-manager test suite — runs on Linux and in Git Bash (Windows).
#
# Strategy: gre-manager.sh is copied to a temp "script under test" (SUT) with
# every absolute system path (/etc/multi-gre, systemd units, /usr/local/sbin,
# the audit log, the sysctl file) sed-redirected into a per-test temp root.
# Fake `ip`, `iptables`, `systemctl`, `ping`, `ss`, `sysctl` and `logger`
# binaries (tests/stubs/) are put first on PATH and keep their state under
# $TEST_ROOT/state, so the real system is never touched. require_root is
# neutralized. Each assertion prints ok/FAIL; exit code is non-zero on any
# failure.
#
# JSON assertions use python/python3 when available; otherwise a grep-based
# structural check is used instead (marked "(structural)").
set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
STUBS="$TESTS_DIR/stubs"

WORK="$(mktemp -d)"
SUT="$WORK/gre-under-test.sh"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
sect() { printf '\n=== %s ===\n' "$1"; }

# assert <desc> <cmd...>   — expects exit 0
assert()    { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
assert_not(){ local d="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

# ------------------------------------------------------------------ JSON
PY=""
if command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
  PY="python"
elif command -v python3 >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
  PY="python3"
fi

# json_valid <desc> — GRE_OUT must be parseable JSON
json_valid() {
  if [[ -n "$PY" ]]; then
    if printf '%s' "$GRE_OUT" | "$PY" -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
      ok "$1"; else bad "$1"; fi
  else
    if printf '%s' "$GRE_OUT" | grep -qE '^\{' && printf '%s' "$GRE_OUT" | grep -q '"schema_version"'; then
      ok "$1 (structural)"; else bad "$1 (structural)"; fi
  fi
}

# json_check <desc> <python expr on d> <fallback extended-regex>
json_check() {
  local d="$1" expr="$2" rx="$3"
  if [[ -n "$PY" ]]; then
    if printf '%s' "$GRE_OUT" | "$PY" -c "import json,sys; d=json.load(sys.stdin); $expr" >/dev/null 2>&1; then
      ok "$d"; else bad "$d"; fi
  else
    if printf '%s' "$GRE_OUT" | grep -qE "$rx"; then
      ok "$d (structural)"; else bad "$d (structural)"; fi
  fi
}

# ---------------------------------------------------------------- build SUT
build_sut() {
  sed -e 's|^CONF_DIR="/etc/multi-gre"|CONF_DIR="${TEST_ROOT}/etc/multi-gre"|' \
      -e 's|^SYSCTL_FILE="/etc/sysctl.d/99-multi-gre.conf"|SYSCTL_FILE="${TEST_ROOT}/etc/sysctl.d/99-multi-gre.conf"|' \
      -e 's|^SERVICE_FILE="/etc/systemd/system/multi-gre.service"|SERVICE_FILE="${TEST_ROOT}/etc/systemd/system/multi-gre.service"|' \
      -e 's|^WATCHDOG_SERVICE_FILE="/etc/systemd/system/multi-gre-watchdog.service"|WATCHDOG_SERVICE_FILE="${TEST_ROOT}/etc/systemd/system/multi-gre-watchdog.service"|' \
      -e 's|^WATCHDOG_TIMER_FILE="/etc/systemd/system/multi-gre-watchdog.timer"|WATCHDOG_TIMER_FILE="${TEST_ROOT}/etc/systemd/system/multi-gre-watchdog.timer"|' \
      -e 's|^INSTALL_PATH="/usr/local/sbin/gre"|INSTALL_PATH="${TEST_ROOT}/usr/local/sbin/gre"|' \
      -e 's|^AUDIT_LOG="/var/log/gre-manager.log"|AUDIT_LOG="${TEST_ROOT}/var/log/gre-manager.log"|' \
      -e 's|if \[\[ ${EUID:-$(id -u)} -ne 0 \]\]; then|if false; then|' \
      -e 's|tar -czf "$path" -C / etc/multi-gre|tar -czf "$path" -C "${TEST_ROOT:-/}" etc/multi-gre|' \
      "$REPO_ROOT/gre-manager.sh" > "$SUT"
}

R=""           # current test root
GRE_OUT=""; GRE_RC=0
mkroot() {
  R="$(mktemp -d -p "$WORK")"
  mkdir -p "$R/var/log" "$R/usr/local/sbin" "$R/etc/systemd/system" "$R/etc/sysctl.d" "$R/state/tunnels"
}

# run the script under test; captures GRE_OUT/GRE_RC, auto-fails on unbound vars
gre() {
  GRE_OUT="$(TEST_ROOT="$R" PATH="$STUBS:$PATH" bash "$SUT" "$@" 2>&1)"
  GRE_RC=$?
  if grep -q "unbound variable" <<< "$GRE_OUT"; then
    bad "unbound variable in: gre $*"
    printf '%s\n' "$GRE_OUT" | grep "unbound variable" | head -3
  fi
  return "$GRE_RC"
}

nat_has()   { grep -qxF "$1" "$R/state/iptables.nat" 2>/dev/null; }
tun_there() { [[ -f "$R/state/tunnels/$1" ]]; }

v1_fixture() { # write a legacy v1 iran.conf into the current root
  mkdir -p "$R/etc/multi-gre"
  cat > "$R/etc/multi-gre/iran.conf" <<'EOF'
NAME=de1
FOREIGN_IP=203.0.113.10
IRAN_IP=198.51.100.20
WAN_IF=eth0
IDX=1
KEY=1001
TUN=gre-de1
TCP_PORTS=80,443
UDP_PORTS=443
MSS_CLAMP=1
EOF
  chmod 600 "$R/etc/multi-gre/iran.conf"
}

add_de1() { gre iran peer add --name de1 --foreign-ip 203.0.113.10 --iran-ip 198.51.100.20 \
              --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes; }
add_nl1() { gre iran peer add --name nl1 --foreign-ip 203.0.113.11 \
              --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 8443 --yes; }
add_uk1() { gre iran peer add --name uk1 --foreign-ip 203.0.113.12 \
              --idx 1 --key 1001 --tcp-ports 2053 --udp-ports 2053 --yes; }

build_sut || { echo "failed to build SUT"; exit 1; }

# ======================================================================
sect "1. fresh server: full CLI sweep, no unbound variables"
mkroot
gre --help;        assert "--help rc=0"        test "$GRE_RC" -eq 0
gre --version;     assert "--version rc=0"     test "$GRE_RC" -eq 0
assert "--version reports current version" grep -q "$(cat "$REPO_ROOT/VERSION" 2>/dev/null || echo 2.0)" <<< "$GRE_OUT"
gre status;        assert "status rc=0"        test "$GRE_RC" -eq 0
gre status --json; assert "status --json rc=0" test "$GRE_RC" -eq 0
json_valid "fresh JSON valid"
gre doctor </dev/null;        assert "fresh doctor rc=0 (no config = warn only)" test "$GRE_RC" -eq 0
gre node list;     assert_not "node list fails when not FOREIGN" test "$GRE_RC" -eq 0
gre node list --json; assert_not "node list --json fails" test "$GRE_RC" -eq 0
gre node add --name x --ip 1.2.3.4 --yes; assert_not "node add fails when not FOREIGN" test "$GRE_RC" -eq 0
gre node remove --name x --yes; assert_not "node remove fails" test "$GRE_RC" -eq 0
gre iran peer list; assert_not "iran peer list fails when no peers" test "$GRE_RC" -eq 0
gre iran peer add --yes; assert_not "peer add without args fails" test "$GRE_RC" -eq 0
gre iran peer remove --name x --yes; assert_not "peer remove missing peer fails" test "$GRE_RC" -eq 0
gre iran peer apply --name x; assert_not "peer apply missing peer fails" test "$GRE_RC" -eq 0
gre iran-setup --yes; assert_not "iran-setup without --foreign-ip fails" test "$GRE_RC" -eq 0
gre iran --help;   assert "iran --help rc=0"   test "$GRE_RC" -eq 0
gre iran peer --help; assert "iran peer --help rc=0" test "$GRE_RC" -eq 0
gre watchdog status; assert "watchdog status rc=0" test "$GRE_RC" -eq 0
gre watchdog bogus; assert_not "watchdog bogus fails" test "$GRE_RC" -eq 0
gre hub status;    assert "hub status rc=0 on fresh" test "$GRE_RC" -eq 0
assert "hub status says not installed" grep -q "not installed" <<< "$GRE_OUT"
gre hub bogus;     assert_not "hub bogus subcommand fails" test "$GRE_RC" -eq 0
gre hub domain "bad_domain!"; assert_not "hub domain invalid fails" test "$GRE_RC" -eq 0
gre hub unexpose;  assert "hub unexpose rc=0 on fresh" test "$GRE_RC" -eq 0
gre export "$WORK/exp.tar.gz" --yes; assert "export with no config writes empty backup (rc=0 with --yes)" test "$GRE_RC" -eq 0
gre import;        assert_not "import without file fails" test "$GRE_RC" -eq 0
gre bogus-command; assert_not "unknown command fails" test "$GRE_RC" -eq 0
gre --apply;       assert "--apply on fresh rc=0" test "$GRE_RC" -eq 0
gre --stop;        assert "--stop on fresh rc=0" test "$GRE_RC" -eq 0
gre --watchdog;    assert "--watchdog on fresh rc=0" test "$GRE_RC" -eq 0
printf '0\n' | { TEST_ROOT="$R" PATH="$STUBS:$PATH" bash "$SUT" >/dev/null 2>&1; }
assert "menu exits cleanly" test "$?" -eq 0
rm -rf "$R"

# ======================================================================
sect "2. v1 -> v2 migration (atomic, idempotent, mixed-layout abort)"
mkroot
v1_fixture
# legacy un-commented v1 rules, as a v1 server would have
cat > "$R/state/iptables.nat" <<'EOF'
PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 10.200.1.1
PREROUTING -i eth0 -d 198.51.100.20 -p udp -m multiport --dports 443 -j DNAT --to-destination 10.200.1.1
POSTROUTING -o gre-de1 -d 10.200.1.1 -j SNAT --to-source 10.200.1.2
EOF
echo 'POSTROUTING -o gre-de1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' > "$R/state/iptables.mangle"
gre --apply
assert "migration --apply rc=0" test "$GRE_RC" -eq 0
assert "peer conf written"        test -f "$R/etc/multi-gre/foreigns/de1.conf"
assert "SUBNET_BASE=10.200 kept"  grep -qx "SUBNET_BASE=10.200" "$R/etc/multi-gre/foreigns/de1.conf"
assert "manifest written"         grep -qx "SCHEMA_VERSION=2" "$R/etc/multi-gre/iran.conf"
assert "manifest role"            grep -qx "ROLE_IRAN=1" "$R/etc/multi-gre/iran.conf"
assert "v1 backup kept"           test -f "$R/etc/multi-gre/iran.conf.v1.bak"
assert "backup holds legacy data" grep -qx "FOREIGN_IP=203.0.113.10" "$R/etc/multi-gre/iran.conf.v1.bak"
assert "tunnel up"                tun_there gre-de1
assert "commented DNAT tcp added" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -m comment --comment multi-gre-iran-de1-dnat-tcp -j DNAT --to-destination 10.200.1.1"
assert "commented SNAT added"     nat_has "POSTROUTING -o gre-de1 -d 10.200.1.1 -m comment --comment multi-gre-iran-de1-snat -j SNAT --to-source 10.200.1.2"
assert "legacy DNAT removed"      bash -c "! grep -qxF 'PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 10.200.1.1' '$R/state/iptables.nat'"
assert "legacy MSS removed"       bash -c "! grep -qxF 'POSTROUTING -o gre-de1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' '$R/state/iptables.mangle'"
assert "commented MSS added"      grep -qxF 'POSTROUTING -o gre-de1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment multi-gre-iran-de1-mss -j TCPMSS --clamp-mss-to-pmtu' "$R/state/iptables.mangle"
# idempotent re-run
cp "$R/state/iptables.nat" "$R/state/nat.before"
gre --apply
assert "re-apply rc=0" test "$GRE_RC" -eq 0
assert "no duplicate rules on re-apply" bash -c "diff '$R/state/nat.before' '$R/state/iptables.nat'"
assert "still one peer" bash -c "ls '$R/etc/multi-gre/foreigns/'*.conf | wc -l | grep -qx 1"
# mixed layout must abort
cat > "$R/etc/multi-gre/iran.conf" <<'EOF'
NAME=zz9
FOREIGN_IP=203.0.113.99
IRAN_IP=198.51.100.20
WAN_IF=eth0
IDX=9
KEY=1009
TUN=gre-zz9
TCP_PORTS=
UDP_PORTS=
MSS_CLAMP=0
EOF
gre --apply
assert_not "mixed legacy+v2 layout aborts" test "$GRE_RC" -eq 0
assert "abort message" grep -qi "inconsistent" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "3. three peers: independent tunnels + rules, idempotent apply/add"
mkroot
add_de1; assert "add de1 rc=0" test "$GRE_RC" -eq 0
add_nl1; assert "add nl1 rc=0" test "$GRE_RC" -eq 0
add_uk1; assert "add uk1 rc=0" test "$GRE_RC" -eq 0
assert "uk1 auto base 10.202" grep -qx "SUBNET_BASE=10.202" "$R/etc/multi-gre/foreigns/uk1.conf"
assert "3 tunnels" bash -c "ls '$R/state/tunnels' | wc -l | grep -qx 3"
assert "de1 tunnel addr" grep -q "10.200.1.2/30" "$R/state/addrs"
assert "nl1 tunnel addr" grep -q "10.201.1.2/30" "$R/state/addrs"
assert "uk1 tunnel addr" grep -q "10.202.1.2/30" "$R/state/addrs"
assert "nl1 DNAT" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 8443 -m comment --comment multi-gre-iran-nl1-dnat-tcp -j DNAT --to-destination 10.201.1.1"
assert "uk1 DNAT udp" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p udp -m multiport --dports 2053 -m comment --comment multi-gre-iran-uk1-dnat-udp -j DNAT --to-destination 10.202.1.1"
cp "$R/state/iptables.nat" "$R/state/nat.before"
gre --apply; gre --apply
assert "double re-apply rc=0" test "$GRE_RC" -eq 0
assert "no duplicate rules after 2x apply" bash -c "diff '$R/state/nat.before' '$R/state/iptables.nat'"
# idempotent re-add with identical config
add_de1
assert "re-add identical rc=0" test "$GRE_RC" -eq 0
assert "re-add identical says so" grep -qi "identical" <<< "$GRE_OUT"
# re-add with different values is rejected
gre iran peer add --name de1 --foreign-ip 203.0.113.77 --iran-ip 198.51.100.20 \
  --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80,443 --udp-ports 443 --yes
assert_not "re-add different values rejected" test "$GRE_RC" -eq 0
assert "no silent update msg" grep -qi "different" <<< "$GRE_OUT"
# duplicate (SUBNET_BASE, IDX) rejected
gre iran peer add --name dup1 --foreign-ip 203.0.113.50 --subnet-base 10.200 --idx 1 --yes
assert_not "duplicate (base,idx) rejected" test "$GRE_RC" -eq 0
assert "names conflicting peer" grep -q "de1" <<< "$GRE_OUT"
# same idx on a different base is fine
gre iran peer add --name fi1 --foreign-ip 203.0.113.60 --subnet-base 10.203 --idx 1 --yes
assert "same idx on another base ok" test "$GRE_RC" -eq 0
# duplicate name rejected
gre iran peer add --name de1 --foreign-ip 203.0.113.61 --subnet-base 10.204 --idx 1 --yes
assert_not "duplicate name rejected" test "$GRE_RC" -eq 0
rm -rf "$R"

# ======================================================================
sect "4. port overlap rules (ranges, TCP vs UDP independent)"
mkroot
gre iran peer add --name ov1 --foreign-ip 203.0.113.10 --subnet-base 10.200 --idx 1 --key 1001 --tcp-ports 80:90 --udp-ports 53 --yes
assert "ov1 added (range)" test "$GRE_RC" -eq 0
gre iran peer add --name ov2 --foreign-ip 203.0.113.11 --subnet-base 10.201 --idx 1 --key 1001 --tcp-ports 85 --yes
assert_not "TCP range overlap (85 in 80:90) rejected" test "$GRE_RC" -eq 0
assert "overlap names peer" grep -q "ov1" <<< "$GRE_OUT"
gre iran peer add --name ov2 --foreign-ip 203.0.113.11 --subnet-base 10.201 --idx 1 --key 1001 --udp-ports 85 --yes
assert "same port number on UDP allowed (TCP independent)" test "$GRE_RC" -eq 0
gre iran peer add --name ov3 --foreign-ip 203.0.113.12 --subnet-base 10.202 --idx 1 --key 1001 --udp-ports 53 --yes
assert_not "UDP overlap rejected" test "$GRE_RC" -eq 0
gre iran peer add --name ov4 --foreign-ip 203.0.113.13 --subnet-base 10.203 --idx 1 --key 1001 --tcp-ports 90 --yes
assert_not "TCP boundary overlap (90 in 80:90) rejected" test "$GRE_RC" -eq 0
gre iran peer add --name ov4 --foreign-ip 203.0.113.13 --subnet-base 10.203 --idx 1 --key 1001 --tcp-ports 91 --yes
assert "adjacent port 91 ok" test "$GRE_RC" -eq 0
rm -rf "$R"

# ======================================================================
sect "5. SSH port 22 protection"
mkroot
gre iran peer add --name de1 --foreign-ip 203.0.113.10 --tcp-ports 22,80 --yes
assert "port 22 allowed with --yes" test "$GRE_RC" -eq 0
gre iran peer add --name nl1 --foreign-ip 203.0.113.11 --tcp-ports 22 </dev/null
assert_not "port 22 refused without --yes" test "$GRE_RC" -eq 0
assert "ssh warning shown" grep -qi "22" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "6. remove middle peer leaves others intact"
mkroot
add_de1; add_nl1; add_uk1
gre iran peer remove --name nl1 --yes
assert "remove nl1 rc=0" test "$GRE_RC" -eq 0
assert_not "nl1 tunnel gone" tun_there gre-nl1
assert "nl1 conf gone" bash -c "! test -f '$R/etc/multi-gre/foreigns/nl1.conf'"
assert_not "nl1 DNAT gone" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 8443 -m comment --comment multi-gre-iran-nl1-dnat-tcp -j DNAT --to-destination 10.201.1.1"
assert "de1 tunnel intact" tun_there gre-de1
assert "uk1 tunnel intact" tun_there gre-uk1
assert "de1 DNAT intact" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -m comment --comment multi-gre-iran-de1-dnat-tcp -j DNAT --to-destination 10.200.1.1"
assert "uk1 SNAT intact" nat_has "POSTROUTING -o gre-uk1 -d 10.202.1.1 -m comment --comment multi-gre-iran-uk1-snat -j SNAT --to-source 10.202.1.2"
assert "shared service kept" test -f "$R/etc/systemd/system/multi-gre.service"
rm -rf "$R"

# ======================================================================
sect "7. watchdog re-applies only the dead peer"
mkroot
add_de1; add_nl1; add_uk1
echo "10.201.1.1" > "$R/state/dead"
gre --watchdog
assert "watchdog rc=0" test "$GRE_RC" -eq 0
assert "watchdog re-applied nl1" grep -q "Tunnel gre-nl1 is up" <<< "$GRE_OUT"
assert_not "watchdog left de1 alone" grep -q "Tunnel gre-de1 is up" <<< "$GRE_OUT"
assert_not "watchdog left uk1 alone" grep -q "Tunnel gre-uk1 is up" <<< "$GRE_OUT"
assert "watchdog log names peer+tun+foreign" grep -q "peer nl1 tunnel gre-nl1 (foreign 203.0.113.11)" "$R/state/logger.log"
: > "$R/state/dead"
: > "$R/state/logger.log"
gre --watchdog
assert_not "healthy watchdog re-applies nothing" grep -q "is up" <<< "$GRE_OUT"
# dead tunnel (missing) also repaired
rm -f "$R/state/tunnels/gre-uk1"
awk '$NF != "gre-uk1"' "$R/state/addrs" > "$R/state/addrs.tmp"; mv "$R/state/addrs.tmp" "$R/state/addrs"
gre --watchdog
assert "missing tunnel re-applied" grep -q "Tunnel gre-uk1 is up" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "8. JSON status: 0 / 1 / 3 peers + deprecated legacy field"
mkroot
gre status --json
json_valid "0-peer JSON valid"
json_check "0-peer iran_peers empty" \
  'assert d["iran_peers"]==[] and d["iran"] is None and d["schema_version"]==2' \
  '"iran_peers": \[\]'
json_check "0-peer legacy iran is null" 'assert d["iran"] is None' '"iran": null'
add_de1
gre status --json
json_valid "1-peer JSON valid"
json_check "1-peer legacy iran emitted (deprecated)" \
  'assert len(d["iran_peers"])==1 and d["iran"] and d["iran"]["deprecated"] is True and d["iran"]["name"]=="de1" and d["iran"]["subnet_base"]=="10.200"' \
  '"iran": \{"name":"de1".*"deprecated":true\}'
json_check "1-peer reachable flag" \
  'assert d["iran_peers"][0]["reachable"] is True' \
  '"reachable":true'
add_nl1; add_uk1
gre status --json
json_valid "3-peer JSON valid"
json_check "3-peer legacy iran is null" \
  'assert len(d["iran_peers"])==3 and d["iran"] is None' \
  '"iran": null'
gre iran peer list --json
json_check "peer list --json valid (3 entries)" \
  'assert isinstance(d,list) and len(d)==3' \
  '"name":"uk1"'
rm -rf "$R"

# ======================================================================
sect "9. doctor exit codes"
mkroot
add_de1
gre doctor
assert "healthy doctor rc=0" test "$GRE_RC" -eq 0
rm -f "$R/state/tunnels/gre-de1"
awk '$NF != "gre-de1"' "$R/state/addrs" > "$R/state/addrs.tmp"; mv "$R/state/addrs.tmp" "$R/state/addrs"
gre doctor
assert_not "missing tunnel -> doctor rc=1" test "$GRE_RC" -eq 0
assert "doctor reports missing tunnel" grep -q "tunnel gre-de1 is missing" <<< "$GRE_OUT"
gre iran peer apply --name de1 >/dev/null 2>&1
grep -vxF "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -m comment --comment multi-gre-iran-de1-dnat-tcp -j DNAT --to-destination 10.200.1.1" "$R/state/iptables.nat" > "$R/state/nat.tmp" || true
mv "$R/state/nat.tmp" "$R/state/iptables.nat"
gre doctor
assert_not "missing DNAT -> doctor rc=1" test "$GRE_RC" -eq 0
assert "doctor reports missing DNAT" grep -q "DNAT rule for tcp ports 80,443 is missing" <<< "$GRE_OUT"
# artificial conflict: duplicate (base,idx) across two peer confs
add_nl1
sed -e 's/^NAME=nl1$/NAME=xx1/' -e 's/^TUN=gre-nl1$/TUN=gre-xx1/' \
    "$R/etc/multi-gre/foreigns/nl1.conf" > "$R/etc/multi-gre/foreigns/xx1.conf"
gre doctor
assert_not "duplicate subnet/idx -> doctor rc=1" test "$GRE_RC" -eq 0
assert "doctor reports duplicate" grep -qi "duplicate subnet/index 10.201.1" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "10. iran-setup backward compatibility"
mkroot
gre iran-setup --foreign-ip 203.0.113.10 --tcp-ports 443 --yes
assert "iran-setup first peer rc=0" test "$GRE_RC" -eq 0
assert "iran-setup wrote peer conf" test -f "$R/etc/multi-gre/foreigns/ir01.conf"
assert "iran-setup wrote manifest" grep -qx "SCHEMA_VERSION=2" "$R/etc/multi-gre/iran.conf"
assert "iran-setup default base" grep -qx "SUBNET_BASE=10.200" "$R/etc/multi-gre/foreigns/ir01.conf"
gre iran-setup --foreign-ip 203.0.113.11 --yes
assert_not "iran-setup refuses on multi-peer server" test "$GRE_RC" -eq 0
assert "refusal points to peer add" grep -q "gre iran peer add" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "11. export / import roundtrips (v2, v1, mixed-unsafe rejected)"
mkroot
add_de1; add_nl1
gre export "$WORK/v2-backup.tar.gz" --yes
assert "export v2 rc=0" test "$GRE_RC" -eq 0
R2="$(mktemp -d -p "$WORK")"; mkdir -p "$R2/var/log" "$R2/usr/local/sbin" "$R2/etc/systemd/system" "$R2/etc/sysctl.d" "$R2/state"
RSAVED="$R"; R="$R2"
gre import "$WORK/v2-backup.tar.gz" --yes
assert "import v2 rc=0" test "$GRE_RC" -eq 0
assert "imported de1 conf" test -f "$R/etc/multi-gre/foreigns/de1.conf"
assert "imported nl1 conf" test -f "$R/etc/multi-gre/foreigns/nl1.conf"
assert "imported tunnels up" tun_there gre-de1
assert "imported rules applied" nat_has "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 8443 -m comment --comment multi-gre-iran-nl1-dnat-tcp -j DNAT --to-destination 10.201.1.1"
R="$RSAVED"

# v1 archive roundtrip
V1S="$(mktemp -d -p "$WORK")"; mkdir -p "$V1S/etc/multi-gre"
cat > "$V1S/etc/multi-gre/iran.conf" <<'EOF'
NAME=de1
FOREIGN_IP=203.0.113.10
IRAN_IP=198.51.100.20
WAN_IF=eth0
IDX=1
KEY=1001
TUN=gre-de1
TCP_PORTS=80,443
UDP_PORTS=443
MSS_CLAMP=1
EOF
cat > "$V1S/etc/multi-gre/global.conf" <<'EOF'
WATCHDOG_ENABLED=1
WATCHDOG_INTERVAL_MIN=1
DOWNTIME_TOLERANCE_MIN=2
EOF
tar -czf "$WORK/v1-backup.tar.gz" -C "$V1S" etc/multi-gre
R2="$(mktemp -d -p "$WORK")"; mkdir -p "$R2/var/log" "$R2/usr/local/sbin" "$R2/etc/systemd/system" "$R2/etc/sysctl.d" "$R2/state"
RSAVED="$R"; R="$R2"
gre import "$WORK/v1-backup.tar.gz" --yes
assert "import v1 rc=0" test "$GRE_RC" -eq 0
assert "v1 import migrated to peer" test -f "$R/etc/multi-gre/foreigns/de1.conf"
assert "v1 import wrote manifest" grep -qx "SCHEMA_VERSION=2" "$R/etc/multi-gre/iran.conf"
assert "v1 import kept bak" test -f "$R/etc/multi-gre/iran.conf.v1.bak"
assert "v1 import tunnel up" tun_there gre-de1
R="$RSAVED"

# mixed archive rejected (legacy iran.conf + foreigns/ together)
VMS="$(mktemp -d -p "$WORK")"; mkdir -p "$VMS/etc/multi-gre/foreigns"
cat > "$VMS/etc/multi-gre/iran.conf" <<'EOF'
NAME=de1
FOREIGN_IP=203.0.113.10
IRAN_IP=198.51.100.20
WAN_IF=eth0
IDX=1
KEY=1001
TUN=gre-de1
TCP_PORTS=80
UDP_PORTS=
MSS_CLAMP=0
EOF
cat > "$VMS/etc/multi-gre/foreigns/nl1.conf" <<'EOF'
NAME=nl1
FOREIGN_IP=203.0.113.11
IRAN_IP=198.51.100.20
WAN_IF=eth0
SUBNET_BASE=10.201
IDX=1
KEY=1001
TUN=gre-nl1
TCP_PORTS=8443
UDP_PORTS=
MSS_CLAMP=1
EOF
tar -czf "$WORK/mixed-backup.tar.gz" -C "$VMS" etc/multi-gre
gre import "$WORK/mixed-backup.tar.gz" --yes
assert_not "mixed archive rejected" test "$GRE_RC" -eq 0
# unsafe archive rejected (path outside etc/multi-gre)
echo evil > "$WORK/evil"
tar -czf "$WORK/evil-backup.tar.gz" -C "$WORK" --transform 's/^evil/..\/evil/' evil 2>/dev/null \
  || tar -czf "$WORK/evil-backup.tar.gz" -C "$WORK" evil
gre import "$WORK/evil-backup.tar.gz" --yes
assert_not "archive without etc/multi-gre rejected" test "$GRE_RC" -eq 0
rm -rf "$R"

# ======================================================================
sect "12. purge removes the new per-peer rules too"
mkroot
add_de1; add_nl1
# simulate a leftover un-commented v1 rule
echo "PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 8080 -j DNAT --to-destination 10.200.1.1" >> "$R/state/iptables.nat"
gre purge --yes
assert "purge rc=0" test "$GRE_RC" -eq 0
assert "purge emptied nat table" bash -c "! grep -qE 'multi-gre|10\.2[0-5][0-9]\.' '$R/state/iptables.nat' 2>/dev/null"
assert "purge emptied mangle" bash -c "! grep -qE 'multi-gre' '$R/state/iptables.mangle' 2>/dev/null"
assert "purge removed tunnels" bash -c "ls '$R/state/tunnels' | wc -l | grep -qx 0"
assert "purge removed config" bash -c "! test -d '$R/etc/multi-gre'"
rm -rf "$R"

# ======================================================================
sect "13. FOREIGN side regression (nodes, whitelist order, subnet-base)"
mkroot
mkdir -p "$R/etc/multi-gre"
cat > "$R/etc/multi-gre/foreign.conf" <<'EOF'
FOREIGN_IP=203.0.113.10
ICMP_DROP=0
GRE_WHITELIST=1
EOF
gre node add --name ir01 --ip 198.51.100.20 --yes
assert "node add rc=0" test "$GRE_RC" -eq 0
assert "node conf has default base" grep -qx "SUBNET_BASE=10.200" "$R/etc/multi-gre/nodes/ir01.conf"
assert "node tunnel up" tun_there gre-ir01
assert "pairing block prints subnet base" grep -q "Tunnel subnet base" <<< "$GRE_OUT"
assert "pairing block prints iran cmd" grep -q "gre iran peer add --name ir01" <<< "$GRE_OUT"
gre node add --name ir02 --ip 198.51.100.21 --subnet-base 10.201 --idx 1 --yes
assert "same idx on different base ok" test "$GRE_RC" -eq 0
gre node add --name ir03 --ip 198.51.100.22 --subnet-base 10.200 --idx 1 --yes
assert_not "duplicate (base,idx) on FOREIGN rejected" test "$GRE_RC" -eq 0
gre node list
printf '%s' "$GRE_OUT" > "$R/out.txt"
assert "node list shows bases" grep -qF "10.201.1.0/30" "$R/out.txt"
gre node list --json
json_check "node list json has subnet_base" \
  'assert isinstance(d,list) and d[1]["subnet_base"]=="10.201"' \
  '"subnet_base":"10.201"'
# whitelist ordering: block rule must come after the ACCEPTs
gre --apply
awk '/multi-gre-node-|multi-gre-block/ {print NR": "$0}' "$R/state/iptables.filter" > "$R/state/order.txt"
assert "two node ACCEPTs" bash -c "grep -c 'multi-gre-node-' '$R/state/order.txt' | grep -qx 2"
assert "block rule is last" bash -c "tail -1 '$R/state/order.txt' | grep -q multi-gre-block"
# regression v2.2.2: with 2 managed tunnels, doctor must NOT report a false
# "unmanaged tunnel" (pipefail+SIGPIPE flipped grep -q when the match was early)
gre doctor
printf '%s' "$GRE_OUT" > "$R/doctor.txt"
assert_not "no false unmanaged-tunnel warning" grep -q "unmanaged GRE tunnel '" "$R/doctor.txt"
assert "coexistence check passes" grep -q "no unmanaged GRE tunnels" "$R/doctor.txt"
# status JSON on foreign side
gre status --json
json_valid "foreign JSON valid"
json_check "foreign nodes in JSON" \
  'assert len(d["nodes"])==2' \
  '"name":"ir02"'
# node without SUBNET_BASE falls back to 10.200
cat > "$R/etc/multi-gre/nodes/ir09.conf" <<'EOF'
NAME=ir09
IRAN_IP=198.51.100.29
IDX=9
KEY=1009
TUN=gre-ir09
EOF
gre --apply
assert "legacy node conf (no base) applied" grep -q "10.200.9.1/30" "$R/state/addrs"
gre node remove --name ir09 --yes
assert "node remove rc=0" test "$GRE_RC" -eq 0
assert "node remove hints peer remove" grep -q "gre iran peer remove --name ir09" <<< "$GRE_OUT"
rm -rf "$R"

# ======================================================================
sect "14. legacy v1 --stop without migration"
mkroot
v1_fixture
cat > "$R/state/iptables.nat" <<'EOF'
PREROUTING -i eth0 -d 198.51.100.20 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 10.200.1.1
POSTROUTING -o gre-de1 -d 10.200.1.1 -j SNAT --to-source 10.200.1.2
EOF
echo "add gre-de1 mode gre" > "$R/state/tunnels/gre-de1"
echo "10.200.1.2/30 gre-de1" >> "$R/state/addrs"
gre --stop
assert "--stop on v1 rc=0" test "$GRE_RC" -eq 0
assert "v1 --stop removed DNAT" bash -c "! grep -q DNAT '$R/state/iptables.nat'"
assert "v1 --stop removed tunnel" bash -c "! test -f '$R/state/tunnels/gre-de1'"
assert "v1 --stop did not migrate" bash -c "! test -f '$R/etc/multi-gre/iran.conf.v1.bak'"
rm -rf "$R"

# ======================================================================
sect "15. interactive peer-add wizard suggests non-colliding values"
mkroot
mkdir -p "$R/etc/multi-gre/foreigns"
printf 'SCHEMA_VERSION=2\nROLE_IRAN=1\n' > "$R/etc/multi-gre/iran.conf"
cat > "$R/etc/multi-gre/foreigns/de1.conf" <<'EOF'
NAME=de1
FOREIGN_IP=203.0.113.10
IRAN_IP=198.51.100.20
WAN_IF=eth0
SUBNET_BASE=10.200
IDX=1
KEY=1001
TUN=gre-de1
TCP_PORTS=3001
UDP_PORTS=3001
MSS_CLAMP=1
EOF
# menu -> option 1 (peers) -> 1 (add) -> answers (all defaults except foreign ip + name) -> back -> exit
printf '1\n1\n\n203.0.113.55\nnl1\n\n\n\n\n\n\n\n0\n0\n' | { TEST_ROOT="$R" PATH="$STUBS:$PATH" bash "$SUT" > "$R/wizard.out" 2>&1; }
assert "wizard rc=0" test "$?" -eq 0
assert "wizard wrote peer conf" test -f "$R/etc/multi-gre/foreigns/nl1.conf"
assert "wizard suggested next base 10.201" grep -qx "SUBNET_BASE=10.201" "$R/etc/multi-gre/foreigns/nl1.conf"
assert "wizard suggested free tcp port 3002" grep -qx "TCP_PORTS=3002" "$R/etc/multi-gre/foreigns/nl1.conf"
assert "wizard suggested free udp port 3002" grep -qx "UDP_PORTS=3002" "$R/etc/multi-gre/foreigns/nl1.conf"
rm -rf "$R"

# ======================================================================
echo
echo "PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
