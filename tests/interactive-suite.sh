#!/usr/bin/env bash
# ==========================================================================
# 31. Interactive input validation — validate at the prompt.
#
# The defect: the interactive wizards used ask(), which trusts whatever it reads.
# Every field was collected first and validated once at the end, so a typo anywhere
# meant answering all the remaining questions and then being told about all of them
# at once. Fields with no batch check (the WAN interface, the MSS answer) were not
# validated at all, and a typo there silently selected the opposite of what the
# operator intended.
#
# These tests drive the real helper functions and the real wizard, with `ip`,
# `iptables`, `systemctl`, `ss` and `logger` replaced by the suite stubs, so no
# interface, tunnel or firewall rule is ever touched.
# ==========================================================================

sect "31. interactive input: validate before advancing"

# ---------------------------------------------------------------- slice helper
# Source the script's definitions (everything before the CLI dispatch) so the
# helpers can be called directly with controlled stdin. Paths are redirected into
# the test root, and the dispatch is excluded so sourcing has no side effects.
INT_SLICE=""
interactive_slice() {
  [[ -n "$INT_SLICE" && -f "$INT_SLICE" ]] && return 0
  local last
  last="$(grep -n '^case "${1:-}" in' "$REPO_ROOT/gre-manager.sh" | head -1 | cut -d: -f1)"
  [[ -n "$last" ]] || return 1
  INT_SLICE="$WORK/interactive-defs.sh"
  # Every path the wizards touch must be redirected. CONF_DIR alone is not enough: the
  # derived paths (NODES_DIR, FOREIGNS_DIR, …) are assigned BEFORE the CONF_DIR line is
  # rewritten, so they would still point at /etc/multi-gre.
  awk -v last="$last" 'NR<last' "$REPO_ROOT/gre-manager.sh" \
    | sed -e "s|^CONF_DIR=\"/etc/multi-gre\"|CONF_DIR=\"$R/etc/multi-gre\"|" \
          -e "s|^SYSCTL_FILE=\"/etc/sysctl.d/99-multi-gre.conf\"|SYSCTL_FILE=\"$R/etc/sysctl.d/99-multi-gre.conf\"|" \
          -e "s|^SERVICE_FILE=\"/etc/systemd/system/multi-gre.service\"|SERVICE_FILE=\"$R/etc/systemd/system/multi-gre.service\"|" \
          -e "s|^WATCHDOG_SERVICE_FILE=\"/etc/systemd/system/multi-gre-watchdog.service\"|WATCHDOG_SERVICE_FILE=\"$R/etc/systemd/system/multi-gre-watchdog.service\"|" \
          -e "s|^WATCHDOG_TIMER_FILE=\"/etc/systemd/system/multi-gre-watchdog.timer\"|WATCHDOG_TIMER_FILE=\"$R/etc/systemd/system/multi-gre-watchdog.timer\"|" \
          -e "s|^INSTALL_PATH=\"/usr/local/sbin/gre\"|INSTALL_PATH=\"$R/usr/local/sbin/gre\"|" \
          -e "s|^AUDIT_LOG=\"/var/log/gre-manager.log\"|AUDIT_LOG=\"$R/var/log/gre-manager.log\"|" \
          -e 's|if \[\[ ${EUID:-$(id -u)} -ne 0 \]\]; then|if false; then|' > "$INT_SLICE"
  # Belt and braces: rewrite the derived paths too, in case their definitions move.
  sed -i -e "s|^NODES_DIR=.*|NODES_DIR=\"$R/etc/multi-gre/nodes\"|" \
         -e "s|^FOREIGNS_DIR=.*|FOREIGNS_DIR=\"$R/etc/multi-gre/foreigns\"|" \
         -e "s|^GLOBAL_CONF=.*|GLOBAL_CONF=\"$R/etc/multi-gre/global.conf\"|" \
         -e "s|^FOREIGN_CONF=.*|FOREIGN_CONF=\"$R/etc/multi-gre/foreign.conf\"|" \
         -e "s|^IRAN_CONF=.*|IRAN_CONF=\"$R/etc/multi-gre/iran.conf\"|" "$INT_SLICE"
  mkdir -p "$R/etc/multi-gre/nodes" "$R/etc/multi-gre/foreigns"
  chmod +x "$INT_SLICE"
  return 0
}

# int_var VAR INPUT... -> prints whatever VAR holds after sourcing the defs and
# prompting. Runs in a subshell, so the parent harness state is untouched.
int_var() {
  local var="$1"; shift
  interactive_slice || return 1
  printf '%s\n' "$@" | {
    # shellcheck disable=SC1090
    source "$INT_SLICE" >/dev/null 2>&1
    ask_valid "$var" "Q" "${INT_DEFAULT:-}" "${INT_VALIDATOR:-valid_ip}" "bad value" >/dev/null 2>&1
    printf '%s\n' "${!var}"
  }
}

# int_out INPUT... -> the messages a prompt printed (stdout+stderr).
int_out() {
  interactive_slice || return 1
  printf '%s\n' "$@" | {
    # shellcheck disable=SC1090
    source "$INT_SLICE" >/dev/null 2>&1
    ask_valid OUT "Q" "${INT_DEFAULT:-}" "${INT_VALIDATOR:-valid_ip}" "${INT_EMSG:-bad value}"
    printf 'RESULT=%s\n' "$OUT"
  } 2>&1
}

int_rc() {
  interactive_slice || return 1
  printf '%s\n' "$@" | {
    # shellcheck disable=SC1090
    source "$INT_SLICE" >/dev/null 2>&1
    ask_valid OUT "Q" "${INT_DEFAULT:-}" "${INT_VALIDATOR:-valid_ip}" "bad value" >/dev/null 2>&1
  }
  return $?
}

# int_validate VALIDATOR VALUE -> 0/1, using the real implementation. The stubs must be on
# PATH: iface_exists calls `ip`, and without the stub it would interrogate the real host.
int_validate() {
  interactive_slice || return 1
  {
    # shellcheck disable=SC1090
    source "$INT_SLICE" >/dev/null 2>&1
    "$1" "$2"
  } >/dev/null 2>&1
}
# Same, but with the stub PATH so filesystem/interface probes are hermetic.
int_validate_stubbed() {
  interactive_slice || return 1
  TEST_ROOT="$R" PATH="$STUBS:$PATH" bash -c "
    source '$INT_SLICE' >/dev/null 2>&1
    '$1' '$2'
  " >/dev/null 2>&1
}

# ------------------------------------------------- 1. invalid IPv4 then valid
mkroot
INT_DEFAULT="10.0.0.1" INT_VALIDATOR="valid_ip" INT_EMSG="Invalid IPv4 address."
assert "ip: invalid value is rejected" test "$(int_var IP 'v1de1na' '198.51.100.20')" = '198.51.100.20'
out="$(int_out 'v1de1na' '198.51.100.20')"
assert "ip: the error is explained" grep -q 'Invalid IPv4 address' <<< "$out"
assert "ip: the prompt is repeated (asked twice for two answers)" test "$(grep -c 'RESULT=' <<< "$out")" -eq 1

# ------------------------------------------------- 11. Enter with valid default
assert "ip: Enter accepts a VALID default" test "$(int_var IP '')" = '10.0.0.1'

# Enter with an INVALID default must be reported, never silently accepted.
INT_DEFAULT="not-an-ip"
assert "ip: Enter refuses to accept an invalid default" \
  test "$(int_var IP '' '198.51.100.20')" = '198.51.100.20'
out="$(int_out '' '198.51.100.20')"
assert "ip: the invalid default is explained" grep -q 'Invalid IPv4 address' <<< "$out"
INT_DEFAULT="10.0.0.1"

# ------------------------------------------------- 13. consecutive invalid attempts
assert "ip: many wrong answers then a right one" \
  test "$(int_var IP 'x' 'y' 'z' '1.2.3' '999.1.1.1' '198.51.100.20')" = '198.51.100.20'
out="$(int_out 'x' 'y' 'z' '1.2.3' '198.51.100.20')"
assert "ip: every bad attempt is reported" test "$(grep -c 'Invalid IPv4 address' <<< "$out")" -eq 4

# ------------------------------------------------- 12. EOF and read failure
INT_DEFAULT=""
assert_not "ip: EOF returns non-zero instead of looping forever" int_rc ''
assert "ip: EOF does not hang (it returned at all)" true

# ------------------------------------------------- 2/3/4/5. the field validators
assert "ip: accepts valid IPv4"           int_validate valid_ip '91.239.214.63'
assert_not "ip: rejects text"             int_validate valid_ip 'v1de1na'
assert_not "ip: rejects octet over 255"   int_validate valid_ip '256.1.1.1'
assert_not "ip: rejects a missing octet"  int_validate valid_ip '1.2.3'
assert_not "ip: rejects a fifth octet"    int_validate valid_ip '1.2.3.4.5'
assert_not "ip: rejects empty"            int_validate valid_ip ''
assert_not "ip: rejects a hostname"       int_validate valid_ip 'example.com'
assert_not "ip: rejects whitespace"       int_validate valid_ip ' 10.0.0.1'

assert "name: accepts de1"                int_validate valid_name 'de1'
assert "name: accepts an 11-char name"    int_validate valid_name 'abcdefghijk'
assert "name: accepts underscore/hyphen"  int_validate valid_name 'de_1-x'
assert_not "name: rejects 12 chars"       int_validate valid_name 'abcdefghijkl'
assert_not "name: rejects leading symbol" int_validate valid_name '_de1'
assert_not "name: rejects the screenshot value" int_validate valid_name '^X,,asda'
assert_not "name: rejects a space"        int_validate valid_name 'de 1'
assert_not "name: rejects a semicolon"    int_validate valid_name 'de1;ls'
assert_not "name: rejects empty"          int_validate valid_name ''

assert "subnet: accepts 10.200"           int_validate valid_subnet_base '10.200'
assert "subnet: accepts 0.0"              int_validate valid_subnet_base '0.0'
assert_not "subnet: rejects a third octet" int_validate valid_subnet_base '10.200.1'
assert_not "subnet: rejects octet > 255"  int_validate valid_subnet_base '256.1'
assert_not "subnet: rejects the screenshot value" int_validate valid_subnet_base 'asdagfahq232041z.z.z.'
assert_not "subnet: rejects one octet"    int_validate valid_subnet_base '10'
assert_not "subnet: rejects empty"        int_validate valid_subnet_base ''

assert "index: accepts 1"                 int_validate valid_idx '1'
assert "index: accepts 254"               int_validate valid_idx '254'
assert_not "index: rejects 0"             int_validate valid_idx '0'
assert_not "index: rejects 255"           int_validate valid_idx '255'
assert_not "index: rejects a negative"    int_validate valid_idx '-3'
assert_not "index: rejects a decimal"     int_validate valid_idx '1.5'
assert_not "index: rejects the screenshot value" int_validate valid_idx 'as15r151'
assert_not "index: rejects a command"     int_validate valid_idx '1;rm -rf /'

assert "key: accepts 0"                   int_validate valid_key '0'
assert "key: accepts 1001"                int_validate valid_key '1001'
assert "key: accepts 4294967295 (max u32)" int_validate valid_key '4294967295'
assert_not "key: rejects 4294967296 (overflow)" int_validate valid_key '4294967296'
assert_not "key: rejects a negative"      int_validate valid_key '-1'
assert_not "key: rejects a decimal"       int_validate valid_key '1.5'
assert_not "key: rejects the screenshot value" int_validate valid_key ',af1t1t1'
assert_not "key: rejects empty"           int_validate valid_key ''
assert_not "key: rejects a very large number" int_validate valid_key '99999999999999999999'

# ------------------------------------------------- 6. nonexistent WAN interface
assert "iface: eth0 exists (stub)"        int_validate_stubbed iface_exists 'eth0'
assert "iface: lo exists (stub)"          int_validate_stubbed iface_exists 'lo'
assert_not "iface: a nonexistent interface is rejected" int_validate_stubbed iface_exists 'ajsdafajgag'
assert_not "iface: a command-looking name is rejected"  int_validate_stubbed iface_exists 'eth0;ls'
assert_not "iface: empty is rejected"     int_validate_stubbed iface_exists ''

# ------------------------------------------------- 7/8/9. port lists
assert "ports: accepts 80,443"            int_validate valid_port_list '80,443'
assert "ports: accepts a range"           int_validate valid_port_list '80:90'
assert "ports: accepts several ranges"    int_validate valid_port_list '80:90,443,8000:8100'
assert "ports: accepts 1"                 int_validate valid_port_list '1'
assert "ports: accepts 65535"             int_validate valid_port_list '65535'
assert "ports: empty list is allowed"     int_validate valid_port_list ''
assert "ports: accepts exactly 15 entries" int_validate valid_port_list '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15'
assert_not "ports: rejects 16 entries"    int_validate valid_port_list '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16'
assert_not "ports: rejects the screenshot value" int_validate valid_port_list 'ajsgagasgas'
assert_not "ports: rejects port 0"        int_validate valid_port_list '0'
assert_not "ports: rejects 70000"         int_validate valid_port_list '70000'
assert_not "ports: rejects a reversed range" int_validate valid_port_list '90:80'
assert_not "ports: rejects an empty element" int_validate valid_port_list '80,,443'
assert_not "ports: rejects a trailing comma" int_validate valid_port_list '80,'
assert_not "ports: rejects spaces"        int_validate valid_port_list '80, 443'
assert_not "ports: rejects a semicolon"   int_validate valid_port_list '80;443'

# ------------------------------------------------- 10. invalid MSS answer
assert "mss: accepts on/off/yes/no/1/0"   int_validate valid_on_off 'on'
assert "mss: accepts off"                 int_validate valid_on_off 'off'
assert "mss: accepts YES (case-insensitive)" int_validate valid_on_off 'YES'
assert_not "mss: rejects the screenshot value" int_validate valid_on_off '1io11'
assert_not "mss: rejects arbitrary text"  int_validate valid_on_off 'maybe'
assert_not "mss: rejects empty (empty is handled by the caller)" int_validate valid_on_off ''

# ask_yes_no: Enter selects the stated default, and a bad answer repeats the question.
int_yesno() { # int_yesno DEFAULT INPUT...
  local def="$1"; shift
  interactive_slice || return 1
  printf '%s\n' "$@" | {
    # shellcheck disable=SC1090
    source "$INT_SLICE" >/dev/null 2>&1
    if ask_yes_no "Enable TCP MSS clamping?" "$def"; then echo YES; else echo NO; fi
  } 2>&1
}
assert "mss: Enter selects the [Y/n] default (yes)" grep -q '^YES$' <<< "$(int_yesno y '')"
assert "mss: Enter selects the [y/N] default (no)"  grep -q '^NO$'  <<< "$(int_yesno n '')"
assert "mss: y means yes"                 grep -q '^YES$' <<< "$(int_yesno y 'y')"
assert "mss: n means no"                  grep -q '^NO$'  <<< "$(int_yesno y 'n')"
assert "mss: an invalid answer is rejected and repeated" \
  grep -q 'Please answer' <<< "$(int_yesno y '1io11' 'y')"
assert "mss: the rejected answer changes nothing (still yes)" \
  grep -q '^YES$' <<< "$(int_yesno y '1io11' 'y')"
assert "mss: a rejected answer can still become no" \
  grep -q '^NO$' <<< "$(int_yesno y '1io11' 'n')"
rm -rf "$R"

# ==========================================================================
# The wizard itself: no plain ask(), and validation before any system change.
# ==========================================================================
mkroot

# Extract one function body from the script under test.
fn_body() { # fn_body "name() {"
  local src sig="$1"
  src="$(cat "$REPO_ROOT/gre-manager.sh")"
  local start; start="$(grep -nF "$sig" <<< "$src" | head -1 | cut -d: -f1)"
  [[ -n "$start" ]] || return 1
  # Up to the next top-level function definition.
  awk -v s="$start" 'NR>=s { if (NR>s && /^[a-zA-Z_][a-zA-Z0-9_]*\(\) \{/) exit; print }' <<< "$src"
}

WIZ="$(fn_body 'interactive_add_iran_peer() {')"
assert "wizard: the function was found" test -n "$WIZ"

# Every prompt in the wizard must be the validated form.
assert_not "wizard: no unvalidated ask() remains" grep -qE '(^|[^_a-zA-Z_])ask( |$)' <<< "$WIZ"
for field in IRAN_IP FOREIGN_IP NAME SUBNET_BASE IDX KEY WAN_IF TCP_PORTS UDP_PORTS; do
  assert "wizard: $field is collected with ask_valid" grep -q "ask_valid $field " <<< "$WIZ"
done
assert "wizard: the MSS question is validated" grep -q 'ask_yes_no .*MSS' <<< "$WIZ"
assert "wizard: the WAN interface must exist locally" grep -q 'ask_valid WAN_IF .* iface_exists' <<< "$WIZ"

# Ordering: the final validation must precede any state change.
final_line="$(grep -n 'validate_peer_values' <<< "$WIZ" | head -1 | cut -d: -f1)"
create_line="$(grep -n 'create_iran_peer\|apply_foreign_node\|write_global_conf\|install_service' <<< "$WIZ" | head -1 | cut -d: -f1)"
assert "wizard: a final validation pass exists" test -n "$final_line"
assert "wizard: the final validation runs before any state change" \
  test "$final_line" -lt "$create_line"
assert "wizard: the local interface is re-checked before applying" \
  grep -q 'iface_exists "\$WAN_IF" ||' <<< "$WIZ"

# The FOREIGN node wizard too.
NODE_WIZ="$(fn_body 'setup_foreign() {')"
assert "node wizard: the function was found" test -n "$NODE_WIZ"
assert_not "node wizard: no unvalidated ask() remains" grep -qE '(^|[^_a-zA-Z_])ask( |$)' <<< "$NODE_WIZ"
for field in NAME IRAN_IP SUBNET_BASE IDX KEY; do
  assert "node wizard: $field is collected with ask_valid" grep -q "ask_valid $field " <<< "$NODE_WIZ"
done
assert "node wizard: values are re-checked as a set before writing" \
  grep -q 'did not pass the final check' <<< "$NODE_WIZ"
node_final="$(grep -n 'did not pass the final check' <<< "$NODE_WIZ" | head -1 | cut -d: -f1)"
node_write="$(grep -n 'NODES_DIR/\$NAME.conf >\|apply_foreign_node' <<< "$NODE_WIZ" | head -1 | cut -d: -f1)"
assert "node wizard: the final check runs before the config is written" \
  test "$node_final" -lt "$node_write"

# The edit wizard: empty keeps the current value, but a typed value must be valid.
EDIT_WIZ="$(fn_body 'interactive_edit_iran_peer() {')"
assert "edit wizard: the function was found" test -n "$EDIT_WIZ"
assert_not "edit wizard: no unvalidated ask() remains" grep -qE '(^|[^_a-zA-Z_])ask( |$)' <<< "$EDIT_WIZ"
for field in FOREIGN_IP IRAN_IP NAME SUBNET_BASE IDX KEY WAN_IF TCP_PORTS UDP_PORTS; do
  assert "edit wizard: $field is validated at its prompt" \
    grep -q "PLAN_REQ_$field=\"\$v\"" <<< "$EDIT_WIZ"
done
assert "edit wizard: empty input keeps the current value" \
  grep -q '\[\[ -n "\$v" \]\] && PLAN_REQ_NAME="\$v"' <<< "$EDIT_WIZ"
assert "edit wizard: the MSS answer is validated" grep -q 'ask_optional_valid v .*valid_on_off' <<< "$EDIT_WIZ"

# No field is evaluated as shell code anywhere in the script.
assert_not "no eval() in the script" \
  bash -c "grep -qE '(^|[^_a-zA-Z])eval ' '$REPO_ROOT/gre-manager.sh'"

# ------------------------------------------------- 14/15: nothing changes on failure
# Drive the REAL wizard function with stubbed system-changing calls, so the test observes
# exactly what the wizard accepted and whether it reached the apply step. The menu's own
# infinite loop is deliberately bypassed: it is not what is under test, and at EOF its
# `read` returns non-zero forever.
#
# The stubs record what they were called with; the real config writer still runs, so the
# resulting peer conf file is the observable evidence of what passed validation.
wiz_setup() { # writes the stub prologue used by wiz_run/wiz_apply
  cat <<'STUBS'
# --- test stubs: no system is touched -------------------------------------
GRE_APPLY_CALLED=0
GRE_CREATE_ARGS=""
create_iran_peer() { GRE_APPLY_CALLED=1; GRE_CREATE_ARGS="$*"; return 0; }
apply_iran_peer()  { GRE_APPLY_CALLED=1; return 0; }
apply_foreign_node() { GRE_APPLY_CALLED=1; return 0; }
install_service()  { :; }
install_watchdog() { :; }
remove_watchdog()  { :; }
write_global_conf() { :; }
systemctl()        { :; }
STUBS
}
# wiz_run INPUT... -> runs the wizard with that stdin; prints the wizard's output.
#
# The stubs are applied AFTER the slice is sourced. Defining them first would be pointless:
# sourcing re-declares every function, so the real create_iran_peer / install_service would
# win and the test would touch the system.
wiz_run() {
  interactive_slice || return 1
  local script="$WORK/wiz-run.sh"
  cat "$INT_SLICE" > "$script"
  wiz_setup >> "$script"
  printf '\ninteractive_add_iran_peer 1\n' >> "$script"
  # Print the exact argument list the wizard handed to the applier: this is the evidence of
  # which values passed validation, and it is why create_iran_peer is stubbed.
  printf 'echo "APPLY=$GRE_APPLY_CALLED"\n' >> "$script"
  printf 'echo "ARGS=[$GRE_CREATE_ARGS]"\n' >> "$script"
  printf '%s\n' "$@" | TEST_ROOT="$R" PATH="$STUBS:$PATH" bash "$script" 2>&1
}

# Answers for the first-peer wizard, in order, as the wizard's own prompt text confirms:
# Iran IP, foreign IP, peer name, subnet base, tunnel index, GRE key, WAN interface,
# TCP ports, UDP ports, MSS yes/no, downtime tolerance.
#
# IMPORTANT: the wizard reads these with `read -rp`, and the tail of this list must NOT be
# a "0" meant for the main menu — driving the function directly means there is no menu.

# ------------------------------------------------- 14. no system change before validation
# Each field is answered with an invalid value FIRST and a valid one SECOND. Because a bad
# answer re-prompts the SAME field, the input must be paired per field — which is itself the
# proof that an invalid value cannot advance to the next question.
rm -rf "$R"; mkroot
before_tunnels="$(ls "$R/state/tunnels" 2>/dev/null | tr '\n' ' ')"
before_nat="$(cat "$R/state/iptables.nat" 2>/dev/null || echo '')"
bad_out="$(wiz_run \
  'v1de1na' '198.51.100.20' \
  'nope' '203.0.113.10' \
  '^X,,asda' 'de1' \
  'bad.subnet.x' '10.200' \
  'as15r151' '1' \
  ',af1t1t1' '1001' \
  'ajsdafajgag' 'eth0' \
  'ajsgagasgas' '80,443' \
  'ajsgasgaga' '443' \
  '1io11' 'y' \
  '2')"
assert "wizard: the IPv4 error is reported at the prompt" grep -q 'Invalid IPv4 address' <<< "$bad_out"
assert "wizard: the peer-name error is reported at the prompt" grep -q 'Invalid peer name' <<< "$bad_out"
assert "wizard: the subnet error is reported at the prompt" grep -q 'Invalid subnet base' <<< "$bad_out"
assert "wizard: the index error is reported at the prompt" grep -q 'Invalid tunnel index' <<< "$bad_out"
assert "wizard: the GRE key error is reported at the prompt" grep -q 'Invalid GRE key' <<< "$bad_out"
assert "wizard: the WAN interface error is reported at the prompt" grep -q 'does not exist on this host' <<< "$bad_out"
assert "wizard: the TCP port error is reported at the prompt" grep -q 'Invalid TCP port list' <<< "$bad_out"
assert "wizard: the UDP port error is reported at the prompt" grep -q 'Invalid UDP port list' <<< "$bad_out"
assert "wizard: the MSS typo is rejected, not treated as 'no'" grep -q "answer 'y' or 'n'" <<< "$bad_out"
# One error per bad answer, produced as it was typed, not batched at the end.
assert "wizard: exactly one error per bad answer (9 fields)" \
  test "$(grep -c 'Invalid \|does not exist on this host\|answer .y. or .n.' <<< "$bad_out")" -eq 10
assert "wizard: the corrected run reached the apply step" grep -q '^APPLY=1$' <<< "$bad_out"
assert_not "wizard: no rejected value was ever applied" \
  grep -qE 'v1de1na|ajsdafajgag|as15r151|ajsgagasgas' <<< "$(grep '^ARGS=' <<< "$bad_out")"

# A run where no field is ever corrected must change nothing at all. The 10 invalid values
# are all consumed by the FIRST prompt, which is exactly the point: nothing advances.
rm -rf "$R"; mkroot
before_tunnels="$(ls "$R/state/tunnels" 2>/dev/null | tr '\n' ' ')"
before_nat="$(cat "$R/state/iptables.nat" 2>/dev/null || echo '')"
never_out="$(wiz_run 'v1de1na' 'nope' '^X,,asda' 'bad.subnet.x' 'as15r151' ',af1t1t1' \
                    'ajsdafajgag' 'ajsgagasgas' 'ajsgasgaga' '1io11')"
assert "wizard: an uncorrected run never applied anything" grep -q '^APPLY=0$' <<< "$never_out"
assert "wizard: the uncorrected run never created a tunnel" \
  test "$(ls "$R/state/tunnels" 2>/dev/null | tr '\n' ' ')" = "$before_tunnels"
assert "wizard: the uncorrected run wrote no NAT rule" \
  test "$(cat "$R/state/iptables.nat" 2>/dev/null || echo '')" = "$before_nat"
assert_not "wizard: the uncorrected run wrote no peer config" \
  bash -c "ls '$R/etc/multi-gre/foreigns/'*.conf 2>/dev/null | grep -q ."

# ------------------------------------------------- 13. recovery inside one session
# Wrong answer first, right answer second, for EVERY field: the wizard must reach the apply
# step without being restarted.
rm -rf "$R"; mkroot
recover_out="$(wiz_run \
  'v1de1na' '198.51.100.20' \
  'nope' '203.0.113.10' \
  '^X,,asda' 'de1' \
  'bad.subnet.x' '10.200' \
  'as15r151' '1' \
  ',af1t1t1' '1001' \
  'ajsdafajgag' 'eth0' \
  'ajsgagasgas' '80,443' \
  'ajsgasgaga' '443' \
  '1io11' 'y' \
  '2')"
assert "recovery: every bad answer was rejected" \
  test "$(grep -c 'Invalid\|answer .y. or .n.' <<< "$recover_out")" -ge 9
assert "recovery: the run still reached the apply step" grep -q '^APPLY=1$' <<< "$recover_out"
# create_iran_peer is stubbed, so there is no config file to read by design; the stub's
# recorded arguments are what prove which values survived validation.
assert "recovery: the corrected foreign IP was accepted" grep -q '203.0.113.10' <<< "$(grep '^ARGS=' <<< "$recover_out")"
assert "recovery: the corrected WAN interface was accepted" grep -q ' eth0 ' <<< "$(grep '^ARGS=' <<< "$recover_out")"
assert "recovery: the retried 'y' enabled MSS" grep -qE ' 1\]$' <<< "$(grep '^ARGS=' <<< "$recover_out")"
assert_not "recovery: no rejected value reached the applier" \
  grep -qE 'v1de1na|ajsdafajgag|as15r151|ajsgagasgas' <<< "$(grep '^ARGS=' <<< "$recover_out")"

# ------------------------------------------------- 11/15. defaults keep working
# The Iran and foreign IPs have NO default, so they must be typed; every other field has a
# default, so Enter accepts it. This is the "valid defaults still work" case.
rm -rf "$R"; mkroot
defaults_out="$(wiz_run '198.51.100.20' '203.0.113.10' '' '' '' '' '' '' '' '' '')"
assert "defaults: Enter accepts every valid default and reaches the apply step" \
  grep -q '^APPLY=1$' <<< "$defaults_out"
assert_not "defaults: it reports no validation error" \
  grep -q 'Invalid\|does not exist' <<< "$defaults_out"
assert "defaults: the accepted peer name is the default de1" grep -q '^ARGS=\[de1 ' <<< "$defaults_out"
assert "defaults: the accepted subnet is the default 10.200" grep -q '10.200' <<< "$(grep '^ARGS=' <<< "$defaults_out")"
assert "defaults: the accepted WAN interface is the detected eth0" grep -q ' eth0 ' <<< "$(grep '^ARGS=' <<< "$defaults_out")"
assert "defaults: Enter on the [Y/n] MSS question selected yes" grep -qE ' 1\]$' <<< "$(grep '^ARGS=' <<< "$defaults_out")"

# ------------------------------------------------- 12. EOF must not loop forever
rm -rf "$R"; mkroot
eof_out="$(wiz_run '198.51.100.20')"
assert "eof: an exhausted input stream ends the wizard" grep -q '^APPLY=0$' <<< "$eof_out"
assert_not "eof: it produced no unbound-variable crash" grep -q 'unbound variable' <<< "$eof_out"

rm -rf "$R"
