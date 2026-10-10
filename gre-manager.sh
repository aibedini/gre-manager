#!/usr/bin/env bash
#
# gre-manager.sh — Multi-GRE Tunnel Manager
# https://github.com/aibedini/gre-manager
#
# Manage multiple GRE tunnels:
#   - many IRAN servers  <-> one FOREIGN server   (nodes on the foreign side)
#   - one IRAN server    <-> many FOREIGN servers (peers on the Iran side, v2)
#
# Layout:
#   - Each IRAN node gets its own tunnel, subnet and GRE key:
#       node ir01 -> gre-ir01, 10.200.1.0/30  (foreign .1, iran .2), key 1001
#       node ir02 -> gre-ir02, 10.200.2.0/30, key 1002 ...
#   - v2: the IRAN side can hold several independent foreign peers, each with
#     its own tunnel, subnet base, GRE key and forwarded ports:
#       peer de1 -> gre-de1, 10.200.1.0/30, key 1001
#       peer nl1 -> gre-nl1, 10.201.1.0/30, key 1001 ...
#   - IRAN side: DNAT selected TCP/UDP ports (arriving on the public IP)
#     into the tunnel towards the foreign server + SNAT on the tunnel.
#     Every (WAN interface, Iran IP, protocol, port) tuple belongs to exactly
#     ONE foreign peer; overlaps are rejected.
#   - FOREIGN side: one GRE tunnel per Iran node. Services (e.g. Xray)
#     listen on 0.0.0.0 and are reachable through every tunnel.
#   - Persistence via a oneshot systemd unit that re-applies config at boot,
#     plus a watchdog timer that re-applies dead tunnels every minute.
#
# State:
#   /etc/multi-gre/foreign.conf        FOREIGN_IP=..., ICMP_DROP=0|1, GRE_WHITELIST=0|1
#   /etc/multi-gre/nodes/<name>.conf   one file per Iran node (foreign side, + optional SUBNET_BASE)
#   /etc/multi-gre/iran.conf           v2: manifest only (SCHEMA_VERSION=2, ROLE_IRAN=1)
#   /etc/multi-gre/foreigns/<name>.conf one file per foreign peer (Iran side, v2)
#
# CLI:
#   gre                 interactive menu
#   gre --apply         bring up everything that is configured   (used by systemd)
#   gre --stop          tear everything down (config is kept)    (used by systemd)
#   gre --watchdog      check tunnels, re-apply dead ones        (used by systemd timer)
#   gre status [--json] show status (machine-readable JSON with --json)
#   gre doctor          diagnostics: PASS/WARN/FAIL per check, non-zero exit on FAIL
#   gre node list [--json]                              list Iran nodes (FOREIGN)
#   gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
#   gre node remove --name NAME [--yes]
#   gre iran peer list [--json]                         list foreign peers (IRAN)
#   gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B]
#                     [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
#                     [--udp-ports LIST] [--mss-clamp on|off] [--yes]
#   gre iran peer remove --name NAME [--yes]
#   gre iran peer apply --name NAME
#   gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
#                  [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
#                  [--mss-clamp on|off] [--yes]     (creates the FIRST peer only)
#   gre foreign-setup [--foreign-ip IP] [--gre-whitelist on|off]
#                  [--icmp-drop on|off] [--downtime MIN] [--yes]
#   gre export [path] [--yes]   back up /etc/multi-gre to a tar.gz archive
#   gre import <file> [--yes]   restore a backup made by 'gre export'
#   gre watchdog        watchdog timer: enable|disable|status
#   gre update          self-update to the latest version from GitHub
#   gre --version       print version
#   gre --help          usage
#
# shellcheck shell=bash
# shellcheck disable=SC1090  # config files under /etc/multi-gre are validated then sourced by design
set -uo pipefail

VERSION="2.17.0"

GITHUB_REPO="aibedini/gre-manager"

CONF_DIR="/etc/multi-gre"
NODES_DIR="$CONF_DIR/nodes"
FOREIGNS_DIR="$CONF_DIR/foreigns"
GLOBAL_CONF="$CONF_DIR/global.conf"
FOREIGN_CONF="$CONF_DIR/foreign.conf"
IRAN_CONF="$CONF_DIR/iran.conf"
SYSCTL_FILE="/etc/sysctl.d/99-multi-gre.conf"
SERVICE_FILE="/etc/systemd/system/multi-gre.service"
WATCHDOG_SERVICE_FILE="/etc/systemd/system/multi-gre-watchdog.service"
WATCHDOG_TIMER_FILE="/etc/systemd/system/multi-gre-watchdog.timer"
INSTALL_PATH="/usr/local/sbin/gre"
AUDIT_LOG="/var/log/gre-manager.log"
DEFAULT_SUBNET_BASE="10.200"
TUN_MTU=1476

# Fields allowed in a v2 peer conf (foreigns/<name>.conf); used by the
# validate-then-source loader. Never add free-form fields without validating.
PEER_CONF_FIELDS_RE='NAME|FOREIGN_IP|IRAN_IP|WAN_IF|SUBNET_BASE|IDX|KEY|TUN|TCP_PORTS|UDP_PORTS|MSS_CLAMP|MTU|NIC_MTU'
OVERLAP_DESC=""   # filled by port_lists_overlap on success

# ---------------------------------------------------------------- colors/log
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    C_CYAN="$(tput setaf 6 2>/dev/null || true)"
    C_GREEN="$(tput setaf 2 2>/dev/null || true)"
    C_YELLOW="$(tput setaf 3 2>/dev/null || true)"
    C_RED="$(tput setaf 1 2>/dev/null || true)"
    C_BOLD="$(tput bold 2>/dev/null || true)"
    C_RESET="$(tput sgr0 2>/dev/null || true)"
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_RESET=""
fi

info() { printf '%s[*]%s %s\n'  "$C_CYAN"   "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*"; }
err()  { printf '%s[x]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; }

audit_log() { # append a line to the audit log (never fails the caller)
    printf '%s user=%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$(whoami 2>/dev/null || echo '?')" "$*" >> "$AUDIT_LOG" 2>/dev/null || true
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        err "This script must be run as root (use: sudo gre)."
        exit 1
    fi
}

confirm() { # confirm "question"  -> 0 on yes (default: NO)
    local ans
    read -rp "$1 [y/N]: " ans
    [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

confirm_yes() { # confirm_yes "question" -> 0 on yes (default: YES)
    local ans
    read -rp "$1 [Y/n]: " ans
    [[ -z "$ans" || "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

ask() { # ask VAR "prompt" ["default"]
    local __var="$1" __prompt="$2" __default="${3:-}" __input=""
    if [[ -n "$__default" ]]; then
        read -rp "$__prompt [$__default]: " __input
        __input="${__input:-$__default}"
    else
        read -rp "$__prompt: " __input
    fi
    printf -v "$__var" '%s' "$__input"
}

# ------------------------------------------------------------- validators
valid_ip() {
    local ip="$1" o
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    local IFS='.'
    read -ra o <<< "$ip"
    local part
    for part in "${o[@]}"; do
        (( part >= 0 && part <= 255 )) || return 1
    done
    return 0
}

valid_name() {
    # Linux interface names are limited to 15 characters; tunnels use gre-NAME.
    [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,10}$ ]]
}

valid_version() { # stable SemVer used by releases (major.minor.patch)
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

version_is_newer() { # candidate current -> 0 only when candidate > current
    local candidate="$1" current="$2" i c n
    local IFS='.'
    local -a candidate_parts=() current_parts=()
    valid_version "$candidate" && valid_version "$current" || return 1
    read -ra candidate_parts <<< "$candidate"
    read -ra current_parts <<< "$current"
    for i in 0 1 2; do
        c=$((10#${candidate_parts[$i]}))
        n=$((10#${current_parts[$i]}))
        (( c > n )) && return 0
        (( c < n )) && return 1
    done
    return 1
}

valid_port_list() { # comma list of ports or a:b ranges, max 15 (multiport limit)
    local list="$1" p a b
    [[ -z "$list" ]] && return 0
    [[ "$list" =~ ^[0-9,:]+$ ]] || return 1
    local IFS=','
    read -ra p <<< "$list"
    unset IFS
    (( ${#p[@]} >= 1 && ${#p[@]} <= 15 )) || return 1
    local item
    for item in "${p[@]}"; do
        if [[ "$item" == *:* ]]; then
            a="${item%%:*}"; b="${item##*:}"
            [[ -n "$a" && -n "$b" ]] || return 1
            (( a >= 1 && a <= 65535 && b >= 1 && b <= 65535 && a <= b )) || return 1
        else
            (( item >= 1 && item <= 65535 )) || return 1
        fi
    done
    return 0
}

port_list_covers_22() {
    local list="$1" item a b p
    [[ -z "$list" ]] && return 1
    local IFS=','
    read -ra p <<< "$list"
    unset IFS
    for item in "${p[@]}"; do
        if [[ "$item" == *:* ]]; then
            a="${item%%:*}"; b="${item##*:}"
            (( a <= 22 && 22 <= b )) && return 0
        else
            (( item == 22 )) && return 0
        fi
    done
    return 1
}

valid_subnet_base() { # A.B prefix of the tunnel /30 (e.g. 10.200 -> 10.200.IDX.0/30)
    local base="$1"
    [[ "$base" =~ ^([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    (( BASH_REMATCH[1] <= 255 && BASH_REMATCH[2] <= 255 )) || return 1
    return 0
}

valid_iface() { # Linux interface name (IFNAMSIZ: max 15 chars, no spaces/slashes)
    [[ "$1" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]]
}

# Validate a conf file BEFORE sourcing: only KEY=VALUE lines with whitelisted
# keys and values from a safe charset (no quotes, $, backticks, spaces ...).
validate_conf_file() { # validate_conf_file FILE ALLOWED_KEYS_REGEX
    local f="$1" keys_re="$2" line key val
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || return 1
        key="${line%%=*}"; val="${line#*=}"
        [[ "$key" =~ ^($keys_re)$ ]] || return 1
        [[ "$val" =~ ^[a-zA-Z0-9.,:_|+-]*$ ]] || return 1
    done < "$f"
    return 0
}

# Full range-aware overlap check between two comma port lists
# (80:90 vs 85 overlaps; caller keeps TCP and UDP checks independent).
port_lists_overlap() { # list1 list2 -> 0 if overlapping (OVERLAP_DESC is set)
    local l1="$1" l2="$2" i1 i2 a1 b1 a2 b2
    [[ -z "$l1" || -z "$l2" ]] && return 1
    local IFS=','
    local -a p1=() p2=()
    read -ra p1 <<< "$l1"
    read -ra p2 <<< "$l2"
    unset IFS
    for i1 in "${p1[@]}"; do
        a1="${i1%%:*}"; b1="$a1"; [[ "$i1" == *:* ]] && b1="${i1##*:}"
        for i2 in "${p2[@]}"; do
            a2="${i2%%:*}"; b2="$a2"; [[ "$i2" == *:* ]] && b2="${i2##*:}"
            if (( a1 <= b2 && a2 <= b1 )); then
                OVERLAP_DESC="$i1 vs $i2"
                return 0
            fi
        done
    done
    return 1
}

# ------------------------------------------------------------- port conflicts
port_in_use() { # proto(tcp|udp) port -> 0 if a local service listens on it
    local proto="$1" port="$2"
    command -v ss >/dev/null 2>&1 || return 1
    # note: herestring, not a pipe — grep -q exiting early would SIGPIPE the
    # producer and pipefail would flip the result (false "port free")
    case "$proto" in
        tcp) grep -q . <<< "$(ss -tlnH "sport = :$port" 2>/dev/null)" ;;
        udp) grep -q . <<< "$(ss -ulnH "sport = :$port" 2>/dev/null)" ;;
        *)   return 1 ;;
    esac
}

# Call a callback-style check for each port in a list; ranges are only checked
# at both endpoints (checking 65k ports one by one would be too slow).
warn_port_conflicts() { # proto(tcp|udp) list — warn for ports already listened on locally
    local proto="$1" list="$2" item a b port
    [[ -z "$list" ]] && return 0
    local IFS=','
    local -a items=()
    read -ra items <<< "$list"
    unset IFS
    for item in "${items[@]}"; do
        if [[ "$item" == *:* ]]; then
            a="${item%%:*}"; b="${item##*:}"
            for port in "$a" "$b"; do
                if port_in_use "$proto" "$port"; then
                    warn "Port $port/$proto (from range $item) is already listened on by a local service; forwarding it may not work as expected."
                fi
            done
        elif port_in_use "$proto" "$item"; then
            warn "Port $item/$proto is already listened on by a local service; forwarding it may not work as expected."
        fi
    done
    return 0
}

# ------------------------------------------------------------- detection
detect_wan_iface() {
    ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

detect_public_ip() {
    local ifc="$1" ip=""
    if [[ -n "$ifc" ]]; then
        ip="$(ip -4 -o addr show dev "$ifc" 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
    fi
    if [[ -z "$ip" ]]; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    fi
    printf '%s' "$ip"
}

tunnel_count() {
    ip tunnel show 2>/dev/null | grep -c '^gre-' || true
}

service_state() {
    systemctl is-enabled multi-gre.service 2>/dev/null || echo "disabled"
}

watchdog_state() {
    systemctl is-active multi-gre-watchdog.timer 2>/dev/null || echo "inactive"
}

# ------------------------------------------------------------- global config
# /etc/multi-gre/global.conf: DOWNTIME_TOLERANCE_MIN, WATCHDOG_INTERVAL_MIN, WATCHDOG_ENABLED
load_global_conf() { # sets WD_ENABLED / WD_INTERVAL_MIN / WD_TOLERANCE_MIN (with defaults)
    WD_ENABLED=1
    WD_INTERVAL_MIN=1
    WD_TOLERANCE_MIN=2
    [[ -f "$GLOBAL_CONF" ]] || return 0
    local v=""
    v="$(grep -E '^WATCHDOG_ENABLED=' "$GLOBAL_CONF" | cut -d= -f2)"
    [[ "$v" == "0" || "$v" == "1" ]] && WD_ENABLED="$v"
    v="$(grep -E '^WATCHDOG_INTERVAL_MIN=' "$GLOBAL_CONF" | cut -d= -f2)"
    [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 )) && WD_INTERVAL_MIN="$v"
    v="$(grep -E '^DOWNTIME_TOLERANCE_MIN=' "$GLOBAL_CONF" | cut -d= -f2)"
    [[ "$v" =~ ^[0-9]+$ ]] && WD_TOLERANCE_MIN="$v"
    return 0
}

write_global_conf() { # write_global_conf enabled interval_min tolerance_min
    mkdir -p "$CONF_DIR"
    cat > "$GLOBAL_CONF" <<EOF
WATCHDOG_ENABLED=$1
WATCHDOG_INTERVAL_MIN=$2
DOWNTIME_TOLERANCE_MIN=$3
EOF
    chmod 600 "$GLOBAL_CONF"
}

# ------------------------------------------------------------- peer model (IRAN, v2)
# A "peer" is one foreign server this Iran connects to: foreigns/<name>.conf.

peer_count() {
    local n=0 f
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        n=$(( n + 1 ))
    done
    printf '%s' "$n"
}

peer_exists() { [[ -f "$FOREIGNS_DIR/$1.conf" ]]; }

write_iran_manifest() { # v2 iran.conf: manifest only, no tunnel parameters
    mkdir -p "$CONF_DIR"
    cat > "$IRAN_CONF" <<EOF
SCHEMA_VERSION=2
ROLE_IRAN=1
EOF
    chmod 600 "$IRAN_CONF"
}

# Validate then source a peer conf. Sets the caller's NAME / FOREIGN_IP /
# IRAN_IP / WAN_IF / SUBNET_BASE / IDX / KEY / TUN / TCP_PORTS / UDP_PORTS /
# MSS_CLAMP variables (declare them local before calling; dynamic scope).
load_peer_conf() { # load_peer_conf FILE
    local f="$1"
    NAME=""; FOREIGN_IP=""; IRAN_IP=""; WAN_IF=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
    IDX=""; KEY=""; TUN=""; TCP_PORTS=""; UDP_PORTS=""; MSS_CLAMP="0"; MTU=""; NIC_MTU=""
    if ! validate_conf_file "$f" "$PEER_CONF_FIELDS_RE"; then
        err "Invalid or unsafe peer config: $f (unknown field or unsafe value)"
        return 1
    fi
    source "$f"
    [[ -z "$TUN" && -n "$NAME" ]] && TUN="gre-$NAME"
    # An absent MTU stays empty, meaning "no explicit override". It is never defaulted
    # here, so a connection written before this feature keeps whatever MTU its
    # interface already has instead of being silently moved onto a new value.
    validate_peer_values "quiet" || { err "Peer config $f contains invalid values."; return 1; }
    return 0
}

# Shared value validation for peer add/migrate. With "quiet" it only returns
# the status (caller prints one error), otherwise it explains the problem.
validate_peer_values() { # validate_peer_values ["quiet"]
    local quiet="${1:-}" e=0
    # MTU and NIC_MTU are optional fields introduced with the MTU feature. Callers that
    # predate it do not declare them, so they are defaulted here rather than assumed to
    # exist — under `set -u` an undeclared MTU would abort the whole command.
    local MTU="${MTU:-}" NIC_MTU="${NIC_MTU:-}"
    valid_ip "$IRAN_IP"          || { [[ -z "$quiet" ]] && err "Invalid Iran IP: '$IRAN_IP'"; e=1; }
    valid_ip "$FOREIGN_IP"       || { [[ -z "$quiet" ]] && err "Invalid foreign IP: '$FOREIGN_IP'"; e=1; }
    valid_name "$NAME"           || { [[ -z "$quiet" ]] && err "Invalid peer name: '$NAME' (use 1-11 letters, digits, '_' or '-'; start with a letter or digit)"; e=1; }
    valid_subnet_base "$SUBNET_BASE" || { [[ -z "$quiet" ]] && err "Invalid subnet base: '$SUBNET_BASE' (expected A.B, e.g. 10.201)"; e=1; }
    { [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )); } \
                                 || { [[ -z "$quiet" ]] && err "Invalid tunnel index: '$IDX' (1-254)"; e=1; }
    [[ "$KEY" =~ ^[0-9]+$ ]]     || { [[ -z "$quiet" ]] && err "Invalid GRE key: '$KEY'"; e=1; }
    valid_iface "$WAN_IF"        || { [[ -z "$quiet" ]] && err "Invalid WAN interface: '$WAN_IF'"; e=1; }
    valid_port_list "$TCP_PORTS" || { [[ -z "$quiet" ]] && err "Invalid TCP port list: '$TCP_PORTS'"; e=1; }
    valid_port_list "$UDP_PORTS" || { [[ -z "$quiet" ]] && err "Invalid UDP port list: '$UDP_PORTS'"; e=1; }
    [[ "$MSS_CLAMP" == "0" || "$MSS_CLAMP" == "1" ]] \
                                 || { [[ -z "$quiet" ]] && err "Invalid MSS_CLAMP: '$MSS_CLAMP' (0|1)"; e=1; }
    # MTU is optional: an empty value means "this connection has no explicit override",
    # which is how every configuration written before this feature keeps working.
    [[ -z "$MTU" ]] || valid_mtu "$MTU" \
                                 || { [[ -z "$quiet" ]] && err "Invalid MTU: '$MTU' (576-9000 for a GRE interface)"; e=1; }
    [[ -z "$NIC_MTU" ]] || valid_mtu "$NIC_MTU" \
                                 || { [[ -z "$quiet" ]] && err "Invalid NIC_MTU: '$NIC_MTU'"; e=1; }
    [[ -n "$TUN" && ${#TUN} -le 15 ]] \
                                 || { [[ -z "$quiet" ]] && err "Invalid tunnel name: '$TUN'"; e=1; }
    (( e == 0 ))
}

# Auto pool 10.200..10.254; first peer and legacy configs get 10.200.
next_free_subnet_base() {
    local used=" " f b
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"
        used+="${b:-$DEFAULT_SUBNET_BASE} "
    done
    local i
    for (( i = 200; i <= 254; i++ )); do
        if [[ "$used" != *" 10.$i "* ]]; then
            printf '10.%s' "$i"
            return 0
        fi
    done
    return 1
}

# First tunnel index free within the given subnet base (pair base+idx is unique).
next_free_peer_idx() { # next_free_peer_idx BASE
    local base="$1" used=" " f b idx=""
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; b="${b:-$DEFAULT_SUBNET_BASE}"
        [[ "$b" == "$base" ]] || continue
        idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        [[ -n "$idx" ]] && used+="$idx "
    done
    local i
    for (( i = 1; i <= 254; i++ )); do
        if [[ "$used" != *" $i "* ]]; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

port_covered_in_list() { # port_covered_in_list PORT "items with possible a-b ranges"
    local cand="$1" item a b
    for item in $2; do
        if [[ "$item" == *-* ]]; then
            a="${item%%-*}"; b="${item##*-}"
            (( a <= cand && cand <= b )) && return 0
        elif [[ "$item" == "$cand" ]]; then
            return 0
        fi
    done
    return 1
}

# Suggest a service port that collides with nothing: not in any other peer's
# same-protocol port list (singles and ranges), not listened on locally, != 22.
suggest_free_port() { # suggest_free_port PROTO(tcp|udp) [START]
    local proto="$1" cand="${2:-3001}"
    local used=" " f plist=""
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        if [[ "$proto" == "tcp" ]]; then
            plist="$(grep -E '^TCP_PORTS=' "$f" | cut -d= -f2)"
        else
            plist="$(grep -E '^UDP_PORTS=' "$f" | cut -d= -f2)"
        fi
        [[ -n "$plist" ]] || continue
        plist="${plist//:/-}"      # ranges 8000:8010 -> 8000-8010
        used+="${plist//,/ } "
    done
    while (( cand <= 65000 )); do
        if (( cand != 22 )) && ! port_covered_in_list "$cand" "$used" && ! port_in_use "$proto" "$cand"; then
            printf '%s' "$cand"
            return 0
        fi
        cand=$(( cand + 1 ))
    done
    return 1
}

# Central collision detection shared by menu, CLI, import and doctor.
# Checks (SUBNET_BASE,IDX) pair, tunnel name and port overlaps against all
# OTHER peers. Returns 1 (after printing the reason) on any conflict.
# Collision check against the other connections.
#
# EXCLUDE_NAME is the connection being edited. Excluding it is what stops a
# connection from being reported as colliding with itself — and during a rename
# there are TWO names to exclude, because the file on disk still carries the old
# one while the requested state carries the new one.
check_peer_collisions() { # check_peer_collisions NAME SUBNET_BASE IDX TUN TCP_PORTS UDP_PORTS [EXCLUDE_ALSO]
    local name="$1" base="$2" idx="$3" tun="$4" tcp="$5" udp="$6" exclude_also="${7:-}"
    local f p_name p_base p_idx p_tun p_tcp p_udp
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        p_name="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
        [[ "$p_name" == "$name" ]] && continue
        [[ -n "$exclude_also" && "$p_name" == "$exclude_also" ]] && continue
        p_base="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; p_base="${p_base:-$DEFAULT_SUBNET_BASE}"
        p_idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        p_tun="$(grep -E '^TUN=' "$f" | cut -d= -f2)"
        p_tcp="$(grep -E '^TCP_PORTS=' "$f" | cut -d= -f2)"
        p_udp="$(grep -E '^UDP_PORTS=' "$f" | cut -d= -f2)"
        if [[ "$p_base" == "$base" && "$p_idx" == "$idx" ]]; then
            err "Subnet/index ${base}.${idx} is already used by peer '$p_name'."
            return 1
        fi
        if [[ -n "$p_tun" && "$p_tun" == "$tun" ]]; then
            err "Tunnel name $tun is already used by peer '$p_name'."
            return 1
        fi
        if port_lists_overlap "$tcp" "$p_tcp"; then
            err "TCP port overlap with peer '$p_name' ($OVERLAP_DESC)."
            err "Each (WAN interface, Iran IP, protocol, port) tuple belongs to exactly ONE foreign."
            return 1
        fi
        if port_lists_overlap "$udp" "$p_udp"; then
            err "UDP port overlap with peer '$p_name' ($OVERLAP_DESC)."
            err "Each (WAN interface, Iran IP, protocol, port) tuple belongs to exactly ONE foreign."
            return 1
        fi
    done
    return 0
}

# The tunnel /30 of a new peer must not collide with existing local routes.
subnet_route_conflict() { # subnet_route_conflict BASE -> 0 if a local route covers BASE.*
    local base="$1"
    local esc="${base//./\\.}"
    grep -qE "^${esc}\." <<< "$(ip -4 route show 2>/dev/null | awk '{print $1}')" || return 1
    return 0
}

# ------------------------------------------------------------- migration v1 -> v2
iran_conf_is_legacy() { # v1 iran.conf holds tunnel params; v2 is a manifest
    [[ -f "$IRAN_CONF" ]] && grep -qE '^FOREIGN_IP=' "$IRAN_CONF"
}

# Atomic, idempotent migration of a legacy v1 iran.conf to foreigns/<name>.conf
# (SUBNET_BASE=10.200) + manifest. Keeps iran.conf.v1.bak (0600). A mixed
# old+new layout aborts instead of silently overwriting anything.
migrate_legacy_iran_conf() {
    iran_conf_is_legacy || return 0

    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    if ! validate_conf_file "$IRAN_CONF" "$PEER_CONF_FIELDS_RE"; then
        err "Legacy $IRAN_CONF failed validation (unknown field or unsafe value); refusing to migrate."
        return 1
    fi
    source "$IRAN_CONF"
    [[ -z "$TUN" && -n "$NAME" ]] && TUN="gre-$NAME"
    if ! validate_peer_values "quiet"; then
        err "Legacy $IRAN_CONF contains invalid values; refusing to migrate."
        return 1
    fi

    local peerf="$FOREIGNS_DIR/$NAME.conf" f="" n=0
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        n=$(( n + 1 ))
    done
    if (( n > 0 )); then
        # Resume after an interrupted migration: exactly one peer, identical to
        # what we would write. Anything else is an inconsistent mixed layout.
        if (( n == 1 )) && [[ -f "$peerf" ]] \
            && grep -qE "^FOREIGN_IP=$FOREIGN_IP\$" "$peerf" \
            && grep -qE "^IDX=$IDX\$" "$peerf" \
            && grep -qE "^KEY=$KEY\$" "$peerf"; then
            info "Resuming interrupted migration of peer '$NAME'..."
        else
            err "Inconsistent state: legacy v1 $IRAN_CONF AND v2 peers in $FOREIGNS_DIR both exist."
            err "Refusing to guess. Back up, then remove either $IRAN_CONF or the peers directory."
            return 1
        fi
    else
        info "Migrating legacy v1 iran.conf to the v2 peer layout (peer '$NAME')..."
        mkdir -p "$FOREIGNS_DIR"
        local tmp=""
        tmp="$(mktemp "$FOREIGNS_DIR/.migrate.XXXXXX")" || { err "mktemp failed"; return 1; }
        cat > "$tmp" <<EOF
NAME=$NAME
FOREIGN_IP=$FOREIGN_IP
IRAN_IP=$IRAN_IP
WAN_IF=$WAN_IF
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=$TUN
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
MSS_CLAMP=$MSS_CLAMP
${MTU:+MTU=$MTU}
${NIC_MTU:+NIC_MTU=$NIC_MTU}
EOF
        chmod 600 "$tmp"
        mv "$tmp" "$peerf" || { err "Could not install $peerf"; rm -f "$tmp"; return 1; }
    fi

    cp -p "$IRAN_CONF" "$IRAN_CONF.v1.bak" 2>/dev/null \
        && chmod 600 "$IRAN_CONF.v1.bak" \
        || warn "Could not keep a backup copy at $IRAN_CONF.v1.bak"
    write_iran_manifest
    audit_log "migrate-v1-to-v2 peer=$NAME base=$SUBNET_BASE idx=$IDX foreign=$FOREIGN_IP"
    ok "Migrated iran.conf -> foreigns/$NAME.conf (backup kept: iran.conf.v1.bak)"
    return 0
}

# ------------------------------------------------------------- UI helpers
dot_on()  { printf '%s●%s' "$C_GREEN"  "$C_RESET"; }
dot_off() { printf '%s○%s' "$C_RED"    "$C_RESET"; }
dot_mid() { printf '%s◐%s' "$C_YELLOW" "$C_RESET"; }

node_count() {
    local n=0 f
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        n=$(( n + 1 ))
    done
    printf '%s' "$n"
}

# ------------------------------------------------------------- coexistence helpers
gre_tunnel_names() { # all GRE/GRETAP tunnel names on this server (except gre0/gretap0 fallbacks)
    ip -o link show type gre    2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1
    ip -o link show type gretap 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1
}

managed_tunnel_names() { # tunnels managed by us (foreign nodes + iran peers)
    local f TUN=""
    for f in "$NODES_DIR"/*.conf "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        TUN="$(grep -E '^TUN=' "$f" | cut -d= -f2)"
        [[ -n "$TUN" ]] && printf '%s\n' "$TUN"
    done
}

unmanaged_gre_tunnels() { # GRE tunnels present but NOT created by gre-manager
    local t managed=""
    managed="$(managed_tunnel_names)"
    gre_tunnel_names | while IFS= read -r t; do
        [[ -n "$t" && "$t" != "gre0" && "$t" != "gretap0" && "$t" != "erspan0" ]] || continue
        # herestring, not a pipe: grep -q exiting on an early match would SIGPIPE
        # the producer; under pipefail that flips the pipeline to failure and
        # falsely reports a managed tunnel as unmanaged.
        grep -qx "$t" <<< "$managed" || printf '%s\n' "$t"
    done
}

pair_fingerprint() { # pair_fingerprint IRAN_IP FOREIGN_IP SUBNET_BASE IDX KEY — identical on both sides
    printf '%s <-> %s · %s.%s.0/30 · key %s' "$1" "$2" "$3" "$4" "$5"
}

# ============================================================ connection identity
#
# A connection needs an identity that survives a rename and an endpoint migration.
# The tunnel parameters cannot serve as that identity, because editing any of them
# is exactly what we want to do — so the id lives in a sidecar map next to the
# configs and is NEVER written into the .conf files themselves. That keeps every
# existing config byte-identical and keeps PEER_CONF_FIELDS_RE (which only allows
# [a-zA-Z0-9.,:_|+-]) untouched.
#
# When no id has been assigned yet, one is derived from the current pairing
# fingerprint. That means an existing installation correlates to a stable id on
# first look, without anyone having to migrate anything.
IDENTITY_FILE="$CONF_DIR/connections.identity"

# Stable, collision-free id for the given fingerprint.
connection_id_for() { # connection_id_for FINGERPRINT
    local fp="$1" line id
    if [[ -f "$IDENTITY_FILE" ]]; then
        while IFS=$'\t' read -r id line || [[ -n "$line" ]]; do
            [[ -n "$line" ]] || continue
            if [[ "$line" == "$fp" ]]; then
                printf '%s' "$id"
                return 0
            fi
        done < "$IDENTITY_FILE"
    fi
    # derive: deterministic, so the same pairing always maps to the same id
    printf 'conn-%s' "$(printf '%s' "$fp" | cksum | cut -d' ' -f1)"
}

# Record (or refresh) the fingerprint a connection id currently points at. Called
# after every successful mutation so a rename or migration keeps its id.
connection_id_remember() { # connection_id_remember ID FINGERPRINT
    local id="$1" fp="$2" tmp
    mkdir -p "$CONF_DIR"
    tmp="$(mktemp)"
    if [[ -f "$IDENTITY_FILE" ]]; then
        # Drop the old mapping for this id AND any other id claiming this
        # fingerprint, so the map stays one-to-one in both directions.
        awk -F'\t' -v id="$id" -v fp="$fp" '$1 != id && $2 != fp' "$IDENTITY_FILE" > "$tmp" 2>/dev/null || true
    fi
    printf '%s\t%s\n' "$id" "$fp" >> "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$IDENTITY_FILE"
}

# Forget a connection id entirely (on remove).
connection_id_forget() { # connection_id_forget ID
    local id="$1" tmp
    [[ -f "$IDENTITY_FILE" ]] || return 0
    tmp="$(mktemp)"
    awk -F'\t' -v id="$id" '$1 != id' "$IDENTITY_FILE" > "$tmp" 2>/dev/null || true
    chmod 600 "$tmp"
    mv "$tmp" "$IDENTITY_FILE"
}

# ---------------------------------------------------------- connection helpers
# The two endpoints of the connection, as this role sees them.
iran_side_ip() { # iran_side_ip IRAN_IP FOREIGN_IP -> whichever is ours
    if [[ -n "$IRAN_IP" ]]; then printf '%s' "$IRAN_IP"; else detect_public_ip "${WAN_IF:-}"; fi
}

# ------------------------------------------------------------ change planning
#
# The whole point of Edit: do NOT treat every change as remove+add. A port change
# is a rule update; only a change to the tunnel's own parameters needs the tunnel
# rebuilt. Getting this wrong is what turns "change 3001 to 3049" into a tunnel
# outage.
#
# Change classes:
#   A  rule-only       TCP ports, UDP ports, MSS clamp        -> no tunnel touch
#   B  tunnel recreate KEY, SUBNET_BASE, IDX, IRAN_IP,
#                      FOREIGN_IP, TUN, NAME(rename)          -> controlled rebuild
#   C  migration       a different PARENT SERVER              -> Hub only
#
# Sets these for the caller:
#   PLAN_CLASS        "A" | "B" | "NONE"
#   PLAN_FIELDS       space-separated changed field names
#   PLAN_TUNNEL       1 when the tunnel interface must be rebuilt
declare -a PLAN_FIELDS=()
PLAN_CLASS="NONE"
PLAN_TUNNEL=0

plan_reset() {
    PLAN_FIELDS=()
    PLAN_CLASS="NONE"
    PLAN_TUNNEL=0
}

plan_field_changed() { # plan_field_changed NAME
    PLAN_FIELDS+=("$1")
}

# Is this field tunnel-affecting (forces a rebuild) or rule-affecting?
plan_is_tunnel_field() {
    case "$1" in
        KEY|SUBNET_BASE|IDX|IRAN_IP|FOREIGN_IP|TUN|NAME) return 0 ;;
        *) return 1 ;;
    esac
}

plan_is_rule_field() {
    case "$1" in
        TCP_PORTS|UDP_PORTS|MSS_CLAMP|MTU) return 0 ;;
        *) return 1 ;;
    esac
}

# Seed the requested state from the current state.
#
# Every caller starts here and then overrides only what it was asked to change. That
# is what makes "an option you did not pass keeps its current value" true by
# construction rather than by a chain of fallbacks, and it removes the ambiguity
# between "not mentioned" and "explicitly set to empty" — the caller always assigns
# a concrete value before the diff runs.
plan_request_from_current() { # plan_request_from_current (uses EDIT_OLD_*)
    PLAN_REQ_NAME="$EDIT_OLD_NAME"
    PLAN_REQ_FOREIGN_IP="$EDIT_OLD_FOREIGN_IP"
    PLAN_REQ_IRAN_IP="$EDIT_OLD_IRAN_IP"
    PLAN_REQ_WAN_IF="$EDIT_OLD_WAN_IF"
    PLAN_REQ_SUBNET_BASE="$EDIT_OLD_SUBNET_BASE"
    PLAN_REQ_IDX="$EDIT_OLD_IDX"
    PLAN_REQ_KEY="$EDIT_OLD_KEY"
    PLAN_REQ_TUN="$EDIT_OLD_TUN"
    PLAN_REQ_TCP_PORTS="$EDIT_OLD_TCP"
    PLAN_REQ_UDP_PORTS="$EDIT_OLD_UDP"
    PLAN_REQ_MSS_CLAMP="${EDIT_OLD_MSS:-0}"
    # An empty MTU means "no explicit override yet". Seeding it from the current
    # effective MTU would silently rewrite every existing configuration the first time
    # any unrelated field was edited, so an unset override stays unset.
    PLAN_REQ_MTU="${EDIT_OLD_MTU:-}"
}

# Compare the requested state against the current one and classify the change.
#
# Deliberately explicit: one case arm per field, no indirect expansion and no
# "empty means keep" inference. Every PLAN_REQ_* var holds a real value by the time
# this runs (see plan_request_from_current), so the diff is a plain string compare.
#
#   A  rule-only       TCP/UDP ports, MSS clamp        -> the tunnel is not rebuilt
#   B  tunnel recreate KEY, SUBNET_BASE, IDX, IRAN_IP,
#                      FOREIGN_IP, TUN, NAME          -> controlled rebuild
plan_edit() {
    plan_reset
    local field
    for field in NAME FOREIGN_IP IRAN_IP WAN_IF SUBNET_BASE IDX KEY TUN TCP_PORTS UDP_PORTS MSS_CLAMP MTU; do
        local cur="" req=""
        case "$field" in
            NAME)        cur="$EDIT_OLD_NAME";        req="$PLAN_REQ_NAME" ;;
            FOREIGN_IP)  cur="$EDIT_OLD_FOREIGN_IP";  req="$PLAN_REQ_FOREIGN_IP" ;;
            IRAN_IP)     cur="$EDIT_OLD_IRAN_IP";     req="$PLAN_REQ_IRAN_IP" ;;
            WAN_IF)      cur="$EDIT_OLD_WAN_IF";      req="$PLAN_REQ_WAN_IF" ;;
            SUBNET_BASE) cur="$EDIT_OLD_SUBNET_BASE"; req="$PLAN_REQ_SUBNET_BASE" ;;
            IDX)         cur="$EDIT_OLD_IDX";         req="$PLAN_REQ_IDX" ;;
            KEY)         cur="$EDIT_OLD_KEY";         req="$PLAN_REQ_KEY" ;;
            TUN)         cur="$EDIT_OLD_TUN";         req="$PLAN_REQ_TUN" ;;
            TCP_PORTS)   cur="$EDIT_OLD_TCP";         req="$PLAN_REQ_TCP_PORTS" ;;
            UDP_PORTS)   cur="$EDIT_OLD_UDP";         req="$PLAN_REQ_UDP_PORTS" ;;
            MSS_CLAMP)   cur="${EDIT_OLD_MSS:-0}";    req="$PLAN_REQ_MSS_CLAMP" ;;
            MTU)         cur="${EDIT_OLD_MTU:-}";     req="${PLAN_REQ_MTU:-}" ;;
        esac
        if [[ "$cur" != "$req" ]]; then
            plan_field_changed "$field"
            plan_is_tunnel_field "$field" && PLAN_TUNNEL=1
        fi
    done
    if (( ${#PLAN_FIELDS[@]} == 0 )); then
        PLAN_CLASS="NONE"
        return 0
    fi
    if (( PLAN_TUNNEL )); then
        PLAN_CLASS="B"
    else
        PLAN_CLASS="A"
    fi
    return 0
}

plan_class_label() {
    case "$1" in
        A) printf 'rule-only update (the tunnel is not rebuilt)' ;;
        B) printf 'tunnel recreation required' ;;
        C) printf 'server migration (make-before-break)' ;;
        *) printf 'no changes' ;;
    esac
}

# Human impact lines for the preview, derived from the plan rather than hardcoded.
plan_impact_lines() {
    local f
    (( PLAN_TUNNEL )) && printf '%s\n' "GRE tunnel recreation required"
    (( PLAN_TUNNEL )) && printf '%s\n' "Iran-side config will change"
    for f in "${PLAN_FIELDS[@]}"; do
        case "$f" in
            TCP_PORTS) printf '%s\n' "NAT TCP rules will change" ;;
            UDP_PORTS) printf '%s\n' "NAT UDP rules will change" ;;
            MSS_CLAMP) printf '%s\n' "MSS clamping will change" ;;
            MTU)       printf '%s\n' "Tunnel MTU will change in place (the interface is not rebuilt)" ;;
            IRAN_IP|FOREIGN_IP) printf '%s\n' "Endpoint addressing will change" ;;
            NAME)      printf '%s\n' "Connection renamed (config file, tunnel and rule comments)" ;;
            SUBNET_BASE|IDX) printf '%s\n' "Tunnel subnet will change" ;;
            KEY)       printf '%s\n' "GRE key will change" ;;
        esac
    done
    printf '%s\n' "Watchdog preserved"
    printf '%s\n' "Other connections are not touched"
}

# ------------------------------------------------- per-connection rule handling
#
# Every rule this project creates carries an ownership comment naming the peer:
#   multi-gre-iran-<name>-dnat-tcp | -dnat-udp | -snat | -mss
#   multi-gre-node-<name>
# That comment is what makes it possible to touch exactly one connection's rules
# and nothing else. Deletion is driven by the comment, never by a parameter sweep,
# so a rule belonging to another peer can never be matched by accident.
peer_rule_comment_prefix() { # peer_rule_comment_prefix NAME
    printf 'multi-gre-iran-%s' "$1"
}

node_rule_comment_prefix() { # node_rule_comment_prefix NAME
    printf 'multi-gre-node-%s' "$1"
}

# Remove the NAT/MSS rules for one peer, from an explicit set of values.
#
# Deletion is by exact rule spec built from a known configuration state, not by a
# wildcard sweep and not by line number. That is deliberate: it is impossible for
# this to remove a rule belonging to a different connection, because every spec
# carries this connection's own DNAT target subnet and its own comment. It also
# means the same function can remove the OLD rule set during an edit and the NEW
# one during a rollback.
peer_rules_remove() { # peer_rules_remove NAME TUN IRAN_IP WAN_IF SELF_IP PEER_IP TCP UDP MSS
    local NAME="$1" TUN="$2" IRAN_IP="$3" WAN_IF="$4" SELF_IP="$5" PEER_IP="$6" \
          TCP_PORTS="$7" UDP_PORTS="$8" MSS_CLAMP="$9"

    if [[ -n "$TCP_PORTS" ]]; then
        # Delete both the commented form and the legacy un-commented form, so an
        # edit also cleans up rules written by an older release.
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -j DNAT --to-destination "$PEER_IP"
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-tcp" -j DNAT --to-destination "$PEER_IP"
    fi
    if [[ -n "$UDP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -j DNAT --to-destination "$PEER_IP"
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-udp" -j DNAT --to-destination "$PEER_IP"
    fi
    ipt_del nat POSTROUTING -o "$TUN" -d "$PEER_IP" \
        -m comment --comment "multi-gre-iran-$NAME-snat" -j SNAT --to-source "$SELF_IP"
    # The MSS rules are deleted by OWNERSHIP COMMENT rather than by full specification.
    #
    # The installed rule carries the MSS value inside its specification, and that value
    # changes with the tunnel MTU. Deleting by exact spec would therefore miss the rule
    # written for a previous MTU and leave two clamps on the same interface — the second
    # one overriding the first with a value that no longer matches the tunnel. The
    # comment already identifies the connection, and an MSS clamp is per-connection, so
    # removing every rule this connection owns is both sufficient and complete.
    local comment="multi-gre-iran-$NAME-mss"
    ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "$comment*" -j TCPMSS
    ipt_del mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "$comment-fwd*" -j TCPMSS
    # Legacy forms: v1.0.0 wrote the rule with no comment at all, in POSTROUTING only.
    ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu
    return 0
}

# Install the NAT/MSS rules for a peer.
#
# Takes the two tunnel ADDRESSES explicitly rather than a subnet base and index,
# because the only thing this needs is "which address do I translate to". Passing
# the decomposition as well invited a positional-parameter mistake ("$10" expands
# as "$1" followed by "0"), and a silently shifted argument list here means rules
# installed against the wrong peer address.
peer_rules_install() { # peer_rules_install NAME TUN IRAN_IP WAN_IF SELF_IP PEER_IP TCP UDP MSS [MTU]
    local NAME="$1" TUN="$2" IRAN_IP="$3" WAN_IF="$4" SELF_IP="$5" PEER_IP="$6" \
          TCP_PORTS="$7" UDP_PORTS="$8" MSS_CLAMP="$9"
    local MTU="${10:-}"

    if [[ -n "$TCP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -j DNAT --to-destination "$PEER_IP"
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-tcp" -j DNAT --to-destination "$PEER_IP"
    fi
    if [[ -n "$UDP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -j DNAT --to-destination "$PEER_IP"
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-udp" -j DNAT --to-destination "$PEER_IP"
    fi
    if [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
        ipt_del nat POSTROUTING -o "$TUN" -d "$PEER_IP" -j SNAT --to-source "$SELF_IP"
        ipt_add nat POSTROUTING -o "$TUN" -d "$PEER_IP" \
            -m comment --comment "multi-gre-iran-$NAME-snat" -j SNAT --to-source "$SELF_IP"
    fi

    # --- TCP MSS clamping
    #
    # This used to be `--clamp-mss-to-pmtu`. That target derives the MSS from the
    # ROUTE's MTU, and for a packet leaving through a GRE tunnel the route is the
    # underlay one, so it commonly computes an MSS for the underlay (e.g. 1460) rather
    # than for the tunnel (e.g. 1436). The result is a SYN advertising an MSS the tunnel
    # cannot carry, which is precisely the broken-PMTU stall the rule was meant to
    # prevent. The tunnel's own MTU is known here, so the MSS is set EXPLICITLY from it.
    #
    # 40 = 20-byte IPv4 header + 20-byte TCP header.
    #
    # When no MTU was passed (a connection with no stored override, which is every
    # connection created before this feature), the LIVE interface MTU is used instead of
    # falling back to the unreliable pmtu-derived clamp. The interface is already up at
    # this point, so its MTU is known even when the config has no explicit value.
    local eff_mtu="$MTU"
    [[ -n "$eff_mtu" ]] || eff_mtu="$(iface_mtu "$TUN")"
    if [[ "${MSS_CLAMP:-0}" == "1" && -n "$eff_mtu" ]]; then
        local mss=$(( eff_mtu - 40 ))
        if (( mss < 536 )); then
            warn "[$NAME] tunnel MTU $eff_mtu leaves an MSS below the IPv4 minimum; not clamping."
        else
            # Remove any previous clamp for THIS connection before writing the new one.
            # Deletion is by ownership comment rather than by full specification, because
            # the MSS value is part of the spec and changes with the tunnel MTU: an
            # exact-spec delete would leave the rule written for the previous MTU in
            # place, and two clamps on one interface means the older one can win.
            ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment "multi-gre-iran-$NAME-mss*" -j TCPMSS
            # The FORWARD clamp covers forwarded traffic, which is where a PMTUD stall
            # actually bites and which is not guaranteed to traverse the POSTROUTING
            # hook of the ingress path just covered.
            ipt_del mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment "multi-gre-iran-$NAME-mss-fwd*" -j TCPMSS
            # Legacy v1.0.0 wrote the clamp with no ownership comment at all, so a
            # comment pattern can never match it. It is removed by its exact
            # specification instead, in both chains.
            ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu
            ipt_del mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu
            ipt_add mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment "multi-gre-iran-$NAME-mss" -j TCPMSS --set-mss "$mss"
            ipt_add mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment "multi-gre-iran-$NAME-mss-fwd" -j TCPMSS --set-mss "$mss"
            ok "[$NAME] TCP MSS clamped to $mss (tunnel MTU $eff_mtu)"
        fi
    elif [[ "${MSS_CLAMP:-0}" == "1" ]]; then
        # No MTU could be determined at all. Rather than writing a clamp derived from the
        # underlay's MTU (which is the defect this replaced), leave the existing rule set
        # alone and say what is missing.
        warn "[$NAME] tunnel MTU is unknown, so the MSS clamp was not written. Set one explicitly: gre mtu set --name $NAME --mtu VALUE"
    fi
    return 0
}

# Is every port in this list free for the connection being edited?
#
# Checks the local listener table and every OTHER connection's rule set. The
# connection's own current ports are excluded, so editing 3001 -> 3049 does not
# report 3001 as a collision with itself. Add-time validators are reused rather
# than reimplemented.
port_available_for_edit() { # port_available_for_edit PROTO PORTS EXCLUDE_NAME
    local proto="$1" ports="$2" exclude="$3" p
    local old_ifs="$IFS"
    IFS=,
    for p in $ports; do
        local lo hi n
        case "$p" in
            *:*) lo="${p%%:*}"; hi="${p##*:}" ;;
            *)   lo="$p"; hi="$p" ;;
        esac
        for (( n = lo; n <= hi; n++ )); do
            local f p_name other
            for f in "$FOREIGNS_DIR"/*.conf; do
                [[ -e "$f" ]] || continue
                p_name="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
                [[ -n "$exclude" && "$p_name" == "$exclude" ]] && continue
                if [[ "$proto" == "tcp" ]]; then
                    other="$(grep -E '^TCP_PORTS=' "$f" | cut -d= -f2)"
                else
                    other="$(grep -E '^UDP_PORTS=' "$f" | cut -d= -f2)"
                fi
                [[ -z "$other" ]] && continue
                if port_lists_overlap "$n" "$other"; then
                    IFS="$old_ifs"
                    return 1
                fi
            done
        done
    done
    IFS="$old_ifs"
    return 0
}

# ------------------------------------------------------------------ transactions
#
# An edit is a transaction: snapshot, apply, verify, and on any failure put the
# previous connection back exactly as it was. The operator must never have to
# rebuild a connection by hand after a failed edit.
#
# The snapshot captures the config file bytes AND enough state to reconstruct the
# rules and the tunnel, because restoring the file alone would leave a half-applied
# rule set behind.
EDIT_TXN_DIR=""

edit_txn_begin() { # edit_txn_begin
    EDIT_TXN_DIR="$(mktemp -d)"
    mkdir -p "$EDIT_TXN_DIR"
}

edit_txn_snapshot_file() { # edit_txn_snapshot_file LABEL FILE
    local label="$1" file="$2"
    if [[ -f "$file" ]]; then
        cp -p "$file" "$EDIT_TXN_DIR/$label.conf"
        printf '1' > "$EDIT_TXN_DIR/$label.existed"
    else
        printf '0' > "$EDIT_TXN_DIR/$label.existed"
    fi
}

# Restore a snapshotted file: byte-identical if it existed, removed if it did not.
edit_txn_restore_file() { # edit_txn_restore_file LABEL FILE
    local label="$1" file="$2"
    if [[ "$(cat "$EDIT_TXN_DIR/$label.existed" 2>/dev/null)" == "1" ]]; then
        cp -p "$EDIT_TXN_DIR/$label.conf" "$file"
        chmod 600 "$file" 2>/dev/null || true
    else
        rm -f "$file"
    fi
}

edit_txn_commit() {
    [[ -n "$EDIT_TXN_DIR" && -d "$EDIT_TXN_DIR" ]] && rm -rf "$EDIT_TXN_DIR"
    EDIT_TXN_DIR=""
}

# =================================================== transactional connection edit
#
# Edit is NOT remove+add. The difference matters in three places:
#
#   1. A rule-only change (ports, MSS) never rebuilds the tunnel. The old rules are
#      removed and the new ones installed while the tunnel stays up, so changing
#      3001 -> 3049 costs no outage at all.
#   2. New rules are installed BEFORE the old ones are removed where the port sets
#      are disjoint. That way a failure to install the new rule leaves the old one
#      working instead of leaving the connection with neither.
#   3. Any failure restores the previous connection from a snapshot taken before the
#      first mutation — config bytes, tunnel and rules. The operator never has to
#      rebuild by hand.
#
# The snapshot is the reason step 3 is honest: it is taken from disk, not from
# memory, and it is restored by writing the file back byte-for-byte.

# Capture everything needed to put a connection back exactly as it is now.
edit_snapshot_current() { # edit_snapshot_current SIDE NAME (sets EDIT_OLD_*)
    local side="$1" name="$2" file
    # The preview snapshots without applying, so the transaction directory has to be
    # available for reading a snapshot too — not only for a mutation. Opening it
    # here is idempotent.
    [[ -n "$EDIT_TXN_DIR" && -d "$EDIT_TXN_DIR" ]] || edit_txn_begin
    if [[ "$side" == "iran" ]]; then
        file="$FOREIGNS_DIR/$name.conf"
    else
        file="$NODES_DIR/$name.conf"
    fi
    EDIT_OLD_FILE="$file"
    EDIT_OLD_EXISTED=0
    [[ -f "$file" ]] && EDIT_OLD_EXISTED=1
    edit_txn_snapshot_file "current" "$file"

    # Values in scope for rollback, so a failed apply can reinstall the old rules
    # without re-reading a file we may already have overwritten.
    EDIT_OLD_NAME=""; EDIT_OLD_FOREIGN_IP=""; EDIT_OLD_IRAN_IP=""; EDIT_OLD_WAN_IF=""
    EDIT_OLD_SUBNET_BASE="$DEFAULT_SUBNET_BASE"; EDIT_OLD_IDX=""; EDIT_OLD_KEY=""
    EDIT_OLD_TUN=""; EDIT_OLD_TCP=""; EDIT_OLD_UDP=""; EDIT_OLD_MSS="0"; EDIT_OLD_MTU=""
    if (( EDIT_OLD_EXISTED )); then
        if [[ "$side" == "iran" ]]; then
            local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
                  IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0" MTU=""
            load_peer_conf "$file" || return 1
            EDIT_OLD_NAME="$NAME"; EDIT_OLD_FOREIGN_IP="$FOREIGN_IP"; EDIT_OLD_IRAN_IP="$IRAN_IP"
            EDIT_OLD_WAN_IF="$WAN_IF"; EDIT_OLD_SUBNET_BASE="$SUBNET_BASE"; EDIT_OLD_IDX="$IDX"
            EDIT_OLD_KEY="$KEY"; EDIT_OLD_TUN="$TUN"; EDIT_OLD_TCP="$TCP_PORTS"
            EDIT_OLD_UDP="$UDP_PORTS"; EDIT_OLD_MSS="$MSS_CLAMP"
            # The MTU override, as stored. Empty means "no override", which is what
            # every configuration written before this feature looks like.
            EDIT_OLD_MTU="$MTU"
        else
            local NAME="" IRAN_IP="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" IDX="" KEY="" TUN="" MTU=""
            node_conf_read "$file" NAME IRAN_IP SUBNET_BASE IDX KEY TUN MTU
            EDIT_OLD_NAME="$NAME"; EDIT_OLD_IRAN_IP="$IRAN_IP"; EDIT_OLD_SUBNET_BASE="$SUBNET_BASE"
            EDIT_OLD_IDX="$IDX"; EDIT_OLD_KEY="$KEY"; EDIT_OLD_TUN="$TUN"
            EDIT_OLD_MSS="0"; EDIT_OLD_MTU="$MTU"
            # This host's own endpoint is not stored in a node config, so capture it
            # rather than reading a caller's global at rollback time. The live
            # interface is the most truthful source; foreign.conf is the fallback.
            EDIT_OLD_FOREIGN_IP="$(tunnel_local_endpoint "$TUN")"
            [[ -n "$EDIT_OLD_FOREIGN_IP" ]] || EDIT_OLD_FOREIGN_IP="$(foreign_local_ip)"
        fi
    fi
    return 0
}

# Put the connection back. Restores the config file, then rebuilds the tunnel and
# the rule set from the snapshot values — in that order, because the tunnel needs
# the interface name and the rules need the subnet.
edit_rollback() { # edit_rollback SIDE
    local side="$1"
    warn "Rolling back '${EDIT_OLD_NAME:-connection}' to its previous state..."

    # 1. Tear down whatever the failed attempt left behind.
    if [[ -n "${EDIT_NEW_TUN:-}" && "${EDIT_NEW_TUN}" != "${EDIT_OLD_TUN}" ]]; then
        delete_tunnel "$EDIT_NEW_TUN" >/dev/null 2>&1 || true
    fi
    if [[ "$side" == "iran" && -n "${EDIT_NEW_NAME:-}" ]]; then
        peer_rules_remove "$EDIT_NEW_NAME" "${EDIT_NEW_TUN:-}" "${EDIT_NEW_IRAN_IP:-}" \
            "${EDIT_NEW_WAN_IF:-}" "${EDIT_NEW_SUBNET_BASE}.${EDIT_NEW_IDX}.2" \
            "${EDIT_NEW_SUBNET_BASE}.${EDIT_NEW_IDX}.1" \
            "${EDIT_NEW_TCP:-}" "${EDIT_NEW_UDP:-}" "${EDIT_NEW_MSS:-0}" >/dev/null 2>&1 || true
    fi

    # 2. Restore the config file bytes.
    if (( EDIT_OLD_EXISTED )); then
        edit_txn_restore_file "current" "$EDIT_OLD_FILE"
    else
        rm -f "$EDIT_OLD_FILE"
    fi

    # 3. Rebuild the previous tunnel and rules from the snapshot values.
    if (( EDIT_OLD_EXISTED )); then
        if [[ "$side" == "iran" ]]; then
            create_tunnel "$EDIT_OLD_TUN" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_FOREIGN_IP" \
                "$EDIT_OLD_KEY" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.2/30" "${EDIT_OLD_MTU:-$TUN_MTU}" >/dev/null 2>&1 || true
            peer_rules_remove "$EDIT_OLD_NAME" "$EDIT_OLD_TUN" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_WAN_IF" \
                "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.2" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1" \
                "$EDIT_OLD_TCP" "$EDIT_OLD_UDP" "$EDIT_OLD_MSS" "${EDIT_OLD_MTU:-$TUN_MTU}" \
                >/dev/null 2>&1 || true
            peer_rules_install "$EDIT_OLD_NAME" "$EDIT_OLD_TUN" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_WAN_IF" \
                "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.2" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1" \
                "$EDIT_OLD_TCP" "$EDIT_OLD_UDP" "$EDIT_OLD_MSS" "${EDIT_OLD_MTU:-$TUN_MTU}" \
                >/dev/null 2>&1 || true
        else
            create_tunnel "$EDIT_OLD_TUN" "${EDIT_OLD_FOREIGN_IP:-$(foreign_local_ip)}" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_KEY" \
                "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1/30" "${EDIT_OLD_MTU:-$TUN_MTU}" >/dev/null 2>&1 || true
            # A rollback that silently fails is worse than no rollback: the operator
            # believes the old connection is back when there is no tunnel at all.
            if ! edit_verify_tunnel "$EDIT_OLD_TUN" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1/30" >/dev/null 2>&1; then
                err "Rollback could not restore tunnel '$EDIT_OLD_TUN' on this host."
                err "Check: gre tunnel diagnose --name $EDIT_OLD_NAME"
                return 1
            fi
        fi
    fi
    ok "Rolled back to the previous configuration of '${EDIT_OLD_NAME:-connection}'."
    return 0
}

# Roll back a failed edit and report the outcome honestly.
#
# Both failure paths end in the same place (commit the transaction, return 1), so
# they share one helper. The important part is the marker: callers and tests can
# assert on ROLLBACK_FAILED instead of having to guess from prose, and a rollback
# that could not be verified never reports success.
edit_fail_and_rollback() { # edit_fail_and_rollback SIDE REASON
    local side="$1" reason="$2"
    if edit_rollback "$side"; then
        edit_txn_commit
        return 1
    fi
    edit_txn_commit
    err "ROLLBACK_FAILED: '$reason' left the connection in an unknown state."
    err "  the previous configuration of '${EDIT_OLD_NAME:-?}' could NOT be restored."
    err "  inspect this host with:  gre status ; gre doctor"
    err "  then re-apply by hand:   gre iran peer edit --name ${EDIT_OLD_NAME:-NAME} --yes"
    err "                        or: gre node edit --name ${EDIT_OLD_NAME:-NAME} --yes"
    return 1
}

# The GRE key an interface is actually using, and where that answer came from.
#
# `ip -d tunnel show` does NOT reliably print the key: for a keyed tunnel the kernel often
# omits it, so treating "no key in the output" as "the interface carries no key" reports a
# correct tunnel as a fault. The fallback chain is explicit and the source is returned, so
# a caller can tell a live reading from a configured one and never presents the latter as
# proof of what the interface is doing.
#
# Echoes: "<key> <source>" where source is live | record | configured | none
tunnel_key_info() { # tunnel_key_info IFACE [CONFIGURED_KEY]
    local iface="${1:-}" configured="${2:-}" out="" key=""
    [[ -n "$iface" ]] || { printf 'none'; return; }
    out="$(ip -d tunnel show "$iface" 2>/dev/null || true)"
    key="$(sed -n 's/.*[[:space:]]key[[:space:]]\+\([0-9]\+\).*/\1/p' <<< "$out" | head -n1)"
    [[ -n "$key" ]] && { printf '%s live' "$key"; return; }
    if [[ -n "${TEST_ROOT:-}" && -r "${TEST_ROOT}/state/tunnels/${iface}" ]]; then
        key="$(sed -n 's/.*[[:space:]]key[[:space:]]\+\([0-9]\+\).*/\1/p' "${TEST_ROOT}/state/tunnels/${iface}" | head -n1)"
        [[ -n "$key" ]] && { printf '%s record' "$key"; return; }
    fi
    [[ -n "$configured" ]] && { printf '%s configured' "$configured"; return; }
    printf 'none'
}

# Does the connection's own interface exist and carry the expected local address?
# Deliberately modest: it proves the edit produced a live tunnel, without claiming
# to prove end-to-end reachability (that is doctor's job, and it needs both ends).
edit_verify_tunnel() { # edit_verify_tunnel TUN EXPECTED_LOCAL_CIDR
    local tun="$1" cidr="$2"
    tun_exists "$tun" || { err "Verification failed: tunnel $tun is not present after the edit."; return 1; }
    local out
    out="$(ip -4 addr show dev "$tun" 2>/dev/null)"
    [[ -n "$out" ]] || { err "Verification failed: tunnel $tun has no address information."; return 1; }
    local want="${cidr%%/*}"
    # Match "inet <want>/" anywhere in the output rather than a fixed field: real
    # `ip` output varies (peer suffixes, "secondary", flags) and pinning a column
    # makes this check fail for reasons that have nothing to do with the edit.
    grep -qE "inet ${want//./\\.}/" <<< "$out" \
        || { err "Verification failed: tunnel $tun expected address $want, output was: $(tr '\n' ' ' <<< "$out")"; return 1; }
    return 0
}

# The end-to-end edit transaction for one side.
#
# Returns 0 only when the requested state is live AND verified. On any failure the
# previous connection is restored and the return is non-zero, so a caller can never
# mistake a rolled-back edit for a successful one.
# shellcheck disable=SC2034  # PLAN_* are read by the callers/preview after this runs
edit_connection_txn() { # edit_connection_txn SIDE CURRENT_NAME
    local side="$1" current="$2"

    # The caller has already snapshotted the current state and populated the
    # requested state (see cli_iran_peer_edit / cli_node_edit). Re-snapshotting here
    # would be wrong as well as noisy: by this point PLAN_REQ_* describes the NEW
    # state, so overwriting EDIT_OLD_* from disk is unnecessary, and re-planning
    # would re-print the preview.
    if [[ -n "$EDIT_TXN_DIR" && -d "$EDIT_TXN_DIR" ]]; then
        : # transaction already open, snapshot already taken
    else
        edit_txn_begin
        if ! edit_snapshot_current "$side" "$current"; then
            err "Could not read the current configuration of '$current'."
            edit_txn_commit
            return 1
        fi
        plan_request_from_current
    fi

    plan_edit
    if [[ "$PLAN_CLASS" == "NONE" ]]; then
        info "No changes requested — nothing to do."
        edit_txn_commit
        return 0
    fi

    # --- validate the requested state --------------------------------
    # plan_request_from_current guarantees every PLAN_REQ_* holds a value, so these
    # are plain reads rather than a chain of fallbacks.
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0" MTU=""
    if [[ "$side" == "iran" ]]; then
        NAME="$PLAN_REQ_NAME"
        FOREIGN_IP="$PLAN_REQ_FOREIGN_IP"
        IRAN_IP="$PLAN_REQ_IRAN_IP"
        WAN_IF="$PLAN_REQ_WAN_IF"
        SUBNET_BASE="$PLAN_REQ_SUBNET_BASE"
        IDX="$PLAN_REQ_IDX"
        KEY="$PLAN_REQ_KEY"
        TUN="gre-$NAME"
        TCP_PORTS="$PLAN_REQ_TCP_PORTS"
        UDP_PORTS="$PLAN_REQ_UDP_PORTS"
        MSS_CLAMP="$PLAN_REQ_MSS_CLAMP"
        MTU="${PLAN_REQ_MTU:-}"
    else
        NAME="$PLAN_REQ_NAME"
        IRAN_IP="$PLAN_REQ_IRAN_IP"
        SUBNET_BASE="$PLAN_REQ_SUBNET_BASE"
        IDX="$PLAN_REQ_IDX"
        KEY="$PLAN_REQ_KEY"
        TUN="gre-$NAME"
        WAN_IF="$EDIT_OLD_WAN_IF"
        FOREIGN_IP="$PLAN_REQ_FOREIGN_IP"
        MTU="${PLAN_REQ_MTU:-}"
    fi

    # Record the requested state for rollback to clean up after.
    EDIT_NEW_NAME="$NAME"; EDIT_NEW_FOREIGN_IP="$FOREIGN_IP"; EDIT_NEW_IRAN_IP="$IRAN_IP"
    EDIT_NEW_WAN_IF="$WAN_IF"; EDIT_NEW_SUBNET_BASE="$SUBNET_BASE"; EDIT_NEW_IDX="$IDX"
    EDIT_NEW_KEY="$KEY"; EDIT_NEW_TUN="$TUN"; EDIT_NEW_TCP="$TCP_PORTS"
    EDIT_NEW_UDP="$UDP_PORTS"; EDIT_NEW_MSS="$MSS_CLAMP"; EDIT_NEW_MTU="$MTU"

    if [[ "$side" == "iran" ]]; then
        validate_peer_values || { edit_txn_commit; return 1; }
    else
        valid_name "$NAME" || { err "Invalid node name: '$NAME'"; edit_txn_commit; return 1; }
        valid_ip "$IRAN_IP" || { err "Invalid Iran IP: '$IRAN_IP'"; edit_txn_commit; return 1; }
        valid_subnet_base "$SUBNET_BASE" || { err "Invalid subnet base: '$SUBNET_BASE'"; edit_txn_commit; return 1; }
        { [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )); } || { err "Invalid index: '$IDX'"; edit_txn_commit; return 1; }
        [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: '$KEY'"; edit_txn_commit; return 1; }
    fi

    # --- collision and port checks, excluding this connection ---------
    if [[ "$side" == "iran" ]]; then
        # The connection being edited must not count as a collision with itself —
        # under either its current or its requested name, because a rename leaves
        # the old file on disk until the new one is verified.
        check_peer_collisions "$NAME" "$SUBNET_BASE" "$IDX" "$TUN" "$TCP_PORTS" "$UDP_PORTS" \
            "$EDIT_OLD_NAME" \
            || { edit_txn_commit; return 1; }
        if [[ "$SUBNET_BASE" != "$EDIT_OLD_SUBNET_BASE" ]] && subnet_route_conflict "$SUBNET_BASE"; then
            err "Subnet base $SUBNET_BASE collides with an existing local route."
            edit_txn_commit
            return 1
        fi
        if [[ "$TCP_PORTS" != "$EDIT_OLD_TCP" ]]; then
            port_available_for_edit tcp "$TCP_PORTS" "$EDIT_OLD_NAME" \
                || { err "TCP ports '$TCP_PORTS' are already owned by another connection."; edit_txn_commit; return 1; }
        fi
        if [[ "$UDP_PORTS" != "$EDIT_OLD_UDP" ]]; then
            port_available_for_edit udp "$UDP_PORTS" "$EDIT_OLD_NAME" \
                || { err "UDP ports '$UDP_PORTS' are already owned by another connection."; edit_txn_commit; return 1; }
        fi
        if [[ "$NAME" != "$EDIT_OLD_NAME" && -e "$FOREIGNS_DIR/$NAME.conf" ]]; then
            err "A connection named '$NAME' already exists."
            edit_txn_commit
            return 1
        fi
    else
        local f p_name p_base p_idx
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            p_name="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
            [[ "$p_name" == "$EDIT_OLD_NAME" ]] && continue
            p_base="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; p_base="${p_base:-$DEFAULT_SUBNET_BASE}"
            p_idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
            if [[ "$p_base" == "$SUBNET_BASE" && "$p_idx" == "$IDX" ]]; then
                err "Subnet/index ${SUBNET_BASE}.${IDX} is already used by node '$p_name'."
                edit_txn_commit
                return 1
            fi
        done
        if [[ "$NAME" != "$EDIT_OLD_NAME" && -e "$NODES_DIR/$NAME.conf" ]]; then
            err "A node named '$NAME' already exists."
            edit_txn_commit
            return 1
        fi
    fi

    # --- apply ---------------------------------------------------------
    local newfile
    if [[ "$side" == "iran" ]]; then
        # CLASS A: the tunnel is not touched at all. Old rules out, new rules in,
        # and the interface keeps running throughout.
        if [[ "$PLAN_CLASS" == "A" ]]; then
            # A rule-only change must not recreate the interface, so the MTU is applied
            # to the EXISTING device. This is the only path that changes MTU without a
            # rebuild, and it is the reason an MTU edit is safe on a live tunnel.
            apply_iface_mtu "$EDIT_OLD_TUN" "$PLAN_REQ_MTU"
            peer_rules_remove "$EDIT_OLD_NAME" "$EDIT_OLD_TUN" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_WAN_IF" \
                "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.2" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1" \
                "$EDIT_OLD_TCP" "$EDIT_OLD_UDP" "$EDIT_OLD_MSS"
            peer_rules_install "$NAME" "$EDIT_OLD_TUN" "$IRAN_IP" "$WAN_IF" \
                "${SUBNET_BASE}.${IDX}.2" "${SUBNET_BASE}.${IDX}.1" "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" "$PLAN_REQ_MTU"
            if ! edit_verify_tunnel "$EDIT_OLD_TUN" "${SUBNET_BASE}.${IDX}.2/30"; then
                edit_fail_and_rollback "$side" "the rule-only update left the tunnel unverified"
                return 1
            fi
        else
            # CLASS B: rebuild. Remove the old rules first so the new tunnel does
            # not inherit a stale DNAT pointing at the old peer address.
            peer_rules_remove "$EDIT_OLD_NAME" "$EDIT_OLD_TUN" "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_WAN_IF" \
                "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.2" "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.1" \
                "$EDIT_OLD_TCP" "$EDIT_OLD_UDP" "$EDIT_OLD_MSS" "${EDIT_OLD_MTU:-$TUN_MTU}"
            if ! create_tunnel "$TUN" "$IRAN_IP" "$FOREIGN_IP" "$KEY" "${SUBNET_BASE}.${IDX}.2/30" "${PLAN_REQ_MTU:-$TUN_MTU}"; then
                edit_fail_and_rollback "$side" "the tunnel could not be recreated"
                return 1
            fi
            enable_ip_forward
            peer_rules_install "$NAME" "$TUN" "$IRAN_IP" "$WAN_IF" \
                "${SUBNET_BASE}.${IDX}.2" "${SUBNET_BASE}.${IDX}.1" "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" "${PLAN_REQ_MTU:-$TUN_MTU}"
            if ! edit_verify_tunnel "$TUN" "${SUBNET_BASE}.${IDX}.2/30"; then
                edit_fail_and_rollback "$side" "the rebuilt tunnel could not be verified"
                return 1
            fi
        fi
    else
        # FOREIGN side: no per-node NAT rules, so a rebuild is the whole change.
        if ! create_tunnel "$TUN" "${EDIT_NEW_FOREIGN_IP:-$(foreign_local_ip)}" "$IRAN_IP" "$KEY" "${SUBNET_BASE}.${IDX}.1/30" "${PLAN_REQ_MTU:-$TUN_MTU}"; then
            edit_fail_and_rollback "$side" "the tunnel could not be recreated"
            return 1
        fi
        if ! edit_verify_tunnel "$TUN" "${SUBNET_BASE}.${IDX}.1/30"; then
            edit_fail_and_rollback "$side" "the rebuilt tunnel could not be verified"
            return 1
        fi
    fi

    # --- commit the new config ----------------------------------------
    if [[ "$side" == "iran" ]]; then
        newfile="$FOREIGNS_DIR/$NAME.conf"
        mkdir -p "$FOREIGNS_DIR"
        cat > "$newfile" <<EOF
NAME=$NAME
FOREIGN_IP=$FOREIGN_IP
IRAN_IP=$IRAN_IP
WAN_IF=$WAN_IF
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=$TUN
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
MSS_CLAMP=$MSS_CLAMP
${MTU:+MTU=$MTU}
${NIC_MTU:+NIC_MTU=$NIC_MTU}
EOF
        chmod 600 "$newfile"
        write_iran_manifest
    else
        newfile="$NODES_DIR/$NAME.conf"
        mkdir -p "$NODES_DIR"
        cat > "$newfile" <<EOF
NAME=$NAME
IRAN_IP=$IRAN_IP
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=$TUN
${MTU:+MTU=$MTU}
EOF
        chmod 600 "$newfile"
    fi

    # A rename leaves the old file behind; remove it only now that the new one is
    # written and verified, so a failure never leaves the connection with no config.
    if [[ "$NAME" != "$EDIT_OLD_NAME" && -f "$EDIT_OLD_FILE" ]]; then
        rm -f "$EDIT_OLD_FILE"
    fi
    # A rename also leaves the old INTERFACE behind when the tunnel name is derived
    # from the connection name (it is: gre-<name>). Tearing it down here keeps
    # "rename" from quietly doubling the tunnel count.
    if [[ -n "$EDIT_OLD_TUN" && "$TUN" != "$EDIT_OLD_TUN" ]]; then
        delete_tunnel "$EDIT_OLD_TUN" >/dev/null 2>&1 || true
    fi

    # Identity follows the connection through renames and endpoint changes.
    local fp
    fp="$(pair_fingerprint "$IRAN_IP" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$KEY")"
    local cid
    cid="$(connection_id_for "$(pair_fingerprint "$EDIT_OLD_IRAN_IP" "$EDIT_OLD_FOREIGN_IP" "$EDIT_OLD_SUBNET_BASE" "$EDIT_OLD_IDX" "$EDIT_OLD_KEY")")"
    connection_id_remember "$cid" "$fp"

    edit_txn_commit
    return 0
}

# Commands the OTHER side needs after a local edit, or nothing when the change is
# local-only. CLI has no credential for the peer, so this is how the operator keeps
# the two ends in step without being told to "figure it out".
edit_peer_command_for_foreign() { # edit_peer_command_for_foreign (uses EDIT_NEW_* / EDIT_OLD_*)
    local changed=0 f
    for f in "${PLAN_FIELDS[@]}"; do
        case "$f" in
            IRAN_IP|SUBNET_BASE|IDX|KEY|NAME) changed=1 ;;
            FOREIGN_IP) changed=1 ;;
        esac
    done
    (( changed )) || return 1
    printf 'gre node edit \\\n'
    printf '  --name %s \\\n' "$EDIT_OLD_NAME"
    [[ "$EDIT_NEW_NAME" != "$EDIT_OLD_NAME" ]] && printf '  --new-name %s \\\n' "$EDIT_NEW_NAME"
    printf '  --ip %s \\\n' "$EDIT_NEW_IRAN_IP"
    printf '  --subnet-base %s \\\n' "$EDIT_NEW_SUBNET_BASE"
    printf '  --idx %s \\\n' "$EDIT_NEW_IDX"
    printf '  --key %s\n' "$EDIT_NEW_KEY"
    return 0
}

progress_bar() { # progress_bar "label" percent
    local label="$1" pct="$2" width=32 filled i
    (( pct < 0 )) && pct=0
    (( pct > 100 )) && pct=100
    filled=$(( pct * width / 100 ))
    printf '\r  %-30s %s[' "$label" "$C_CYAN"
    for (( i = 0; i < filled; i++ )); do printf '#'; done
    for (( i = filled; i < width; i++ )); do printf '-'; done
    printf ']%s %3d%%' "$C_RESET" "$pct"
    (( pct >= 100 )) && echo
    return 0
}

# ------------------------------------------------------------- ip/iptables helpers
tun_exists() { ip link show "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------- MTU helpers
#
# MTU_MIN_INNER is the smallest IPv4 MTU any host must accept (RFC 791). A GRE MTU
# below it would be illegal for the inner protocol, so recommendations are clamped
# here rather than being allowed to follow a bad measurement down.
MTU_MIN_INNER=576
# When the inner path carries IPv6, the floor is 1280 (RFC 8200), because IPv6 has no
# router fragmentation at all. The `gre mtu recommend` engine reads it.
# shellcheck disable=SC2034  # read by gre mtu recommend
MTU_MIN_INNER_V6=1280
# A GRE interface MTU above the underlay's is meaningless: the encapsulated packet
# would not fit, so it is capped rather than recommended.
MTU_MAX_GRE=9000

valid_mtu() { # valid_mtu VALUE — a GRE interface MTU is 576..9000
    [[ "${1:-}" =~ ^[0-9]+$ ]] || return 1
    (( $1 >= MTU_MIN_INNER && $1 <= MTU_MAX_GRE ))
}

# =========================================================== PMTU probing engine
#
# A bounded DF-probe search for the largest packet that survives a path.
#
# Design constraints, because this runs against live production links:
#   - BOUNDED. At most MTU_PROBE_BUDGET probes per direction, then it stops and reports
#     UNKNOWN rather than continuing to hunt.
#   - BINARY SEARCH over a coarse grid, not a walk over every size.
#   - SLOW. A short delay between probes, so the search cannot look like a flood.
#   - It distinguishes three outcomes, which is the whole point:
#       ok        the packet made it (or a reply came back)
#       frag_needed   an ICMP "fragmentation needed" came back -> a hard ceiling
#       timeout   no reply. NOT proof of an MTU problem: ICMP may be filtered, the path
#                 may be down, or the far end may simply not answer. Reported as
#                 inconclusive.
#
# It never reports a number it did not measure, and never treats a failed probe as
# evidence of a smaller path unless a frag-needed message actually arrived.

MTU_PROBE_BUDGET=12
MTU_PROBE_DELAY_MS=150
MTU_PROBE_TIMEOUT=3
# 20 (IPv4) + 8 (ICMP echo) = 28 bytes of header inside the -s payload size.
MTU_PROBE_HDR=28

mtu_probe_sleep() {
    [[ "$MTU_PROBE_DELAY_MS" -gt 0 ]] || return 0
    sleep "$(printf '%s.%03d' "$(( MTU_PROBE_DELAY_MS / 1000 ))" "$(( MTU_PROBE_DELAY_MS % 1000 ))")" 2>/dev/null || true
}

# Probe one size over a path.
#
# `via_iface` is the interface to force as the egress. Passing the tunnel name makes this
# an INNER path measurement; leaving it empty measures the underlay through whatever the
# kernel picks. The interface is a real name, never the literal word "tun".
#
# Echoes: ok | frag_needed | timeout | nosupport | noip
mtu_probe_size() { # mtu_probe_size DEST SIZE [EGRESS_IFACE]
    local dest="$1" size="$2" iface="${3:-}"
    local out="" rc=0
    [[ -n "$dest" && -n "$size" ]] || { printf 'noip'; return; }
    command -v ping >/dev/null 2>&1 || { printf 'nosupport'; return; }

    if [[ -n "$iface" ]]; then
        out="$(ping -M "do" -s "$size" -c 1 -W "$MTU_PROBE_TIMEOUT" -I "$iface" "$dest" 2>&1)" || rc=$?
    else
        out="$(ping -M "do" -s "$size" -c 1 -W "$MTU_PROBE_TIMEOUT" "$dest" 2>&1)" || rc=$?
    fi

    # A frag-needed message is the only thing that proves a real MTU ceiling.
    if grep -qiE 'frag needed|fragmentation needed|message too long|packet too big' <<< "$out"; then
        printf 'frag_needed'; return
    fi
    # Blocked or unsupported DF: this host cannot do the measurement at all.
    if grep -qiE 'not permitted|operation not permitted|invalid option|bad option|unknown option' <<< "$out"; then
        printf 'nosupport'; return
    fi
    (( rc == 0 )) && { printf 'ok'; return; }
    printf 'timeout'
}

# Find the largest size that survives, by bounded binary search.
#
# Echoes a compact result: "<state> <max_ok> <frag_at> <probes>"
#   state    ok | frag_needed | inconclusive | unsupported | unknown
#   max_ok   largest confirmed-ok size, or "-"
#   frag_at  smallest size that reported frag-needed (as an MTU), or "-"
mtu_probe_path() { # mtu_probe_path DEST [EGRESS_IFACE] [START_HIGH]
    local dest="$1" iface="${2:-}" high="${3:-1472}"
    local lo=$(( MTU_MIN_INNER - MTU_PROBE_HDR )) hi="$high"
    local probes=0 max_ok="" frag_at="" last=""

    # Seed: does the smallest legal size work at all? If not, this is not an MTU
    # question — the path is down or ICMP is filtered — so say so instead of narrowing.
    mtu_probe_sleep
    last="$(mtu_probe_size "$dest" "$lo" "$iface")"; probes=$(( probes + 1 ))
    case "$last" in
        nosupport) printf 'unsupported - - %d' "$probes"; return ;;
        noip)      printf 'unknown - - %d' "$probes"; return ;;
        timeout)   printf 'inconclusive - - %d' "$probes"; return ;;
        frag_needed)
            # Even the floor is too big, which means the path MTU is below the legal
            # IPv4 minimum. Report the ceiling; the recommender refuses to go lower.
            printf 'frag_needed - %d %d' "$(( lo + MTU_PROBE_HDR ))" "$probes"; return ;;
    esac
    max_ok="$lo"

    # Is the top of the range already fine? Then there is nothing to search.
    if (( probes < MTU_PROBE_BUDGET )); then
        mtu_probe_sleep
        last="$(mtu_probe_size "$dest" "$hi" "$iface")"; probes=$(( probes + 1 ))
        case "$last" in
            ok)          printf 'ok %d - %d' "$hi" "$probes"; return ;;
            frag_needed) frag_at="$(( hi + MTU_PROBE_HDR ))" ;;
            timeout)     printf 'inconclusive - - %d' "$probes"; return ;;
            nosupport)   printf 'unsupported - - %d' "$probes"; return ;;
        esac
    fi

    # Binary search between a known-good lo and a known-bad hi.
    local mid
    while (( probes < MTU_PROBE_BUDGET && hi - lo > 1 )); do
        mid=$(( (lo + hi) / 2 ))
        mtu_probe_sleep
        last="$(mtu_probe_size "$dest" "$mid" "$iface")"; probes=$(( probes + 1 ))
        case "$last" in
            ok)          max_ok="$mid"; lo="$mid" ;;
            frag_needed) frag_at="$(( mid + MTU_PROBE_HDR ))" ; hi="$mid" ;;
            timeout)
                # A timeout narrows nothing: it is not evidence of a smaller MTU. Stop
                # rather than guessing, and report what was actually confirmed.
                printf 'inconclusive %d %s %d' "$max_ok" "${frag_at:--}" "$probes"; return ;;
            nosupport)   printf 'unsupported %s %s %d' "$max_ok" "${frag_at:--}" "$probes"; return ;;
        esac
    done

    if [[ -n "$frag_at" ]]; then
        printf 'frag_needed %s %s %d' "$max_ok" "$frag_at" "$probes"
    else
        printf 'ok %s %s %d' "$max_ok" "${frag_at:--}" "$probes"
    fi
}

# Does this path answer ICMP at all? Distinguishes "ICMP is filtered" from "the path is
# broken", which is what stops a filtered probe being reported as a tunnel failure.
mtu_icmp_available() { # mtu_icmp_available DEST
    command -v ping >/dev/null 2>&1 || return 1
    ping -c 2 -W 2 "$1" >/dev/null 2>&1
}

# The observed route MTU metric for a destination, if one is set.
mtu_diag_route() { # mtu_diag_route DEST
    [[ -n "${1:-}" ]] || { printf ''; return; }
    ip -4 route get "$1" 2>/dev/null | head -n1
}

# The encapsulation overhead THIS tunnel adds to a packet it carries.
#
# This is what has to be subtracted from the underlay's capacity to get the largest inner
# packet that still fits, so it is the OUTER IPv4 header plus the GRE header (plus the
# 4-byte key field when a key is configured) — NOT the inner IP header. The inner header
# is part of the packet the tunnel is carrying, so counting it would understate the
# tunnel MTU by 20 bytes and silently cost 20 bytes of payload on every connection.
#
# Never a fixed constant: a keyed tunnel carries 4 bytes more than an unkeyed one, and an
# outer IPv6 header is 20 bytes larger again. Getting this wrong by 4 bytes is exactly
# what produces an intermittent blackhole, so it is computed from the tunnel's own flags.
gre_overhead_bytes() { # gre_overhead_bytes KEY OUTER_IPV
    local key="${1:-0}" outer_ipv="${2:-4}"
    local bytes=0
    # Outer IP header
    if [[ "$outer_ipv" == "6" ]]; then bytes=$(( bytes + 40 )); else bytes=$(( bytes + 20 )); fi
    # GRE header: 4 bytes base, plus the optional 4-byte key/sequence field. The manager
    # always passes a key, so this is normally +4.
    bytes=$(( bytes + 4 ))
    [[ -n "$key" && "$key" != "0" ]] && bytes=$(( bytes + 4 ))
    printf '%s' "$bytes"
}

# The MTU actually in effect for an interface, from the kernel.
#
# ip(8) is preferred over sysfs: it is the same source the operator sees, it works for
# every link type, and it does not depend on /sys being readable in the environment the
# manager happens to run in.
iface_mtu() { # iface_mtu IFACE
    local iface="${1:-}" mtu=""
    [[ -n "$iface" ]] || { printf ''; return; }
    mtu="$(ip -o link show dev "$iface" 2>/dev/null | sed -n 's/.*[[:space:]]mtu[[:space:]]\+\([0-9]\+\).*/\1/p' | head -n1)"
    if [[ -z "$mtu" ]]; then
        mtu="$(ip -o link show "$iface" 2>/dev/null | sed -n 's/.*[[:space:]]mtu[[:space:]]\+\([0-9]\+\).*/\1/p' | head -n1)"
    fi
    if [[ -z "$mtu" ]]; then
        mtu="$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null)"
    fi
    printf '%s' "$mtu"
}

# The MTU of the interface the kernel would actually use to reach a destination,
# which is the underlay capacity that matters — not the default route's.
underlay_egress_mtu() { # underlay_egress_mtu DEST
    local dest="${1:-}" iface="" mtu=""
    [[ -n "$dest" ]] || { printf ''; return; }
    iface="$(ip -4 route get "$dest" 2>/dev/null | sed -n 's/.*[[:space:]]dev[[:space:]]\+\([^ ]\+\).*/\1/p' | head -n1)"
    [[ -n "$iface" ]] || { printf ''; return; }
    mtu="$(iface_mtu "$iface")"
    printf '%s' "$mtu"
}

# The route MTU metric, when one is set. A non-empty value here overrides the device
# MTU for this path and is a common cause of "the NIC says 1500 but the path is 1400".
route_mtu_for() { # route_mtu_for DEST
    local dest="${1:-}"
    [[ -n "$dest" ]] || { printf ''; return; }
    ip -4 route get "$dest" 2>/dev/null | sed -n 's/.*[[:space:]]mtu[[:space:]]\+\([0-9]\+\).*/\1/p' | head -n1
}

# Is this the interface that carries the control plane (the SSH session / the Hub)?
# Used to refuse automatic changes that could strand the operator.
iface_carries_control_plane() { # iface_carries_control_plane IFACE
    local iface="${1:-}" out=""
    [[ -n "$iface" ]] || return 1
    # The interface holding the default route is the one a remote operator reached us
    # through, in every topology this manager supports.
    out="$(ip -4 route show default 2>/dev/null | sed -n 's/.*[[:space:]]dev[[:space:]]\+\([^ ]\+\).*/\1/p' | head -n1)"
    [[ "$out" == "$iface" ]]
}

create_tunnel() { # create_tunnel NAME LOCAL_IP REMOTE_IP KEY ADDR [MTU]
    local name="$1" local_ip="$2" remote_ip="$3" key="$4" addr="$5"
    # MTU is per-connection. The default is only a fallback for a connection that has
    # never had one set, so existing deployments keep the exact behaviour they had.
    local mtu="${6:-$TUN_MTU}"
    if tun_exists "$name"; then
        ip link set "$name" down 2>/dev/null || true
        ip tunnel del "$name" 2>/dev/null || true
    fi
    ip tunnel add "$name" mode gre local "$local_ip" remote "$remote_ip" key "$key" ttl 255 || return 1
    ip addr add "$addr" dev "$name" || return 1
    ip link set "$name" mtu "$mtu" up || return 1
    ok "Tunnel $name is up ($addr, key $key, mtu $mtu)"
}

delete_tunnel() { # name
    local name="$1"
    if tun_exists "$name"; then
        ip link set "$name" down 2>/dev/null || true
        ip tunnel del "$name" 2>/dev/null || true
        ok "Tunnel $name removed"
    else
        info "Tunnel $name does not exist (skipped)"
    fi
}

ipt_add() { # table chain rule...
    local table="$1" chain="$2"; shift 2
    if ! iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        iptables -t "$table" -A "$chain" "$@"
    fi
}

ipt_del() { # table chain rule...   (delete ALL copies, silently ignore absence)
    local table="$1" chain="$2"; shift 2
    while iptables -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -t "$table" -D "$chain" "$@"
    done
}

ipt_del_report() { # like ipt_del but prints what happened
    local table="$1" chain="$2"; shift 2
    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        ipt_del "$table" "$chain" "$@"
        ok "Removed: iptables -t $table -D $chain $*"
    else
        info "Not present (skipped): iptables -t $table -A $chain $*"
    fi
}

enable_ip_forward() {
    echo "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

# ------------------------------------------------------------- apply / stop
# Read a node config into the caller's variables.
#
# Wraps `source` in a subshell so a malformed or hostile config file cannot leak
# unrelated assignments into the caller. Only the known fields are copied back.
# The caller must declare the targets (NAME, IRAN_IP, ...) before calling.
node_conf_read() { # node_conf_read FILE NAME_VAR IRAN_IP_VAR SUBNET_BASE_VAR IDX_VAR KEY_VAR TUN_VAR [MTU_VAR]
    local f="$1"
    local -n _name="$2" _iran="$3" _base="$4" _idx="$5" _key="$6" _tun="$7"
    local _mtu_name="${8:-}"
    local -a vals=()
    if [[ -f "$f" ]]; then
        mapfile -t vals < <(
            # shellcheck disable=SC1090  # this host's own config file
            source "$f" >/dev/null 2>&1
            printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
                "${NAME:-}" "${IRAN_IP:-}" "${SUBNET_BASE:-$DEFAULT_SUBNET_BASE}" \
                "${IDX:-}" "${KEY:-}" "${TUN:-}" "${MTU:-}"
        )
    fi
    _name="${vals[0]:-}"; _iran="${vals[1]:-}"
    _base="${vals[2]:-$DEFAULT_SUBNET_BASE}"
    _idx="${vals[3]:-}"; _key="${vals[4]:-}"; _tun="${vals[5]:-}"
    if [[ -n "$_mtu_name" ]]; then
        local -n _mtu="$_mtu_name"
        _mtu="${vals[6]:-}"
    fi
}

# Change an existing interface's MTU without recreating it.
#
# This is the operation an MTU edit uses. Rebuilding the interface would also work,
# but it would drop the tunnel and every rule pointing at it, so an MTU-only change
# deliberately does the minimum: one `ip link set` on the device that is already up.
# Routing, NAT, the GRE key and the endpoints are all left untouched.
#
# Returns 0 when the interface ends up at the requested MTU, so a caller can verify
# rather than assume.
apply_iface_mtu() { # apply_iface_mtu IFACE MTU
    local iface="${1:-}" mtu="${2:-}"
    [[ -n "$iface" ]] || { err "apply_iface_mtu: no interface given"; return 1; }
    tun_exists "$iface" || { err "Interface $iface does not exist."; return 1; }
    if [[ -z "$mtu" ]]; then
        info "Interface $iface: no MTU requested, leaving it alone."
        return 0
    fi
    valid_mtu "$mtu" || { err "Refusing to set an illegal MTU on $iface: '$mtu'"; return 1; }
    if [[ "$(iface_mtu "$iface")" == "$mtu" ]]; then
        info "Interface $iface is already at MTU $mtu."
        return 0
    fi
    ip link set dev "$iface" mtu "$mtu" || { err "Could not set MTU $mtu on $iface."; return 1; }
    # Confirm from the kernel rather than trusting the command's exit status.
    if [[ "$(iface_mtu "$iface")" != "$mtu" ]]; then
        err "MTU on $iface did not take effect (wanted $mtu, found '$(iface_mtu "$iface")')."
        return 1
    fi
    ok "Interface $iface MTU set to $mtu."
}

# This host's public IP, for use as the GRE local endpoint.
#
# It lives in foreign.conf, NOT in a node config. Callers used to pass it in from
# whatever happened to be in scope, which meant a node config applied on its own got
# an empty `local` and the tunnel could not come up.
foreign_local_ip() {
    # Not named `ip`: that would shadow the ip(8) command for anything called from
    # here, which is how tunnel_local_endpoint silently returned an empty string.
    local addr=""
    if [[ -f "$FOREIGN_CONF" ]]; then
        addr="$(grep -E '^FOREIGN_IP=' "$FOREIGN_CONF" 2>/dev/null | head -n1 | cut -d= -f2)"
    fi
    printf '%s' "$addr"
}

# The local endpoint an interface is ACTUALLY using, so a rebuild reproduces the
# live tunnel rather than trusting a stored value that may have drifted.
tunnel_local_endpoint() { # tunnel_local_endpoint IFACE
    local iface="$1" out="" local_addr=""
    [[ -n "$iface" ]] || return 0
    out="$(ip -d tunnel show "$iface" 2>/dev/null || true)"
    [[ -n "$out" ]] || out="$(ip tunnel show "$iface" 2>/dev/null || true)"
    local_addr="$(printf '%s\n' "$out" | sed -n 's/.*[[:space:]]local[[:space:]]\+\([0-9.]\+\)[[:space:]].*/\1/p' | head -n1)"
    printf '%s' "$local_addr"
}

apply_foreign_node() { # apply_foreign_node NODE_CONF_FILE [LOCAL_IP]
    local f="$1" local_ip="${2:-}"
    local NAME="" IRAN_IP="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" IDX="" KEY="" TUN="" MTU=""
    node_conf_read "$f" NAME IRAN_IP SUBNET_BASE IDX KEY TUN MTU

    # The local endpoint is this host's own IP. It is resolved HERE rather than
    # inherited from the caller, so applying one node config on its own is
    # self-contained: previously the value had to be in scope or the tunnel was
    # created with no `local` address at all.
    if [[ -z "$local_ip" ]]; then
        local_ip="$(foreign_local_ip)"
    fi
    if [[ -z "$TUN" ]]; then
        err "Node config $f has no TUN value; cannot create a tunnel."
        return 1
    fi
    if ! valid_ip "$local_ip"; then
        err "This host's public IP is unknown or invalid ('${local_ip:-empty}')."
        err "Set it first:  gre foreign setup --foreign-ip <THIS_HOST_PUBLIC_IP>"
        return 1
    fi
    if ! valid_ip "$IRAN_IP"; then
        err "Node config $f has an invalid IRAN_IP ('${IRAN_IP:-empty}')."
        return 1
    fi

    create_tunnel "$TUN" "$local_ip" "$IRAN_IP" "$KEY" "${SUBNET_BASE}.${IDX}.1/30" "${MTU:-$TUN_MTU}"
}

# Distinct subnet bases used by the foreign-side nodes (default base included).
foreign_node_bases() {
    local bases=" $DEFAULT_SUBNET_BASE " f b out=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; b="${b:-$DEFAULT_SUBNET_BASE}"
        if [[ "$bases" != *" $b "* ]]; then
            bases+="$b "
        fi
    done
    out="${bases# }"; out="${out% }"
    printf '%s' "$out"
}

apply_foreign() {
    [[ -f "$FOREIGN_CONF" ]] || return 0
    local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        apply_foreign_node "$f"
    done

    # --- firewall hardening: only allow GRE (proto 47) from known Iran node IPs
    if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
        # remove the catch-all first so new ACCEPTs are inserted BEFORE it
        ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            ipt_add filter INPUT -p gre -s "$IRAN_IP" \
                -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
        done
        ipt_add filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
    fi

    # --- optional ICMP drop (tunnel subnets stay pingable for the watchdog)
    if [[ "${ICMP_DROP:-0}" == "1" ]]; then
        # migrate/remove any old un-commented rule from v1.0.0
        ipt_del filter INPUT -p icmp -j DROP
        ipt_del filter INPUT -p icmp -m comment --comment "multi-gre-icmp-block" -j DROP
        local base
        for base in $(foreign_node_bases); do
            ipt_add filter INPUT -p icmp -s "${base}.0.0/16" \
                -m comment --comment "multi-gre-tunnel-icmp" -j ACCEPT
        done
        ipt_add filter INPUT -p icmp -m comment --comment "multi-gre-icmp-block" -j DROP
        ok "Inbound ICMP (ping) is dropped (tunnel subnets stay pingable)"
    fi
}

# Bring up ONE Iran-side peer from its conf: tunnel + per-peer, comment-tagged
# DNAT/SNAT/MSS rules. Legacy un-commented v1 rules (pre-migration) are removed
# first so an apply right after migration leaves no duplicates.
apply_iran_peer() { # apply_iran_peer PEER_CONF_FILE
    local f="$1"
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0" MTU=""
    load_peer_conf "$f" || return 1
    local peer="${SUBNET_BASE}.${IDX}.1"
    local self="${SUBNET_BASE}.${IDX}.2"

    create_tunnel "$TUN" "$IRAN_IP" "$FOREIGN_IP" "$KEY" "${self}/30" "${MTU:-$TUN_MTU}" || return 1
    enable_ip_forward

    if [[ -n "$TCP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -j DNAT --to-destination "$peer"
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-tcp" -j DNAT --to-destination "$peer"
        ok "[$NAME] TCP ports $TCP_PORTS on $IRAN_IP -> $peer (DNAT)"
    fi
    if [[ -n "$UDP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -j DNAT --to-destination "$peer"
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-udp" -j DNAT --to-destination "$peer"
        ok "[$NAME] UDP ports $UDP_PORTS on $IRAN_IP -> $peer (DNAT)"
    fi
    if [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
        ipt_del nat POSTROUTING -o "$TUN" -d "$peer" -j SNAT --to-source "$self"
        ipt_add nat POSTROUTING -o "$TUN" -d "$peer" \
            -m comment --comment "multi-gre-iran-$NAME-snat" -j SNAT --to-source "$self"
    fi

    # --- TCP MSS clamping on the tunnel (avoids broken-PMTU stalls)
    #
    # Delegated to peer_rules_install rather than duplicated here. The two copies had
    # already drifted (this one knew nothing about the tunnel MTU), and a second,
    # subtly different MSS rule is exactly how a clamp ends up applied twice or not at
    # all depending on which path brought the peer up.
    peer_rules_install "$NAME" "$TUN" "$IRAN_IP" "$WAN_IF" "$self" "$peer" \
        "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" "${MTU:-$TUN_MTU}"
    return 0
}

apply_iran() { # bring up every configured foreign peer (a failure stops no other peer)
    [[ -f "$IRAN_CONF" ]] || return 0
    local rc=0 f any=0
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        any=1
        apply_iran_peer "$f" || { warn "Failed to apply peer from $f"; rc=1; }
    done
    (( any )) || info "IRAN role: no foreign peers configured yet (add one: gre iran peer add)."
    return "$rc"
}

apply_all() {
    migrate_legacy_iran_conf || return 1
    # shellcheck disable=SC1090
    [[ -f "$FOREIGN_CONF" ]] && source "$FOREIGN_CONF"
    apply_foreign
    apply_iran
}

stop_foreign() {
    [[ -f "$FOREIGN_CONF" ]] || return 0
    local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
        source "$f"
        [[ -n "$TUN" ]] && delete_tunnel "$TUN"
    done

    # GRE whitelist rules
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
        source "$f"
        ipt_del filter INPUT -p gre -s "$IRAN_IP" \
            -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
    done
    ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP

    # ICMP rules (commented v1.1.0 style + plain v1.0.0 style, per node subnet base)
    local base
    for base in $(foreign_node_bases); do
        ipt_del filter INPUT -p icmp -s "${base}.0.0/16" \
            -m comment --comment "multi-gre-tunnel-icmp" -j ACCEPT
    done
    ipt_del filter INPUT -p icmp -m comment --comment "multi-gre-icmp-block" -j DROP
    ipt_del filter INPUT -p icmp -j DROP
}

# Tear down ONE Iran-side peer: its comment-tagged rules, any leftover
# un-commented v1 rules with the same match, then its tunnel. Other peers and
# the shared service/watchdog are never touched.
stop_iran_peer() { # stop_iran_peer PEER_CONF_FILE
    local f="$1"
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    load_peer_conf "$f" || return 1
    local peer="${SUBNET_BASE}.${IDX}.1"
    local self="${SUBNET_BASE}.${IDX}.2"

    if [[ -n "$TCP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-tcp" -j DNAT --to-destination "$peer"
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -j DNAT --to-destination "$peer"
    fi
    if [[ -n "$UDP_PORTS" ]]; then
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -m comment --comment "multi-gre-iran-$NAME-dnat-udp" -j DNAT --to-destination "$peer"
        ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -j DNAT --to-destination "$peer"
    fi
    if [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
        ipt_del nat POSTROUTING -o "$TUN" -d "$peer" \
            -m comment --comment "multi-gre-iran-$NAME-snat" -j SNAT --to-source "$self"
        ipt_del nat POSTROUTING -o "$TUN" -d "$peer" -j SNAT --to-source "$self"
    fi
    ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "multi-gre-iran-$NAME-mss" -j TCPMSS --clamp-mss-to-pmtu
    ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu
    [[ -n "$TUN" ]] && delete_tunnel "$TUN"
    return 0
}

stop_iran() {
    [[ -f "$IRAN_CONF" ]] || return 0
    if iran_conf_is_legacy; then
        # unmigrated v1 config: tear down the old un-commented single-tunnel rules
        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
              IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
        validate_conf_file "$IRAN_CONF" "$PEER_CONF_FIELDS_RE" || { warn "Legacy iran.conf unreadable; skipping Iran-side stop."; return 1; }
        source "$IRAN_CONF"
        local peer="${SUBNET_BASE}.${IDX}.1"
        local self="${SUBNET_BASE}.${IDX}.2"
        if [[ -n "$TCP_PORTS" ]]; then
            ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
                -j DNAT --to-destination "$peer"
        fi
        if [[ -n "$UDP_PORTS" ]]; then
            ipt_del nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
                -j DNAT --to-destination "$peer"
        fi
        if [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
            ipt_del nat POSTROUTING -o "$TUN" -d "$peer" -j SNAT --to-source "$self"
        fi
        ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu
        [[ -n "$TUN" ]] && delete_tunnel "$TUN"
        return 0
    fi
    local f
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        stop_iran_peer "$f" || warn "Problems while stopping peer from $f"
    done
    return 0
}

stop_all() {
    # shellcheck disable=SC1090
    [[ -f "$FOREIGN_CONF" ]] && source "$FOREIGN_CONF"
    stop_foreign
    stop_iran
}

# ------------------------------------------------------------- watchdog
watchdog_run() { # called by systemd timer; logs to the journal via logger
    local restarted=0 f
    migrate_legacy_iran_conf || return 1
    if [[ -f "$FOREIGN_CONF" ]]; then
        # shellcheck disable=SC1090
        source "$FOREIGN_CONF"
        local NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE"
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            if ! tun_exists "$TUN" || ! ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.2" >/dev/null 2>&1; then
                logger -t gre-watchdog "tunnel $TUN (node $NAME) missing or unreachable; re-applying"
                apply_foreign_node "$f" && restarted=$(( restarted + 1 ))
            fi
        done
    fi
    if [[ -f "$IRAN_CONF" ]]; then
        local FOREIGN_IP="" WAN_IF="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; FOREIGN_IP=""; IRAN_IP=""; WAN_IF=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            IDX=""; KEY=""; TUN=""; TCP_PORTS=""; UDP_PORTS=""; MSS_CLAMP=""
            load_peer_conf "$f" || { logger -t gre-watchdog "peer conf $f invalid; skipped"; continue; }
            if ! tun_exists "$TUN" || ! ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.1" >/dev/null 2>&1; then
                logger -t gre-watchdog "peer $NAME tunnel $TUN (foreign $FOREIGN_IP) missing or unreachable; re-applying"
                apply_iran_peer "$f" && restarted=$(( restarted + 1 ))
            fi
        done
    fi
    (( restarted > 0 )) && logger -t gre-watchdog "re-applied $restarted tunnel(s)"
    return 0
}

write_watchdog_units() { # write_watchdog_units interval_min
    local interval="${1:-1}"
    cat > "$WATCHDOG_SERVICE_FILE" <<EOF
[Unit]
Description=Multi-GRE tunnel watchdog (gre-manager)

[Service]
Type=oneshot
ExecStart=$INSTALL_PATH --watchdog
EOF
    cat > "$WATCHDOG_TIMER_FILE" <<EOF
[Unit]
Description=Multi-GRE tunnel watchdog timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
}

install_watchdog() {
    load_global_conf
    write_watchdog_units "$WD_INTERVAL_MIN"
    systemctl enable --now multi-gre-watchdog.timer >/dev/null 2>&1 || true
    ok "Watchdog enabled (checks every ${WD_INTERVAL_MIN} min, downtime tolerance ~${WD_TOLERANCE_MIN} min)"
    info "Change or disable anytime: menu -> Watchdog, or 'gre watchdog interval N' / 'gre watchdog disable'"
}

remove_watchdog() {
    systemctl disable --now multi-gre-watchdog.timer >/dev/null 2>&1 || true
    rm -f "$WATCHDOG_TIMER_FILE" "$WATCHDOG_SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
}

# apply_watchdog_config enabled interval_min tolerance_min — persist + apply live
apply_watchdog_config() {
    local enabled="$1" interval="$2" tol="$3"
    write_global_conf "$enabled" "$interval" "$tol"
    if [[ "$enabled" == "1" ]]; then
        write_watchdog_units "$interval"
        systemctl enable --now multi-gre-watchdog.timer >/dev/null 2>&1 || true
        systemctl restart multi-gre-watchdog.timer >/dev/null 2>&1 || true
        ok "Watchdog enabled: checks every ${interval} min (downtime tolerance ~${tol} min)"
    else
        remove_watchdog
        ok "Watchdog disabled. Re-enable anytime: menu -> Watchdog, or 'gre watchdog enable'"
    fi
    audit_log "watchdog-config enabled=$enabled interval=${interval}m tolerance=${tol}m"
}

ask_downtime_tolerance() { # sets ASKED_ENABLED / ASKED_INTERVAL / ASKED_TOL
    echo
    info "Auto-heal watchdog"
    info "If a tunnel dies, the watchdog revives it automatically."
    info "How many minutes of tunnel downtime are acceptable for you? (0 = disable auto-heal)"
    local tol=""
    ask tol "Downtime tolerance in minutes" "2"
    if ! [[ "$tol" =~ ^[0-9]+$ ]]; then
        warn "Not a number; using the default of 2 minutes."
        tol=2
    fi
    ASKED_TOL="$tol"
    if (( tol == 0 )); then
        ASKED_ENABLED=0
        ASKED_INTERVAL=1
        info "Auto-heal disabled — you can re-enable it anytime from the menu (Watchdog)."
    else
        ASKED_ENABLED=1
        ASKED_INTERVAL=$(( tol / 2 ))
        (( ASKED_INTERVAL < 1 )) && ASKED_INTERVAL=1
        info "Watchdog will check every ${ASKED_INTERVAL} min so real downtime stays under ~${tol} min."
        info "Change or cancel anytime: menu -> Watchdog."
    fi
}

watchdog_menu() { # gre watchdog [enable|disable|status|interval N]
    require_root
    case "${1:-status}" in
        enable)
            load_global_conf
            apply_watchdog_config 1 "$WD_INTERVAL_MIN" "$WD_TOLERANCE_MIN"
            ;;
        disable)
            load_global_conf
            apply_watchdog_config 0 "$WD_INTERVAL_MIN" "$WD_TOLERANCE_MIN"
            ;;
        interval)
            local n="${2:-}"
            [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= 60 )) || {
                err "Usage: gre watchdog interval <1-60>   (check interval in minutes)"
                return 1
            }
            load_global_conf
            apply_watchdog_config 1 "$n" "$(( n * 2 ))"
            ;;
        status)
            load_global_conf
            echo "watchdog timer:      $(watchdog_state)"
            echo "check interval:      every ${WD_INTERVAL_MIN} min"
            echo "downtime tolerance:  ~${WD_TOLERANCE_MIN} min"
            systemctl list-timers multi-gre-watchdog.timer --no-pager 2>/dev/null || true
            ;;
        *) err "Usage: gre watchdog [enable|disable|status|interval <1-60>]"; return 1 ;;
    esac
}

# ------------------------------------------------------------- persistence
install_service() {
    local src
    src="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    if [[ "$src" != "$INSTALL_PATH" ]]; then
        cp "$src" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
    fi
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Multi-GRE tunnels (gre-manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_PATH --apply
ExecStop=$INSTALL_PATH --stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable multi-gre.service >/dev/null 2>&1 || true
    ok "systemd service 'multi-gre.service' installed and enabled (survives reboot)"
    load_global_conf
    if [[ "$WD_ENABLED" == "1" ]]; then
        install_watchdog
    else
        remove_watchdog
        info "Watchdog stays disabled (your choice). Enable anytime: 'gre watchdog enable'"
    fi
}

# ------------------------------------------------------------- menu actions
# First free tunnel index on the FOREIGN side, optionally within one subnet
# base only (the pair base+idx must be unique per foreign).
next_free_idx() { # next_free_idx [BASE]
    local base="${1:-$DEFAULT_SUBNET_BASE}" used=" " f idx="" b=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; b="${b:-$DEFAULT_SUBNET_BASE}"
        [[ "$b" == "$base" ]] || continue
        idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        [[ -n "$idx" ]] && used+="$idx "
    done
    local i
    for (( i = 1; i <= 254; i++ )); do
        if [[ "$used" != *" $i "* ]]; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

# Is the (base, idx) pair already taken by another node on this FOREIGN?
node_idx_taken() { # node_idx_taken BASE IDX
    local base="$1" want_idx="$2" f b i
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; b="${b:-$DEFAULT_SUBNET_BASE}"
        i="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        [[ "$b" == "$base" && "$i" == "$want_idx" ]] && return 0
    done
    return 1
}

# Write + apply ONE Iran-side peer. On failure only that peer's artifacts are
# rolled back (never stop_all, never other peers).
create_iran_peer() { # name foreign_ip iran_ip wan_if subnet_base idx key tcp udp mss
    local NAME="$1" FOREIGN_IP="$2" IRAN_IP="$3" WAN_IF="$4" SUBNET_BASE="$5" \
          IDX="$6" KEY="$7" TCP_PORTS="$8" UDP_PORTS="$9" MSS_CLAMP="${10}" TUN="gre-$1"
    mkdir -p "$FOREIGNS_DIR"
    local f="$FOREIGNS_DIR/$NAME.conf"
    cat > "$f" <<EOF
NAME=$NAME
FOREIGN_IP=$FOREIGN_IP
IRAN_IP=$IRAN_IP
WAN_IF=$WAN_IF
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=$TUN
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
MSS_CLAMP=$MSS_CLAMP
${MTU:+MTU=$MTU}
${NIC_MTU:+NIC_MTU=$NIC_MTU}
EOF
    chmod 600 "$f"
    write_iran_manifest
    if ! apply_iran_peer "$f"; then
        err "Failed to bring the tunnel up — rolling back peer '$NAME' only (other peers untouched)."
        stop_iran_peer "$f" >/dev/null 2>&1 || true
        rm -f "$f"
        return 1
    fi
    return 0
}

# Interactive add of one Iran-side peer (menu flow). FIRST=1 is the first-peer
# wizard and additionally asks the downtime-tolerance question and installs the
# systemd service; FIRST=0 is used from the peers management submenu.
interactive_add_iran_peer() { # interactive_add_iran_peer FIRST(0|1)
    local first="$1"
    local wan_if="" detected_ip=""
    wan_if="$(detect_wan_iface)"
    detected_ip="$(detect_public_ip "$wan_if")"
    local sug_base="$DEFAULT_SUBNET_BASE"
    sug_base="$(next_free_subnet_base)" || sug_base="$DEFAULT_SUBNET_BASE"

    echo
    if (( first )); then
        info "IRAN node setup — connect to your first FOREIGN server"
    else
        info "Add a new foreign peer"
    fi
    local IRAN_IP="" FOREIGN_IP="" NAME="" SUBNET_BASE="" IDX="" KEY="" WAN_IF="" \
          TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0" TUN=""
    ask IRAN_IP      "Public IP of THIS Iran server" "$detected_ip"
    ask FOREIGN_IP   "Public IP of the FOREIGN server"
    ask NAME         "Peer name (must match the name used on FOREIGN, e.g. de1)" "de1"
    ask SUBNET_BASE  "Tunnel subnet base (A.B; the tunnel net is A.B.IDX.0/30)" "$sug_base"
    local sug_idx="1"
    sug_idx="$(next_free_peer_idx "$SUBNET_BASE")" || sug_idx="1"
    ask IDX          "Tunnel index (must match FOREIGN, 1-254)" "$sug_idx"
    local default_key="1001"
    [[ "$IDX" =~ ^[0-9]+$ ]] && default_key=$(( 1000 + IDX ))
    ask KEY          "GRE key (must match FOREIGN)" "$default_key"
    ask WAN_IF       "Public (WAN) interface" "$wan_if"
    echo
    info "Enter the service ports on this Iran server that should be forwarded to THIS foreign."
    info "Comma separated, ranges allowed with ':', max 15 entries. Leave empty for none."
    local sug_tcp="" sug_udp=""
    sug_tcp="$(suggest_free_port tcp)" || sug_tcp=""
    sug_udp="$(suggest_free_port udp)" || sug_udp=""
    ask TCP_PORTS  "TCP ports (suggested free: $sug_tcp)" "$sug_tcp"
    ask UDP_PORTS  "UDP ports (suggested free: $sug_udp)" "$sug_udp"

    if confirm_yes "Enable TCP MSS clamping on the tunnel? (recommended)"; then
        MSS_CLAMP="1"
    fi

    local ASKED_ENABLED=1 ASKED_INTERVAL=1 ASKED_TOL=2
    if (( first )); then
        ask_downtime_tolerance
    fi

    TUN="gre-$NAME"
    validate_peer_values || return 1
    if peer_exists "$NAME"; then
        err "Peer '$NAME' already exists. Remove it first (gre iran peer remove --name $NAME)."
        return 1
    fi
    check_peer_collisions "$NAME" "$SUBNET_BASE" "$IDX" "gre-$NAME" "$TCP_PORTS" "$UDP_PORTS" || return 1
    if subnet_route_conflict "$SUBNET_BASE"; then
        err "Subnet base $SUBNET_BASE collides with an existing local route; pick another base."
        return 1
    fi

    warn_port_conflicts "tcp" "$TCP_PORTS"
    warn_port_conflicts "udp" "$UDP_PORTS"

    if port_list_covers_22 "$TCP_PORTS"; then
        warn "Port 22 (SSH) is in the TCP list: SSH to this server will be forwarded to the FOREIGN server!"
        confirm "Are you sure you want to forward port 22?" || { info "Aborted."; return 1; }
    fi

    create_iran_peer "$NAME" "$FOREIGN_IP" "$IRAN_IP" "$WAN_IF" "$SUBNET_BASE" \
        "$IDX" "$KEY" "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" \
        || { err "Peer '$NAME' was not added."; return 1; }

    if (( first )); then
        write_global_conf "$ASKED_ENABLED" "$ASKED_INTERVAL" "$ASKED_TOL"
        install_service
    elif [[ ! -f "$SERVICE_FILE" ]]; then
        install_service
    fi
    audit_log "iran-peer-add name=$NAME foreign=$FOREIGN_IP base=$SUBNET_BASE idx=$IDX key=$KEY tcp='$TCP_PORTS' udp='$UDP_PORTS' mss=$MSS_CLAMP"

    echo
    ok "Foreign peer '$NAME' configured."
    info "Tunnel: gre-$NAME  ${SUBNET_BASE}.${IDX}.2/30  <->  $FOREIGN_IP (key $KEY)"
    info "On the FOREIGN server this node must exist with the SAME name, subnet base, index and key."
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.1"
    return 0
}

menu_iran_peer_remove() {
    local files=("$FOREIGNS_DIR"/*.conf)
    [[ -e "${files[0]}" ]] || { info "No foreign peers configured."; return; }

    echo
    info "Configured foreign peers:"
    local i=1 f NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    for f in "${files[@]}"; do
        if load_peer_conf "$f"; then
            printf '  %d) %s  (foreign %s, subnet %s.%s.0/30, tunnel %s)\n' \
                "$i" "$NAME" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$TUN"
        else
            printf '  %d) %s  (INVALID conf)\n' "$i" "$(basename "$f" .conf)"
        fi
        i=$(( i + 1 ))
    done
    local choice=""
    ask choice "Number of the peer to remove (empty = cancel)" ""
    [[ -z "$choice" ]] && { info "Cancelled."; return; }
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )) || { err "Invalid choice."; return 1; }

    f="${files[$(( choice - 1 ))]}"
    if ! load_peer_conf "$f"; then
        confirm "Peer conf is invalid; delete the file only (no rule cleanup possible)?" || { info "Cancelled."; return; }
        rm -f "$f"
        audit_log "iran-peer-remove invalid-conf file=$f"
        ok "Invalid peer conf removed."
        return
    fi
    confirm "Remove peer '$NAME' (tunnel $TUN, foreign $FOREIGN_IP)? Other peers keep running." \
        || { info "Cancelled."; return; }
    stop_iran_peer "$f"
    rm -f "$f"
    audit_log "iran-peer-remove name=$NAME foreign=$FOREIGN_IP base=$SUBNET_BASE idx=$IDX"
    ok "Peer '$NAME' removed."
    if (( $(peer_count) == 0 )); then
        info "No peers remain; the service/watchdog stay installed (menu option 12 uninstalls everything)."
    fi
}

menu_iran_peer_apply() {
    local files=("$FOREIGNS_DIR"/*.conf)
    [[ -e "${files[0]}" ]] || { info "No foreign peers configured."; return; }

    echo
    info "Configured foreign peers:"
    local i=1 f NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    for f in "${files[@]}"; do
        if load_peer_conf "$f"; then
            printf '  %d) %s  (foreign %s, tunnel %s)\n' "$i" "$NAME" "$FOREIGN_IP" "$TUN"
        else
            printf '  %d) %s  (INVALID conf)\n' "$i" "$(basename "$f" .conf)"
        fi
        i=$(( i + 1 ))
    done
    local choice=""
    ask choice "Number of the peer to re-apply (empty = cancel)" ""
    [[ -z "$choice" ]] && { info "Cancelled."; return; }
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )) || { err "Invalid choice."; return 1; }

    f="${files[$(( choice - 1 ))]}"
    apply_iran_peer "$f" && ok "Peer re-applied."
}

# Interactive Edit wizard.
#
# The same fields as Create, with the current value shown as the default. Pressing
# Enter keeps it. Nothing is applied until the operator sees the preview and
# confirms, and the preview comes from the same planner the CLI uses — so the wizard
# and the one-liner can never disagree about what a change means.
menu_iran_peer_edit() { # interactive: pick a peer, edit it
    local files=() f i c
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        files+=("$f")
    done
    (( ${#files[@]} )) || { info "No peers to edit."; return 0; }

    echo
    echo "  Which peer do you want to edit?"
    i=1
    for f in "${files[@]}"; do
        local n ir
        n="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
        ir="$(grep -E '^FOREIGN_IP=' "$f" | cut -d= -f2)"
        printf '  %d) %s (foreign %s)\n' "$i" "$n" "$ir"
        i=$(( i + 1 ))
    done
    ask c "Number (empty = cancel)" ""
    [[ -z "$c" ]] && { info "Cancelled."; return 0; }
    { [[ "$c" =~ ^[0-9]+$ ]] && (( c >= 1 && c < i )); } || { err "Invalid choice."; return 1; }

    local CURRENT
    CURRENT="$(grep -E '^NAME=' "${files[$(( c - 1 ))]}" | cut -d= -f2)"
    interactive_edit_iran_peer "$CURRENT"
}

# The prefilled field-by-field wizard for one Iran-side connection.
interactive_edit_iran_peer() { # interactive_edit_iran_peer CURRENT_NAME
    local CURRENT="$1" v
    require_root
    edit_txn_begin
    if ! edit_snapshot_current iran "$CURRENT"; then
        err "Could not read '$CURRENT'."
        edit_txn_commit
        return 1
    fi
    plan_request_from_current

    echo
    info "Editing '$CURRENT'. Press Enter to keep the value shown in [brackets]."

    ask v "Foreign IP [${PLAN_REQ_FOREIGN_IP}]" ""
    [[ -n "$v" ]] && PLAN_REQ_FOREIGN_IP="$v"
    ask v "Iran IP [${PLAN_REQ_IRAN_IP}]" ""
    [[ -n "$v" ]] && PLAN_REQ_IRAN_IP="$v"
    ask v "Name [${PLAN_REQ_NAME}]" ""
    [[ -n "$v" ]] && PLAN_REQ_NAME="$v"
    ask v "Subnet base [${PLAN_REQ_SUBNET_BASE}]" ""
    [[ -n "$v" ]] && PLAN_REQ_SUBNET_BASE="$v"
    ask v "Index [${PLAN_REQ_IDX}]" ""
    [[ -n "$v" ]] && PLAN_REQ_IDX="$v"
    ask v "GRE key [${PLAN_REQ_KEY}]" ""
    [[ -n "$v" ]] && PLAN_REQ_KEY="$v"
    ask v "WAN interface [${PLAN_REQ_WAN_IF}]" ""
    [[ -n "$v" ]] && PLAN_REQ_WAN_IF="$v"
    ask v "TCP ports [${PLAN_REQ_TCP_PORTS:-none}]" ""
    [[ -n "$v" ]] && PLAN_REQ_TCP_PORTS="$v"
    ask v "UDP ports [${PLAN_REQ_UDP_PORTS:-none}]" ""
    [[ -n "$v" ]] && PLAN_REQ_UDP_PORTS="$v"
    local cur_mss
    [[ "${PLAN_REQ_MSS_CLAMP:-0}" == "1" ]] && cur_mss="on" || cur_mss="off"
    ask v "MSS clamp on|off [$cur_mss]" ""
    if [[ -n "$v" ]]; then
        case "$v" in
            on|ON|1|yes)  PLAN_REQ_MSS_CLAMP="1" ;;
            off|OFF|0|no) PLAN_REQ_MSS_CLAMP="0" ;;
            *) err "Expected on or off; keeping '$cur_mss'." ;;
        esac
    fi
    PLAN_REQ_TUN="gre-$PLAN_REQ_NAME"

    preview_connection_edit iran "$CURRENT" || { edit_txn_commit; return 1; }
    if (( EDIT_PREVIEW_EMPTY )); then
        edit_txn_commit
        return 0
    fi
    if ! confirm "Apply this change?"; then
        info "Cancelled — nothing was changed."
        edit_txn_commit
        return 0
    fi

    if ! edit_connection_txn iran "$CURRENT"; then
        err "Edit failed and the previous configuration was restored."
        return 1
    fi
    # Mirror what edit_connection_txn recorded, so the audit line and the summary
    # describe the NEW state rather than reading unset variables.
    EDIT_NEW_NAME="$PLAN_REQ_NAME"
    EDIT_NEW_IRAN_IP="$PLAN_REQ_IRAN_IP"
    EDIT_NEW_SUBNET_BASE="$PLAN_REQ_SUBNET_BASE"
    EDIT_NEW_IDX="$PLAN_REQ_IDX"
    EDIT_NEW_KEY="$PLAN_REQ_KEY"
    EDIT_NEW_TUN="gre-$PLAN_REQ_NAME"
    audit_log "iran-peer-edit from=$CURRENT name=$EDIT_NEW_NAME base=$EDIT_NEW_SUBNET_BASE idx=$EDIT_NEW_IDX key=$EDIT_NEW_KEY class=$PLAN_CLASS"
    echo
    ok "Connection '$EDIT_NEW_NAME' updated (${PLAN_CLASS}: $(plan_class_label "$PLAN_CLASS"))."
    local fcmd
    if fcmd="$(edit_peer_command_for_foreign)"; then
        echo
        warn "This change also affects the FOREIGN side. Run there:"
        printf '%s\n' "$fcmd"
    fi
}

# Interactive Edit wizard for one FOREIGN-side node.
interactive_edit_foreign_node() { # interactive_edit_foreign_node CURRENT_NAME
    local CURRENT="$1" v
    require_root
    FOREIGN_IP="$(grep -E '^FOREIGN_IP=' "$FOREIGN_CONF" 2>/dev/null | head -n1 | cut -d= -f2)"
    edit_txn_begin
    if ! edit_snapshot_current foreign "$CURRENT"; then
        err "Could not read '$CURRENT'."
        edit_txn_commit
        return 1
    fi
    plan_request_from_current

    echo
    info "Editing node '$CURRENT'. Press Enter to keep the value shown in [brackets]."

    ask v "Iran IP [${PLAN_REQ_IRAN_IP}]" ""
    [[ -n "$v" ]] && PLAN_REQ_IRAN_IP="$v"
    ask v "Name [${PLAN_REQ_NAME}]" ""
    [[ -n "$v" ]] && PLAN_REQ_NAME="$v"
    ask v "Subnet base [${PLAN_REQ_SUBNET_BASE}]" ""
    [[ -n "$v" ]] && PLAN_REQ_SUBNET_BASE="$v"
    ask v "Index [${PLAN_REQ_IDX}]" ""
    [[ -n "$v" ]] && PLAN_REQ_IDX="$v"
    ask v "GRE key [${PLAN_REQ_KEY}]" ""
    [[ -n "$v" ]] && PLAN_REQ_KEY="$v"
    PLAN_REQ_TUN="gre-$PLAN_REQ_NAME"

    preview_connection_edit foreign "$CURRENT" || { edit_txn_commit; return 1; }
    if (( EDIT_PREVIEW_EMPTY )); then
        edit_txn_commit
        return 0
    fi
    if ! confirm "Apply this change?"; then
        info "Cancelled — nothing was changed."
        edit_txn_commit
        return 0
    fi

    if ! edit_connection_txn foreign "$CURRENT"; then
        err "Edit failed and the previous configuration was restored."
        return 1
    fi
    EDIT_NEW_NAME="$PLAN_REQ_NAME"
    EDIT_NEW_IRAN_IP="$PLAN_REQ_IRAN_IP"
    EDIT_NEW_SUBNET_BASE="$PLAN_REQ_SUBNET_BASE"
    EDIT_NEW_IDX="$PLAN_REQ_IDX"
    EDIT_NEW_KEY="$PLAN_REQ_KEY"
    EDIT_NEW_TUN="gre-$PLAN_REQ_NAME"
    audit_log "node-edit from=$CURRENT name=$EDIT_NEW_NAME base=$EDIT_NEW_SUBNET_BASE idx=$EDIT_NEW_IDX key=$EDIT_NEW_KEY class=$PLAN_CLASS"
    echo
    ok "Node '$EDIT_NEW_NAME' updated (${PLAN_CLASS}: $(plan_class_label "$PLAN_CLASS"))."
}

# Pick a node to edit, from the FOREIGN menu.
menu_foreign_node_edit() {
    local files=() f i c
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        files+=("$f")
    done
    (( ${#files[@]} )) || { info "No nodes to edit."; return 0; }
    echo
    echo "  Which node do you want to edit?"
    i=1
    for f in "${files[@]}"; do
        local n ir
        n="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
        ir="$(grep -E '^IRAN_IP=' "$f" | cut -d= -f2)"
        printf '  %d) %s (iran %s)\n' "$i" "$n" "$ir"
        i=$(( i + 1 ))
    done
    ask c "Number (empty = cancel)" ""
    [[ -z "$c" ]] && { info "Cancelled."; return 0; }
    { [[ "$c" =~ ^[0-9]+$ ]] && (( c >= 1 && c < i )); } || { err "Invalid choice."; return 1; }
    local CURRENT
    CURRENT="$(grep -E '^NAME=' "${files[$(( c - 1 ))]}" | cut -d= -f2)"
    interactive_edit_foreign_node "$CURRENT"
}

# Menu option 1: first run = first-peer wizard; afterwards manage the list of
# foreigns connected to this Iran (no more "reconfigure from scratch").
iran_peers_menu() {
    require_root
    migrate_legacy_iran_conf || return 1
    if (( $(peer_count) == 0 )); then
        interactive_add_iran_peer 1 || return
    fi
    local c="" f dot=""
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    while true; do
        echo
        echo   "  -- Foreigns connected to this Iran ----------------------"
        # Both endpoints are shown: the local address is not "obvious" to an
        # operator looking at a server they did not log in to.
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            if load_peer_conf "$f"; then
                if tun_exists "$TUN"; then dot="$(dot_on)"; else dot="$(dot_off)"; fi
                printf '  %s %-10s %s -> %-16s subnet %s.%s.0/30  tunnel %s\n' \
                    "$dot" "$NAME" "$IRAN_IP" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$TUN"
            else
                printf '  %s %s (invalid conf)\n' "$(dot_off)" "$(basename "$f")"
            fi
        done
        echo   "  --------------------------------------------------------"
        echo   "  1) Add a foreign peer"
        echo   "  2) Edit a foreign peer"
        echo   "  3) Remove a foreign peer"
        echo   "  4) Re-apply a foreign peer"
        echo   "  0) Back"
        read -rp "  Select: " c
        case "$c" in
            1) interactive_add_iran_peer 0 ;;
            2) menu_iran_peer_edit ;;
            3) menu_iran_peer_remove ;;
            4) menu_iran_peer_apply ;;
            0) return ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

setup_foreign() {
    require_root
    mkdir -p "$NODES_DIR"

    if [[ ! -f "$FOREIGN_CONF" ]]; then
        local wan_if; wan_if="$(detect_wan_iface)"
        local detected_ip; detected_ip="$(detect_public_ip "$wan_if")"
        echo
        info "FOREIGN server setup (first run)"
        ask FOREIGN_IP "Public IP of THIS foreign server" "$detected_ip"
        valid_ip "$FOREIGN_IP" || { err "Invalid IP: $FOREIGN_IP"; return 1; }

        local icmp_drop="0" gre_whitelist="0"
        local other_tuns=""
        other_tuns="$(unmanaged_gre_tunnels | tr '\n' ' ')"
        if [[ -n "${other_tuns// /}" ]]; then
            warn "Other GRE tunnels already exist on this server: $other_tuns"
            warn "If you enable the GRE whitelist, those tunnels will be BLOCKED (their peer IPs are not whitelisted)."
        fi
        if confirm_yes "Restrict GRE (proto 47) to known Iran node IPs? (recommended)"; then
            gre_whitelist="1"
        fi
        if confirm "Drop inbound ICMP (ping) on this server? (tunnel subnets stay pingable)"; then
            icmp_drop="1"
        fi

        ask_downtime_tolerance

        cat > "$FOREIGN_CONF" <<EOF
FOREIGN_IP=$FOREIGN_IP
ICMP_DROP=$icmp_drop
GRE_WHITELIST=$gre_whitelist
EOF
        chmod 600 "$FOREIGN_CONF"
        write_global_conf "$ASKED_ENABLED" "$ASKED_INTERVAL" "$ASKED_TOL"
        install_service
        audit_log "foreign-setup ip=$FOREIGN_IP icmp_drop=$icmp_drop gre_whitelist=$gre_whitelist tolerance=${ASKED_TOL}m"
    fi
    # shellcheck disable=SC1090
    source "$FOREIGN_CONF"

    echo
    info "Current Iran nodes on this FOREIGN:"
    local cf="" cn=0 cbase=""
    for cf in "$NODES_DIR"/*.conf; do
        [[ -e "$cf" ]] || continue
        cn=$(( cn + 1 ))
        cbase="$(grep -E '^SUBNET_BASE=' "$cf" | cut -d= -f2)"
        printf '  - %s  (iran %s · %s.%s.0/30 · key %s)\n' \
            "$(grep -E '^NAME=' "$cf" | cut -d= -f2)" \
            "$(grep -E '^IRAN_IP=' "$cf" | cut -d= -f2)" \
            "${cbase:-$DEFAULT_SUBNET_BASE}" \
            "$(grep -E '^IDX=' "$cf" | cut -d= -f2)" \
            "$(grep -E '^KEY=' "$cf" | cut -d= -f2)"
    done
    (( cn == 0 )) && echo "  (none yet — this will be the first node)"

    echo
    info "Add a new IRAN node"
    ask NAME    "Node name (e.g. ir01)" "ir01"
    valid_name "$NAME" || { err "Invalid node name: $NAME (use 1-11 letters, digits, '_' or '-'; start with a letter or digit)"; return 1; }
    if [[ -f "$NODES_DIR/$NAME.conf" ]]; then
        err "Node '$NAME' already exists. Remove it first (menu option 3)."
        return 1
    fi

    ask IRAN_IP "Public IP of the Iran server"
    valid_ip "$IRAN_IP" || { err "Invalid IP: $IRAN_IP"; return 1; }

    local SUBNET_BASE=""
    ask SUBNET_BASE "Tunnel subnet base (A.B; the tunnel net is A.B.IDX.0/30)" "$DEFAULT_SUBNET_BASE"
    valid_subnet_base "$SUBNET_BASE" || { err "Invalid subnet base: $SUBNET_BASE"; return 1; }

    local idx; idx="$(next_free_idx "$SUBNET_BASE")" || { err "No free tunnel index left in $SUBNET_BASE"; return 1; }
    ask IDX "Tunnel index (1-254)" "$idx"
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    if node_idx_taken "$SUBNET_BASE" "$IDX"; then
        err "Subnet/index ${SUBNET_BASE}.${IDX} is already used by another node."
        return 1
    fi
    local default_key=$(( 1000 + IDX ))
    ask KEY "GRE key" "$default_key"
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }

    cat > "$NODES_DIR/$NAME.conf" <<EOF
NAME=$NAME
IRAN_IP=$IRAN_IP
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=gre-$NAME
EOF
    chmod 600 "$NODES_DIR/$NAME.conf"

    apply_foreign_node "$NODES_DIR/$NAME.conf" || {
        err "Failed to create the tunnel."
        rm -f "$NODES_DIR/$NAME.conf"
        return 1
    }
    # refresh firewall hardening so the new node's ACCEPT lands before the block rule
    if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
        ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
        ipt_add filter INPUT -p gre -s "$IRAN_IP" \
            -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
        ipt_add filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
    fi
    audit_log "node-add name=$NAME iran_ip=$IRAN_IP base=$SUBNET_BASE idx=$IDX key=$KEY"

    echo
    ok "Node '$NAME' added on FOREIGN."
    echo "------------------------------------------------------------"
    echo "  Run 'gre' -> option 1 on the IRAN server and enter:"
    echo "    Public IP of THIS Iran server : $IRAN_IP"
    echo "    Public IP of the FOREIGN server: $FOREIGN_IP"
    echo "    Peer name                     : $NAME"
    echo "    Tunnel subnet base            : $SUBNET_BASE"
    echo "    Tunnel index                  : $IDX"
    echo "    GRE key                       : $KEY"
    echo "  Or non-interactively:"
    echo "    gre iran peer add --name $NAME --foreign-ip $FOREIGN_IP \\"
    echo "      --iran-ip $IRAN_IP --subnet-base $SUBNET_BASE --idx $IDX --key $KEY"
    echo "------------------------------------------------------------"
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.2  (after the Iran side is up)"
}

# Interactive: pick one configured Iran node and edit it in place. Mirrors
# remove_node's picker so the two feel the same.
edit_node() {
    require_root
    [[ -f "$FOREIGN_CONF" ]] || { err "This server is not configured as FOREIGN."; return 1; }
    local files=("$NODES_DIR"/*.conf)
    [[ -e "${files[0]}" ]] || { info "No Iran nodes configured."; return; }

    echo
    info "Configured Iran nodes:"
    local i=1 f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    for f in "${files[@]}"; do
        NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
        # shellcheck disable=SC1090
        source "$f"
        printf '  %d) %s  (iran ip %s, idx %s, tunnel %s)\n' "$i" "$NAME" "$IRAN_IP" "$IDX" "$TUN"
        i=$(( i + 1 ))
    done
    local choice="" CURRENT
    ask choice "Number of the node to edit (empty = cancel)" ""
    [[ -z "$choice" ]] && { info "Cancelled."; return; }
    { [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )); } || { err "Invalid choice."; return 1; }

    f="${files[$(( choice - 1 ))]}"
    CURRENT="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
    interactive_edit_foreign_node "$CURRENT"
}

remove_node() {
    require_root
    [[ -f "$FOREIGN_CONF" ]] || { err "This server is not configured as FOREIGN."; return 1; }
    local files=("$NODES_DIR"/*.conf)
    [[ -e "${files[0]}" ]] || { info "No Iran nodes configured."; return; }

    echo
    info "Configured Iran nodes:"
    local i=1 f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    for f in "${files[@]}"; do
        NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
        source "$f"
        printf '  %d) %s  (iran ip %s, idx %s, tunnel %s)\n' "$i" "$NAME" "$IRAN_IP" "$IDX" "$TUN"
        i=$(( i + 1 ))
    done
    local choice=""
    ask choice "Number of the node to remove (empty = cancel)" ""
    [[ -z "$choice" ]] && { info "Cancelled."; return; }
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )) || { err "Invalid choice."; return 1; }

    f="${files[$(( choice - 1 ))]}"
    NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
    source "$f"
    confirm "Remove node '$NAME' (tunnel $TUN)?" || { info "Cancelled."; return; }
    delete_tunnel "$TUN"
    ipt_del filter INPUT -p gre -s "$IRAN_IP" \
        -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
    rm -f "$f"
    audit_log "node-remove name=$NAME iran_ip=$IRAN_IP idx=$IDX"
    ok "Node '$NAME' removed."
    info "On the IRAN server, remove the matching peer:  gre iran peer remove --name $NAME"
    info "(No need to uninstall the Iran server — only that one peer.)"
}

restart_all() {
    require_root
    info "Restarting all configured tunnels..."
    stop_all
    apply_all
    audit_log "restart-all"
    ok "Done."
}

stop_menu() {
    require_root
    info "Stopping all configured tunnels (config is kept, service stays enabled)..."
    stop_all
    audit_log "stop-all"
    ok "Done."
}

show_status() {
    migrate_legacy_iran_conf || true
    echo
    info "Roles on this server:"
    [[ -f "$FOREIGN_CONF" ]] && echo "  - FOREIGN ($FOREIGN_CONF)"
    [[ -f "$IRAN_CONF" ]]    && echo "  - IRAN    ($IRAN_CONF)"
    [[ ! -f "$FOREIGN_CONF" && ! -f "$IRAN_CONF" ]] && echo "  - not configured"
    echo
    info "Tunnels:"
    ip -d tunnel show 2>/dev/null | sed 's/^/  /' || true
    echo
    info "Tunnel addresses:"
    ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^gre-/ {print "  " $2 "  " $4}' || true
    echo
    if [[ -f "$IRAN_CONF" ]]; then
        info "Foreign peers (IRAN role):"
        local f NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
              IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
        local found=0
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            found=1
            load_peer_conf "$f" || { warn "  invalid peer conf: $f"; continue; }
            local peer="${SUBNET_BASE}.${IDX}.1" reach="unreachable"
            ping -c 1 -W 2 "$peer" >/dev/null 2>&1 && reach="reachable"
            printf '  - %s: foreign %s, subnet %s.%s.0/30, tunnel %s, tcp [%s] udp [%s], %s\n' \
                "$NAME" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$TUN" \
                "${TCP_PORTS:-none}" "${UDP_PORTS:-none}" "$reach"
            printf '    pair: %s\n' "$(pair_fingerprint "$IRAN_IP" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$KEY")"
        done
        (( found )) || echo "  (none — add one: gre iran peer add)"
        echo
        info "NAT rules added for peers:"
        iptables -t nat -S 2>/dev/null | grep -E 'multi-gre-iran-' | sed 's/^/  /' || echo "  (none)"
        echo
    fi
    if [[ -f "$FOREIGN_CONF" ]]; then
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" FOREIGN_IP=""
        # shellcheck disable=SC1090
        source "$FOREIGN_CONF"
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            echo
            printf '  pair: %s\n' "$(pair_fingerprint "$IRAN_IP" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$KEY")"
            info "Node $NAME: ping Iran end (${SUBNET_BASE}.${IDX}.2):"
            ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.2" 2>&1 | tail -n 2 | sed 's/^/  /' || true
        done
    fi
    echo
    info "systemd:"
    echo "  service:  $(service_state)"
    echo "  watchdog: $(watchdog_state)"
}

uninstall() {
    require_root
    warn "This removes ALL multi-gre configuration from THIS server:"
    warn "tunnels, NAT rules, systemd service + watchdog, sysctl file and $CONF_DIR."
    confirm "Continue with uninstall?" || { info "Aborted."; return; }

    stop_all
    systemctl disable multi-gre.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    remove_watchdog
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$SYSCTL_FILE"
    rm -rf "$CONF_DIR"
    rm -f "$INSTALL_PATH"
    audit_log "uninstall"
    ok "Uninstalled."
    info "Note: net.ipv4.ip_forward stays enabled until reboot (harmless)."
    info "If the original vatanhost gre.sh was also used on this server, run menu option 8 too."
}

legacy_cleanup() {
    require_root
    warn "This removes only artifacts created by the original vatanhost gre.sh:"
    warn "interface vatan-m2, its 132.168.30.0/30 addresses, three broad NAT rules, and the broad ICMP DROP rule."
    warn "If you manually created identical unscoped iptables rules for another purpose, they are indistinguishable and will also be removed."
    confirm "Continue with legacy cleanup on this server?" || { info "Aborted."; return; }

    echo
    # 1) tunnel itself (gre.sh lines: ip tunnel add vatan-m2 ... ; both roles)
    delete_tunnel "vatan-m2"

    # 2) exact NAT rules added by gre.sh on the IRAN side
    #    (note: 'DNAT', 'MASQUERADE' are literal iptables targets, not variables)
    ipt_del_report nat PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2
    ipt_del_report nat PREROUTING -j DNAT --to-destination 132.168.30.1
    ipt_del_report nat POSTROUTING -j MASQUERADE

    # 3) exact filter rule added by gre.sh on the FOREIGN side
    ipt_del_report filter INPUT -p icmp -j DROP

    echo
    audit_log "legacy-cleanup"
    ok "Legacy cleanup finished."
    info "Verify with:  ip tunnel show   |   iptables -t nat -S   |   iptables -S INPUT"
}

sync_installed_hub() { # sync_installed_hub TARGET_VERSION — hub must match the CLI release
    local target_version="$1"
    [[ -d "$HUB_DIR" ]] || return 0
    [[ -f "$HUB_DIR/server/index.js" ]] || return 0
    local installed=""
    installed="$(hub_read_version "$HUB_DIR")"
    if [[ "$installed" == "$target_version" ]]; then
        # Same release: only re-sync when the tree looks incomplete (for example
        # a previous npm ci failed), never a blind re-download.
        if [[ -d "$HUB_DIR/node_modules" ]]; then
            info "gre-hub is already at v$target_version."
            return 0
        fi
        info "gre-hub v$target_version is incomplete; re-syncing..."
    else
        info "gre-hub is installed at ${installed:+v$installed }; syncing dashboard to v$target_version..."
    fi
    if ! HUB_FORCE_HUB_UPDATE=1 hub_update_to_release "v$target_version"; then
        err "gre-hub update failed."
        info "Retry with: sudo gre hub update"
        return 1
    fi
    ok "gre-hub updated to v$target_version."
    return 0
}

self_update() {
    require_root
    command -v curl >/dev/null 2>&1 || { err "curl is required for update."; return 1; }
    info "Checking for updates ($GITHUB_REPO)..."
    local tmp
    tmp="$(mktemp -d)" || { err "mktemp failed"; return 1; }

    local remote_ver="" verified="no"
    # Only install the latest pinned GitHub release. Falling back to main made
    # update results depend on transient asset-download failures and bypassed
    # checksum verification.
    # GitHub connectivity from some networks is flaky — retry each step once.
    local tag="" attempt="" dl_ok=0
    for attempt in 1 2; do
        tag="$(curl -fsSL --max-time 20 "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
            | grep -m1 '"tag_name"' | cut -d'"' -f4)"
        if [[ -z "$tag" ]]; then
            (( attempt == 1 )) && info "GitHub API unreachable (rate limit or network); retrying..." && sleep 3
            continue
        fi
        if curl -fsSL --max-time 60 "https://github.com/${GITHUB_REPO}/releases/download/${tag}/gre" \
            -o "$tmp/gre" 2>/dev/null \
        && curl -fsSL --max-time 60 "https://github.com/${GITHUB_REPO}/releases/download/${tag}/gre.sha256" \
            -o "$tmp/gre.sha256" 2>/dev/null \
        && [[ -s "$tmp/gre" && -s "$tmp/gre.sha256" ]]; then
            dl_ok=1
            break
        fi
        (( attempt == 1 )) && info "Release asset download failed; retrying..." && sleep 3
    done

    if [[ "$dl_ok" != "1" ]]; then
        err "Latest release assets are unavailable after retries; update aborted."
        info "No files were changed. Retry later."
        rm -rf "$tmp"
        return 1
    fi

    if ! command -v sha256sum >/dev/null 2>&1; then
        err "sha256sum is required for a verified update; refusing to install."
        rm -rf "$tmp"
        return 1
    fi
    if (cd "$tmp" && sha256sum -c gre.sha256 >/dev/null 2>&1); then
        verified="yes"
    else
        err "Checksum verification FAILED for release $tag; refusing to update."
        rm -rf "$tmp"
        return 1
    fi
    remote_ver="$(grep -m1 -E '^VERSION=' "$tmp/gre" | cut -d'"' -f2)"

    if ! valid_version "$remote_ver"; then
        err "Could not parse a valid release version."
        rm -rf "$tmp"
        return 1
    fi
    if [[ "$remote_ver" == "$VERSION" ]]; then
        ok "Already up to date (v$VERSION)."
        rm -rf "$tmp"
        sync_installed_hub "$remote_ver" || return 1
        print_release_summary "$remote_ver"
        return 0
    fi
    if ! version_is_newer "$remote_ver" "$VERSION"; then
        warn "Installed v$VERSION is newer than latest release v$remote_ver; refusing to downgrade."
        rm -rf "$tmp"
        return 0
    fi
    if ! bash -n "$tmp/gre" 2>/dev/null; then
        err "Downloaded file failed the syntax check; refusing to install."
        rm -rf "$tmp"
        return 1
    fi
    cp "$tmp/gre" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    rm -rf "$tmp"
    audit_log "self-update from=$VERSION to=$remote_ver checksum=$verified"
    ok "Updated: v$VERSION -> v$remote_ver (checksum verified: $verified)"

    sync_installed_hub "$remote_ver" || {
        err "CLI updated to v$remote_ver, but gre-hub update did not complete."
        return 1
    }

    print_release_summary "$remote_ver"
    info "Run 'gre' again to use the new version."
    exit 0
}

# One unambiguous block at the end of any update: what the CLI is, what the hub
# is, and which release both came from. If these ever differ, one of the two
# halves of the upgrade did not land.
print_release_summary() { # print_release_summary TARGET_VERSION
    local target="$1" hub_ver="" hub_state="not installed" running=""
    if [[ -f "$HUB_DIR/server/index.js" ]]; then
        hub_ver="$(hub_read_version "$HUB_DIR")"
        hub_state="${hub_ver:+v$hub_ver}"
        running="$(hub_meta_version 2>/dev/null || true)"
        if [[ -n "$running" ]]; then
            hub_state="${hub_state} (running v$running)"
        fi
    fi
    echo
    echo "  ${C_BOLD:-}gre-manager:${C_RESET:-} v$target"
    echo "  ${C_BOLD:-}gre-hub:    ${C_RESET:-} ${hub_state}"
    echo "  ${C_BOLD:-}release:    ${C_RESET:-} v$target"
    echo
    if [[ -n "$hub_ver" && "$hub_ver" != "$target" ]]; then
        warn "gre-hub (v$hub_ver) does not match the CLI release (v$target); run 'gre hub update'."
    fi
    if [[ -n "$running" && -n "$hub_ver" && "$running" != "$hub_ver" ]]; then
        warn "The running gre-hub process (v$running) does not match the installed files (v$hub_ver); restart it: sudo gre hub restart"
    fi
    return 0
}

# ------------------------------------------------------------- gre-hub (web dashboard)
HUB_DIR="/opt/gre-hub"
HUB_SERVICE_FILE="/etc/systemd/system/gre-hub.service"
HUB_PORT_DEFAULT=3939

hub_curl_get() { # hub_curl_get URL DEST — honors the test override, otherwise curl
    local url="$1" dest="$2"
    if [[ -n "${HUB_TEST_CURL_CMD:-}" ]]; then
        # shellcheck disable=SC2086  # intentional word splitting for the override
        $HUB_TEST_CURL_CMD "$url" > "$dest"
        return $?
    fi
    curl -fsSL --max-time 90 "$url" -o "$dest" 2>/dev/null
}

hub_curl_text() { # hub_curl_text URL — prints the body, non-zero on failure
    local url="$1"
    if [[ -n "${HUB_TEST_CURL_CMD:-}" ]]; then
        # shellcheck disable=SC2086
        $HUB_TEST_CURL_CMD "$url"
        return $?
    fi
    curl -fsSL --max-time 20 "$url" 2>/dev/null
}

# Resolve the GitHub release tag to install from.
#   explicit tag  -> used as-is (used by `gre hub install <tag>`)
#   latest|""     -> the newest stable release
# A 404 of /releases/latest means the repo has no release: for `latest` we then
# fall back to the tag matching this script's VERSION, never to main.
resolve_release_tag() {
    local want="${1:-latest}" tag=""
    if [[ -n "$want" && "$want" != "latest" ]]; then
        printf '%s\n' "$want"
        return 0
    fi
    tag="$(hub_curl_text "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    if [[ -n "$tag" ]]; then
        printf '%s\n' "$tag"
        return 0
    fi
    printf 'v%s\n' "$VERSION"
}

hub_read_version() { # hub_read_version DIR [COMMIT] — version of an installed/staged hub
    local dir="$1" commit="${2:-}"
    local v=""
    if [[ -n "$commit" && -f "${dir}/build-info.json" ]]; then
        v="$(grep -m1 '"version"' "${dir}/build-info.json" | cut -d'"' -f4)"
    fi
    if [[ -z "$v" && -f "${dir}/VERSION" ]]; then
        v="$(tr -d '[:space:]' < "${dir}/VERSION")"
    fi
    if [[ -z "$v" && -f "${dir}/package.json" ]]; then
        v="$(grep -m1 '"version"' "${dir}/package.json" | cut -d'"' -f4)"
    fi
    printf '%s\n' "$v"
}

hub_service_active() {
    systemctl is-active gre-hub.service >/dev/null 2>&1
}

hub_service_restart() { # returns non-zero only when the unit refuses to start
    systemctl daemon-reload 2>/dev/null || true
    if [[ -f "$HUB_SERVICE_FILE" ]]; then
        systemctl enable gre-hub.service >/dev/null 2>&1 || true
    fi
    if systemctl restart gre-hub.service 2>/dev/null; then
        return 0
    fi
    return 1
}

# Make sure the unit exists. On a fresh install it is written; on an existing
# install a missing/renamed unit file is restored, because losing the unit must
# not silently break a hub that was already running.
hub_ensure_service() {
    if [[ -f "$HUB_SERVICE_FILE" ]]; then
        return 0
    fi
    cat > "$HUB_SERVICE_FILE" <<EOF
[Unit]
Description=gre-hub web dashboard (gre-manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$HUB_DIR
Environment=PORT=$HUB_PORT_DEFAULT HUB_HOST=127.0.0.1
ExecStart=$(command -v node) server/index.js
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p "$(dirname "$HUB_SERVICE_FILE")"
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable gre-hub.service >/dev/null 2>&1 || true
}

# Install runtime dependencies. better-sqlite3 is a NATIVE module: if its install
# script does not run, npm still reports success but the hub then dies with
# "Could not locate the bindings file". Recent npm versions refuse to run
# dependency install scripts unless the package allows them, which is why the
# hub ships an .npmrc with `allow-scripts=true`. A plain `npm ci` is therefore
# not sufficient on its own, and `--allow-scripts` is deliberately NOT passed on
# the command line: npm 11 rejects it for project-scoped installs.
hub_npm_ci() { # hub_npm_ci DIR
    local dir="$1"

    # Explicit opt-out for air-gapped hosts and for the test suite.
    if [[ "${HUB_SKIP_NPM:-0}" == "1" ]]; then
        info "HUB_SKIP_NPM=1: skipping dependency installation."
        return 0
    fi
    if [[ -n "${HUB_TEST_NPM_CMD:-}" ]]; then
        # shellcheck disable=SC2086
        (cd "$dir" && $HUB_TEST_NPM_CMD)
        return $?
    fi

    if [[ ! -f "$dir/.npmrc" ]]; then
        warn "The hub package has no .npmrc; native modules may not build."
    fi

    info "Installing dependencies (npm ci)..."
    if (cd "$dir" && npm ci --omit=dev --no-audit --no-fund); then
        return 0
    fi

    # The native module compiles from source when no prebuilt binary matches, so
    # make sure a toolchain exists before retrying.
    warn "Dependency install failed; installing build tools and retrying..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y build-essential python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc-c++ make python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc-c++ make python3
    fi
    if (cd "$dir" && npm ci --omit=dev --no-audit --no-fund); then
        return 0
    fi

    # Last resort: install the tree without lifecycle scripts so the dashboard
    # can start for diagnosis, then build the native modules separately.
    warn "Falling back to an install without lifecycle scripts."
    if (cd "$dir" && npm install --omit=dev --no-audit --no-fund --ignore-scripts); then
        warn "Rebuilding native modules (better-sqlite3, ssh2)..."
        (cd "$dir" && npm rebuild better-sqlite3 ssh2 --no-audit --no-fund) && return 0
        warn "Native rebuild failed; the hub will not be able to open its database."
        return 0
    fi
    return 1
}

# Installing the dependency tree is not the same as having a working database
# driver. better-sqlite3 needs a compiled binding, and npm reports a completely
# successful install even when it silently skipped that build (the behaviour
# depends on the npm version and on allow-scripts / ignore-scripts settings we do
# not control). When the binding is missing the hub dies at startup with an
# opaque "Could not locate the bindings file", so check for it here and try to
# repair it before we ever hand the service over.
hub_verify_native_deps() { # hub_verify_native_deps DIR
    local dir="$1"
    if [[ "${HUB_SKIP_NPM:-0}" == "1" ]]; then
        return 0
    fi
    if [[ -n "${HUB_TEST_NPM_CMD:-}" ]]; then
        return 0
    fi
    (cd "$dir" && node -e "require('better-sqlite3')" >/dev/null 2>&1) && return 0

    warn "better-sqlite3 has no working binding after install; rebuilding natively..."
    (cd "$dir" && npm rebuild better-sqlite3 --no-audit --no-fund) >/dev/null 2>&1 || true
    if (cd "$dir" && node -e "require('better-sqlite3')" >/dev/null 2>&1); then
        return 0
    fi

    # A source build needs a toolchain; install one and make one final attempt.
    warn "Installing build tools and rebuilding better-sqlite3..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y build-essential python3 >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc-c++ make python3 >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc-c++ make python3 >/dev/null 2>&1 || true
    fi
    (cd "$dir" && npm rebuild better-sqlite3 --no-audit --no-fund) >/dev/null 2>&1 || true
    if (cd "$dir" && node -e "require('better-sqlite3')" >/dev/null 2>&1); then
        return 0
    fi

    err "gre-hub cannot load its database driver (better-sqlite3 has no compiled binding)."
    err "The installation was left untouched. Fix on the target host and retry:"
    err "  cd $dir && npm rebuild better-sqlite3"
    err "  Installing a C++ toolchain first usually fixes it:"
    err "  apt-get install -y build-essential python3   # or dnf/yum equivalent"
    return 1
}

# Download a release tarball + its checksum and verify them. Prints nothing on
# success; the verified archive is left at $2.
hub_fetch_release() { # hub_fetch_release TAG DEST_TGZ
    local tag="$1" dest="$2"
    local base="https://github.com/${GITHUB_REPO}/releases/download/${tag}"
    local attempt="" ok=0

    command -v sha256sum >/dev/null 2>&1 || {
        err "sha256sum is required so the hub package can be verified; refusing to install."
        return 1
    }

    # Never reuse a stale archive from an earlier attempt.
    rm -f "$dest" "${dest}.sha256"

    for attempt in 1 2; do
        if hub_curl_get "${base}/gre-hub.tar.gz" "$dest" \
            && hub_curl_get "${base}/gre-hub.tar.gz.sha256" "${dest}.sha256" \
            && [[ -s "$dest" && -s "${dest}.sha256" ]]; then
            ok=1
            break
        fi
        (( attempt == 1 )) && info "Hub package download failed for ${tag}; retrying..." && sleep 3
    done
    if (( ! ok )); then
        err "Could not download the gre-hub package for release ${tag}."
        rm -f "$dest" "${dest}.sha256"
        return 1
    fi

    # A checksum that does not name the tarball is worse than no checksum: it
    # would make `sha256sum -c` pass by verifying something else.
    if ! grep -q 'gre-hub\.tar\.gz' "${dest}.sha256"; then
        err "Release ${tag} has an unusable checksum file; refusing to install."
        rm -f "$dest" "${dest}.sha256"
        return 1
    fi
    if ! (cd "$(dirname "$dest")" && sha256sum -c "$(basename "${dest}").sha256" >/dev/null 2>&1); then
        err "Checksum verification FAILED for release ${tag}; refusing to install."
        rm -f "$dest" "${dest}.sha256"
        return 1
    fi
    return 0
}

hub_extract() { # hub_extract TGZ DEST_DIR — validated extraction of the hub/ tree
    local tgz="$1" dest="$2" listing=""
    listing="$(tar tzf "$tgz" 2>/dev/null)" || { err "Could not read the hub archive."; return 1; }
    # Path-traversal guard: a release archive must never contain absolute paths.
    if grep -qE '(^|/)\.\.(/|$)|^/' <<< "$listing"; then
        err "The hub archive contains an unsafe path; refusing to install."
        return 1
    fi
    rm -rf "$dest"
    mkdir -p "$dest"
    if ! tar xzf "$tgz" -C "$dest" 2>/dev/null; then
        err "Could not extract the hub archive."
        return 1
    fi
    local src="$dest/hub"
    if [[ ! -f "$src/package.json" ]]; then
        src="$(dirname "$(find "$dest" -maxdepth 3 -path '*/hub/package.json' 2>/dev/null | head -1)")"
    fi
    if [[ -z "$src" || ! -f "$src/package.json" ]]; then
        err "hub package not found in the archive."
        return 1
    fi
    printf '%s\n' "$src"
}

# Stage -> install deps -> atomic swap -> restart -> verify -> roll back on
# failure. $HUB_DIR/data is never touched by the swap.
hub_deploy_tarball() { # hub_deploy_tarball TGZ TAG
    local tgz="$1" tag="$2"
    local tmp="" src="" stage="" backup="" newver="" running=""

    tmp="$(mktemp -d)" || { err "mktemp failed"; return 1; }
    # shellcheck disable=SC2064  # expand $tmp now, on purpose
    trap "rm -rf '$tmp'" RETURN

    src="$(hub_extract "$tgz" "$tmp/x")" || return 1
    stage="$tmp/stage"
    mkdir -p "$stage"
    cp -a "$src/." "$stage/"
    if [[ -f "$HUB_DIR/data" ]]; then
        warn "Ignoring unexpected regular file at $HUB_DIR/data."
    fi

    newver="$(hub_read_version "$stage" yes)"
    if [[ -z "$newver" ]]; then
        warn "The hub package does not declare a version; continuing without a version check."
    fi

    hub_npm_ci "$stage" || { err "Dependency installation failed; $HUB_DIR was left untouched."; return 1; }
    # A successful `npm ci` is not proof of a usable database driver, and the hub
    # cannot start without one. Verify (and try to repair) before swapping in the
    # new build, so a broken install never reaches the running service.
    hub_verify_native_deps "$stage" || return 1

    mkdir -p "$HUB_DIR"
    backup="${HUB_DIR}.old.$$"
    rm -rf "$backup"
    mkdir -p "$backup"
    if ! cp -a "$HUB_DIR/." "$backup/" 2>/dev/null; then
        warn "Could not snapshot the current hub before upgrading."
    fi
    rm -rf "$backup/data"

    # Swap only generated code: data/ (hub.db, master.key, ssh keys) stays put.
    find "$HUB_DIR" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} + 2>/dev/null || true
    cp -a "$stage/." "$HUB_DIR/"

    hub_ensure_service || true
    if ! hub_service_restart; then
        err "gre-hub did not restart after the upgrade."
        hub_restore_backup "$backup"
        rm -rf "$backup"
        return 1
    fi

    sleep 2
    if [[ "${HUB_SKIP_HEALTHCHECK:-0}" != "1" ]]; then
        running="$(hub_meta_version)"
        if [[ -n "$newver" && -n "$running" && "$running" != "$newver" ]]; then
            err "gre-hub restarted but reports v${running} while v${newver} was installed."
            info "This usually means a stale process is still bound to the port."
            hub_restore_backup "$backup"
            rm -rf "$backup"
            return 1
        fi
        if [[ -z "$running" ]] && ! hub_service_active; then
            err "gre-hub is not running after the upgrade."
            hub_restore_backup "$backup"
            rm -rf "$backup"
            return 1
        fi
    fi

    rm -rf "$backup"
    audit_log "hub-deploy tag=$tag version=${newver:-unknown}"
    ok "gre-hub updated to ${newver:+v$newver }(${tag})."
    return 0
}

# Restore a pre-upgrade snapshot. data/ is re-attached from the live directory
# if the snapshot is missing it, so this can never lose hub.db/master.key.
hub_restore_backup() { # hub_restore_backup BACKUP_DIR
    local backup="$1"
    [[ -d "$backup" ]] || return 0
    local keep="$backup/data.keep.$$"
    if [[ -d "$HUB_DIR/data" ]]; then
        cp -a "$HUB_DIR/data" "$keep" 2>/dev/null || true
    fi
    find "$HUB_DIR" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} + 2>/dev/null || true
    cp -a "$backup/." "$HUB_DIR/" 2>/dev/null || true
    rm -rf "$HUB_DIR/data"
    if [[ -d "$keep" ]]; then mv "$keep" "$HUB_DIR/data"; fi
    warn "Restored the previous gre-hub build from $backup."
    hub_service_restart >/dev/null 2>&1 || warn "The restored gre-hub did not restart."
}

hub_meta_version() { # hub_meta_version — version reported by the running hub, if any
    local body="" port="${PORT:-$HUB_PORT_DEFAULT}"
    body="$(hub_curl_text "http://127.0.0.1:${port}/api/meta" 2>/dev/null)" || return 1
    [[ -n "$body" ]] || return 1
    printf '%s' "$body" | tr ',' '\n' | grep -m1 '"version"' | cut -d'"' -f4
}

# The authoritative hub update path, shared by `gre update` and `gre hub update`.
hub_update_to_release() { # hub_update_to_release [TAG|latest]
    require_root
    local want="${1:-latest}"
    [[ -d "$HUB_DIR" ]] || { err "gre-hub is not installed at $HUB_DIR."; return 1; }
    command -v curl >/dev/null 2>&1 || [[ -n "${HUB_TEST_CURL_CMD:-}" ]] || { err "curl is required."; return 1; }
    command -v tar >/dev/null 2>&1 || { err "tar is required."; return 1; }
    hub_ensure_node || return 1

    local tag="" target="" installed="" tmp="" tgz=""
    tag="$(resolve_release_tag "$want")"
    if [[ -z "$tag" ]]; then
        err "Could not determine which release to install."
        return 1
    fi
    target="${tag#v}"
    installed="$(hub_read_version "$HUB_DIR")"

    if [[ -n "${HUB_FORCE_HUB_UPDATE:-}" || "$want" != "latest" ]]; then
        info "Target release: ${tag}${installed:+ (installed: v$installed)}."
    elif [[ "$installed" == "$target" ]]; then
        # Same release: only re-sync when the on-disk tree looks incomplete.
        if [[ -d "$HUB_DIR/node_modules" && -f "$HUB_DIR/server/index.js" ]]; then
            ok "gre-hub is already at v${target}."
            return 0
        fi
        info "gre-hub v${target} is installed but incomplete; re-syncing..."
    else
        info "Updating gre-hub ${installed:+from v$installed }to v${target}..."
    fi

    tmp="$(mktemp -d)" || { err "mktemp failed"; return 1; }
    tgz="$tmp/gre-hub.tar.gz"
    if ! hub_fetch_release "$tag" "$tgz"; then
        rm -rf "$tmp"
        err "gre-hub was not changed."
        return 1
    fi
    if ! hub_deploy_tarball "$tgz" "$tag"; then
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    return 0
}

hub_status_text() {
    if [[ ! -d "$HUB_DIR" ]]; then
        echo "not installed"
        return 0
    fi
    local st en
    st="$(systemctl is-active gre-hub.service 2>/dev/null || echo inactive)"
    en="$(systemctl is-enabled gre-hub.service 2>/dev/null || echo disabled)"
    echo "installed ($st, $en, $HUB_DIR, port $HUB_PORT_DEFAULT)"
}

hub_ensure_node() {
    local major=0
    if command -v node >/dev/null 2>&1; then
        major="$(node -v 2>/dev/null | sed 's/^v//;s/\..*//')"
    fi
    if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 18 )); then
        ok "Node.js $(node -v) found"
        return 0
    fi
    info "Node.js >= 18 is required; installing Node.js 22 (NodeSource)..."
    if command -v apt-get >/dev/null 2>&1; then
        curl -fsSL --max-time 90 https://deb.nodesource.com/setup_22.x | bash - || return 1
        apt-get install -y nodejs || return 1
    elif command -v dnf >/dev/null 2>&1; then
        curl -fsSL --max-time 90 https://rpm.nodesource.com/setup_22.x | bash - || return 1
        dnf install -y nodejs || return 1
    elif command -v yum >/dev/null 2>&1; then
        curl -fsSL --max-time 90 https://rpm.nodesource.com/setup_22.x | bash - || return 1
        yum install -y nodejs || return 1
    else
        err "No supported package manager found; install Node.js >= 18 manually."
        return 1
    fi
    ok "Node.js $(node -v) installed"
}

hub_install() { # hub_install [--yes] [TAG|latest]
    require_root
    local noninteractive=0 tag="latest"
    local arg=""
    for arg in "$@"; do
        case "$arg" in
            --yes|-y) noninteractive=1 ;;
            "") ;;
            *) tag="$arg" ;;
        esac
    done
    local was_installed=0
    [[ -f "$HUB_DIR/server/index.js" ]] && was_installed=1
    command -v curl >/dev/null 2>&1 || [[ -n "${HUB_TEST_CURL_CMD:-}" ]] || { err "curl is required."; return 1; }
    command -v ssh-keygen >/dev/null 2>&1 || warn "ssh-keygen not found (usually in openssh-client) — hub SSH keys need it."
    hub_ensure_node || return 1
    mkdir -p "$HUB_DIR"

    # An explicit tag on an existing installation is an intentional change of
    # release, so allow it even if it is not newer.
    if (( was_installed )) && [[ "$tag" != "latest" ]]; then
        HUB_FORCE_HUB_UPDATE=1 hub_update_to_release "$tag" || {
            err "gre-hub installation failed."
            return 1
        }
    else
        hub_update_to_release "$tag" || {
            err "gre-hub installation failed."
            return 1
        }
    fi
    audit_log "hub-install dir=$HUB_DIR tag=$tag"

    echo
    ok "gre-hub is installed and running."
    info "On this server:   http://127.0.0.1:$HUB_PORT_DEFAULT"
    info "From your PC:     ssh -L $HUB_PORT_DEFAULT:127.0.0.1:$HUB_PORT_DEFAULT root@<this-server-ip>"
    info "                  then open http://127.0.0.1:$HUB_PORT_DEFAULT"
    info "First visit: create the hub password, then enable 2FA in Settings."
    info "Manage: gre hub [status|update|start|stop|restart|uninstall]"
    (( noninteractive )) && return 0
    echo
    if confirm "Set up web access with a domain + free HTTPS now?"; then
        hub_expose || true
    else
        info "Later: gre hub domain  (or menu -> gre-hub -> option 5)"
    fi
}

hub_update_cmd() { # gre hub update [TAG] — always the newest stable release
    require_root
    local tag="${1:-latest}"
    hub_ensure_node || return 1
    if ! hub_update_to_release "$tag"; then
        return 1
    fi
    local running=""
    running="$(hub_meta_version 2>/dev/null || true)"
    echo
    ok "gre-hub is up to date${running:+ (running v$running)}."
    print_release_summary "$VERSION"
    info "Verify in the UI top bar or with:  curl -s http://127.0.0.1:$HUB_PORT_DEFAULT/api/meta"
    return 0
}

hub_menu() { # gre hub [install|update|status|start|stop|restart|uninstall]
    require_root
    case "${1:-status}" in
        install|reinstall) hub_install "${2:-}" "${3:-}" ;;
        update|upgrade)    hub_update_cmd "${2:-latest}" ;;
        status)
            echo "gre-hub: $(hub_status_text)"
            if [[ -d "$HUB_DIR" ]]; then
                local inst run
                inst="$(hub_read_version "$HUB_DIR")"
                run="$(hub_meta_version 2>/dev/null || true)"
                [[ -n "$inst" ]] && echo "gre-hub files:     v$inst"
                [[ -n "$run" ]] && echo "gre-hub running:    v$run"
                if [[ -n "$inst" && -n "$run" && "$inst" != "$run" ]]; then
                    warn "Installed files and the running process disagree; run 'gre hub update'."
                fi
                systemctl status gre-hub.service --no-pager 2>/dev/null | head -n 5 || true
            fi
            ;;
        start)   systemctl start gre-hub.service   && ok "gre-hub started" ;;
        stop)    systemctl stop gre-hub.service    && ok "gre-hub stopped" ;;
        restart) systemctl restart gre-hub.service && ok "gre-hub restarted" ;;
        domain)    hub_expose "${2:-}" ;;
        unexpose)  hub_unexpose ;;
        uninstall)
            warn "This removes the gre-hub service and $HUB_DIR (including dashboard data)."
            confirm "Continue with gre-hub uninstall?" || { info "Aborted."; return; }
            systemctl disable --now gre-hub.service >/dev/null 2>&1 || true
            rm -f "$HUB_SERVICE_FILE"
            systemctl daemon-reload 2>/dev/null || true
            rm -rf "$HUB_DIR"
            audit_log "hub-uninstall"
            ok "gre-hub removed."
            ;;
        *) err "Usage: gre hub [install [TAG]|update [TAG]|status|start|stop|restart|domain [DOMAIN]|unexpose|uninstall]"; return 1 ;;
    esac
}

# ------------------------------------------------------------- gre-hub web exposure (domain + HTTPS)
CADDY_BIN="/usr/local/bin/caddy"
CADDY_UNIT="/etc/systemd/system/caddy.service"
CADDY_MAIN="/etc/caddy/Caddyfile"
CADDY_SITES="/etc/caddy/sites"
HUB_DOMAIN_FILE="/etc/gre-hub/domain"
HUB_WEB_DROPIN="/etc/systemd/system/gre-hub.service.d/web.conf"

hub_domain_current() {
    [[ -f "$HUB_DOMAIN_FILE" ]] && grep -E '^DOMAIN=' "$HUB_DOMAIN_FILE" | cut -d= -f2
    return 0
}

valid_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]
}

hub_ensure_caddy() {
    if [[ -x "$CADDY_BIN" ]] || command -v caddy >/dev/null 2>&1; then
        ok "Caddy found: $(caddy version 2>/dev/null | awk '{print $1}')"
        return 0
    fi
    info "Installing Caddy (official static binary)..."
    local arch="" pkg="linux_amd64"
    arch="$(uname -m)"
    [[ "$arch" == "aarch64" || "$arch" == "arm64" ]] && pkg="linux_arm64"
    local tmp="" url=""
    tmp="$(mktemp -d)" || return 1
    url="$(curl -fsSL --max-time 30 "https://api.github.com/repos/caddyserver/caddy/releases/latest" 2>/dev/null \
        | grep -m1 "browser_download_url.*${pkg}\.tar\.gz" | cut -d'"' -f4)"
    if [[ -z "$url" ]] || ! curl -fsSL --max-time 240 "$url" -o "$tmp/caddy.tar.gz" 2>/dev/null; then
        err "Could not download Caddy."
        rm -rf "$tmp"; return 1
    fi
    tar xzf "$tmp/caddy.tar.gz" -C "$tmp" caddy || { err "Could not extract Caddy."; rm -rf "$tmp"; return 1; }
    mv "$tmp/caddy" "$CADDY_BIN"
    chmod +x "$CADDY_BIN"
    rm -rf "$tmp"
    cat > "$CADDY_UNIT" <<EOF
[Unit]
Description=Caddy web server (installed by gre-manager for gre-hub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$CADDY_BIN run --environ --config $CADDY_MAIN
ExecReload=$CADDY_BIN reload --config $CADDY_MAIN
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p /etc/caddy "$CADDY_SITES"
    systemctl daemon-reload
    ok "Caddy $("$CADDY_BIN" version 2>/dev/null | awk '{print $1}') installed"
}

hub_expose() { # hub_expose [domain]
    require_root
    [[ -d "$HUB_DIR" ]] || { err "gre-hub is not installed yet (run: gre hub install)."; return 1; }
    local domain="${1:-}"
    if [[ -z "$domain" ]]; then
        ask domain "Domain for the dashboard (e.g. hub.example.com)" "$(hub_domain_current)"
    fi
    valid_domain "$domain" || { err "Invalid domain: $domain"; return 1; }

    # DNS sanity check (warn only — user may still be propagating)
    local my_ip="" dns_ip=""
    my_ip="$(detect_public_ip "$(detect_wan_iface)")"
    dns_ip="$(getent hosts "$domain" 2>/dev/null | awk '{print $1; exit}')"
    if [[ -z "$dns_ip" ]]; then
        warn "DNS: $domain does not resolve from this server yet."
    elif [[ -n "$my_ip" && "$dns_ip" != "$my_ip" ]]; then
        warn "DNS: $domain -> $dns_ip, but this server's IP is $my_ip."
    fi
    if [[ -z "$dns_ip" ]] || [[ -n "$my_ip" && "$dns_ip" != "$my_ip" ]]; then
        confirm "Continue anyway? (Let's Encrypt fails until DNS points here)" || { info "Aborted."; return 1; }
    fi

    # port 80/443 must be free (or already ours via caddy)
    if ! systemctl is-active caddy.service >/dev/null 2>&1; then
        grep -q . <<< "$(ss -tlnH 'sport = :80' 2>/dev/null)" && { err "Port 80 is used by another service."; return 1; }
        grep -q . <<< "$(ss -tlnH 'sport = :443' 2>/dev/null)" && { err "Port 443 is used by another service."; return 1; }
    fi

    hub_ensure_caddy || return 1
    mkdir -p /etc/caddy "$CADDY_SITES"
    cat > "$CADDY_SITES/gre-hub.caddy" <<EOF
# gre-hub (managed by 'gre hub domain')
$domain {
	reverse_proxy 127.0.0.1:$HUB_PORT_DEFAULT
}
EOF
    if [[ ! -f "$CADDY_MAIN" ]]; then
        printf 'import %s/*.caddy\n' "$CADDY_SITES" > "$CADDY_MAIN"
    elif ! grep -q "$CADDY_SITES" "$CADDY_MAIN"; then
        printf '\nimport %s/*.caddy\n' "$CADDY_SITES" >> "$CADDY_MAIN"
    fi

    mkdir -p "$(dirname "$HUB_WEB_DROPIN")"
    printf '[Service]\nEnvironment=HUB_SECURE=1\n' > "$HUB_WEB_DROPIN"
    mkdir -p "$(dirname "$HUB_DOMAIN_FILE")"
    printf 'DOMAIN=%s\n' "$domain" > "$HUB_DOMAIN_FILE"
    chmod 600 "$HUB_DOMAIN_FILE"

    systemctl daemon-reload
    systemctl enable --now caddy.service >/dev/null 2>&1 || true
    systemctl reload caddy.service 2>/dev/null || systemctl restart caddy.service
    systemctl restart gre-hub.service >/dev/null 2>&1 || true
    audit_log "hub-expose domain=$domain"

    echo
    ok "Web access enabled:  https://$domain"
    info "Let's Encrypt issues the certificate on first request; if it is not up yet, wait ~30s and re-check."
    info "Verify:  curl -fsSI https://$domain"
}

hub_unexpose() {
    require_root
    rm -f "$CADDY_SITES/gre-hub.caddy" "$HUB_WEB_DROPIN" "$HUB_DOMAIN_FILE"
    systemctl daemon-reload
    systemctl reload caddy.service 2>/dev/null || systemctl restart caddy.service 2>/dev/null || true
    systemctl restart gre-hub.service >/dev/null 2>&1 || true
    audit_log "hub-unexpose"
    ok "Web access disabled — the hub listens on 127.0.0.1:$HUB_PORT_DEFAULT again (SSH tunnel still works)."
}

hub_settings_menu() {
    require_root
    local c="" web=""
    while true; do
        web="$(hub_domain_current)"
        echo
        echo   "  ── gre-hub dashboard ─────────────────────────────────────"
        printf '  Status: %s\n' "$(hub_status_text)"
        if [[ -n "$web" ]]; then
            printf '  Web:    %shttps://%s%s\n' "$C_GREEN" "$web" "$C_RESET"
        else
            echo   "  Web:    not exposed (localhost only)"
        fi
        echo   "  1) Install / reinstall"
        echo   "  2) Start"
        echo   "  3) Stop"
        echo   "  4) Restart"
        echo   "  5) Set up web access (domain + HTTPS)"
        echo   "  6) Disable web access"
        echo   "  7) Uninstall"
        echo   "  0) Back"
        read -rp "  Select: " c
        case "$c" in
            1) hub_install ;;
            2) hub_menu start ;;
            3) hub_menu stop ;;
            4) hub_menu restart ;;
            5) hub_expose ;;
            6) hub_unexpose ;;
            7) hub_menu uninstall ;;
            0) return ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

# ------------------------------------------------------------- purge (scorched earth)
purge_tunnels() { # delete EVERY gre/gretap tunnel, not just configured ones
    local name=""
    ip -o link show type gre 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | \
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        ip link set "$name" down 2>/dev/null || true
        if ip tunnel del "$name" 2>/dev/null; then
            ok "Removed GRE tunnel: $name"
        fi
    done
    ip -o link show type gretap 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | \
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        ip link set "$name" down 2>/dev/null || true
        if ip tunnel del "$name" 2>/dev/null; then
            ok "Removed GRETAP tunnel: $name"
        fi
    done
}

purge_iptables() { # delete every rule mentioning GRE artifacts in filter/nat/mangle
    # 'multi-gre' covers every commented rule incl. the v2 per-peer style
    # (multi-gre-iran-<peer>-*, multi-gre-node-*, ...); the 10.2xx.x. pattern
    # covers un-commented v1 rules referencing tunnel subnets 10.200-10.259.
    local table line spec chain
    local -a parts=()
    for table in filter nat mangle; do
        iptables -t "$table" -S 2>/dev/null | \
        grep -E 'multi-gre|vatan|gre-|-p gre |10\.2[0-5][0-9]\.|132\.168\.30\.' | \
        while IFS= read -r line; do
            case "$line" in
                -A\ *)
                    spec="${line#-A }"
                    chain="${spec%% *}"
                    read -ra parts <<< "$spec"
                    if iptables -t "$table" -D "${parts[@]}" 2>/dev/null; then
                        ok "Removed rule [$table]: $line"
                    fi
                    ;;
            esac
        done
    done
}

purge_all() { # gre purge [--yes]
    require_root
    local YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y)  YES=1; shift ;;
            --help|-h) echo "Usage: gre purge [--yes]"; return 0 ;;
            *)         err "Unknown option: $1"; err "Usage: gre purge [--yes]"; return 1 ;;
        esac
    done

    echo
    warn "PURGE — this removes EVERYTHING GRE-related from THIS server:"
    warn "  - ALL GRE/GRETAP tunnels (even ones NOT created by gre-manager, incl. vatan-m2)"
    warn "  - every iptables rule mentioning multi-gre (incl. per-peer multi-gre-iran-*),"
    warn "    GRE interfaces, proto 47, tunnel subnets 10.2xx.x.x or 132.168.30.0/30"
    warn "    (tables: filter, nat, mangle)"
    warn "  - the legacy vatanhost broad rules (unscoped MASQUERADE + broad ICMP DROP)"
    warn "  - systemd units: multi-gre.service, multi-gre-watchdog.service/timer"
    warn "  - /etc/multi-gre, the sysctl file, the audit log, bash completion"
    warn "  - the 'gre' and 'multi-gre-manager' commands themselves"
    warn "If other software on this server uses GRE or identical broad rules, it WILL be affected."
    warn "This cannot be undone."
    if (( ! YES )); then
        confirm "Really PURGE everything GRE from this server?" || { info "Aborted."; return; }
    fi

    echo
    info "Step 1/5: stopping configured tunnels and rules..."
    stop_all

    info "Step 2/5: removing ALL GRE tunnels (including foreign/legacy ones)..."
    purge_tunnels

    info "Step 3/5: sweeping iptables (filter, nat, mangle)..."
    purge_iptables
    # legacy vatanhost broad rules that carry no GRE identifier
    ipt_del_report nat POSTROUTING -j MASQUERADE
    ipt_del_report filter INPUT -p icmp -j DROP

    info "Step 4/5: removing systemd units..."
    systemctl disable --now multi-gre.service multi-gre-watchdog.timer multi-gre-watchdog.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE" "$WATCHDOG_TIMER_FILE" "$WATCHDOG_SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed 2>/dev/null || true
    ok "systemd units removed"

    info "Step 5/5: removing files, config and commands..."
    rm -f "$SYSCTL_FILE"
    rm -rf "$CONF_DIR"
    rm -f /etc/bash_completion.d/gre
    rm -f "$AUDIT_LOG"
    rm -f /usr/local/sbin/multi-gre-manager.sh
    rm -f "$INSTALL_PATH"
    ok "Files removed"

    echo
    ok "PURGE complete — nothing GRE-related from gre-manager (any version) remains."
    info "Verify with:  ip tunnel show   |   iptables -S | grep -i gre   |   iptables -t nat -S | grep -E 'multi-gre|10\\.2[0-5][0-9]|132.168'"
    info "Note: net.ipv4.ip_forward stays enabled until reboot (harmless)."
}

# ------------------------------------------------------------- CLI: node mgmt
cli_node_list() { # gre node list [--json]
    local json=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)     json=1; shift ;;
            --help|-h)  echo "Usage: gre node list [--json]"; return 0 ;;
            *)          err "Unknown option: $1"; err "Usage: gre node list [--json]"; return 1 ;;
        esac
    done
    [[ -f "$FOREIGN_CONF" ]] || { err "This server is not configured as FOREIGN."; return 1; }

    local f NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE"
    if (( json )); then
        local out="[" sep=""
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            out+="${sep}{\"name\":\"$NAME\",\"iran_ip\":\"$IRAN_IP\",\"subnet_base\":\"$SUBNET_BASE\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\"}"
            sep=","
        done
        out+="]"
        printf '%s\n' "$out"
    else
        info "Configured Iran nodes:"
        if ! render_connection_list foreign; then
            info "  (none)"
        fi
        echo
        info "Edit one in place:  gre node edit --name NAME [--ip IRAN_IP] ..."
    fi
}

cli_node_add() { # gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
    require_root
    if [[ ! -f "$FOREIGN_CONF" ]]; then
        err "This server is not configured as FOREIGN yet."
        err "Run 'gre' (menu option 2) once for the initial foreign setup, then retry."
        return 1
    fi
    local NAME="" IRAN_IP="" IDX="" KEY="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)        [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --ip)          [[ -n "${2:-}" ]] || { err "Missing value for --ip"; return 1; }; IRAN_IP="$2"; shift 2 ;;
            --idx)         [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; IDX="$2"; shift 2 ;;
            --key)         [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; KEY="$2"; shift 2 ;;
            --subnet-base) [[ -n "${2:-}" ]] || { err "Missing value for --subnet-base"; return 1; }; SUBNET_BASE="$2"; shift 2 ;;
            --yes|-y)      YES=1; shift ;;
            --help|-h)     echo "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]"; return 0 ;;
            *)             err "Unknown option: $1"
                           err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]"
                           return 1 ;;
        esac
    done
    [[ -n "$NAME" ]]    || { err "Missing required option: --name"; err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]"; return 1; }
    [[ -n "$IRAN_IP" ]] || { err "Missing required option: --ip";   err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]"; return 1; }

    valid_name "$NAME" || { err "Invalid node name: $NAME (use 1-11 letters, digits, '_' or '-'; start with a letter or digit)"; return 1; }
    if [[ -f "$NODES_DIR/$NAME.conf" ]]; then
        err "Node '$NAME' already exists. Remove it first (gre node remove --name $NAME)."
        return 1
    fi
    valid_ip "$IRAN_IP" || { err "Invalid IP: $IRAN_IP"; return 1; }
    valid_subnet_base "$SUBNET_BASE" || { err "Invalid subnet base: $SUBNET_BASE (expected A.B, e.g. 10.201)"; return 1; }

    if [[ -z "$IDX" ]]; then
        IDX="$(next_free_idx "$SUBNET_BASE")" || { err "No free tunnel index left in $SUBNET_BASE"; return 1; }
    fi
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    if node_idx_taken "$SUBNET_BASE" "$IDX"; then
        err "Subnet/index ${SUBNET_BASE}.${IDX} is already used by another node."
        return 1
    fi
    [[ -z "$KEY" ]] && KEY=$(( 1000 + IDX ))
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }

    if (( ! YES )); then
        confirm "Add node '$NAME' (iran ip $IRAN_IP, subnet ${SUBNET_BASE}.${IDX}.0/30, key $KEY)?" || { info "Cancelled."; return; }
    fi

    mkdir -p "$NODES_DIR"
    cat > "$NODES_DIR/$NAME.conf" <<EOF
NAME=$NAME
IRAN_IP=$IRAN_IP
SUBNET_BASE=$SUBNET_BASE
IDX=$IDX
KEY=$KEY
TUN=gre-$NAME
EOF
    chmod 600 "$NODES_DIR/$NAME.conf"

    # FOREIGN_IP must be in scope for apply_foreign_node; GRE_WHITELIST decides
    # whether the firewall hardening below needs a refresh.
    local FOREIGN_IP="" ICMP_DROP="" GRE_WHITELIST=""
    # shellcheck disable=SC1090
    source "$FOREIGN_CONF"

    apply_foreign_node "$NODES_DIR/$NAME.conf" || {
        err "Failed to create the tunnel."
        rm -f "$NODES_DIR/$NAME.conf"
        return 1
    }
    # refresh firewall hardening so the new node's ACCEPT lands before the block rule
    if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
        ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
        ipt_add filter INPUT -p gre -s "$IRAN_IP" \
            -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
        ipt_add filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
    fi
    audit_log "node-add name=$NAME iran_ip=$IRAN_IP base=$SUBNET_BASE idx=$IDX key=$KEY"

    echo
    ok "Node '$NAME' added on FOREIGN."
    echo "------------------------------------------------------------"
    echo "  Run 'gre' -> option 1 on the IRAN server and enter:"
    echo "    Public IP of THIS Iran server : $IRAN_IP"
    echo "    Public IP of the FOREIGN server: $FOREIGN_IP"
    echo "    Peer name                     : $NAME"
    echo "    Tunnel subnet base            : $SUBNET_BASE"
    echo "    Tunnel index                  : $IDX"
    echo "    GRE key                       : $KEY"
    echo "  Or non-interactively:"
    echo "    gre iran peer add --name $NAME --foreign-ip $FOREIGN_IP \\"
    echo "      --iran-ip $IRAN_IP --subnet-base $SUBNET_BASE --idx $IDX --key $KEY"
    echo "------------------------------------------------------------"
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.2  (after the Iran side is up)"
}

# ============================================================ CLI: gre node edit
cli_node_edit() { # gre node edit --name CURRENT [--new-name N] [--ip IRAN_IP] [--foreign-ip IP] [...]
    require_root
    [[ -f "$FOREIGN_CONF" ]] || { err "This server is not configured as FOREIGN."; return 1; }
    local CURRENT="" YES=0 PLAN_ONLY=0
    local R_NAME="" R_IRAN_IP="" R_FOREIGN_IP="" R_SUBNET_BASE="" R_IDX="" R_KEY=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)        [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; CURRENT="$2"; shift 2 ;;
            --new-name)    [[ -n "${2:-}" ]] || { err "Missing value for --new-name"; return 1; }; R_NAME="$2"; shift 2 ;;
            --ip)          [[ -n "${2:-}" ]] || { err "Missing value for --ip"; return 1; }; R_IRAN_IP="$2"; shift 2 ;;
            --foreign-ip)  [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; R_FOREIGN_IP="$2"; shift 2 ;;
            --subnet-base) [[ -n "${2:-}" ]] || { err "Missing value for --subnet-base"; return 1; }; R_SUBNET_BASE="$2"; shift 2 ;;
            --idx)         [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; R_IDX="$2"; shift 2 ;;
            --key)         [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; R_KEY="$2"; shift 2 ;;
            --plan)        PLAN_ONLY=1; shift ;;
            --yes|-y)      YES=1; shift ;;
            --help|-h)     echo "Usage: gre node edit --name CURRENT [--new-name NAME] [--ip IRAN_IP] [--foreign-ip FOREIGN_IP] [--subnet-base A.B] [--idx N] [--key K] [--plan] [--yes]"; return 0 ;;
            *)             err "Unknown option: $1"
                           err "Usage: gre node edit --name CURRENT [--new-name NAME] [--ip IRAN_IP] [--foreign-ip FOREIGN_IP] [--subnet-base A.B] [--idx N] [--key K] [--plan] [--yes]"
                           return 1 ;;
        esac
    done
    [[ -n "$CURRENT" ]] || { err "Missing required option: --name (the node to edit)"; return 1; }
    [[ -f "$NODES_DIR/$CURRENT.conf" ]] || { err "Node '$CURRENT' does not exist."; err "List them with: gre node list"; return 1; }
    [[ -n "$R_NAME" ]] && { valid_name "$R_NAME" || { err "Invalid new name: '$R_NAME'"; return 1; }; }

    # FOREIGN_IP is the local address of this host, held in foreign.conf rather
    # than per node. --foreign-ip lets the operator correct it for this edit
    # without touching the global file.
    FOREIGN_IP="$(grep -E '^FOREIGN_IP=' "$FOREIGN_CONF" | head -n1 | cut -d= -f2)"
    if [[ -n "$R_FOREIGN_IP" ]]; then
        valid_ip "$R_FOREIGN_IP" || { err "Invalid foreign IP: '$R_FOREIGN_IP'"; return 1; }
        FOREIGN_IP="$R_FOREIGN_IP"
    fi

    edit_txn_begin
    if ! edit_snapshot_current foreign "$CURRENT"; then
        err "Could not read the current configuration of '$CURRENT'."
        edit_txn_commit
        return 1
    fi
    plan_request_from_current
    [[ -n "$R_NAME" ]]        && PLAN_REQ_NAME="$R_NAME"
    [[ -n "$R_IRAN_IP" ]]     && PLAN_REQ_IRAN_IP="$R_IRAN_IP"
    [[ -n "$R_SUBNET_BASE" ]] && PLAN_REQ_SUBNET_BASE="$R_SUBNET_BASE"
    [[ -n "$R_IDX" ]]         && PLAN_REQ_IDX="$R_IDX"
    [[ -n "$R_KEY" ]]         && PLAN_REQ_KEY="$R_KEY"
    [[ -n "$R_FOREIGN_IP" ]]  && PLAN_REQ_FOREIGN_IP="$R_FOREIGN_IP"
    PLAN_REQ_TUN="gre-$PLAN_REQ_NAME"

    preview_connection_edit foreign "$CURRENT" || { edit_txn_commit; return 1; }

    if (( PLAN_ONLY )); then
        info "Plan only (--plan): nothing was changed."
        return 0
    fi
    if (( ! YES )); then
        confirm "Apply this change to node '$CURRENT'?" || { info "Cancelled."; return 0; }
    fi

    if ! edit_connection_txn foreign "$CURRENT"; then
        err "Edit of '$CURRENT' failed and the previous configuration was restored."
        return 1
    fi

    # Keep the GRE input whitelist in step when the peer address changed: the old
    # ACCEPT for this node is replaced, never left behind and never duplicated.
    if [[ "$EDIT_OLD_IRAN_IP" != "$EDIT_NEW_IRAN_IP" ]]; then
        ipt_del filter INPUT -p gre -s "$EDIT_OLD_IRAN_IP" \
            -m comment --comment "multi-gre-node-$EDIT_OLD_NAME" -j ACCEPT
        if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
            # Insert before the catch-all DROP so the new address is actually allowed.
            ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
            ipt_add filter INPUT -p gre -s "$EDIT_NEW_IRAN_IP" \
                -m comment --comment "multi-gre-node-$EDIT_NEW_NAME" -j ACCEPT
            ipt_add filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
        fi
    elif [[ "$EDIT_OLD_NAME" != "$EDIT_NEW_NAME" ]]; then
        # Rename: the comment carries the name, so move the rule with it.
        ipt_del filter INPUT -p gre -s "$EDIT_OLD_IRAN_IP" \
            -m comment --comment "multi-gre-node-$EDIT_OLD_NAME" -j ACCEPT
        if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
            ipt_del filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
            ipt_add filter INPUT -p gre -s "$EDIT_NEW_IRAN_IP" \
                -m comment --comment "multi-gre-node-$EDIT_NEW_NAME" -j ACCEPT
            ipt_add filter INPUT -p gre -m comment --comment "multi-gre-block" -j DROP
        fi
    fi

    audit_log "node-edit from=$CURRENT name=$EDIT_NEW_NAME iran_ip=$EDIT_NEW_IRAN_IP base=$EDIT_NEW_SUBNET_BASE idx=$EDIT_NEW_IDX key=$EDIT_NEW_KEY class=$PLAN_CLASS"

    echo
    ok "Node '$EDIT_NEW_NAME' updated (${PLAN_CLASS}: $(plan_class_label "$PLAN_CLASS"))."
    info "Tunnel: $EDIT_NEW_TUN  ${EDIT_NEW_SUBNET_BASE}.${EDIT_NEW_IDX}.1/30  <->  $EDIT_NEW_IRAN_IP (key $EDIT_NEW_KEY)"

    # Commands for the other side, only when the other side must change.
    local changed=0 f
    for f in "${PLAN_FIELDS[@]}"; do
        case "$f" in IRAN_IP|SUBNET_BASE|IDX|KEY|NAME|FOREIGN_IP) changed=1 ;; esac
    done
    if (( changed )); then
        echo
        warn "This change also affects the IRAN side. Run there:"
        printf 'gre iran peer edit \\\n'
        printf '  --name %s \\\n' "$EDIT_OLD_NAME"
        [[ "$EDIT_NEW_NAME" != "$EDIT_OLD_NAME" ]] && printf '  --new-name %s \\\n' "$EDIT_NEW_NAME"
        printf '  --iran-ip %s \\\n' "$EDIT_NEW_IRAN_IP"
        printf '  --subnet-base %s \\\n' "$EDIT_NEW_SUBNET_BASE"
        printf '  --idx %s \\\n' "$EDIT_NEW_IDX"
        printf '  --key %s\n' "$EDIT_NEW_KEY"
    fi
    return 0
}

cli_node_remove() { # gre node remove --name NAME [--yes]
    require_root
    [[ -f "$FOREIGN_CONF" ]] || { err "This server is not configured as FOREIGN."; return 1; }
    local NAME="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)     [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --yes|-y)   YES=1; shift ;;
            --help|-h)  echo "Usage: gre node remove --name NAME [--yes]"; return 0 ;;
            *)          err "Unknown option: $1"; err "Usage: gre node remove --name NAME [--yes]"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Missing required option: --name"; err "Usage: gre node remove --name NAME [--yes]"; return 1; }

    local f="$NODES_DIR/$NAME.conf"
    [[ -f "$f" ]] || { err "Node '$NAME' does not exist."; return 1; }
    local IRAN_IP="" IDX="" KEY="" TUN=""
    # shellcheck disable=SC1090
    source "$f"
    if (( ! YES )); then
        confirm "Remove node '$NAME' (tunnel $TUN)?" || { info "Cancelled."; return; }
    fi
    delete_tunnel "$TUN"
    ipt_del filter INPUT -p gre -s "$IRAN_IP" \
        -m comment --comment "multi-gre-node-$NAME" -j ACCEPT
    rm -f "$f"
    audit_log "node-remove name=$NAME iran_ip=$IRAN_IP idx=$IDX"
    ok "Node '$NAME' removed."
    info "On the IRAN server, remove the matching peer:  gre iran peer remove --name $NAME"
    info "(No need to uninstall the Iran server — only that one peer.)"
}

# ------------------------------------------------------------- CLI: foreign setup
cli_foreign_setup() { # gre foreign-setup [--foreign-ip IP] [--gre-whitelist on|off] [--icmp-drop on|off] [--downtime MIN] [--yes]
    require_root
    if [[ -f "$FOREIGN_CONF" ]]; then
        err "This server is already configured as FOREIGN (add nodes with: gre node add --name NAME --ip IRAN_IP)."
        return 1
    fi
    local FOREIGN_IP="" GRE_WHITELIST="on" ICMP_DROP="off" DOWNTIME="2" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --foreign-ip)    [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; FOREIGN_IP="$2"; shift 2 ;;
            --gre-whitelist) [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--gre-whitelist must be 'on' or 'off'"; return 1; }; GRE_WHITELIST="$2"; shift 2 ;;
            --icmp-drop)     [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--icmp-drop must be 'on' or 'off'"; return 1; }; ICMP_DROP="$2"; shift 2 ;;
            --downtime)      [[ "${2:-}" =~ ^[0-9]+$ ]] || { err "--downtime must be minutes (0 = disable auto-heal)"; return 1; }; DOWNTIME="$2"; shift 2 ;;
            --yes|-y)        YES=1; shift ;;
            --help|-h)       echo "Usage: gre foreign-setup [--foreign-ip IP] [--gre-whitelist on|off] [--icmp-drop on|off] [--downtime MIN] [--yes]"; return 0 ;;
            *)               err "Unknown option: $1"
                             err "Usage: gre foreign-setup [--foreign-ip IP] [--gre-whitelist on|off] [--icmp-drop on|off] [--downtime MIN] [--yes]"
                             return 1 ;;
        esac
    done

    if [[ -z "$FOREIGN_IP" ]]; then
        FOREIGN_IP="$(detect_public_ip "$(detect_wan_iface)")"
    fi
    valid_ip "$FOREIGN_IP" || { err "Invalid or undetectable foreign IP: '$FOREIGN_IP' (pass --foreign-ip)"; return 1; }

    local whitelist_flag="0" icmp_flag="0"
    [[ "$GRE_WHITELIST" == "on" ]] && whitelist_flag="1"
    [[ "$ICMP_DROP" == "on" ]] && icmp_flag="1"

    # warn (non-fatal) if other GRE tunnels exist and the whitelist will block them
    if [[ "$whitelist_flag" == "1" ]]; then
        local other_tuns=""
        other_tuns="$(unmanaged_gre_tunnels | tr '\n' ' ')"
        [[ -n "${other_tuns// /}" ]] && \
            warn "Other GRE tunnels exist ($other_tuns) — the whitelist will BLOCK them."
    fi

    mkdir -p "$CONF_DIR" "$NODES_DIR"
    cat > "$FOREIGN_CONF" <<EOF
FOREIGN_IP=$FOREIGN_IP
ICMP_DROP=$icmp_flag
GRE_WHITELIST=$whitelist_flag
EOF
    chmod 600 "$FOREIGN_CONF"

    local dt_enabled=1 dt_interval=$(( DOWNTIME / 2 ))
    (( DOWNTIME == 0 )) && dt_enabled=0
    (( dt_interval < 1 )) && dt_interval=1
    write_global_conf "$dt_enabled" "$dt_interval" "$DOWNTIME"

    install_service
    audit_log "foreign-setup ip=$FOREIGN_IP icmp_drop=$icmp_flag gre_whitelist=$whitelist_flag tolerance=${DOWNTIME}m"

    echo
    ok "FOREIGN server configured (ip $FOREIGN_IP, whitelist $GRE_WHITELIST, icmp drop $ICMP_DROP)."
    info "Add Iran nodes with:  gre node add --name ir01 --ip IRAN_PUBLIC_IP"
    info "Each add prints the exact values / command for the Iran side."
}

# ------------------------------------------------------------- CLI: iran setup
cli_iran_setup() { # gre iran-setup --foreign-ip IP [options]  (creates the FIRST peer only)
    require_root
    migrate_legacy_iran_conf || return 1
    if (( $(peer_count) > 0 )); then
        err "This server already has $(peer_count) foreign peer(s); refusing to overwrite them."
        err "To connect to an additional foreign server:  gre iran peer add --name NAME --foreign-ip IP ..."
        err "To remove a peer first:                     gre iran peer remove --name NAME"
        return 1
    fi
    local FOREIGN_IP="" IRAN_IP="" NAME="ir01" IDX="1" KEY="" WAN_IF="" \
          SUBNET_BASE="$DEFAULT_SUBNET_BASE" TCP_PORTS="" UDP_PORTS="" MSS="on" YES=0 DOWNTIME="2"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --foreign-ip)  [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; FOREIGN_IP="$2"; shift 2 ;;
            --iran-ip)     [[ -n "${2:-}" ]] || { err "Missing value for --iran-ip"; return 1; }; IRAN_IP="$2"; shift 2 ;;
            --name)        [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --idx)         [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; IDX="$2"; shift 2 ;;
            --key)         [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; KEY="$2"; shift 2 ;;
            --subnet-base) [[ -n "${2:-}" ]] || { err "Missing value for --subnet-base"; return 1; }; SUBNET_BASE="$2"; shift 2 ;;
            --wan)         [[ -n "${2:-}" ]] || { err "Missing value for --wan"; return 1; }; WAN_IF="$2"; shift 2 ;;
            --tcp-ports)   [[ -n "${2:-}" ]] || { err "Missing value for --tcp-ports"; return 1; }; TCP_PORTS="$2"; shift 2 ;;
            --udp-ports)   [[ -n "${2:-}" ]] || { err "Missing value for --udp-ports"; return 1; }; UDP_PORTS="$2"; shift 2 ;;
            --mss-clamp)   [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--mss-clamp must be 'on' or 'off'"; return 1; }; MSS="$2"; shift 2 ;;
            --downtime)    [[ "${2:-}" =~ ^[0-9]+$ ]] || { err "--downtime must be minutes (0 = disable auto-heal)"; return 1; }; DOWNTIME="$2"; shift 2 ;;
            --yes|-y)      YES=1; shift ;;
            --help|-h)     echo "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--subnet-base A.B] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--downtime MIN] [--yes]"; return 0 ;;
            *)             err "Unknown option: $1"
                           err "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--subnet-base A.B] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"
                           return 1 ;;
        esac
    done
    if [[ -z "$FOREIGN_IP" ]]; then
        err "Missing required option: --foreign-ip"
        err "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--subnet-base A.B] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"
        return 1
    fi

    if [[ -z "$WAN_IF" ]]; then
        WAN_IF="$(detect_wan_iface)"
    fi
    if [[ -z "$IRAN_IP" ]]; then
        IRAN_IP="$(detect_public_ip "$WAN_IF")"
    fi
    [[ -z "$KEY" ]] && { [[ "$IDX" =~ ^[0-9]+$ ]] && KEY=$(( 1000 + IDX )); }

    local MSS_CLAMP="0"
    [[ "$MSS" == "on" ]] && MSS_CLAMP="1"
    local TUN="gre-$NAME"

    validate_peer_values || return 1
    [[ -n "$WAN_IF" ]] || { err "WAN interface could not be detected (pass --wan)"; return 1; }

    warn_port_conflicts "tcp" "$TCP_PORTS"
    warn_port_conflicts "udp" "$UDP_PORTS"

    if port_list_covers_22 "$TCP_PORTS" && (( ! YES )); then
        err "The TCP port list covers port 22 (SSH): SSH to this server would be forwarded to the FOREIGN server!"
        err "Re-run with --yes to confirm."
        return 1
    fi

    create_iran_peer "$NAME" "$FOREIGN_IP" "$IRAN_IP" "$WAN_IF" "$SUBNET_BASE" \
        "$IDX" "$KEY" "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" \
        || { err "Failed to bring the tunnel up. Check the IPs and that GRE (proto 47) is not blocked."; return 1; }

    local dt_enabled=1 dt_interval=$(( DOWNTIME / 2 ))
    (( DOWNTIME == 0 )) && dt_enabled=0
    (( dt_interval < 1 )) && dt_interval=1
    write_global_conf "$dt_enabled" "$dt_interval" "$DOWNTIME"
    install_service
    audit_log "iran-setup name=$NAME foreign=$FOREIGN_IP base=$SUBNET_BASE idx=$IDX key=$KEY tcp='$TCP_PORTS' udp='$UDP_PORTS' mss=$MSS_CLAMP tolerance=${DOWNTIME}m"

    echo
    ok "IRAN node '$NAME' configured (first foreign peer)."
    info "Tunnel: gre-$NAME  ${SUBNET_BASE}.${IDX}.2/30  <->  $FOREIGN_IP (key $KEY)"
    info "On the FOREIGN server this node must exist with the SAME name, subnet base, index and key (gre node add)."
    info "Add more foreigns anytime:  gre iran peer add --name NAME --foreign-ip IP ..."
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.1"
}

# ------------------------------------------------------------- CLI: iran peers
iran_peers_json() { # prints the iran_peers JSON array (pings each peer once)
    local out="[" sep="" f
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        load_peer_conf "$f" || continue
        local reach="false"
        ping -c 1 -W 2 "${SUBNET_BASE}.${IDX}.1" >/dev/null 2>&1 && reach="true"
        out+="${sep}{\"name\":\"$NAME\",\"foreign_ip\":\"$FOREIGN_IP\",\"subnet_base\":\"$SUBNET_BASE\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\",\"tcp_ports\":\"$TCP_PORTS\",\"udp_ports\":\"$UDP_PORTS\",\"reachable\":$reach}"
        sep=","
    done
    out+="]"
    printf '%s' "$out"
}

json_string_array() {
    local sep="" value
    printf '['
    for value in "$@"; do
        printf '%s"%s"' "$sep" "$value"
        sep=","
    done
    printf ']'
}

json_number_array() {
    local sep="" value
    printf '['
    for value in "$@"; do
        printf '%s%s' "$sep" "$value"
        sep=","
    done
    printf ']'
}

cli_suggest_resources() { # cli_suggest_resources peer|node [--json] [--count N] [--base A.B]
    local kind="$1"; shift
    local json=0 count=1 requested_base="" conf_dir="" include_ports=0
    if [[ "$kind" == "peer" ]]; then
        conf_dir="$FOREIGNS_DIR"
        include_ports=1
    else
        conf_dir="$NODES_DIR"
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)     json=1; shift ;;
            --count)    [[ -n "${2:-}" ]] || { err "Missing value for --count"; return 1; }; count="$2"; shift 2 ;;
            --base)     [[ -n "${2:-}" ]] || { err "Missing value for --base"; return 1; }; requested_base="$2"; shift 2 ;;
            --help|-h)
                if [[ "$kind" == "peer" ]]; then
                    echo "Usage: gre iran peer suggest [--json] [--count N] [--base A.B]"
                else
                    echo "Usage: gre node suggest [--json] [--count N] [--base A.B]"
                fi
                return 0 ;;
            *)          err "Unknown option: $1"; return 1 ;;
        esac
    done
    if ! [[ "$count" =~ ^[0-9]+$ ]] || (( count < 1 || count > 20 )); then
        err "Invalid count: $count (expected 1..20)"
        return 1
    fi
    [[ -z "$requested_base" ]] || valid_subnet_base "$requested_base" || {
        err "Invalid subnet base: $requested_base (expected A.B, e.g. 10.201)"
        return 1
    }

    local f existing_names=" " used_bases=" " n="" b="" idx="" i port=""
    local -a names=() bases=() indexes=() keys=() tcp_ports=() udp_ports=()
    for f in "$conf_dir"/*.conf; do
        [[ -e "$f" ]] || continue
        n="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
        [[ -n "$n" ]] && existing_names+="$n "
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"
        used_bases+="${b:-$DEFAULT_SUBNET_BASE} "
    done
    for (( i = 1; i <= 99 && ${#names[@]} < count; i++ )); do
        n="$(printf 'ir%02d' "$i")"
        [[ "$existing_names" == *" $n "* ]] || names+=("$n")
    done
    for (( i = 200; i <= 254 && ${#bases[@]} < count; i++ )); do
        [[ "$used_bases" == *" 10.$i "* ]] || bases+=("10.$i")
    done
    ((${#bases[@]})) || { err "No free subnet base left (pool exhausted)"; return 1; }

    local context_base="${requested_base:-${bases[0]}}" used_indexes=" "
    for f in "$conf_dir"/*.conf; do
        [[ -e "$f" ]] || continue
        b="$(grep -E '^SUBNET_BASE=' "$f" | cut -d= -f2)"; b="${b:-$DEFAULT_SUBNET_BASE}"
        [[ "$b" == "$context_base" ]] || continue
        idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        [[ -n "$idx" ]] && used_indexes+="$idx "
    done
    for (( i = 1; i <= 254 && ${#indexes[@]} < count; i++ )); do
        if [[ "$used_indexes" != *" $i "* ]]; then
            indexes+=("$i")
            keys+=("$((1000 + i))")
        fi
    done
    ((${#indexes[@]})) || { err "No free tunnel index left in $context_base"; return 1; }

    if (( include_ports )); then
        port=3001
        for (( i = 0; i < count; i++ )); do
            port="$(suggest_free_port tcp "$port")" || break
            tcp_ports+=("$port")
            port=$((port + 1))
        done
        port=3001
        for (( i = 0; i < count; i++ )); do
            port="$(suggest_free_port udp "$port")" || break
            udp_ports+=("$port")
            port=$((port + 1))
        done
    fi

    if (( json )); then
        if (( count == 1 )); then
            if (( include_ports )); then
                printf '{"name":"%s","subnet_base":"%s","idx":%s,"key":%s,"tcp_port":"%s","udp_port":"%s"}\n' \
                    "${names[0]:-}" "${bases[0]}" "${indexes[0]}" "${keys[0]}" "${tcp_ports[0]:-}" "${udp_ports[0]:-}"
            else
                printf '{"name":"%s","subnet_base":"%s","idx":%s,"key":%s}\n' \
                    "${names[0]:-}" "${bases[0]}" "${indexes[0]}" "${keys[0]}"
            fi
        else
            printf '{"context_base":"%s","name":' "$context_base"; json_string_array "${names[@]}"
            printf ',"subnet_base":'; json_string_array "${bases[@]}"
            printf ',"idx":'; json_number_array "${indexes[@]}"
            printf ',"key":'; json_number_array "${keys[@]}"
            if (( include_ports )); then
                printf ',"tcp_port":'; json_string_array "${tcp_ports[@]}"
                printf ',"udp_port":'; json_string_array "${udp_ports[@]}"
            fi
            printf '}\n'
        fi
    else
        echo "Suggested values (collision-free with existing $kind config):"
        printf '  names       : %s\n' "${names[*]:-none}"
        printf '  subnet bases: %s\n' "${bases[*]:-none}"
        printf '  indexes     : %s  (for %s)\n' "${indexes[*]:-none}" "$context_base"
        printf '  GRE keys    : %s\n' "${keys[*]:-none}"
        if (( include_ports )); then
            printf '  TCP ports   : %s\n' "${tcp_ports[*]:-none}"
            printf '  UDP ports   : %s\n' "${udp_ports[*]:-none}"
        fi
    fi
}

cli_node_suggest() { cli_suggest_resources node "$@"; }
cli_iran_peer_suggest() { cli_suggest_resources peer "$@"; }

# ---------------------------------------------------------------- list rendering
#
# A connection is a PAIR, so the list always shows both endpoints. Showing only the
# far end and assuming "this server is obviously the local one" is exactly what made
# an operator hold two configs in their head.
terminal_width() {
    local w=""
    if [[ -t 1 ]]; then
        w="$(tput cols 2>/dev/null || true)"
    fi
    # `tput` needs a terminal; fall back to COLUMNS, then to a safe default.
    if [[ -z "$w" || ! "$w" =~ ^[0-9]+$ ]]; then w="${COLUMNS:-}"; fi
    if [[ -z "$w" || ! "$w" =~ ^[0-9]+$ ]]; then w=120; fi
    printf '%s' "$w"
}

# Is the tunnel's own interface up? Purely local: this reports what THIS side can
# see, which is all a single CLI invocation can honestly know.
tunnel_state_local() { # tunnel_state_local TUN
    local tun="$1"
    if ! tun_exists "$tun"; then printf 'MISSING'; return 0; fi
    if ip link show "$tun" 2>/dev/null | grep -qE 'state (UP|UNKNOWN)'; then printf 'UP'; else printf 'DOWN'; fi
}

# Compact two-line rendering for a narrow terminal.
print_connection_compact() { # print_connection_compact NAME IRAN_IP FOREIGN_IP TUN SUBNET_CIDR KEY TCP UDP STATE
    local name="$1" iran="$2" foreign="$3" tun="$4" subnet="$5" key="$6" tcp="$7" udp="$8" state="$9"
    printf '  %s\n' "$name"
    printf '    %s -> %s\n' "$iran" "$foreign"
    printf '    %s · %s · key %s · tcp/udp %s · %s\n' \
        "$tun" "$subnet" "$key" "${tcp:-none}" "$state"
}

# Full table. Column widths are computed from the data so nothing is truncated by a
# hardcoded guess.
print_connection_table() { # print_connection_table <rows-file>
    local rows="$1"
    awk -F'\t' '
        BEGIN {
            h[1]="NAME"; h[2]="IRAN IP"; h[3]="FOREIGN IP"; h[4]="TUNNEL";
            h[5]="SUBNET"; h[6]="KEY"; h[7]="TCP"; h[8]="UDP"; h[9]="STATE"
        }
        { for (i=1;i<=9;i++) { if (length($i) > w[i]) w[i]=length($i) } n++ }
        END {
            for (i=1;i<=9;i++) { if (length(h[i]) > w[i]) w[i]=length(h[i]) }
            for (i=1;i<=9;i++) printf "%-*s  ", w[i], h[i]
            printf "\n"
            for (i=1;i<=9;i++) { s=""; for (j=0;j<w[i];j++) s=s"-"; printf "%-*s  ", w[i], s }
            printf "\n"
        }
    ' "$rows"
    while IFS=$'\t' read -r c1 c2 c3 c4 c5 c6 c7 c8 c9; do
        [[ -n "$c1" ]] || continue
        printf '%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %s\n' \
            "${LIST_W[1]}" "$c1" "${LIST_W[2]}" "$c2" "${LIST_W[3]}" "$c3" \
            "${LIST_W[4]}" "$c4" "${LIST_W[5]}" "$c5" "${LIST_W[6]}" "$c6" \
            "${LIST_W[7]}" "$c7" "${LIST_W[8]}" "$c8" "$c9"
    done < "$rows"
}

# Emit a list of connections for one side, in whichever layout fits the terminal.
# SIDE is "iran" (peers) or "foreign" (nodes).
render_connection_list() { # render_connection_list SIDE
    local side="$1" f found=0 width
    width="$(terminal_width)"
    local -a rows=()
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"

    if [[ "$side" == "iran" ]]; then
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            load_peer_conf "$f" || { warn "  invalid peer conf: $f"; continue; }
            found=1
            rows+=("$NAME"$'\t'"$IRAN_IP"$'\t'"$FOREIGN_IP"$'\t'"$TUN"$'\t'"${SUBNET_BASE}.${IDX}.0/30"$'\t'"$KEY"$'\t'"${TCP_PORTS:-none}"$'\t'"${UDP_PORTS:-none}"$'\t'"$(tunnel_state_local "$TUN")")
        done
    else
        FOREIGN_IP="$(grep -E '^FOREIGN_IP=' "$FOREIGN_CONF" 2>/dev/null | head -n1 | cut -d= -f2)"
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"; IDX=""; KEY=""; TUN=""
            # shellcheck disable=SC1090
            source "$f"
            [[ -n "$TUN" ]] || TUN="gre-$NAME"
            found=1
            # The foreign side has no per-node port list, so TCP/UDP read as "-".
            rows+=("$NAME"$'\t'"$IRAN_IP"$'\t'"$FOREIGN_IP"$'\t'"$TUN"$'\t'"${SUBNET_BASE}.${IDX}.0/30"$'\t'"$KEY"$'\t'"-"$'\t'"-"$'\t'"$(tunnel_state_local "$TUN")")
        done
    fi
    (( found )) || return 1

    # 110 columns fits the full table of nine columns with typical values; below
    # that a two-line row is far more readable than a wrapped table.
    if (( width >= 110 )); then
        local tmp
        tmp="$(mktemp)"
        printf '%s\n' "${rows[@]}" > "$tmp"
        # Column widths, computed once and reused by the row printer.
        LIST_W=()
        local i
        for (( i=1; i<=9; i++ )); do
            local maxlen
            maxlen="$(awk -F'\t' -v c="$i" '{ if (length($c) > m) m=length($c) } END { print m+0 }' "$tmp")"
            local hlen
            case "$i" in
                1) hlen=4 ;; 2) hlen=7 ;; 3) hlen=10 ;; 4) hlen=6 ;; 5) hlen=6 ;;
                6) hlen=3 ;; 7) hlen=3 ;; 8) hlen=3 ;; 9) hlen=5 ;;
            esac
            (( maxlen < hlen )) && maxlen=$hlen
            LIST_W[$i]="$maxlen"
        done
        print_connection_table "$tmp"
        rm -f "$tmp"
    else
        local row
        for row in "${rows[@]}"; do
            local -a rowcols=()
            IFS=$'\t' read -r -a rowcols <<< "$row"
            print_connection_compact "${rowcols[0]}" "${rowcols[1]}" "${rowcols[2]}" "${rowcols[3]}" \
                "${rowcols[4]}" "${rowcols[5]}" "${rowcols[6]}" "${rowcols[7]}" "${rowcols[8]}"
        done
    fi
    return 0
}

cli_iran_peer_list() { # gre iran peer list [--json]
    local json=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)     json=1; shift ;;
            --help|-h)  echo "Usage: gre iran peer list [--json]"; return 0 ;;
            *)          err "Unknown option: $1"; err "Usage: gre iran peer list [--json]"; return 1 ;;
        esac
    done
    migrate_legacy_iran_conf || return 1
    [[ -f "$IRAN_CONF" ]] || { err "This server is not configured as IRAN (no peers yet)."; return 1; }

    if (( json )); then
        iran_peers_json; echo
        return 0
    fi
    info "Configured foreign peers:"
    if ! render_connection_list iran; then
        info "  (none — add one: gre iran peer add)"
    fi
    echo
    info "Edit one in place:  gre iran peer edit --name NAME [--tcp-ports LIST] ..."
}

cli_iran_peer_add() { # gre iran peer add --name NAME --foreign-ip IP [options]
    require_root
    migrate_legacy_iran_conf || return 1
    local FOREIGN_IP="" IRAN_IP="" NAME="" IDX="" KEY="" WAN_IF="" \
          SUBNET_BASE="" TCP_PORTS="" UDP_PORTS="" MSS="on" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)        [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --foreign-ip)  [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; FOREIGN_IP="$2"; shift 2 ;;
            --iran-ip)     [[ -n "${2:-}" ]] || { err "Missing value for --iran-ip"; return 1; }; IRAN_IP="$2"; shift 2 ;;
            --subnet-base) [[ -n "${2:-}" ]] || { err "Missing value for --subnet-base"; return 1; }; SUBNET_BASE="$2"; shift 2 ;;
            --idx)         [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; IDX="$2"; shift 2 ;;
            --key)         [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; KEY="$2"; shift 2 ;;
            --wan)         [[ -n "${2:-}" ]] || { err "Missing value for --wan"; return 1; }; WAN_IF="$2"; shift 2 ;;
            --tcp-ports)   [[ -n "${2:-}" ]] || { err "Missing value for --tcp-ports"; return 1; }; TCP_PORTS="$2"; shift 2 ;;
            --udp-ports)   [[ -n "${2:-}" ]] || { err "Missing value for --udp-ports"; return 1; }; UDP_PORTS="$2"; shift 2 ;;
            --mss-clamp)   [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--mss-clamp must be 'on' or 'off'"; return 1; }; MSS="$2"; shift 2 ;;
            --yes|-y)      YES=1; shift ;;
            --help|-h)     echo "Usage: gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"; return 0 ;;
            *)             err "Unknown option: $1"
                           err "Usage: gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"
                           return 1 ;;
        esac
    done
    [[ -n "$NAME" ]]       || { err "Missing required option: --name";       return 1; }
    [[ -n "$FOREIGN_IP" ]] || { err "Missing required option: --foreign-ip"; return 1; }

    if [[ -z "$WAN_IF" ]]; then
        WAN_IF="$(detect_wan_iface)"
    fi
    if [[ -z "$IRAN_IP" ]]; then
        IRAN_IP="$(detect_public_ip "$WAN_IF")"
    fi
    if [[ -z "$SUBNET_BASE" ]]; then
        SUBNET_BASE="$(next_free_subnet_base)" || { err "No free subnet base left in the 10.200-10.254 pool (pass --subnet-base)"; return 1; }
    fi
    if [[ -z "$IDX" ]] && valid_subnet_base "$SUBNET_BASE"; then
        IDX="$(next_free_peer_idx "$SUBNET_BASE")" || { err "No free tunnel index left in $SUBNET_BASE"; return 1; }
    fi
    [[ -z "$KEY" ]] && { [[ "$IDX" =~ ^[0-9]+$ ]] && KEY=$(( 1000 + IDX )); }

    local MSS_CLAMP="0"
    [[ "$MSS" == "on" ]] && MSS_CLAMP="1"
    local TUN="gre-$NAME"

    validate_peer_values || return 1
    [[ -n "$WAN_IF" ]] || { err "WAN interface could not be detected (pass --wan)"; return 1; }

    # Idempotent re-add: identical config is a success; different values are not
    # a silent update — the peer must be removed first.
    if peer_exists "$NAME"; then
        local pf="$FOREIGNS_DIR/$NAME.conf"
        local o_foreign="" o_iran="" o_wan="" o_base="" o_idx="" o_key="" o_tcp="" o_udp="" o_mss=""
        o_foreign="$(grep -E '^FOREIGN_IP=' "$pf" | cut -d= -f2)"
        o_iran="$(grep -E '^IRAN_IP=' "$pf" | cut -d= -f2)"
        o_wan="$(grep -E '^WAN_IF=' "$pf" | cut -d= -f2)"
        o_base="$(grep -E '^SUBNET_BASE=' "$pf" | cut -d= -f2)"; o_base="${o_base:-$DEFAULT_SUBNET_BASE}"
        o_idx="$(grep -E '^IDX=' "$pf" | cut -d= -f2)"
        o_key="$(grep -E '^KEY=' "$pf" | cut -d= -f2)"
        o_tcp="$(grep -E '^TCP_PORTS=' "$pf" | cut -d= -f2)"
        o_udp="$(grep -E '^UDP_PORTS=' "$pf" | cut -d= -f2)"
        o_mss="$(grep -E '^MSS_CLAMP=' "$pf" | cut -d= -f2)"
        if [[ "$o_foreign" == "$FOREIGN_IP" && "$o_iran" == "$IRAN_IP" && "$o_wan" == "$WAN_IF" \
            && "$o_base" == "$SUBNET_BASE" && "$o_idx" == "$IDX" && "$o_key" == "$KEY" \
            && "$o_tcp" == "$TCP_PORTS" && "$o_udp" == "$UDP_PORTS" && "${o_mss:-0}" == "$MSS_CLAMP" ]]; then
            ok "Peer '$NAME' already exists with identical configuration — nothing to do."
            return 0
        fi
        err "Peer '$NAME' already exists with DIFFERENT values (no silent update)."
        err "Remove it first:  gre iran peer remove --name $NAME"
        return 1
    fi

    check_peer_collisions "$NAME" "$SUBNET_BASE" "$IDX" "$TUN" "$TCP_PORTS" "$UDP_PORTS" || return 1
    if subnet_route_conflict "$SUBNET_BASE"; then
        err "Subnet base $SUBNET_BASE collides with an existing local route; pick another base (--subnet-base)."
        return 1
    fi

    warn_port_conflicts "tcp" "$TCP_PORTS"
    warn_port_conflicts "udp" "$UDP_PORTS"

    if port_list_covers_22 "$TCP_PORTS" && (( ! YES )); then
        err "The TCP port list covers port 22 (SSH): SSH to this server would be forwarded to the FOREIGN server!"
        err "Re-run with --yes to confirm."
        return 1
    fi

    create_iran_peer "$NAME" "$FOREIGN_IP" "$IRAN_IP" "$WAN_IF" "$SUBNET_BASE" \
        "$IDX" "$KEY" "$TCP_PORTS" "$UDP_PORTS" "$MSS_CLAMP" \
        || { err "Peer '$NAME' was not added."; return 1; }

    [[ -f "$SERVICE_FILE" ]] || install_service
    audit_log "iran-peer-add name=$NAME foreign=$FOREIGN_IP base=$SUBNET_BASE idx=$IDX key=$KEY tcp='$TCP_PORTS' udp='$UDP_PORTS' mss=$MSS_CLAMP"

    echo
    ok "Foreign peer '$NAME' added."
    info "Tunnel: gre-$NAME  ${SUBNET_BASE}.${IDX}.2/30  <->  $FOREIGN_IP (key $KEY)"
    info "On the FOREIGN server this node must exist with the SAME name, subnet base, index and key (gre node add)."
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.1"
}

# ===================================================== CLI: gre iran peer edit
#
# Non-interactive connection edit. Every option is optional: an option that is not
# given keeps its current value, which is what makes "change only the ports" a
# one-liner instead of a full re-specification.
# shellcheck disable=SC2034  # PLAN_REQ_* are read by plan_edit via indirect expansion
cli_iran_peer_edit() { # gre iran peer edit --name CURRENT [--new-name N] [options]
    require_root
    migrate_legacy_iran_conf || return 1
    local CURRENT="" YES=0 PLAN_ONLY=0
    local R_NAME="" R_FOREIGN_IP="" R_IRAN_IP="" R_SUBNET_BASE="" R_IDX="" R_KEY="" \
          R_WAN="" R_TCP="" R_UDP="" R_MSS=""
    # Track which options were supplied, so "keep current" is distinguishable from
    # "explicitly set to empty" (clearing a port list is a legitimate edit).
    local set_TCP=0 set_UDP=0 set_MSS=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)        [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; CURRENT="$2"; shift 2 ;;
            --new-name)    [[ -n "${2:-}" ]] || { err "Missing value for --new-name"; return 1; }; R_NAME="$2"; shift 2 ;;
            --foreign-ip)  [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; R_FOREIGN_IP="$2"; shift 2 ;;
            --iran-ip)     [[ -n "${2:-}" ]] || { err "Missing value for --iran-ip"; return 1; }; R_IRAN_IP="$2"; shift 2 ;;
            --subnet-base) [[ -n "${2:-}" ]] || { err "Missing value for --subnet-base"; return 1; }; R_SUBNET_BASE="$2"; shift 2 ;;
            --idx)         [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; R_IDX="$2"; shift 2 ;;
            --key)         [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; R_KEY="$2"; shift 2 ;;
            --wan)         [[ -n "${2:-}" ]] || { err "Missing value for --wan"; return 1; }; R_WAN="$2"; shift 2 ;;
            --tcp-ports)   R_TCP="${2:-}"; set_TCP=1; shift 2 ;;
            --udp-ports)   R_UDP="${2:-}"; set_UDP=1; shift 2 ;;
            --mss-clamp)   [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--mss-clamp must be 'on' or 'off'"; return 1; }
                           [[ "$2" == "on" ]] && R_MSS="1" || R_MSS="0"; set_MSS=1; shift 2 ;;
            --plan)        PLAN_ONLY=1; shift ;;
            --yes|-y)      YES=1; shift ;;
            --help|-h)     echo "Usage: gre iran peer edit --name CURRENT [--new-name NAME] [--foreign-ip IP] [--iran-ip IP] [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--plan] [--yes]"; return 0 ;;
            *)             err "Unknown option: $1"
                           err "Usage: gre iran peer edit --name CURRENT [--new-name NAME] [--foreign-ip IP] [--iran-ip IP] [--subnet-base A.B] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--plan] [--yes]"
                           return 1 ;;
        esac
    done
    [[ -n "$CURRENT" ]] || { err "Missing required option: --name (the connection to edit)"; return 1; }
    [[ -f "$FOREIGNS_DIR/$CURRENT.conf" ]] || { err "Peer '$CURRENT' does not exist."; err "List them with: gre iran peer list"; return 1; }

    # Read + snapshot the current state, seed the request from it, then apply only
    # the overrides the operator actually gave.
    edit_txn_begin
    if ! edit_snapshot_current iran "$CURRENT"; then
        err "Could not read the current configuration of '$CURRENT'."
        edit_txn_commit
        return 1
    fi
    plan_request_from_current
    [[ -n "$R_NAME" ]]        && PLAN_REQ_NAME="$R_NAME"
    [[ -n "$R_FOREIGN_IP" ]]  && PLAN_REQ_FOREIGN_IP="$R_FOREIGN_IP"
    [[ -n "$R_IRAN_IP" ]]     && PLAN_REQ_IRAN_IP="$R_IRAN_IP"
    [[ -n "$R_SUBNET_BASE" ]] && PLAN_REQ_SUBNET_BASE="$R_SUBNET_BASE"
    [[ -n "$R_IDX" ]]         && PLAN_REQ_IDX="$R_IDX"
    [[ -n "$R_KEY" ]]         && PLAN_REQ_KEY="$R_KEY"
    [[ -n "$R_WAN" ]]         && PLAN_REQ_WAN_IF="$R_WAN"
    (( set_TCP )) && PLAN_REQ_TCP_PORTS="$R_TCP"
    (( set_UDP )) && PLAN_REQ_UDP_PORTS="$R_UDP"
    (( set_MSS )) && PLAN_REQ_MSS_CLAMP="$R_MSS"
    # The tunnel name follows the connection name.
    PLAN_REQ_TUN="gre-$PLAN_REQ_NAME"

    preview_connection_edit iran "$CURRENT" || { edit_txn_commit; return 1; }

    # A handful of validations before any snapshot, so an obviously bad request
    # never even opens a transaction.
    if [[ -n "$R_TCP" ]] && ! valid_port_list "$R_TCP"; then err "Invalid TCP port list: '$R_TCP'"; return 1; fi
    if [[ -n "$R_UDP" ]] && ! valid_port_list "$R_UDP"; then err "Invalid UDP port list: '$R_UDP'"; return 1; fi
    if [[ -n "$R_NAME" ]] && ! valid_name "$R_NAME"; then err "Invalid new name: '$R_NAME'"; return 1; fi

    if (( PLAN_ONLY )); then
        info "Plan only (--plan): nothing was changed."
        return 0
    fi
    if (( ! YES )); then
        confirm "Apply this change to connection '$CURRENT'?" || { info "Cancelled."; return 0; }
    fi

    if ! edit_connection_txn iran "$CURRENT"; then
        err "Edit of '$CURRENT' failed and the previous configuration was restored."
        return 1
    fi

    # edit_connection_txn may run inside a command substitution, which would trap
    # any variable it set in a subshell. Derive the summary from the requested
    # state here, in the caller's scope, so the audit line and the message never
    # read an unset variable.
    EDIT_NEW_NAME="$PLAN_REQ_NAME"
    EDIT_NEW_FOREIGN_IP="$PLAN_REQ_FOREIGN_IP"
    EDIT_NEW_IRAN_IP="$PLAN_REQ_IRAN_IP"
    EDIT_NEW_SUBNET_BASE="$PLAN_REQ_SUBNET_BASE"
    EDIT_NEW_IDX="$PLAN_REQ_IDX"
    EDIT_NEW_KEY="$PLAN_REQ_KEY"
    EDIT_NEW_TUN="gre-$PLAN_REQ_NAME"

    audit_log "iran-peer-edit from=$CURRENT name=$EDIT_NEW_NAME foreign=$EDIT_NEW_FOREIGN_IP iran=$EDIT_NEW_IRAN_IP base=$EDIT_NEW_SUBNET_BASE idx=$EDIT_NEW_IDX key=$EDIT_NEW_KEY tcp='$PLAN_REQ_TCP_PORTS' udp='$PLAN_REQ_UDP_PORTS' mss=$PLAN_REQ_MSS_CLAMP class=$PLAN_CLASS"

    echo
    ok "Connection '$EDIT_NEW_NAME' updated (${PLAN_CLASS}: $(plan_class_label "$PLAN_CLASS"))."
    info "Tunnel: $EDIT_NEW_TUN  ${EDIT_NEW_SUBNET_BASE}.${EDIT_NEW_IDX}.2/30  <->  $EDIT_NEW_FOREIGN_IP (key $EDIT_NEW_KEY)"

    # Only print the far-side command when the far side actually has to change.
    local fcmd
    if fcmd="$(edit_peer_command_for_foreign)"; then
        echo
        warn "This change also affects the FOREIGN side. Run there:"
        printf '%s\n' "$fcmd"
    fi
    return 0
}

# Human-readable before/after preview, plus the impact list.
#
# Read-only with respect to the live system: it renders whatever the planner
# decided. The caller has already snapshotted the current state and populated the
# PLAN_REQ_* vars, so this function never mutates anything — which is what makes
# --plan safe to run against production.
preview_connection_edit() { # preview_connection_edit SIDE CURRENT
    local side="$1" current="$2"
    plan_edit
    if [[ "$PLAN_CLASS" == "NONE" ]]; then
        info "No changes requested — '$current' is already in the requested state."
        EDIT_PREVIEW_EMPTY=1
        return 0
    fi
    EDIT_PREVIEW_EMPTY=0

    local NAME="$PLAN_REQ_NAME" FOREIGN_IP="$PLAN_REQ_FOREIGN_IP" IRAN_IP="$PLAN_REQ_IRAN_IP" \
          WAN_IF="$PLAN_REQ_WAN_IF" SUBNET_BASE="$PLAN_REQ_SUBNET_BASE" IDX="$PLAN_REQ_IDX" \
          KEY="$PLAN_REQ_KEY" TCP_PORTS="$PLAN_REQ_TCP_PORTS" UDP_PORTS="$PLAN_REQ_UDP_PORTS" \
          MSS_CLAMP="$PLAN_REQ_MSS_CLAMP"

    echo
    printf '%s\n' "CURRENT"
    printf '  %-12s %s\n' "NAME"    "$EDIT_OLD_NAME"
    printf '  %-12s %s\n' "IRAN"    "${EDIT_OLD_IRAN_IP:-—}"
    printf '  %-12s %s\n' "FOREIGN" "${EDIT_OLD_FOREIGN_IP:-—}"
    printf '  %-12s %s\n' "SUBNET"  "${EDIT_OLD_SUBNET_BASE}.${EDIT_OLD_IDX}.0/30"
    printf '  %-12s %s\n' "KEY"     "$EDIT_OLD_KEY"
    if [[ "$side" == "iran" ]]; then
        printf '  %-12s %s\n' "TCP" "${EDIT_OLD_TCP:-none}"
        printf '  %-12s %s\n' "UDP" "${EDIT_OLD_UDP:-none}"
        printf '  %-12s %s\n' "MSS" "$([[ "${EDIT_OLD_MSS:-0}" == "1" ]] && echo on || echo off)"
    fi

    echo
    printf '%s\n' "NEW"
    local f
    for f in "${PLAN_FIELDS[@]}"; do
        case "$f" in
            NAME)        printf '  %-10s %s -> %s\n' "Name:"    "$EDIT_OLD_NAME" "$NAME" ;;
            FOREIGN_IP)  printf '  %-10s %s -> %s\n' "Foreign:" "$EDIT_OLD_FOREIGN_IP" "$FOREIGN_IP" ;;
            IRAN_IP)     printf '  %-10s %s -> %s\n' "Iran:"    "$EDIT_OLD_IRAN_IP" "$IRAN_IP" ;;
            WAN_IF)      printf '  %-10s %s -> %s\n' "WAN:"     "$EDIT_OLD_WAN_IF" "$WAN_IF" ;;
            SUBNET_BASE) printf '  %-10s %s -> %s\n' "Subnet:"  "$EDIT_OLD_SUBNET_BASE" "$SUBNET_BASE" ;;
            IDX)         printf '  %-10s %s -> %s\n' "Index:"   "$EDIT_OLD_IDX" "$IDX" ;;
            KEY)         printf '  %-10s %s -> %s\n' "Key:"     "$EDIT_OLD_KEY" "$KEY" ;;
            TCP_PORTS)   printf '  %-10s %s -> %s\n' "TCP:"     "${EDIT_OLD_TCP:-none}" "${TCP_PORTS:-none}" ;;
            UDP_PORTS)   printf '  %-10s %s -> %s\n' "UDP:"     "${EDIT_OLD_UDP:-none}" "${UDP_PORTS:-none}" ;;
            MSS_CLAMP)   printf '  %-10s %s -> %s\n' "MSS:" "$([[ "${EDIT_OLD_MSS:-0}" == "1" ]] && echo on || echo off)" "$([[ "$MSS_CLAMP" == "1" ]] && echo on || echo off)" ;;
        esac
    done

    echo
    printf '%s\n' "Impact:"
    plan_impact_lines | while IFS= read -r line; do printf '  - %s\n' "$line"; done
    echo
    printf 'Change class: %s (%s)\n' "$PLAN_CLASS" "$(plan_class_label "$PLAN_CLASS")"
    return 0
}

cli_iran_peer_remove() { # gre iran peer remove --name NAME [--yes]    require_root
    migrate_legacy_iran_conf || return 1
    local NAME="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)     [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --yes|-y)   YES=1; shift ;;
            --help|-h)  echo "Usage: gre iran peer remove --name NAME [--yes]"; return 0 ;;
            *)          err "Unknown option: $1"; err "Usage: gre iran peer remove --name NAME [--yes]"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Missing required option: --name"; err "Usage: gre iran peer remove --name NAME [--yes]"; return 1; }

    local f="$FOREIGNS_DIR/$NAME.conf"
    [[ -f "$f" ]] || { err "Peer '$NAME' does not exist."; return 1; }
    local FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    load_peer_conf "$f" || return 1
    if (( ! YES )); then
        confirm "Remove peer '$NAME' (tunnel $TUN, foreign $FOREIGN_IP)? Other peers keep running." \
            || { info "Cancelled."; return; }
    fi
    stop_iran_peer "$f"
    rm -f "$f"
    audit_log "iran-peer-remove name=$NAME foreign=$FOREIGN_IP base=$SUBNET_BASE idx=$IDX"
    ok "Peer '$NAME' removed."
    if (( $(peer_count) == 0 )); then
        info "No peers remain; the shared service/watchdog stay installed (gre uninstall removes everything)."
    fi
}

cli_iran_peer_apply() { # gre iran peer apply --name NAME
    require_root
    migrate_legacy_iran_conf || return 1
    local NAME=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)     [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --help|-h)  echo "Usage: gre iran peer apply --name NAME"; return 0 ;;
            *)          err "Unknown option: $1"; err "Usage: gre iran peer apply --name NAME"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Missing required option: --name"; err "Usage: gre iran peer apply --name NAME"; return 1; }

    local f="$FOREIGNS_DIR/$NAME.conf"
    [[ -f "$f" ]] || { err "Peer '$NAME' does not exist."; return 1; }
    apply_iran_peer "$f" || { err "Failed to apply peer '$NAME'."; return 1; }
    [[ -f "$SERVICE_FILE" ]] || install_service
    audit_log "iran-peer-apply name=$NAME"
    ok "Peer '$NAME' applied."
}

# ------------------------------------------------------------- CLI: JSON status
show_status_json() { # pure-bash JSON; values are pre-validated (IPs/alphanumeric)
    migrate_legacy_iran_conf >/dev/null || true  # keep stdout pure JSON
    local roles="[" sep=""
    if [[ -f "$FOREIGN_CONF" ]]; then roles+="${sep}\"foreign\""; sep=","; fi
    if [[ -f "$IRAN_CONF" ]];    then roles+="${sep}\"iran\"";    sep=","; fi
    roles+="]"

    local nodes_json="[" nsep=""
    if [[ -f "$FOREIGN_CONF" ]]; then
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE"
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            local reach="false"
            ping -c 1 -W 2 "${SUBNET_BASE}.${IDX}.2" >/dev/null 2>&1 && reach="true"
            nodes_json+="${nsep}{\"name\":\"$NAME\",\"iran_ip\":\"$IRAN_IP\",\"subnet_base\":\"$SUBNET_BASE\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\",\"reachable\":$reach}"
            nsep=","
        done
    fi
    nodes_json+="]"

    local peers_json
    peers_json="$(iran_peers_json)"

    # legacy field for single-peer setups (deprecated; read iran_peers instead)
    local iran_json="null"
    if [[ "$(peer_count)" == "1" ]]; then
        local f NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
              IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            load_peer_conf "$f" || continue
            local reach="false"
            ping -c 1 -W 2 "${SUBNET_BASE}.${IDX}.1" >/dev/null 2>&1 && reach="true"
            iran_json="{\"name\":\"$NAME\",\"foreign_ip\":\"$FOREIGN_IP\",\"subnet_base\":\"$SUBNET_BASE\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\",\"tcp_ports\":\"$TCP_PORTS\",\"udp_ports\":\"$UDP_PORTS\",\"reachable\":$reach,\"deprecated\":true}"
        done
    fi

    local svc_state wd_state
    svc_state="$(service_state)";  svc_state="${svc_state:-unknown}"
    wd_state="$(watchdog_state)";  wd_state="${wd_state:-unknown}"

    cat <<EOF
{
  "version": "$VERSION",
  "schema_version": 2,
  "roles": $roles,
  "service": "$svc_state",
  "watchdog": "$wd_state",
  "tunnels_up": $(tunnel_count),
  "nodes": $nodes_json,
  "iran_peers": $peers_json,
  "iran": $iran_json
}
EOF
}

# ------------------------------------------------------------- CLI: doctor
d_pass() { printf '%s[PASS]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
d_warn() { DOC_WARN=$(( ${DOC_WARN:-0} + 1 )); printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
d_fail() { DOC_FAIL=$(( ${DOC_FAIL:-0} + 1 )); printf '%s[FAIL]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }

# Per-peer doctor helpers; use NAME/WAN_IF/IRAN_IP/TUN/peer/MSS_CLAMP and the
# port lists from the caller's scope (set by load_peer_conf).
doctor_gre_filtered_hint() { # doctor_gre_filtered_hint REMOTE_PUBLIC_IP — printed after a failed tunnel ping
    info "      cause: the far side is down, or GRE (protocol 47) is filtered — often only one-way — by a datacenter."
    info "      proof: run 'tcpdump -n proto 47' on BOTH servers while pinging the tunnel peer."
    info "      The direction showing no packets is the filtered one (remote public IP: $1)."
    info "      Note: plain 'ping $1' (ICMP) can still work while proto 47 is blocked — they are different protocols."
}

doctor_peer_dnat() { # doctor_peer_dnat PROTO LIST
    local proto="$1" plist="$2"
    [[ -z "$plist" ]] && return 0
    if iptables -t nat -C PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p "$proto" \
        -m multiport --dports "$plist" \
        -m comment --comment "multi-gre-iran-$NAME-dnat-$proto" \
        -j DNAT --to-destination "$peer" 2>/dev/null; then
        d_pass "[$NAME] NAT DNAT rule for $proto ports $plist is present"
    elif iptables -t nat -C PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p "$proto" \
        -m multiport --dports "$plist" -j DNAT --to-destination "$peer" 2>/dev/null; then
        d_warn "[$NAME] NAT DNAT rule for $proto ports $plist uses the legacy un-commented style (fix: gre iran peer apply --name $NAME)"
    else
        d_fail "[$NAME] NAT DNAT rule for $proto ports $plist is missing (fix: gre iran peer apply --name $NAME)"
    fi
}

doctor_peer_snat() { # uses TCP_PORTS/UDP_PORTS/TUN/peer/self
    [[ -z "$TCP_PORTS" && -z "$UDP_PORTS" ]] && return 0
    local self="${SUBNET_BASE}.${IDX}.2"
    if iptables -t nat -C POSTROUTING -o "$TUN" -d "$peer" \
        -m comment --comment "multi-gre-iran-$NAME-snat" -j SNAT --to-source "$self" 2>/dev/null; then
        d_pass "[$NAME] NAT SNAT rule on $TUN is present"
    elif iptables -t nat -C POSTROUTING -o "$TUN" -d "$peer" -j SNAT --to-source "$self" 2>/dev/null; then
        d_warn "[$NAME] NAT SNAT rule on $TUN uses the legacy un-commented style (fix: gre iran peer apply --name $NAME)"
    else
        d_fail "[$NAME] NAT SNAT rule on $TUN is missing (fix: gre iran peer apply --name $NAME)"
    fi
}

doctor_peer_mss() {
    [[ "${MSS_CLAMP:-0}" == "1" ]] || return 0
    # The current form sets the MSS EXPLICITLY from the tunnel's MTU. Derive it the same
    # way peer_rules_install does, so doctor looks for exactly the rule a correct apply
    # would have written.
    #
    # The LIVE interface MTU is preferred over the stored one, because a connection with
    # no explicit override has an empty MTU in its config while its interface is at the
    # default. Trusting the config only would make doctor fail every such connection.
    local want_mtu="${MTU:-}" want_mss=""
    [[ -n "$want_mtu" ]] || want_mtu="$(iface_mtu "$TUN")"
    [[ -n "$want_mtu" ]] && want_mss=$(( want_mtu - 40 ))
    if [[ -n "$want_mss" ]] && (( want_mss >= 536 )) && \
       iptables -t mangle -C POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "multi-gre-iran-$NAME-mss" -j TCPMSS --set-mss "$want_mss" 2>/dev/null; then
        d_pass "[$NAME] TCP MSS clamped to $want_mss for tunnel MTU $want_mtu"
        if iptables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment "multi-gre-iran-$NAME-mss-fwd" -j TCPMSS --set-mss "$want_mss" 2>/dev/null; then
            d_pass "[$NAME] TCP MSS clamp is also on the FORWARD path"
        else
            d_warn "[$NAME] TCP MSS clamp is missing on the FORWARD path (forwarded traffic can still stall; fix: gre iran peer apply --name $NAME)"
        fi
    elif iptables -t mangle -C POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        # The old rule is not a failure: it is simply less reliable, because the MSS is
        # derived from the route MTU (the underlay) rather than the tunnel's own MTU.
        d_warn "[$NAME] TCP MSS is derived from the PMTU, which for a GRE egress is the underlay MTU and can advertise an MSS the tunnel cannot carry (fix: gre iran peer apply --name $NAME)"
    else
        d_fail "[$NAME] TCP MSS clamping rule on $TUN is missing (fix: gre iran peer apply --name $NAME)"
    fi
}

# ------------------------------------------------- tunnel diagnose (read-only)
#
# A read-only counterpart to `gre doctor`, for the case where the tunnel exists (or
# should) but traffic does not flow. It answers the question doctor cannot: is this a
# CONFIGURATION problem, an UNDERLAY problem, a FIREWALL problem, or simply a probe
# that could not tell?
#
# It changes nothing: no interface is created or removed, no rule is touched, no
# service is restarted. Every check reports PASS / WARN / FAIL / UNKNOWN, and UNKNOWN
# is used honestly — for a probe that could not run, rather than being reported as a
# failure or quietly as a success.

# Escape a string for a JSON string value. Tolerates an empty/missing argument, so it
# is safe under `set -u` when an optional field happens to be unset.
json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Every iptables rule mentioning GRE or this manager, across all tables. Read-only.
dump_gre_rules() {
    local t
    for t in filter nat mangle raw; do
        iptables -t "$t" -S 2>/dev/null | sed "s|^|-t $t |"
    done
}

tunnel_diagnose() { # tunnel_diagnose NAME [--json]
    local name="$1"; shift || true
    local AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) AS_JSON=1; shift ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done

    [[ -n "$name" ]] || { err "Usage: gre tunnel diagnose --name NAME [--json]"; return 1; }
    valid_name "$name" || { err "Invalid connection name: '$name'"; return 1; }

    # Resolve which side this host is for this connection. The name identifies the
    # connection on both sides; which FILE it lives in says which side we are on.
    local side="" peerf="$FOREIGNS_DIR/$name.conf" nodef="$NODES_DIR/$name.conf"
    if [[ -f "$peerf" ]]; then
        side="iran"
    elif [[ -f "$nodef" ]]; then
        side="foreign"
    else
        err "No connection named '$name' is configured on this host."
        err "  looked for: $peerf"
        err "              $nodef"
        return 1
    fi

    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    if [[ "$side" == "iran" ]]; then
        load_peer_conf "$peerf" || { err "Peer config $peerf failed validation."; return 1; }
    else
        node_conf_read "$nodef" NAME IRAN_IP SUBNET_BASE IDX KEY TUN
        FOREIGN_IP="$(foreign_local_ip)"
    fi
    [[ -n "$TUN" ]] || TUN="gre-$NAME"

    # The two ends, as this host sees them.
    local self_ip peer_ip self_cidr peer_cidr
    if [[ "$side" == "iran" ]]; then
        self_ip="$IRAN_IP"; peer_ip="$FOREIGN_IP"
        self_cidr="${SUBNET_BASE}.${IDX}.2/30"; peer_cidr="${SUBNET_BASE}.${IDX}.1"
    else
        self_ip="$FOREIGN_IP"; peer_ip="$IRAN_IP"
        self_cidr="${SUBNET_BASE}.${IDX}.1/30"; peer_cidr="${SUBNET_BASE}.${IDX}.2"
    fi

    local checks_json="" n_ok=0 n_warn=0 n_fail=0 n_unknown=0
    add_check() { # add_check ID STATUS DETAIL
        local id="$1" st="$2" dt="$3"
        case "$st" in
            PASS) n_ok=$(( n_ok + 1 )) ;;
            WARN) n_warn=$(( n_warn + 1 )) ;;
            FAIL) n_fail=$(( n_fail + 1 )) ;;
            *)    n_unknown=$(( n_unknown + 1 )) ;;
        esac
        [[ -n "$checks_json" ]] && checks_json+=","
        checks_json+="{\"id\":\"$(json_escape "$id")\",\"status\":\"$st\",\"detail\":\"$(json_escape "$dt")\"}"
        [[ "$AS_JSON" == "1" ]] || printf '%-9s %-28s %s\n' "[$st]" "$id" "$dt"
    }

    # 1 + 2. interface present and administratively up
    local iface_up="no"
    if tun_exists "$TUN"; then
        if ip link show "$TUN" 2>/dev/null | grep -qE 'state (UP|UNKNOWN)|<[^>]*UP'; then
            iface_up="yes"
        fi
        # ip link show does not always print state; treat a present interface with an
        # address as up, and say so rather than guessing.
        [[ "$iface_up" == "no" ]] && iface_up="unknown"
    fi

    # 3 + 4. endpoints and key, compared against the live interface
    local live_local live_remote live_key
    live_local="$(tunnel_local_endpoint "$TUN")"
    live_remote="$(ip -d tunnel show "$TUN" 2>/dev/null | sed -n 's/.*[[:space:]]remote[[:space:]]\+\([0-9.]\+\)[[:space:]].*/\1/p' | head -n1)"
    local _ki; _ki="$(tunnel_key_info "$TUN" "$KEY")"; live_key="${_ki%% *}"; key_source="${_ki##* }"

    # 5 + 6. addressing
    local live_addr
    live_addr="$(ip -4 addr show dev "$TUN" 2>/dev/null | sed -n 's/.*inet[[:space:]]\+\([0-9./]\+\).*/\1/p' | head -n1)"

    # 7 + 8. routing to the peer, and a route that would loop GRE back into itself
    local peer_route="" loop_route=""
    if [[ -n "$peer_ip" ]]; then
        peer_route="$(ip -4 route get "$peer_ip" 2>/dev/null | head -n1)"
    fi
    loop_route="$(ip -4 route show 2>/dev/null | grep -E "dev $TUN" | grep -vE "${SUBNET_BASE}\.${IDX}\." | head -n1)"

    # 9 + 10. is GRE (protocol 47) blocked, and what does our own rule set say
    local gre_blocked="unknown"
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p gre -m comment --comment "multi-gre-block" -j DROP 2>/dev/null; then
            # A catch-all DROP exists. The peer is only permitted if an ACCEPT for its
            # address is present, so that is what decides the verdict.
            if [[ -n "$peer_ip" ]] && iptables -C INPUT -p gre -s "$peer_ip" \
                    -m comment --comment "multi-gre-node-$NAME" -j ACCEPT 2>/dev/null; then
                gre_blocked="no"
            else
                gre_blocked="yes"
            fi
        else
            gre_blocked="no"
        fi
    fi

    # 11. forwarding, only meaningful where this host forwards
    local ip_forward=""
    ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"

    # 12. counters
    local rx_bytes="" tx_bytes=""
    if [[ -r "/sys/class/net/$TUN/statistics/rx_bytes" ]]; then
        rx_bytes="$(cat "/sys/class/net/$TUN/statistics/rx_bytes" 2>/dev/null)"
        tx_bytes="$(cat "/sys/class/net/$TUN/statistics/tx_bytes" 2>/dev/null)"
    fi

    # 13. duplicates / stale interfaces carrying the same subnet
    local dup_tuns=""
    dup_tuns="$(ip -4 addr show 2>/dev/null | grep -E "inet ${SUBNET_BASE}\.${IDX}\." | sed -n 's/.*[[:space:]]\([^ ]*\)$/\1/p' | sort -u | tr '\n' ' ')"

    # 14. does the config agree with what is live?
    local drift=""
    if tun_exists "$TUN"; then
        [[ -n "$live_local" && "$live_local" != "$self_ip" ]] && drift+="local $live_local != $self_ip; "
        [[ -n "$live_remote" && -n "$peer_ip" && "$live_remote" != "$peer_ip" ]] && drift+="remote $live_remote != $peer_ip; "
        [[ -n "$live_key" && -n "$KEY" && "$live_key" != "$KEY" ]] && drift+="key $live_key != $KEY; "
    fi

    # 15. is the far end of the tunnel actually reachable
    local ping_state="UNKNOWN" ping_detail="not attempted"
    if tun_exists "$TUN"; then
        if ping -c 2 -W 3 "$peer_cidr" >/dev/null 2>&1; then
            ping_state="PASS"; ping_detail="$peer_cidr replied"
        else
            # Distinguish "the tunnel is down" from "ICMP over the tunnel is filtered":
            # the underlay telling us the peer host is up makes a silent tunnel much
            # more likely to be a filter than a broken link.
            local underlay="down"
            if [[ -n "$peer_ip" ]] && ping -c 2 -W 3 "$peer_ip" >/dev/null 2>&1; then
                underlay="up"
            fi
            if [[ "$underlay" == "up" ]]; then
                ping_state="WARN"
                ping_detail="$peer_cidr did not reply, but the peer host $peer_ip is reachable on the underlay (tunnel ICMP may be filtered)"
            else
                ping_state="FAIL"
                ping_detail="$peer_cidr did not reply"
            fi
        fi
    fi

    # ---- the checks, in the order an operator should read them
    if tun_exists "$TUN"; then
        add_check "interface_exists" "PASS" "$TUN is present"
    else
        add_check "interface_exists" "FAIL" "$TUN does not exist (create it: gre iran peer apply --name $NAME / gre node add)"
    fi

    if [[ "$iface_up" == "yes" ]]; then
        add_check "interface_up" "PASS" "$TUN is administratively up"
    elif [[ "$iface_up" == "unknown" ]]; then
        add_check "interface_up" "UNKNOWN" "could not read the link state of $TUN"
    elif tun_exists "$TUN"; then
        add_check "interface_up" "FAIL" "$TUN is present but not up"
    else
        add_check "interface_up" "UNKNOWN" "no interface to inspect"
    fi

    if ! tun_exists "$TUN"; then
        add_check "local_endpoint" "UNKNOWN" "no interface to inspect"
        add_check "remote_endpoint" "UNKNOWN" "no interface to inspect"
        add_check "gre_key" "UNKNOWN" "no interface to inspect"
    else
        if [[ -z "$live_local" ]]; then
            add_check "local_endpoint" "FAIL" "the interface has no local address (this is the endpoint that must be this host's public IP)"
        elif [[ -n "$self_ip" && "$live_local" != "$self_ip" ]]; then
            add_check "local_endpoint" "FAIL" "interface local=$live_local but this host should use $self_ip"
        else
            add_check "local_endpoint" "PASS" "$live_local"
        fi
        if [[ -z "$live_remote" ]]; then
            add_check "remote_endpoint" "FAIL" "the interface has no remote address"
        elif [[ -n "$peer_ip" && "$live_remote" != "$peer_ip" ]]; then
            add_check "remote_endpoint" "FAIL" "interface remote=$live_remote but the config says $peer_ip"
        else
            add_check "remote_endpoint" "PASS" "$live_remote"
        fi
        if [[ -z "$live_key" ]]; then
            add_check "gre_key" "WARN" "no GRE key on the interface (both ends must match; unset is only valid if both ends are unset)"
        elif [[ -n "$KEY" && "$live_key" != "$KEY" ]]; then
            add_check "gre_key" "FAIL" "interface key=$live_key but the config says $KEY (both ends and the config must match)"
        else
            add_check "gre_key" "PASS" "$live_key"
        fi
    fi

    if [[ -z "$live_addr" ]]; then
        add_check "tunnel_address" "FAIL" "no IPv4 address on $TUN (expected $self_cidr)"
    elif [[ "$live_addr" != "$self_cidr" ]]; then
        add_check "tunnel_address" "WARN" "$live_addr (config expects $self_cidr)"
    else
        add_check "tunnel_address" "PASS" "$live_addr"
    fi

    if [[ -z "$peer_ip" ]]; then
        add_check "underlay_route" "UNKNOWN" "the peer address is not configured"
    elif [[ -z "$peer_route" ]]; then
        add_check "underlay_route" "FAIL" "no route to $peer_ip"
    elif [[ "$peer_route" == *"dev $TUN"* ]]; then
        add_check "underlay_route" "FAIL" "the route to $peer_ip goes back out through $TUN itself (GRE cannot be carried inside GRE)"
    else
        add_check "underlay_route" "PASS" "$peer_route"
    fi

    if [[ -n "$loop_route" ]]; then
        add_check "no_gre_loop_route" "FAIL" "a route sends non-tunnel traffic out $TUN: $loop_route"
    else
        add_check "no_gre_loop_route" "PASS" "no non-tunnel route points at $TUN"
    fi

    if [[ "$gre_blocked" == "yes" ]]; then
        add_check "gre_47_permitted" "FAIL" "the GRE whitelist drops protocol 47 from $peer_ip (fix: gre node add --name $NAME --ip $peer_ip, or disable the whitelist)"
    elif [[ "$gre_blocked" == "no" ]]; then
        add_check "gre_47_permitted" "PASS" "protocol 47 is not dropped by the manager's whitelist"
    else
        add_check "gre_47_permitted" "UNKNOWN" "iptables is not available, so GRE filtering could not be checked"
    fi

    if [[ -n "$dup_tuns" && "$(echo "$dup_tuns" | tr -d ' \n')" != "$TUN" ]]; then
        add_check "duplicate_address" "WARN" "these interfaces share ${SUBNET_BASE}.${IDX}.x: $dup_tuns"
    else
        add_check "duplicate_address" "PASS" "no other interface uses ${SUBNET_BASE}.${IDX}.x"
    fi

    if [[ -z "$ip_forward" ]]; then
        add_check "ip_forward" "UNKNOWN" "could not read net.ipv4.ip_forward"
    elif [[ "$ip_forward" == "1" ]]; then
        add_check "ip_forward" "PASS" "net.ipv4.ip_forward=1"
    elif [[ "$side" == "iran" && ( -n "$TCP_PORTS" || -n "$UDP_PORTS" ) ]]; then
        add_check "ip_forward" "FAIL" "net.ipv4.ip_forward=0 but this host forwards ports (enable: sysctl -w net.ipv4.ip_forward=1)"
    else
        add_check "ip_forward" "WARN" "net.ipv4.ip_forward=0"
    fi

    if [[ -z "$rx_bytes" ]]; then
        add_check "traffic_counters" "UNKNOWN" "no counters for $TUN"
    elif [[ "$rx_bytes" == "0" && "${tx_bytes:-0}" == "0" ]]; then
        add_check "traffic_counters" "WARN" "no bytes have crossed $TUN (rx=$rx_bytes tx=${tx_bytes:-0})"
    else
        add_check "traffic_counters" "PASS" "rx=$rx_bytes tx=${tx_bytes:-0}"
    fi

    if [[ -n "$drift" ]]; then
        add_check "config_matches_live" "FAIL" "${drift%; }"
    elif tun_exists "$TUN"; then
        add_check "config_matches_live" "PASS" "the live interface matches the configuration"
    else
        add_check "config_matches_live" "UNKNOWN" "no interface to compare"
    fi

    add_check "tunnel_reachable" "$ping_state" "$ping_detail"

    if [[ "$AS_JSON" == "1" ]]; then
        printf '{"name":"%s","side":"%s","tunnel":"%s","generated_at":"%s",' \
            "$(json_escape "$name")" "$side" "$(json_escape "$TUN")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '"summary":{"pass":%d,"warn":%d,"fail":%d,"unknown":%d},' "$n_ok" "$n_warn" "$n_fail" "$n_unknown"
        printf '"checks":[%s]}\n' "$checks_json"
    else
        printf '\n'
        printf 'pass=%d warn=%d fail=%d unknown=%d\n' "$n_ok" "$n_warn" "$n_fail" "$n_unknown"
    fi

    # Exit non-zero only on a real failure, so a script can gate on it.
    (( n_fail == 0 ))
}

cli_tunnel_diagnose() { # gre tunnel diagnose --name NAME [--json]
    local NAME="" AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json) AS_JSON=1; shift ;;
            --help|-h)
                echo "Usage: gre tunnel diagnose --name NAME [--json]"
                echo "Read-only: reports whether a connection's tunnel is configured, up,"
                echo "routed, permitted and actually passing traffic. Changes nothing."
                return 0 ;;
            *) err "Unknown option: $1"; err "Usage: gre tunnel diagnose --name NAME [--json]"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre tunnel diagnose --name NAME [--json]"; return 1; }
    if [[ "$AS_JSON" == "1" ]]; then
        tunnel_diagnose "$NAME" --json
    else
        echo
        info "Diagnosing connection '$NAME' (read-only)..."
        echo
        tunnel_diagnose "$NAME"
    fi
}

# Also dump the raw rule set on request, for a report an operator can paste.
cli_tunnel_rules() { # gre tunnel rules [--json]
    local AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) AS_JSON=1; shift ;;
            --help|-h) echo "Usage: gre tunnel rules [--json]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    if [[ "$AS_JSON" == "1" ]]; then
        printf '{"rules":"%s"}\n' "$(dump_gre_rules | json_escape)"
    else
        dump_gre_rules
    fi
}

# ==================================================== per-connection MTU diagnosis
#
# Gathers what the recommender needs for ONE connection on THIS host and exposes it as
# JSON, so the Hub can merge both sides. It sets MTU_* scalars rather than echoing
# because the same data feeds both the recommendation and the human report.

# Resolve a connection name to the side and files this host holds for it.
mtu_resolve() { # mtu_resolve NAME
    local name="$1"
    local peerf="$FOREIGNS_DIR/$name.conf" nodef="$NODES_DIR/$name.conf"
    MTU_SIDE=""; MTU_FILE=""; MTU_NAME=""; MTU_PEER_IP=""; MTU_SELF_IP=""
    MTU_SUBNET_BASE="$DEFAULT_SUBNET_BASE"; MTU_IDX=""; MTU_KEY=""; MTU_TUN=""
    MTU_MSS="0"; MTU_OVERRIDE=""; MTU_TCP=""; MTU_UDP=""; MTU_WAN_IF=""

    if [[ -f "$peerf" ]]; then
        MTU_SIDE="iran"; MTU_FILE="$peerf"
        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
              IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0" MTU=""
        load_peer_conf "$peerf" || return 1
        MTU_NAME="$NAME"; MTU_PEER_IP="$FOREIGN_IP"; MTU_SELF_IP="$IRAN_IP"
        MTU_SUBNET_BASE="$SUBNET_BASE"; MTU_IDX="$IDX"; MTU_KEY="$KEY"; MTU_TUN="$TUN"
        MTU_MSS="$MSS_CLAMP"; MTU_OVERRIDE="$MTU"
        # The port set and WAN interface are what the health check needs to inspect this
        # connection's own forwarding rules. Read by gre health-check.
        MTU_TCP="$TCP_PORTS"; MTU_UDP="$UDP_PORTS"; MTU_WAN_IF="$WAN_IF"
    elif [[ -f "$nodef" ]]; then
        MTU_SIDE="foreign"; MTU_FILE="$nodef"
        local N_NAME="" N_IRAN_IP="" N_BASE="$DEFAULT_SUBNET_BASE" N_IDX="" N_KEY="" N_TUN="" N_MTU=""
        node_conf_read "$nodef" N_NAME N_IRAN_IP N_BASE N_IDX N_KEY N_TUN N_MTU
        MTU_NAME="$N_NAME"; MTU_PEER_IP="$N_IRAN_IP"; MTU_SELF_IP="$(foreign_local_ip)"
        MTU_SUBNET_BASE="$N_BASE"; MTU_IDX="$N_IDX"; MTU_KEY="$N_KEY"; MTU_TUN="$N_TUN"
        MTU_OVERRIDE="$N_MTU"
        # The FOREIGN side has no per-node NAT or MSS rules; a node config cannot
        # express them, so the clamp is reported as unavailable rather than "off".
        MTU_MSS=""
    else
        return 1
    fi
    [[ -n "$MTU_TUN" ]] || MTU_TUN="gre-$MTU_NAME"
    return 0
}

# Collect the MTU picture. Read-only; sends packets only with --probe.
mtu_collect() { # mtu_collect [--probe]
    local do_probe="${1:-}"
    local self_tun_ip
    if [[ "$MTU_SIDE" == "iran" ]]; then
        self_tun_ip="${MTU_SUBNET_BASE}.${MTU_IDX}.2"
    else
        self_tun_ip="${MTU_SUBNET_BASE}.${MTU_IDX}.1"
    fi

    local tun_present="no" tun_mtu="" iface_up="unknown"
    if tun_exists "$MTU_TUN"; then
        tun_present="yes"
        tun_mtu="$(iface_mtu "$MTU_TUN")"
        ip link show "$MTU_TUN" 2>/dev/null | grep -qE 'state (UP|UNKNOWN)|<[^>]*UP' && iface_up="yes"
    fi

    # The underlay, as the kernel would actually use it for this peer.
    local under_iface="" under_mtu="" route_line="" route_mtu="" icmp_state="unknown"
    route_line="$(mtu_diag_route "$MTU_PEER_IP")"
    under_iface="$(sed -n 's/.*[[:space:]]dev[[:space:]]\+\([^ ]\+\).*/\1/p' <<< "$route_line" | head -n1)"
    under_mtu="$(iface_mtu "$under_iface")"
    route_mtu="$(route_mtu_for "$MTU_PEER_IP")"

    # The overhead of THIS encapsulation, from its own flags rather than a constant.
    local outer_ipv=4
    [[ "$MTU_PEER_IP" == *:* ]] && outer_ipv=6
    local overhead; overhead="$(gre_overhead_bytes "$MTU_KEY" "$outer_ipv")"

    # Is ICMP usable here at all? A filtered path makes every probe inconclusive, and
    # that must never be dressed up as a tunnel or MTU failure.
    local icmp_ok="no"
    if mtu_icmp_available "$MTU_PEER_IP"; then icmp_ok="yes"; icmp_state="seen"; fi

    local probe_state="UNKNOWN" probe_max="-" probe_frag="-" probe_n="0"
    if [[ "$do_probe" == "--probe" ]]; then
        if [[ "$icmp_ok" == "yes" ]]; then
            local res; res="$(mtu_probe_path "$MTU_PEER_IP" "" 1472)"
            local -a parts=(); read -r -a parts <<< "$res"
            probe_state="${parts[0]:-UNKNOWN}"; probe_max="${parts[1]:--}"
            probe_frag="${parts[2]:--}"; probe_n="${parts[3]:-0}"
        else
            probe_state="unknown"
        fi
    fi

    # The verified path capacity, in IP-packet terms: a measurement if there is one, else
    # the egress interface MTU, and empty rather than invented when neither exists.
    #
    # This is the UNDERLAY capacity. The largest inner packet the tunnel can carry is
    # this minus the encapsulation overhead, which is what the recommender computes.
    local capacity=""
    if [[ "$probe_max" != "-" && -n "$probe_max" ]]; then
        capacity="$(( probe_max + MTU_PROBE_HDR ))"
    elif [[ -n "$route_mtu" ]]; then
        capacity="$route_mtu"
    elif [[ -n "$under_mtu" ]]; then
        capacity="$under_mtu"
    fi

    MTU_SELF_TUN_IP="$self_tun_ip"
    MTU_TUN_PRESENT="$tun_present"; MTU_TUN_MTU="$tun_mtu"
    MTU_UNDER_IFACE="$under_iface"; MTU_UNDER_MTU="$under_mtu"

    MTU_OVERHEAD="$overhead"
    MTU_PROBE_STATE="$probe_state"; MTU_PROBE_MAX="$probe_max"; MTU_PROBE_N="$probe_n"
    MTU_CAPACITY="$capacity"

    # The MSS clamp, as actually installed for this connection.
    local mss_mode="absent" mss_value="" want_mss=""
    if [[ "$tun_present" == "yes" && -n "$tun_mtu" ]]; then
        want_mss=$(( tun_mtu - 40 ))
        if iptables -t mangle -C POSTROUTING -o "$MTU_TUN" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment "multi-gre-iran-$MTU_NAME-mss" -j TCPMSS --set-mss "$want_mss" 2>/dev/null; then
            mss_mode="set"; mss_value="$want_mss"
        elif iptables -t mangle -C POSTROUTING -o "$MTU_TUN" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            mss_mode="pmtu"
        fi
    fi
    MTU_MSS_MODE="$mss_mode"; MTU_MSS_VALUE="$mss_value"

    local checks="" n_pass=0 n_warn=0 n_fail=0 n_unknown=0
    add_mtu_check() {
        [[ -n "$checks" ]] && checks+=","
        checks+="{\"id\":\"$(json_escape "$1")\",\"status\":\"$2\",\"detail\":\"$(json_escape "$3")\"}"
    }
    if [[ "$tun_present" == "yes" ]]; then
        add_mtu_check "interface_exists" "PASS" "$MTU_TUN is present"; n_pass=$((n_pass+1))
    else
        add_mtu_check "interface_exists" "FAIL" "$MTU_TUN does not exist"; n_fail=$((n_fail+1))
    fi
    if [[ "$iface_up" == "yes" ]]; then add_mtu_check "interface_up" "PASS" "up"; n_pass=$((n_pass+1))
    elif [[ "$iface_up" == "unknown" ]]; then add_mtu_check "interface_up" "UNKNOWN" "could not read the link state"; n_unknown=$((n_unknown+1))
    else add_mtu_check "interface_up" "FAIL" "not up"; n_fail=$((n_fail+1)); fi

    if [[ -z "$under_mtu" ]]; then
        add_mtu_check "underlay_mtu" "UNKNOWN" "could not read the egress interface MTU"; n_unknown=$((n_unknown+1))
    else
        add_mtu_check "underlay_mtu" "PASS" "$under_iface mtu $under_mtu"; n_pass=$((n_pass+1))
    fi

    if [[ -z "$capacity" ]]; then
        add_mtu_check "path_capacity" "UNKNOWN" "no measurement and no usable default"; n_unknown=$((n_unknown+1))
    elif [[ "$probe_state" == "ok" || "$probe_state" == "frag_needed" ]]; then
        add_mtu_check "path_capacity" "PASS" "measured $capacity"; n_pass=$((n_pass+1))
    else
        add_mtu_check "path_capacity" "WARN" "assuming $capacity from the interface MTU; not measured"; n_warn=$((n_warn+1))
    fi

    case "$probe_state" in
        ok|frag_needed) add_mtu_check "icmp_df_probe" "PASS" "probed in $probe_n packets ($probe_state)"; n_pass=$((n_pass+1)) ;;
        unsupported)    add_mtu_check "icmp_df_probe" "UNKNOWN" "this host cannot send DF probes"; n_unknown=$((n_unknown+1)) ;;
        *)              add_mtu_check "icmp_df_probe" "UNKNOWN" "ICMP is filtered or unresponsive, so the path MTU could not be measured (that is not proof of an MTU problem)"; n_unknown=$((n_unknown+1)) ;;
    esac

    if [[ -n "$tun_mtu" && -n "$capacity" ]]; then
        local want=$(( capacity - overhead ))
        (( want < MTU_MIN_INNER )) && want="$MTU_MIN_INNER"
        if (( tun_mtu > capacity )); then
            add_mtu_check "gre_mtu_fits_path" "FAIL" "tunnel MTU $tun_mtu exceeds the path capacity $capacity"; n_fail=$((n_fail+1))
        elif (( tun_mtu > want )); then
            add_mtu_check "gre_mtu_fits_path" "WARN" "tunnel MTU $tun_mtu is larger than the path allows ($want)"; n_warn=$((n_warn+1))
        else
            add_mtu_check "gre_mtu_fits_path" "PASS" "tunnel MTU $tun_mtu fits (path allows $want)"; n_pass=$((n_pass+1))
        fi
    else
        add_mtu_check "gre_mtu_fits_path" "UNKNOWN" "no tunnel MTU or no path capacity"; n_unknown=$((n_unknown+1))
    fi

    case "$mss_mode" in
        set)  add_mtu_check "tcp_mss_clamp" "PASS" "MSS set to $mss_value"; n_pass=$((n_pass+1)) ;;
        pmtu) add_mtu_check "tcp_mss_clamp" "WARN" "MSS is derived from the route MTU, which for a GRE egress is the underlay and can be too large"; n_warn=$((n_warn+1)) ;;
        *)    if [[ "$MTU_MSS" == "1" ]]; then
                  add_mtu_check "tcp_mss_clamp" "FAIL" "clamping is enabled for this connection but no rule is installed"; n_fail=$((n_fail+1))
              elif [[ -z "$MTU_MSS" ]]; then
                  add_mtu_check "tcp_mss_clamp" "SKIPPED" "not applicable on this side"; n_unknown=$((n_unknown+1))
              else
                  add_mtu_check "tcp_mss_clamp" "SKIPPED" "MSS clamping is disabled for this connection"; n_unknown=$((n_unknown+1))
              fi ;;
    esac

    MTU_CHECKS_JSON="$checks"
    MTU_N_PASS="$n_pass"; MTU_N_WARN="$n_warn"; MTU_N_FAIL="$n_fail"; MTU_N_UNKNOWN="$n_unknown"

    MTU_JSON="$(printf '{"name":"%s","side":"%s","tunnel":"%s","generated_at":"%s",' \
        "$(json_escape "$MTU_NAME")" "$MTU_SIDE" "$(json_escape "$MTU_TUN")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")"
    MTU_JSON+="$(printf '"underlay":{"iface":"%s","mtu":%s,"route":"%s","src":"%s","dst":"%s","route_mtu":%s,"icmp_frag_needed":"%s"},' \
        "$(json_escape "$under_iface")" "${under_mtu:-null}" "$(json_escape "$route_line")" \
        "$(json_escape "$MTU_SELF_IP")" "$(json_escape "$MTU_PEER_IP")" "${route_mtu:-null}" "$icmp_state")"
    MTU_JSON+="$(printf '"gre":{"tun":"%s","encap":"gre","key":%s,"flags":[],"outer_ipv":%s,"local":"%s","remote":"%s","mtu":%s,"inner_cidr":"%s/30","overhead":%s},' \
        "$(json_escape "$MTU_TUN")" "${MTU_KEY:-0}" "$outer_ipv" "$(json_escape "$MTU_SELF_IP")" \
        "$(json_escape "$MTU_PEER_IP")" "${tun_mtu:-null}" "$self_tun_ip" "$overhead")"
    MTU_JSON+="$(printf '"pmtu":{"inner_probe":{"state":"%s","max_ok":%s,"frag_needed_at":%s,"probes_sent":%s}},' \
        "$probe_state" "$([[ "$probe_max" == "-" ]] && echo null || echo "$probe_max")" \
        "$([[ "$probe_frag" == "-" ]] && echo null || echo "$probe_frag")" "$probe_n")"
    MTU_JSON+="$(printf '"mss_clamp":{"enabled":%s,"mode":"%s","value":%s,"scoped_to_connection":true},' \
        "$([[ "$MTU_MSS" == "1" ]] && echo true || echo false)" "$mss_mode" "${mss_value:-null}")"
    MTU_JSON+="$(printf '"summary":{"pass":%s,"warn":%s,"fail":%s,"unknown":%s},' "$n_pass" "$n_warn" "$n_fail" "$n_unknown")"
    MTU_JSON+="$(printf '"checks":[%s]}' "$checks")"
    return 0
}

# Build a recommendation from the collected data. Read-only.
mtu_make_recommendation() {
    local capacity="$MTU_CAPACITY" overhead="$MTU_OVERHEAD" cur="$MTU_TUN_MTU"
    local confidence="unknown" reason="" recommended="" margin=0 margin_reason="" safe="false"
    local min_legal="$MTU_MIN_INNER"

    # The inner protocol's own floor. A hard limit: no measurement can justify going
    # below it, so a "smaller is safer" instinct is capped here.
    case "${MTU_SELF_TUN_IP:-}" in *:*) min_legal="$MTU_MIN_INNER_V6" ;; esac

    if [[ -z "$capacity" ]]; then
        reason="No usable path measurement and no interface MTU to fall back on, so no recommendation can be made."
    else
        case "$MTU_PROBE_STATE" in
            ok|frag_needed) confidence="high" ;;
            inconclusive|unknown)
                confidence="low"
                reason="ICMP is filtered or unresponsive, so the path MTU could not be measured. The value below comes from the interface MTU and is a starting point, not a measurement." ;;
            unsupported)
                confidence="low"
                reason="This host cannot send DF probes, so the value below comes from the interface MTU rather than a measurement." ;;
            *) confidence="medium" ;;
        esac
        recommended=$(( capacity - overhead ))
        if (( recommended < min_legal )); then
            margin=$(( min_legal - recommended ))
            recommended="$min_legal"
            margin_reason="raised to the minimum legal MTU for the inner protocol"
            confidence="low"
        fi
        if [[ -z "$reason" ]]; then
            local keyed=""
            [[ -n "${MTU_KEY:-}" && "${MTU_KEY:-0}" != "0" ]] && keyed="keyed "
            reason="Path capacity $capacity minus $overhead bytes of ${keyed}GRE encapsulation"
        fi
    fi

    local requires="false"
    if [[ -n "$cur" && -n "$recommended" && "$cur" != "$recommended" ]]; then requires="true"; fi

    # A recommendation is only safe to offer when it rests on real evidence AND there is
    # an interface to change. Asking an operator to apply a guess is how an MTU change
    # makes things worse.
    if [[ "$confidence" != "unknown" && -n "$recommended" && "$MTU_TUN_PRESENT" == "yes" && -n "$cur" ]]; then
        safe="true"
    fi
    if [[ "$MTU_TUN_PRESENT" != "yes" ]]; then
        reason="${reason} The interface does not exist, so there is nothing to tune here."
        safe="false"
    fi

    MTU_REC_RECOMMENDED="$recommended"; MTU_REC_CONFIDENCE="$confidence"
    MTU_REC_SAFE="$safe"; MTU_REC_REQUIRES="$requires"

    MTU_REC_JSON="$(printf '{"connection":"%s","side":"%s","underlay_mtu":%s,"encapsulation_overhead":%s,"current_gre_mtu":%s,"recommended_gre_mtu":%s,"confidence":"%s","requires_change":%s,"reason":"%s","safe_to_apply":%s,"safety_margin":%s,"margin_reason":"%s","min_legal_mtu":%s}' \
        "$(json_escape "$MTU_NAME")" "$MTU_SIDE" "${capacity:-null}" "$overhead" "${cur:-null}" \
        "${recommended:-null}" "$confidence" "$requires" "$(json_escape "$reason")" "$safe" \
        "$margin" "$(json_escape "$margin_reason")" "$min_legal")"
}

mtu_print_side() {
    printf '  side            %s (%s)\n' "$MTU_SIDE" "$MTU_TUN"
    printf '  egress          %s mtu %s\n' "${MTU_UNDER_IFACE:--}" "${MTU_UNDER_MTU:--}"
    printf '  route mtu       %s\n' "${MTU_ROUTE_MTU:-none}"
    printf '  gre mtu         %s\n' "${MTU_TUN_MTU:-none}"
    printf '  overhead        %s bytes\n' "$MTU_OVERHEAD"
    printf '  path capacity   %s\n' "${MTU_CAPACITY:-unknown}"
    printf '  df probe        %s (max payload %s, %s packets)\n' "$MTU_PROBE_STATE" "$MTU_PROBE_MAX" "$MTU_PROBE_N"
    printf '  mss clamp       %s%s\n' "$MTU_MSS_MODE" "$([[ -n "$MTU_MSS_VALUE" ]] && printf ' %s' "$MTU_MSS_VALUE")"
    printf '  checks          pass=%s warn=%s fail=%s unknown=%s\n' "$MTU_N_PASS" "$MTU_N_WARN" "$MTU_N_FAIL" "$MTU_N_UNKNOWN"
}

# --------------------------------------------------------------- CLI: gre mtu
cli_mtu() { # gre mtu <list|diagnose|recommend|set|auto|restore|nic> ...
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)      cli_mtu_list "$@" ;;
        diagnose)  cli_mtu_diagnose "$@" ;;
        recommend) cli_mtu_recommend "$@" ;;
        set)       cli_mtu_set "$@" ;;
        auto)      cli_mtu_auto "$@" ;;
        restore)   cli_mtu_restore "$@" ;;
        nic)       cli_mtu_nic "$@" ;;
        --help|-h|"")
            cat <<'EOF'
Usage:
  gre mtu list [--json]
      Every configured connection with its tunnel MTU and GRE overhead. Read-only.

  gre mtu diagnose --name NAME [--json] [--probe]
      Per-connection MTU diagnosis for THIS host: egress interface and MTU, route MTU
      metric, the GRE overhead of this encapsulation, the tunnel MTU, the TCP MSS clamp
      state, and (with --probe) a bounded DF path probe. Read-only either way; it never
      changes an MTU.

  gre mtu recommend --name NAME [--json]
      A recommendation derived from the measurement, with an explicit confidence. It
      reports UNKNOWN rather than inventing a value when ICMP is filtered. Read-only.

  gre mtu auto --name NAME [--json]
      The same recommendation, phrased as an apply-ready command. Applies nothing.

  gre mtu set --name NAME --mtu VALUE [--yes]
      Change ONLY this connection's tunnel MTU, in place, without recreating the
      interface. Requires --yes, and verifies from the kernel afterwards.

  gre mtu restore --name NAME [--yes]
      Restore the MTU recorded before the last change on this host.

  gre mtu nic list [--json]
  gre mtu nic analyze --name NAME [--json]
      Advanced: the physical/virtual NIC MTU. Read-only analysis only. Changing a WAN
      NIC MTU can cut the connection you are managing, so this never applies one.

No MTU command here changes a WAN interface. Nothing is applied without --yes.
EOF
            ;;
        *) err "Usage: gre mtu <list|diagnose|recommend|set|auto|restore|nic> ...  (see: gre mtu --help)"; return 1 ;;
    esac
}

# Every configured connection with its MTU picture. Read-only, no probes.
cli_mtu_list() {
    local AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) AS_JSON=1; shift ;;
            --help|-h) echo "Usage: gre mtu list [--json]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done

    local json_rows="" count=0
    local -a names=()
    for conf_file in "$FOREIGNS_DIR"/*.conf "$NODES_DIR"/*.conf; do
        [[ -e "$conf_file" ]] || continue
        local nm
        nm="$(grep -E '^NAME=' "$conf_file" | head -n1 | cut -d= -f2)"
        [[ -n "$nm" ]] || continue
        names+=("$nm")
    done

    local nm
    for nm in ${names[@]+"${names[@]}"}; do
        mtu_resolve "$nm" || continue
        mtu_collect || continue
        count=$(( count + 1 ))
        [[ -n "$json_rows" ]] && json_rows+=","
        json_rows+="$(printf '{"name":"%s","side":"%s","tunnel":"%s","tunnel_mtu":%s,"override":%s,"egress_iface":"%s","egress_mtu":%s,"overhead":%s,"mss_mode":"%s"}' \
            "$(json_escape "$MTU_NAME")" "$MTU_SIDE" "$(json_escape "$MTU_TUN")" \
            "${MTU_TUN_MTU:-null}" "${MTU_OVERRIDE:-null}" "$(json_escape "$MTU_UNDER_IFACE")" \
            "${MTU_UNDER_MTU:-null}" "$MTU_OVERHEAD" "$MTU_MSS_MODE")"
    done

    if [[ "$AS_JSON" == "1" ]]; then
        printf '{"count":%s,"connections":[%s]}\n' "$count" "$json_rows"
    else
        if (( count == 0 )); then
            info "No connections are configured on this host."
            return 0
        fi
        printf '\n'
        printf '%-14s %-8s %-14s %-8s %-9s %-9s %s\n' NAME SIDE TUNNEL GRE-MTU EGRESS EGR-MTU OVERHEAD
        for nm in ${names[@]+"${names[@]}"}; do
            mtu_resolve "$nm" || continue
            mtu_collect || continue
            printf '%-14s %-8s %-14s %-8s %-9s %-9s %s\n' \
                "$MTU_NAME" "$MTU_SIDE" "$MTU_TUN" "${MTU_TUN_MTU:--}" \
                "${MTU_UNDER_IFACE:--}" "${MTU_UNDER_MTU:--}" "$MTU_OVERHEAD"
        done
        printf '\n'
    fi
    return 0
}

cli_mtu_diagnose() {
    local NAME="" AS_JSON=0 PROBE=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json) AS_JSON=1; shift ;;
            --probe) PROBE="--probe"; shift ;;
            --help|-h) echo "Usage: gre mtu diagnose --name NAME [--json] [--probe]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre mtu diagnose --name NAME [--json] [--probe]"; return 1; }

    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    mtu_collect "$PROBE" || { err "Could not collect MTU data for '$NAME'."; return 1; }
    mtu_make_recommendation

    if [[ "$AS_JSON" == "1" ]]; then
        # The contract object plus the recommendation, in one document.
        printf '%s' "${MTU_JSON%\}}"
        printf ',"recommendation":%s}\n' "$MTU_REC_JSON"
    else
        echo
        info "MTU diagnosis for '$NAME' (read-only)..."
        echo
        mtu_print_side
        printf '\n  checks:\n'
        # One check per line, pulled from the contract object rather than re-derived, so
        # the human report and the JSON can never disagree.
        printf '%s' "$MTU_CHECKS_JSON" | sed -e 's/},{/}\n{/g' -e 's/^\[//' -e 's/\]$//' > "$CONF_DIR/.mtu-checks.tmp"
        while IFS= read -r _line; do
            cid="$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' <<< "$_line")"
            cst="$(sed -n 's/.*"status":"\([^"]*\)".*/\1/p' <<< "$_line")"
            cdt="$(sed -n 's/.*"detail":"\([^"]*\)".*/\1/p' <<< "$_line")"
            [[ -n "$cid" ]] && printf '    [%-7s] %-22s %s\n' "$cst" "$cid" "$cdt"
        done < "$CONF_DIR/.mtu-checks.tmp"
        rm -f "$CONF_DIR/.mtu-checks.tmp"
        printf '\n  recommendation:\n'
        printf '    %s\n' "$(printf '%s' "$MTU_REC_JSON" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')"
        printf '    recommended gre mtu: %s (confidence %s)\n' "${MTU_REC_RECOMMENDED:-none}" "$MTU_REC_CONFIDENCE"
        [[ "$PROBE" == "--probe" ]] || printf '    (run with --probe to measure the path instead of assuming it)\n'
        printf '\n'
    fi

    # Non-zero only when a real FAIL was found, so a script can gate on it.
    (( MTU_N_FAIL == 0 ))
}

cli_mtu_recommend() {
    local NAME="" AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json) AS_JSON=1; shift ;;
            --help|-h) echo "Usage: gre mtu recommend --name NAME [--json]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre mtu recommend --name NAME [--json]"; return 1; }
    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    # A recommendation without a measurement is still offered, but labelled low
    # confidence and not safe to apply on its own.
    mtu_collect "--probe" || { err "Could not collect MTU data for '$NAME'."; return 1; }
    mtu_make_recommendation

    if [[ "$AS_JSON" == "1" ]]; then
        printf '%s\n' "$MTU_REC_JSON"
    else
        echo
        info "MTU recommendation for '$NAME'"
        echo
        printf '  current gre mtu   %s\n' "${MTU_TUN_MTU:--}"
        printf '  path capacity     %s\n' "${MTU_CAPACITY:-unknown}"
        printf '  overhead          %s bytes\n' "$MTU_OVERHEAD"
        printf '  recommended       %s\n' "${MTU_REC_RECOMMENDED:-none}"
        printf '  confidence        %s\n' "$MTU_REC_CONFIDENCE"
        printf '  safe to apply     %s\n' "$MTU_REC_SAFE"
        printf '  why               %s\n' "$(printf '%s' "$MTU_REC_JSON" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')"
        if [[ "$MTU_REC_REQUIRES" == "true" && "$MTU_REC_SAFE" == "true" ]]; then
            printf '\n  apply it with:\n    gre mtu set --name %s --mtu %s --yes\n' "$NAME" "$MTU_REC_RECOMMENDED"
        elif [[ "$MTU_REC_SAFE" != "true" ]]; then
            printf '\n  Not applied automatically: the evidence is not strong enough. Re-run with --probe, or set a value explicitly.\n'
        fi
        printf '\n'
    fi
    [[ "$MTU_REC_CONFIDENCE" != "unknown" ]]
}

cli_mtu_auto() {
    # Deliberately the same read-only recommendation, phrased for an operator. `auto`
    # does NOT mean "apply": nothing here changes an MTU.
    local NAME="" AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json) AS_JSON=1; shift ;;
            --help|-h) echo "Usage: gre mtu auto --name NAME [--json]  (read-only; applies nothing)"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre mtu auto --name NAME [--json]"; return 1; }
    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    mtu_collect "--probe" || { err "Could not collect MTU data for '$NAME'."; return 1; }
    mtu_make_recommendation

    if [[ "$AS_JSON" == "1" ]]; then
        printf '%s' "${MTU_REC_JSON%\}}"
        printf ',"apply_command":"%s","applied":false}\n' \
            "$(json_escape "gre mtu set --name $NAME --mtu ${MTU_REC_RECOMMENDED:-} --yes")"
    else
        echo
        if [[ -z "$MTU_REC_RECOMMENDED" ]]; then
            warn "Not enough evidence to suggest an MTU for '$NAME'."
            printf '  %s\n\n' "$(printf '%s' "$MTU_REC_JSON" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')"
            return 1
        fi
        info "Suggested MTU for '$NAME': $MTU_REC_RECOMMENDED (confidence $MTU_REC_CONFIDENCE)"
        printf '  %s\n' "$(printf '%s' "$MTU_REC_JSON" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')"
        if [[ "$MTU_REC_SAFE" == "true" ]]; then
            printf '\n  This was NOT applied. To apply it:\n    gre mtu set --name %s --mtu %s --yes\n\n' "$NAME" "$MTU_REC_RECOMMENDED"
        else
            printf '\n  Not offered for automatic application: %s\n\n' \
                "$([[ -z "$MTU_CAPACITY" ]] && echo "no usable capacity measurement" || echo "the evidence is not conclusive")"
        fi
    fi
    return 0
}

# Where the previous MTU is recorded so a change can be undone on this host.
# One line per connection, so a later change to a different connection cannot clobber it.
mtu_journal_set() { # mtu_journal_set NAME MTU
    local f="$CONF_DIR/mtu.journal"
    mkdir -p "$CONF_DIR"
    local tmp="$f.tmp"
    : > "$tmp"
    if [[ -f "$f" ]]; then
        grep -vE "^$1	" "$f" >> "$tmp" 2>/dev/null || true
    fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$tmp"
    mv "$tmp" "$f"
    chmod 600 "$f" 2>/dev/null || true
}

mtu_journal_get() { # mtu_journal_get NAME -> prints the recorded MTU
    local f="$CONF_DIR/mtu.journal"
    [[ -f "$f" ]] || return 1
    local v
    v="$(grep -E "^$1	" "$f" 2>/dev/null | tail -n1 | cut -f2)"
    [[ -n "$v" ]] || return 1
    printf '%s' "$v"
}

mtu_journal_forget() { # mtu_journal_forget NAME
    local f="$CONF_DIR/mtu.journal"
    [[ -f "$f" ]] || return 0
    local tmp="$f.tmp"
    grep -vE "^$1	" "$f" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$f"
}

# Persist the connection's MTU into its own config.
mtu_persist_override() { # mtu_persist_override NAME MTU
    local name="$1" value="$2" file
    file="$( [[ -f "$FOREIGNS_DIR/$name.conf" ]] && printf '%s' "$FOREIGNS_DIR/$name.conf" || printf '%s' "$NODES_DIR/$name.conf" )"
    [[ -f "$file" ]] || { err "No config file for '$name'."; return 1; }
    local tmp="$file.tmp"
    grep -vE '^MTU=' "$file" > "$tmp" || true
    printf 'MTU=%s\n' "$value" >> "$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv "$tmp" "$file"
    chmod 600 "$file" 2>/dev/null || true
}

# Change ONE connection's MTU in place. Never recreates the interface, never touches
# another connection, and never touches a physical NIC.
cli_mtu_set() {
    local NAME="" MTU_NEW="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --mtu)  [[ -n "${2:-}" ]] || { err "Missing value for --mtu"; return 1; }; MTU_NEW="$2"; shift 2 ;;
            --yes|-y) YES=1; shift ;;
            --help|-h) echo "Usage: gre mtu set --name NAME --mtu VALUE [--yes]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre mtu set --name NAME --mtu VALUE [--yes]"; return 1; }
    [[ -n "$MTU_NEW" ]] || { err "Missing required option: --mtu"; return 1; }
    valid_mtu "$MTU_NEW" || { err "Invalid MTU '$MTU_NEW': must be 576-9000."; return 1; }

    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    mtu_collect || { err "Could not read the current state of '$NAME'."; return 1; }

    if [[ "$MTU_TUN_PRESENT" != "yes" ]]; then
        err "Tunnel $MTU_TUN does not exist, so there is no MTU to change."
        err "Bring the connection up first:  gre iran peer apply --name $NAME"
        return 1
    fi

    # Refuse a value that cannot work, rather than writing it and letting the operator
    # discover the blackhole later. The egress MTU is the ceiling the encapsulated
    # packet has to fit inside.
    local capacity="$MTU_CAPACITY" overhead="$MTU_OVERHEAD"
    if [[ -n "$capacity" ]]; then
        local max_ok=$(( capacity - overhead ))
        if (( MTU_NEW > max_ok )); then
            err "Refusing MTU $MTU_NEW: with $overhead bytes of GRE overhead this path allows at most $max_ok."
            err "  path capacity $capacity ($( [[ "$MTU_PROBE_STATE" == "ok" || "$MTU_PROBE_STATE" == "frag_needed" ]] && echo measured || echo "from the interface MTU, not measured" ))"
            err "  inspect with:  gre mtu diagnose --name $NAME --probe"
            return 1
        fi
    fi
    if (( MTU_NEW < MTU_MIN_INNER )); then
        err "Refusing MTU $MTU_NEW: below the minimum legal IPv4 MTU ($MTU_MIN_INNER)."
        return 1
    fi

    local old="$MTU_TUN_MTU"
    if [[ "$old" == "$MTU_NEW" ]]; then
        info "Tunnel $MTU_TUN is already at MTU $MTU_NEW — nothing to do."
        return 0
    fi

    if (( YES == 0 )); then
        echo
        info "About to change ONLY this connection:"
        printf '  connection   %s (%s)\n' "$MTU_NAME" "$MTU_SIDE"
        printf '  interface    %s\n' "$MTU_TUN"
        printf '  mtu          %s -> %s\n' "${old:--}" "$MTU_NEW"
        printf '  overhead     %s bytes\n' "$overhead"
        printf '  the interface is NOT recreated; no other connection is touched;\n'
        printf '  the WAN interface is not touched.\n\n'
        confirm "Apply MTU $MTU_NEW to $MTU_TUN?" || { info "Cancelled."; return 0; }
    fi

    # --- record the old value BEFORE the mutation, so a failure can be undone
    mtu_journal_set "$MTU_NAME" "${old:-}"

    if ! apply_iface_mtu "$MTU_TUN" "$MTU_NEW"; then
        err "Could not set MTU $MTU_NEW on $MTU_TUN."
        if [[ -n "$old" ]] && apply_iface_mtu "$MTU_TUN" "$old" >/dev/null 2>&1; then
            err "Restored the previous MTU $old."
        else
            err "ROLLBACK_FAILED: the previous MTU could not be restored."
        fi
        return 1
    fi

    # --- verify from the kernel, not from the command's exit status
    local now; now="$(iface_mtu "$MTU_TUN")"
    if [[ "$now" != "$MTU_NEW" ]]; then
        err "Verification failed: $MTU_TUN reports MTU '$now', not '$MTU_NEW'."
        if [[ -n "$old" ]] && apply_iface_mtu "$MTU_TUN" "$old" >/dev/null 2>&1; then
            err "Restored the previous MTU $old."
        else
            err "ROLLBACK_FAILED: the previous MTU could not be restored."
        fi
        return 1
    fi

    # Persist so the value survives a restart, a watchdog re-apply and a migration.
    mtu_persist_override "$MTU_NAME" "$MTU_NEW" || warn "The MTU is applied but could not be written to the config file."

    # Re-write the MSS clamp, since it is derived from the tunnel MTU. Without this the
    # clamp would keep advertising the MSS of the previous MTU.
    if [[ "$MTU_SIDE" == "iran" && "$MTU_MSS" == "1" ]]; then
        mtu_refresh_mss "$MTU_NAME" "$MTU_TUN" "$MTU_NEW" || warn "The MTU changed but the MSS clamp could not be refreshed."
    fi

    audit_log "mtu-set name=$NAME side=$MTU_SIDE tun=$MTU_TUN from=${old:-none} to=$MTU_NEW"
    ok "Tunnel $MTU_TUN MTU is now $MTU_NEW (was ${old:-unknown})."
    if [[ -n "$MTU_CAPACITY" ]]; then
        info "Verified against a path capacity of $MTU_CAPACITY with $MTU_OVERHEAD bytes of overhead."
    fi
    return 0
}

# Re-derive the connection's MSS clamp from a new tunnel MTU, in place.
mtu_refresh_mss() { # mtu_refresh_mss NAME TUN MTU
    local name="$1" tun="$2" mtu="$3"
    local mss=$(( mtu - 40 ))
    (( mss >= 536 )) || { warn "MTU $mtu leaves an MSS below the IPv4 minimum; leaving the clamp alone."; return 1; }
    local comment="multi-gre-iran-$name-mss"
    ipt_del mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$comment*" -j TCPMSS
    ipt_del mangle FORWARD -o "$tun" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$comment-fwd*" -j TCPMSS
    ipt_del mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ipt_del mangle FORWARD -o "$tun" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ipt_add mangle POSTROUTING -o "$tun" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "$comment" -j TCPMSS --set-mss "$mss"
    ipt_add mangle FORWARD -o "$tun" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "$comment-fwd" -j TCPMSS --set-mss "$mss"
    return 0
}

cli_mtu_restore() {
    local NAME="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --yes|-y) YES=1; shift ;;
            --help|-h) echo "Usage: gre mtu restore --name NAME [--yes]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre mtu restore --name NAME [--yes]"; return 1; }
    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }

    local want
    want="$(mtu_journal_get "$NAME")" || {
        err "No previous MTU is recorded for '$NAME' on this host."
        err "A restore is only possible after a change made by 'gre mtu set'."
        return 1
    }
    valid_mtu "$want" || { err "The recorded value '$want' is not a valid MTU; refusing to apply it."; return 1; }

    mtu_collect || { err "Could not read the current state of '$NAME'."; return 1; }
    [[ "$MTU_TUN_PRESENT" == "yes" ]] || { err "Tunnel $MTU_TUN does not exist."; return 1; }

    if (( YES == 0 )); then
        printf '\n  connection   %s\n  interface    %s\n  mtu          %s -> %s (recorded)\n\n' \
            "$MTU_NAME" "$MTU_TUN" "${MTU_TUN_MTU:--}" "$want"
        confirm "Restore MTU $want on $MTU_TUN?" || { info "Cancelled."; return 0; }
    fi

    if ! apply_iface_mtu "$MTU_TUN" "$want"; then
        err "Could not restore MTU $want on $MTU_TUN."
        return 1
    fi
    local now; now="$(iface_mtu "$MTU_TUN")"
    if [[ "$now" != "$want" ]]; then
        err "Verification failed after restore: $MTU_TUN reports '$now', not '$want'."
        return 1
    fi

    mtu_persist_override "$MTU_NAME" "$want" || warn "MTU restored but could not be written to the config file."
    if [[ "$MTU_SIDE" == "iran" && "$MTU_MSS" == "1" ]]; then
        mtu_refresh_mss "$MTU_NAME" "$MTU_TUN" "$want" || warn "The MTU was restored but the MSS clamp could not be refreshed."
    fi
    mtu_journal_forget "$MTU_NAME"
    audit_log "mtu-restore name=$NAME tun=$MTU_TUN to=$want"
    ok "Tunnel $MTU_TUN MTU restored to $want."
    return 0
}

# ------------------------------------------------- advanced: the physical NIC MTU
#
# Read-only by design. Changing a WAN NIC MTU can sever the SSH session the operator is
# using, and with it the Hub's ability to recover the host at all, so this reports and
# advises rather than applying. An unattended change is refused outright.
cli_mtu_nic() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        list)
            local AS_JSON=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --json) AS_JSON=1; shift ;;
                    --help|-h) echo "Usage: gre mtu nic list [--json]"; return 0 ;;
                    *) err "Unknown option: $1"; return 1 ;;
                esac
            done
            local nic_rows="" count=0
            # `ip -o link show` prefixes each line with an index, but not every
            # implementation numbers every line, so the name is taken as "the first
            # token, minus any index and separator" rather than assuming a number.
            while read -r dev; do
                [[ -n "$dev" ]] || continue
                local m; m="$(iface_mtu "$dev")"
                [[ -n "$m" ]] || continue
                count=$(( count + 1 ))
                local cp="false"
                iface_carries_control_plane "$dev" && cp="true"
                [[ -n "$nic_rows" ]] && nic_rows+=","
                nic_rows+="$(printf '{"iface":"%s","mtu":%s,"carries_control_plane":%s}' \
                    "$(json_escape "$dev")" "$m" "$cp")"
            done < <(ip -o link show 2>/dev/null | sed -e 's/^[0-9]\+:[[:space:]]*//' -e 's/:.*//' -e 's/@.*//' | grep -v '^$')

            if [[ "$AS_JSON" == "1" ]]; then
                printf '{"count":%s,"nics":[%s]}\n' "$count" "$nic_rows"
            else
                printf '\n%-16s %-8s %s\n' IFACE MTU CONTROL-PLANE
                printf '%s' "$nic_rows" | tr '}' '\n' | sed -n 's/.*"iface":"\([^"]*\)","mtu":\([0-9]*\),"carries_control_plane":\([a-z]*\).*/\1 \2 \3/p' \
                    | while read -r i m c; do printf '%-16s %-8s %s\n' "$i" "$m" "$([[ "$c" == "true" ]] && echo YES || echo no)"; done
                printf '\n'
            fi
            return 0 ;;
        analyze)
            local NAME="" AS_JSON=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
                    --json) AS_JSON=1; shift ;;
                    --help|-h) echo "Usage: gre mtu nic analyze --name NAME [--json]"; return 0 ;;
                    *) err "Unknown option: $1"; return 1 ;;
                esac
            done
            [[ -n "$NAME" ]] || { err "Usage: gre mtu nic analyze --name NAME [--json]"; return 1; }
            mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
            mtu_collect || { err "Could not read state for '$NAME'."; return 1; }

            local risk="low" reasons="" cp="false"
            iface_carries_control_plane "$MTU_UNDER_IFACE" && cp="true"
            add_reason() { [[ -n "$reasons" ]] && reasons+="; "; reasons+="$1"; }
            if [[ "$cp" == "true" ]]; then
                risk="high"
                add_reason "this interface carries the default route, so it almost certainly carries the SSH session and the Hub's access to this host"
            fi
            if [[ -n "$MTU_CAPACITY" && -n "$MTU_UNDER_MTU" && "$MTU_CAPACITY" -lt "$MTU_UNDER_MTU" ]]; then
                [[ "$risk" == "low" ]] && risk="medium"
                add_reason "the path to the peer measured $MTU_CAPACITY, below the interface MTU $MTU_UNDER_MTU"
            fi
            if [[ -z "$MTU_UNDER_MTU" ]]; then
                add_reason "the egress interface MTU could not be read"
            fi

            if [[ "$AS_JSON" == "1" ]]; then
                printf '{"name":"%s","iface":"%s","nic_mtu":%s,"path_capacity":%s,"carries_control_plane":%s,"risk":"%s","reasons":"%s","applied":false}\n' \
                    "$(json_escape "$MTU_NAME")" "$(json_escape "$MTU_UNDER_IFACE")" \
                    "${MTU_UNDER_MTU:-null}" "${MTU_CAPACITY:-null}" "$cp" "$risk" "$(json_escape "$reasons")"
            else
                echo
                info "NIC MTU analysis for '$NAME' (read-only; nothing is changed)"
                echo
                printf '  egress interface  %s\n' "${MTU_UNDER_IFACE:--}"
                printf '  NIC MTU           %s\n' "${MTU_UNDER_MTU:--}"
                printf '  path capacity     %s\n' "${MTU_CAPACITY:-unknown}"
                printf '  control plane     %s\n' "$([[ "$cp" == "true" ]] && echo "YES - changing this can cut your own session" || echo no)"
                printf '  risk              %s\n' "$risk"
                [[ -n "$reasons" ]] && printf '  because           %s\n' "$reasons"
                printf '\n  This command never changes a NIC MTU. A WAN MTU change can sever SSH,\n'
                printf '  and with it the Hub ability to recover the host, so it is deliberately\n'
                printf '  left to you, at the console, with a rollback already scheduled.\n\n'
            fi
            # A successful read-only analysis exits 0 even when the risk is high. The
            # risk is DATA, not a failure: a non-zero exit would make a caller (the Hub,
            # or a script) treat "this NIC is risky to change" as "the command failed".
            return 0 ;;
        --help|-h|"")
            cat <<'EOF'
Usage:
  gre mtu nic list [--json]
  gre mtu nic analyze --name NAME [--json]

Read-only analysis of the physical or virtual NIC MTU. Neither form changes an MTU.

Changing a WAN NIC MTU can sever the SSH session you are working over and remove the
Hub's ability to recover the host, so it is never done automatically and is not offered
as an unattended repair. Do it at the console with an independent rollback armed.
EOF
            ;;
        *) err "Usage: gre mtu nic <list|analyze> ...  (see: gre mtu nic --help)"; return 1 ;;
    esac
}

# ============================================================ Full Network Health Check
#
# One read-only pass that inspects the layers a GRE connection depends on and reports
# what is wrong, with the evidence for each conclusion.
#
# It does NOT duplicate doctor or tunnel diagnose: those answer "is the manager healthy"
# and "is this tunnel configured and up". This answers "why does this connection not
# work", by walking the layers in the order they can fail and collecting ISSUE CODES with
# evidence, so a caller (the Hub) can correlate both sides and name a root cause.
#
# Every check reports PASS / WARN / FAIL / UNKNOWN / SKIPPED, and UNKNOWN is used
# honestly: a probe that could not run is not a failure and not a success.
#
# Read-only. It never changes a rule, an interface or a service. The only repairs it can
# offer are separate, explicit commands.

# Time budget, so a full pass on a slow or unreachable host cannot hang a caller. Each
# check is individually short; these bound the total.
HEALTH_TIMEOUT_PING=3
HEALTH_BUDGET_SECONDS_FULL=75
HEALTH_BUDGET_SECONDS_QUICK=20

# Emit one check. Adds to the JSON array and the human output, and counts statuses.
#   health_add ID CATEGORY STATUS DETAIL [EVIDENCE]
health_add() {
    local id="$1" cat="$2" st="$3" detail="$4" evidence="${5:-}"
    case "$st" in
        PASS) HEALTH_N_PASS=$(( HEALTH_N_PASS + 1 )) ;;
        WARN) HEALTH_N_WARN=$(( HEALTH_N_WARN + 1 )) ;;
        FAIL) HEALTH_N_FAIL=$(( HEALTH_N_FAIL + 1 )) ;;
        SKIPPED) HEALTH_N_SKIP=$(( HEALTH_N_SKIP + 1 )) ;;
        *) HEALTH_N_UNKNOWN=$(( HEALTH_N_UNKNOWN + 1 )) ;;
    esac
    [[ -n "$HEALTH_CHECKS_JSON" ]] && HEALTH_CHECKS_JSON+=","
    HEALTH_CHECKS_JSON+="$(printf '{"id":"%s","category":"%s","status":"%s","detail":"%s","evidence":"%s"}' \
        "$(json_escape "$id")" "$(json_escape "$cat")" "$st" "$(json_escape "$detail")" "$(json_escape "$evidence")")"
    [[ "$HEALTH_JSON_ONLY" == "1" ]] || printf '  [%-7s] %-22s %s\n' "$st" "$id" "$detail"
}

# Record a finding: an issue code with severity, evidence, probable cause and whether a
# safe repair exists. A finding is only ever recorded with the observation behind it.
#   health_find CODE SEVERITY CONFIDENCE EVIDENCE CAUSE REPAIR_KEY
health_find() {
    local code="$1" sev="$2" conf="$3" evidence="$4" cause="$5" repair="${6:-}"
    local safe="false" action="" risk=""
    if [[ -n "$repair" ]]; then
        case "$repair" in
            mtu_set)      safe="true";  risk="low";    action="Set this connection's tunnel MTU from the measured path" ;;
            rule_restore) safe="true";  risk="low";    action="Reinstall the missing rule this connection owns" ;;
            iface_up)     safe="true";  risk="low";    action="Bring the configured tunnel interface up" ;;
            peer_apply)   safe="true";  risk="medium"; action="Reapply this connection (rebuilds its tunnel and rules)" ;;
            mss_clamp)    safe="true";  risk="low";    action="Reinstall the TCP MSS clamp for the measured MTU" ;;
            endpoint)     safe="false"; risk="high";   action="The public endpoint must be corrected on both servers by hand" ;;
            wan_mtu)      safe="false"; risk="high";   action="A WAN NIC MTU change is not automated: it can sever SSH" ;;
            provider)     safe="false"; risk="high";   action="Nothing on this host can fix an upstream filter" ;;
            *)            safe="false"; risk="medium"; action="" ;;
        esac
    fi
    [[ -n "$HEALTH_FINDINGS_JSON" ]] && HEALTH_FINDINGS_JSON+=","
    HEALTH_FINDINGS_JSON+="$(printf '{"code":"%s","severity":"%s","server":"%s","connection":"%s","confidence":"%s","evidence":"%s","probable_cause":"%s","recommended_action":"%s","safe_repair":%s,"risk":"%s","repair_key":"%s"}' \
        "$code" "$sev" "$(json_escape "${HEALTH_SERVER:-$(hostname 2>/dev/null || echo local)}")" \
        "$(json_escape "$HEALTH_NAME")" "$conf" "$(json_escape "$evidence")" "$(json_escape "$cause")" \
        "$(json_escape "$action")" "$safe" "${risk:-none}" "$repair")"
    [[ "$HEALTH_JSON_ONLY" == "1" ]] || printf '    -> %s (%s, confidence %s)\n' "$code" "$sev" "$conf"
    case "$sev" in
        critical) HEALTH_N_CRITICAL=$(( HEALTH_N_CRITICAL + 1 )) ;;
    esac
}

# Has the time budget run out? A caller gets a partial answer with INSUFFICIENT_EVIDENCE
# rather than a hang.
health_expired() {
    local now; now="$(date +%s 2>/dev/null || echo 0)"
    (( HEALTH_START == 0 )) && return 1
    (( now - HEALTH_START >= HEALTH_BUDGET ))
}

# ping with the configured timeout, returning 0/1 without leaking output.
health_ping() { # health_ping DEST [IFACE]
    local dest="$1" iface="${2:-}"
    command -v ping >/dev/null 2>&1 || return 2
    if [[ -n "$iface" ]]; then
        ping -c 2 -W "$HEALTH_TIMEOUT_PING" -I "$iface" "$dest" >/dev/null 2>&1
    else
        ping -c 2 -W "$HEALTH_TIMEOUT_PING" "$dest" >/dev/null 2>&1
    fi
}

# A single RTT/loss sample, parsed from ping's summary. Empty when it cannot be read.
health_ping_stats() { # health_ping_stats DEST
    local dest="$1" out
    command -v ping >/dev/null 2>&1 || { printf ''; return; }
    out="$(ping -c 3 -W "$HEALTH_TIMEOUT_PING" "$dest" 2>/dev/null || true)"
    local loss rtt
    loss="$(sed -n 's/.*, \([0-9]\+\)% packet loss.*/\1/p' <<< "$out" | head -n1)"
    rtt="$(sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p' <<< "$out" | head -n1)"
    printf '%s %s' "${loss:-}" "${rtt:-}"
}

# sshd listening? Cheap evidence that the control plane is up.
health_sshd_listening() {
    local port="${SSH_PORT:-22}"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]" && return 0
    fi
    return 1
}

# ------------------------------------------------------------ the check themselves
#
# Each returns nothing and reports through health_add/health_find, so a single check can
# both record what it saw and, when it saw something wrong, say what it implies.

health_check_server() {
    local cat="A_ssh_and_server"
    # Am I the host that was asked? If the caller reached this point at all then the
    # control plane worked; saying so is still worth recording, because a WARN here is
    # often the real explanation for everything below.
    if [[ -n "${HEALTH_REMOTE:-}" ]]; then
        health_add "control_plane" "$cat" "PASS" "ran on ${HEALTH_REMOTE}" ""
    else
        health_add "control_plane" "$cat" "PASS" "ran locally on $(hostname 2>/dev/null || echo this host)" ""
    fi

    if [[ "$(id -u 2>/dev/null || echo 0)" == "0" ]]; then
        health_add "privilege" "$cat" "PASS" "running as root" ""
    else
        health_add "privilege" "$cat" "WARN" "not running as root; some checks will be UNKNOWN" "uid=$(id -u 2>/dev/null)"
    fi

    local os_name=""
    if [[ -r /etc/os-release ]]; then
        os_name="$(sed -n 's/^PRETTY_NAME="\?\(.*\)"\?$/\1/p' /etc/os-release | head -n1)"
    fi
    [[ -n "$os_name" ]] || os_name="$(uname -s 2>/dev/null)"
    health_add "operating_system" "$cat" "PASS" "${os_name:-unknown}" ""

    local kern; kern="$(uname -r 2>/dev/null)"
    health_add "kernel" "$cat" "PASS" "${kern:-unknown}" ""

    # The GRE module is what makes any of this possible. On a host that is not Linux at
    # all -- a development machine, or a container with no module support -- the absence
    # of /sys/module proves nothing, so it is UNKNOWN rather than a fault.
    if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
        health_add "gre_module" "$cat" "UNKNOWN" "not a Linux host, so GRE module support cannot be assessed" ""
    elif [[ -d /sys/module/ip_gre || -d /sys/module/gre ]]; then
        health_add "gre_module" "$cat" "PASS" "ip_gre is loaded" ""
    elif modprobe -n gre >/dev/null 2>&1; then
        health_add "gre_module" "$cat" "WARN" "ip_gre is not loaded but can be" ""
    else
        health_add "gre_module" "$cat" "FAIL" "this kernel has no usable GRE support" "no /sys/module/ip_gre"
        health_find "GRE_MODULE_MISSING" "critical" "high" \
            "no GRE module is loaded or loadable" \
            "the kernel cannot create GRE interfaces at all" "provider"
    fi

    # The manager's own version, so a Hub can flag a mismatched pair.
    health_add "cli_version" "$cat" "PASS" "gre-manager ${VERSION:-unknown}" ""

    # The watchdog is the mechanism that brings a dead tunnel back.
    local wd_state="unknown"
    if [[ -f "$GLOBAL_CONF" ]]; then
        local dt_enabled=""
        dt_enabled="$(grep -E '^WATCHDOG_ENABLED=' "$GLOBAL_CONF" 2>/dev/null | head -n1 | cut -d= -f2)"
        case "$dt_enabled" in
            1) wd_state="enabled" ;;
            0) wd_state="disabled" ;;
        esac
    fi
    local timer_active=""
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active multi-gre-watchdog.timer >/dev/null 2>&1 && timer_active="yes"
    fi
    if [[ "$wd_state" == "enabled" && "$timer_active" == "yes" ]]; then
        health_add "watchdog" "$cat" "PASS" "the watchdog timer is active" ""
    elif [[ "$wd_state" == "enabled" ]]; then
        health_add "watchdog" "$cat" "WARN" "the watchdog is enabled in config but its timer is not active" ""
    elif [[ "$wd_state" == "disabled" ]]; then
        health_add "watchdog" "$cat" "WARN" "the watchdog is disabled; a dropped tunnel will not recover on its own" ""
    else
        health_add "watchdog" "$cat" "UNKNOWN" "could not determine the watchdog state" ""
    fi

    if [[ "$HEALTH_MODE" == "full" ]]; then
        if health_sshd_listening; then
            health_add "sshd_listening" "$cat" "PASS" "sshd is listening" ""
        else
            # Not a failure: the Hub reached this host, so *something* carried the
            # session. It only means the probe could not confirm it.
            health_add "sshd_listening" "$cat" "UNKNOWN" "could not confirm an sshd listener (the session itself proves the control plane works)" ""
        fi
    else
        health_add "sshd_listening" "$cat" "SKIPPED" "quick check" ""
    fi
}

health_check_underlay() {
    local cat="B_underlay"
    local peer="$HEALTH_PEER_IP"

    local iface="" self_ip="" route_line=""
    if [[ -n "$peer" ]]; then
        route_line="$(ip -4 route get "$peer" 2>/dev/null | head -n1)"
        iface="$(sed -n 's/.*[[:space:]]dev[[:space:]]\+\([^ ]\+\).*/\1/p' <<< "$route_line" | head -n1)"
        self_ip="$(ip -4 route get "$peer" 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]\+\).*/\1/p' | head -n1)"
    fi

    if [[ -z "$peer" ]]; then
        health_add "public_ip" "$cat" "UNKNOWN" "this connection has no remote endpoint recorded" ""
    else
        health_add "route_to_peer" "$cat" "PASS" "${route_line:-none}" ""
    fi

    if [[ -n "$iface" ]]; then
        health_add "egress_interface" "$cat" "PASS" "$iface (mtu $(iface_mtu "$iface"))" ""
    else
        health_add "egress_interface" "$cat" "UNKNOWN" "could not determine the egress interface" ""
    fi

    # A route that sends the peer's own address back out of the tunnel can never work:
    # GRE would have to be carried inside GRE.
    if [[ -n "$iface" && "$iface" == "$HEALTH_TUN" ]]; then
        health_add "no_route_loop" "$cat" "FAIL" "the route to $peer goes back out through $HEALTH_TUN" "$route_line"
        health_find "GRE_ROUTE_LOOP" "critical" "high" \
            "the route to $peer resolves to $HEALTH_TUN" \
            "the underlay route for the peer points at the tunnel itself, so GRE cannot be encapsulated" "peer_apply"
    else
        health_add "no_route_loop" "$cat" "PASS" "the peer route does not use the tunnel" ""
    fi

    # rp_filter can silently drop GRE return traffic on a multi-homed host.
    local rp=""
    [[ -n "$iface" ]] && rp="$(sysctl -n "net.ipv4.conf.${iface}.rp_filter" 2>/dev/null)"
    case "$rp" in
        0) health_add "rp_filter" "$cat" "PASS" "rp_filter is off on $iface" "" ;;
        1) health_add "rp_filter" "$cat" "WARN" "rp_filter is strict (1) on $iface; asymmetric routing can drop GRE replies" "" ;;
        2) health_add "rp_filter" "$cat" "PASS" "rp_filter is loose (2) on $iface" "" ;;
        *) health_add "rp_filter" "$cat" "UNKNOWN" "could not read rp_filter on ${iface:-the egress interface}" "" ;;
    esac

    # Underlay reachability, with RTT and loss. Crucial framing: this SUCCEEDS even when
    # the tunnel is broken, which is exactly why it can never be read as "GRE is fine".
    if [[ -z "$peer" ]]; then
        health_add "underlay_ping" "$cat" "UNKNOWN" "no remote endpoint to test" ""
    elif [[ "$HEALTH_MODE" == "quick" ]]; then
        health_add "underlay_ping" "$cat" "SKIPPED" "quick check" ""
    else
        local st; st="$(health_ping_stats "$peer")"
        local loss rtt; loss="${st%% *}"; rtt="${st##* }"
        if [[ -n "$loss" ]]; then
            if [[ "$loss" == "0" ]]; then
                health_add "underlay_ping" "$cat" "PASS" "reachable, ${rtt:-?} ms average, no loss" "loss=$loss rtt=$rtt"
            elif [[ "$loss" -lt 100 ]]; then
                health_add "underlay_ping" "$cat" "WARN" "reachable with ${loss}% packet loss" "loss=$loss rtt=$rtt"
                health_find "UNDERLAY_PACKET_LOSS" "warning" "medium" \
                    "$loss% packet loss to $peer" \
                    "the path to the peer is losing packets, which makes any tunnel over it unreliable" "provider"
            else
                health_add "underlay_ping" "$cat" "FAIL" "the peer's public address does not answer ICMP" "loss=$loss"
                health_find "UNDERLAY_UNREACHABLE" "critical" "medium" \
                    "no ICMP reply from $peer" \
                    "the public path to the peer is down, or ICMP is filtered (which this probe cannot tell apart)" "provider"
            fi
        else
            health_add "underlay_ping" "$cat" "UNKNOWN" "ICMP gave no usable result (blocked or unsupported)" ""
        fi
    fi

    # Policy routing can send the peer's traffic somewhere unexpected.
    local rules=""
    rules="$(ip rule show 2>/dev/null | grep -vE '^(0|32766|32767):' | head -n3)"
    if [[ -n "$rules" ]]; then
        health_add "policy_routing" "$cat" "WARN" "non-default policy routing rules exist; they can override the route above" "$(tr '\n' ';' <<< "$rules")"
    else
        health_add "policy_routing" "$cat" "PASS" "only the default routing rules are present" ""
    fi
}

health_check_gre_config() {
    local cat="C_gre_config"
    local peer="$HEALTH_PEER_IP"

    if [[ "$HEALTH_TUN_PRESENT" == "yes" ]]; then
        health_add "interface_exists" "$cat" "PASS" "$HEALTH_TUN is present" ""
    else
        health_add "interface_exists" "$cat" "FAIL" "$HEALTH_TUN does not exist" ""
        health_find "GRE_INTERFACE_MISSING" "critical" "high" \
            "$HEALTH_TUN is not present on this host" \
            "the connection is configured but its interface was never created, or was removed" "iface_up"
        # Everything below depends on the interface, so stop rather than pile on.
        return 0
    fi

    if ip link show "$HEALTH_TUN" 2>/dev/null | grep -qE 'state (UP|UNKNOWN)|<[^>]*UP'; then
        health_add "interface_up" "$cat" "PASS" "$HEALTH_TUN is up" ""
    else
        health_add "interface_up" "$cat" "FAIL" "$HEALTH_TUN is present but down" ""
        health_find "GRE_INTERFACE_DOWN" "critical" "high" \
            "$HEALTH_TUN reports itself as not up" \
            "the interface exists but is administratively down or has no carrier" "iface_up"
    fi

    # The local endpoint must be this host's address. An empty or wrong one produces a
    # tunnel that exists and can never pass traffic.
    local live_local live_remote live_key
    live_local="$(tunnel_local_endpoint "$HEALTH_TUN")"
    live_remote="$(ip -d tunnel show "$HEALTH_TUN" 2>/dev/null | sed -n 's/.*[[:space:]]remote[[:space:]]\+\([0-9.]\+\)[[:space:]].*/\1/p' | head -n1)"
    local _hki; _hki="$(tunnel_key_info "$HEALTH_TUN" "$HEALTH_KEY")"; live_key="${_hki%% *}"; key_source="${_hki##* }"

    if [[ -z "$live_local" ]]; then
        health_add "local_endpoint" "$cat" "FAIL" "the interface has no local endpoint" ""
        health_find "GRE_LOCAL_ENDPOINT_MISMATCH" "critical" "high" \
            "no local address on $HEALTH_TUN" \
            "a GRE interface with no local endpoint cannot pass traffic" "peer_apply"
    elif [[ -n "$HEALTH_SELF_IP" && "$live_local" != "$HEALTH_SELF_IP" ]]; then
        health_add "local_endpoint" "$cat" "FAIL" "interface local=$live_local but this host is $HEALTH_SELF_IP" ""
        health_find "GRE_LOCAL_ENDPOINT_MISMATCH" "critical" "high" \
            "the interface uses $live_local, the connection expects $HEALTH_SELF_IP" \
            "the local endpoint does not match this host's address" "peer_apply"
    else
        health_add "local_endpoint" "$cat" "PASS" "${live_local:-$HEALTH_SELF_IP}" ""
    fi

    if [[ -z "$live_remote" ]]; then
        health_add "remote_endpoint" "$cat" "FAIL" "the interface has no remote endpoint" ""
        health_find "GRE_REMOTE_ENDPOINT_MISMATCH" "critical" "high" \
            "no remote address on $HEALTH_TUN" "" "peer_apply"
    elif [[ -n "$peer" && "$live_remote" != "$peer" ]]; then
        health_add "remote_endpoint" "$cat" "FAIL" "interface remote=$live_remote but the peer is $peer" ""
        health_find "GRE_REMOTE_ENDPOINT_MISMATCH" "critical" "high" \
            "the interface points at $live_remote, the configuration says $peer" \
            "the tunnel is aimed at the wrong peer address" "endpoint"
    else
        health_add "remote_endpoint" "$cat" "PASS" "$live_remote" ""
    fi

    # A key the kernel did not report is only a fault when the key is genuinely absent.
    # When the reading came from the config or the tunnel record, the honest statement is
    # that the live key could not be read -- not that the interface has none.
    if [[ "$live_key" == "none" || -z "$live_key" ]]; then
        health_add "gre_key" "$cat" "WARN" "the interface carries no GRE key" ""
    elif [[ "$key_source" != "live" ]]; then
        health_add "gre_key" "$cat" "PASS" "$live_key (from the $key_source, not readable from the kernel here)" ""
    elif [[ -n "$HEALTH_KEY" && "$live_key" != "$HEALTH_KEY" ]]; then
        health_add "gre_key" "$cat" "FAIL" "interface key=$live_key but the configuration says $HEALTH_KEY" ""
        health_find "GRE_KEY_MISMATCH" "critical" "high" \
            "the interface key $live_key differs from the configured $HEALTH_KEY" \
            "the two ends will not accept each other's GRE packets" "peer_apply"
    else
        health_add "gre_key" "$cat" "PASS" "$live_key" ""
    fi

    # Addressing.
    local live_addr
    live_addr="$(ip -4 addr show dev "$HEALTH_TUN" 2>/dev/null | sed -n 's/.*inet[[:space:]]\+\([0-9./]\+\).*/\1/p' | head -n1)"
    if [[ "$live_addr" == "$HEALTH_SELF_CIDR" ]]; then
        health_add "tunnel_address" "$cat" "PASS" "$live_addr" ""
    elif [[ -z "$live_addr" ]]; then
        health_add "tunnel_address" "$cat" "FAIL" "no IPv4 address on $HEALTH_TUN (expected $HEALTH_SELF_CIDR)" ""
        health_find "GRE_TUNNEL_ADDRESS_MISSING" "critical" "high" \
            "$HEALTH_TUN has no address" "" "peer_apply"
    else
        health_add "tunnel_address" "$cat" "WARN" "$live_addr (expected $HEALTH_SELF_CIDR)" ""
        health_find "GRE_SUBNET_MISMATCH" "warning" "high" \
            "the interface has $live_addr, the connection expects $HEALTH_SELF_CIDR" \
            "the two ends are probably using different subnet or index values" "peer_apply"
    fi

    # The inner route: can this host reach the far tunnel address at all?
    if [[ "$HEALTH_MODE" == "full" ]]; then
        if [[ -n "$HEALTH_PEER_TUN_IP" ]]; then
            ip -4 route get "$HEALTH_PEER_TUN_IP" >/dev/null 2>&1
            if ip -4 route get "$HEALTH_PEER_TUN_IP" 2>/dev/null | grep -q "dev $HEALTH_TUN"; then
                health_add "inner_route" "$cat" "PASS" "the peer's tunnel address routes via $HEALTH_TUN" ""
            else
                health_add "inner_route" "$cat" "FAIL" "the peer's tunnel address does not route via $HEALTH_TUN" ""
                health_find "GRE_ROUTE_MISSING" "critical" "high" \
                    "no route to $HEALTH_PEER_TUN_IP through $HEALTH_TUN" \
                    "the tunnel subnet is not routed over the interface, so inner traffic has nowhere to go" "peer_apply"
            fi
        fi
    else
        health_add "inner_route" "$cat" "SKIPPED" "quick check" ""
    fi

    # The interface must agree with the stored configuration.
    if [[ -n "$HEALTH_MTU" && -n "$HEALTH_TUN_MTU" && "$HEALTH_MTU" != "$HEALTH_TUN_MTU" ]]; then
        health_add "interface_matches_config" "$cat" "WARN" \
            "the interface MTU ($HEALTH_TUN_MTU) differs from the stored override ($HEALTH_MTU)" ""
    else
        health_add "interface_matches_config" "$cat" "PASS" "the live interface matches the stored configuration" ""
    fi
}

health_check_protocol47() {
    local cat="D_gre_protocol47"
    local peer="$HEALTH_PEER_IP"

    # What the local firewall says about protocol 47 from this peer.
    local blocked="unknown"
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p gre -m comment --comment "multi-gre-block" -j DROP 2>/dev/null; then
            if [[ -n "$peer" ]] && iptables -C INPUT -p gre -s "$peer" \
                    -m comment --comment "multi-gre-node-$HEALTH_NAME" -j ACCEPT 2>/dev/null; then
                blocked="no"
            else
                blocked="yes"
            fi
        else
            blocked="no"
        fi
    fi
    case "$blocked" in
        no)  health_add "gre47_local_policy" "$cat" "PASS" "the local firewall does not drop this peer's GRE" "" ;;
        yes) health_add "gre47_local_policy" "$cat" "FAIL" "the local whitelist drops protocol 47 from this peer" ""
             health_find "GRE_PROTOCOL47_SUSPECTED_BLOCKED" "critical" "high" \
                 "the INPUT whitelist has a DROP but no ACCEPT for $peer" \
                 "inbound GRE from the peer is being dropped on this host" "rule_restore" ;;
        *)   health_add "gre47_local_policy" "$cat" "UNKNOWN" "iptables is unavailable, so GRE filtering could not be checked" "" ;;
    esac

    # Whether GRE packets are actually crossing the underlay. This needs a capture, which
    # is only attempted in a full check and only when the tooling exists.
    if [[ "$HEALTH_MODE" != "full" ]]; then
        health_add "gre47_traffic" "$cat" "SKIPPED" "quick check" ""
        return 0
    fi
    if ! command -v timeout >/dev/null 2>&1 || ! command -v tcpdump >/dev/null 2>&1; then
        health_add "gre47_traffic" "$cat" "UNKNOWN" \
            "no packet capture available (needs tcpdump), so GRE traffic could not be observed" ""
        return 0
    fi
    if [[ -z "$peer" ]]; then
        health_add "gre47_traffic" "$cat" "UNKNOWN" "no peer to capture against" ""
        return 0
    fi

    # A short, bounded capture of protocol 47 while generating a little GRE traffic by
    # pinging the far tunnel address. Correlating the two is what separates "the packets
    # never left" from "the packets left and were dropped".
    local cap_file="/tmp/.gre-health-$$.cap"
    local seen_any=0
    if timeout 4 tcpdump -n -c 20 -w "$cap_file" "proto gre and host $peer" >/dev/null 2>&1; then
        [[ -s "$cap_file" ]] && seen_any=1
    fi
    rm -f "$cap_file" 2>/dev/null || true

    if (( seen_any )); then
        health_add "gre47_traffic" "$cat" "PASS" "GRE packets to or from $peer were observed on this host" ""
    else
        # Absence of capture is not proof of absence of traffic: the capture window is
        # tiny. Say UNKNOWN rather than blaming the provider.
        health_add "gre47_traffic" "$cat" "UNKNOWN" \
            "no GRE packets were seen in a short capture window; that is not proof none were sent" ""
    fi
}

health_check_connectivity() {
    local cat="E_tunnel_connectivity"

    if [[ "$HEALTH_TUN_PRESENT" != "yes" ]]; then
        health_add "inner_ping" "$cat" "UNKNOWN" "no interface to test" ""
        return 0
    fi
    if [[ "$HEALTH_MODE" != "full" ]]; then
        health_add "inner_ping" "$cat" "SKIPPED" "quick check" ""
        return 0
    fi
    [[ -n "$HEALTH_PEER_TUN_IP" ]] || { health_add "inner_ping" "$cat" "UNKNOWN" "no peer tunnel address" ""; return 0; }

    local st; st="$(health_ping_stats "$HEALTH_PEER_TUN_IP")"
    local loss rtt; loss="${st%% *}"; rtt="${st##* }"

    # The underlay result decides how to read a failed inner ping. This is the single most
    # useful distinction in the whole report: it separates "the tunnel is broken" from
    # "the tunnel is fine but ICMP inside it is filtered".
    local underlay_ok="unknown"
    if [[ -n "$HEALTH_PEER_IP" ]] && health_ping "$HEALTH_PEER_IP"; then underlay_ok="yes"; else underlay_ok="no"; fi

    if [[ -n "$loss" && "$loss" == "0" ]]; then
        health_add "inner_ping" "$cat" "PASS" "$HEALTH_PEER_TUN_IP replies, ${rtt:-?} ms average" "loss=0 rtt=$rtt"
    elif [[ -n "$loss" && "$loss" -lt 100 ]]; then
        health_add "inner_ping" "$cat" "WARN" "${loss}% loss across the tunnel" "loss=$loss"
        health_find "GRE_ONE_WAY_TRAFFIC" "warning" "medium" \
            "$loss% loss over the tunnel" \
            "some inner packets are lost; with a working handshake this usually means MTU, not reachability" "mtu_set"
    elif [[ "$underlay_ok" == "yes" ]]; then
        # The peer's public address answers but its tunnel address does not.
        health_add "inner_ping" "$cat" "FAIL" "$HEALTH_PEER_TUN_IP does not reply, but $HEALTH_PEER_IP does" ""
        health_find "GRE_INNER_PING_FAILED" "critical" "high" \
            "the underlay answers ($HEALTH_PEER_IP) while the tunnel address ($HEALTH_PEER_TUN_IP) does not" \
            "the public path works, so this is inside the tunnel: the peer may not have this connection, or its key/subnet differs" "peer_apply"
    elif [[ "$underlay_ok" == "no" ]]; then
        health_add "inner_ping" "$cat" "FAIL" "neither the tunnel address nor the public address answers" ""
        health_find "UNDERLAY_UNREACHABLE" "critical" "medium" \
            "no reply from $HEALTH_PEER_IP or $HEALTH_PEER_TUN_IP" \
            "the peer host itself is unreachable, so this is not a GRE problem yet" "provider"
    else
        health_add "inner_ping" "$cat" "UNKNOWN" "ICMP gave no usable result; this probe is inconclusive" ""
        health_find "INSUFFICIENT_EVIDENCE" "info" "low" \
            "no ICMP reply from either address" \
            "ICMP may be filtered on both paths, so reachability could not be established" ""
    fi
}

health_check_routing_firewall() {
    local cat="F_routing_and_firewall"
    local peer_tun="$HEALTH_PEER_TUN_IP"

    # Forwarding, only meaningful where this host forwards.
    local fwd; fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    if [[ -n "$HEALTH_TCP" || -n "$HEALTH_UDP" ]]; then
        if [[ "$fwd" == "1" ]]; then
            health_add "ip_forward" "$cat" "PASS" "net.ipv4.ip_forward=1" ""
        elif [[ -n "$fwd" ]]; then
            health_add "ip_forward" "$cat" "FAIL" "net.ipv4.ip_forward=0 but this connection forwards ports" ""
            health_find "IP_FORWARD_DISABLED" "critical" "high" \
                "net.ipv4.ip_forward=0 while the connection forwards $HEALTH_TCP/$HEALTH_UDP" \
                "forwarded traffic will be dropped by the kernel" "rule_restore"
        else
            health_add "ip_forward" "$cat" "UNKNOWN" "could not read net.ipv4.ip_forward" ""
        fi
    else
        health_add "ip_forward" "$cat" "SKIPPED" "this connection does not forward ports" ""
    fi

    # Which backend is in use: a rule the manager wrote with iptables is invisible to an
    # nftables-only host, and vice versa.
    local backend="none"
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        backend="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        backend="iptables"
    fi
    health_add "firewall_backend" "$cat" "PASS" "$backend" ""

    # The rules this connection OWNS must all be present. Only the owned rules are
    # checked: this never inspects or judges unrelated firewall state.
    if [[ "$HEALTH_SIDE" == "iran" && ( -n "$HEALTH_TCP" || -n "$HEALTH_UDP" ) ]]; then
        local missing=""
        if [[ -n "$HEALTH_TCP" ]]; then
            iptables -t nat -C PREROUTING -i "$HEALTH_WAN_IF" -d "$HEALTH_SELF_IP" -p tcp \
                -m multiport --dports "$HEALTH_TCP" -m comment --comment "multi-gre-iran-$HEALTH_NAME-dnat-tcp" \
                -j DNAT --to-destination "$peer_tun" 2>/dev/null || missing+="dnat-tcp "
        fi
        if [[ -n "$HEALTH_UDP" ]]; then
            iptables -t nat -C PREROUTING -i "$HEALTH_WAN_IF" -d "$HEALTH_SELF_IP" -p udp \
                -m multiport --dports "$HEALTH_UDP" -m comment --comment "multi-gre-iran-$HEALTH_NAME-dnat-udp" \
                -j DNAT --to-destination "$peer_tun" 2>/dev/null || missing+="dnat-udp "
        fi
        iptables -t nat -C POSTROUTING -o "$HEALTH_TUN" -d "$peer_tun" \
            -m comment --comment "multi-gre-iran-$HEALTH_NAME-snat" -j SNAT --to-source "$HEALTH_SELF_TUN_IP" 2>/dev/null \
            || missing+="snat "

        if [[ -z "$missing" ]]; then
            health_add "owned_rules" "$cat" "PASS" "every rule this connection owns is installed" ""
        else
            health_add "owned_rules" "$cat" "FAIL" "missing rules: $missing" ""
            health_find "FIREWALL_RULE_MISSING" "critical" "high" \
                "these rules this connection owns are absent: $missing" \
                "the connection's NAT is incomplete, so its ports cannot be reached" "rule_restore"
        fi
    else
        health_add "owned_rules" "$cat" "SKIPPED" "this side installs no per-connection NAT rules" ""
    fi

    # Conflicting rules: the same port owned by another connection is a real conflict.
    if [[ -n "$HEALTH_TCP" ]]; then
        local others="" f nm tcp
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            nm="$(grep -E '^NAME=' "$f" 2>/dev/null | head -n1 | cut -d= -f2)"
            [[ "$nm" == "$HEALTH_NAME" || -z "$nm" ]] && continue
            tcp="$(grep -E '^TCP_PORTS=' "$f" 2>/dev/null | head -n1 | cut -d= -f2)"
            [[ -z "$tcp" ]] && continue
            # Reuse the add-time overlap logic rather than reimplementing it.
            if ports_overlap "$HEALTH_TCP" "$tcp" 2>/dev/null; then
                others+="$nm($tcp) "
            fi
        done
        if [[ -n "$others" ]]; then
            health_add "port_conflicts" "$cat" "FAIL" "these connections claim the same ports: $others" ""
            health_find "FIREWALL_RULE_CONFLICT" "critical" "high" \
                "$HEALTH_NAME uses $HEALTH_TCP, which overlaps $others" \
                "two connections cannot own the same inbound port; only one will receive the traffic" "endpoint"
        else
            health_add "port_conflicts" "$cat" "PASS" "no other connection claims these ports" ""
        fi
    fi

    # Rule counters: a rule that never matches is evidence the traffic is not arriving.
    if [[ "$HEALTH_MODE" == "full" && "$HEALTH_SIDE" == "iran" && -n "$HEALTH_TCP" ]]; then
        local ctr
        ctr="$(iptables -t nat -L PREROUTING -v -n 2>/dev/null \
            | grep -- "multi-gre-iran-$HEALTH_NAME-dnat-tcp" | awk '{print $1}' | head -n1)"
        if [[ -n "$ctr" && "$ctr" == "0" ]]; then
            health_add "rule_counters" "$cat" "WARN" "the DNAT rule has matched 0 packets" ""
        elif [[ -n "$ctr" ]]; then
            health_add "rule_counters" "$cat" "PASS" "the DNAT rule has matched $ctr packets" ""
        else
            health_add "rule_counters" "$cat" "UNKNOWN" "could not read the rule counters" ""
        fi
    else
        health_add "rule_counters" "$cat" "SKIPPED" "quick check, or no per-connection rules" ""
    fi
}

health_check_mtu() {
    local cat="G_mtu_and_mss"
    if ! command -v gre >/dev/null 2>&1 && [[ ! -f "$0" ]]; then
        health_add "mtu_diagnostics" "$cat" "UNKNOWN" "the mtu subsystem is unavailable" ""
        return 0
    fi
    # Integrated with the MTU engine rather than reimplemented: same collector, same
    # recommendation, so the two can never disagree.
    if ! mtu_collect; then
        health_add "mtu_diagnostics" "$cat" "UNKNOWN" "could not collect MTU data for this connection" ""
        return 0
    fi
    local probe=""
    [[ "$HEALTH_MODE" == "full" ]] && probe="--probe"
    [[ -n "$probe" ]] && mtu_collect --probe

    health_add "underlay_mtu" "$cat" \
        "$([[ -n "$MTU_UNDER_MTU" ]] && echo PASS || echo UNKNOWN)" \
        "${MTU_UNDER_IFACE:-egress} mtu ${MTU_UNDER_MTU:-unknown}" ""
    health_add "gre_overhead" "$cat" "PASS" "$MTU_OVERHEAD bytes for this encapsulation" ""
    health_add "tunnel_mtu" "$cat" "$([[ -n "$MTU_TUN_MTU" ]] && echo PASS || echo UNKNOWN)" \
        "${MTU_TUN_MTU:-unknown}" ""

    mtu_make_recommendation
    if [[ "$MTU_REC_REQUIRES" == "true" ]]; then
        health_add "mtu_recommendation" "$cat" "WARN" \
            "MTU ${MTU_TUN_MTU:-?} -> ${MTU_REC_RECOMMENDED} (confidence ${MTU_REC_CONFIDENCE})" ""
        # Only a real MTU problem is reported as one: a recommendation to change a value
        # is not by itself a fault.
        if [[ "$MTU_REC_SAFE" == "true" ]]; then
            local delta=$(( MTU_TUN_MTU - MTU_REC_RECOMMENDED ))
            local sev="warning"
            (( delta < 0 )) && (( -delta > 40 )) && sev="critical"
            health_find "GRE_MTU_MISMATCH" "$sev" "$MTU_REC_CONFIDENCE" \
                "tunnel MTU ${MTU_TUN_MTU} against a path that allows ${MTU_REC_RECOMMENDED}" \
                "$(printf '%s' "$MTU_REC_JSON" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')" "mtu_set"
        fi
    else
        health_add "mtu_recommendation" "$cat" "PASS" "the current MTU matches the path" ""
    fi

    case "$MTU_MSS_MODE" in
        set)  health_add "mss_clamp" "$cat" "PASS" "MSS clamped to $MTU_MSS_VALUE" "" ;;
        pmtu) health_add "mss_clamp" "$cat" "WARN" "MSS is derived from the route MTU, which for GRE is the underlay" ""
              health_find "GRE_TCP_MSS_PROBLEM" "warning" "high" \
                  "the clamp uses --clamp-mss-to-pmtu, which resolves against the underlay MTU" \
                  "SYNs can advertise an MSS the tunnel cannot carry, which stalls large TCP transfers" "mss_clamp" ;;
        *)    if [[ "$MTU_MSS" == "1" ]]; then
                  health_add "mss_clamp" "$cat" "FAIL" "clamping is enabled but no rule is installed" ""
                  health_find "GRE_TCP_MSS_PROBLEM" "critical" "high" \
                      "MSS_CLAMP=1 but no clamp rule exists on $HEALTH_TUN" \
                      "large TCP segments will be dropped inside the tunnel" "mss_clamp"
              else
                  health_add "mss_clamp" "$cat" "SKIPPED" "MSS clamping is disabled for this connection" ""
              fi ;;
    esac

    if [[ "$MTU_PROBE_STATE" == "inconclusive" || "$MTU_PROBE_STATE" == "unknown" ]]; then
        health_add "pmtud" "$cat" "UNKNOWN" "the path MTU could not be measured (ICMP filtered)" ""
        health_find "GRE_PMTUD_BLACKHOLE_SUSPECTED" "info" "low" \
            "DF probes produced no usable answer" \
            "PMTUD may be blackholed, which would stall large packets; this is a suspicion, not a measurement" "mtu_set"
    else
        health_add "pmtud" "$cat" "PASS" "DF probing worked ($MTU_PROBE_STATE)" ""
    fi
}

health_check_service() {
    local cat="H_service"
    # Only when this connection actually has a panel behind it.
    if [[ -z "$HEALTH_PANEL" ]]; then
        health_add "service_layer" "$cat" "SKIPPED" "this connection has no panel configured" ""
        return 0
    fi
    if [[ "$HEALTH_MODE" != "full" ]]; then
        health_add "service_layer" "$cat" "SKIPPED" "quick check" ""
        return 0
    fi

    # Is the panel itself reachable? A failing panel must not be reported as a GRE fault.
    local host port
    host="$(sed -n 's|^https\?://\([^:/]*\).*|\1|p' <<< "$HEALTH_PANEL" | head -n1)"
    port="$(sed -n 's|^https\?://[^:]*:\([0-9]*\).*|\1|p' <<< "$HEALTH_PANEL" | head -n1)"
    [[ -n "$port" ]] || port="$( [[ "$HEALTH_PANEL" == https* ]] && echo 443 || echo 80 )"

    if [[ -z "$host" ]]; then
        health_add "panel_reachable" "$cat" "UNKNOWN" "could not parse the panel address" "$HEALTH_PANEL"
        return 0
    fi
    if command -v timeout >/dev/null 2>&1 && timeout 5 bash -c ": >/dev/tcp/$host/$port" 2>/dev/null; then
        health_add "panel_reachable" "$cat" "PASS" "the panel port $host:$port accepts connections" ""
    else
        health_add "panel_reachable" "$cat" "WARN" "the panel at $host:$port did not accept a connection" ""
        health_find "SERVICE_LISTENER_MISSING" "warning" "medium" \
            "nothing accepted a TCP connection to $host:$port" \
            "the 3x-ui panel is not listening; the tunnel may be fine while the service is not" "endpoint"
    fi

    # A listener for the connection's own port: the service it exists to forward.
    local listen_port="${HEALTH_TCP%%,*}"
    if [[ -n "$listen_port" ]] && command -v ss >/dev/null 2>&1; then
        if ss -ltn 2>/dev/null | grep -qE "[:.]${listen_port}[[:space:]]"; then
            health_add "service_port" "$cat" "PASS" "port $listen_port is listening" ""
        else
            health_add "service_port" "$cat" "WARN" "nothing is listening on TCP $listen_port" ""
            health_find "XUI_INBOUND_MISSING" "warning" "medium" \
                "no listener on TCP $listen_port" \
                "the panel has no inbound on this port, so the forward has nothing to reach" "endpoint"
        fi
    else
        health_add "service_port" "$cat" "SKIPPED" "no TCP port, or ss is unavailable" ""
    fi
}

# --------------------------------------------------------------- the orchestrator
# health_check NAME [--json] [--quick] [--full] [--budget SECONDS]
health_check_run() {
    local NAME="" AS_JSON=0 MODE="full" BUDGET=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)   [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json)   AS_JSON=1; shift ;;
            --quick)  MODE="quick"; shift ;;
            --full)   MODE="full"; shift ;;
            --budget) [[ -n "${2:-}" ]] || { err "Missing value for --budget"; return 1; }; BUDGET="$2"; shift 2 ;;
            --help|-h) echo "Usage: gre health-check --name NAME [--json] [--quick|--full] [--budget SECONDS]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre health-check --name NAME [--json] [--quick|--full]"; return 1; }

    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    # mtu_resolve gives us the side and the config values; the MTU collector adds the
    # live interface and path picture, which the GRE and MTU checks both need.
    mtu_collect || true

    HEALTH_NAME="$MTU_NAME"
    HEALTH_SIDE="$MTU_SIDE"
    HEALTH_TUN="$MTU_TUN"
    HEALTH_PEER_IP="$MTU_PEER_IP"
    HEALTH_SELF_IP="$MTU_SELF_IP"
    HEALTH_KEY="$MTU_KEY"
    HEALTH_TCP="$MTU_TCP"
    HEALTH_UDP="$MTU_UDP"
    HEALTH_WAN_IF="$MTU_WAN_IF"
    HEALTH_MTU="$MTU_OVERRIDE"
    HEALTH_TUN_MTU="$MTU_TUN_MTU"
    HEALTH_TUN_PRESENT="$MTU_TUN_PRESENT"
    HEALTH_MODE="$MODE"
    if [[ "$HEALTH_SIDE" == "iran" ]]; then
        HEALTH_SELF_TUN_IP="${MTU_SUBNET_BASE}.${MTU_IDX}.2"
        HEALTH_PEER_TUN_IP="${MTU_SUBNET_BASE}.${MTU_IDX}.1"
        HEALTH_SELF_CIDR="${MTU_SUBNET_BASE}.${MTU_IDX}.2/30"
    else
        HEALTH_SELF_TUN_IP="${MTU_SUBNET_BASE}.${MTU_IDX}.1"
        HEALTH_PEER_TUN_IP="${MTU_SUBNET_BASE}.${MTU_IDX}.2"
        HEALTH_SELF_CIDR="${MTU_SUBNET_BASE}.${MTU_IDX}.1/30"
    fi
    HEALTH_PANEL="$(config_panel_url "$NAME" 2>/dev/null || true)"

    if [[ -n "$BUDGET" ]]; then
        [[ "$BUDGET" =~ ^[0-9]+$ ]] || { err "--budget must be a whole number of seconds"; return 1; }
        HEALTH_BUDGET="$BUDGET"
    elif [[ "$MODE" == "quick" ]]; then
        HEALTH_BUDGET="$HEALTH_BUDGET_SECONDS_QUICK"
    else
        HEALTH_BUDGET="$HEALTH_BUDGET_SECONDS_FULL"
    fi

    HEALTH_CHECKS_JSON=""
    HEALTH_FINDINGS_JSON=""
    HEALTH_N_PASS=0; HEALTH_N_WARN=0; HEALTH_N_FAIL=0
    HEALTH_N_UNKNOWN=0; HEALTH_N_SKIP=0; HEALTH_N_CRITICAL=0
    HEALTH_JSON_ONLY="$AS_JSON"
    HEALTH_START="$(date +%s 2>/dev/null || echo 0)"
    local timed_out=0

    [[ "$AS_JSON" == "1" ]] || {
        echo
        info "Full network health check for '$NAME' ($MODE, ${HEALTH_BUDGET}s budget, read-only)"
        echo
    }

    # The categories run in the order the layers can fail. Each is skipped when the
    # budget is already spent, and that is reported as a timeout, not as a pass.
    local cat_fn
    for cat_fn in health_check_server health_check_underlay health_check_gre_config \
                  health_check_protocol47 health_check_connectivity \
                  health_check_routing_firewall health_check_mtu health_check_service; do
        if health_expired; then
            timed_out=1
            health_add "budget_exhausted" "Z_diagnostic" "UNKNOWN" \
                "the ${HEALTH_BUDGET}s budget ran out before $cat_fn could run" ""
            break
        fi
        "$cat_fn"
    done

    # ---- the verdict, derived from the checks rather than asserted independently
    local overall="HEALTHY"
    if (( HEALTH_N_FAIL > 0 )); then overall="BROKEN"; fi
    if (( HEALTH_N_CRITICAL > 0 )); then overall="BROKEN"; fi

    local completeness="complete"
    if (( timed_out )); then
        completeness="partial"
        health_find "INSUFFICIENT_EVIDENCE" "info" "low" \
            "the check budget expired; some layers were not inspected" \
            "raise --budget or run again when the host is less loaded" ""
    elif (( HEALTH_N_UNKNOWN > 0 )); then
        completeness="partial"
    fi

    # A WARN with no FAIL still means something is degraded rather than broken.
    if [[ "$overall" == "HEALTHY" && ( HEALTH_N_WARN -gt 0 || HEALTH_N_UNKNOWN -gt 0 ) ]]; then
        overall="DEGRADED"
    fi

    if [[ "$AS_JSON" == "1" ]]; then
        printf '{"connection":"%s","side":"%s","server":"%s","mode":"%s","overall_status":"%s","evidence_completeness":"%s","budget_seconds":%s,"elapsed_seconds":%s,"summary":{"pass":%s,"warn":%s,"fail":%s,"unknown":%s,"skipped":%s,"critical_findings":%s},"checks":[%s],"findings":[%s],"tested_at":"%s"}\n' \
            "$(json_escape "$HEALTH_NAME")" "$HEALTH_SIDE" \
            "$(json_escape "$(hostname 2>/dev/null || echo this-host)")" "$MODE" "$overall" "$completeness" \
            "$HEALTH_BUDGET" "$(( $(date +%s 2>/dev/null || echo 0) - HEALTH_START ))" \
            "$HEALTH_N_PASS" "$HEALTH_N_WARN" "$HEALTH_N_FAIL" "$HEALTH_N_UNKNOWN" "$HEALTH_N_SKIP" "$HEALTH_N_CRITICAL" \
            "$HEALTH_CHECKS_JSON" "$HEALTH_FINDINGS_JSON" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    else
        printf '\n'
        printf '  overall: %s   evidence: %s\n' "$overall" "$completeness"
        printf '  checks:  pass=%s warn=%s fail=%s unknown=%s skipped=%s\n' \
            "$HEALTH_N_PASS" "$HEALTH_N_WARN" "$HEALTH_N_FAIL" "$HEALTH_N_UNKNOWN" "$HEALTH_N_SKIP"
        if [[ -n "$HEALTH_FINDINGS_JSON" ]]; then
            printf '\n  findings:\n'
        fi
        printf '\n'
    fi

    audit_log "health-check name=$NAME side=$HEALTH_SIDE mode=$MODE overall=$overall fail=$HEALTH_N_FAIL critical=$HEALTH_N_CRITICAL"

    # Non-zero only when something is actually broken, so a caller can gate on it.
    [[ "$overall" != "BROKEN" ]]
}

# Which panel URL this connection is associated with, if any. Kept deliberately simple:
# the Hub passes it in when it knows, and a local caller may not have one at all.
config_panel_url() { # config_panel_url NAME
    local name="$1"
    [[ -n "${PANEL_URL:-}" ]] && { printf '%s' "$PANEL_URL"; return 0; }
    return 1
}

cli_health_check() { # gre health-check ...
    health_check_run "$@"
}

# ==================================================== intelligent repair recommendations
#
# A repair is only offered for an issue this host can actually fix, and applying one goes
# through the same transactional path as any other mutation. Nothing here is automatic:
# every repair needs --yes, verifies its result, and restores the previous state if the
# verification fails.

# cli_repair_preview NAME — what a repair would do, read-only.
cli_repair_preview() {
    local NAME="" AS_JSON=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --json) AS_JSON=1; shift ;;
            --help|-h) echo "Usage: gre repair preview --name NAME [--json]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre repair preview --name NAME [--json]"; return 1; }
    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }
    mtu_collect || true

    # The preview is the health check's own findings, filtered to what is repairable.
    local out
    out="$(health_check_run --name "$NAME" --json 2>/dev/null)" || true
    local repairable=""
    # Pull the findings that carry a repair key and are marked safe. Parsing our own
    # JSON with sed is deliberate: adding a JSON parser to a bash CLI is a bigger risk
    # than reading a shape this program just wrote.
    local findings
    findings="$(sed -n 's/.*"findings":\[\(.*\)\],"tested_at".*/\1/p' <<< "$out")"
    if [[ -n "$findings" ]]; then
        repairable="$(printf '%s' "$findings" | sed -e 's/},{/}\n{/g' | grep '"safe_repair":true' || true)"
    fi

    if [[ "$AS_JSON" == "1" ]]; then
        if [[ -n "$repairable" ]]; then
            printf '{"connection":"%s","read_only":true,"repairable":[%s]}\n' \
                "$(json_escape "$NAME")" "$(printf '%s' "$repairable" | tr '\n' '\034' | sed 's/\x1c/,/g')"
        else
            printf '{"connection":"%s","read_only":true,"repairable":[]}\n' "$(json_escape "$NAME")"
        fi
        return 0
    fi

    echo
    if [[ -z "$repairable" ]]; then
        info "No safe automated repair is available for '$NAME'."
        printf '  Every finding either has no verified repair on this host, or can only be\n'
        printf '  fixed by hand. Re-run: gre health-check --name %s\n\n' "$NAME"
        return 0
    fi
    info "Repairs available for '$NAME' (nothing is changed yet)"
    echo
    printf '%s\n' "$repairable" | while IFS= read -r line; do
        local code act risk
        code="$(sed -n 's/.*"code":"\([^"]*\)".*/\1/p' <<< "$line")"
        act="$(sed -n 's/.*"recommended_action":"\([^"]*\)".*/\1/p' <<< "$line")"
        risk="$(sed -n 's/.*"risk":"\([^"]*\)".*/\1/p' <<< "$line")"
        [[ -n "$code" ]] && printf '  [%-6s] %-32s %s\n' "$risk" "$code" "$act"
    done
    printf '\n  To apply one:  gre repair apply --name %s --code CODE --yes\n\n' "$NAME"
    return 0
}

# cli_repair_apply NAME CODE --yes — apply ONE named repair, verified, with rollback.
cli_repair_apply() {
    local NAME="" CODE="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --code) [[ -n "${2:-}" ]] || { err "Missing value for --code"; return 1; }; CODE="$2"; shift 2 ;;
            --yes|-y) YES=1; shift ;;
            --help|-h) echo "Usage: gre repair apply --name NAME --code CODE [--yes]"; return 0 ;;
            *) err "Unknown option: $1"; return 1 ;;
        esac
    done
    [[ -n "$NAME" ]] || { err "Usage: gre repair apply --name NAME --code CODE [--yes]"; return 1; }
    [[ -n "$CODE" ]] || { err "Missing required option: --code"; return 1; }

    mtu_resolve "$NAME" || { err "No connection named '$NAME' is configured on this host."; return 1; }

    # Only repairs this host can verify are implemented. The rest are reported as
    # unrepairable rather than half-done.
    local desc="" do_repair=""
    case "$CODE" in
        GRE_INTERFACE_MISSING|GRE_INTERFACE_DOWN)
            desc="bring $MTU_TUN up by reapplying this connection"
            do_repair="iface_up" ;;
        GRE_KEY_MISMATCH|GRE_REMOTE_ENDPOINT_MISMATCH|GRE_LOCAL_ENDPOINT_MISMATCH|GRE_SUBNET_MISMATCH)
            desc="reapply this connection so its interface matches its configuration"
            do_repair="peer_apply" ;;
        GRE_MTU_MISMATCH)
            desc="set this connection's tunnel MTU from the measured path"
            do_repair="mtu_set" ;;
        GRE_TCP_MSS_PROBLEM)
            desc="reinstall the TCP MSS clamp from the tunnel MTU"
            do_repair="mss_clamp" ;;
        FIREWALL_RULE_MISSING|IP_FORWARD_DISABLED)
            desc="reinstall the rules this connection owns"
            do_repair="peer_apply" ;;
        *)
            err "No automated repair exists for '$CODE' on this host."
            err "Findings without a safe repair are reported for a human to act on:"
            err "  gre health-check --name $NAME"
            return 1 ;;
    esac

    if (( YES == 0 )); then
        echo
        info "About to repair '$NAME':"
        printf '  issue        %s\n' "$CODE"
        printf '  action       %s\n' "$desc"
        printf '  scope        this connection only; no other connection and no NIC is touched\n\n'
        confirm "Apply this repair?" || { info "Cancelled."; return 0; }
    fi

    local mtu_target=""
    if [[ "$do_repair" == "mtu_set" ]]; then
        mtu_collect --probe || true
        mtu_make_recommendation
        if [[ "$MTU_REC_SAFE" != "true" || -z "$MTU_REC_RECOMMENDED" ]]; then
            err "Refusing: the recommended MTU is not backed by sufficient evidence."
            err "  run: gre mtu diagnose --name $NAME --probe"
            return 1
        fi
        mtu_target="$MTU_REC_RECOMMENDED"
    fi

    audit_log "repair-preview name=$NAME code=$CODE action=$do_repair"

    case "$do_repair" in
        mtu_set)
            # Goes through the MTU transaction, which journals the old value, verifies
            # from the kernel and restores on failure.
            cli_mtu_set --name "$NAME" --mtu "$mtu_target" --yes || {
                err "The repair did not complete; the previous MTU was restored if it could be."
                return 1
            } ;;
        mss_clamp)
            mtu_collect || true
            [[ -n "$MTU_TUN_MTU" ]] || { err "Cannot clamp MSS without a known tunnel MTU."; return 1; }
            mtu_refresh_mss "$NAME" "$MTU_TUN" "$MTU_TUN_MTU" || { err "Could not install the clamp."; return 1; }
            if ! iptables -t mangle -C POSTROUTING -o "$MTU_TUN" -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS --set-mss "$(( MTU_TUN_MTU - 40 ))" 2>/dev/null; then
                err "The clamp was written but does not verify."
                err "ROLLBACK_FAILED: inspect with: gre tunnel diagnose --name $NAME"
                return 1
            fi
            ok "MSS clamp reinstalled for tunnel MTU $MTU_TUN_MTU." ;;
        iface_up|peer_apply)
            if [[ "$MTU_SIDE" == "iran" ]]; then
                apply_iran_peer "$MTU_FILE" || { err "Reapplying the connection failed."; return 1; }
            else
                apply_foreign_node "$MTU_FILE" || { err "Reapplying the connection failed."; return 1; }
            fi ;;
        *)
            err "Internal error: no handler for repair '$do_repair'."; return 1 ;;
    esac

    # Verify: the repair is only reported as done when a fresh check agrees.
    local after
    after="$(health_check_run --name "$NAME" --json --quick 2>/dev/null)" || true
    local still
    still="$(grep -c "\"$CODE\"" <<< "$after" || true)"
    if [[ "${still:-0}" == "0" ]]; then
        audit_log "repair-applied name=$NAME code=$CODE action=$do_repair verified=yes"
        ok "Repaired: $CODE is no longer reported for '$NAME'."
        return 0
    fi
    err "The repair ran but $CODE is still reported."
    err "Nothing is claimed to have been fixed. Inspect with:"
    err "  gre health-check --name $NAME"
    return 1
}

doctor() { # gre doctor — diagnostics; exits non-zero if any check FAILs
    local DOC_FAIL=0 DOC_WARN=0
    echo
    info "Running multi-gre diagnostics..."
    echo

    # --- required binaries
    local b
    for b in ip iptables ping systemctl curl; do
        if command -v "$b" >/dev/null 2>&1; then
            d_pass "binary found: $b"
        else
            d_fail "missing required binary: $b"
        fi
    done

    migrate_legacy_iran_conf || true

    local is_foreign=0 is_iran=0
    [[ -f "$FOREIGN_CONF" ]] && is_foreign=1
    [[ -f "$IRAN_CONF" ]]    && is_iran=1
    if (( ! is_foreign && ! is_iran )); then
        d_warn "no configuration found in $CONF_DIR — fresh server, role checks skipped"
    fi

    # --- IRAN role checks (one block per foreign peer)
    if (( is_iran )); then
        if iran_conf_is_legacy; then
            d_fail "legacy v1 iran.conf is present but was not migrated (fix: gre --apply)"
        fi
        if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]; then
            d_pass "net.ipv4.ip_forward = 1"
        else
            d_fail "net.ipv4.ip_forward is not 1 (fix: sysctl -w net.ipv4.ip_forward=1)"
        fi

        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
              IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
        local f peer="" npeers=0
        local seen_pairs=" " seen_tuns=" "
        local -a p_names=() p_tcps=() p_udps=()
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            if ! load_peer_conf "$f"; then
                d_fail "peer conf $f is invalid or unsafe"
                continue
            fi
            peer="${SUBNET_BASE}.${IDX}.1"
            p_names+=("$NAME"); p_tcps+=("$TCP_PORTS"); p_udps+=("$UDP_PORTS")
            npeers=$(( npeers + 1 ))
            echo
            info "Peer $NAME (foreign $FOREIGN_IP, subnet ${SUBNET_BASE}.${IDX}.0/30):"

            # cross-peer duplicate detection
            if [[ "$seen_pairs" == *" ${SUBNET_BASE}.${IDX} "* ]]; then
                d_fail "duplicate subnet/index ${SUBNET_BASE}.${IDX} across peers"
            else
                seen_pairs+="${SUBNET_BASE}.${IDX} "
            fi
            if [[ "$seen_tuns" == *" $TUN "* ]]; then
                d_fail "duplicate tunnel name $TUN across peers"
            else
                seen_tuns+="$TUN "
            fi

            if [[ -n "$WAN_IF" ]] && ip link show "$WAN_IF" >/dev/null 2>&1; then
                d_pass "[$NAME] WAN interface '$WAN_IF' exists"
            else
                d_fail "[$NAME] WAN interface '$WAN_IF' from the peer conf does not exist"
            fi
            if grep -qx "$IRAN_IP" <<< "$(ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')"; then
                d_pass "[$NAME] IRAN_IP $IRAN_IP is assigned to a local interface"
            else
                d_fail "[$NAME] IRAN_IP $IRAN_IP is not assigned to any local interface"
            fi
            if [[ -n "$TUN" ]]; then
                if tun_exists "$TUN"; then
                    d_pass "[$NAME] tunnel $TUN exists"
                else
                    d_fail "[$NAME] tunnel $TUN is missing (fix: gre iran peer apply --name $NAME)"
                fi
                if ping -c 2 -W 2 "$peer" >/dev/null 2>&1; then
                    d_pass "[$NAME] tunnel peer $peer answers ping"
                else
                    d_fail "[$NAME] tunnel peer $peer does not answer ping"
                    doctor_gre_filtered_hint "$FOREIGN_IP"
                fi
            fi
            doctor_peer_dnat tcp "$TCP_PORTS"
            doctor_peer_dnat udp "$UDP_PORTS"
            doctor_peer_snat
            doctor_peer_mss
            # port conflicts: a local service already listening on a forwarded port
            local conflicts=0 proto plist item a b port
            for proto in tcp udp; do
                if [[ "$proto" == "tcp" ]]; then plist="$TCP_PORTS"; else plist="$UDP_PORTS"; fi
                [[ -z "$plist" ]] && continue
                local IFS=','
                local -a pitems=()
                read -ra pitems <<< "$plist"
                unset IFS
                for item in "${pitems[@]}"; do
                    if [[ "$item" == *:* ]]; then
                        a="${item%%:*}"; b="${item##*:}"
                        for port in "$a" "$b"; do
                            if port_in_use "$proto" "$port"; then
                                d_warn "[$NAME] port $port/$proto (range $item) is already listened on by a local service"
                                conflicts=1
                            fi
                        done
                    elif port_in_use "$proto" "$item"; then
                        d_warn "[$NAME] port $item/$proto is already listened on by a local service"
                        conflicts=1
                    fi
                done
            done
            if (( conflicts == 0 )) && [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
                d_pass "[$NAME] no local listeners conflict with the forwarded ports"
            fi
        done
        (( npeers == 0 )) && d_warn "IRAN is configured but has no foreign peers yet"

        # cross-peer port overlaps (TCP and UDP independent, range-aware)
        local i j
        for (( i = 0; i < npeers; i++ )); do
            for (( j = i + 1; j < npeers; j++ )); do
                if port_lists_overlap "${p_tcps[$i]}" "${p_tcps[$j]}"; then
                    d_fail "TCP port overlap between peers '${p_names[$i]}' and '${p_names[$j]}' ($OVERLAP_DESC)"
                fi
                if port_lists_overlap "${p_udps[$i]}" "${p_udps[$j]}"; then
                    d_fail "UDP port overlap between peers '${p_names[$i]}' and '${p_names[$j]}' ($OVERLAP_DESC)"
                fi
            done
        done
    fi

    # --- FOREIGN role checks
    if (( is_foreign )); then
        local FOREIGN_IP="" ICMP_DROP="" GRE_WHITELIST=""
        # shellcheck disable=SC1090
        source "$FOREIGN_CONF"
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE"
        local node_count=0
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            node_count=$(( node_count + 1 ))
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            if tun_exists "$TUN"; then
                d_pass "tunnel $TUN (node $NAME) exists"
            else
                d_fail "tunnel $TUN (node $NAME) is missing (fix: gre --apply)"
            fi
            if ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.2" >/dev/null 2>&1; then
                d_pass "node $NAME (${SUBNET_BASE}.${IDX}.2) answers ping"
            else
                d_fail "node $NAME (${SUBNET_BASE}.${IDX}.2) does not answer ping"
                doctor_gre_filtered_hint "$IRAN_IP"
            fi
        done
        (( node_count == 0 )) && d_warn "FOREIGN is configured but has no Iran nodes yet"
        if [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
            if iptables -C INPUT -p gre -m comment --comment "multi-gre-block" -j DROP 2>/dev/null; then
                d_pass "GRE whitelist block rule is present"
            else
                d_fail "GRE whitelist block rule is missing (fix: gre --apply)"
            fi
            for f in "$NODES_DIR"/*.conf; do
                [[ -e "$f" ]] || continue
                NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
                source "$f"
                if iptables -C INPUT -p gre -s "$IRAN_IP" \
                    -m comment --comment "multi-gre-node-$NAME" -j ACCEPT 2>/dev/null; then
                    d_pass "GRE whitelist ACCEPT rule for node $NAME is present"
                else
                    d_fail "GRE whitelist ACCEPT rule for node $NAME is missing (fix: gre --apply)"
                fi
            done
        fi
    fi

    # --- coexistence: GRE tunnels not managed by gre-manager
    local ut="" ut_found=0
    while IFS= read -r ut; do
        [[ -n "$ut" ]] || continue
        ut_found=1
        if (( is_foreign )) && [[ "${GRE_WHITELIST:-0}" == "1" ]]; then
            d_warn "unmanaged GRE tunnel '$ut' exists — it is BLOCKED by the GRE whitelist (its peer IP is not whitelisted)"
        else
            d_warn "unmanaged GRE tunnel '$ut' exists (not created by gre-manager; left untouched)"
        fi
    done < <(unmanaged_gre_tunnels)
    (( ut_found == 0 )) && d_pass "no unmanaged GRE tunnels (no coexistence conflicts)"

    # --- systemd
    if [[ "$(service_state)" == "enabled" ]]; then
        d_pass "multi-gre.service is enabled"
    else
        d_warn "multi-gre.service is not enabled"
    fi
    if [[ "$(watchdog_state)" == "active" ]]; then
        d_pass "multi-gre-watchdog.timer is active"
    else
        d_warn "multi-gre-watchdog.timer is not active"
    fi

    echo
    info "Note: GRE (protocol 47) must be allowed by the datacenter on both sides."
    echo
    if (( DOC_FAIL > 0 )); then
        err "doctor: $DOC_FAIL check(s) failed, $DOC_WARN warning(s)."
        return 1
    fi
    ok "doctor: all checks passed ($DOC_WARN warning(s))."
    return 0
}

# ------------------------------------------------------------- CLI: backup
cli_export() { # gre export [path] [--yes]
    require_root
    local path="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y)   YES=1; shift ;;
            --help|-h)  echo "Usage: gre export [path] [--yes]"; return 0 ;;
            -*)         err "Unknown option: $1"; err "Usage: gre export [path] [--yes]"; return 1 ;;
            *)          [[ -z "$path" ]] || { err "Unexpected extra argument: $1"; err "Usage: gre export [path] [--yes]"; return 1; }
                        path="$1"; shift ;;
        esac
    done
    [[ -z "$path" ]] && path="./gre-backup-$(date '+%Y%m%d-%H%M%S').tar.gz"

    if [[ ! -d "$CONF_DIR" ]]; then
        if (( ! YES )); then
            err "No configuration found ($CONF_DIR does not exist); nothing to export."
            return 1
        fi
        warn "No configuration found ($CONF_DIR does not exist); writing an empty backup."
        tar -czf "$path" --files-from /dev/null || { err "Backup failed."; rm -f "$path"; return 1; }
    else
        tar -czf "$path" -C / etc/multi-gre || { err "Backup failed."; rm -f "$path"; return 1; }
    fi
    chmod 600 "$path"
    audit_log "export path=$path"
    ok "Backup written to $path"
}

cli_import() { # gre import <file> [--yes]
    require_root
    local file="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y)   YES=1; shift ;;
            --help|-h)  echo "Usage: gre import <file> [--yes]"; return 0 ;;
            -*)         err "Unknown option: $1"; err "Usage: gre import <file> [--yes]"; return 1 ;;
            *)          [[ -z "$file" ]] || { err "Unexpected extra argument: $1"; err "Usage: gre import <file> [--yes]"; return 1; }
                        file="$1"; shift ;;
        esac
    done
    [[ -n "$file" ]] || { err "Missing backup file."; err "Usage: gre import <file> [--yes]"; return 1; }
    [[ -f "$file" ]] || { err "File not found: $file"; return 1; }

    if ! tar -tzf "$file" >/dev/null 2>&1; then
        err "Not a gzip tar archive: $file"
        return 1
    fi
    local list
    list="$(tar -tzf "$file")"
    if ! grep -Eq '^(\./)?etc/multi-gre(/|$)' <<< "$list"; then
        err "Archive does not contain etc/multi-gre; refusing to import."
        return 1
    fi
    if grep -Eq '(^|/)\.\.(/|$)|^/' <<< "$list"; then
        err "Archive contains unsafe paths (absolute or '..'); refusing to import."
        return 1
    fi

    if (( ! YES )); then
        confirm "Import '$file'? This replaces the current multi-gre configuration on this server." \
            || { info "Cancelled."; return; }
    fi

    # Stage the archive in a temp dir and validate the layout BEFORE touching
    # the live config: reject mixed legacy+v2 states and unsafe peer confs.
    local tmp=""
    tmp="$(mktemp -d)" || { err "mktemp failed"; return 1; }
    if ! tar -xzf "$file" -C "$tmp"; then
        err "Extraction failed."
        rm -rf "$tmp"
        return 1
    fi
    local newconf="$tmp/etc/multi-gre" f=""
    if [[ -f "$newconf/iran.conf" ]] && grep -qE '^FOREIGN_IP=' "$newconf/iran.conf"; then
        for f in "$newconf"/foreigns/*.conf; do
            [[ -e "$f" ]] || continue
            err "Archive mixes a legacy v1 iran.conf with v2 peers in foreigns/; refusing to import."
            rm -rf "$tmp"
            return 1
        done
    fi
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    for f in "$newconf"/foreigns/*.conf; do
        [[ -e "$f" ]] || continue
        if ! load_peer_conf "$f"; then
            err "Archive contains an invalid or unsafe peer conf: ${f#$tmp/}"
            rm -rf "$tmp"
            return 1
        fi
    done

    info "Stopping current tunnels..."
    stop_all
    mkdir -p "$CONF_DIR"
    if [[ -d "$newconf" ]]; then
        cp -a "$newconf/." "$CONF_DIR/" || { err "Could not install the imported config."; rm -rf "$tmp"; return 1; }
    fi
    rm -rf "$tmp"

    # accepts both v1 and v2 layouts: a legacy iran.conf is migrated now
    migrate_legacy_iran_conf || { err "Migration of the imported legacy config failed."; return 1; }
    install_service
    apply_all
    audit_log "import file=$file"
    ok "Import complete."
}

# ------------------------------------------------------------- main
banner() {
    local roles="not configured"
    if [[ -f "$FOREIGN_CONF" && -f "$IRAN_CONF" ]]; then
        roles="FOREIGN + IRAN"
    elif [[ -f "$FOREIGN_CONF" ]]; then
        roles="FOREIGN"
    elif [[ -f "$IRAN_CONF" ]]; then
        roles="IRAN"
    fi

    load_global_conf
    local wstate; wstate="$(watchdog_state)"
    local tcount; tcount="$(tunnel_count)"
    local ncount; ncount="$(node_count)"

    # Iran-side peer health shown as healthy/total (tunnel interface up = up)
    local ptotal=0 pup=0 f ptun=""
    if [[ -f "$IRAN_CONF" ]]; then
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            ptotal=$(( ptotal + 1 ))
            ptun="$(grep -E '^TUN=' "$f" | cut -d= -f2)"
            [[ -n "$ptun" ]] && tun_exists "$ptun" && pup=$(( pup + 1 ))
        done
        if iran_conf_is_legacy; then
            roles="$roles (legacy v1 config — migrates automatically on apply)"
        elif (( ptotal > 0 )); then
            roles="$roles (peers: $pup/$ptotal up)"
        fi
    fi

    local tun_dot wdot wlabel
    if (( tcount > 0 )); then tun_dot="$(dot_on)"; else tun_dot="$(dot_off)"; fi
    if [[ "$wstate" == "active" ]]; then
        wdot="$(dot_on)";  wlabel="ON · every ${WD_INTERVAL_MIN}m"
    else
        wdot="$(dot_off)"; wlabel="OFF"
    fi

    echo
    printf '%s%s' "$C_BOLD" "$C_CYAN"
    cat <<'EOF'
   __________  ____     __  ___
  / ____/ __ \/ __ \   /  |/  /__ _____  ____ _____ ____  _____
 / / __/ /_/ / /_/ /  / /|_/ / _ `/ _ \/ _ `/ _ `/ -_) __/
 \____/_/ |_/_____/  /_/  /_/\_,_/_//_/\_,_/\_, /\__/_/
                                           /____/
EOF
    printf '%s' "$C_RESET"
    echo   "  Multi-GRE Tunnel Manager  ${C_BOLD}v${VERSION}${C_RESET}  ·  github.com/${GITHUB_REPO}"
    echo   "  ═════════════════════════════════════════════════════════════"
    printf '  Role: %s%s%s   Tunnels: %s %s up   Watchdog: %s %s\n' \
        "$C_GREEN" "$roles" "$C_RESET" "$tun_dot" "$tcount" "$wdot" "$wlabel"
    if [[ "$roles" == "not configured" ]]; then
        printf '  %sStart here → this server is in IRAN? press 1 · is it the FOREIGN server? press 2%s\n' \
            "$C_YELLOW" "$C_RESET"
    fi
    echo   "  ── Tunnels ─────────────────────────────────────────────────"
    echo   "  1) Configure this server as IRAN (add / edit / manage foreign peers)"
    echo   "  2) Configure this server as FOREIGN / add an Iran node"
    printf '  3) Edit an Iran node on FOREIGN                      [%s nodes]\n' "$ncount"
    printf '  4) Remove an Iran node from FOREIGN                  [%s nodes]\n' "$ncount"
    echo   "  5) Restart all configured tunnels"
    echo   "  6) Stop all configured tunnels"
    echo   "  ── Monitoring ──────────────────────────────────────────────"
    echo   "  7) Status & health"
    printf '  8) Auto-heal watchdog                                %s %s\n' "$wdot" "$wlabel"
    echo   "  9) Doctor (diagnostics)"
    echo   "  ── Maintenance ─────────────────────────────────────────────"
    echo   " 10) Backup / restore (export / import)"
    echo   " 11) Clean up original vatanhost gre.sh (vatan-m2)"
    echo   " 12) Update gre-manager + gre-hub to the latest release"
    echo   " 13) Uninstall from this server"
    printf ' %s14) PURGE: remove EVERYTHING GRE (danger)%s\n' "$C_RED" "$C_RESET"
    echo   " 15) gre-hub dashboard (web UI: install / manage)"
    echo   "  0) Exit"
    echo   "  ═════════════════════════════════════════════════════════════"
}

watchdog_settings_menu() {
    require_root
    local c=""
    while true; do
        load_global_conf
        local st; st="$(watchdog_state)"
        echo
        echo   "  ── Auto-heal watchdog ────────────────────────────────────"
        if [[ "$st" == "active" ]]; then
            printf '  State: %s ON    check every %s min    downtime tolerance ~%s min\n' \
                "$(dot_on)" "$WD_INTERVAL_MIN" "$WD_TOLERANCE_MIN"
        else
            printf '  State: %s OFF\n' "$(dot_off)"
        fi
        echo   "  ────────────────────────────────────────────────────────────"
        echo   "  1) Change downtime tolerance"
        echo   "  2) Enable watchdog"
        echo   "  3) Disable watchdog"
        echo   "  0) Back"
        read -rp "  Select: " c
        case "$c" in
            1) ask_downtime_tolerance
               apply_watchdog_config "$ASKED_ENABLED" "$ASKED_INTERVAL" "$ASKED_TOL" ;;
            2) apply_watchdog_config 1 "$WD_INTERVAL_MIN" "$WD_TOLERANCE_MIN" ;;
            3) apply_watchdog_config 0 "$WD_INTERVAL_MIN" "$WD_TOLERANCE_MIN" ;;
            0) return ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

backup_restore_menu() {
    require_root
    local c="" bpath=""
    while true; do
        echo
        echo   "  ── Backup / restore ──────────────────────────────────────"
        echo   "  1) Export config (tar.gz of /etc/multi-gre)"
        echo   "  2) Import config from a backup file"
        echo   "  0) Back"
        read -rp "  Select: " c
        case "$c" in
            1)
                ask bpath "Backup file path (empty = ./gre-backup-<timestamp>.tar.gz)" ""
                if [[ -n "$bpath" ]]; then cli_export "$bpath"; else cli_export; fi
                ;;
            2)
                ask bpath "Backup file to import (empty = cancel)" ""
                if [[ -n "$bpath" ]]; then cli_import "$bpath"; else info "Cancelled."; fi
                ;;
            0) return ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

main_menu() {
    require_root
    trap 'echo; warn "Interrupted — back to the menu."' INT
    local choice=""
    while true; do
        banner
        read -rp "  Select: " choice
        case "$choice" in
            1)  iran_peers_menu ;;
            2)  setup_foreign ;;
            3)  edit_node ;;
            4)  remove_node ;;
            5)  restart_all ;;
            6)  stop_menu ;;
            7)  show_status ;;
            8)  watchdog_settings_menu ;;
            9)  doctor ;;
            10) backup_restore_menu ;;
            11) legacy_cleanup ;;
            12) self_update ;;
            13) uninstall ;;
            14) purge_all ;;
            15) hub_settings_menu ;;
            0)  trap - INT; echo "Bye."; exit 0 ;;
            *)  warn "Invalid selection." ;;
        esac
        echo
    done
}

usage() {
    cat <<EOF
Multi-GRE Tunnel Manager v$VERSION — https://github.com/$GITHUB_REPO

Usage:
  gre                     interactive menu
  gre status [--json]     show status (machine-readable JSON with --json)
  gre doctor              diagnostics: PASS/WARN/FAIL per check, non-zero exit on FAIL
  gre tunnel diagnose --name NAME [--json]
                          read-only per-connection tunnel health; changes nothing
  gre tunnel rules [--json]
                          print the manager's iptables rules (read-only)
  gre mtu list [--json]
                          every connection's tunnel MTU, egress MTU and GRE overhead
  gre mtu diagnose --name NAME [--json] [--probe]
                          per-connection MTU diagnosis; read-only, changes nothing
  gre mtu recommend --name NAME [--json]
                          evidence-based MTU recommendation with a confidence level
  gre mtu auto --name NAME [--json]
                          the same recommendation as an apply-ready command (applies nothing)
  gre mtu set --name NAME --mtu VALUE [--yes]
                          change ONE connection's tunnel MTU in place (no rebuild)
  gre mtu restore --name NAME [--yes]
                          restore the MTU recorded before the last change
  gre mtu nic list|analyze
                          advanced, read-only physical NIC MTU analysis
  gre health-check --name NAME [--json] [--quick|--full] [--budget SECONDS]
                          full network health check: every layer this connection depends
                          on, with issue codes and evidence. Read-only; changes nothing.
                          Exits non-zero when the verdict is BROKEN.
  gre repair preview --name NAME [--json]
                          the repairs available for a connection (read-only)
  gre repair apply --name NAME --code CODE [--yes]
                          apply ONE named repair, verified, with rollback on failure
  gre node list [--json]  list configured Iran nodes (FOREIGN)
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
                          add an Iran node on FOREIGN (non-interactive)
  gre node remove --name NAME [--yes]
                          remove an Iran node from FOREIGN
  gre iran peer list [--json]
                          list foreign peers this Iran connects to
  gre iran peer suggest [--json]
                          print collision-free suggested values for a new peer
                          (name, subnet base, index, GRE key, TCP/UDP ports)
  gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B]
                    [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
                    [--udp-ports LIST] [--mss-clamp on|off] [--yes]
                          connect this Iran to an additional foreign server
  gre iran peer remove --name NAME [--yes]
                          remove one foreign peer (other peers keep running)
  gre iran peer apply --name NAME
                          re-apply one peer's tunnel and rules
  gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
                 [--key K] [--subnet-base A.B] [--wan IFACE] [--tcp-ports LIST]
                 [--udp-ports LIST] [--mss-clamp on|off] [--downtime MIN] [--yes]
                          configure this server as an IRAN node (non-interactive);
                          creates the FIRST foreign peer only — on a server that
                          already has peers it refuses and points to 'iran peer add'
                          --downtime MIN: acceptable tunnel downtime in minutes
                          (0 disables the auto-heal watchdog; default 2)
  gre export [path] [--yes]
                          back up /etc/multi-gre (default: ./gre-backup-<timestamp>.tar.gz)
  gre import <file> [--yes]
                          restore a backup created by 'gre export'
  gre foreign-setup [--foreign-ip IP] [--gre-whitelist on|off]
                 [--icmp-drop on|off] [--downtime MIN] [--yes]
                          configure this server as FOREIGN (non-interactive);
                          refuses when already configured (use 'gre node add')
  gre watchdog            watchdog: enable|disable|status|interval <1-60>
  gre purge [--yes]       remove EVERYTHING GRE-related from this server
                          (all GRE tunnels, all related iptables rules,
                          systemd units, configs, old versions' artifacts)
  gre hub                 gre-hub web dashboard: install|status|start|stop|restart
                          domain [DOMAIN]|unexpose|uninstall
  gre update              self-update to the latest version
  gre --apply             bring up all configured tunnels (used by systemd)
  gre --stop              tear down all tunnels, keep config (used by systemd)
  gre --watchdog          check tunnels and re-apply dead ones (used by systemd timer)
  gre --version           print version
  gre --help              this help

All mutating commands ask for confirmation unless --yes is passed.
EOF
}

case "${1:-}" in
    --apply)           require_root; apply_all ;;
    --stop)            require_root; stop_all ;;
    --watchdog)        require_root; watchdog_run ;;
    watchdog)          watchdog_menu "${2:-status}" "${3:-}" ;;
    --status|status)
        case "${2:-}" in
            "")      show_status ;;
            --json)  show_status_json ;;
            *)       err "Unknown option: $2"; err "Usage: gre status [--json]"; exit 1 ;;
        esac ;;
    node)
        case "${2:-}" in
            list)    cli_node_list "${@:3}" ;;
            suggest) cli_node_suggest "${@:3}" ;;
            add)     cli_node_add "${@:3}" ;;
            edit)    cli_node_edit "${@:3}" ;;
            remove)  cli_node_remove "${@:3}" ;;
            --help|-h)
                cat <<'EOF'
Usage:
  gre node list [--json]
  gre node suggest [--json] [--count N] [--base A.B]
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
  gre node edit --name CURRENT [--new-name NAME] [--ip IRAN_IP] [--foreign-ip IP]
                [--subnet-base A.B] [--idx N] [--key K] [--plan] [--yes]
  gre node remove --name NAME [--yes]

Edit changes an existing node in place. Every option is optional: an option you do
not pass keeps its current value, and the current values are shown as the defaults
in the interactive wizard. A change of ip/subnet/idx/key rebuilds only this node's
tunnel; if a failure occurs, the previous configuration is restored.
EOF
                ;;
            *)       err "Usage: gre node <list|add|edit|remove> ...  (see: gre node --help)"; exit 1 ;;
        esac ;;
    iran)
        case "${2:-}" in
            peer)
                case "${3:-}" in
                    list)    cli_iran_peer_list "${@:4}" ;;
                    add)     cli_iran_peer_add "${@:4}" ;;
                    edit)    cli_iran_peer_edit "${@:4}" ;;
                    remove)  cli_iran_peer_remove "${@:4}" ;;
                    apply)   cli_iran_peer_apply "${@:4}" ;;
                    suggest) cli_iran_peer_suggest "${@:4}" ;;
                    --help|-h)
                        cat <<'EOF'
Usage:
  gre iran peer list [--json]
  gre iran peer suggest [--json] [--count N] [--base A.B]
  gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B]
                    [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
                    [--udp-ports LIST] [--mss-clamp on|off] [--yes]
  gre iran peer edit --name CURRENT [--new-name NAME] [--foreign-ip IP]
                    [--iran-ip IP] [--subnet-base A.B] [--idx N] [--key K]
                    [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
                    [--mss-clamp on|off] [--plan] [--yes]
  gre iran peer remove --name NAME [--yes]
  gre iran peer apply --name NAME
EOF
                        ;;
                    *)       err "Usage: gre iran peer <list|add|remove|apply> ...  (see: gre iran peer --help)"; exit 1 ;;
                esac ;;
            --help|-h|"")
                cat <<'EOF'
Usage:
  gre iran peer list [--json]
  gre iran peer add --name NAME --foreign-ip IP [options] [--yes]
  gre iran peer remove --name NAME [--yes]
  gre iran peer apply --name NAME

'gre iran-setup' still creates the FIRST peer on a peer-less server.
EOF
                ;;
            *)       err "Usage: gre iran peer <list|add|remove|apply> ...  (see: gre iran --help)"; exit 1 ;;
        esac ;;
    iran-setup)        cli_iran_setup "${@:2}" ;;
    foreign-setup)     cli_foreign_setup "${@:2}" ;;
    mtu)               cli_mtu "${@:2}" ;;
    health-check)      cli_health_check "${@:2}" ;;
    repair)
        case "${2:-}" in
            preview) cli_repair_preview "${@:3}" ;;
            apply)   cli_repair_apply "${@:3}" ;;
            --help|-h|"")
                cat <<'EOF'
Usage:
  gre repair preview --name NAME [--json]
      List the repairs available for a connection. Read-only; changes nothing.

  gre repair apply --name NAME --code CODE [--yes]
      Apply ONE named repair. Requires --yes. It verifies the result, and restores
      the previous state when the verification fails.

Only repairs this host can verify are offered. Everything else is reported as a
finding for a human to act on.
EOF
                ;;
            *) err "Usage: gre repair <preview|apply> ...  (see: gre repair --help)"; exit 1 ;;
        esac ;;
    doctor)            doctor ;;
    tunnel)
        case "${2:-}" in
            diagnose)  cli_tunnel_diagnose "${@:3}" ;;
            rules)     cli_tunnel_rules "${@:3}" ;;
            --help|-h|"")
                cat <<'EOF'
Usage:
  gre tunnel diagnose --name NAME [--json]
      Read-only health report for one connection: interface present and up,
      endpoints and GRE key correct, addressing, underlay route (including a route
      that would loop GRE inside GRE), whether protocol 47 is filtered, IP
      forwarding, traffic counters, duplicate/stale interfaces, whether the live
      interface matches the configuration, and whether the far end actually replies.
      Every check reports PASS, WARN, FAIL or UNKNOWN, and changes nothing.

  gre tunnel rules [--json]
      Print the manager's iptables rules across all tables. Read-only.

Exits non-zero when any check FAILs, so it can gate a script.
EOF
                ;;
            *)         err "Usage: gre tunnel <diagnose|rules> ...  (see: gre tunnel --help)"; exit 1 ;;
        esac ;;
    export)            cli_export "${@:2}" ;;
    import)            cli_import "${@:2}" ;;
    update)            self_update ;;
    purge)             purge_all "${@:2}" ;;
    hub)               hub_menu "${@:2}" ;;
    --version|-v)      echo "gre-manager v$VERSION" ;;
    --help|-h)         usage ;;
    "")                main_menu ;;
    *)                 err "Unknown argument: $1"; usage; exit 1 ;;
esac
