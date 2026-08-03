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

VERSION="2.2.3"

GITHUB_REPO="aibedini/gre-manager"
RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/gre-manager.sh"

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
PEER_CONF_FIELDS_RE='NAME|FOREIGN_IP|IRAN_IP|WAN_IF|SUBNET_BASE|IDX|KEY|TUN|TCP_PORTS|UDP_PORTS|MSS_CLAMP'
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
    [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,9}$ ]]
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
    IDX=""; KEY=""; TUN=""; TCP_PORTS=""; UDP_PORTS=""; MSS_CLAMP="0"
    if ! validate_conf_file "$f" "$PEER_CONF_FIELDS_RE"; then
        err "Invalid or unsafe peer config: $f (unknown field or unsafe value)"
        return 1
    fi
    source "$f"
    [[ -z "$TUN" && -n "$NAME" ]] && TUN="gre-$NAME"
    validate_peer_values "quiet" || { err "Peer config $f contains invalid values."; return 1; }
    return 0
}

# Shared value validation for peer add/migrate. With "quiet" it only returns
# the status (caller prints one error), otherwise it explains the problem.
validate_peer_values() { # validate_peer_values ["quiet"]
    local quiet="${1:-}" e=0
    valid_ip "$IRAN_IP"          || { [[ -z "$quiet" ]] && err "Invalid Iran IP: '$IRAN_IP'"; e=1; }
    valid_ip "$FOREIGN_IP"       || { [[ -z "$quiet" ]] && err "Invalid foreign IP: '$FOREIGN_IP'"; e=1; }
    valid_name "$NAME"           || { [[ -z "$quiet" ]] && err "Invalid peer name: '$NAME'"; e=1; }
    valid_subnet_base "$SUBNET_BASE" || { [[ -z "$quiet" ]] && err "Invalid subnet base: '$SUBNET_BASE' (expected A.B, e.g. 10.201)"; e=1; }
    { [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )); } \
                                 || { [[ -z "$quiet" ]] && err "Invalid tunnel index: '$IDX' (1-254)"; e=1; }
    [[ "$KEY" =~ ^[0-9]+$ ]]     || { [[ -z "$quiet" ]] && err "Invalid GRE key: '$KEY'"; e=1; }
    valid_iface "$WAN_IF"        || { [[ -z "$quiet" ]] && err "Invalid WAN interface: '$WAN_IF'"; e=1; }
    valid_port_list "$TCP_PORTS" || { [[ -z "$quiet" ]] && err "Invalid TCP port list: '$TCP_PORTS'"; e=1; }
    valid_port_list "$UDP_PORTS" || { [[ -z "$quiet" ]] && err "Invalid UDP port list: '$UDP_PORTS'"; e=1; }
    [[ "$MSS_CLAMP" == "0" || "$MSS_CLAMP" == "1" ]] \
                                 || { [[ -z "$quiet" ]] && err "Invalid MSS_CLAMP: '$MSS_CLAMP' (0|1)"; e=1; }
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

# Central collision detection shared by menu, CLI, import and doctor.
# Checks (SUBNET_BASE,IDX) pair, tunnel name and port overlaps against all
# OTHER peers. Returns 1 (after printing the reason) on any conflict.
check_peer_collisions() { # check_peer_collisions NAME SUBNET_BASE IDX TUN TCP_PORTS UDP_PORTS
    local name="$1" base="$2" idx="$3" tun="$4" tcp="$5" udp="$6"
    local f p_name p_base p_idx p_tun p_tcp p_udp
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        p_name="$(grep -E '^NAME=' "$f" | cut -d= -f2)"
        [[ "$p_name" == "$name" ]] && continue
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

create_tunnel() { # name local_ip remote_ip key addr/mask
    local name="$1" local_ip="$2" remote_ip="$3" key="$4" addr="$5"
    if tun_exists "$name"; then
        ip link set "$name" down 2>/dev/null || true
        ip tunnel del "$name" 2>/dev/null || true
    fi
    ip tunnel add "$name" mode gre local "$local_ip" remote "$remote_ip" key "$key" ttl 255 || return 1
    ip addr add "$addr" dev "$name" || return 1
    ip link set "$name" mtu "$TUN_MTU" up || return 1
    ok "Tunnel $name is up ($addr, key $key)"
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
apply_foreign_node() { # node-conf-file
    local f="$1" NAME="" IRAN_IP="" IDX="" KEY="" TUN="" SUBNET_BASE="$DEFAULT_SUBNET_BASE"
    source "$f"
    create_tunnel "$TUN" "$FOREIGN_IP" "$IRAN_IP" "$KEY" "${SUBNET_BASE}.${IDX}.1/30"
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
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    load_peer_conf "$f" || return 1
    local peer="${SUBNET_BASE}.${IDX}.1"
    local self="${SUBNET_BASE}.${IDX}.2"

    create_tunnel "$TUN" "$IRAN_IP" "$FOREIGN_IP" "$KEY" "${self}/30" || return 1
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
    if [[ "${MSS_CLAMP:-0}" == "1" ]]; then
        ipt_del mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu
        ipt_add mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment "multi-gre-iran-$NAME-mss" -j TCPMSS --clamp-mss-to-pmtu
        ok "[$NAME] TCP MSS clamping enabled on $TUN"
    fi
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
    ask TCP_PORTS  "TCP ports (e.g. 80,443,8443)" ""
    ask UDP_PORTS  "UDP ports (e.g. 443,8443)" ""

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
        echo   "  ── Foreigns connected to this Iran ─────────────────────"
        for f in "$FOREIGNS_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            if load_peer_conf "$f"; then
                if tun_exists "$TUN"; then dot="$(dot_on)"; else dot="$(dot_off)"; fi
                printf '  %s %-10s foreign %-16s subnet %s.%s.0/30  tunnel %s\n' \
                    "$dot" "$NAME" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$TUN"
            else
                printf '  %s %s (invalid conf)\n' "$(dot_off)" "$(basename "$f")"
            fi
        done
        echo   "  ──────────────────────────────────────────────────────────"
        echo   "  1) Add a foreign peer"
        echo   "  2) Remove a foreign peer"
        echo   "  3) Re-apply a peer"
        echo   "  0) Back"
        read -rp "  Select: " c
        case "$c" in
            1) interactive_add_iran_peer 0 ;;
            2) menu_iran_peer_remove ;;
            3) menu_iran_peer_apply ;;
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
    valid_name "$NAME" || { err "Invalid node name: $NAME"; return 1; }
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

self_update() {
    require_root
    command -v curl >/dev/null 2>&1 || { err "curl is required for update."; return 1; }
    info "Checking for updates ($GITHUB_REPO)..."
    local tmp
    tmp="$(mktemp -d)" || { err "mktemp failed"; return 1; }

    local remote_ver="" verified="no"
    # Preferred: latest pinned GitHub release, verified against its SHA-256 checksum.
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

    if [[ "$dl_ok" == "1" ]]; then
        if command -v sha256sum >/dev/null 2>&1; then
            if (cd "$tmp" && sha256sum -c gre.sha256 >/dev/null 2>&1); then
                verified="yes"
            else
                err "Checksum verification FAILED for release $tag; refusing to update."
                rm -rf "$tmp"
                return 1
            fi
        else
            warn "sha256sum not available; installing release $tag without checksum verification."
        fi
        remote_ver="$(grep -m1 -E '^VERSION=' "$tmp/gre" | cut -d'"' -f2)"
    else
        # Fallback: raw main branch (no checksum possible)
        warn "Release assets unavailable after retries; falling back to the main branch (no checksum)."
        if ! curl -fsSL --max-time 60 "$RAW_URL" -o "$tmp/gre"; then
            err "Download failed. Check your internet connection."
            rm -rf "$tmp"
            return 1
        fi
        remote_ver="$(grep -m1 -E '^VERSION=' "$tmp/gre" | cut -d'"' -f2)"
    fi

    if [[ -z "$remote_ver" ]]; then
        err "Could not parse the remote version."
        rm -rf "$tmp"
        return 1
    fi
    if [[ "$remote_ver" == "$VERSION" ]]; then
        ok "Already up to date (v$VERSION)."
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
    info "Run 'gre' again to use the new version."
    exit 0
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
        local found=0
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            found=1
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""; SUBNET_BASE="$DEFAULT_SUBNET_BASE"
            source "$f"
            printf '  %s  iran ip %s, subnet %s.%s.0/30, key %s, tunnel %s\n' \
                "$NAME" "$IRAN_IP" "$SUBNET_BASE" "$IDX" "$KEY" "$TUN"
        done
        (( found )) || info "  (none)"
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

    valid_name "$NAME" || { err "Invalid node name: $NAME"; return 1; }
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
    local f NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" SUBNET_BASE="$DEFAULT_SUBNET_BASE" \
          IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS="" MSS_CLAMP="0"
    local found=0
    for f in "$FOREIGNS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        found=1
        load_peer_conf "$f" || { warn "  invalid peer conf: $f"; continue; }
        printf '  %s  foreign %s, subnet %s.%s.0/30, key %s, tunnel %s, tcp [%s] udp [%s]\n' \
            "$NAME" "$FOREIGN_IP" "$SUBNET_BASE" "$IDX" "$KEY" "$TUN" \
            "${TCP_PORTS:-none}" "${UDP_PORTS:-none}"
    done
    (( found )) || info "  (none — add one: gre iran peer add)"
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

cli_iran_peer_remove() { # gre iran peer remove --name NAME [--yes]
    require_root
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
    if iptables -t mangle -C POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "multi-gre-iran-$NAME-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        d_pass "[$NAME] TCP MSS clamping rule on $TUN is present"
    elif iptables -t mangle -C POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        d_warn "[$NAME] TCP MSS clamping rule on $TUN uses the legacy un-commented style (fix: gre iran peer apply --name $NAME)"
    else
        d_fail "[$NAME] TCP MSS clamping rule on $TUN is missing (fix: gre iran peer apply --name $NAME)"
    fi
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
    echo   "  1) Configure this server as IRAN (add / manage foreign peers)"
    echo   "  2) Configure this server as FOREIGN / add an Iran node"
    printf '  3) Remove an Iran node from FOREIGN                  [%s nodes]\n' "$ncount"
    echo   "  4) Restart all configured tunnels"
    echo   "  5) Stop all configured tunnels"
    echo   "  ── Monitoring ──────────────────────────────────────────────"
    echo   "  6) Status & health"
    printf '  7) Auto-heal watchdog                                %s %s\n' "$wdot" "$wlabel"
    echo   "  8) Doctor (diagnostics)"
    echo   "  ── Maintenance ─────────────────────────────────────────────"
    echo   "  9) Backup / restore (export / import)"
    echo   " 10) Clean up original vatanhost gre.sh (vatan-m2)"
    echo   " 11) Update gre-manager to the latest version"
    echo   " 12) Uninstall from this server"
    printf ' %s13) PURGE: remove EVERYTHING GRE (danger)%s\n' "$C_RED" "$C_RESET"
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
            3)  remove_node ;;
            4)  restart_all ;;
            5)  stop_menu ;;
            6)  show_status ;;
            7)  watchdog_settings_menu ;;
            8)  doctor ;;
            9)  backup_restore_menu ;;
            10) legacy_cleanup ;;
            11) self_update ;;
            12) uninstall ;;
            13) purge_all ;;
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
  gre node list [--json]  list configured Iran nodes (FOREIGN)
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
                          add an Iran node on FOREIGN (non-interactive)
  gre node remove --name NAME [--yes]
                          remove an Iran node from FOREIGN
  gre iran peer list [--json]
                          list foreign peers this Iran connects to
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
  gre watchdog            watchdog: enable|disable|status|interval <1-60>
  gre purge [--yes]       remove EVERYTHING GRE-related from this server
                          (all GRE tunnels, all related iptables rules,
                          systemd units, configs, old versions' artifacts)
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
            add)     cli_node_add "${@:3}" ;;
            remove)  cli_node_remove "${@:3}" ;;
            --help|-h)
                cat <<'EOF'
Usage:
  gre node list [--json]
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--subnet-base A.B] [--yes]
  gre node remove --name NAME [--yes]
EOF
                ;;
            *)       err "Usage: gre node <list|add|remove> ...  (see: gre node --help)"; exit 1 ;;
        esac ;;
    iran)
        case "${2:-}" in
            peer)
                case "${3:-}" in
                    list)    cli_iran_peer_list "${@:4}" ;;
                    add)     cli_iran_peer_add "${@:4}" ;;
                    remove)  cli_iran_peer_remove "${@:4}" ;;
                    apply)   cli_iran_peer_apply "${@:4}" ;;
                    --help|-h)
                        cat <<'EOF'
Usage:
  gre iran peer list [--json]
  gre iran peer add --name NAME --foreign-ip IP [--iran-ip IP] [--subnet-base A.B]
                    [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST]
                    [--udp-ports LIST] [--mss-clamp on|off] [--yes]
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
    doctor)            doctor ;;
    export)            cli_export "${@:2}" ;;
    import)            cli_import "${@:2}" ;;
    update)            self_update ;;
    purge)             purge_all "${@:2}" ;;
    --version|-v)      echo "gre-manager v$VERSION" ;;
    --help|-h)         usage ;;
    "")                main_menu ;;
    *)                 err "Unknown argument: $1"; usage; exit 1 ;;
esac
