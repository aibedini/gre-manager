#!/usr/bin/env bash
#
# gre-manager.sh — Multi-GRE Tunnel Manager
# https://github.com/aibedini/gre-manager
#
# Manage multiple GRE tunnels: several IRAN servers <-> one FOREIGN server.
#
# Layout:
#   - Each IRAN node gets its own tunnel, subnet and GRE key:
#       node ir01 -> gre-ir01, 10.200.1.0/30  (foreign .1, iran .2), key 1001
#       node ir02 -> gre-ir02, 10.200.2.0/30, key 1002 ...
#   - IRAN side: DNAT selected TCP/UDP ports (arriving on the public IP)
#     into the tunnel towards the foreign server + SNAT on the tunnel.
#   - FOREIGN side: one GRE tunnel per Iran node. Services (e.g. Xray)
#     listen on 0.0.0.0 and are reachable through every tunnel.
#   - Persistence via a oneshot systemd unit that re-applies config at boot,
#     plus a watchdog timer that re-applies dead tunnels every minute.
#
# State:
#   /etc/multi-gre/foreign.conf      FOREIGN_IP=..., ICMP_DROP=0|1, GRE_WHITELIST=0|1
#   /etc/multi-gre/iran.conf         single-file config on an Iran node
#   /etc/multi-gre/nodes/<name>.conf one file per Iran node (foreign side)
#
# CLI:
#   gre                 interactive menu
#   gre --apply         bring up everything that is configured   (used by systemd)
#   gre --stop          tear everything down (config is kept)    (used by systemd)
#   gre --watchdog      check tunnels, re-apply dead ones        (used by systemd timer)
#   gre status [--json] show status (machine-readable JSON with --json)
#   gre doctor          diagnostics: PASS/WARN/FAIL per check, non-zero exit on FAIL
#   gre node list [--json]                              list Iran nodes (FOREIGN)
#   gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]
#   gre node remove --name NAME [--yes]
#   gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
#                  [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
#                  [--mss-clamp on|off] [--yes]
#   gre export [path] [--yes]   back up /etc/multi-gre to a tar.gz archive
#   gre import <file> [--yes]   restore a backup made by 'gre export'
#   gre watchdog        watchdog timer: enable|disable|status
#   gre update          self-update to the latest version from GitHub
#   gre --version       print version
#   gre --help          usage
#
# shellcheck shell=bash
# shellcheck disable=SC1090  # config files under /etc/multi-gre are sourced dynamically by design
set -uo pipefail

VERSION="1.3.0"

GITHUB_REPO="aibedini/gre-manager"
RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/gre-manager.sh"

CONF_DIR="/etc/multi-gre"
NODES_DIR="$CONF_DIR/nodes"
FOREIGN_CONF="$CONF_DIR/foreign.conf"
IRAN_CONF="$CONF_DIR/iran.conf"
SYSCTL_FILE="/etc/sysctl.d/99-multi-gre.conf"
SERVICE_FILE="/etc/systemd/system/multi-gre.service"
WATCHDOG_SERVICE_FILE="/etc/systemd/system/multi-gre-watchdog.service"
WATCHDOG_TIMER_FILE="/etc/systemd/system/multi-gre-watchdog.timer"
INSTALL_PATH="/usr/local/sbin/gre"
AUDIT_LOG="/var/log/gre-manager.log"
SUBNET_BASE="10.200"
TUN_MTU=1476

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

# ------------------------------------------------------------- port conflicts
port_in_use() { # proto(tcp|udp) port -> 0 if a local service listens on it
    local proto="$1" port="$2"
    command -v ss >/dev/null 2>&1 || return 1
    case "$proto" in
        tcp) ss -tlnH "sport = :$port" 2>/dev/null | grep -q . ;;
        udp) ss -ulnH "sport = :$port" 2>/dev/null | grep -q . ;;
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
    local f="$1" NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    source "$f"
    create_tunnel "$TUN" "$FOREIGN_IP" "$IRAN_IP" "$KEY" "${SUBNET_BASE}.${IDX}.1/30"
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
        ipt_add filter INPUT -p icmp -s "${SUBNET_BASE}.0.0/16" \
            -m comment --comment "multi-gre-tunnel-icmp" -j ACCEPT
        ipt_add filter INPUT -p icmp -m comment --comment "multi-gre-icmp-block" -j DROP
        ok "Inbound ICMP (ping) is dropped (tunnel subnets stay pingable)"
    fi
}

apply_iran() {
    [[ -f "$IRAN_CONF" ]] || return 0
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" \
          TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
    source "$IRAN_CONF"
    local peer="${SUBNET_BASE}.${IDX}.1"
    local self="${SUBNET_BASE}.${IDX}.2"

    create_tunnel "$TUN" "$IRAN_IP" "$FOREIGN_IP" "$KEY" "${self}/30" || return 1
    enable_ip_forward

    if [[ -n "$TCP_PORTS" ]]; then
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp -m multiport --dports "$TCP_PORTS" \
            -j DNAT --to-destination "$peer"
        ok "TCP ports $TCP_PORTS on $IRAN_IP -> $peer (DNAT)"
    fi
    if [[ -n "$UDP_PORTS" ]]; then
        ipt_add nat PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp -m multiport --dports "$UDP_PORTS" \
            -j DNAT --to-destination "$peer"
        ok "UDP ports $UDP_PORTS on $IRAN_IP -> $peer (DNAT)"
    fi
    if [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
        ipt_add nat POSTROUTING -o "$TUN" -d "$peer" -j SNAT --to-source "$self"
    fi

    # --- TCP MSS clamping on the tunnel (avoids broken-PMTU stalls)
    if [[ "${MSS_CLAMP:-0}" == "1" ]]; then
        ipt_add mangle POSTROUTING -o "$TUN" -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu
        ok "TCP MSS clamping enabled on $TUN"
    fi
}

apply_all() {
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

    # ICMP rules (commented v1.1.0 style + plain v1.0.0 style)
    ipt_del filter INPUT -p icmp -s "${SUBNET_BASE}.0.0/16" \
        -m comment --comment "multi-gre-tunnel-icmp" -j ACCEPT
    ipt_del filter INPUT -p icmp -m comment --comment "multi-gre-icmp-block" -j DROP
    ipt_del filter INPUT -p icmp -j DROP
}

stop_iran() {
    [[ -f "$IRAN_CONF" ]] || return 0
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" \
          TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
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
    if [[ -f "$FOREIGN_CONF" ]]; then
        # shellcheck disable=SC1090
        source "$FOREIGN_CONF"
        local NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            if ! tun_exists "$TUN" || ! ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.2" >/dev/null 2>&1; then
                logger -t gre-watchdog "tunnel $TUN (node $NAME) missing or unreachable; re-applying"
                apply_foreign_node "$f" && restarted=$(( restarted + 1 ))
            fi
        done
    fi
    if [[ -f "$IRAN_CONF" ]]; then
        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" \
              TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
        source "$IRAN_CONF"
        if ! tun_exists "$TUN" || ! ping -c 2 -W 2 "${SUBNET_BASE}.${IDX}.1" >/dev/null 2>&1; then
            logger -t gre-watchdog "tunnel $TUN missing or unreachable; re-applying"
            apply_iran && restarted=$(( restarted + 1 ))
        fi
    fi
    (( restarted > 0 )) && logger -t gre-watchdog "re-applied $restarted tunnel(s)"
    return 0
}

install_watchdog() {
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
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now multi-gre-watchdog.timer >/dev/null 2>&1 || true
    ok "Watchdog timer enabled (checks tunnels every minute)"
}

remove_watchdog() {
    systemctl disable --now multi-gre-watchdog.timer >/dev/null 2>&1 || true
    rm -f "$WATCHDOG_TIMER_FILE" "$WATCHDOG_SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
}

watchdog_menu() { # gre watchdog enable|disable|status
    require_root
    case "${1:-status}" in
        enable)  install_watchdog ;;
        disable) remove_watchdog; ok "Watchdog disabled" ;;
        status)
            echo "watchdog timer: $(watchdog_state)"
            systemctl list-timers multi-gre-watchdog.timer --no-pager 2>/dev/null || true
            ;;
        *) err "Usage: gre watchdog [enable|disable|status]"; return 1 ;;
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
    install_watchdog
}

# ------------------------------------------------------------- menu actions
next_free_idx() {
    local used=" " f idx=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
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

setup_iran() {
    require_root
    if [[ -f "$IRAN_CONF" ]]; then
        warn "This server is already configured as an IRAN node."
        confirm "Reconfigure from scratch?" || return
        stop_iran
        rm -f "$IRAN_CONF"
    fi

    local wan_if; wan_if="$(detect_wan_iface)"
    local detected_ip; detected_ip="$(detect_public_ip "$wan_if")"

    echo
    info "IRAN node setup"
    ask IRAN_IP    "Public IP of THIS Iran server" "$detected_ip"
    ask FOREIGN_IP "Public IP of the FOREIGN server"
    ask NAME       "Node name (must match the name used on FOREIGN, e.g. ir01)" "ir01"
    ask IDX        "Tunnel index (must match FOREIGN, 1-254)" "1"
    local default_key=$(( 1000 + IDX ))
    ask KEY        "GRE key (must match FOREIGN)" "$default_key"
    ask WAN_IF     "Public (WAN) interface" "$wan_if"
    echo
    info "Enter the service ports on this Iran server that should be forwarded to the FOREIGN server."
    info "Comma separated, ranges allowed with ':', max 15 entries. Leave empty for none."
    ask TCP_PORTS  "TCP ports (e.g. 80,443,8443)" ""
    ask UDP_PORTS  "UDP ports (e.g. 443,8443)" ""

    local mss_clamp="0"
    if confirm_yes "Enable TCP MSS clamping on the tunnel? (recommended)"; then
        mss_clamp="1"
    fi

    valid_ip "$IRAN_IP"    || { err "Invalid Iran IP: $IRAN_IP";       return 1; }
    valid_ip "$FOREIGN_IP" || { err "Invalid foreign IP: $FOREIGN_IP"; return 1; }
    valid_name "$NAME"     || { err "Invalid node name: $NAME";        return 1; }
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }
    [[ -n "$WAN_IF" ]] || { err "WAN interface is empty"; return 1; }
    valid_port_list "$TCP_PORTS" || { err "Invalid TCP port list"; return 1; }
    valid_port_list "$UDP_PORTS" || { err "Invalid UDP port list"; return 1; }

    warn_port_conflicts "tcp" "$TCP_PORTS"
    warn_port_conflicts "udp" "$UDP_PORTS"

    if port_list_covers_22 "$TCP_PORTS"; then
        warn "Port 22 (SSH) is in the TCP list: SSH to this server will be forwarded to the FOREIGN server!"
        confirm "Are you sure you want to forward port 22?" || { info "Aborted."; return 1; }
    fi

    mkdir -p "$CONF_DIR"
    cat > "$IRAN_CONF" <<EOF
NAME=$NAME
FOREIGN_IP=$FOREIGN_IP
IRAN_IP=$IRAN_IP
WAN_IF=$WAN_IF
IDX=$IDX
KEY=$KEY
TUN=gre-$NAME
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
MSS_CLAMP=$mss_clamp
EOF
    chmod 600 "$IRAN_CONF"

    apply_iran || { err "Failed to bring the tunnel up. Check the IPs and that GRE (proto 47) is not blocked."; return 1; }
    install_service
    audit_log "iran-setup name=$NAME foreign=$FOREIGN_IP idx=$IDX key=$KEY tcp='$TCP_PORTS' udp='$UDP_PORTS' mss=$mss_clamp"

    echo
    ok "IRAN node '$NAME' configured."
    info "Tunnel: gre-$NAME  ${SUBNET_BASE}.${IDX}.2/30  <->  $FOREIGN_IP (key $KEY)"
    info "On the FOREIGN server this node must exist with the SAME name, index and key (menu option 2)."
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.1"
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
        if confirm_yes "Restrict GRE (proto 47) to known Iran node IPs? (recommended)"; then
            gre_whitelist="1"
        fi
        if confirm "Drop inbound ICMP (ping) on this server? (tunnel subnets stay pingable)"; then
            icmp_drop="1"
        fi
        cat > "$FOREIGN_CONF" <<EOF
FOREIGN_IP=$FOREIGN_IP
ICMP_DROP=$icmp_drop
GRE_WHITELIST=$gre_whitelist
EOF
        chmod 600 "$FOREIGN_CONF"
        install_service
        audit_log "foreign-setup ip=$FOREIGN_IP icmp_drop=$icmp_drop gre_whitelist=$gre_whitelist"
    fi
    # shellcheck disable=SC1090
    source "$FOREIGN_CONF"

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

    local idx; idx="$(next_free_idx)" || { err "No free tunnel index left"; return 1; }
    ask IDX "Tunnel index (1-254)" "$idx"
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    local f existing_idx=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        existing_idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        if [[ "$existing_idx" == "$IDX" ]]; then
            err "Index $IDX is already used by another node."
            return 1
        fi
    done
    local default_key=$(( 1000 + IDX ))
    ask KEY "GRE key" "$default_key"
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }

    cat > "$NODES_DIR/$NAME.conf" <<EOF
NAME=$NAME
IRAN_IP=$IRAN_IP
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
    audit_log "node-add name=$NAME iran_ip=$IRAN_IP idx=$IDX key=$KEY"

    echo
    ok "Node '$NAME' added on FOREIGN."
    echo "------------------------------------------------------------"
    echo "  Run 'gre' -> option 1 on the IRAN server and enter:"
    echo "    Public IP of THIS Iran server : $IRAN_IP"
    echo "    Public IP of the FOREIGN server: $FOREIGN_IP"
    echo "    Node name                     : $NAME"
    echo "    Tunnel index                  : $IDX"
    echo "    GRE key                       : $KEY"
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
    info "On the IRAN server itself, run menu option 7 (Uninstall) to clean up that side."
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
        info "NAT rules mentioning tunnel subnets:"
        iptables -t nat -S 2>/dev/null | grep -E "$SUBNET_BASE\." | sed 's/^/  /' || echo "  (none)"
        echo
        local IDX="" peer=""
        IDX="$(grep -E '^IDX=' "$IRAN_CONF" | cut -d= -f2)"
        if [[ -n "$IDX" ]]; then
            peer="${SUBNET_BASE}.${IDX}.1"
            info "Ping foreign end ($peer):"
            ping -c 2 -W 2 "$peer" 2>&1 | tail -n 2 | sed 's/^/  /' || true
        fi
    fi
    if [[ -f "$FOREIGN_CONF" ]]; then
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            echo
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
    local tag=""
    tag="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    if [[ -n "$tag" ]] \
        && curl -fsSL "https://github.com/${GITHUB_REPO}/releases/download/${tag}/gre" \
            -o "$tmp/gre" 2>/dev/null \
        && curl -fsSL "https://github.com/${GITHUB_REPO}/releases/download/${tag}/gre.sha256" \
            -o "$tmp/gre.sha256" 2>/dev/null; then
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
        warn "Release assets unavailable; falling back to the main branch (no checksum)."
        if ! curl -fsSL "$RAW_URL" -o "$tmp/gre"; then
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

    local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
    if (( json )); then
        local out="[" sep=""
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            out+="${sep}{\"name\":\"$NAME\",\"iran_ip\":\"$IRAN_IP\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\"}"
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
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            printf '  %s  iran ip %s, idx %s, key %s, tunnel %s\n' \
                "$NAME" "$IRAN_IP" "$IDX" "$KEY" "$TUN"
        done
        (( found )) || info "  (none)"
    fi
}

cli_node_add() { # gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]
    require_root
    if [[ ! -f "$FOREIGN_CONF" ]]; then
        err "This server is not configured as FOREIGN yet."
        err "Run 'gre' (menu option 2) once for the initial foreign setup, then retry."
        return 1
    fi
    local NAME="" IRAN_IP="" IDX="" KEY="" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)     [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --ip)       [[ -n "${2:-}" ]] || { err "Missing value for --ip"; return 1; }; IRAN_IP="$2"; shift 2 ;;
            --idx)      [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; IDX="$2"; shift 2 ;;
            --key)      [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; KEY="$2"; shift 2 ;;
            --yes|-y)   YES=1; shift ;;
            --help|-h)  echo "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]"; return 0 ;;
            *)          err "Unknown option: $1"
                        err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]"
                        return 1 ;;
        esac
    done
    [[ -n "$NAME" ]]    || { err "Missing required option: --name"; err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]"; return 1; }
    [[ -n "$IRAN_IP" ]] || { err "Missing required option: --ip";   err "Usage: gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]"; return 1; }

    valid_name "$NAME" || { err "Invalid node name: $NAME"; return 1; }
    if [[ -f "$NODES_DIR/$NAME.conf" ]]; then
        err "Node '$NAME' already exists. Remove it first (gre node remove --name $NAME)."
        return 1
    fi
    valid_ip "$IRAN_IP" || { err "Invalid IP: $IRAN_IP"; return 1; }

    if [[ -z "$IDX" ]]; then
        IDX="$(next_free_idx)" || { err "No free tunnel index left"; return 1; }
    fi
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    local f existing_idx=""
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        existing_idx="$(grep -E '^IDX=' "$f" | cut -d= -f2)"
        if [[ "$existing_idx" == "$IDX" ]]; then
            err "Index $IDX is already used by another node."
            return 1
        fi
    done
    [[ -z "$KEY" ]] && KEY=$(( 1000 + IDX ))
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }

    if (( ! YES )); then
        confirm "Add node '$NAME' (iran ip $IRAN_IP, idx $IDX, key $KEY)?" || { info "Cancelled."; return; }
    fi

    mkdir -p "$NODES_DIR"
    cat > "$NODES_DIR/$NAME.conf" <<EOF
NAME=$NAME
IRAN_IP=$IRAN_IP
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
    audit_log "node-add name=$NAME iran_ip=$IRAN_IP idx=$IDX key=$KEY"

    echo
    ok "Node '$NAME' added on FOREIGN."
    echo "------------------------------------------------------------"
    echo "  Run 'gre' -> option 1 on the IRAN server and enter:"
    echo "    Public IP of THIS Iran server : $IRAN_IP"
    echo "    Public IP of the FOREIGN server: $FOREIGN_IP"
    echo "    Node name                     : $NAME"
    echo "    Tunnel index                  : $IDX"
    echo "    GRE key                       : $KEY"
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
    info "On the IRAN server itself, run menu option 7 (Uninstall) to clean up that side."
}

# ------------------------------------------------------------- CLI: iran setup
cli_iran_setup() { # gre iran-setup --foreign-ip IP [options]
    require_root
    local FOREIGN_IP="" IRAN_IP="" NAME="ir01" IDX="1" KEY="" WAN_IF="" \
          TCP_PORTS="" UDP_PORTS="" MSS="on" YES=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --foreign-ip) [[ -n "${2:-}" ]] || { err "Missing value for --foreign-ip"; return 1; }; FOREIGN_IP="$2"; shift 2 ;;
            --iran-ip)    [[ -n "${2:-}" ]] || { err "Missing value for --iran-ip"; return 1; }; IRAN_IP="$2"; shift 2 ;;
            --name)       [[ -n "${2:-}" ]] || { err "Missing value for --name"; return 1; }; NAME="$2"; shift 2 ;;
            --idx)        [[ -n "${2:-}" ]] || { err "Missing value for --idx"; return 1; }; IDX="$2"; shift 2 ;;
            --key)        [[ -n "${2:-}" ]] || { err "Missing value for --key"; return 1; }; KEY="$2"; shift 2 ;;
            --wan)        [[ -n "${2:-}" ]] || { err "Missing value for --wan"; return 1; }; WAN_IF="$2"; shift 2 ;;
            --tcp-ports)  [[ -n "${2:-}" ]] || { err "Missing value for --tcp-ports"; return 1; }; TCP_PORTS="$2"; shift 2 ;;
            --udp-ports)  [[ -n "${2:-}" ]] || { err "Missing value for --udp-ports"; return 1; }; UDP_PORTS="$2"; shift 2 ;;
            --mss-clamp)  [[ "${2:-}" == "on" || "${2:-}" == "off" ]] || { err "--mss-clamp must be 'on' or 'off'"; return 1; }; MSS="$2"; shift 2 ;;
            --yes|-y)     YES=1; shift ;;
            --help|-h)    echo "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"; return 0 ;;
            *)            err "Unknown option: $1"
                          err "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"
                          return 1 ;;
        esac
    done
    if [[ -z "$FOREIGN_IP" ]]; then
        err "Missing required option: --foreign-ip"
        err "Usage: gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N] [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST] [--mss-clamp on|off] [--yes]"
        return 1
    fi

    if [[ -z "$WAN_IF" ]]; then
        WAN_IF="$(detect_wan_iface)"
    fi
    if [[ -z "$IRAN_IP" ]]; then
        IRAN_IP="$(detect_public_ip "$WAN_IF")"
    fi

    valid_ip "$IRAN_IP"    || { err "Invalid or undetectable Iran IP: '$IRAN_IP' (pass --iran-ip)"; return 1; }
    valid_ip "$FOREIGN_IP" || { err "Invalid foreign IP: $FOREIGN_IP"; return 1; }
    valid_name "$NAME"     || { err "Invalid node name: $NAME"; return 1; }
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    [[ -z "$KEY" ]] && KEY=$(( 1000 + IDX ))
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }
    [[ -n "$WAN_IF" ]] || { err "WAN interface could not be detected (pass --wan)"; return 1; }
    valid_port_list "$TCP_PORTS" || { err "Invalid TCP port list"; return 1; }
    valid_port_list "$UDP_PORTS" || { err "Invalid UDP port list"; return 1; }

    warn_port_conflicts "tcp" "$TCP_PORTS"
    warn_port_conflicts "udp" "$UDP_PORTS"

    if port_list_covers_22 "$TCP_PORTS" && (( ! YES )); then
        err "The TCP port list covers port 22 (SSH): SSH to this server would be forwarded to the FOREIGN server!"
        err "Re-run with --yes to confirm."
        return 1
    fi

    # only tear down the old config once every new value has been validated
    if [[ -f "$IRAN_CONF" ]]; then
        warn "This server is already configured as an IRAN node."
        if (( ! YES )); then
            confirm "Reconfigure from scratch?" || return
        fi
        stop_iran
        rm -f "$IRAN_CONF"
    fi

    local mss_clamp="0"
    [[ "$MSS" == "on" ]] && mss_clamp="1"

    mkdir -p "$CONF_DIR"
    cat > "$IRAN_CONF" <<EOF
NAME=$NAME
FOREIGN_IP=$FOREIGN_IP
IRAN_IP=$IRAN_IP
WAN_IF=$WAN_IF
IDX=$IDX
KEY=$KEY
TUN=gre-$NAME
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
MSS_CLAMP=$mss_clamp
EOF
    chmod 600 "$IRAN_CONF"

    apply_iran || { err "Failed to bring the tunnel up. Check the IPs and that GRE (proto 47) is not blocked."; return 1; }
    install_service
    audit_log "iran-setup name=$NAME foreign=$FOREIGN_IP idx=$IDX key=$KEY tcp='$TCP_PORTS' udp='$UDP_PORTS' mss=$mss_clamp"

    echo
    ok "IRAN node '$NAME' configured."
    info "Tunnel: gre-$NAME  ${SUBNET_BASE}.${IDX}.2/30  <->  $FOREIGN_IP (key $KEY)"
    info "On the FOREIGN server this node must exist with the SAME name, index and key (gre node add)."
    info "Test from here:  ping ${SUBNET_BASE}.${IDX}.1"
}

# ------------------------------------------------------------- CLI: JSON status
show_status_json() { # pure-bash JSON; values are pre-validated (IPs/alphanumeric)
    local roles="[" sep=""
    if [[ -f "$FOREIGN_CONF" ]]; then roles+="${sep}\"foreign\""; sep=","; fi
    if [[ -f "$IRAN_CONF" ]];    then roles+="${sep}\"iran\"";    sep=","; fi
    roles+="]"

    local nodes_json="[" nsep=""
    if [[ -f "$FOREIGN_CONF" ]]; then
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
            source "$f"
            local reach="false"
            ping -c 1 -W 2 "${SUBNET_BASE}.${IDX}.2" >/dev/null 2>&1 && reach="true"
            nodes_json+="${nsep}{\"name\":\"$NAME\",\"iran_ip\":\"$IRAN_IP\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\",\"reachable\":$reach}"
            nsep=","
        done
    fi
    nodes_json+="]"

    local iran_json="null"
    if [[ -f "$IRAN_CONF" ]]; then
        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" \
              TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
        # shellcheck disable=SC1090
        source "$IRAN_CONF"
        local reach="false"
        ping -c 1 -W 2 "${SUBNET_BASE}.${IDX}.1" >/dev/null 2>&1 && reach="true"
        iran_json="{\"name\":\"$NAME\",\"foreign_ip\":\"$FOREIGN_IP\",\"idx\":$IDX,\"key\":$KEY,\"tun\":\"$TUN\",\"tcp_ports\":\"$TCP_PORTS\",\"udp_ports\":\"$UDP_PORTS\",\"reachable\":$reach}"
    fi

    local svc_state wd_state
    svc_state="$(service_state)";  svc_state="${svc_state:-unknown}"
    wd_state="$(watchdog_state)";  wd_state="${wd_state:-unknown}"

    cat <<EOF
{
  "version": "$VERSION",
  "roles": $roles,
  "service": "$svc_state",
  "watchdog": "$wd_state",
  "tunnels_up": $(tunnel_count),
  "nodes": $nodes_json,
  "iran": $iran_json
}
EOF
}

# ------------------------------------------------------------- CLI: doctor
d_pass() { printf '%s[PASS]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
d_warn() { DOC_WARN=$(( ${DOC_WARN:-0} + 1 )); printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
d_fail() { DOC_FAIL=$(( ${DOC_FAIL:-0} + 1 )); printf '%s[FAIL]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }

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

    local is_foreign=0 is_iran=0
    [[ -f "$FOREIGN_CONF" ]] && is_foreign=1
    [[ -f "$IRAN_CONF" ]]    && is_iran=1
    if (( ! is_foreign && ! is_iran )); then
        d_warn "no configuration found in $CONF_DIR — fresh server, role checks skipped"
    fi

    # --- IRAN role checks
    if (( is_iran )); then
        local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" \
              TCP_PORTS="" UDP_PORTS="" MSS_CLAMP=""
        # shellcheck disable=SC1090
        source "$IRAN_CONF"
        local peer="${SUBNET_BASE}.${IDX}.1"

        if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]; then
            d_pass "net.ipv4.ip_forward = 1"
        else
            d_fail "net.ipv4.ip_forward is not 1 (fix: sysctl -w net.ipv4.ip_forward=1)"
        fi
        if [[ -n "$WAN_IF" ]] && ip link show "$WAN_IF" >/dev/null 2>&1; then
            d_pass "WAN interface '$WAN_IF' exists"
        else
            d_fail "WAN interface '$WAN_IF' from iran.conf does not exist"
        fi
        if ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$IRAN_IP"; then
            d_pass "IRAN_IP $IRAN_IP is assigned to a local interface"
        else
            d_fail "IRAN_IP $IRAN_IP is not assigned to any local interface"
        fi
        if [[ -n "$TUN" ]]; then
            if tun_exists "$TUN"; then
                d_pass "tunnel $TUN exists"
            else
                d_fail "tunnel $TUN is missing (fix: gre --apply)"
            fi
            if ping -c 2 -W 2 "$peer" >/dev/null 2>&1; then
                d_pass "tunnel peer $peer answers ping"
            else
                d_fail "tunnel peer $peer does not answer ping"
            fi
        fi
        # NAT DNAT rules from iran.conf
        if [[ -n "$TCP_PORTS" ]]; then
            if iptables -t nat -C PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p tcp \
                -m multiport --dports "$TCP_PORTS" -j DNAT --to-destination "$peer" 2>/dev/null; then
                d_pass "NAT DNAT rule for TCP ports $TCP_PORTS is present"
            else
                d_fail "NAT DNAT rule for TCP ports $TCP_PORTS is missing (fix: gre --apply)"
            fi
        fi
        if [[ -n "$UDP_PORTS" ]]; then
            if iptables -t nat -C PREROUTING -i "$WAN_IF" -d "$IRAN_IP" -p udp \
                -m multiport --dports "$UDP_PORTS" -j DNAT --to-destination "$peer" 2>/dev/null; then
                d_pass "NAT DNAT rule for UDP ports $UDP_PORTS is present"
            else
                d_fail "NAT DNAT rule for UDP ports $UDP_PORTS is missing (fix: gre --apply)"
            fi
        fi
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
                            d_warn "port $port/$proto (range $item) is already listened on by a local service"
                            conflicts=1
                        fi
                    done
                elif port_in_use "$proto" "$item"; then
                    d_warn "port $item/$proto is already listened on by a local service"
                    conflicts=1
                fi
            done
        done
        if (( conflicts == 0 )) && [[ -n "$TCP_PORTS" || -n "$UDP_PORTS" ]]; then
            d_pass "no local listeners conflict with the forwarded ports"
        fi
    fi

    # --- FOREIGN role checks
    if (( is_foreign )); then
        local FOREIGN_IP="" ICMP_DROP="" GRE_WHITELIST=""
        # shellcheck disable=SC1090
        source "$FOREIGN_CONF"
        local f NAME="" IRAN_IP="" IDX="" KEY="" TUN=""
        local node_count=0
        for f in "$NODES_DIR"/*.conf; do
            [[ -e "$f" ]] || continue
            node_count=$(( node_count + 1 ))
            NAME=""; IRAN_IP=""; IDX=""; KEY=""; TUN=""
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

    info "Stopping current tunnels..."
    stop_all
    tar -xzf "$file" -C / || { err "Extraction failed."; return 1; }
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
    echo   "  ---------------------------------------------------------------"
    printf '  Role: %s%s%s   Tunnels up: %s%s%s   Watchdog: %s%s%s\n' \
        "$C_GREEN" "$roles" "$C_RESET" \
        "$C_GREEN" "$(tunnel_count)" "$C_RESET" \
        "$C_GREEN" "$(watchdog_state)" "$C_RESET"
    echo   "  ---------------------------------------------------------------"
    echo   "  1) Configure this server as an IRAN node"
    echo   "  2) Configure this server as FOREIGN / add an Iran node"
    echo   "  3) Remove an Iran node from FOREIGN"
    echo   "  4) Restart all configured tunnels"
    echo   "  5) Stop all configured tunnels"
    echo   "  6) Show status"
    echo   "  7) Uninstall from this server"
    echo   "  8) Clean up original vatanhost gre.sh (vatan-m2)"
    echo   "  9) Update gre-manager to the latest version"
    echo   "  0) Exit"
}

main_menu() {
    require_root
    local choice=""
    while true; do
        banner
        read -rp "Select: " choice
        case "$choice" in
            1) setup_iran ;;
            2) setup_foreign ;;
            3) remove_node ;;
            4) restart_all ;;
            5) stop_menu ;;
            6) show_status ;;
            7) uninstall ;;
            8) legacy_cleanup ;;
            9) self_update ;;
            0) echo "Bye."; exit 0 ;;
            *) warn "Invalid selection." ;;
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
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]
                          add an Iran node on FOREIGN (non-interactive)
  gre node remove --name NAME [--yes]
                          remove an Iran node from FOREIGN
  gre iran-setup --foreign-ip IP [--iran-ip IP] [--name NAME] [--idx N]
                 [--key K] [--wan IFACE] [--tcp-ports LIST] [--udp-ports LIST]
                 [--mss-clamp on|off] [--yes]
                          configure this server as an IRAN node (non-interactive)
  gre export [path] [--yes]
                          back up /etc/multi-gre (default: ./gre-backup-<timestamp>.tar.gz)
  gre import <file> [--yes]
                          restore a backup created by 'gre export'
  gre watchdog            watchdog timer: enable|disable|status
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
    watchdog)          watchdog_menu "${2:-status}" ;;
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
  gre node add --name NAME --ip IRAN_IP [--idx N] [--key K] [--yes]
  gre node remove --name NAME [--yes]
EOF
                ;;
            *)       err "Usage: gre node <list|add|remove> ...  (see: gre node --help)"; exit 1 ;;
        esac ;;
    iran-setup)        cli_iran_setup "${@:2}" ;;
    doctor)            doctor ;;
    export)            cli_export "${@:2}" ;;
    import)            cli_import "${@:2}" ;;
    update)            self_update ;;
    --version|-v)      echo "gre-manager v$VERSION" ;;
    --help|-h)         usage ;;
    "")                main_menu ;;
    *)                 err "Unknown argument: $1"; usage; exit 1 ;;
esac
