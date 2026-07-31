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
#   - Persistence via a oneshot systemd unit that re-applies config at boot.
#
# State:
#   /etc/multi-gre/foreign.conf      FOREIGN_IP=..., ICMP_DROP=0|1
#   /etc/multi-gre/iran.conf         single-file config on an Iran node
#   /etc/multi-gre/nodes/<name>.conf one file per Iran node (foreign side)
#
# CLI:
#   gre                 interactive menu
#   gre --apply         bring up everything that is configured   (used by systemd)
#   gre --stop          tear everything down (config is kept)    (used by systemd)
#   gre --status        show status
#   gre update          self-update to the latest version from GitHub
#   gre --version       print version
#   gre --help          usage
#
set -uo pipefail

VERSION="1.0.0"

GITHUB_REPO="aibedini/gre-manager"
RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/gre-manager.sh"

CONF_DIR="/etc/multi-gre"
NODES_DIR="$CONF_DIR/nodes"
FOREIGN_CONF="$CONF_DIR/foreign.conf"
IRAN_CONF="$CONF_DIR/iran.conf"
SYSCTL_FILE="/etc/sysctl.d/99-multi-gre.conf"
SERVICE_FILE="/etc/systemd/system/multi-gre.service"
INSTALL_PATH="/usr/local/sbin/gre"
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

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        err "This script must be run as root (use: sudo gre)."
        exit 1
    fi
}

confirm() { # confirm "question"  -> 0 on yes
    local ans
    read -rp "$1 [y/N]: " ans
    [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
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
    local f
    for f in "$NODES_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        apply_foreign_node "$f"
    done
    if [[ "${ICMP_DROP:-0}" == "1" ]]; then
        ipt_add filter INPUT -p icmp -j DROP
        ok "Inbound ICMP (ping) is dropped"
    fi
}

apply_iran() {
    [[ -f "$IRAN_CONF" ]] || return 0
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS=""
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
    if [[ "${ICMP_DROP:-0}" == "1" ]]; then
        ipt_del filter INPUT -p icmp -j DROP
        info "ICMP DROP rule removed"
    fi
}

stop_iran() {
    [[ -f "$IRAN_CONF" ]] || return 0
    local NAME="" FOREIGN_IP="" IRAN_IP="" WAN_IF="" IDX="" KEY="" TUN="" TCP_PORTS="" UDP_PORTS=""
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
    [[ -n "$TUN" ]] && delete_tunnel "$TUN"
}

stop_all() {
    # shellcheck disable=SC1090
    [[ -f "$FOREIGN_CONF" ]] && source "$FOREIGN_CONF"
    stop_foreign
    stop_iran
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

    valid_ip "$IRAN_IP"    || { err "Invalid Iran IP: $IRAN_IP";       return 1; }
    valid_ip "$FOREIGN_IP" || { err "Invalid foreign IP: $FOREIGN_IP"; return 1; }
    valid_name "$NAME"     || { err "Invalid node name: $NAME";        return 1; }
    [[ "$IDX" =~ ^[0-9]+$ ]] && (( IDX >= 1 && IDX <= 254 )) || { err "Invalid index: $IDX"; return 1; }
    [[ "$KEY" =~ ^[0-9]+$ ]] || { err "Invalid key: $KEY"; return 1; }
    [[ -n "$WAN_IF" ]] || { err "WAN interface is empty"; return 1; }
    valid_port_list "$TCP_PORTS" || { err "Invalid TCP port list"; return 1; }
    valid_port_list "$UDP_PORTS" || { err "Invalid UDP port list"; return 1; }

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
EOF

    apply_iran || { err "Failed to bring the tunnel up. Check the IPs and that GRE (proto 47) is not blocked."; return 1; }
    install_service

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

        local icmp_drop="0"
        if confirm "Drop inbound ICMP (ping) on this server?"; then
            icmp_drop="1"
        fi
        cat > "$FOREIGN_CONF" <<EOF
FOREIGN_IP=$FOREIGN_IP
ICMP_DROP=$icmp_drop
EOF
        install_service
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

    apply_foreign_node "$NODES_DIR/$NAME.conf" || {
        err "Failed to create the tunnel."
        rm -f "$NODES_DIR/$NAME.conf"
        return 1
    }

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
    rm -f "$f"
    ok "Node '$NAME' removed."
    info "On the IRAN server itself, run menu option 7 (Uninstall) to clean up that side."
}

restart_all() {
    require_root
    info "Restarting all configured tunnels..."
    stop_all
    apply_all
    ok "Done."
}

stop_menu() {
    require_root
    info "Stopping all configured tunnels (config is kept, service stays enabled)..."
    stop_all
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
    info "systemd service:"
    echo "  enabled: $(service_state)"
    systemctl is-active multi-gre.service 2>/dev/null | sed 's/^/  active:  /' || true
}

uninstall() {
    require_root
    warn "This removes ALL multi-gre configuration from THIS server:"
    warn "tunnels, NAT rules, systemd service, sysctl file and $CONF_DIR."
    confirm "Continue with uninstall?" || { info "Aborted."; return; }

    stop_all
    systemctl disable multi-gre.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$SYSCTL_FILE"
    rm -rf "$CONF_DIR"
    rm -f "$INSTALL_PATH"
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
    ok "Legacy cleanup finished."
    info "Verify with:  ip tunnel show   |   iptables -t nat -S   |   iptables -S INPUT"
}

self_update() {
    require_root
    command -v curl >/dev/null 2>&1 || { err "curl is required for update."; return 1; }
    info "Checking for updates ($GITHUB_REPO)..."
    local tmp
    tmp="$(mktemp)" || { err "mktemp failed"; return 1; }
    if ! curl -fsSL "$RAW_URL" -o "$tmp"; then
        err "Download failed. Check your internet connection."
        rm -f "$tmp"
        return 1
    fi
    local remote_ver=""
    remote_ver="$(grep -m1 -E '^VERSION=' "$tmp" | cut -d'"' -f2)"
    if [[ -z "$remote_ver" ]]; then
        err "Could not parse the remote version."
        rm -f "$tmp"
        return 1
    fi
    if [[ "$remote_ver" == "$VERSION" ]]; then
        ok "Already up to date (v$VERSION)."
        rm -f "$tmp"
        return 0
    fi
    if ! bash -n "$tmp" 2>/dev/null; then
        err "Downloaded file failed the syntax check; refusing to install."
        rm -f "$tmp"
        return 1
    fi
    cp "$tmp" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    rm -f "$tmp"
    ok "Updated: v$VERSION -> v$remote_ver"
    info "Run 'gre' again to use the new version."
    exit 0
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
    printf '  Role: %s%s%s   Tunnels up: %s%s%s   Service: %s%s%s\n' \
        "$C_GREEN" "$roles" "$C_RESET" \
        "$C_GREEN" "$(tunnel_count)" "$C_RESET" \
        "$C_GREEN" "$(service_state)" "$C_RESET"
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
  gre              interactive menu
  gre --apply      bring up all configured tunnels (used by systemd)
  gre --stop       tear down all tunnels, keep config (used by systemd)
  gre --status     show status
  gre update       self-update to the latest version
  gre --version    print version
  gre --help       this help
EOF
}

case "${1:-}" in
    --apply)           require_root; apply_all ;;
    --stop)            require_root; stop_all ;;
    --status|status)   show_status ;;
    update)            self_update ;;
    --version|-v)      echo "gre-manager v$VERSION" ;;
    --help|-h)         usage ;;
    "")                main_menu ;;
    *)                 err "Unknown argument: $1"; usage; exit 1 ;;
esac
