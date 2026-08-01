#!/usr/bin/env bash
#
# install.sh — install gre-manager as the `gre` command
# https://github.com/aibedini/gre-manager
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | sudo bash
#
# Installs the latest PINNED GitHub release and verifies its SHA-256 checksum
# before installing. Set GRE_EDGE=1 to install the bleeding-edge main branch
# instead (not recommended for production).
#
set -euo pipefail

REPO="aibedini/gre-manager"
INSTALL_PATH="/usr/local/sbin/gre"
COMPLETION_SRC="https://raw.githubusercontent.com/${REPO}/main/completion/gre.bash"
COMPLETION_DIR="/etc/bash_completion.d"

if [[ -t 1 ]]; then
    C_CYAN="$(tput setaf 6 2>/dev/null || true)"
    C_GREEN="$(tput setaf 2 2>/dev/null || true)"
    C_BOLD="$(tput bold 2>/dev/null || true)"
    C_RESET="$(tput sgr0 2>/dev/null || true)"
else
    C_CYAN=""; C_GREEN=""; C_BOLD=""; C_RESET=""
fi

progress() { # progress "label" percent
    local label="$1" pct="$2" width=32 filled i
    filled=$(( pct * width / 100 ))
    printf '\r  %-28s %s[' "$label" "$C_CYAN"
    for (( i = 0; i < filled; i++ )); do printf '#'; done
    for (( i = filled; i < width; i++ )); do printf '-'; done
    printf ']%s %3d%%%s' "$C_RESET" "$pct" "$C_RESET"
    (( pct >= 100 )) && echo
    return 0
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[x] Please run as root:  curl -fsSL .../install.sh | sudo bash" >&2
    exit 1
fi

echo
printf '%s%s  Multi-GRE Tunnel Manager — installer%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
echo "  github.com/${REPO}"
echo

progress "Checking dependencies" 10
if ! command -v curl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl >/dev/null
    else
        echo; echo "[x] curl is required and no supported package manager was found." >&2
        exit 1
    fi
fi
progress "Checking dependencies" 25

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

install_from_release() {
    local tag
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    [[ -n "$tag" ]] || return 1

    echo "  Latest release: ${C_BOLD}$tag${C_RESET}"
    curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/gre"        -o "$TMP/gre"        || return 1
    curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/gre.sha256" -o "$TMP/gre.sha256" || return 1

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$TMP" && sha256sum -c gre.sha256 >/dev/null) || {
            echo "[x] Checksum verification FAILED — refusing to install." >&2
            return 1
        }
        return 0
    fi
    echo "[!] sha256sum not available; skipping checksum verification" >&2
    return 0
}

if [[ "${GRE_EDGE:-0}" == "1" ]]; then
    echo "  ${C_BOLD}GRE_EDGE=1${C_RESET} — bleeding-edge main branch (no checksum)"
    progress "Downloading gre-manager" 50
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
    progress "Downloading gre-manager" 60
else
    progress "Downloading gre-manager" 40
    if install_from_release; then
        progress "Downloading gre-manager" 55
        progress "Verifying SHA-256 checksum" 70
    else
        echo "[!] Release install unavailable; falling back to main branch (no checksum)." >&2
        curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
    fi
    progress "Verifying SHA-256 checksum" 75
fi

bash -n "$TMP/gre" 2>/dev/null || { echo; echo "[x] Downloaded script failed syntax check." >&2; exit 1; }

progress "Installing gre command" 85
cp "$TMP/gre" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# bash completion (best effort)
if [[ -d "$COMPLETION_DIR" ]]; then
    curl -fsSL "$COMPLETION_SRC" -o "$COMPLETION_DIR/gre" 2>/dev/null || true
fi
progress "Installing gre command" 100

VER="$(grep -m1 -E '^VERSION=' "$INSTALL_PATH" | cut -d'"' -f2)"
echo
printf '  %s[+] gre-manager v%s installed%s -> %s\n' "$C_GREEN" "${VER:-unknown}" "$C_RESET" "$INSTALL_PATH"
echo
printf '  %sRun it with:%s   sudo gre\n' "$C_BOLD" "$C_RESET"
echo
