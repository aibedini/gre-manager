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
progress "Checking dependencies" 100

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

download_release() { # downloads latest pinned release assets into $TMP; prints the tag first
    local tag="" attempt
    for attempt in 1 2; do
        tag="$(curl -fsSL --max-time 20 "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep -m1 '"tag_name"' | cut -d'"' -f4)"
        [[ -n "$tag" ]] && break
        (( attempt == 1 )) && sleep 3
    done
    [[ -n "$tag" ]] || return 1
    echo "  Latest release: ${C_BOLD}$tag${C_RESET}"
    for attempt in 1 2; do
        if curl -fsSL --max-time 60 "https://github.com/${REPO}/releases/download/${tag}/gre"        -o "$TMP/gre" \
        && curl -fsSL --max-time 60 "https://github.com/${REPO}/releases/download/${tag}/gre.sha256" -o "$TMP/gre.sha256" \
        && [[ -s "$TMP/gre" && -s "$TMP/gre.sha256" ]]; then
            return 0
        fi
        (( attempt == 1 )) && sleep 3
    done
    return 1
}

verify_checksum() {
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "  [!] sha256sum not available; skipping checksum verification" >&2
        return 0
    fi
    (cd "$TMP" && sha256sum -c gre.sha256 >/dev/null) || {
        echo "[x] Checksum verification FAILED — refusing to install." >&2
        return 1
    }
    return 0
}

if [[ "${GRE_EDGE:-0}" == "1" ]]; then
    echo "  ${C_BOLD}GRE_EDGE=1${C_RESET} — bleeding-edge main branch (no checksum)"
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
    progress "Downloading gre-manager (edge)" 100
else
    if download_release; then
        progress "Downloading gre-manager" 100
        verify_checksum || exit 1
        progress "Verifying SHA-256 checksum" 100
    else
        echo "  [!] Release install unavailable; falling back to main branch (no checksum)." >&2
        curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
        progress "Downloading gre-manager (main)" 100
    fi
fi

bash -n "$TMP/gre" 2>/dev/null || { echo; echo "[x] Downloaded script failed syntax check." >&2; exit 1; }

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
