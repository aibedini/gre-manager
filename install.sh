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

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[x] Please run as root:  curl -fsSL .../install.sh | sudo bash" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "[*] curl not found, trying to install it..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl
    else
        echo "[x] curl is required and no supported package manager was found." >&2
        exit 1
    fi
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

install_from_release() {
    local tag
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    [[ -n "$tag" ]] || return 1

    echo "[*] Latest release: $tag"
    curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/gre"        -o "$TMP/gre"       || return 1
    curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/gre.sha256" -o "$TMP/gre.sha256" || return 1

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$TMP" && sha256sum -c gre.sha256 >/dev/null) || {
            echo "[x] Checksum verification FAILED — refusing to install." >&2
            return 1
        }
        echo "[+] SHA-256 checksum verified"
    else
        echo "[!] sha256sum not available; skipping checksum verification" >&2
    fi
    return 0
}

if [[ "${GRE_EDGE:-0}" == "1" ]]; then
    echo "[!] GRE_EDGE=1 — installing bleeding-edge main branch (no checksum)..."
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
else
    if ! install_from_release; then
        echo "[!] Release install unavailable; falling back to main branch (no checksum)." >&2
        curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/gre-manager.sh" -o "$TMP/gre"
    fi
fi

bash -n "$TMP/gre" 2>/dev/null || { echo "[x] Downloaded script failed syntax check." >&2; exit 1; }

cp "$TMP/gre" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# bash completion (best effort)
if [[ -d "$COMPLETION_DIR" ]]; then
    curl -fsSL "$COMPLETION_SRC" -o "$COMPLETION_DIR/gre" 2>/dev/null \
        && echo "[+] bash completion installed ($COMPLETION_DIR/gre)" || true
fi

VER="$(grep -m1 -E '^VERSION=' "$INSTALL_PATH" | cut -d'"' -f2)"
echo
echo "[+] Installed gre-manager v${VER:-unknown} -> $INSTALL_PATH"
echo
echo "    Run it with:   sudo gre"
echo
