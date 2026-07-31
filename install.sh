#!/usr/bin/env bash
#
# install.sh — install gre-manager as the `gre` command
# https://github.com/aibedini/gre-manager
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aibedini/gre-manager/main/install.sh | sudo bash
#
set -euo pipefail

INSTALL_PATH="/usr/local/sbin/gre"
RAW_URL="https://raw.githubusercontent.com/aibedini/gre-manager/main/gre-manager.sh"

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

echo "[*] Downloading gre-manager..."
curl -fsSL "$RAW_URL" -o "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

VER="$(grep -m1 -E '^VERSION=' "$INSTALL_PATH" | cut -d'"' -f2)"
echo "[+] Installed gre-manager v${VER:-unknown} -> $INSTALL_PATH"
echo
echo "    Run it with:   sudo gre"
echo
