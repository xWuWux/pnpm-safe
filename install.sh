#!/usr/bin/env bash
# install.sh — install pnpm-safe on the current machine
set -euo pipefail

INSTALL_DIR="${PNPM_SAFE_INSTALL_DIR:-${HOME}/.local/bin}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing pnpm-safe to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

chmod +x "$REPO_DIR/bin/pnpm-safe"
chmod +x "$REPO_DIR/bin/scan-lockfile"

# Create symlinks
ln -sf "$REPO_DIR/bin/pnpm-safe" "${INSTALL_DIR}/pnpm-safe"
ln -sf "$REPO_DIR/bin/scan-lockfile" "${INSTALL_DIR}/scan-lockfile"

echo ""
echo "✅ Installed. Make sure ${INSTALL_DIR} is on your PATH."
echo ""
echo "Usage:"
echo "  pnpm-safe add express         # intercepts pnpm add"
echo "  pnpm-safe install             # intercepts pnpm install"
echo "  scan-lockfile                 # standalone lockfile scan"
echo "  scan-lockfile --check-age     # + publish-age checks (network)"
echo "  scan-lockfile --registry-full # + full registry checks"
echo ""
echo "Environment variables:"
echo "  PNPM_SAFE_BLOCK=1             # 1=block on risk (default), 0=warn-only"
echo "  PNPM_SAFE_MIN_AGE=1440        # min package age in minutes (default: 1440=24h)"
echo "  PNPM_SAFE_CACHE_TTL=21600     # registry cache TTL in seconds (default: 6h)"
echo "  PNPM_SAFE_AGE_EXCLUDE='pkg1 pkg2'  # skip age check for these packages"
echo ""
echo "Recommended: also copy hardening/pnpm-workspace.yaml into your project root."
echo "pnpm's native minimumReleaseAge + blockExoticSubdeps are the strongest controls."
