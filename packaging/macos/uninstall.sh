#!/bin/bash
# SSC uninstall — removes CLI installed by the macOS PKG.
# Usage: sudo ssc-uninstall [--purge]
#   --purge  also delete SSC config + sing-box under the user's Application Support
set -euo pipefail

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      echo "Usage: sudo ssc-uninstall [--purge]"
      echo "  --purge  remove profiles and sing-box from Application Support"
      exit 0
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-running with sudo…"
  exec sudo "$0" "$@"
fi

remove_file() {
  local f="$1"
  if [[ -e "$f" || -L "$f" ]]; then
    rm -f "$f"
    echo "removed $f"
  fi
}

remove_file /usr/local/bin/ssc
remove_file /usr/local/bin/ssc-uninstall
remove_file /etc/sudoers.d/ssc

# Drop the managed `ssc.lan` hosts line (added by `ssc privileges install`).
if grep -q '# ssc (managed)$' /etc/hosts 2>/dev/null; then
  sed -i '' '/# ssc (managed)$/d' /etc/hosts
  dscacheutil -flushcache 2>/dev/null || true
  killall -HUP mDNSResponder 2>/dev/null || true
  echo "removed ssc.lan from /etc/hosts"
fi

# Forget receipts from either arch package id.
for id in com.ssc.cli com.ssc.cli.arm64 com.ssc.cli.amd64; do
  if pkgutil --pkg-info "$id" >/dev/null 2>&1; then
    pkgutil --forget "$id" >/dev/null || true
    echo "forgot package $id"
  fi
done

if [[ "$PURGE" -eq 1 ]]; then
  CONSOLE_USER="$(stat -f%Su /dev/console 2>/dev/null || true)"
  if [[ -n "${CONSOLE_USER:-}" && "$CONSOLE_USER" != "root" ]]; then
    HOME_DIR="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [[ -z "${HOME_DIR:-}" ]]; then
      HOME_DIR="/Users/$CONSOLE_USER"
    fi
    CFG="$HOME_DIR/Library/Application Support/ssc"
    if [[ -d "$CFG" ]]; then
      rm -rf "$CFG"
      echo "removed $CFG"
    fi
  fi
  # Also clear root config if setup ran as root.
  if [[ -d "/var/root/Library/Application Support/ssc" ]]; then
    rm -rf "/var/root/Library/Application Support/ssc"
    echo "removed /var/root/Library/Application Support/ssc"
  fi
fi

echo "SSC uninstalled."
if [[ "$PURGE" -eq 0 ]]; then
  echo "Profiles/sing-box kept. To remove them too: sudo ssc-uninstall --purge"
fi
