#!/bin/bash
# Double-clickable uninstaller for Finder (shipped on the DMG).
cd "$(dirname "$0")"
echo "======================================"
echo "  SSC VPN — Uninstall"
echo "======================================"
echo
echo "This removes /usr/local/bin/ssc (admin password required)."
echo
read -r -p "Also delete profiles and sing-box? [y/N] " ans
echo
PURGE_ARGS=()
case "$ans" in
  y|Y|yes|YES) PURGE_ARGS=(--purge) ;;
esac

if [[ -x /usr/local/bin/ssc-uninstall ]]; then
  sudo /usr/local/bin/ssc-uninstall "${PURGE_ARGS[@]}"
elif [[ -x ./ssc-uninstall ]]; then
  sudo ./ssc-uninstall "${PURGE_ARGS[@]}"
else
  echo "error: ssc-uninstall not found (is SSC installed?)" >&2
  read -r -p "Press Enter to close…"
  exit 1
fi

echo
read -r -p "Press Enter to close…"
