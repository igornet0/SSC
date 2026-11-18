#!/usr/bin/env bash
# SSC VPN installer — installs `ssc` into PATH and prepares sing-box.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/ssc"

if [[ ! -x "$BIN" ]]; then
  echo "error: ssc binary not found next to install.sh" >&2
  exit 1
fi

SYSTEM=0
PREFIX=""
SKIP_SETUP=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [--system] [--prefix DIR] [--skip-setup]

  --system       Install to /usr/local/bin (may need sudo)
  --prefix DIR   Install binary into DIR
  --skip-setup   Do not download sing-box yet
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) SYSTEM=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --skip-setup) SKIP_SETUP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

ARGS=(install)
if [[ "$SYSTEM" -eq 1 ]]; then
  ARGS+=(--system)
fi
if [[ -n "$PREFIX" ]]; then
  ARGS+=(--prefix "$PREFIX")
fi
if [[ "$SKIP_SETUP" -eq 1 ]]; then
  ARGS+=(--skip-setup)
fi

# System install may need root for /usr/local/bin.
if [[ "$SYSTEM" -eq 1 && "$(id -u)" -ne 0 ]]; then
  echo "System install requires privileges — re-running with sudo…"
  exec sudo "$BIN" "${ARGS[@]}"
fi

exec "$BIN" "${ARGS[@]}"
