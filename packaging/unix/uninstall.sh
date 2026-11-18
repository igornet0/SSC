#!/usr/bin/env bash
# SSC VPN uninstaller — removes `ssc` from the install location.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/ssc"

SYSTEM=0
PREFIX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) SYSTEM=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [--system] [--prefix DIR]"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

# Prefer already-installed ssc on PATH; fall back to bundled binary.
CMD=(ssc)
if ! command -v ssc >/dev/null 2>&1; then
  if [[ -x "$BIN" ]]; then
    CMD=("$BIN")
  else
    echo "error: ssc not found" >&2
    exit 1
  fi
fi

ARGS=(uninstall)
if [[ "$SYSTEM" -eq 1 ]]; then
  ARGS+=(--system)
fi
if [[ -n "$PREFIX" ]]; then
  ARGS+=(--prefix "$PREFIX")
fi

if [[ "$SYSTEM" -eq 1 && "$(id -u)" -ne 0 ]]; then
  exec sudo "${CMD[@]}" "${ARGS[@]}"
fi

exec "${CMD[@]}" "${ARGS[@]}"
