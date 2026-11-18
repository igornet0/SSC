#!/usr/bin/env bash
# Build SSC.pkg + DMG for macOS.
#
# Usage:
#   packaging/macos/build-dmg.sh <ssc-binary> <version> <arch-tag> <output-dmg>
set -euo pipefail

BIN_SRC="${1:?ssc binary path}"
VERSION="${2:?version}"
ARCH_TAG="${3:?arch tag e.g. macos-arm64}"
OUT_DMG="${4:?output dmg path}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MACOS_DIR="$ROOT/packaging/macos"
OUT_DIR="$(cd "$(dirname "$OUT_DMG")" && pwd)"
OUT_NAME="$(basename "$OUT_DMG")"
WORK="$ROOT/dist/macos-build/$ARCH_TAG"

rm -rf "$WORK"
mkdir -p "$WORK/payload/usr/local/bin" "$WORK/scripts" "$WORK/dmg" "$OUT_DIR"

case "$ARCH_TAG" in
  *arm64*) PKG_ID="com.ssc.cli.arm64" ;;
  *amd64*|*x86_64*) PKG_ID="com.ssc.cli.amd64" ;;
  *) PKG_ID="com.ssc.cli" ;;
esac

cp "$BIN_SRC" "$WORK/payload/usr/local/bin/ssc"
chmod 755 "$WORK/payload/usr/local/bin/ssc"
cp "$MACOS_DIR/uninstall.sh" "$WORK/payload/usr/local/bin/ssc-uninstall"
chmod 755 "$WORK/payload/usr/local/bin/ssc-uninstall"

cp "$MACOS_DIR/scripts/postinstall" "$WORK/scripts/postinstall"
chmod 755 "$WORK/scripts/postinstall"

PKG="$WORK/Install SSC.pkg"
pkgbuild \
  --root "$WORK/payload" \
  --scripts "$WORK/scripts" \
  --identifier "$PKG_ID" \
  --version "$VERSION" \
  --install-location / \
  "$PKG"

cp "$PKG" "$WORK/dmg/Install SSC.pkg"
cp "$MACOS_DIR/Uninstall SSC.command" "$WORK/dmg/Uninstall SSC.command"
chmod 755 "$WORK/dmg/Uninstall SSC.command"
cp "$MACOS_DIR/README.txt" "$WORK/dmg/README.txt"
cp "$MACOS_DIR/uninstall.sh" "$WORK/dmg/ssc-uninstall"
chmod 755 "$WORK/dmg/ssc-uninstall"

VOLNAME="SSC $VERSION"
rm -f "$OUT_DIR/$OUT_NAME"
hdiutil create \
  -volname "$VOLNAME" \
  -srcfolder "$WORK/dmg" \
  -ov \
  -format UDZO \
  "$OUT_DIR/$OUT_NAME" >/dev/null

# Keep a copy of the .pkg next to the DMG for CI / direct install.
cp "$PKG" "$OUT_DIR/ssc-${ARCH_TAG}-${VERSION}.pkg"

echo "==> $OUT_DIR/$OUT_NAME"
echo "    pkg: $OUT_DIR/ssc-${ARCH_TAG}-${VERSION}.pkg  (id: $PKG_ID)"
ls -lh "$OUT_DIR/$OUT_NAME" "$OUT_DIR/ssc-${ARCH_TAG}-${VERSION}.pkg"
