#!/bin/bash
# Builds the Windows GUI as a single self-contained .exe with the TUN
# child process and wintun.dll embedded.
#
# Output: /tmp/tamizdat-gui-singleexe.exe (UPX-compressed, ~7 MB)
#
# Requires on the build host:
#   - go (cross-compile to GOOS=windows GOARCH=amd64)
#   - upx 4.x
#   - wintun.dll (amd64) somewhere — set WINTUN_DLL env var
#
# Run from repo root:
#   WINTUN_DLL=/path/to/wintun.dll ./cmd/tamizdat-windows-gui/build-singleexe.sh

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
GUI_DIR="$REPO_ROOT/cmd/tamizdat-windows-gui"
TUN_DIR="$REPO_ROOT/cmd/tamizdat-tun-windows"
OUT=/tmp/tamizdat-gui-singleexe.exe

if [[ -z "${WINTUN_DLL:-}" ]]; then
  echo "set WINTUN_DLL=/path/to/wintun.dll" >&2
  exit 1
fi
if [[ ! -f "$WINTUN_DLL" ]]; then
  echo "WINTUN_DLL not found: $WINTUN_DLL" >&2
  exit 1
fi

echo "[1/4] Cross-build TUN (Windows amd64, stripped)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags="-s -w -H windowsgui" -trimpath \
  -o "$GUI_DIR/embed-tun.exe" "$TUN_DIR"

echo "[2/4] UPX-compress TUN..."
upx --best --lzma "$GUI_DIR/embed-tun.exe" >/dev/null

echo "[3/4] Copy wintun.dll into embed slot..."
cp "$WINTUN_DLL" "$GUI_DIR/embed-wintun.dll"

echo "[4/4] Build GUI with embedded TUN + DLL, then UPX..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags="-s -w -H windowsgui" -trimpath \
  -o "$OUT" "$GUI_DIR"
upx --best --lzma "$OUT" >/dev/null

echo
echo "Done: $OUT ($(stat -c %s "$OUT") bytes)"
