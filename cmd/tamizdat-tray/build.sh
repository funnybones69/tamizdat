#!/bin/bash
# Build the single-EXE tamizdat-tray for Windows amd64.
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
TRAY_DIR="$REPO_ROOT/cmd/tamizdat-tray"
TUN_DIR="$REPO_ROOT/cmd/tamizdat-tun-windows"

WINTUN_DLL="${WINTUN_DLL:-$REPO_ROOT/tools/wintun/wintun.dll}"
if [[ ! -f "$WINTUN_DLL" ]]; then
  echo "wintun.dll not found at $WINTUN_DLL (override with WINTUN_DLL=...)" >&2
  exit 1
fi

OUT="${OUT:-/tmp/tamizdat-tray.exe}"
UPX_COMPRESS="${UPX_COMPRESS:-0}"

echo "[1/5] Cross-build tamizdat-tun-windows.exe …"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags="-s -w -H windowsgui" -trimpath \
  -o "$TRAY_DIR/embed-tun.exe" "$TUN_DIR"

if [[ "$UPX_COMPRESS" == "1" ]]; then
  echo "[2/5] UPX-compress TUN engine …"
  upx --best --lzma "$TRAY_DIR/embed-tun.exe" >/dev/null
else
  echo "[2/5] Skip UPX for TUN engine (UPX_COMPRESS=0)"
fi

echo "[3/5] Copy wintun.dll into embed slot …"
cp "$WINTUN_DLL" "$TRAY_DIR/embed-wintun.dll"

echo "[4/5] Cross-build tamizdat-tray.exe …"
cd "$REPO_ROOT"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags="-s -w -H windowsgui" -trimpath \
  -o "$OUT" ./cmd/tamizdat-tray

if [[ "$UPX_COMPRESS" == "1" ]]; then
  echo "[5/5] UPX-compress tray .exe …"
  upx --best --lzma "$OUT" >/dev/null
else
  echo "[5/5] Skip UPX for tray (UPX_COMPRESS=0)"
fi

echo
echo "Done: $OUT ($(stat -c %s "$OUT") bytes)"
