#!/usr/bin/env bash
# Build the Windows tray release artifact.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GOOS=${GOOS:-windows}
GOARCH=${GOARCH:-amd64}
DIST=${DIST:-"${ROOT}/dist"}
WORK=${WORK:-"${ROOT}/build/windows-${GOARCH}"}
WINTUN_VERSION=${WINTUN_VERSION:-0.14.1}
WINTUN_SHA256=${WINTUN_SHA256:-e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce}
UPX_COMPRESS=${UPX_COMPRESS:-0}

if [[ "${GOOS}" != "windows" ]]; then
  echo "package-windows.sh only supports GOOS=windows" >&2
  exit 2
fi
if [[ "${GOARCH}" != "amd64" ]]; then
  echo "package-windows.sh currently supports GOARCH=amd64 only (Wintun asset is amd64)" >&2
  exit 2
fi

mkdir -p "${DIST}" "${WORK}"
log() { printf '[package-windows] %s\n' "$*" >&2; }

WINTUN_DLL=${WINTUN_DLL:-}
WINTUN_LICENSE=${WINTUN_LICENSE:-}
if [[ -z "${WINTUN_DLL}" ]]; then
  cache="${WORK}/wintun-${WINTUN_VERSION}.zip"
  extract="${WORK}/wintun-${WINTUN_VERSION}"
  if [[ ! -s "${cache}" ]]; then
    log "download Wintun ${WINTUN_VERSION}"
    python3 - <<PY
import urllib.request
url='https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip'
urllib.request.urlretrieve(url, ${cache@Q})
PY
  fi
  rm -rf "${extract}"
  mkdir -p "${extract}"
  python3 - <<PY
import zipfile
with zipfile.ZipFile(${cache@Q}) as z:
    z.extractall(${extract@Q})
PY
  WINTUN_DLL="${extract}/wintun/bin/amd64/wintun.dll"
  WINTUN_LICENSE="${extract}/wintun/LICENSE.txt"
fi
[[ -s "${WINTUN_DLL}" ]] || { echo "wintun.dll not found: ${WINTUN_DLL}" >&2; exit 1; }
[[ -s "${WINTUN_LICENSE}" ]] || { echo "Wintun license not found; set WINTUN_LICENSE" >&2; exit 1; }
actual=$(sha256sum "${WINTUN_DLL}" | awk '{print $1}')
if [[ "${actual}" != "${WINTUN_SHA256}" ]]; then
  echo "wintun.dll sha256 mismatch: got ${actual}, want ${WINTUN_SHA256}" >&2
  exit 1
fi

log "build single-exe Windows tray"
OUT="${WORK}/tamizdat-tray.exe" WINTUN_DLL="${WINTUN_DLL}" UPX_COMPRESS="${UPX_COMPRESS}" \
  "${ROOT}/cmd/tamizdat-tray/build.sh"

install -m 0644 "${ROOT}/LICENSE" "${WORK}/LICENSE.txt"
install -m 0644 "${WINTUN_LICENSE}" "${WORK}/LICENSE-WINTUN.txt"
install -m 0644 "${ROOT}/cmd/tamizdat-tray/config.example.uri" "${WORK}/config.example.uri"
cat > "${WORK}/README-WINDOWS.txt" <<'EOF'
Tamizdat Windows tray client

Included files:
- tamizdat-tray.exe   single Windows GUI tray client; TUN engine and wintun.dll are embedded
- config.example.uri  example profile list; copy to config.uri before use
- LICENSE.txt         Tamizdat license
- LICENSE-WINTUN.txt  Wintun license for the embedded driver DLL

Usage:
1. Copy config.example.uri to config.uri next to tamizdat-tray.exe.
2. Replace examples with generated tamizdat:// profile URI lines from the panel.
3. Run tamizdat-tray.exe as Administrator.
4. Use the tray menu to connect, disconnect, show logs, or exit.

On first start the binary extracts the embedded TUN engine and wintun.dll to
%LOCALAPPDATA%\Tamizdat-Tray\. Later starts rewrite them only when SHA-256 differs.

Logs:
- tamizdat-tray.log is written next to tamizdat-tray.exe.
- It rotates at 5 MiB by replacing the same file; no .1/.2 backup logs are kept.
- Standard verbose TUN messages are suppressed. The log keeps connect/stop state,
  route/adapter/DNS readiness, warnings, errors, timeouts, and failures.
- Full tamizdat:// profile URIs, pubkeys, and short IDs are redacted before logging.
EOF

ZIP="${DIST}/tamizdat-windows-${GOARCH}.zip"
rm -f "${ZIP}"
WORK="${WORK}" ZIP="${ZIP}" python3 - <<'PY'
import os, pathlib, zipfile
work = pathlib.Path(os.environ['WORK'])
zip_path = pathlib.Path(os.environ['ZIP'])
include = [
    'tamizdat-tray.exe',
    'config.example.uri',
    'README-WINDOWS.txt',
    'LICENSE.txt',
    'LICENSE-WINTUN.txt',
]
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in include:
        z.write(work / name, f'tamizdat-windows-amd64/{name}')
PY

"${ROOT}/scripts/package-checksums.sh" >/dev/null
log "wrote ${ZIP}"
sha256sum "${ZIP}"
file "${WORK}/tamizdat-tray.exe" || true
