#!/usr/bin/env bash
# Build a S-UI-style Linux release tarball for Tamizdat.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-$(go env GOARCH)}
OUT_DIR=${TAMIZDAT_DIST_DIR:-${ROOT}/dist}
STAGE=$(mktemp -d /tmp/tamizdat-package.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

[[ "$GOOS" == "linux" ]] || { echo "package-linux.sh only builds linux assets (GOOS=$GOOS)" >&2; exit 1; }
case "$GOARCH" in
  amd64|arm64) ;;
  *) echo "unsupported GOARCH for public binary release: $GOARCH" >&2; exit 1 ;;
esac

cd "$ROOT"
mkdir -p "$OUT_DIR" "$STAGE/tamizdat"

copy_install_script() {
  local dst=$1
  install -m 0755 "$ROOT/scripts/install.sh" "$dst"
  if [[ -n "${TAMIZDAT_BAKE_RELEASE_BASE:-}" ]]; then
    python3 - "$dst" "$TAMIZDAT_BAKE_RELEASE_BASE" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
base = sys.argv[2]
text = path.read_text()
old = 'RELEASE_BASE=${TAMIZDAT_RELEASE_BASE:-https://github.com/funnybones69/tamizdat/releases/latest/download}'
new = f'RELEASE_BASE=${{TAMIZDAT_RELEASE_BASE:-{base}}}'
if old not in text:
    raise SystemExit(f'cannot find RELEASE_BASE line in {path}')
path.write_text(text.replace(old, new, 1))
PY
  fi
}

echo "== building server/client for ${GOOS}/${GOARCH} =="
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build -trimpath -ldflags='-s -w' -o "$STAGE/tamizdat/tamizdat-server-app" ./cmd/tamizdat-server
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build -trimpath -ldflags='-s -w' -o "$STAGE/tamizdat/tamizdat-client" ./cmd/tamizdat-client

cp "$ROOT/panel/tamizdat-panel.py" "$STAGE/tamizdat/tamizdat-panel.py"
copy_install_script "$STAGE/tamizdat/install.sh"
cp "$ROOT/scripts/uninstall.sh" "$STAGE/tamizdat/uninstall.sh"
cp "$ROOT/scripts/tamizdat" "$STAGE/tamizdat/tamizdat"
cp "$ROOT/README.md" "$ROOT/INSTALL.md" "$ROOT/OPENWRT.md" "$ROOT/LICENSE" "$STAGE/tamizdat/"

chmod 0755 "$STAGE/tamizdat/tamizdat-server-app" \
           "$STAGE/tamizdat/tamizdat-client" \
           "$STAGE/tamizdat/tamizdat-panel.py" \
           "$STAGE/tamizdat/install.sh" \
           "$STAGE/tamizdat/uninstall.sh" \
           "$STAGE/tamizdat/tamizdat"
chmod 0644 "$STAGE/tamizdat/README.md" "$STAGE/tamizdat/INSTALL.md" "$STAGE/tamizdat/OPENWRT.md" "$STAGE/tamizdat/LICENSE"

asset="$OUT_DIR/tamizdat-${GOOS}-${GOARCH}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2026-01-01' -C "$STAGE" -czf "$asset" tamizdat
copy_install_script "$OUT_DIR/install.sh"
"$ROOT/scripts/package-checksums.sh" >/dev/null
sha256sum "$asset" "$OUT_DIR/install.sh"
echo "wrote $asset"
echo "wrote $OUT_DIR/install.sh"
echo "wrote $OUT_DIR/SHA256SUMS"
