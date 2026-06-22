#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST=${TAMIZDAT_DIST_DIR:-${ROOT}/dist}
mkdir -p "${DIST}"
cd "${DIST}"

assets=()
for pattern in install.sh 'tamizdat-linux-'*.tar.gz 'tamizdat-windows-'*.zip 'tamizdat-openwrt-luci-'*.tar; do
  for f in ${pattern}; do
    [[ -f "${f}" ]] && assets+=("${f}")
  done
done

if [[ ${#assets[@]} -eq 0 ]]; then
  echo "no release assets found in ${DIST}" >&2
  exit 1
fi
printf '%s\0' "${assets[@]}" | sort -z | xargs -0 sha256sum > SHA256SUMS
printf 'wrote %s/SHA256SUMS\n' "${DIST}"
