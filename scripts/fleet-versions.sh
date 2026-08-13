#!/usr/bin/env bash
# Read-only fleet inventory. SSH aliases/hosts are supplied by the operator so
# this script contains no credentials or environment-specific secrets.
set -euo pipefail

if (($# == 0)); then
  cat >&2 <<'EOF'
usage: scripts/fleet-versions.sh HOST [HOST...]

Examples:
  scripts/fleet-versions.sh gateway ru2 sync2 router
  scripts/fleet-versions.sh tam-gateway tam-ru2 tam-sync2 tam-router

The command is read-only. New servers report embedded JSON build identity;
legacy servers are identified by executable path and SHA-256.
EOF
  exit 2
fi

printf 'host\tversion\tbuild_id\tcommit\tdirty\tsha256\tpath\n'
for host in "$@"; do
  if ! raw=$(ssh -o BatchMode=yes -o ConnectTimeout=7 "$host" 'sh -s' <<'REMOTE'
set -eu
for path in \
  /usr/bin/tamizdat-server-app \
  /usr/local/bin/tamizdat-server-app \
  /usr/local/tamizdat/bin/tamizdat-server-app; do
  [ -x "$path" ] || continue
  sha=unknown
  if command -v sha256sum >/dev/null 2>&1; then
    sha=$(sha256sum "$path" | awk '{print $1}')
  fi
  if json=$($path --version-json 2>/dev/null); then
    printf 'json\t%s\t%s\n' "$sha" "$path"
    printf '%s\n' "$json"
  else
    printf 'legacy\t%s\t%s\n' "$sha" "$path"
  fi
  exit 0
done
printf 'missing\tunknown\tnot-found\n'
REMOTE
  ); then
    printf '%s\tunreachable\tunknown\tunknown\tunknown\tunknown\tunknown\n' "$host"
    continue
  fi

  header=${raw%%$'\n'*}
  kind=${header%%$'\t'*}
  rest=${header#*$'\t'}
  sha=${rest%%$'\t'*}
  path=${rest#*$'\t'}
  if [[ "$kind" == json ]]; then
    json=${raw#*$'\n'}
    fields=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print("\t".join(str(d.get(k,"unknown")).lower() if k=="dirty" else str(d.get(k,"unknown")) for k in ("version","build_id","commit","dirty")))' <<<"$json" 2>/dev/null || printf 'invalid-json\tunknown\tunknown\tunknown')
    printf '%s\t%s\t%s\t%s\n' "$host" "$fields" "$sha" "$path"
  elif [[ "$kind" == legacy ]]; then
    printf '%s\tlegacy\tsha256-%s\tunknown\tunknown\t%s\t%s\n' "$host" "${sha:0:12}" "$sha" "$path"
  else
    printf '%s\tmissing\tunknown\tunknown\tunknown\tunknown\t%s\n' "$host" "$path"
  fi
done
