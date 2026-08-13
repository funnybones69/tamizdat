#!/usr/bin/env bash
# Source this file from build/package jobs to stamp every artifact consistently.
# Defaults are reproducible for a clean commit; CI may override any value.

_tamizdat_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ -z "${TAMIZDAT_VERSION:-}" ]]; then
  TAMIZDAT_VERSION=$(tr -d '\r\n[:space:]' < "${_tamizdat_root}/VERSION")
fi
if [[ -z "${TAMIZDAT_COMMIT:-}" ]]; then
  TAMIZDAT_COMMIT=$(git -C "${_tamizdat_root}" rev-parse HEAD 2>/dev/null || printf unknown)
fi
if [[ -z "${TAMIZDAT_BUILD_TIME:-}" ]]; then
  TAMIZDAT_BUILD_TIME=$(git -C "${_tamizdat_root}" show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
fi

_tamizdat_short=${TAMIZDAT_COMMIT:0:12}
if [[ -z "${TAMIZDAT_BUILD_ID:-}" ]]; then
  TAMIZDAT_BUILD_ID="${TAMIZDAT_VERSION}-${_tamizdat_short}"
  if [[ -n "$(git -C "${_tamizdat_root}" status --porcelain --untracked-files=normal -- . ':(exclude)dist' 2>/dev/null)" ]]; then
    TAMIZDAT_BUILD_ID="${TAMIZDAT_BUILD_ID}-dirty"
  fi
fi

_tamizdat_pkg=github.com/funnybones69/tamizdat/internal/buildinfo
TAMIZDAT_LDFLAGS="-s -w -X ${_tamizdat_pkg}.Version=${TAMIZDAT_VERSION} -X ${_tamizdat_pkg}.BuildID=${TAMIZDAT_BUILD_ID} -X ${_tamizdat_pkg}.Commit=${TAMIZDAT_COMMIT} -X ${_tamizdat_pkg}.BuildTime=${TAMIZDAT_BUILD_TIME}"

export TAMIZDAT_VERSION TAMIZDAT_BUILD_ID TAMIZDAT_COMMIT TAMIZDAT_BUILD_TIME TAMIZDAT_LDFLAGS
unset _tamizdat_root _tamizdat_short _tamizdat_pkg
