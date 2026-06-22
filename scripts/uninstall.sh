#!/usr/bin/env bash
#
# Tamizdat uninstaller. Stops + removes services, app directory, management
# command and compatibility symlinks. Config/keys/DB under /etc/tamizdat are
# KEPT unless you pass --purge.
#
#   ./uninstall.sh           # remove services + app binaries, keep /etc/tamizdat
#   ./uninstall.sh --purge   # also wipe /etc/tamizdat (keys, DB, certs) + logs
set -euo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'
log() { echo -e "${yellow}==>${plain} $*"; }

[[ ${EUID} -eq 0 ]] || { echo -e "${red}Fatal:${plain} run as root" >&2; exit 1; }

APP_DIR=${TAMIZDAT_APP_DIR:-/usr/local/tamizdat}
COMPAT_BIN_DIR=${TAMIZDAT_COMPAT_BIN_DIR:-/usr/local/bin}
COMMAND_BIN=${TAMIZDAT_COMMAND_BIN:-/usr/bin/tamizdat}
ETC_DIR=${TAMIZDAT_ETC_DIR:-/etc/tamizdat}
SERVER_SERVICE=${TAMIZDAT_SERVER_SERVICE_NAME:-tamizdat-server-app}
PANEL_SERVICE=${TAMIZDAT_PANEL_SERVICE_NAME:-tamizdat-panel}
SERVER_UNIT=${SERVER_SERVICE%.service}.service
PANEL_UNIT=${PANEL_SERVICE%.service}.service
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

case "${APP_DIR}" in
  ""|"/"|"/usr"|"/usr/"|"/usr/local"|"/usr/local/"|"/usr/local/bin"|"/usr/local/bin/"|"/etc"|"/etc/"|"/bin"|"/bin/"|"/sbin"|"/sbin/")
    echo -e "${red}Fatal:${plain} refusing unsafe TAMIZDAT_APP_DIR=${APP_DIR}" >&2
    exit 1
    ;;
esac

log "Stopping + disabling services..."
systemctl disable --now "${PANEL_UNIT}" "${SERVER_UNIT}" >/dev/null 2>&1 || true

log "Removing systemd units and generated drop-ins..."
rm -f "/etc/systemd/system/${SERVER_UNIT}" "/etc/systemd/system/${PANEL_UNIT}"
rm -rf "/etc/systemd/system/${SERVER_UNIT}.d" "/etc/systemd/system/${PANEL_UNIT}.d"
systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true

log "Removing app directory and commands..."
rm -rf "${APP_DIR}"
rm -f "${COMMAND_BIN}"
rm -f "${COMPAT_BIN_DIR}/tamizdat-server-app" \
      "${COMPAT_BIN_DIR}/tamizdat-panel.py" \
      "${COMPAT_BIN_DIR}/tamizdat-client"

if [[ ${PURGE} -eq 1 ]]; then
  log "Purging ${ETC_DIR} and logs..."
  rm -rf "${ETC_DIR}" /var/log/tamizdat
  echo -e "${green}Tamizdat fully removed (purged).${plain}"
else
  echo -e "${green}Tamizdat removed.${plain} Config kept at ${ETC_DIR} (use --purge to wipe)."
fi
