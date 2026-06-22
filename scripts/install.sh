#!/usr/bin/env bash
#
# Tamizdat installer — release-bundle first, GitHub Release fallback.
#
# S-UI-style user flow:
#   curl -fsSL https://github.com/funnybones69/tamizdat/releases/latest/download/install.sh -o install.sh && sudo bash install.sh
# or from a release tarball:
#   tar xf tamizdat-linux-amd64.tar.gz && cd tamizdat && sudo ./install.sh
#
# Release bundle shape:
#   tamizdat/
#     tamizdat-server-app
#     tamizdat-client
#     tamizdat-panel.py
#     tamizdat              # management command
#     install.sh
#     uninstall.sh
#     LICENSE
#
# Defaults stay intentionally safer than S-UI:
#   - server     -> 0.0.0.0:443
#   - panel      -> 127.0.0.1:random + random URL base path
#   - admin pass -> random if left blank
#   - two systemd services remain: server + panel
set -euo pipefail

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; plain='\033[0m'
log()  { echo -e "${yellow}==>${plain} $*"; }
ok()   { echo -e "${green}$*${plain}"; }
warn() { echo -e "${yellow}WARN:${plain} $*" >&2; }
die()  { echo -e "${red}Fatal:${plain} $*" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

APP_DIR=${TAMIZDAT_APP_DIR:-/usr/local/tamizdat}
BIN_DIR=${TAMIZDAT_BIN_DIR:-${APP_DIR}/bin}
PANEL_DIR=${TAMIZDAT_PANEL_DIR:-${APP_DIR}/panel}
SCRIPTS_DIR=${TAMIZDAT_SCRIPTS_DIR:-${APP_DIR}/scripts}
COMPAT_BIN_DIR=${TAMIZDAT_COMPAT_BIN_DIR:-/usr/local/bin}
COMMAND_BIN=${TAMIZDAT_COMMAND_BIN:-/usr/bin/tamizdat}
ETC_DIR=${TAMIZDAT_ETC_DIR:-/etc/tamizdat}
DB_PATH=${TAMIZDAT_DB_PATH:-${ETC_DIR}/data.db}
SERVER_SERVICE=${TAMIZDAT_SERVER_SERVICE_NAME:-tamizdat-server-app}
PANEL_SERVICE=${TAMIZDAT_PANEL_SERVICE_NAME:-tamizdat-panel}
SERVER_UNIT=${SERVER_SERVICE%.service}.service
PANEL_UNIT=${PANEL_SERVICE%.service}.service
SERVER_PIDFILE=${TAMIZDAT_SERVER_PIDFILE:-/run/${SERVER_SERVICE%.service}.pid}
SERVER_BIN=${BIN_DIR}/tamizdat-server-app
CLIENT_BIN=${BIN_DIR}/tamizdat-client
PANEL_BIN=${PANEL_DIR}/tamizdat-panel.py
MANAGER_BIN=${SCRIPTS_DIR}/tamizdat
UNINSTALL_BIN=${SCRIPTS_DIR}/uninstall.sh
RELEASE_BASE=${TAMIZDAT_RELEASE_BASE:-https://github.com/funnybones69/tamizdat/releases/latest/download}
INSTALL_CLIENT=${TAMIZDAT_INSTALL_CLIENT:-1}
BUNDLE_DIR=""

need_root() { [[ ${EUID} -eq 0 ]] || die "run as root"; }
require_linux_systemd() {
  [[ "$(uname -s)" == "Linux" ]] || die "Linux only"
  command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl required"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported CPU arch: $(uname -m)" ;;
  esac
}

# Retry apt-get to ride out the dpkg lock held by cloud-init /
# unattended-upgrades on first boot (common on fresh VPS images).
apt_get_retry() {
  local i
  for i in $(seq 1 60); do
    if DEBIAN_FRONTEND=noninteractive apt-get "$@"; then return 0; fi
    log "apt/dpkg busy (lock held), retry ${i}/60 in 5s..."
    sleep 5
  done
  die "apt-get still locked after ~5 min; another package operation may be running"
}

install_base_deps() {
  log "Installing runtime dependencies (python3, openssl, ca-certificates, tar)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt_get_retry update -q
    apt_get_retry install -y -q ca-certificates openssl python3 tar
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates openssl python3 tar
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates openssl python3 tar
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates openssl python tar
  else
    die "unsupported package manager; install python3 + openssl + tar manually"
  fi
  command -v python3 >/dev/null 2>&1 || die "python3 not available after install"
  command -v tar >/dev/null 2>&1 || die "tar not available after install"
}

# download_file <url> <dest> — curl, then wget, then python3 urllib.
download_file() {
  local url=$1 dest=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "${dest}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${dest}" "${url}"
  else
    python3 - "$url" "$dest" <<'PY'
import sys, urllib.request
url, dest = sys.argv[1], sys.argv[2]
urllib.request.urlretrieve(url, dest)
PY
  fi
}

candidate() {
  local p
  for p in "$@"; do
    [[ -n "${p}" && -s "${p}" ]] && { printf '%s\n' "${p}"; return 0; }
  done
  return 1
}

bundle_is_complete() {
  local dir=$1
  [[ -d "${dir}" ]] || return 1
  candidate "${dir}/tamizdat-server-app" "${dir}/tamizdat-server-app-linux-${ARCH}" >/dev/null || return 1
  candidate "${dir}/tamizdat-panel.py" "${dir}/panel/tamizdat-panel.py" >/dev/null || return 1
  candidate "${dir}/tamizdat" "${dir}/scripts/tamizdat" >/dev/null || return 1
  candidate "${dir}/uninstall.sh" "${dir}/scripts/uninstall.sh" >/dev/null || return 1
  if [[ "${INSTALL_CLIENT}" == "1" ]]; then
    candidate "${dir}/tamizdat-client" "${dir}/tamizdat-client-linux-${ARCH}" >/dev/null || return 1
  fi
}

install_info_value() {
  local key=$1 file=${ETC_DIR}/install-info.txt
  [[ -s "${file}" ]] || return 0
  awk -v key="${key}" '{
    for (i = 1; i <= NF; i++) {
      split($i, a, "=");
      if (a[1] == key) { sub("^[^=]*=", "", $i); print $i; exit }
    }
  }' "${file}" 2>/dev/null || true
}

find_local_bundle() {
  local dir
  for dir in "${SCRIPT_DIR}" "${SCRIPT_DIR}/.."; do
    if bundle_is_complete "${dir}"; then
      BUNDLE_DIR=$(cd "${dir}" && pwd)
      return 0
    fi
  done
  return 1
}

download_release_bundle() {
  [[ -n "${BUNDLE_DIR}" ]] && return 0
  local dl_dir tarball cand local_tarball
  dl_dir=$(mktemp -d /tmp/tamizdat-dl.XXXXXX)
  tarball="${dl_dir}/tamizdat-linux-${ARCH}.tar.gz"
  for local_tarball in \
      "${SCRIPT_DIR}/tamizdat-linux-${ARCH}.tar.gz" \
      "${SCRIPT_DIR}/../tamizdat-linux-${ARCH}.tar.gz"; do
    if [[ -s "${local_tarball}" ]]; then
      log "Using local release bundle ${local_tarball}"
      cp "${local_tarball}" "${tarball}"
      break
    fi
  done
  if [[ ! -s "${tarball}" ]]; then
    log "Downloading release bundle tamizdat-linux-${ARCH}.tar.gz..."
    download_file "${RELEASE_BASE}/tamizdat-linux-${ARCH}.tar.gz" "${tarball}" || return 1
  fi
  tar -xzf "${tarball}" -C "${dl_dir}"
  for cand in "${dl_dir}/tamizdat" "${dl_dir}"; do
    if bundle_is_complete "${cand}"; then
      BUNDLE_DIR=${cand}
      return 0
    fi
  done
  die "release bundle did not contain a complete tamizdat/ directory"
}

asset_from_release() {
  local name=$1 out=$2 label=$3
  log "Downloading ${label} from releases..."
  download_file "${RELEASE_BASE}/${name}" "${out}" || return 1
  [[ -s "${out}" ]]
}

locate_sources() {
  local dl_dir
  # A complete extracted release bundle is trusted as a unit. A standalone
  # installer should not accidentally mix in stale files from its working
  # directory; if there is no complete bundle next to it, download the bundle
  # before considering legacy individual-asset fallbacks.
  find_local_bundle || true

  # --- server binary ---
  if [[ -n "${TAMIZDAT_SERVER_BIN_SRC:-}" ]]; then
    SERVER_SRC=${TAMIZDAT_SERVER_BIN_SRC}
  elif [[ -n "${BUNDLE_DIR}" ]]; then
    SERVER_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-server-app" "${BUNDLE_DIR}/tamizdat-server-app-linux-${ARCH}")
  elif download_release_bundle 2>/dev/null; then
    SERVER_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-server-app" "${BUNDLE_DIR}/tamizdat-server-app-linux-${ARCH}")
  elif SERVER_SRC=$(candidate \
      "${SCRIPT_DIR}/tamizdat-server-app" \
      "${SCRIPT_DIR}/tamizdat-server-app-linux-${ARCH}" \
      "${SCRIPT_DIR}/bin/tamizdat-server-app" \
      "${SCRIPT_DIR}/../tamizdat-server-app" \
      "${SCRIPT_DIR}/../bin/tamizdat-server-app" 2>/dev/null); then
    warn "Using individual local server binary fallback from ${SERVER_SRC}; release bundle was not available"
  else
    dl_dir=$(mktemp -d /tmp/tamizdat-dl.XXXXXX)
    asset_from_release "tamizdat-server-app-linux-${ARCH}" "${dl_dir}/tamizdat-server-app" "server binary (linux/${ARCH})" \
      || die "failed to download server binary; ship it in tamizdat-linux-${ARCH}.tar.gz or set TAMIZDAT_SERVER_BIN_SRC"
    SERVER_SRC="${dl_dir}/tamizdat-server-app"
  fi
  [[ -s "${SERVER_SRC}" ]] || die "server binary not found at ${SERVER_SRC}"

  # --- client binary (installed by default for S-UI-like all-in-one Linux package UX) ---
  if [[ "${INSTALL_CLIENT}" == "1" ]]; then
    if [[ -n "${TAMIZDAT_CLIENT_BIN_SRC:-}" ]]; then
      CLIENT_SRC=${TAMIZDAT_CLIENT_BIN_SRC}
    elif [[ -n "${BUNDLE_DIR}" ]] && CLIENT_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-client" "${BUNDLE_DIR}/tamizdat-client-linux-${ARCH}" 2>/dev/null); then
      true
    elif CLIENT_SRC=$(candidate \
        "${SCRIPT_DIR}/tamizdat-client" \
        "${SCRIPT_DIR}/tamizdat-client-linux-${ARCH}" \
        "${SCRIPT_DIR}/bin/tamizdat-client" \
        "${SCRIPT_DIR}/../tamizdat-client" \
        "${SCRIPT_DIR}/../bin/tamizdat-client" 2>/dev/null); then
      true
    else
      [[ -n "${BUNDLE_DIR}" ]] || download_release_bundle 2>/dev/null || true
      if [[ -n "${BUNDLE_DIR}" ]] && CLIENT_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-client" "${BUNDLE_DIR}/tamizdat-client-linux-${ARCH}" 2>/dev/null); then
        true
      else
        dl_dir=${dl_dir:-$(mktemp -d /tmp/tamizdat-dl.XXXXXX)}
        asset_from_release "tamizdat-client-linux-${ARCH}" "${dl_dir}/tamizdat-client" "Linux client (linux/${ARCH})" \
          || die "failed to download Linux client; ship it in the release bundle, upload tamizdat-client-linux-${ARCH}, or set TAMIZDAT_INSTALL_CLIENT=0"
        CLIENT_SRC="${dl_dir}/tamizdat-client"
      fi
    fi
    [[ -s "${CLIENT_SRC}" ]] || die "client binary not found at ${CLIENT_SRC}"
  fi

  # --- panel ---
  if [[ -n "${TAMIZDAT_PANEL_SRC:-}" ]]; then
    PANEL_SRC=${TAMIZDAT_PANEL_SRC}
  elif [[ -n "${BUNDLE_DIR}" ]] && PANEL_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-panel.py" "${BUNDLE_DIR}/panel/tamizdat-panel.py" 2>/dev/null); then
    true
  elif PANEL_SRC=$(candidate \
      "${SCRIPT_DIR}/tamizdat-panel.py" \
      "${SCRIPT_DIR}/panel/tamizdat-panel.py" \
      "${SCRIPT_DIR}/../tamizdat-panel.py" \
      "${SCRIPT_DIR}/../panel/tamizdat-panel.py" 2>/dev/null); then
    true
  else
    [[ -n "${BUNDLE_DIR}" ]] || download_release_bundle 2>/dev/null || true
    if [[ -n "${BUNDLE_DIR}" ]] && PANEL_SRC=$(candidate "${BUNDLE_DIR}/tamizdat-panel.py" "${BUNDLE_DIR}/panel/tamizdat-panel.py" 2>/dev/null); then
      true
    else
      dl_dir=${dl_dir:-$(mktemp -d /tmp/tamizdat-dl.XXXXXX)}
      asset_from_release "tamizdat-panel.py" "${dl_dir}/tamizdat-panel.py" "panel" \
        || die "failed to download panel; ship it alongside install.sh or set TAMIZDAT_PANEL_SRC"
      PANEL_SRC="${dl_dir}/tamizdat-panel.py"
    fi
  fi
  [[ -s "${PANEL_SRC}" ]] || die "panel not found at ${PANEL_SRC}"

  # --- management command ---
  if [[ -n "${TAMIZDAT_MANAGER_SRC:-}" ]]; then
    MANAGER_SRC=${TAMIZDAT_MANAGER_SRC}
  elif [[ -n "${BUNDLE_DIR}" ]] && MANAGER_SRC=$(candidate "${BUNDLE_DIR}/tamizdat" "${BUNDLE_DIR}/scripts/tamizdat" 2>/dev/null); then
    true
  elif MANAGER_SRC=$(candidate \
      "${SCRIPT_DIR}/tamizdat" \
      "${SCRIPT_DIR}/scripts/tamizdat" \
      "${SCRIPT_DIR}/../tamizdat" \
      "${SCRIPT_DIR}/../scripts/tamizdat" 2>/dev/null); then
    true
  else
    dl_dir=${dl_dir:-$(mktemp -d /tmp/tamizdat-dl.XXXXXX)}
    asset_from_release "tamizdat" "${dl_dir}/tamizdat" "management command" \
      || die "failed to download management command; ship scripts/tamizdat in the bundle or upload a tamizdat release asset"
    MANAGER_SRC="${dl_dir}/tamizdat"
  fi
  [[ -s "${MANAGER_SRC}" ]] || die "management command not found at ${MANAGER_SRC}"

  # --- uninstaller ---
  if [[ -n "${TAMIZDAT_UNINSTALL_SRC:-}" ]]; then
    UNINSTALL_SRC=${TAMIZDAT_UNINSTALL_SRC}
  elif [[ -n "${BUNDLE_DIR}" ]] && UNINSTALL_SRC=$(candidate "${BUNDLE_DIR}/uninstall.sh" "${BUNDLE_DIR}/scripts/uninstall.sh" 2>/dev/null); then
    true
  elif UNINSTALL_SRC=$(candidate \
      "${SCRIPT_DIR}/uninstall.sh" \
      "${SCRIPT_DIR}/scripts/uninstall.sh" \
      "${SCRIPT_DIR}/../uninstall.sh" \
      "${SCRIPT_DIR}/../scripts/uninstall.sh" 2>/dev/null); then
    true
  else
    dl_dir=${dl_dir:-$(mktemp -d /tmp/tamizdat-dl.XXXXXX)}
    asset_from_release "uninstall.sh" "${dl_dir}/uninstall.sh" "uninstaller" \
      || die "failed to download uninstaller; ship uninstall.sh in the bundle or set TAMIZDAT_UNINSTALL_SRC"
    UNINSTALL_SRC="${dl_dir}/uninstall.sh"
  fi
  [[ -s "${UNINSTALL_SRC}" ]] || die "uninstaller not found at ${UNINSTALL_SRC}"
}

rand_port() { python3 -c 'import secrets;print(secrets.randbelow(40000)+20000)'; }
rand_hex()  { python3 -c 'import secrets;print(secrets.token_hex(8))'; }
rand_pw()   { python3 -c 'import secrets;print(secrets.token_urlsafe(12))'; }

PW_GENERATED=0
SET_ADMIN=1
EXISTING_INSTALL=0
prompt_config() {
  [[ -s "${DB_PATH}" ]] && EXISTING_INSTALL=1 || EXISTING_INSTALL=0
  local existing_port existing_base existing_user existing_bind existing_host
  existing_port=$(install_info_value port)
  existing_base=$(install_info_value base); existing_base=${existing_base#/}; existing_base=${existing_base%/}
  existing_user=$(install_info_value user)
  existing_bind=$(install_info_value bind)
  existing_host=$(install_info_value host)

  VPN_PORT=${TAMIZDAT_VPN_PORT:-443}
  LISTEN_ADDR=${TAMIZDAT_LISTEN_ADDR:-0.0.0.0}
  PANEL_BIND_ADDR=${TAMIZDAT_PANEL_BIND_ADDR:-${TAMIZDAT_INSTALL_BIND_ADDR:-${existing_bind:-127.0.0.1}}}
  PANEL_SERVER_HOST=${TAMIZDAT_PANEL_SERVER_HOST:-${TAMIZDAT_INSTALL_HOSTNAME:-${existing_host:-}}}
  if [[ -z "${PANEL_SERVER_HOST}" ]]; then
    PANEL_SERVER_HOST=$(hostname -f 2>/dev/null || true)
  fi
  if [[ -z "${PANEL_SERVER_HOST}" || "${PANEL_SERVER_HOST}" == "localhost" || "${PANEL_SERVER_HOST}" == "localhost.localdomain" ]]; then
    PANEL_SERVER_HOST=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  if [[ -z "${PANEL_SERVER_HOST}" ]]; then
    die "Cannot infer server hostname/IP; set TAMIZDAT_PANEL_SERVER_HOST=server.example.com"
  fi
  if [[ "${PANEL_SERVER_HOST}" =~ [[:space:]/] || "${PANEL_SERVER_HOST}" == *"://"* ]]; then
    die "TAMIZDAT_PANEL_SERVER_HOST must be a bare hostname or IP, not a URL: ${PANEL_SERVER_HOST}"
  fi
  local def_port def_base
  def_port=${existing_port:-$(rand_port)}; def_base=${existing_base:-$(rand_hex)}

  if [[ "${TAMIZDAT_INSTALL_NONINTERACTIVE:-0}" == "1" ]]; then
    PANEL_PORT=${TAMIZDAT_INSTALL_PORT:-$def_port}
    PANEL_USER=${TAMIZDAT_INSTALL_USERNAME:-${existing_user:-admin}}
    BASE_PATH=${TAMIZDAT_INSTALL_BASE_PATH:-$def_base}
    if [[ -n "${TAMIZDAT_INSTALL_PASSWORD:-}" ]]; then
      PANEL_PASSWORD=${TAMIZDAT_INSTALL_PASSWORD}; SET_ADMIN=1
    elif [[ ${EXISTING_INSTALL} -eq 1 && "${TAMIZDAT_INSTALL_RESET_ADMIN:-0}" != "1" ]]; then
      PANEL_PASSWORD=""; SET_ADMIN=0
    else
      PANEL_PASSWORD=$(rand_pw); PW_GENERATED=1; SET_ADMIN=1
    fi
  else
    echo -e "${yellow}Tamizdat panel setup${plain} (press Enter to accept the [default])"
    read -r -p "Panel port [${def_port}]: " PANEL_PORT
    PANEL_PORT=${PANEL_PORT:-$def_port}
    read -r -p "Public server hostname/IP for generated client URIs [${PANEL_SERVER_HOST}]: " _host_input
    PANEL_SERVER_HOST=${_host_input:-$PANEL_SERVER_HOST}
    read -r -p "Panel URL base path [${def_base}]: " BASE_PATH
    BASE_PATH=${BASE_PATH:-$def_base}
    read -r -p "Panel username [${existing_user:-admin}]: " PANEL_USER
    PANEL_USER=${PANEL_USER:-${existing_user:-admin}}
    if [[ ${EXISTING_INSTALL} -eq 1 && "${TAMIZDAT_INSTALL_RESET_ADMIN:-0}" != "1" ]]; then
      read -r -p "Reset panel admin password? [y/N]: " _reset_admin
      case "${_reset_admin}" in
        y|Y|yes|YES) SET_ADMIN=1 ;;
        *) SET_ADMIN=0; PANEL_PASSWORD="" ;;
      esac
    fi
    if [[ ${SET_ADMIN} -eq 1 ]]; then
      read -r -s -p "Panel password [Enter = generate random]: " PANEL_PASSWORD; echo
      if [[ -z "${PANEL_PASSWORD}" ]]; then
        PANEL_PASSWORD=$(rand_pw); PW_GENERATED=1
      fi
    fi
  fi

  [[ "${PANEL_PORT}" =~ ^[0-9]+$ ]] && (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )) || die "panel port must be 1..65535"
  [[ "${PANEL_USER}" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || die "username must be 1-64 chars: letters digits _ . @ -"
  BASE_PATH=${BASE_PATH#/}; BASE_PATH=${BASE_PATH%/}
  [[ -n "${BASE_PATH}" ]] || BASE_PATH=$(rand_hex)
  [[ "${BASE_PATH}" =~ ^[A-Za-z0-9._~-]{1,128}$ ]] || die "panel base path must be 1-128 chars: letters digits . _ ~ -"
}

install_files() {
  log "Installing Tamizdat into ${APP_DIR}..."
  mkdir -p "${BIN_DIR}" "${PANEL_DIR}" "${SCRIPTS_DIR}" "${COMPAT_BIN_DIR}" "${ETC_DIR}" /var/log/tamizdat
  install -m 0755 "${SERVER_SRC}" "${SERVER_BIN}"
  if [[ "${INSTALL_CLIENT}" == "1" ]]; then
    install -m 0755 "${CLIENT_SRC}" "${CLIENT_BIN}"
  fi
  install -m 0755 "${PANEL_SRC}" "${PANEL_BIN}"
  install -m 0755 "${MANAGER_SRC}" "${MANAGER_BIN}"
  install -m 0755 "${UNINSTALL_SRC}" "${UNINSTALL_BIN}"

  # Compatibility symlinks for older docs/scripts and operator muscle memory.
  ln -sfn "${SERVER_BIN}" "${COMPAT_BIN_DIR}/tamizdat-server-app"
  [[ "${INSTALL_CLIENT}" == "1" ]] && ln -sfn "${CLIENT_BIN}" "${COMPAT_BIN_DIR}/tamizdat-client"
  ln -sfn "${PANEL_BIN}" "${COMPAT_BIN_DIR}/tamizdat-panel.py"
  ln -sfn "${MANAGER_BIN}" "${COMMAND_BIN}"
}

generate_server_material() {
  if [[ ! -s "${ETC_DIR}/inbound_priv_key.hex" || ! -s "${ETC_DIR}/shortid.hex" ]]; then
    log "Generating Tamizdat key material..."
    local out priv sid
    out=$("${SERVER_BIN}" --genkeys)
    priv=$(printf '%s\n' "${out}" | awk -F': *' '/Private key:/{print $2; exit}')
    sid=$(printf '%s\n' "${out}" | awk -F': *' '/Short ID:/{print $2; exit}')
    [[ -n "${priv}" && -n "${sid}" ]] || die "failed to parse generated keys"
    umask 077
    printf '%s\n' "${priv}" > "${ETC_DIR}/inbound_priv_key.hex"
    printf '%s\n' "${sid}"  > "${ETC_DIR}/shortid.hex"
  fi
  if [[ ! -s "${ETC_DIR}/cert.pem" || ! -s "${ETC_DIR}/key.pem" ]]; then
    log "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "${ETC_DIR}/key.pem" -out "${ETC_DIR}/cert.pem" \
      -days 3650 -subj "/CN=cover.example.com" >/dev/null 2>&1
  fi
  chmod 700 "${ETC_DIR}"
  chmod 600 "${ETC_DIR}/inbound_priv_key.hex" "${ETC_DIR}/shortid.hex" "${ETC_DIR}/key.pem" 2>/dev/null || true
  chmod 644 "${ETC_DIR}/cert.pem" 2>/dev/null || true
}

init_panel_db() {
  log "Initializing panel DB and inbound defaults..."
  local priv
  priv=$(tr -d '\r\n[:space:]' < "${ETC_DIR}/inbound_priv_key.hex")
  local cmd=(python3 "${PANEL_BIN}"
      --panel-port "${PANEL_PORT}"
      --panel-bind-addr "${PANEL_BIND_ADDR}"
      --panel-hostname "${PANEL_SERVER_HOST}"
      --panel-base-path "/${BASE_PATH}"
      --inbound-priv-key "${priv}"
      --inbound-cert-path "${ETC_DIR}/cert.pem"
      --inbound-key-path "${ETC_DIR}/key.pem"
      --inbound-priv-key-path "${ETC_DIR}/inbound_priv_key.hex"
      --inbound-shortid-path "${ETC_DIR}/shortid.hex"
      --inbound-listen-addr "${LISTEN_ADDR}"
      --inbound-listen-port "${VPN_PORT}"
      --inbound-public-port "${VPN_PORT}")
  if [[ ${SET_ADMIN} -eq 1 ]]; then
    log "Updating panel admin login..."
    cmd+=(--set-admin "${PANEL_USER}" --password-stdin)
    printf '%s' "${PANEL_PASSWORD}" | \
      TAMIZDAT_PANEL_DB="${DB_PATH}" \
      TAMIZDAT_PRIVKEY_PATH="${ETC_DIR}/inbound_priv_key.hex" \
      TAMIZDAT_SERVER_BIN="${SERVER_BIN}" \
      "${cmd[@]}" >/dev/null
  else
    log "Keeping existing panel admin login (set TAMIZDAT_INSTALL_RESET_ADMIN=1 to reset)"
    TAMIZDAT_PANEL_DB="${DB_PATH}" \
      TAMIZDAT_PRIVKEY_PATH="${ETC_DIR}/inbound_priv_key.hex" \
      TAMIZDAT_SERVER_BIN="${SERVER_BIN}" \
      "${cmd[@]}" >/dev/null
  fi
  chmod 600 "${DB_PATH}" 2>/dev/null || true
}

write_systemd_units() {
  log "Writing systemd units..."
  rm -f "/etc/systemd/system/${SERVER_UNIT}.d/10-debug.conf" \
        "/etc/systemd/system/${PANEL_UNIT}.d/10-bind-public.conf"
  rmdir "/etc/systemd/system/${SERVER_UNIT}.d" "/etc/systemd/system/${PANEL_UNIT}.d" 2>/dev/null || true

  cat > "/etc/systemd/system/${SERVER_UNIT}" <<EOF
[Unit]
Description=Tamizdat Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${SERVER_BIN} -server-db ${DB_PATH} -pidfile ${SERVER_PIDFILE}
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${PANEL_UNIT}" <<EOF
[Unit]
Description=Tamizdat Panel
After=network-online.target ${SERVER_UNIT}
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=TAMIZDAT_PANEL_DB=${DB_PATH}
Environment=TAMIZDAT_PANEL_PORT=${PANEL_PORT}
Environment=TAMIZDAT_PANEL_BIND_ADDR=${PANEL_BIND_ADDR}
Environment=TAMIZDAT_PANEL_SERVER_HOST=${PANEL_SERVER_HOST}
Environment=TAMIZDAT_PANEL_BASE_PATH=/${BASE_PATH}
Environment=TAMIZDAT_PANEL_FORCE_SECURE_COOKIE=0
Environment=TAMIZDAT_PANEL_SERVICE_NAME=${SERVER_SERVICE%.service}
Environment=TAMIZDAT_PANEL_SELF_SERVICE=${PANEL_UNIT}
Environment=TAMIZDAT_PANEL_SERVER_PIDFILE=${SERVER_PIDFILE}
Environment=TAMIZDAT_SERVER_BIN=${SERVER_BIN}
Environment=TAMIZDAT_PRIVKEY_PATH=${ETC_DIR}/inbound_priv_key.hex
ExecStart=/usr/bin/python3 ${PANEL_BIN}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
}

start_services() {
  log "Starting services..."
  systemctl daemon-reload
  systemctl stop "${PANEL_UNIT}" "${SERVER_UNIT}" >/dev/null 2>&1 || true
  systemctl enable --now "${SERVER_UNIT}"
  systemctl enable --now "${PANEL_UNIT}"
}

verify() {
  log "Verifying (server may take a few seconds to bind ${VPN_PORT})..."
  local i bound=0
  for i in $(seq 1 40); do
    if ss -tln 2>/dev/null | grep -qE "[:.]${VPN_PORT}[[:space:]]"; then bound=1; break; fi
    sleep 1
  done
  local server_state panel_state
  server_state=$(systemctl is-active "${SERVER_UNIT}" || true)
  panel_state=$(systemctl is-active "${PANEL_UNIT}" || true)
  echo "  server : ${server_state}  (VPN ${LISTEN_ADDR}:${VPN_PORT} $([[ ${bound} -eq 1 ]] && echo listening || echo 'NOT yet listening'))"
  echo "  panel  : ${panel_state}  (port ${PANEL_PORT})"
  [[ "${server_state}" == "active" ]] || die "${SERVER_UNIT} is not active"
  [[ "${panel_state}" == "active" ]] || die "${PANEL_UNIT} is not active"
  [[ ${bound} -eq 1 ]] || die "server did not bind ${VPN_PORT}"
  if [[ "${INSTALL_CLIENT}" == "1" ]]; then
    echo "  client : ${CLIENT_BIN}"
  fi
}

print_result() {
  local ip
  ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  printf '%s\n' "user=${PANEL_USER} bind=${PANEL_BIND_ADDR} host=${PANEL_SERVER_HOST} port=${PANEL_PORT} base=/${BASE_PATH} app=${APP_DIR}" > "${ETC_DIR}/install-info.txt"
  echo
  ok "Tamizdat installed."
  echo -e "Install:  ${green}${APP_DIR}${plain}"
  if [[ "${PANEL_BIND_ADDR}" == "127.0.0.1" || "${PANEL_BIND_ADDR}" == "localhost" ]]; then
    echo -e "Panel:    ${green}http://127.0.0.1:${PANEL_PORT}/${BASE_PATH}/${plain}  ${yellow}(use SSH tunnel for remote access)${plain}"
  else
    echo -e "Panel:    ${green}http://${ip:-SERVER_IP}:${PANEL_PORT}/${BASE_PATH}/${plain}"
  fi
  echo -e "Username: ${green}${PANEL_USER}${plain}"
  echo -e "Hostname: ${green}${PANEL_SERVER_HOST:-unset}${plain} (used in generated client URIs)"
  if [[ ${SET_ADMIN} -eq 0 ]]; then
    echo -e "Password: ${yellow}(existing admin password kept)${plain}"
  elif [[ ${PW_GENERATED} -eq 1 ]]; then
    echo -e "Password: ${green}${PANEL_PASSWORD}${plain}  ${yellow}(generated — save it now)${plain}"
  else
    echo -e "Password: ${yellow}(the one you entered)${plain}"
  fi
  echo -e "VPN:      ${green}${LISTEN_ADDR}:${VPN_PORT}${plain} (HTTPS masquerade)"
  echo "Command:  tamizdat status | tamizdat panel-url | tamizdat logs"
  echo "Uninstall: tamizdat uninstall"
  echo "Services: systemctl status ${SERVER_UNIT} ${PANEL_UNIT}"
}

main() {
  need_root
  require_linux_systemd
  detect_arch
  install_base_deps
  locate_sources
  prompt_config
  install_files
  generate_server_material
  init_panel_db
  write_systemd_units
  start_services
  verify
  print_result
}

main "$@"
