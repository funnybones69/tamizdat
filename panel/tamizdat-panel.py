#!/usr/bin/env python3
"""Tamizdat Panel — SQLite-backed admin auth and outbound chain management."""

import json
import os
import sqlite3
import subprocess
import secrets
import http.cookies
import threading
import time
import urllib.request
import re
import signal
import sys
import hashlib
import hmac
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs, quote

CONFIG_PATH = os.environ.get("TAMIZDAT_PANEL_DB", "/etc/tamizdat/data.db")
PANEL_DB = CONFIG_PATH
PANEL_PORT = int(os.environ.get("TAMIZDAT_PANEL_PORT", "8888"))
SERVER_HOST = os.environ.get("TAMIZDAT_PANEL_SERVER_HOST", "example.com")
SERVER_PORT = int(os.environ.get("TAMIZDAT_PANEL_SERVER_PORT", "443"))
BASE_PATH = os.environ.get("TAMIZDAT_PANEL_BASE_PATH", "").rstrip("/")
# Kept for compatibility only. Phase 1 traffic is a stub; Phase 2 will scrape tamizdat expvar.
CLASH_API = os.environ.get("TAMIZDAT_PANEL_CLASH_API", "http://127.0.0.1:9090")
TAMIZDAT_EXPVAR_URL = os.environ.get("TAMIZDAT_PANEL_EXPVAR_URL", "http://127.0.0.1:6060/debug/vars").strip()
SERVICE_NAME = os.environ.get("TAMIZDAT_PANEL_SERVICE_NAME", "tamizdat-server")
SERVER_PIDFILE = os.environ.get("TAMIZDAT_PANEL_SERVER_PIDFILE", "/run/tamizdat-server.pid")
SERVER_BIN = os.environ.get("TAMIZDAT_SERVER_BIN", "/usr/local/tamizdat/bin/tamizdat-server-app")
LEGACY_CONFIG_PATH = os.environ.get("TAMIZDAT_PANEL_LEGACY_CONFIG", "/etc/anytls/config.json")
SESSION_TTL = 3600

# I-5 (multi-user-cleanup): the panel session cookie defaults to Secure
# (only sent over HTTPS). Operators running the panel on plain-HTTP for
# bench testing can set TAMIZDAT_PANEL_FORCE_SECURE_COOKIE=0 to disable.
# Default 1 = enforce HTTPS-only transport for the auth cookie.
FORCE_SECURE_COOKIE = os.environ.get("TAMIZDAT_PANEL_FORCE_SECURE_COOKIE", "1").strip() not in ("0", "false", "no", "")
COOKIE_SECURE_FLAG = "; Secure" if FORCE_SECURE_COOKIE else ""

TAG_RE = re.compile(r"^[\w.-]{1,64}$", re.UNICODE)
PANEL_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
PANEL_PBKDF2_ITERATIONS = int(os.environ.get("TAMIZDAT_PANEL_PBKDF2_ITERATIONS", "260000"))

# Canonical path for the X25519 private key the server reads via -privkey-file.
# 2026-05-11 dead-mine fix: panel-side PUT to inbound_priv_key now atomically
# writes this file ALSO (not just DB row) so server actually picks up new key
# after restart. Env override for testing / non-systemd deployments.
TAMIZDAT_PRIVKEY_PATH = os.environ.get("TAMIZDAT_PRIVKEY_PATH", "/etc/tamizdat/inbound_priv_key.hex")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS outbounds (
    tag TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    uri TEXT,
    note TEXT,
    bind_iface TEXT,                                        -- direct outbound: pin dial source to a network interface (SO_BINDTODEVICE on Linux). NULL = OS default route.
    bytes_up INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,
    h2_peak_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_admins (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    master_shortid       TEXT NOT NULL UNIQUE,
    epoch_key            TEXT,                         -- DEPRECATED post-2026-05-09 shortid full-B simplification; nullable.
    pool_size            INTEGER,                      -- DEPRECATED: same vintage as epoch_key.
    outbound_tag         TEXT NOT NULL DEFAULT 'direct',
    bytes_up             INTEGER NOT NULL DEFAULT 0,
    bytes_down           INTEGER NOT NULL DEFAULT 0,
    bytes_reset_at       INTEGER,                      -- rolling-quota anchor (unix sec); 0/NULL = since-creation.
    expires_at           INTEGER,
    bandwidth_cap        INTEGER,                      -- total-byte quota (since bytes_reset_at). 0/NULL = no quota.
    rate_limit_mbps      INTEGER,                      -- token-bucket throughput cap in Mbits/sec. 0/NULL = unlimited. Added 2026-05-13.
    last_seen_at         INTEGER,
    notification_pending INTEGER NOT NULL DEFAULT 0,   -- set 1 on quota overrun; deferred client push.
    notification_text    TEXT,                          -- per-user manual / "BROADCAST: " prefix; pushed to client via bundle (Phase C).
    quota_baseline       INTEGER NOT NULL DEFAULT 0,   -- bytes_up+bytes_down at last "Reset Quota" click; over-quota check subtracts this so traffic stats stay visible.
    h2_peak_streams      INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 CONNECT streams observed for this user (tcp+udp).
    h2_peak_tcp_streams  INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 TCP CONNECT streams observed for this user.
    h2_peak_udp_streams  INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 UDP CONNECT streams observed for this user.
    h2_peak_at           INTEGER NOT NULL DEFAULT 0,   -- unix sec when one of the H2 peak counters last advanced.
    h2_relay_peak_streams      INTEGER NOT NULL DEFAULT 0,   -- max concurrent streams this user's traffic opened toward an outbound/next hop.
    h2_relay_peak_tcp_streams  INTEGER NOT NULL DEFAULT 0,
    h2_relay_peak_udp_streams  INTEGER NOT NULL DEFAULT 0,
    h2_relay_peak_at           INTEGER NOT NULL DEFAULT 0,
    turn_room_link       TEXT,                         -- operator-pushed TURN room/link; delivered via bundle.
    turn_room_hash       TEXT,
    turn_profile_pending INTEGER NOT NULL DEFAULT 0,
    turn_profile_version INTEGER NOT NULL DEFAULT 0,
    turn_profile_updated_at INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    FOREIGN KEY (outbound_tag) REFERENCES outbounds(tag)
);
CREATE INDEX IF NOT EXISTS idx_users_master ON users(master_shortid);
CREATE TABLE IF NOT EXISTS user_sessions (
    user_id        TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    started_at     INTEGER NOT NULL,
    bytes_up       INTEGER NOT NULL DEFAULT 0,
    bytes_down     INTEGER NOT NULL DEFAULT 0,
    last_active_at INTEGER NOT NULL,
    pool_index     INTEGER,
    transport      TEXT NOT NULL DEFAULT 'h2',
    PRIMARY KEY (user_id, session_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(last_active_at);
CREATE TABLE IF NOT EXISTS routing_folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_routing_folders_priority ON routing_folders(priority);
CREATE TABLE IF NOT EXISTS routing_rules (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    priority             INTEGER NOT NULL,
    match_json           TEXT NOT NULL,
    outbound_tag         TEXT NOT NULL,
    description_override TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    group_name           TEXT,                                -- DEPRECATED post folders-v1 (2026-05-10): superseded by folder_id; column kept orphaned for graceful downgrade. _migrate_routing_folders() copies any non-empty group_name into a routing_folders row on first run, then leaves group_name in place.
    folder_id            INTEGER REFERENCES routing_folders(id),
    created_at           INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at           INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_routing_priority ON routing_rules(priority);
-- idx_routing_folder_id is created by _migrate_routing_folders() so it
-- doesn't fire on a v0 DB that still has no folder_id column at the
-- moment SCHEMA_SQL runs (CREATE TABLE IF NOT EXISTS leaves the old
-- shape intact when the table already exists).
"""

# Default settings inserted by ensure_db on first run / upgrade. These mirror
# the userdb.defaultSettings map in internal/userdb/schema.go and let the
# panel's /api/inbound endpoint render a complete form even on a fresh DB.
DEFAULT_SETTINGS = {
    "default_outbound_tag":        "direct",
    "pool_size_default":           "1",
    "inbound_listen_port":         "7780",
    "inbound_listen_addr":         "127.0.0.1",
    "inbound_public_port":         "443",
    "inbound_max_streams":         "1000",
    "panel_test_target":           "http://www.gstatic.com/generate_204",   # external URL probed for direct's TEST (HTTP GET)
    "inbound_geoip_url":           "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "inbound_geosite_url":         "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    "inbound_jitter_ms":           "0",
    "inbound_cert_path":           "/etc/tamizdat/cert.pem",
    "inbound_key_path":            "/etc/tamizdat/key.pem",
    "inbound_priv_key":            "",
    "inbound_priv_key_path":       "/etc/tamizdat/inbound_priv_key.hex",
    "inbound_shortid_path":        "/etc/tamizdat/shortid.hex",
    "inbound_masquerade_domain":   "cover.example.com",
    "inbound_masquerade_pool":     "cover.example.com=cover.example.com:443,ok.ru=ok.ru:443,vk.com=vk.com:443,mail.ru=mail.ru:443,yandex.ru=yandex.ru:443",
    "inbound_fingerprint":         "mix",
    # Server-pushes-pool (2026-05-09): when set, the URI generator emits
    # &bootstrap=<sni>. Empty leaves the URI host as the bootstrap SNI,
    # which is sensible for DNS hosts but emits a bare-IP TLS handshake
    # for IP-literal hosts. Operators distributing to L7-filtered networks
    # should set this to a whitelist-friendly cover SNI (e.g. yandex.ru).
    "inbound_bootstrap_sni":       "",
    # Standalone release installs run the server directly. PROXY protocol must
    # stay off unless a trusted reverse proxy is explicitly configured.
    "inbound_proxy_protocol":      "0",
    "inbound_proxy_protocol_from": "127.0.0.1/32",
    # Server-authoritative pool variant (2026-05-11). Pushed to clients via
    # cover-config bundle. Client strips its own URI/CLI/GUI choice — only
    # server dictates. Default "v1" = single H2 transport (operator policy).
    "inbound_pool_variant":        "v1",
    # TLS SNI / HTTP Host sniffing (2026-05-11). Server peeks first ~4KB
    # of client→destination payload and extracts hostname for routing rule
    # evaluation. Needed for IP-mode clients (iOS sing-tun, full-tunnel
    # VPNs) where domain: rules would otherwise never match. Default ON.
    "inbound_sniff_enabled":       "1",
    # Settings refactor Phase 2 (2026-05-11): "bundle enabled" toggle for the
    # inbound block + fallback host/port (previously buried in legacy
    # panel_inbounds_json). bundle_enabled=1 by default — operators flipping
    # this off effectively disable the tamizdat-server side without removing
    # config, which is useful for staged rollouts.
    "inbound_bundle_enabled":      "1",
    "inbound_fallback_server":     "",
    "inbound_fallback_port":       "0",
    # Panel self-config (settings refactor Phase 2). On a fresh install these
    # default to the matching TAMIZDAT_PANEL_* env vars; subsequent panel
    # restarts read from settings table first, env second. Operator edits via
    # PUT /api/panel land here. panel_tls_cert_path / panel_tls_key_path are
    # optional — both set => panel binds HTTPS itself.
    "panel_hostname":              os.environ.get("TAMIZDAT_PANEL_SERVER_HOST", ""),
    "panel_port":                  os.environ.get("TAMIZDAT_PANEL_PORT", "8888"),
    "panel_bind_addr":             os.environ.get("TAMIZDAT_PANEL_BIND_ADDR", ""),
    "panel_base_path":             os.environ.get("TAMIZDAT_PANEL_BASE_PATH", ""),
    "panel_tls_cert_path":         "",
    "panel_tls_key_path":          "",
    # wgturn inbound (WireGuard over DTLS/TURN). Empty listen disables.
    "wgturn_enabled":              "0",
    "wgturn_listen":               "",
    "wgturn_password":             "",
    "wgturn_wg_port":              "56001",
    "wgturn_config_dir":           "/etc/tamizdat/wgturn",
    "wgturn_subnet":               "10.66.66.0/24",
    "wgturn_server_ip":            "10.66.66.1",
    "wgturn_outbound_tag":         "",
}

# Panel version surfaced via GET /api/panel for the Settings block. Bumped
# manually on releases; reviewer can override with TAMIZDAT_PANEL_VERSION env
# (e.g. CI stamping a git short SHA).
PANEL_VERSION = os.environ.get("TAMIZDAT_PANEL_VERSION", "1.0")

_db_lock = threading.RLock()

def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

def db_conn():
    _ensure_parent(PANEL_DB)
    # ThreadingHTTPServer (2026-05-11) means many threads call db_conn()
    # concurrently. PRAGMA journal_mode=WAL would acquire an EXCLUSIVE
    # lock here on every request — repeated under load it serializes
    # all writers and causes SQLITE_BUSY storms in the Go server-app's
    # accounting flush. journal_mode persists in the DB file header, so
    # it only needs to be set once (done in ensure_db). busy_timeout is
    # per-connection state — keep it here.
    con = sqlite3.connect(PANEL_DB, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=5000")
    return con

def _setting(con, key, default=""):
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def _set_setting(con, key, value):
    con.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

def _valid_tag(tag):
    tag = (tag or "").strip()
    if not TAG_RE.fullmatch(tag):
        raise ValueError("tag must be 1-64 chars (letters/digits/Cyrillic/CJK/etc., plus _.-, no spaces or slashes)")
    return tag

def _fixed_hex(value, want_bytes, name):
    value = (value or "").strip()
    if not value:
        raise ValueError(f"missing {name}")
    if not HEX_RE.fullmatch(value):
        raise ValueError(f"{name} must be hex")
    if len(value) != want_bytes * 2:
        raise ValueError(f"{name} must be {want_bytes * 2} hex chars")
    return value.lower()

def _legacy_outbound_to_uri(ob):
    uri = (ob.get("uri") or "").strip()
    if uri.startswith("tamizdat://"):
        return uri
    if uri.startswith("tamizdat://"):
        return "tamizdat://" + uri[len("tamizdat://"):]
    host = (ob.get("server") or ob.get("host") or "").strip()
    port = int(ob.get("server_port") or ob.get("port") or 0)
    pub = (ob.get("public_key") or ob.get("pubkey") or ob.get("pbk") or "").strip()
    sid = (ob.get("short_id") or ob.get("shortid") or ob.get("sid") or "").strip()
    sni = (ob.get("server_name") or ob.get("sni") or host).strip()
    fp = (ob.get("fingerprint") or ob.get("fp") or "mix").strip()
    if not (host and port and pub and sid and sni):
        return ""
    return f"tamizdat://{host}:{port}/?sni={quote(sni, safe='')}&pubkey={pub}&shortid={sid}&fp={quote(fp, safe='')}"

def parse_tamizdat_uri(uri, tag_override=None):
    """Parse tamizdat://host:port/?sni=...&pubkey=...&shortid=...&fp=mix[#tag]."""
    uri = (uri or "").strip()
    u = urlparse(uri)
    if u.scheme != "tamizdat":
        raise ValueError("Unsupported URI. Phase 1 supports tamizdat:// and direct only")
    if not u.hostname:
        raise ValueError("tamizdat URI must include host")
    try:
        port = u.port
    except ValueError as e:
        raise ValueError(f"bad port: {e}")
    if not port:
        raise ValueError("tamizdat URI must include host:port")
    if u.path not in ("", "/"):
        raise ValueError("tamizdat URI path must be empty or /")
    params = parse_qs(u.query, keep_blank_values=True)
    sni = (params.get("sni", [""])[0] or params.get("server_name", [""])[0] or u.hostname).strip()
    pub = (params.get("pubkey", [""])[0] or params.get("public_key", [""])[0] or params.get("pbk", [""])[0]).strip()
    sid = (params.get("shortid", [""])[0] or params.get("sid", [""])[0] or (unquote(u.username) if u.username else "")).strip()
    fp = (params.get("fp", ["mix"])[0] or "mix").strip()
    bootstrap = (params.get("bootstrap", [""])[0] or "").strip()
    pub = _fixed_hex(pub, 32, "pubkey")
    sid = _fixed_hex(sid, 8, "shortid")
    tag = _valid_tag(tag_override or (unquote(u.fragment) if u.fragment else f"tamizdat-{u.hostname}"))
    out = {
        "type": "tamizdat",
        "kind": "tamizdat",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(port),
        "public_key": pub,
        "short_id": sid,
        "server_name": sni,
        "fingerprint": fp,
        "tls": {"enabled": True, "server_name": sni},
        "uri": uri,
    }
    if bootstrap:
        out["bootstrap_sni"] = bootstrap
    return out

def _migrate_legacy_if_needed(con):
    non_direct = con.execute("SELECT COUNT(*) AS n FROM outbounds WHERE tag <> 'direct'").fetchone()["n"]
    migrated = con.execute("SELECT 1 FROM schema_meta WHERE key='migrated_from_anytls'").fetchone()
    if migrated or non_direct:
        return
    if not os.path.exists(LEGACY_CONFIG_PATH):
        return
    try:
        with open(LEGACY_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
        legacy = json.loads(raw)
    except Exception as e:
        print(f"legacy migration skipped: {e}")
        return
    now = int(time.time())
    inbounds = legacy.get("inbounds", [])
    if inbounds:
        _set_setting(con, "panel_inbounds_json", json.dumps(inbounds, ensure_ascii=False))
    route = legacy.get("route", {})
    if route.get("rules"):
        _set_setting(con, "panel_route_rules_json", json.dumps(route.get("rules", []), ensure_ascii=False))
    if route.get("final"):
        _set_setting(con, "default_outbound_tag", route.get("final"))
    for ib in inbounds:
        if ib.get("type") == "tamizdat":
            for key in ("master_short_id", "public_port", "listen_port", "masquerade_domain", "fingerprint", "bootstrap_sni"):
                if ib.get(key) not in (None, ""):
                    _set_setting(con, f"tamizdat_{key}", ib.get(key))
    for ob in legacy.get("outbounds", []):
        kind = (ob.get("kind") or ob.get("type") or "").strip().lower()
        tag = (ob.get("tag") or ob.get("name") or "").strip()
        if kind == "direct" or tag == "direct":
            continue
        if kind not in ("tamizdat", "tamizdat"):
            continue
        uri = _legacy_outbound_to_uri(ob)
        if not uri or not tag:
            continue
        try:
            parsed = parse_tamizdat_uri(uri, tag_override=tag)
        except Exception as e:
            print(f"legacy outbound {tag} skipped: {e}")
            continue
        con.execute("INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                    (parsed["tag"], "tamizdat", uri, "migrated from /etc/anytls/config.json", now, now))
    con.execute("INSERT OR REPLACE INTO schema_meta(key, value) VALUES('migrated_from_anytls', '1')")


# --- Phase 2 user management helpers ---
#
# The panel is the source of truth for users + outbound binding. The
# server's userdb package consumes the same DB read-only at handshake time:
# it loads `users` rows on SIGHUP and accepts a connection iff the
# ClientHello's shortid byte-equals one of the loaded `users.master_shortid`
# values.
#
# Multi-user-cleanup (2026-05-10) finalised the shortid full-B simplification:
# the panel no longer writes `epoch_key` or `pool_size` on user create/update.
# Schema v3 makes the columns nullable + adds `notification_pending` so the
# server can flag quota-overrun events to the panel UI. See SPEC.md §10.
#
# Operator policy: shortIDs ONLY in the users table; NO global
# master_shortid identity field. The server still accepts `--shortid` for
# embedded callers without a userdb but production deployments rely on the
# panel exclusively.

LEGACY_SHORTID_PATH = os.environ.get("TAMIZDAT_PANEL_LEGACY_SHORTID", "/etc/tamizdat/shortid.hex")


def _bootstrap_legacy_shortid(con):
    """If the users table is empty AND /etc/tamizdat/shortid.hex contains a
    valid 16-hex master shortid, create one default user "admin" so the
    upgrade from Phase 1 to Phase 2 doesn't break legacy clients connecting
    with the legacy URI. Idempotent: a second call when users already exist
    is a no-op. Operator can rename via panel after first login."""
    n = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if n != 0:
        return
    try:
        with open(LEGACY_SHORTID_PATH, "r") as f:
            data = f.read().strip()
    except FileNotFoundError:
        return
    except Exception as e:
        print(f"bootstrap legacy shortid: {e}")
        return
    if not HEX_RE.fullmatch(data) or len(data) != 16:
        return
    master = data.lower()
    uid = secrets.token_hex(8)
    now = int(time.time())
    con.execute("""INSERT INTO users(id, name, master_shortid, outbound_tag, created_at, updated_at)
        VALUES(?, 'admin', ?, 'direct', ?, ?)""", (uid, master, now, now))
    con.execute("INSERT OR REPLACE INTO schema_meta(key, value) VALUES('migrated_from_v1', ?)", (str(now),))


def _new_unique_master_shortid(con):
    """Random 8-byte (16-hex) master shortid that is not already used by another user."""
    for _ in range(64):
        m = secrets.token_hex(8)
        row = con.execute("SELECT 1 FROM users WHERE master_shortid=?", (m,)).fetchone()
        if not row:
            return m
    raise RuntimeError("failed to allocate a unique master_shortid after 64 attempts")


def _user_row_to_dict(row, online_count=0, _current_pool_index=-1, active_transport=""):
    """Translate a sqlite3.Row from the users table into the JSON shape the
    Phase 2 panel UI consumes. Master shortid is intentionally NOT included
    in the list response (per spec: NO shortid display in the user table —
    operator clicks "Show URI" to see it)."""
    # I-2/I-3 (multi-user-cleanup commit 5): master_shortid is intentionally
    # NOT included. Operator clicks "Show URI" → /api/users/<id>/uri to see
    # the full tamizdat:// URI (which embeds the shortid). Listing endpoints
    # have no need for the raw shortid; keeping it here only invited
    # operator-error leaks via copy-paste of admin-panel HTML.
    return {
        "id": row["id"],
        "name": row["name"],
        "outbound_tag": row["outbound_tag"],
        "pool_size": (row["pool_size"] if "pool_size" in row.keys() else 1) or 1,
        "expires_at": row["expires_at"],
        "bandwidth_cap": row["bandwidth_cap"],
        "rate_limit_mbps": (row["rate_limit_mbps"] if "rate_limit_mbps" in row.keys() else 0) or 0,
        "bytes_up": row["bytes_up"],
        "bytes_down": row["bytes_down"],
        "bytes_reset_at": row["bytes_reset_at"],
        "notification_pending": bool(row["notification_pending"]) if "notification_pending" in row.keys() else False,
        "notification_text": (row["notification_text"] or "") if "notification_text" in row.keys() else "",
        "turn_room_link": (row["turn_room_link"] or "") if "turn_room_link" in row.keys() else "",
        "turn_room_hash": (row["turn_room_hash"] or "") if "turn_room_hash" in row.keys() else "",
        "turn_profile_pending": bool(row["turn_profile_pending"]) if "turn_profile_pending" in row.keys() else False,
        "turn_profile_version": (row["turn_profile_version"] if "turn_profile_version" in row.keys() else 0) or 0,
        "turn_profile_updated_at": (row["turn_profile_updated_at"] if "turn_profile_updated_at" in row.keys() else 0) or 0,
        "quota_baseline": row["quota_baseline"] if "quota_baseline" in row.keys() else 0,
        "h2_peak_streams": (row["h2_peak_streams"] if "h2_peak_streams" in row.keys() else 0) or 0,
        "h2_peak_tcp_streams": (row["h2_peak_tcp_streams"] if "h2_peak_tcp_streams" in row.keys() else 0) or 0,
        "h2_peak_udp_streams": (row["h2_peak_udp_streams"] if "h2_peak_udp_streams" in row.keys() else 0) or 0,
        "h2_peak_at": (row["h2_peak_at"] if "h2_peak_at" in row.keys() else 0) or 0,
        "h2_relay_peak_streams": (row["h2_relay_peak_streams"] if "h2_relay_peak_streams" in row.keys() else 0) or 0,
        "h2_relay_peak_tcp_streams": (row["h2_relay_peak_tcp_streams"] if "h2_relay_peak_tcp_streams" in row.keys() else 0) or 0,
        "h2_relay_peak_udp_streams": (row["h2_relay_peak_udp_streams"] if "h2_relay_peak_udp_streams" in row.keys() else 0) or 0,
        "h2_relay_peak_at": (row["h2_relay_peak_at"] if "h2_relay_peak_at" in row.keys() else 0) or 0,
        "h2_live_streams": 0,
        "h2_live_tcp_streams": 0,
        "h2_live_udp_streams": 0,
        "h2_relay_live_streams": 0,
        "h2_relay_live_tcp_streams": 0,
        "h2_relay_live_udp_streams": 0,
        "last_seen_at": row["last_seen_at"],
        "online_sessions": online_count,
        "active_transport": (active_transport or "") if online_count else "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


_LIVE_USERS_CACHE = {"at": 0.0, "data": {}}
_LIVE_USERS_LOCK = threading.Lock()
_LIVE_OUTBOUNDS_CACHE = {"at": 0.0, "data": {}}
_LIVE_OUTBOUNDS_LOCK = threading.Lock()


def _intish(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def _live_users_from_expvar():
    if not TAMIZDAT_EXPVAR_URL:
        return {}

    now = time.monotonic()
    with _LIVE_USERS_LOCK:
        if now - float(_LIVE_USERS_CACHE.get("at") or 0) < 0.75:
            return dict(_LIVE_USERS_CACHE.get("data") or {})

    live = {}
    try:
        req = urllib.request.Request(TAMIZDAT_EXPVAR_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=0.25) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        users = payload.get("tamizdat_users") if isinstance(payload, dict) else None
        if isinstance(users, dict):
            for uid, item in users.items():
                if not isinstance(item, dict):
                    continue
                live[str(uid)] = {
                    "h2_live_streams": _intish(item.get("h2_live_streams")),
                    "h2_live_tcp_streams": _intish(item.get("h2_live_tcp_streams")),
                    "h2_live_udp_streams": _intish(item.get("h2_live_udp_streams")),
                    "h2_relay_live_streams": _intish(item.get("h2_relay_live_streams")),
                    "h2_relay_live_tcp_streams": _intish(item.get("h2_relay_live_tcp_streams")),
                    "h2_relay_live_udp_streams": _intish(item.get("h2_relay_live_udp_streams")),
                    "active_transport": str(item.get("active_transport") or ""),
                }
    except Exception:
        live = {}

    with _LIVE_USERS_LOCK:
        _LIVE_USERS_CACHE["at"] = now
        _LIVE_USERS_CACHE["data"] = dict(live)
    return live


def _merge_live_user_counts(users, live):
    if not live:
        return users
    for u in users:
        item = live.get(u.get("id"))
        if item:
            u.update(item)
    return users


def _live_outbounds_from_expvar():
    if not TAMIZDAT_EXPVAR_URL:
        return {}

    now = time.monotonic()
    with _LIVE_OUTBOUNDS_LOCK:
        if now - float(_LIVE_OUTBOUNDS_CACHE.get("at") or 0) < 0.75:
            return dict(_LIVE_OUTBOUNDS_CACHE.get("data") or {})

    live = {}
    try:
        req = urllib.request.Request(TAMIZDAT_EXPVAR_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=0.25) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        outbounds = payload.get("tamizdat_outbounds") if isinstance(payload, dict) else None
        if isinstance(outbounds, dict):
            for tag, item in outbounds.items():
                if not isinstance(item, dict):
                    continue
                live[str(tag)] = {
                    "h2_live_streams": _intish(item.get("h2_live_streams")),
                    "h2_live_tcp_streams": _intish(item.get("h2_live_tcp_streams")),
                    "h2_live_udp_streams": _intish(item.get("h2_live_udp_streams")),
                    "h2_peak_streams": _intish(item.get("h2_peak_streams")),
                    "h2_peak_tcp_streams": _intish(item.get("h2_peak_tcp_streams")),
                    "h2_peak_udp_streams": _intish(item.get("h2_peak_udp_streams")),
                    "h2_peak_at": _intish(item.get("h2_peak_at")),
                    "h2_dial_failed_tcp_streams": _intish(item.get("h2_dial_failed_tcp_streams")),
                    "h2_dial_failed_udp_streams": _intish(item.get("h2_dial_failed_udp_streams")),
                    "h2_dial_failed_at": _intish(item.get("h2_dial_failed_at")),
                    "h2_dial_failed_network": str(item.get("h2_dial_failed_network") or ""),
                    "h2_dial_failed_error": str(item.get("h2_dial_failed_error") or ""),
                }
    except Exception:
        live = {}

    with _LIVE_OUTBOUNDS_LOCK:
        _LIVE_OUTBOUNDS_CACHE["at"] = now
        _LIVE_OUTBOUNDS_CACHE["data"] = dict(live)
    return live


def _merge_live_outbound_counts(outbounds, live):
    if not live:
        return outbounds
    for o in outbounds:
        item = live.get(o.get("tag"))
        if item:
            o.update(item)
    return outbounds


def _online_counts(con, active_window_sec=5):
    """Return {user_id: (n_online, max_pool_index_seen, active_transport)} for sessions whose
    last_active_at is within the window. active_transport prefers TURN when both
    H2 control and wgturn sessions are active."""
    cutoff = int(time.time()) - active_window_sec
    rows = con.execute("""SELECT user_id, COUNT(*) AS n,
        COALESCE(MAX(pool_index), -1) AS p FROM user_sessions
        WHERE last_active_at >= ? GROUP BY user_id""", (cutoff,)).fetchall()
    transports = con.execute("""SELECT user_id, transport, COUNT(*) AS n FROM user_sessions
        WHERE last_active_at >= ? GROUP BY user_id, transport""", (cutoff,)).fetchall()
    active = {}
    for r in transports:
        tr = (r["transport"] or "h2").strip() or "h2"
        uid = r["user_id"]
        if tr == "turn" or not active.get(uid):
            active[uid] = tr
    out = {}
    for r in rows:
        out[r["user_id"]] = (r["n"], r["p"], active.get(r["user_id"], "h2"))
    return out


def list_users():
    ensure_db()
    with db_conn() as con:
        online = _online_counts(con)
        rows = con.execute("SELECT * FROM users ORDER BY created_at, id").fetchall()
    out = []
    for r in rows:
        n, p, active_transport = online.get(r["id"], (0, -1, ""))
        out.append(_user_row_to_dict(r, n, p, active_transport))
    return _merge_live_user_counts(out, _live_users_from_expvar())


def get_user(user_id):
    ensure_db()
    with db_conn() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return None
        n, p, active_transport = _online_counts(con).get(user_id, (0, -1, ""))
    return _user_row_to_dict(row, n, p, active_transport)


def create_user(body):
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    pool_size = body.get("pool_size")
    if pool_size is not None and pool_size != "":
        try:
            pool_size = int(pool_size)
        except Exception:
            raise ValueError("pool_size must be int")
        if pool_size <= 0 or pool_size > 4:
            raise ValueError("pool_size out of range [1,4]")
    outbound = (body.get("outbound_tag") or "direct").strip() or "direct"
    expires_at = body.get("expires_at")
    if expires_at in (None, "", 0, "0"):
        expires_at = None
    else:
        expires_at = int(expires_at)
    bandwidth_cap = body.get("bandwidth_cap")
    if bandwidth_cap in (None, "", 0, "0"):
        bandwidth_cap = None
    else:
        bandwidth_cap = int(bandwidth_cap)
    rate_limit_mbps = body.get("rate_limit_mbps")
    if rate_limit_mbps in (None, "", 0, "0"):
        rate_limit_mbps = None
    else:
        rate_limit_mbps = int(rate_limit_mbps)

    ensure_db()
    with db_conn() as con:
        row = con.execute("SELECT 1 FROM outbounds WHERE tag=?", (outbound,)).fetchone()
        if not row:
            raise ValueError(f"outbound_tag {outbound!r} does not exist")
        if pool_size is None:
            try:
                pool_size = int(_setting(con, "pool_size_default", DEFAULT_SETTINGS["pool_size_default"]))
            except Exception:
                pool_size = 1
            if pool_size <= 0 or pool_size > 4:
                pool_size = 1
        master = _new_unique_master_shortid(con)
        uid = secrets.token_hex(8)
        now = int(time.time())
        # pool_size is now the exact H2 transport count per user. When the
        # caller omits it, the server-side default is used and clamped to the
        # supported 1..4 range.
        con.execute("""INSERT INTO users(id, name, master_shortid, pool_size, outbound_tag, expires_at, bandwidth_cap, rate_limit_mbps, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", (uid, name, master, pool_size, outbound, expires_at, bandwidth_cap, rate_limit_mbps, now, now))
    _sighup_server()
    return get_user(uid)


def update_user(user_id, body):
    ensure_db()
    fields = []
    args = []
    if "name" in body:
        n = (body.get("name") or "").strip()
        if not n:
            raise ValueError("name cannot be empty")
        fields.append("name=?"); args.append(n)
    if "outbound_tag" in body:
        ob = (body.get("outbound_tag") or "direct").strip() or "direct"
        with db_conn() as con:
            if not con.execute("SELECT 1 FROM outbounds WHERE tag=?", (ob,)).fetchone():
                raise ValueError(f"outbound_tag {ob!r} does not exist")
        fields.append("outbound_tag=?"); args.append(ob)
    if "pool_size" in body:
        ps = body.get("pool_size")
        if ps in (None, "", 0, "0"):
            ps = 1
        else:
            try:
                ps = int(ps)
            except Exception:
                raise ValueError("pool_size must be int")
            if ps <= 0 or ps > 4:
                raise ValueError("pool_size out of range [1,4]")
        fields.append("pool_size=?"); args.append(ps)
    if "expires_at" in body:
        ea = body.get("expires_at")
        if ea in (None, "", 0, "0"):
            fields.append("expires_at=NULL")
        else:
            fields.append("expires_at=?"); args.append(int(ea))
    if "bandwidth_cap" in body:
        bc = body.get("bandwidth_cap")
        if bc in (None, "", 0, "0"):
            fields.append("bandwidth_cap=NULL")
        else:
            fields.append("bandwidth_cap=?"); args.append(int(bc))
    if "rate_limit_mbps" in body:
        rl = body.get("rate_limit_mbps")
        if rl in (None, "", 0, "0"):
            fields.append("rate_limit_mbps=NULL")
        else:
            fields.append("rate_limit_mbps=?"); args.append(int(rl))
    if "notification_text" in body:
        nt = (body.get("notification_text") or "")
        if len(nt) > 512:
            raise ValueError("notification_text exceeds 512 bytes")
        # Empty value clears the notification AND the pending flag (so the
        # operator can de-stage a queued message). Non-empty value flips
        # pending=1 so the server emits it on next bundle fetch.
        if nt == "":
            fields.append("notification_text=NULL")
            fields.append("notification_pending=?"); args.append(0)
        else:
            fields.append("notification_text=?"); args.append(nt)
            fields.append("notification_pending=?"); args.append(1)
    if "turn_room_link" in body:
        link = (body.get("turn_room_link") or "").strip()
        if len(link.encode("utf-8")) > 1024:
            raise ValueError("turn_room_link exceeds 1024 bytes")
        # Minimal validation only: accept full VK room/call links or the raw
        # hash. The iOS client owns provider-specific parsing and status UI.
        now = int(time.time())
        if link == "":
            fields.append("turn_room_link=NULL")
            fields.append("turn_room_hash=NULL")
            fields.append("turn_profile_pending=?"); args.append(0)
        else:
            fields.append("turn_room_link=?"); args.append(link)
            fields.append("turn_profile_pending=?"); args.append(1)
            fields.append("turn_profile_version=COALESCE(turn_profile_version,0)+1")
            fields.append("turn_profile_updated_at=?"); args.append(now)
    if not fields:
        return get_user(user_id)
    fields.append("updated_at=?"); args.append(int(time.time()))
    args.append(user_id)
    with db_conn() as con:
        cur = con.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", args)
        if cur.rowcount == 0:
            raise ValueError("user not found")
    _sighup_server()
    return get_user(user_id)


def delete_user(user_id):
    ensure_db()
    with db_conn() as con:
        cur = con.execute("DELETE FROM users WHERE id=?", (user_id,))
        if cur.rowcount == 0:
            raise ValueError("user not found")
    _sighup_server()


def reset_user_quota(user_id):
    """Panel "Reset Quota" button: unblock a capped user without erasing
    historical traffic stats.

    Sets quota_baseline = bytes_up + bytes_down so the server's IsOverQuota
    check (which subtracts the baseline) sees a fresh window. Bumps
    bytes_reset_at and clears notification_pending. Crucially LEAVES
    bytes_up/bytes_down untouched so the operator-facing lifetime traffic
    ticker keeps growing.
    """
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        cur = con.execute(
            "UPDATE users SET quota_baseline=(bytes_up+bytes_down), "
            "bytes_reset_at=?, notification_pending=0, notification_text=NULL, updated_at=? WHERE id=?",
            (now, now, user_id),
        )
        if cur.rowcount == 0:
            raise ValueError("user not found")
    _sighup_server()


def reset_user_bytes(user_id):
    """Panel 🔄 (U+1F504) icon-button next to the traffic counters: hard-zero
    the bytes accounting entirely.

    Wipes bytes_up + bytes_down + quota_baseline, re-anchors bytes_reset_at,
    and clears notification_pending. This is the "factory reset" semantic
    — the lifetime ↓↑ display visibly drops to 0 so the operator gets a
    clean slate (e.g. for a brand-new billing period or an account-reuse
    handoff). reset_user_quota is the everyday unblock-without-erasing
    counterpart.
    """
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        cur = con.execute(
            "UPDATE users SET bytes_up=0, bytes_down=0, quota_baseline=0, "
            "bytes_reset_at=?, notification_pending=0, notification_text=NULL, updated_at=? WHERE id=?",
            (now, now, user_id),
        )
        if cur.rowcount == 0:
            raise ValueError("user not found")
    _sighup_server()


def broadcast_notification(text):
    """Phase C iOS-notify pipeline (2026-05-10): set the same notification_text
    on EVERY user (system-wide message) and flip notification_pending=1 for
    all of them. The "BROADCAST: " prefix is the wire signal that this is a
    system-wide message vs an operator-targeted one — the server emits a
    NotificationEntry.Code = "broadcast" when it sees the prefix. Empty text
    clears every user's pending state (useful as an undo).
    """
    text = text or ""
    if len(text) > 512:
        raise ValueError("text exceeds 512 bytes")
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        if text == "":
            con.execute(
                "UPDATE users SET notification_text=NULL, notification_pending=0, updated_at=?",
                (now,),
            )
        else:
            payload = "BROADCAST: " + text
            con.execute(
                "UPDATE users SET notification_text=?, notification_pending=1, updated_at=?",
                (payload, now),
            )
    _sighup_server()


def rotate_user_epoch(user_id):
    """Regenerate this user's master_shortid (and epoch_key for transitional
    cleanliness). Renamed semantically in the shortid full-B simplification
    (2026-05-09): pre-2026-05-09 this rotated the HKDF-derived pool via
    epoch_key push; post-2026-05-09 the pool concept is gone so the only
    rotation primitive is "assign a new master_shortid". The endpoint URL
    stays /api/users/<uid>/rotate-epoch for backward-compat with the panel
    JS, but the underlying SQL update now overwrites master_shortid as
    well as epoch_key. WARNING: this is wire-breaking for any deployed
    client of this user — the URI must be redistributed.
    """
    ensure_db()
    new_master = secrets.token_hex(8)
    now = int(time.time())
    # Finding 1 from I-rerun review: drop the epoch_key write entirely.
    # Pre-2026-05-09 this rotated the HKDF-derived pool via epoch_key push;
    # post-2026-05-09 the pool concept is gone (see SPEC.md §10) and writing
    # a fresh epoch_key with NULL master_shortid bump used to silently produce
    # a fresh pool of 50 immediately accepted in the now-removed code path.
    # The single rotation primitive is now "assign a new master_shortid".
    with db_conn() as con:
        cur = con.execute(
            "UPDATE users SET master_shortid=?, updated_at=? WHERE id=?",
            (new_master, now, user_id),
        )
        if cur.rowcount == 0:
            raise ValueError("user not found")
    _sighup_server()
    return new_master


def get_inbound_settings():
    ensure_db()
    with db_conn() as con:
        rows = con.execute("SELECT key, value FROM settings WHERE key LIKE 'inbound_%' OR key LIKE 'wgturn_%' OR key='pool_size_default'").fetchall()
    out = dict(DEFAULT_SETTINGS)
    for r in rows:
        out[r["key"]] = r["value"]
    # panel_test_target is panel-only (Go server doesn't consult it). The
    # base SELECT only pulls inbound_* keys, so fetch the override here.
    with db_conn() as con:
        out["panel_test_target"] = _setting(
            con,
            "panel_test_target",
            DEFAULT_SETTINGS.get("panel_test_target", "http://www.gstatic.com/generate_204"),
        )
        # Geo URLs default to Loyalsoldier; empty value means "skip geodata
        # loading and free the in-memory db" (operator request, ~10 MB
        # saved on small VPSes when geo rules aren't in use).
        out["inbound_geoip_url"]   = _setting(con, "inbound_geoip_url",   DEFAULT_SETTINGS["inbound_geoip_url"])
        out["inbound_geosite_url"] = _setting(con, "inbound_geosite_url", DEFAULT_SETTINGS["inbound_geosite_url"])
    return out


# Subset of inbound_* keys that the panel allows the operator to edit. Keys
# outside this set are NOT persisted by put_inbound_settings even if present
# in the JSON body — protects against accidental writes to private_key etc.
INBOUND_EDITABLE = {
    "inbound_listen_port", "inbound_listen_addr", "inbound_public_port",
    "inbound_max_streams", "inbound_jitter_ms", "inbound_cert_path",
    "inbound_key_path", "inbound_priv_key", "inbound_priv_key_path",
    "inbound_shortid_path",
    "inbound_masquerade_domain", "inbound_masquerade_pool",
    "inbound_fingerprint", "inbound_bootstrap_sni",
    "inbound_proxy_protocol", "inbound_proxy_protocol_from",
    "inbound_pool_variant",  # server-authoritative push (2026-05-11).
    "inbound_sniff_enabled",  # TLS SNI / HTTP Host sniff (2026-05-11).
    # Settings refactor Phase 2 (2026-05-11): newly editable.
    "inbound_bundle_enabled",
    "inbound_fallback_server", "inbound_fallback_port",
    "pool_size_default",
    "panel_test_target",  # panel-only setting; saved via /api/inbound for UI symmetry.
    "inbound_geoip_url",    # GitHub-style raw URL or empty (disable + free memory).
    "inbound_geosite_url",  # same.
    "wgturn_enabled", "wgturn_listen", "wgturn_password",
    "wgturn_wg_port", "wgturn_config_dir", "wgturn_subnet",
    "wgturn_server_ip", "wgturn_outbound_tag",
}

TAMIZDAT_RESTART_REQUIRED = {
    "inbound_listen_port",
    "inbound_listen_addr",
    "inbound_cert_path",
    "inbound_key_path",
    "inbound_priv_key",
    "inbound_priv_key_path",
    "inbound_shortid_path",
    "inbound_masquerade_domain",
    "inbound_masquerade_pool",
    "inbound_proxy_protocol",
    "inbound_proxy_protocol_from",
    "inbound_max_streams",
    "inbound_pool_variant",
    "inbound_sniff_enabled",
    "wgturn_enabled",
    "wgturn_listen",
    "wgturn_password",
    "wgturn_wg_port",
    "wgturn_config_dir",
    "wgturn_subnet",
    "wgturn_server_ip",
    "wgturn_outbound_tag",
}


def tamizdat_restart_required(changed):
    return any(k in TAMIZDAT_RESTART_REQUIRED for k in changed or ())


def _write_priv_key_file(priv_hex):
    """Dead-mine fix 2026-05-11: when operator PUTs a new inbound_priv_key
    (typed manually or via Generate button), the value used to ONLY land in
    settings.inbound_priv_key DB row — but the server reads the key from
    the file passed via -privkey-file CLI arg (default
    /etc/tamizdat/inbound_priv_key.hex). So new key sat in DB unused,
    pubkey in URI generation diverged from the live wire pubkey, clients
    silently broke after the next restart.

    Now: validated hex → write atomically to TAMIZDAT_PRIVKEY_PATH file
    (chmod 0600 root:root best-effort) AFTER the DB row lands. Caller is
    responsible for sighup/restart of tamizdat-server so it re-reads.

    Raises ValueError on bad hex. Returns the resolved path on success.
    """
    priv_hex = (priv_hex or "").strip().lower()
    if not priv_hex or len(priv_hex) != 64 or not HEX_RE.fullmatch(priv_hex):
        raise ValueError("inbound_priv_key must be 64 lowercase hex chars")
    path = TAMIZDAT_PRIVKEY_PATH
    tmp_path = path + ".new"
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, priv_hex.encode("ascii") + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    try:
        # Best-effort root:root ownership. Non-root panels silently skip.
        os.chown(tmp_path, 0, 0)
    except (OSError, AttributeError):
        pass
    os.rename(tmp_path, path)
    return path


def put_inbound_settings(body):
    """Update the inbound_* settings rows from the panel form. Returns the
    list of keys whose value actually changed (the caller may need to log
    'restart required' if listen_port / listen_addr changed).

    Light per-key validation:
      - integer-valued keys (port/streams/jitter) → must parse as int and
        non-negative; bad input raises ValueError.
      - inbound_bundle_enabled → normalised to "0" / "1".
      - inbound_priv_key → must be empty or 64 lowercase hex chars.
        Non-empty value ALSO writes to canonical TAMIZDAT_PRIVKEY_PATH
        file atomically (dead-mine fix 2026-05-11).
      - inbound_fingerprint → must be in {mix, chrome, firefox, safari}.
    All other keys are stored as stripped strings (free-form).
    """
    int_keys = {"inbound_listen_port", "inbound_public_port",
                "inbound_max_streams", "inbound_jitter_ms", "pool_size_default",
                "inbound_fallback_port", "wgturn_wg_port"}
    allowed_fp = {"mix", "chrome", "firefox", "safari"}
    changed = []
    ensure_db()
    with db_conn() as con:
        for k in INBOUND_EDITABLE:
            if k not in body:
                continue
            v = body.get(k)
            if v is None:
                continue
            # Bool coming from JSON → "0"/"1" canonical form so the Go server
            # (which reads with strconv.Atoi) sees a clean integer.
            if k == "inbound_bundle_enabled" or k == "wgturn_enabled":
                if isinstance(v, bool):
                    v = "1" if v else "0"
                else:
                    v = "1" if str(v).strip() in ("1", "true", "yes", "on") else "0"
            elif k in int_keys:
                try:
                    iv = int(str(v).strip() or "0")
                except (TypeError, ValueError):
                    raise ValueError(f"{k} must be an integer")
                if iv < 0:
                    raise ValueError(f"{k} must be non-negative")
                v = str(iv)
            elif k == "inbound_priv_key":
                vv = (str(v) or "").strip().lower()
                if vv and (len(vv) != 64 or not HEX_RE.fullmatch(vv)):
                    raise ValueError("inbound_priv_key must be 64 lowercase hex chars or empty")
                v = vv
            elif k == "inbound_fingerprint":
                vv = (str(v) or "").strip().lower()
                if vv and vv not in allowed_fp:
                    raise ValueError(f"inbound_fingerprint must be one of {sorted(allowed_fp)}")
                v = vv or "mix"
            elif k == "inbound_pool_variant":
                vv = (str(v) or "").strip().lower()
                if vv and vv not in {"v1", "v2", "v3"}:
                    raise ValueError("inbound_pool_variant must be one of v1/v2/v3")
                v = vv or "v1"
            elif k == "pool_size_default":
                if iv < 1 or iv > 4:
                    raise ValueError("pool_size_default out of range [1,4]")
                v = str(iv)
            elif k == "inbound_sniff_enabled":
                # accept 1/0/true/false; persist as 1/0.
                vv = str(v).strip().lower()
                v = "1" if vv in {"1", "true", "yes", "on"} else "0"
            else:
                v = str(v).strip()
            row = con.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
            if row and row["value"] == v:
                continue
            con.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
            changed.append(k)
    # Filesystem side-effect AFTER DB commit closes: if a fresh non-empty
    # inbound_priv_key actually landed, also write it to the canonical
    # TAMIZDAT_PRIVKEY_PATH so server's -privkey-file CLI arg reads the
    # new key on next start. SIGHUP doesn't re-read the priv key (loaded
    # once at boot), so restart_required surfaces in the response.
    if "inbound_priv_key" in changed:
        priv = (body.get("inbound_priv_key") or "").strip().lower()
        if priv:
            try:
                _write_priv_key_file(priv)
            except Exception as e:
                # Don't roll back the DB write — operator can still see the
                # value in the UI. Log + leave file write for a follow-up
                # manual scp if it failed (permissions / read-only mount).
                import sys as _sys
                print(f"WARN: failed to write {TAMIZDAT_PRIVKEY_PATH}: {e}", file=_sys.stderr)
    if changed:
        _sighup_server()
    return changed


# --- Settings refactor Phase 2: panel self-config helpers ---

# Subset of panel_* keys editable via PUT /api/panel. panel_test_target stays
# under put_inbound_settings because the inbound block already auto-saves it.
PANEL_EDITABLE = {
    "panel_hostname",
    "panel_port",
    "panel_bind_addr",
    "panel_base_path",
    "panel_tls_cert_path",
    "panel_tls_key_path",
}

# Keys whose change requires a panel restart for the new value to take
# effect. hostname is read fresh on every URI-build so it can change on the
# fly without a restart; port/base_path/TLS-paths only bind on startup.
PANEL_RESTART_REQUIRED = {
    "panel_port",
    "panel_bind_addr",
    "panel_base_path",
    "panel_tls_cert_path",
    "panel_tls_key_path",
}


def put_panel_settings(body):
    """Persist panel_* settings. Returns {"changed": [...], "restart_required": bool}.

    Light validation: panel_port must be 1..65535; TLS pair must be both-or-
    neither (operator can't ship a cert without a key, that's a config error).
    """
    changed = []
    ensure_db()
    with db_conn() as con:
        # Whole-body validate first so a bad port doesn't leave half the
        # body persisted.
        new_port = body.get("panel_port")
        if new_port is not None and str(new_port).strip() != "":
            try:
                ip = int(str(new_port).strip())
            except (TypeError, ValueError):
                raise ValueError("panel_port must be an integer")
            if not (1 <= ip <= 65535):
                raise ValueError("panel_port must be in [1,65535]")
        cert = (body.get("panel_tls_cert_path") or "").strip() if isinstance(body.get("panel_tls_cert_path"), str) else None
        key  = (body.get("panel_tls_key_path")  or "").strip() if isinstance(body.get("panel_tls_key_path"),  str) else None
        if cert is not None or key is not None:
            # Only enforce both-or-neither when at least one is supplied.
            cert_s = cert if cert is not None else _setting(con, "panel_tls_cert_path", "")
            key_s  = key  if key  is not None else _setting(con, "panel_tls_key_path", "")
            if bool(cert_s) != bool(key_s):
                raise ValueError("panel_tls_cert_path and panel_tls_key_path must be both set or both empty")
        for k in PANEL_EDITABLE:
            if k not in body:
                continue
            v = body.get(k)
            if v is None:
                continue
            v = str(v).strip()
            if k == "panel_base_path":
                # Normalise: must start with "/" if non-empty, no trailing slash.
                if v:
                    if not v.startswith("/"):
                        v = "/" + v
                    v = v.rstrip("/") or ""
            row = con.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
            if row and row["value"] == v:
                continue
            con.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
            changed.append(k)
    restart_required = any(k in changed for k in PANEL_RESTART_REQUIRED)
    return {"changed": changed, "restart_required": restart_required}


def _panel_setting_with_env_fallback(key, env_var, default):
    """Read panel_<x> from DB; if empty/missing fall back to env var, then default.
    Called on panel startup so operators can keep existing env configs working
    while the new UI gradually populates the DB. Safe to call before ensure_db
    (returns env/default in that case)."""
    try:
        with db_conn() as con:
            v = _setting(con, key, "")
    except Exception:
        v = ""
    if v:
        return v
    return os.environ.get(env_var, default)


def panel_public_hostname():
    """Single source of truth for hostnames embedded into generated configs.

    Public hostname is editable in Settings and explicitly says it affects
    user URIs. Every URI/JSON generator must use the same DB→env→default
    chain so fresh installs do not leak the module-load SERVER_HOST fallback
    ("example.com") into some config paths.
    """
    return _panel_setting_with_env_fallback(
        "panel_hostname", "TAMIZDAT_PANEL_SERVER_HOST", SERVER_HOST
    )


def make_master_uri_from_settings():
    """Build the "master" tamizdat URI from flat inbound_* settings, used by
    the Settings page Block 1's read-only URI field. Returns "" when the
    inbound isn't fully configured (no priv key / no cert) — caller renders
    a placeholder.

    Differs from make_user_uri (which embeds a per-user shortid). This is the
    inbound's bare config URI useful for sanity-check / share-with-team
    purposes. We embed a synthetic 16-hex placeholder for shortid since the
    flat-settings model no longer stores a master shortid (each user owns its
    own master_shortid in users.master_shortid). Empty shortid would make the
    URI unparseable by clients, so we use 16 zero bytes — operator should
    distribute per-user URIs from the Users page instead.
    """
    ensure_db()
    with db_conn() as con:
        priv = _setting(con, "inbound_priv_key", "").strip()
        priv_path = _setting(con, "inbound_priv_key_path", "")
        public_port = _setting(con, "inbound_public_port", "443")
        listen_port = _setting(con, "inbound_listen_port", "7780")
        masq = _setting(con, "inbound_masquerade_domain", "")
        fp = _setting(con, "inbound_fingerprint", "mix")
        bootstrap = _setting(con, "inbound_bootstrap_sni", "").strip()
        hostname = panel_public_hostname()
    if not priv and priv_path and os.path.exists(priv_path):
        try:
            with open(priv_path, "r") as f:
                priv = f.read().strip()
        except Exception:
            priv = ""
    if not priv or len(priv) != 64:
        return ""
    pub = x25519_public_from_private(priv)
    if not pub:
        return ""
    try:
        port = int(public_port) or int(listen_port) or 443
    except ValueError:
        port = 443
    base = (f"tamizdat://{hostname}:{port}/?sni={masq}&pubkey={pub}"
            f"&shortid=0000000000000000&fp={fp}")
    if bootstrap:
        base += f"&bootstrap={quote(bootstrap, safe='')}"
    return base + "#master-config"


def server_pubkey_from_settings():
    ensure_db()
    with db_conn() as con:
        priv = _setting(con, "inbound_priv_key", "")
        path = _setting(con, "inbound_priv_key_path", "")
    if not priv:
        # Try configured path first, then fall back to canonical locations
        # used by different bootstrap scripts (2026-05-11: install via
        # mirror-bootstrap creates inbound_priv_key.hex; older scripts on
        # ru2/llm2 used privkey.hex). Don't fail just because the DB
        # setting points at a stale path.
        candidates = []
        if path:
            candidates.append(path)
        candidates += [
            "/etc/tamizdat/inbound_priv_key.hex",
            "/etc/tamizdat/privkey.hex",
            "/etc/tamizdat/server.key",
        ]
        for p in candidates:
            if p and os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        priv = f.read().strip()
                    if priv:
                        break
                except Exception:
                    continue
    if not priv or len(priv) != 64:
        return ""
    return x25519_public_from_private(priv)


def _get_user_shortid(user_id):
    """Fetch users.master_shortid for the given user_id directly from the
    DB. Used by make_user_uri so /api/users responses can stay shortid-
    free (I-2/I-3): the bare shortid is loaded only inside the URI-
    generation path."""
    ensure_db()
    with db_conn() as con:
        row = con.execute("SELECT master_shortid FROM users WHERE id=?", (user_id,)).fetchone()
        return row["master_shortid"] if row else None


def make_user_uri(user):
    """Build a tamizdat://host:port/?... URI for one user. Falls back to None
    if cert/private key isn't usable yet OR the user is gone.

    Server-pushes-pool (2026-05-09): when inbound_bootstrap_sni is set, the
    URI carries &bootstrap=<sni> so the very first transport (before the
    server-pushed pool arrives) uses an explicit cover SNI. Empty bootstrap
    falls back to URI host (DNS or IP literal). The legacy &sni= and &fp=
    fields are preserved for backward-compat with v2 clients."""
    settings = get_inbound_settings()
    hostname = panel_public_hostname()
    sni = settings.get("inbound_masquerade_domain", "") or hostname
    fp = settings.get("inbound_fingerprint", "mix")
    bootstrap = (settings.get("inbound_bootstrap_sni", "") or "").strip()
    port = int(settings.get("inbound_public_port") or settings.get("inbound_listen_port") or 443)
    pubkey = server_pubkey_from_settings()
    if not pubkey:
        return None
    shortid = _get_user_shortid(user["id"])
    if not shortid:
        return None
    pool = int(user.get("pool_size") or 1)
    if pool < 1:
        pool = 1
    elif pool > 4:
        pool = 4
    label = quote(user["name"])
    base = f"tamizdat://{hostname}:{port}/?sni={sni}&pubkey={pubkey}&shortid={shortid}&fp={fp}&min_transports={pool}&max_transports={pool}"
    if bootstrap:
        base += f"&bootstrap={quote(bootstrap, safe='')}"
    return base + f"#{label}"


def _migrate_routing_group_name(con):
    """Add routing_rules.group_name column if missing. Idempotent.
    Panel-only label for collapsible folders in the routing UI; server
    routing engine ignores it (priority + match_json drive matching).

    Kept for backward compat with v0 schema. Folders v1 supersedes
    group_name with a real routing_folders table — see
    _migrate_routing_folders() below, which is run after this and
    promotes any existing group_name strings to first-class folder rows.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(routing_rules)").fetchall()}
    if "group_name" not in cols:
        con.execute("ALTER TABLE routing_rules ADD COLUMN group_name TEXT")


def _migrate_routing_folders(con):
    """Folders v1 (2026-05-10) — promote routing_rules.group_name labels
    to a real routing_folders table with first-class priority.

    Steps (all guarded by PRAGMA introspection so the function is idempotent):

    1. Ensure routing_folders table exists. SCHEMA_SQL CREATE TABLE
       IF NOT EXISTS already handles this on a fresh DB; we re-check
       anyway in case ensure_db is invoked against a partial schema.
    2. Add routing_rules.folder_id column if missing.
    3. For each distinct non-empty group_name across enabled+disabled rules,
       create a routing_folders row (priority = MIN(rule.priority within
       the group), enabled = 1) and update each member rule's folder_id +
       intra-folder priority (ROW_NUMBER over old priority).

    The legacy group_name column is left intact (orphaned, undocumented in
    new code) so a partial downgrade — running an older panel binary that
    only knows group_name — keeps showing the same UI labels.

    Server-side rulesdb.Load (Go) reads the new hierarchical schema via
    UNION over (ungrouped, grouped) and falls back to the flat ORDER BY
    priority on a pre-folders DB, so server boot is robust through this
    migration whether the panel has run yet or not.
    """
    # Step 1: ensure routing_folders table exists (no-op when SCHEMA_SQL
    # already created it).
    con.execute(
        "CREATE TABLE IF NOT EXISTS routing_folders ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL, "
        "priority INTEGER NOT NULL, "
        "enabled INTEGER NOT NULL DEFAULT 1, "
        "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
        "updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
        ")"
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_routing_folders_priority "
        "ON routing_folders(priority)"
    )

    # Step 2: add folder_id column to routing_rules if missing.
    rule_cols = {r["name"] for r in con.execute("PRAGMA table_info(routing_rules)").fetchall()}
    if "folder_id" not in rule_cols:
        con.execute(
            "ALTER TABLE routing_rules ADD COLUMN "
            "folder_id INTEGER REFERENCES routing_folders(id)"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_routing_folder_id "
            "ON routing_rules(folder_id)"
        )

    # Step 3: promote group_name labels (only if any rule still references
    # one AND that group has not already been migrated). Idempotent: a
    # rule whose folder_id is already set is skipped.
    if "group_name" not in rule_cols:
        # Pre-v0 (pre-2026-05-09) panel — no group_name to migrate.
        return
    pending = con.execute(
        "SELECT id, priority, COALESCE(group_name,'') AS gn "
        "FROM routing_rules "
        "WHERE folder_id IS NULL "
        "  AND group_name IS NOT NULL AND group_name != '' "
        "ORDER BY group_name COLLATE NOCASE, priority ASC, id ASC"
    ).fetchall()
    if not pending:
        return
    now = int(time.time())
    # Map group-name → folder-id, creating the folder once per distinct
    # name. Folder priority = MIN(rule.priority for rules in this group);
    # fall back to MAX+1 when MIN is already taken by an ungrouped row.
    seen = {}
    # Pre-existing folders (e.g. operator manually inserted some) keep their id.
    for r in con.execute("SELECT id, name FROM routing_folders").fetchall():
        seen.setdefault((r["name"] or "").strip(), r["id"])
    # Collect rule lists per group to assign intra-folder priority by ROW_NUMBER.
    groups = {}
    for row in pending:
        groups.setdefault(row["gn"], []).append(row)
    for gname, rules in groups.items():
        if gname in seen:
            folder_id = seen[gname]
        else:
            min_pr = min(int(r["priority"]) for r in rules)
            cur = con.execute(
                "INSERT INTO routing_folders(name, priority, enabled, created_at, updated_at) "
                "VALUES(?,?,1,?,?)",
                (gname, min_pr, now, now),
            )
            folder_id = cur.lastrowid
            seen[gname] = folder_id
        # Re-number intra-folder priority from 1..N preserving old order.
        for ip, row in enumerate(rules, start=1):
            con.execute(
                "UPDATE routing_rules SET folder_id=?, priority=?, updated_at=? WHERE id=?",
                (folder_id, ip, now, row["id"]),
            )


def _migrate_outbounds_bind_iface(con):
    """Add outbounds.bind_iface column on existing DBs (idempotent).
    Direct outbound stores the network interface name to pin the dial
    source to; NULL = OS default route. Other outbound kinds ignore.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(outbounds)").fetchall()}
    if "bind_iface" not in cols:
        con.execute("ALTER TABLE outbounds ADD COLUMN bind_iface TEXT")


def _migrate_outbounds_bytes_counters(con):
    """Add outbounds.bytes_up / outbounds.bytes_down on existing DBs
    (idempotent). Per-outbound byte accounting (2026-05-12) — populated by
    the server's userdb.Accounting.Flush() in the same transaction that
    flushes per-user counters. Panel /api/outbounds GET surfaces them as
    dl/ul; the "Reset outbound traffic" button zeros them.

    DEFAULT 0 + NOT NULL means existing rows get 0 on the ALTER (no
    backfill needed). The server's internal/outbounds/registry.go runs
    the equivalent migration so panel-less deployments stay in sync.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(outbounds)").fetchall()}
    if "bytes_up" not in cols:
        con.execute("ALTER TABLE outbounds ADD COLUMN bytes_up INTEGER NOT NULL DEFAULT 0")
    if "bytes_down" not in cols:
        con.execute("ALTER TABLE outbounds ADD COLUMN bytes_down INTEGER NOT NULL DEFAULT 0")


def _migrate_outbounds_h2_peak(con):
    """Add per-outbound relay stream diagnostics on existing DBs.

    These counters are written by tamizdat-server when a routed outbound
    stream is successfully opened toward the next hop. They are separate
    from per-user inbound H2 counters.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(outbounds)").fetchall()}
    add = [
        ("h2_peak_streams", "ALTER TABLE outbounds ADD COLUMN h2_peak_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_tcp_streams", "ALTER TABLE outbounds ADD COLUMN h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_udp_streams", "ALTER TABLE outbounds ADD COLUMN h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_at", "ALTER TABLE outbounds ADD COLUMN h2_peak_at INTEGER NOT NULL DEFAULT 0"),
    ]
    for name, sql in add:
        if name not in cols:
            con.execute(sql)


def _migrate_users_rate_limit_mbps(con):
    """v6 → v7 migration mirroring internal/userdb/schema.go::migrateUsersV7.

    Adds users.rate_limit_mbps (INTEGER NULL) — token-bucket throughput cap
    in Mbits/sec. NULL/0 = unlimited. Server's per-user rate limiter reads
    this column on every userdb reload and resizes the bucket accordingly.
    Idempotent: re-runs on already-v7 schemas no-op.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()}
    if "rate_limit_mbps" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN rate_limit_mbps INTEGER")


def _migrate_users_h2_peak(con):
    """v8 -> v9 migration mirroring internal/userdb/schema.go::migrateUsersV9.

    Adds per-user H2 peak counters used only for diagnostics in the Users
    table. Idempotent: panel and server can run this in any order.
    """
    cols = {r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()}
    add = [
        ("h2_peak_streams", "ALTER TABLE users ADD COLUMN h2_peak_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_tcp_streams", "ALTER TABLE users ADD COLUMN h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_udp_streams", "ALTER TABLE users ADD COLUMN h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_peak_at", "ALTER TABLE users ADD COLUMN h2_peak_at INTEGER NOT NULL DEFAULT 0"),
        ("h2_relay_peak_streams", "ALTER TABLE users ADD COLUMN h2_relay_peak_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_relay_peak_tcp_streams", "ALTER TABLE users ADD COLUMN h2_relay_peak_tcp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_relay_peak_udp_streams", "ALTER TABLE users ADD COLUMN h2_relay_peak_udp_streams INTEGER NOT NULL DEFAULT 0"),
        ("h2_relay_peak_at", "ALTER TABLE users ADD COLUMN h2_relay_peak_at INTEGER NOT NULL DEFAULT 0"),
    ]
    for name, sql in add:
        if name not in cols:
            con.execute(sql)


def _migrate_users_turn_profile(con):
    """v10 migration: per-user TURN room/link push fields."""
    cols = {r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()}
    add = [
        ("turn_room_link", "ALTER TABLE users ADD COLUMN turn_room_link TEXT"),
        ("turn_room_hash", "ALTER TABLE users ADD COLUMN turn_room_hash TEXT"),
        ("turn_profile_pending", "ALTER TABLE users ADD COLUMN turn_profile_pending INTEGER NOT NULL DEFAULT 0"),
        ("turn_profile_version", "ALTER TABLE users ADD COLUMN turn_profile_version INTEGER NOT NULL DEFAULT 0"),
        ("turn_profile_updated_at", "ALTER TABLE users ADD COLUMN turn_profile_updated_at INTEGER NOT NULL DEFAULT 0"),
    ]
    for name, sql in add:
        if name not in cols:
            con.execute(sql)


def _migrate_user_sessions_transport(con):
    """v11 migration: active H2/TURN badge for live sessions."""
    cols = {r["name"] for r in con.execute("PRAGMA table_info(user_sessions)").fetchall()}
    if "transport" not in cols:
        con.execute("ALTER TABLE user_sessions ADD COLUMN transport TEXT NOT NULL DEFAULT 'h2'")


def _migrate_users_v3(con):
    """v2 → v3 migration mirroring internal/userdb/schema.go::migrateUsersV3.

    - Drops legacy NOT NULL on users.epoch_key by rebuilding the table when
      detected (SQLite cannot ALTER COLUMN NULL/NOT NULL in place).
    - Ensures notification_pending column exists for deferred client push of
      quota overrun.
    Idempotent: PRAGMA-driven, re-runs are no-ops on already-v3 schemas.
    """
    cols = {r["name"]: r for r in con.execute("PRAGMA table_info(users)").fetchall()}
    if not cols:
        # Brand-new DB after CREATE TABLE IF NOT EXISTS — schema is already v3.
        return
    if cols.get("epoch_key") and cols["epoch_key"]["notnull"] == 1:
        # Rebuild users table with epoch_key nullable + notification_pending +
        # quota_baseline columns. The rebuilt schema is already v4-shaped so
        # _migrate_users_v4 below becomes a no-op for fresh-from-v2 upgrades.
        con.execute("ALTER TABLE users RENAME TO users_v2_legacy")
        con.execute("""CREATE TABLE users (
            id                   TEXT PRIMARY KEY,
            name                 TEXT NOT NULL,
            master_shortid       TEXT NOT NULL UNIQUE,
            epoch_key            TEXT,
            pool_size            INTEGER,
            outbound_tag         TEXT NOT NULL DEFAULT 'direct',
            bytes_up             INTEGER NOT NULL DEFAULT 0,
            bytes_down           INTEGER NOT NULL DEFAULT 0,
            bytes_reset_at       INTEGER,
            expires_at           INTEGER,
            bandwidth_cap        INTEGER,
            last_seen_at         INTEGER,
            notification_pending INTEGER NOT NULL DEFAULT 0,
            notification_text    TEXT,
            quota_baseline       INTEGER NOT NULL DEFAULT 0,
            created_at           INTEGER NOT NULL,
            updated_at           INTEGER NOT NULL,
            FOREIGN KEY (outbound_tag) REFERENCES outbounds(tag)
        )""")
        con.execute("""INSERT INTO users (id, name, master_shortid, epoch_key, pool_size, outbound_tag,
                bytes_up, bytes_down, bytes_reset_at, expires_at, bandwidth_cap, last_seen_at,
                notification_pending, notification_text, quota_baseline, created_at, updated_at)
            SELECT id, name, master_shortid, epoch_key, pool_size, outbound_tag,
                   bytes_up, bytes_down, bytes_reset_at, expires_at, bandwidth_cap, last_seen_at,
                   0 AS notification_pending, NULL AS notification_text, 0 AS quota_baseline, created_at, updated_at
            FROM users_v2_legacy""")
        con.execute("DROP TABLE users_v2_legacy")
        con.execute("CREATE INDEX IF NOT EXISTS idx_users_master ON users(master_shortid)")
        return
    # epoch_key already nullable. Just ensure notification_pending exists.
    if "notification_pending" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN notification_pending INTEGER NOT NULL DEFAULT 0")


def _migrate_panel_test_target_to_url(con):
    """Rewrite legacy `host:port` form of settings.panel_test_target to the
    new full-URL form `http://www.gstatic.com/generate_204`.

    Background: the original panel_test_target was a `host:port` tuple used
    for raw TLS handshake probes against direct. The CL replaced it with
    an HTTP GET URL (so the probe exercises the actual proxy path). New
    installs ship the URL form via DEFAULT_SETTINGS, but pre-existing
    settings rows kept the colon-form because INSERT OR IGNORE leaves
    existing values alone. This migration upgrades them in place.

    Idempotent: only rewrites the exact legacy value the original default
    used. Operator-customised targets are left untouched.
    """
    row = con.execute(
        "SELECT value FROM settings WHERE key='panel_test_target'"
    ).fetchone()
    if not row:
        return
    legacy = "www.gstatic.com:443"
    if row["value"].strip() == legacy:
        con.execute(
            "UPDATE settings SET value=? WHERE key='panel_test_target'",
            ("http://www.gstatic.com/generate_204",),
        )


def _migrate_legacy_inbounds_json_to_flat(con):
    """Settings refactor Phase 2 one-shot: if the operator still has data in
    the legacy `panel_inbounds_json` row AND the flat inbound_listen_port
    setting hasn't been touched yet (signal of pre-Phase-2 install), copy the
    tamizdat inbound's fields into the flat settings table.

    Idempotent guards:
      - Marker key `legacy_inbounds_migrated_to_flat` in schema_meta. Set on
        first successful run; subsequent calls early-out.
      - Even without the marker, if the operator has already populated
        inbound_listen_port via the new UI, we skip the copy (would clobber
        their edits).

    Why so cautious: existing pre-Phase-2 installs on llm2 + example-outbound have
    populated panel_inbounds_json (the legacy JSON-blob store) but never
    filled the flat keys because the legacy "Tamizdat server" save button
    was a stub. We want their port/cert/key to survive the panel upgrade
    without manual re-entry.
    """
    marker = con.execute(
        "SELECT 1 FROM schema_meta WHERE key='legacy_inbounds_migrated_to_flat'"
    ).fetchone()
    if marker:
        return
    raw = _setting(con, "panel_inbounds_json", "")
    if not raw:
        # Nothing to migrate; stamp the marker so we never re-check this DB.
        con.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) "
            "VALUES('legacy_inbounds_migrated_to_flat', '1')"
        )
        return
    try:
        inbounds = json.loads(raw)
    except Exception:
        # Malformed legacy JSON — stamp marker and bail.
        con.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) "
            "VALUES('legacy_inbounds_migrated_to_flat', '1')"
        )
        return
    tam = None
    for ib in inbounds:
        if (ib.get("type") or "") in ("tamizdat", "anytls"):
            tam = ib
            break
    if not tam:
        con.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) "
            "VALUES('legacy_inbounds_migrated_to_flat', '1')"
        )
        return
    # Map legacy JSON keys → flat settings keys. Only writes the key if the
    # flat setting is currently empty (operator hasn't supplied a value yet)
    # so re-running this migration on a DB the operator partially-edited is
    # safe.
    mapping = [
        ("listen_port",            "inbound_listen_port"),
        ("listen_addr",            "inbound_listen_addr"),
        ("public_port",            "inbound_public_port"),
        ("private_key",            "inbound_priv_key"),
        ("cert_path",              "inbound_cert_path"),
        ("key_path",               "inbound_key_path"),
        ("masquerade_domain",      "inbound_masquerade_domain"),
        ("fingerprint",            "inbound_fingerprint"),
        ("bootstrap_sni",          "inbound_bootstrap_sni"),
        ("max_concurrent_streams", "inbound_max_streams"),
        ("server_jitter_ms",       "inbound_jitter_ms"),
    ]
    # tls + fallback are nested objects in the legacy schema.
    tls = tam.get("tls") or {}
    if "certificate_path" in tls and not tam.get("cert_path"):
        tam["cert_path"] = tls["certificate_path"]
    if "key_path" in tls and not tam.get("key_path"):
        tam["key_path"] = tls["key_path"]
    fb = tam.get("fallback") or {}
    if fb.get("server"):
        v = str(fb["server"]).strip()
        existing = _setting(con, "inbound_fallback_server", "")
        default = DEFAULT_SETTINGS.get("inbound_fallback_server", "")
        # Only promote if the row is empty or still holds the install-time
        # default — never clobber an operator-supplied value.
        if v and (not existing or existing == default):
            con.execute(
                "INSERT INTO settings(key,value) VALUES('inbound_fallback_server', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (v,))
    if fb.get("server_port"):
        try:
            v = str(int(fb["server_port"]))
        except (TypeError, ValueError):
            v = ""
        existing = _setting(con, "inbound_fallback_port", "")
        default = DEFAULT_SETTINGS.get("inbound_fallback_port", "")
        if v and (not existing or existing == default):
            con.execute(
                "INSERT INTO settings(key,value) VALUES('inbound_fallback_port', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (v,))
    for legacy_key, flat_key in mapping:
        v = tam.get(legacy_key)
        if v in (None, ""):
            continue
        # Compare against the DEFAULT_SETTINGS value: if the flat key still
        # holds its default (set by INSERT OR IGNORE on first ensure_db),
        # promote the legacy JSON value over it.
        existing = _setting(con, flat_key, "")
        default = DEFAULT_SETTINGS.get(flat_key, "")
        if existing and existing != default:
            # Operator already supplied a value via the new UI; don't clobber.
            continue
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (flat_key, str(v).strip()),
        )
    con.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) "
        "VALUES('legacy_inbounds_migrated_to_flat', '1')"
    )


def _migrate_users_v4(con):
    """v3 → v4 migration mirroring internal/userdb/schema.go::migrateUsersV4.

    Adds users.quota_baseline if missing. The v2 → v3 rebuild path in
    _migrate_users_v3 already includes the column in the rebuilt CREATE
    TABLE, so this only fires when the DB previously stopped at v3
    (post-multi-user-cleanup, pre-quota-reset-split).

    Idempotent: PRAGMA-driven, re-runs are no-ops on already-v4 schemas.
    """
    cols = {r["name"]: r for r in con.execute("PRAGMA table_info(users)").fetchall()}
    if not cols:
        # Fresh DB; CREATE TABLE IF NOT EXISTS already produced a v4 shape.
        return
    if "quota_baseline" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN quota_baseline INTEGER NOT NULL DEFAULT 0")


def _migrate_users_v5(con):
    """v4 → v5 migration mirroring internal/userdb/schema.go::migrateUsersV5.

    Adds users.notification_text if missing. Phase C iOS-notify pipeline
    (2026-05-10): the column carries the per-user notification body the
    operator set via the panel ("BROADCAST: " prefix marks system-wide).
    The server reads it during bundle delivery and surfaces it to clients;
    notification_pending=1 is the trigger flag.

    Idempotent: PRAGMA-driven, re-runs are no-ops on already-v5 schemas.
    """
    cols = {r["name"]: r for r in con.execute("PRAGMA table_info(users)").fetchall()}
    if not cols:
        return
    if "notification_text" not in cols:
        con.execute("ALTER TABLE users ADD COLUMN notification_text TEXT")


def _normalize_panel_username(username):
    username = (username or "").strip()
    if not PANEL_USERNAME_RE.fullmatch(username):
        raise ValueError("panel username must be 1-64 chars: letters, digits, _ . @ -")
    return username


def hash_panel_password(password, *, salt_hex=None, iterations=None):
    if password is None or password == "":
        raise ValueError("panel password must not be empty")
    iterations = int(iterations or PANEL_PBKDF2_ITERATIONS)
    if iterations < 100000:
        raise ValueError("panel password hash iterations too low")
    salt_hex = salt_hex or secrets.token_hex(16)
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt_hex}${digest.hex()}"


def verify_panel_password(stored_hash, password):
    try:
        algo, iter_s, salt_hex, digest_hex = (stored_hash or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        expected = hash_panel_password(password or "", salt_hex=salt_hex, iterations=int(iter_s))
        return hmac.compare_digest(expected, stored_hash)
    except Exception:
        return False


def _set_panel_admin_in_conn(con, username, password, now=None):
    username = _normalize_panel_username(username)
    password_hash = hash_panel_password(password)
    now = int(now or time.time())
    existing = con.execute("SELECT created_at FROM panel_admins WHERE username=?", (username,)).fetchone()
    created_at = int(existing["created_at"]) if existing else now
    con.execute(
        "INSERT INTO panel_admins(username, password_hash, created_at, updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, updated_at=excluded.updated_at",
        (username, password_hash, created_at, now),
    )
    con.execute("DELETE FROM panel_sessions WHERE username=?", (username,))
    if isinstance(globals().get("sessions"), dict):
        for token, session_user in list(sessions.items()):
            if session_user == username:
                sessions.pop(token, None)
    return username


def set_panel_admin(username, password):
    ensure_db()
    with db_conn() as con:
        return _set_panel_admin_in_conn(con, username, password)


def panel_admin_usernames():
    ensure_db()
    with db_conn() as con:
        rows = con.execute("SELECT username FROM panel_admins ORDER BY username").fetchall()
    return [r["username"] for r in rows]


def check_panel_password(username, password):
    username = (username or "").strip()
    if not username or password is None:
        return False
    try:
        ensure_db()
        with db_conn() as con:
            row = con.execute("SELECT password_hash FROM panel_admins WHERE username=?", (username,)).fetchone()
        return bool(row and verify_panel_password(row["password_hash"], password))
    except Exception:
        return False


def _bootstrap_panel_admin_from_env(con, now):
    username = os.environ.get("TAMIZDAT_PANEL_ADMIN_USER", "").strip()
    password = os.environ.get("TAMIZDAT_PANEL_ADMIN_PASSWORD", "")
    if not username or not password:
        return
    force = os.environ.get("TAMIZDAT_PANEL_ADMIN_FORCE_UPDATE", "").strip().lower() in ("1", "true", "yes")
    exists = con.execute("SELECT 1 FROM panel_admins WHERE username=?", (username,)).fetchone()
    if exists and not force:
        return
    _set_panel_admin_in_conn(con, username, password, now=now)


# ensure_db ran on EVERY API call previously, each time doing BEGIN
# IMMEDIATE (exclusive write lock) + schema migrations. Under
# ThreadingHTTPServer (2026-05-11) that produced a lock storm — the
# Go server-app's user_accounting flush kept hitting SQLITE_BUSY
# every few seconds, and concurrent panel writes (e.g. creating a
# user) deadlocked. Make schema/bootstrap a one-shot at process start.
_ensure_db_done = False

def ensure_db():
    global _ensure_db_done
    if _ensure_db_done:
        return
    with _db_lock:
        if _ensure_db_done:
            return
        with db_conn() as con:
            # journal_mode is a one-shot pragma that persists in the DB file
            # header. Set once here at schema-ensure time so per-request
            # db_conn() doesn't repeat it under ThreadingHTTPServer load.
            try:
                con.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass
            # BEGIN IMMEDIATE serializes concurrent first-run schema/bootstrap work
            # before any schema reads, avoiding SQLite deferred-transaction lock races.
            con.executescript("BEGIN IMMEDIATE;\n" + SCHEMA_SQL)
            _migrate_outbounds_bind_iface(con)
            _migrate_outbounds_bytes_counters(con)
            _migrate_outbounds_h2_peak(con)
            _migrate_routing_group_name(con)
            _migrate_routing_folders(con)
            _migrate_users_v3(con)
            _migrate_users_v4(con)
            _migrate_users_v5(con)
            _migrate_users_rate_limit_mbps(con)
            _migrate_users_h2_peak(con)
            _migrate_users_turn_profile(con)
            _migrate_user_sessions_transport(con)
            _migrate_panel_test_target_to_url(con)
            now = int(time.time())
            # INSERT OR IGNORE is atomic + idempotent: it avoids concurrent
            # first-run SELECT/INSERT races while preserving operator edits on
            # existing bootstrap rows.
            con.execute("INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES('direct', 'direct', NULL, 'Direct dial from server IP', ?, ?)", (now, now))
            # Auto-create a 'block' blackhole outbound so routing rules can
            # point at it for blocking (Windows telemetry, ads, RKN, …).
            # Server registers BlackholeDialer for kind=blackhole as of
            # 2026-05-13 — prior builds crashed at startup on unknown kind,
            # which is why this row was briefly disabled. Safe again now.
            con.execute("INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES('block', 'blackhole', NULL, 'Blackhole — drops every connection', ?, ?)", (now, now))
            for k, v in DEFAULT_SETTINGS.items():
                con.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
            _bootstrap_panel_admin_from_env(con, now)
            con.execute("INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', '7')")
            con.execute("DELETE FROM settings WHERE key='schema_version'")
            _migrate_legacy_if_needed(con)
            _bootstrap_legacy_shortid(con)
            _bootstrap_default_routing_rule(con, now)
            # Settings refactor Phase 2 (2026-05-11): one-shot copy of legacy
            # panel_inbounds_json (Phase 1 JSON-blob store) into the flat
            # inbound_* settings table. Runs AFTER DEFAULT_SETTINGS inserts so
            # the migration can compare a flat key against its default and
            # decide "this is fresh, promote legacy value". Idempotent via the
            # legacy_inbounds_migrated_to_flat schema_meta marker.
            _migrate_legacy_inbounds_json_to_flat(con)
        # mark done only after full schema/bootstrap pass succeeds
        _ensure_db_done = True


def _bootstrap_default_routing_rule(con, now):
    """CL-4 (2026-05-10): on a fresh install, once the operator has at
    least one non-direct outbound configured, auto-add a catch-all
    routing rule pointing to that outbound. This makes out-of-the-box
    behaviour predictable: the panel ships a routing rule that says
    "default → tamizdat outbound" instead of relying on the implicit
    default_outbound_tag fallback that lived in the old "Set default"
    button (CL-2 removed).

    Idempotent via the schema_meta `default_route_bootstrapped` marker.
    Once set, re-running ensure_db never re-creates the rule, even if
    the operator has since deleted it. The rule is a normal DB row, so
    the operator can drag/up-down-reorder it like any other (CL-5).

    Skipped when there is no non-direct outbound yet — we re-check on
    every ensure_db call (every API hit) so the rule lands as soon as
    the operator imports their first tamizdat outbound.
    """
    bootstrapped = con.execute(
        "SELECT 1 FROM schema_meta WHERE key='default_route_bootstrapped'"
    ).fetchone()
    if bootstrapped:
        return
    # If the operator already has routing rules (e.g. upgraded from a
    # previous panel version where they configured rules manually),
    # don't inject a catch-all on top — just stamp the marker so we
    # never try again, and let the existing rules stand.
    rule_count = con.execute("SELECT COUNT(*) AS n FROM routing_rules").fetchone()["n"]
    if int(rule_count or 0) > 0:
        con.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) "
            "VALUES('default_route_bootstrapped', '1')"
        )
        return
    # 2026-05-12: changed default catch-all from "first non-direct outbound"
    # to a hard 'direct' tag. Rationale: a fresh install should produce a
    # working "internet just works from this server's own IP" baseline, not
    # silently pin everything onto whatever outbound happens to sort first
    # alphabetically (which on a fresh mirror was the auto-created 'block'
    # blackhole — operator got a server that dropped all traffic by default
    # and had to delete the bogus rule + restart to recover).
    outbound_tag = "direct"
    # priority = max+1 so the rule lands at the bottom of the list
    # (catch-all-last). Operator can drag/move-up afterwards.
    pr_row = con.execute("SELECT COALESCE(MAX(priority), 0) AS m FROM routing_rules").fetchone()
    priority = int(pr_row["m"] or 0) + 1
    con.execute(
        "INSERT INTO routing_rules(priority, outbound_tag, match_json, "
        "description_override, enabled, created_at, updated_at) "
        "VALUES(?, ?, ?, ?, 1, ?, ?)",
        (priority, outbound_tag, "{}",
         "default — route everything via " + outbound_tag,
         now, now),
    )
    con.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) "
        "VALUES('default_route_bootstrapped', '1')"
    )

def _load_sessions():
    try:
        ensure_db()
        now = int(time.time())
        with db_conn() as con:
            con.execute("DELETE FROM panel_sessions WHERE expires_at <= ?", (now,))
            rows = con.execute("SELECT token, username FROM panel_sessions WHERE expires_at > ?", (now,)).fetchall()
        return {r["token"]: r["username"] for r in rows}
    except Exception as e:
        print(f"session load warning: {e}")
        return {}

def _save_sessions():
    try:
        ensure_db()
        now = int(time.time())
        with db_conn() as con:
            con.execute("DELETE FROM panel_sessions")
            for token, username in sessions.items():
                con.execute("INSERT OR REPLACE INTO panel_sessions(token, username, created_at, expires_at) VALUES(?,?,?,?)",
                            (token, username, now, now + SESSION_TTL))
    except Exception as e:
        print(f"session save warning: {e}")

def _session_username(token):
    token = (token or "").strip()
    if not token:
        return None
    now = int(time.time())
    try:
        ensure_db()
        with db_conn() as con:
            row = con.execute("SELECT username, expires_at FROM panel_sessions WHERE token=?", (token,)).fetchone()
            if not row or int(row["expires_at"]) <= now:
                con.execute("DELETE FROM panel_sessions WHERE token=?", (token,))
                sessions.pop(token, None)
                return None
            con.execute("UPDATE panel_sessions SET expires_at=? WHERE token=?", (now + SESSION_TTL, token))
            sessions[token] = row["username"]
            return row["username"]
    except Exception:
        return sessions.get(token)

sessions = _load_sessions()

# Phase 1 traffic stubs. Phase 2 will move traffic accounting into the shared DB.
_traffic = {}
_traffic_lock = threading.Lock()
_global_traffic = {"download": 0, "upload": 0, "_last_clash_dl": 0, "_last_clash_ul": 0}
_ob_traffic = {}

# CPU% needs two samples of /proc/stat with a real-time delta between
# them. Previous design kept a single shared _sysinfo_prev pair and let
# the per-request delta be "time since the last call hit this lock".
# With multiple endpoints (browser polling /api/sysinfo every 5 s AND
# /api/sysinfo/cpu every 500 ms plus any external scraper) the delta
# collapsed to whatever the inter-call gap happened to be — sometimes
# 10-50 ms, which on HZ=100 yields 1-5 jiffies and per-sample noise of
# 20-100%. Panel rings then bounced between 0 % and 100 % at random
# while top showed a calm 12 %.
#
# Fix: every _read_cpu_pct() takes its OWN 100 ms snapshot in-line.
# No shared cross-request state, no lock contention, deterministic
# 10 jiffies per sample = ~10 % worst-case quantization noise (well
# below human perception in a CPU-gauge). 100 ms latency per call is
# bounded and capped by the 500 ms poll cadence so no congestion.
def _read_cpu_pct():
    def _snap():
        try:
            with open("/proc/stat", "r") as f:
                parts = f.readline().split()
        except Exception:
            return None
        # cpu  user nice system idle iowait irq softirq steal guest guest_nice
        vals = [int(x) for x in parts[1:8]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        return sum(vals), idle
    a = _snap()
    if a is None:
        return 0.0
    time.sleep(0.1)
    b = _snap()
    if b is None:
        return 0.0
    dt = b[0] - a[0]
    di = b[1] - a[1]
    if dt <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (dt - di) * 100.0 / dt)), 2)


def _read_meminfo():
    """Returns (mem_total_b, mem_used_b, swap_total_b, swap_used_b).
    'used' follows the htop convention: total - free - buffers - cached -
    slab_reclaimable, i.e. memory genuinely held by processes.
    """
    info = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                k = parts[0].strip()
                v = parts[1].strip().split()
                if not v:
                    continue
                try:
                    info[k] = int(v[0]) * 1024  # /proc/meminfo is in kB
                except ValueError:
                    pass
    except Exception:
        pass
    mt = info.get("MemTotal", 0)
    mf = info.get("MemFree", 0)
    buf = info.get("Buffers", 0)
    cache = info.get("Cached", 0)
    slab = info.get("SReclaimable", 0)
    used = max(0, mt - mf - buf - cache - slab)
    st = info.get("SwapTotal", 0)
    sf = info.get("SwapFree", 0)
    swap_used = max(0, st - sf)
    return mt, used, st, swap_used


def _read_disk():
    """Free + total bytes on /. Statvfs picks up the live mount."""
    try:
        s = os.statvfs("/")
        total = s.f_blocks * s.f_frsize
        free = s.f_bavail * s.f_frsize
        used = max(0, total - free)
        return total, used
    except Exception:
        return 0, 0


def get_sysinfo():
    cpu = _read_cpu_pct()
    mt, mu, st, su = _read_meminfo()
    dt, du = _read_disk()
    def pct(used, total):
        return round(used * 100.0 / total, 2) if total else 0.0
    return {
        "cpu_pct":      cpu,
        "mem_total":    mt,
        "mem_used":     mu,
        "mem_pct":      pct(mu, mt),
        "swap_total":   st,
        "swap_used":    su,
        "swap_pct":     pct(su, st),
        "disk_total":   dt,
        "disk_used":    du,
        "disk_pct":     pct(du, dt),
    }

def _load_traffic():
    return None

def _save_traffic():
    return None

def _get_user_traffic(username):
    return {"download": 0, "upload": 0}

def _reset_user_traffic(username):
    """Legacy helper kept for callsite compatibility. The actual per-user
    reset lives in reset_user_bytes(user_id) at L587; this stub returned
    None which silently swallowed callers' intent. 2026-05-11 audit
    flagged this as a UI-lie regression — now routes through the real
    bytes reset by username lookup."""
    ensure_db()
    if not username:
        return None
    now = int(time.time())
    with db_conn() as con:
        con.execute(
            "UPDATE users SET bytes_up=0, bytes_down=0, quota_baseline=0, "
            "bytes_reset_at=?, notification_pending=0, notification_text=NULL, updated_at=? "
            "WHERE name=?",
            (now, now, username),
        )
    _sighup_server()
    return None

def _reset_all_traffic():
    """Danger-zone "Reset all traffic counters" — zero bytes_up + bytes_down
    + quota_baseline for EVERY user. The previous stub returned None and the
    UI toast lied "All traffic counters reset" while the DB was untouched.
    2026-05-11 audit flagged as new regression from mockup port; this
    implementation makes the button actually reset.
    """
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        con.execute(
            "UPDATE users SET bytes_up=0, bytes_down=0, quota_baseline=0, "
            "bytes_reset_at=?, notification_pending=0, notification_text=NULL, updated_at=?",
            (now, now),
        )
    _sighup_server()
    return None

def _reset_ob_traffic(tag):
    """Zero per-outbound byte counters for a tag. Called from the
    "Reset" pill on the Outbounds table. Server-side counters are
    accumulated in userdb.Accounting and flushed to outbounds.bytes_up /
    bytes_down — this UPDATE wipes the persisted total to 0, then the
    next Flush adds fresh deltas on top.

    Idempotent on missing tags (UPDATE just touches 0 rows). NULL/empty
    tag is a panel-side bug guard — log and skip.
    """
    if not tag or not isinstance(tag, str):
        return None
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        con.execute(
            "UPDATE outbounds SET bytes_up=0, bytes_down=0, updated_at=? WHERE tag=?",
            (now, tag),
        )
    return None


def _reset_all_ob_traffic():
    """Danger-zone analog of _reset_all_traffic for outbounds. Wipes
    every outbound's bytes_up / bytes_down in one transaction.
    Currently unwired in the UI — kept for parity with the user-side
    "Reset all" button so a future Danger-zone block can call it.
    """
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        con.execute("UPDATE outbounds SET bytes_up=0, bytes_down=0, updated_at=?", (now,))
    return None


# --- Geo-categories enumeration --------------------------------------------
# Extract category names from /etc/tamizdat/{geoip,geosite[-N]}.dat files so
# the routing-rule modal can offer a searchable picker for ALL ~1200
# Loyalsoldier + ~1210 runetfreedom tags, not just the curated shortlist.
# Cached in memory + invalidated on file mtime change. Geosite results are
# merged across all `geosite*.dat` files (runetfreedom is geosite-1.dat).

_geo_cats_cache = {"mtime": 0, "data": {"geoip": [], "geosite": []}}
_geo_cats_lock = threading.Lock()

def _geo_cat_files():
    base = "/etc/tamizdat"
    return {
        "geoip": [os.path.join(base, n) for n in os.listdir(base) if re.match(r"geoip(-\d+)?\.dat$", n)] if os.path.isdir(base) else [],
        "geosite": [os.path.join(base, n) for n in os.listdir(base) if re.match(r"geosite(-\d+)?\.dat$", n)] if os.path.isdir(base) else [],
    }

# ISO 3166-1 alpha-2 country codes. Used to whitelist 2-letter geoip
# tag strings extracted from .dat files: random protobuf byte-pairs like
# 'AA', 'AB', 'AZ' satisfy [A-Z]{2} but aren't real categories. ~250 real
# codes; everything outside this set in 2-char form is junk.
_ISO_3166_ALPHA2 = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ
EC EE EG EH ER ES ET
FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT
JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ
OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA
RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ
VA VC VE VG VI VN VU
WF WS
YE YT
ZA ZM ZW
""".split())


def _extract_category_names(path):
    """v2ray-rules-dat / Loyalsoldier files are protobuf-encoded but the
    category-name strings are stored as plain UPPERCASE ASCII runs inside
    the blob (one per `SiteGroup.tag` / `GeoIP.country_code`). A strings-
    style scan with a strict UPPERCASE-ASCII-only filter pulls them out
    without needing a protobuf parser dependency.

    2-letter strings are matched against an ISO 3166-1 alpha-2 whitelist
    because random byte-pairs like 'AA', 'XY' satisfy regex but aren't
    real geo categories. 3+ char strings keep the broader pattern.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return []
    out = []
    pat_2 = re.compile(rb"^[A-Z]{2}$")
    # 3+ chars: require the first two characters to be letters (real
    # category names always start with words: TELEGRAM, GOOGLE, CATEGORY-,
    # WIN-, RU-, ...). Random 3-char protobuf byte-triples like 'A1-',
    # 'A6!', 'AB7' pass the looser regex but are noise.
    # {1,62} (not {0,62}) forces total length >= 3 so 2-char strings
    # take the ISO-whitelisted branch only.
    pat_long = re.compile(rb"^[A-Z][A-Z][A-Z0-9!_-]{1,62}$")
    for m in re.finditer(rb"[!-~]{2,}", data):
        s = m.group()
        if pat_2.match(s):
            if s.decode("ascii") in _ISO_3166_ALPHA2:
                out.append(s.decode("ascii").lower())
        elif pat_long.match(s):
            out.append(s.decode("ascii", errors="ignore").lower())
    return out

def _load_geo_categories():
    files = _geo_cat_files()
    paths = files["geoip"] + files["geosite"]
    mtime = 0
    for p in paths:
        try:
            mtime = max(mtime, int(os.path.getmtime(p)))
        except Exception:
            pass
    with _geo_cats_lock:
        if _geo_cats_cache["mtime"] == mtime and _geo_cats_cache["data"]["geoip"]:
            return _geo_cats_cache["data"]
        geoip = set()
        for p in files["geoip"]:
            for n in _extract_category_names(p):
                geoip.add(n)
        geosite = set()
        for p in files["geosite"]:
            for n in _extract_category_names(p):
                geosite.add(n)
        result = {"geoip": sorted(geoip), "geosite": sorted(geosite)}
        _geo_cats_cache["mtime"] = mtime
        _geo_cats_cache["data"] = result
        return result


_load_traffic()

# --- Live log parser: maps IP -> username via journalctl ---
_conn_ip = {}       # connID -> IP
_ip_user = {}       # IP -> username
_ip_user_lock = threading.Lock()
IP_USER_FILE = "/var/lib/tamizdat-panel/ip_user.json"

_RE_CONN_FROM = re.compile(r'\[(\d+)\s+\d+ms\].*inbound connection from (\d+\.\d+\.\d+\.\d+):\d+')
_RE_CONN_USER = re.compile(r'\[(\d+)\s+\d+ms\].*\[([^\]]+)\]\s+inbound connection to')


def _load_ip_user():
    global _ip_user
    try:
        if os.path.exists(IP_USER_FILE):
            with open(IP_USER_FILE, "r") as f:
                _ip_user = json.load(f)
            print(f"Loaded IP->user map: {len(_ip_user)} entries")
    except Exception as e:
        print(f"Error loading IP->user map: {e}")

def _save_ip_user():
    try:
        os.makedirs(os.path.dirname(IP_USER_FILE), exist_ok=True)
        with _ip_user_lock:
            data = dict(_ip_user)
        with open(IP_USER_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

_load_ip_user()


def _parse_log_line(line):
    m = _RE_CONN_FROM.search(line)
    if m:
        conn_id, ip = m.group(1), m.group(2)
        _conn_ip[conn_id] = ip
        if len(_conn_ip) > 10000:
            for k in list(_conn_ip.keys())[:5000]:
                _conn_ip.pop(k, None)
        return
    m = _RE_CONN_USER.search(line)
    if m:
        conn_id, username = m.group(1), m.group(2)
        ip = _conn_ip.get(conn_id)
        if ip:
            with _ip_user_lock:
                _ip_user[ip] = username


def _lookup_ip_user_journal(ip):
    """On-demand journal lookup for an unmapped IP.
    Two-step: grep journal for IP to get conn_ids, then search those conn_ids for username."""
    try:
        # Step 1: find conn_ids associated with this IP
        r = subprocess.run(
            ["journalctl", "-u", SERVICE_NAME, "--no-pager", "-n", "5000", "--grep", ip],
            capture_output=True, text=True, timeout=3
        )
        conn_ids = set()
        for line in r.stdout.splitlines():
            m = _RE_CONN_FROM.search(line)
            if m and m.group(2) == ip:
                conn_ids.add(m.group(1))
        if not conn_ids:
            return ""
        # Step 2: search for username lines matching those conn_ids
        for cid in list(conn_ids)[-20:]:  # check last 20 conn_ids
            r2 = subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "--no-pager", "-n", "5000", "--grep", cid],
                capture_output=True, text=True, timeout=2
            )
            for line in r2.stdout.splitlines():
                m = _RE_CONN_USER.search(line)
                if m and m.group(1) == cid:
                    username = m.group(2)
                    with _ip_user_lock:
                        _ip_user[ip] = username
                    return username
    except Exception:
        pass
    return ""


def _log_tailer():
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", SERVICE_NAME, "-f", "--no-pager", "-n", "5000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in proc.stdout:
                _parse_log_line(line.strip())
        except Exception:
            pass
        time.sleep(2)


threading.Thread(target=_log_tailer, daemon=True).start()

# Periodic IP->user map saver (every 60s, alongside traffic)
def _ip_user_saver():
    while True:
        time.sleep(60)
        _save_ip_user()

threading.Thread(target=_ip_user_saver, daemon=True).start()

# Periodic traffic saver
def _traffic_saver():
    while True:
        time.sleep(60)
        _save_traffic()

threading.Thread(target=_traffic_saver, daemon=True).start()


def get_ip_user_map():
    with _ip_user_lock:
        return dict(_ip_user)


# Server-side cache for /api/clients (fixes F5 flicker)
_clients_cache = {"data": None, "time": 0}
_clients_last_good = {"data": None, "time": 0}  # last result with online users
_user_last_online = {}  # username -> timestamp (server-side last seen)


# Panel credentials are stored in panel_admins as PBKDF2 hashes. OS account
# authentication was intentionally removed: panel access is now independent
# from system users and is initialized by the installer or
# `tamizdat-panel.py --set-admin`.


def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


_restart_timer = None
_restart_lock = threading.Lock()


def _do_restart_tamizdat_server():
    try:
        subprocess.Popen(["systemctl", "restart", SERVICE_NAME])
    except Exception as e:
        print(f"restart error: {e}")


def save_config(config):
    global _restart_timer
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    # Debounce restarts: several quick saves in a row (add user, set outbound,
    # rename…) coalesce into a single restart 0.8s after the last save.
    with _restart_lock:
        if _restart_timer is not None:
            _restart_timer.cancel()
        _restart_timer = threading.Timer(0.8, _do_restart_tamizdat_server)
        _restart_timer.daemon = True
        _restart_timer.start()


def get_users(config):
    for ib in config.get("inbounds", []):
        if ib.get("type") in ("tamizdat", "anytls"):
            return ib.get("users", [])
    return []


def set_users(config, users):
    for ib in config.get("inbounds", []):
        if ib.get("type") in ("tamizdat", "anytls"):
            ib["users"] = users
            break
    save_config(config)


def get_outbounds(config):
    return config.get("outbounds", [])


def get_active_outbound(config):
    return config.get("route", {}).get("final", "direct")


# -------------------------------------------------------------------------
# Panel v5: routing rules CRUD
# -------------------------------------------------------------------------
#
# routing_rules rows are consumed by tamizdat-server at startup and SIGHUP
# reload. Every modifying endpoint below ends with _sighup_server() so the
# server picks up changes without a restart. Match payload is stored as
# JSON (match_json column) for forward-compat with new match types; the
# server-side rulesdb package only honours the keys it knows about.

ROUTING_MATCH_KEYS = ("geoip", "geosite", "ip", "domain", "source", "port", "network", "inbound_tag", "user")


def _routing_row_to_dict(row):
    try:
        match = json.loads(row["match_json"]) if row["match_json"] else {}
    except Exception:
        match = {}
    out = {
        "id": row["id"],
        "priority": row["priority"],
        "outbound_tag": row["outbound_tag"],
        "match": match,
        "description_override": row["description_override"] or "",
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    try:
        out["group_name"] = row["group_name"] or ""
    except (IndexError, KeyError):
        out["group_name"] = ""
    # folders v1 (2026-05-10): folder_id may be NULL for ungrouped rules
    # OR may be absent entirely on a pre-migration row read (legacy SELECT).
    try:
        fid = row["folder_id"]
        out["folder_id"] = int(fid) if fid is not None else None
    except (IndexError, KeyError):
        out["folder_id"] = None
    return out


def _routing_row_to_dict_BAK_REPLACED(row):
    try:
        match = json.loads(row["match_json"]) if row["match_json"] else {}
    except Exception:
        match = {}
    return {
        "id": row["id"],
        "priority": row["priority"],
        "outbound_tag": row["outbound_tag"],
        "description_override": row["description_override"] or "",
        "description": _routing_auto_description(match) if not row["description_override"] else row["description_override"],
        "match": match,
        "enabled": int(row["enabled"]) == 1,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _routing_auto_description(match):
    parts = []
    for name in ("geoip", "geosite"):
        for v in (match.get(name) or []):
            parts.append(f"{name}:{v}")
    for v in (match.get("ip") or []):
        parts.append(f"ip:{v}")
    for v in (match.get("domain") or []):
        parts.append(f"domain:{v}")
    for v in (match.get("user") or []):
        parts.append(f"User:{v}")
    for v in (match.get("source") or []):
        parts.append(f"src:{v}")
    if match.get("port"):
        parts.append(f"port:{match['port']}")
    if match.get("network"):
        parts.append(f"net:{match['network']}")
    for v in (match.get("inbound_tag") or []):
        parts.append(f"in:{v}")
    return ", ".join(parts) if parts else "(match all)"


def _routing_validate_match(raw):
    if not isinstance(raw, dict):
        raise ValueError("match must be an object")
    out = {}
    # list-valued categories
    for key in ("geoip", "geosite", "ip", "domain", "source", "user", "inbound_tag"):
        v = raw.get(key)
        if v is None or v == "":
            continue
        if isinstance(v, str):
            v = [s.strip() for s in v.split(",") if s.strip()]
        if not isinstance(v, list):
            raise ValueError(f"match.{key} must be list or comma-string")
        v = [str(s).strip() for s in v if str(s).strip()]
        if v:
            out[key] = v
    port = (raw.get("port") or "").strip() if isinstance(raw.get("port"), str) else raw.get("port")
    if port:
        out["port"] = str(port).strip()
    nw = (raw.get("network") or "").strip().lower() if isinstance(raw.get("network"), str) else None
    if nw:
        if nw not in ("tcp", "udp", "tcp,udp", "udp,tcp"):
            raise ValueError("network must be tcp|udp|tcp,udp")
        out["network"] = nw
    return out


def list_routing_rules():
    """List every routing rule with its folder_id annotation. The
    rendered/iterated order is determined by the *caller* (panel JS)
    composing rules with folders into a hierarchy; this helper returns
    a stable but flat slice keyed first by folder_id NULLS FIRST then
    intra-folder priority — sufficient for both the panel UI and the
    occasional debug dump."""
    ensure_db()
    with db_conn() as con:
        rows = con.execute(
            "SELECT id, priority, outbound_tag, match_json, description_override, enabled, "
            "COALESCE(group_name, '') AS group_name, folder_id, created_at, updated_at "
            "FROM routing_rules "
            "ORDER BY (folder_id IS NULL) DESC, folder_id ASC, priority ASC, id ASC"
        ).fetchall()
    return [_routing_row_to_dict(r) for r in rows]


def list_routing_folders():
    """Return [{id,name,priority,enabled,...}] in priority order."""
    ensure_db()
    with db_conn() as con:
        rows = con.execute(
            "SELECT id, name, priority, enabled, created_at, updated_at "
            "FROM routing_folders ORDER BY priority ASC, id ASC"
        ).fetchall()
    return [
        {
            "id": int(r["id"]),
            "name": r["name"] or "",
            "priority": int(r["priority"]),
            "enabled": bool(r["enabled"]),
            "created_at": int(r["created_at"]),
            "updated_at": int(r["updated_at"]),
        }
        for r in rows
    ]


def _validate_folder_name(name):
    name = (name or "").strip()
    if not name:
        raise ValueError("name required")
    if len(name) > 64:
        raise ValueError("name max 64 chars")
    return name


def _folder_exists(con, folder_id):
    if folder_id is None:
        return False
    row = con.execute("SELECT 1 FROM routing_folders WHERE id=?", (int(folder_id),)).fetchone()
    return bool(row)


def create_routing_folder(body):
    """Create a new routing_folders row at the bottom of the global
    queue (priority = MAX(folders.priority, ungrouped.priority) + 1)."""
    if not isinstance(body, dict):
        raise ValueError("body must be object")
    name = _validate_folder_name(body.get("name"))
    enabled = 0 if body.get("enabled") is False else 1
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        # Append at the end of the global queue: max(folders.priority,
        # ungrouped rules.priority) + 1.
        f_max = con.execute("SELECT COALESCE(MAX(priority),0) AS m FROM routing_folders").fetchone()["m"]
        r_max = con.execute(
            "SELECT COALESCE(MAX(priority),0) AS m FROM routing_rules WHERE folder_id IS NULL"
        ).fetchone()["m"]
        priority = max(int(f_max or 0), int(r_max or 0)) + 1
        cur = con.execute(
            "INSERT INTO routing_folders(name, priority, enabled, created_at, updated_at) "
            "VALUES(?,?,?,?,?)",
            (name, priority, enabled, now, now),
        )
        folder_id = cur.lastrowid
        row = con.execute(
            "SELECT id, name, priority, enabled, created_at, updated_at "
            "FROM routing_folders WHERE id=?", (folder_id,),
        ).fetchone()
    _sighup_server()
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "priority": int(row["priority"]),
        "enabled": bool(row["enabled"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def update_routing_folder(folder_id, body):
    if not isinstance(body, dict):
        raise ValueError("body must be object")
    folder_id = int(folder_id)
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        row = con.execute("SELECT id FROM routing_folders WHERE id=?", (folder_id,)).fetchone()
        if not row:
            raise ValueError("folder not found")
        sets, args = [], []
        if "name" in body:
            sets.append("name=?"); args.append(_validate_folder_name(body.get("name")))
        if "enabled" in body:
            sets.append("enabled=?"); args.append(0 if body.get("enabled") is False else 1)
        if "priority" in body and body.get("priority") is not None:
            sets.append("priority=?"); args.append(int(body["priority"]))
        if not sets:
            raise ValueError("nothing to update")
        sets.append("updated_at=?"); args.append(now)
        args.append(folder_id)
        con.execute(f"UPDATE routing_folders SET {', '.join(sets)} WHERE id=?", args)
        row = con.execute(
            "SELECT id, name, priority, enabled, created_at, updated_at "
            "FROM routing_folders WHERE id=?", (folder_id,),
        ).fetchone()
    _sighup_server()
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "priority": int(row["priority"]),
        "enabled": bool(row["enabled"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def delete_routing_folder(folder_id):
    """Delete a folder. Member rules are re-parented to NULL (ungrouped)
    and slotted into the global queue at consecutive priorities starting
    where the folder previously sat. The deletion is destructive only to
    the folder row, not the rules — operator can manually delete those
    afterwards if desired."""
    folder_id = int(folder_id)
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        row = con.execute(
            "SELECT priority FROM routing_folders WHERE id=?", (folder_id,)
        ).fetchone()
        if not row:
            raise ValueError("folder not found")
        folder_pr = int(row["priority"])
        member_rows = con.execute(
            "SELECT id, priority FROM routing_rules "
            "WHERE folder_id=? ORDER BY priority ASC, id ASC", (folder_id,),
        ).fetchall()
        # Free up global slots for the orphaned members: shift everyone
        # at gp > folder_pr (folders + ungrouped rules) by len(members).
        n = len(member_rows)
        if n:
            con.execute(
                "UPDATE routing_folders SET priority=priority+?, updated_at=? "
                "WHERE priority>?", (n, now, folder_pr),
            )
            con.execute(
                "UPDATE routing_rules SET priority=priority+?, updated_at=? "
                "WHERE folder_id IS NULL AND priority>?", (n, now, folder_pr),
            )
            for offset, mrow in enumerate(member_rows):
                con.execute(
                    "UPDATE routing_rules SET folder_id=NULL, priority=?, updated_at=? "
                    "WHERE id=?", (folder_pr + offset, now, int(mrow["id"])),
                )
        con.execute("DELETE FROM routing_folders WHERE id=?", (folder_id,))
    _sighup_server()
    return {"ok": True, "orphaned_rules": len(member_rows)}


def move_routing_folder(folder_id, direction):
    """Swap a folder's global priority with its nearest neighbour in the
    GLOBAL queue (folder OR ungrouped rule).  Used by the ↑/↓ arrow
    buttons on the folder header."""
    folder_id = int(folder_id)
    direction = (direction or "").lower()
    if direction not in ("up", "down"):
        raise ValueError("direction must be 'up' or 'down'")
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        row = con.execute(
            "SELECT priority FROM routing_folders WHERE id=?", (folder_id,)
        ).fetchone()
        if not row:
            raise ValueError("folder not found")
        cur_pr = int(row["priority"])
        # Look at the global queue (folders + ungrouped rules) to find the
        # neighbour. Prefer folders on tie (id-stable).
        if direction == "up":
            cand_f = con.execute(
                "SELECT id, priority FROM routing_folders "
                "WHERE priority<? ORDER BY priority DESC, id DESC LIMIT 1",
                (cur_pr,),
            ).fetchone()
            cand_r = con.execute(
                "SELECT id, priority FROM routing_rules "
                "WHERE folder_id IS NULL AND priority<? "
                "ORDER BY priority DESC, id DESC LIMIT 1",
                (cur_pr,),
            ).fetchone()
        else:
            cand_f = con.execute(
                "SELECT id, priority FROM routing_folders "
                "WHERE priority>? ORDER BY priority ASC, id ASC LIMIT 1",
                (cur_pr,),
            ).fetchone()
            cand_r = con.execute(
                "SELECT id, priority FROM routing_rules "
                "WHERE folder_id IS NULL AND priority>? "
                "ORDER BY priority ASC, id ASC LIMIT 1",
                (cur_pr,),
            ).fetchone()
        # Pick whichever neighbour is closer in priority.
        cand = None
        if cand_f and cand_r:
            df = abs(int(cand_f["priority"]) - cur_pr)
            dr = abs(int(cand_r["priority"]) - cur_pr)
            cand = ("folder", cand_f) if df <= dr else ("rule", cand_r)
        elif cand_f:
            cand = ("folder", cand_f)
        elif cand_r:
            cand = ("rule", cand_r)
        if not cand:
            return {"ok": True, "noop": True}
        kind, other = cand
        other_pr = int(other["priority"])
        # Two-step swap via tmp negative priority to dodge any future unique constraint.
        con.execute(
            "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
            (-1 - cur_pr, now, folder_id),
        )
        if kind == "folder":
            con.execute(
                "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
                (cur_pr, now, int(other["id"])),
            )
        else:
            con.execute(
                "UPDATE routing_rules SET priority=?, updated_at=? "
                "WHERE id=? AND folder_id IS NULL",
                (cur_pr, now, int(other["id"])),
            )
        con.execute(
            "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
            (other_pr, now, folder_id),
        )
    _sighup_server()
    return {"ok": True}


def reorder_routing_folders(ids):
    """Set folders.priority = position-in-list. Ungrouped rule
    priorities are NOT touched — caller is expected to send a separate
    /api/routing/reorder for those, or to use the unified
    reorder_global_queue helper if they want a single round-trip.

    Idempotent: missing ids leave their rows untouched, extra ids are
    ignored.  Two-pass via negative tmp priority to avoid uniqueness
    collision (currently no UNIQUE on priority but defensive)."""
    if not isinstance(ids, list):
        raise ValueError("ids must be a list")
    ids_clean = []
    for x in ids:
        try:
            ids_clean.append(int(x))
        except (TypeError, ValueError):
            raise ValueError(f"non-int id in list: {x!r}")
    if not ids_clean:
        return {"ok": True, "noop": True}
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        existing = {int(r["id"]) for r in con.execute("SELECT id FROM routing_folders").fetchall()}
        for new_pos, fid in enumerate(ids_clean):
            if fid not in existing:
                continue
            con.execute(
                "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
                (-1 - new_pos, now, fid),
            )
        for new_pos, fid in enumerate(ids_clean):
            if fid not in existing:
                continue
            con.execute(
                "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
                (new_pos + 1, now, fid),
            )
    _sighup_server()
    return {"ok": True, "reordered": len([i for i in ids_clean if i in existing])}


def _routing_validate_outbound(con, tag):
    tag = (tag or "").strip()
    if not tag:
        raise ValueError("outbound_tag required")
    if tag == "block":
        return tag
    row = con.execute("SELECT 1 FROM outbounds WHERE tag=?", (tag,)).fetchone()
    if not row:
        raise ValueError(f"outbound_tag {tag!r} not in outbounds table")
    return tag


def create_routing_rule(body):
    """Create a new routing rule.

    Folders v1 (2026-05-10): when body.folder_id is provided we treat
    rules.priority as INTRA-folder; auto-priority falls back to
    MAX(priority WHERE folder_id=X)+1.  When folder_id is NULL/absent
    rules.priority is GLOBAL; auto-priority is MAX over the union of
    folder priorities + ungrouped rule priorities + 1.

    body.group_name is preserved for backward-compat with v0 panels;
    panels that pass folder_id need not pass group_name.
    """
    if not isinstance(body, dict):
        raise ValueError("body must be object")
    match = _routing_validate_match(body.get("match") or {})
    desc = (body.get("description_override") or "").strip() or None
    enabled = 0 if body.get("enabled") is False else 1
    group_name = (body.get("group_name") or "").strip() or None
    folder_id = body.get("folder_id")
    if folder_id in ("", None):
        folder_id = None
    else:
        try:
            folder_id = int(folder_id)
        except (TypeError, ValueError):
            raise ValueError("folder_id must be integer or null")
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        tag = _routing_validate_outbound(con, body.get("outbound_tag"))
        if folder_id is not None and not _folder_exists(con, folder_id):
            raise ValueError(f"folder_id {folder_id!r} not found")
        # auto-assign priority unless explicit. Scope is intra-folder when
        # folder_id IS NOT NULL, else GLOBAL (ungrouped + folders).
        if "priority" in body and body.get("priority") is not None:
            priority = int(body["priority"])
        else:
            if folder_id is None:
                row_r = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_rules WHERE folder_id IS NULL"
                ).fetchone()
                row_f = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_folders"
                ).fetchone()
                priority = max(int(row_r["m"] or 0), int(row_f["m"] or 0)) + 1
            else:
                row = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_rules WHERE folder_id=?",
                    (folder_id,),
                ).fetchone()
                priority = int(row["m"] or 0) + 1
        cur = con.execute(
            "INSERT INTO routing_rules(priority, outbound_tag, match_json, description_override, enabled, group_name, folder_id, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (priority, tag, json.dumps(match), desc, enabled, group_name, folder_id, now, now),
        )
        rule_id = cur.lastrowid
        row = con.execute(
            "SELECT id, priority, outbound_tag, match_json, description_override, enabled, "
            "COALESCE(group_name,'') AS group_name, folder_id, created_at, updated_at "
            "FROM routing_rules WHERE id=?", (rule_id,),
        ).fetchone()
    _sighup_server()
    return _routing_row_to_dict(row)


def update_routing_rule(rule_id, body):
    """Update a routing rule. Folders v1 (2026-05-10): body.folder_id
    re-parents the rule. When the rule moves into a different folder
    (or out to ungrouped) we also reset its priority to the bottom of
    the destination's queue so the new neighbours don't shift.
    Operator can subsequently drag-reorder."""
    if not isinstance(body, dict):
        raise ValueError("body must be object")
    rule_id = int(rule_id)
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        row = con.execute(
            "SELECT id, folder_id FROM routing_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            raise ValueError("rule not found")
        sets, args = [], []
        re_parented = False
        new_folder_id = None
        if "outbound_tag" in body:
            tag = _routing_validate_outbound(con, body.get("outbound_tag"))
            sets.append("outbound_tag=?"); args.append(tag)
        if "match" in body:
            match = _routing_validate_match(body.get("match") or {})
            sets.append("match_json=?"); args.append(json.dumps(match))
        if "description_override" in body:
            desc = (body.get("description_override") or "").strip() or None
            sets.append("description_override=?"); args.append(desc)
        if "group_name" in body:
            gn = (body.get("group_name") or "").strip() or None
            sets.append("group_name=?"); args.append(gn)
        if "folder_id" in body:
            fid = body.get("folder_id")
            if fid in ("", None):
                new_folder_id = None
            else:
                try:
                    new_folder_id = int(fid)
                except (TypeError, ValueError):
                    raise ValueError("folder_id must be integer or null")
                if not _folder_exists(con, new_folder_id):
                    raise ValueError(f"folder_id {new_folder_id!r} not found")
            old_folder_id = row["folder_id"]
            old_folder_id = int(old_folder_id) if old_folder_id is not None else None
            if new_folder_id != old_folder_id:
                re_parented = True
                sets.append("folder_id=?"); args.append(new_folder_id)
        if "enabled" in body:
            sets.append("enabled=?"); args.append(0 if body.get("enabled") is False else 1)
        if re_parented and ("priority" not in body or body.get("priority") is None):
            # Auto-bottom of new scope.
            if new_folder_id is None:
                row_r = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_rules WHERE folder_id IS NULL"
                ).fetchone()
                row_f = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_folders"
                ).fetchone()
                new_pr = max(int(row_r["m"] or 0), int(row_f["m"] or 0)) + 1
            else:
                row_p = con.execute(
                    "SELECT COALESCE(MAX(priority),0) AS m FROM routing_rules WHERE folder_id=?",
                    (new_folder_id,),
                ).fetchone()
                new_pr = int(row_p["m"] or 0) + 1
            sets.append("priority=?"); args.append(new_pr)
        elif "priority" in body and body.get("priority") is not None:
            sets.append("priority=?"); args.append(int(body["priority"]))
        if not sets:
            raise ValueError("nothing to update")
        sets.append("updated_at=?"); args.append(now)
        args.append(rule_id)
        con.execute(f"UPDATE routing_rules SET {', '.join(sets)} WHERE id=?", args)
        row = con.execute(
            "SELECT id, priority, outbound_tag, match_json, description_override, enabled, "
            "COALESCE(group_name,'') AS group_name, folder_id, created_at, updated_at "
            "FROM routing_rules WHERE id=?", (rule_id,),
        ).fetchone()
    _sighup_server()
    return _routing_row_to_dict(row)


def delete_routing_rule(rule_id):
    rule_id = int(rule_id)
    ensure_db()
    with db_conn() as con:
        row = con.execute("SELECT priority FROM routing_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise ValueError("rule not found")
        deleted_priority = int(row["priority"])
        con.execute("DELETE FROM routing_rules WHERE id=?", (rule_id,))
        # renumber rules whose priority was higher than the deleted one (slide down)
        con.execute("UPDATE routing_rules SET priority=priority-1, updated_at=? WHERE priority>?",
                    (int(time.time()), deleted_priority))
    _sighup_server()
    return {"ok": True}


def move_routing_rule(rule_id, direction):
    """Swap a rule's priority with the nearest sibling in the SAME folder
    scope (or the same ungrouped queue when folder_id IS NULL).

    Folders v1 (2026-05-10): cross-folder moves are NOT done by ↑/↓ —
    operator either drags the rule into another folder body OR PUTs
    folder_id=X to re-parent.  This keeps ↑/↓ predictable and avoids
    surprise re-parenting on a long sequence of arrow clicks at the
    edge of the folder.
    """
    rule_id = int(rule_id)
    direction = (direction or "").lower()
    if direction not in ("up", "down"):
        raise ValueError("direction must be 'up' or 'down'")
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        row = con.execute(
            "SELECT id, priority, folder_id FROM routing_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            raise ValueError("rule not found")
        cur_pr = int(row["priority"])
        fid = row["folder_id"]
        if fid is None:
            scope_clause = "folder_id IS NULL"
            scope_args = ()
        else:
            scope_clause = "folder_id=?"
            scope_args = (int(fid),)
        if direction == "up":
            other = con.execute(
                f"SELECT id, priority FROM routing_rules WHERE {scope_clause} AND priority<? ORDER BY priority DESC, id DESC LIMIT 1",
                (*scope_args, cur_pr),
            ).fetchone()
        else:
            other = con.execute(
                f"SELECT id, priority FROM routing_rules WHERE {scope_clause} AND priority>? ORDER BY priority ASC, id ASC LIMIT 1",
                (*scope_args, cur_pr),
            ).fetchone()
        if not other:
            return {"ok": True, "noop": True}
        other_pr = int(other["priority"])
        # swap priorities. Two-step via temp value to avoid violating any
        # uniqueness constraints (currently none on priority but cheap).
        con.execute("UPDATE routing_rules SET priority=?, updated_at=? WHERE id=?", (-1 - cur_pr, now, row["id"]))
        con.execute("UPDATE routing_rules SET priority=?, updated_at=? WHERE id=?", (cur_pr, now, other["id"]))
        con.execute("UPDATE routing_rules SET priority=?, updated_at=? WHERE id=?", (other_pr, now, row["id"]))
    _sighup_server()
    return {"ok": True}


def reorder_routing_rules(ids):
    """Reorder rules by setting priority = position-in-list.

    Folders v1 (2026-05-10): each id reorder is folder-scoped — the
    rule's existing folder_id determines which queue it's reordered
    inside.  The caller (panel JS) sends a separate list per folder
    (or one list of ungrouped ids) — mixing folders in a single
    reorder call still works but the priorities collide between
    folders, which is fine because intra-folder priority is
    independent.

    For cross-folder re-parenting, callers PUT folder_id=X via
    update_routing_rule before/instead of reorder.

    Idempotent — missing ids are ignored, extra ids in the list are
    ignored.  Two-pass via tmp negative priority to dodge potential
    uniqueness collisions."""
    if not isinstance(ids, list):
        raise ValueError("ids must be a list")
    ids_clean = []
    for x in ids:
        try:
            ids_clean.append(int(x))
        except (TypeError, ValueError):
            raise ValueError(f"non-int id in list: {x!r}")
    if not ids_clean:
        return {"ok": True, "noop": True}
    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        existing = {int(r["id"]) for r in con.execute("SELECT id FROM routing_rules").fetchall()}
        # Two-pass priority swap to dodge any uniqueness collision: first
        # park each touched row at a negative priority offset, then settle
        # to the final position-based priority.
        for new_pos, rid in enumerate(ids_clean):
            if rid not in existing:
                continue
            con.execute("UPDATE routing_rules SET priority=?, updated_at=? WHERE id=?",
                        (-1 - new_pos, now, rid))
        for new_pos, rid in enumerate(ids_clean):
            if rid not in existing:
                continue
            con.execute("UPDATE routing_rules SET priority=?, updated_at=? WHERE id=?",
                        (new_pos + 1, now, rid))
    _sighup_server()
    return {"ok": True, "reordered": len([i for i in ids_clean if i in existing])}


def set_routing_layout(layout):
    """Atomic re-layout of the whole routing queue (Sortable.js 2026-05-10).

    Accepts the WHOLE layout in one transaction:

        [
          {"kind":"folder","id":5,"children":[3,1]},
          {"kind":"rule","id":2},
          {"kind":"folder","id":7,"children":[]},
          {"kind":"rule","id":4}
        ]

    Folders and ungrouped rules SHARE the same global priority space —
    each top-level entry gets priority = index+1. For folder entries,
    children are stamped with folder_id = folder.id and intra-folder
    priority = j+1.

    Returns {"rules": list_routing_rules(), "folders":
    list_routing_folders()} on success — caller (panel JS) can render
    without an extra GET.

    Validates aggressively before opening a write txn:
      - kind must be {"folder","rule"}
      - every id must exist
      - no duplicate id (folder OR rule) across the entire payload
      - children must be list of ints
      - rules referenced as children must exist
      - folder children may only contain rule ids, never folder ids

    Two-pass priority swap (negative tmp first, positive final) mirrors
    reorder_routing_rules / reorder_routing_folders so we stay safe if a
    future schema adds UNIQUE(priority).
    """
    if not isinstance(layout, list):
        raise ValueError("layout must be a list")

    seen_folders = set()
    seen_rules = set()
    parsed = []   # [(kind, id, [child_rule_ids])]

    for idx, entry in enumerate(layout):
        if not isinstance(entry, dict):
            raise ValueError(f"layout[{idx}] must be object")
        kind = entry.get("kind")
        if kind not in ("folder", "rule"):
            raise ValueError(f"layout[{idx}].kind must be 'folder' or 'rule' (got {kind!r})")
        try:
            eid = int(entry.get("id"))
        except (TypeError, ValueError):
            raise ValueError(f"layout[{idx}].id must be int")
        children = []
        if kind == "folder":
            if eid in seen_folders:
                raise ValueError(f"duplicate folder id {eid} at layout[{idx}]")
            seen_folders.add(eid)
            raw_children = entry.get("children", [])
            if not isinstance(raw_children, list):
                raise ValueError(f"layout[{idx}].children must be a list")
            for j, cid in enumerate(raw_children):
                try:
                    cid_int = int(cid)
                except (TypeError, ValueError):
                    raise ValueError(f"layout[{idx}].children[{j}] must be int")
                if cid_int in seen_rules:
                    raise ValueError(
                        f"duplicate rule id {cid_int} (children of folder {eid})"
                    )
                seen_rules.add(cid_int)
                children.append(cid_int)
        else:  # rule
            if eid in seen_rules:
                raise ValueError(f"duplicate rule id {eid} at layout[{idx}]")
            seen_rules.add(eid)
        parsed.append((kind, eid, children))

    ensure_db()
    now = int(time.time())
    with db_conn() as con:
        existing_folders = {int(r["id"]) for r in con.execute("SELECT id FROM routing_folders").fetchall()}
        existing_rules = {int(r["id"]) for r in con.execute("SELECT id FROM routing_rules").fetchall()}
        for kind, eid, children in parsed:
            if kind == "folder":
                if eid not in existing_folders:
                    raise ValueError(f"folder id {eid} not found")
                for cid in children:
                    if cid not in existing_rules:
                        raise ValueError(f"rule id {cid} (child of folder {eid}) not found")
            else:
                if eid not in existing_rules:
                    raise ValueError(f"rule id {eid} not found")

        # Two-pass to dodge any UNIQUE(priority) constraint. Pass 1:
        # park every touched row at a negative tmp value. Pass 2: settle
        # at the final positive priorities.
        # ---- pass 1 (negative tmp) ----
        tmp = -1
        for idx, (kind, eid, children) in enumerate(parsed):
            if kind == "folder":
                con.execute(
                    "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
                    (tmp, now, eid),
                )
                tmp -= 1
                for cid in children:
                    con.execute(
                        "UPDATE routing_rules SET folder_id=?, priority=?, updated_at=? WHERE id=?",
                        (eid, tmp, now, cid),
                    )
                    tmp -= 1
            else:
                con.execute(
                    "UPDATE routing_rules SET folder_id=NULL, priority=?, updated_at=? WHERE id=?",
                    (tmp, now, eid),
                )
                tmp -= 1
        # ---- pass 2 (final positive priorities) ----
        for idx, (kind, eid, children) in enumerate(parsed):
            pri = idx + 1
            if kind == "folder":
                con.execute(
                    "UPDATE routing_folders SET priority=?, updated_at=? WHERE id=?",
                    (pri, now, eid),
                )
                for j, cid in enumerate(children):
                    con.execute(
                        "UPDATE routing_rules SET folder_id=?, priority=?, updated_at=? WHERE id=?",
                        (eid, j + 1, now, cid),
                    )
            else:
                con.execute(
                    "UPDATE routing_rules SET folder_id=NULL, priority=?, updated_at=? WHERE id=?",
                    (pri, now, eid),
                )
    _sighup_server()
    return {
        "ok": True,
        "rules": list_routing_rules(),
        "folders": list_routing_folders(),
    }


def reload_routing_signal():
    _sighup_server()
    return {"ok": True}


def set_active_outbound(config, tag):
    if "route" not in config:
        config["route"] = {}
    config["route"]["final"] = tag
    # Ensure localhost stays direct
    _ensure_localhost_rule(config)
    save_config(config)


def _ensure_localhost_rule(config):
    """Make sure route rules include 127.0.0.0/8 -> direct so fallback works."""
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    local_cidrs = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    for r in rules:
        if r.get("outbound") == "direct" and "ip_cidr" in r:
            if set(local_cidrs).issubset(set(r["ip_cidr"])):
                return
    # Add the rule
    rules.insert(0, {"ip_cidr": local_cidrs, "outbound": "direct"})


# --- X25519 keypair helpers (used by tamizdat inbound) ---

def generate_x25519_keypair():
    """Generate an X25519 keypair. Returns (private_hex, public_hex) — 64 hex chars each."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes.hex(), pub_bytes.hex()
    except Exception as e:
        return None, None


def x25519_public_from_private(priv_hex):
    """Derive X25519 public key from a 64-hex private key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    except Exception:
        return None


# --- Tamizdat (post-rename, master-shortid only) helpers ---
#
# Tamizdat is the wire-renamed fork of tamizdat (URI scheme tamizdat://, HKDF
# label "TAMIZDAT v1" used for PSK derivation, magic authority
# "tamizdat-config.invalid:443", header "Tamizdat-Protocol"). Each user has
# exactly one master_shortid stored in users.master_shortid; the server
# accepts only that exact 8-byte value. The URI carries the master.
# (HKDF-derived shortid pool was removed in the shortid full-B simplification
# 2026-05-09 — see SPEC.md §10.)
#
# URI form (per github.com/funnybones69/tamizdat internal/configurl):
#   tamizdat://<host>:<port>/?sni=<masq>&pubkey=<64hex>&shortid=<16hex>&fp=mix
#
# Default fp is "mix" (post-foundation; the older "chrome" pool included stale
# Chrome_100/106_Shuffle variants).

def get_tamizdat_inbound(config):
    """Return the (single) tamizdat-typed inbound from sing-box config or None."""
    for ib in config.get("inbounds", []):
        if ib.get("type") == "tamizdat":
            return ib
    return None


def make_tamizdat_uri(cfg, outbound=None, label_override=None):
    """Build tamizdat://host:port/?sni=...&pubkey=...&shortid=...&fp=mix#label.

    No per-user param: the URI carries the inbound's master_short_id, and each
    client derives its current-epoch shortID via HKDF server-side. User
    differentiation for routing is via auth_user route rules (same as tamizdat).

    Returns None if no tamizdat inbound is configured or key derivation failed.
    """
    ib = get_tamizdat_inbound(cfg)
    if not ib:
        return None
    priv = ib.get("private_key", "")
    if len(priv) != 64:
        return None
    pub = x25519_public_from_private(priv)
    if not pub:
        return None
    master = (ib.get("master_short_id") or "").strip().lower()
    if len(master) != 16 or not all(c in "0123456789abcdef" for c in master):
        return None
    # public_port: client-facing TCP port (e.g. 443 when behind nginx/haproxy);
    # falls back to listen_port for direct-listen deployments.
    port = int(ib.get("public_port") or ib.get("listen_port") or 8443)
    hostname = panel_public_hostname()
    masq = ib.get("masquerade_domain", hostname)
    fp = ib.get("fingerprint", "mix")  # tamizdat default
    bootstrap = (ib.get("bootstrap_sni") or "").strip()
    if label_override:
        label = label_override
    elif outbound == "direct":
        label = "Обход белых списков"
    elif outbound:
        label = "Обход блокировок"
    else:
        label = f"tamizdat-{port}"
    base = f"tamizdat://{hostname}:{port}/?sni={masq}&pubkey={pub}&shortid={master}&fp={fp}"
    if bootstrap:
        base += f"&bootstrap={quote(bootstrap, safe='')}"
    return base + f"#{quote(label)}"


def make_tamizdat_json(cfg):
    """iOS / tamizdat-client JSON config equivalent to the URI but as JSON.

    The new client expects { server, domain, public_key, master_short_id, fingerprint }.
    Returns None if no tamizdat inbound is configured.
    """
    ib = get_tamizdat_inbound(cfg)
    if not ib:
        return None
    priv = ib.get("private_key", "")
    if len(priv) != 64:
        return None
    pub = x25519_public_from_private(priv)
    if not pub:
        return None
    master = (ib.get("master_short_id") or "").strip().lower()
    if len(master) != 16:
        return None
    port = int(ib.get("public_port") or ib.get("listen_port") or 8443)
    hostname = panel_public_hostname()
    masq = ib.get("masquerade_domain", hostname)
    bootstrap = (ib.get("bootstrap_sni") or "").strip()
    out = {
        "server": f"{hostname}:{port}",
        "domain": masq,
        "public_key": pub,
        "master_short_id": master,
        "fingerprint": ib.get("fingerprint", "mix"),
    }
    if bootstrap:
        out["bootstrap_sni"] = bootstrap
    return out


# --- Per-user routing via auth_user rules ---

def _get_rules(config):
    return config.setdefault("route", {}).setdefault("rules", [])


def _is_user_rule(r):
    """True for rules whose only purpose is user->outbound routing."""
    return "auth_user" in r and "outbound" in r and set(r.keys()) == {"auth_user", "outbound"}


def get_user_outbound(config, name):
    """Return outbound tag for user, or None if no explicit rule."""
    for r in _get_rules(config):
        if _is_user_rule(r) and name in r["auth_user"]:
            return r["outbound"]
    return None


def _strip_user_from_rules(config, name):
    """Remove user from every auth_user rule; drop rules that become empty."""
    rules = _get_rules(config)
    out = []
    for r in rules:
        if _is_user_rule(r):
            r["auth_user"] = [u for u in r["auth_user"] if u != name]
            if not r["auth_user"]:
                continue
        out.append(r)
    config["route"]["rules"] = out


def set_user_outbound(config, name, tag):
    """Assign user to outbound tag. Aggregates users with same outbound into one rule."""
    _ensure_localhost_rule(config)
    _strip_user_from_rules(config, name)
    if not tag:
        return
    rules = _get_rules(config)
    for r in rules:
        if _is_user_rule(r) and r["outbound"] == tag:
            if name not in r["auth_user"]:
                r["auth_user"].append(name)
            return
    rules.append({"auth_user": [name], "outbound": tag})


def rename_user_in_rules(config, old, new):
    for r in _get_rules(config):
        if _is_user_rule(r) and old in r["auth_user"]:
            r["auth_user"] = [new if u == old else u for u in r["auth_user"]]


def remove_outbound_from_rules(config, tag):
    """Drop rules pointing at a deleted outbound — affected users fall back to route.final."""
    config["route"]["rules"] = [r for r in _get_rules(config) if r.get("outbound") != tag]


def count_users_per_outbound(config):
    counts = {}
    for r in _get_rules(config):
        if _is_user_rule(r):
            t = r["outbound"]
            counts[t] = counts.get(t, 0) + len(r["auth_user"])
    return counts


# --- URI parsers ---
# Phase 1 accepts tamizdat:// outbound URIs only; parser lives below after QRCODE_JS.

# qrcode-generator v1.4.4 (MIT, Kazuhiko Arase) — minified, served at /qrcode.js
import hashlib as _hl

# Sortable.js 1.15.6 — vendored inline 2026-05-10. Upstream:
#   https://github.com/SortableJS/Sortable/releases/tag/1.15.6
# SHA-256(source): 6d0a831fc19b4bae851797ad3393157e861afb7862459c11226359b27e2c4337
# Vendored locally so the panel works without external CDN dependencies.
SORTABLE_JS_INLINE = r'''/*! Sortable 1.15.6 - MIT | git://github.com/SortableJS/Sortable.git */
!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?module.exports=e():"function"==typeof define&&define.amd?define(e):(t=t||self).Sortable=e()}(this,function(){"use strict";function e(e,t){var n,o=Object.keys(e);return Object.getOwnPropertySymbols&&(n=Object.getOwnPropertySymbols(e),t&&(n=n.filter(function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable})),o.push.apply(o,n)),o}function I(o){for(var t=1;t<arguments.length;t++){var i=null!=arguments[t]?arguments[t]:{};t%2?e(Object(i),!0).forEach(function(t){var e,n;e=o,t=i[n=t],n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t}):Object.getOwnPropertyDescriptors?Object.defineProperties(o,Object.getOwnPropertyDescriptors(i)):e(Object(i)).forEach(function(t){Object.defineProperty(o,t,Object.getOwnPropertyDescriptor(i,t))})}return o}function o(t){return(o="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t})(t)}function a(){return(a=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var n,o=arguments[e];for(n in o)Object.prototype.hasOwnProperty.call(o,n)&&(t[n]=o[n])}return t}).apply(this,arguments)}function i(t,e){if(null==t)return{};var n,o=function(t,e){if(null==t)return{};for(var n,o={},i=Object.keys(t),r=0;r<i.length;r++)n=i[r],0<=e.indexOf(n)||(o[n]=t[n]);return o}(t,e);if(Object.getOwnPropertySymbols)for(var i=Object.getOwnPropertySymbols(t),r=0;r<i.length;r++)n=i[r],0<=e.indexOf(n)||Object.prototype.propertyIsEnumerable.call(t,n)&&(o[n]=t[n]);return o}function r(t){return function(t){if(Array.isArray(t))return l(t)}(t)||function(t){if("undefined"!=typeof Symbol&&null!=t[Symbol.iterator]||null!=t["@@iterator"])return Array.from(t)}(t)||function(t,e){if(t){if("string"==typeof t)return l(t,e);var n=Object.prototype.toString.call(t).slice(8,-1);return"Map"===(n="Object"===n&&t.constructor?t.constructor.name:n)||"Set"===n?Array.from(t):"Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?l(t,e):void 0}}(t)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function l(t,e){(null==e||e>t.length)&&(e=t.length);for(var n=0,o=new Array(e);n<e;n++)o[n]=t[n];return o}function t(t){if("undefined"!=typeof window&&window.navigator)return!!navigator.userAgent.match(t)}var y=t(/(?:Trident.*rv[ :]?11\.|msie|iemobile|Windows Phone)/i),w=t(/Edge/i),s=t(/firefox/i),u=t(/safari/i)&&!t(/chrome/i)&&!t(/android/i),c=t(/iP(ad|od|hone)/i),n=t(/chrome/i)&&t(/android/i),d={capture:!1,passive:!1};function h(t,e,n){t.addEventListener(e,n,!y&&d)}function p(t,e,n){t.removeEventListener(e,n,!y&&d)}function f(t,e){if(e&&(">"===e[0]&&(e=e.substring(1)),t))try{if(t.matches)return t.matches(e);if(t.msMatchesSelector)return t.msMatchesSelector(e);if(t.webkitMatchesSelector)return t.webkitMatchesSelector(e)}catch(t){return}}function g(t){return t.host&&t!==document&&t.host.nodeType?t.host:t.parentNode}function P(t,e,n,o){if(t){n=n||document;do{if(null!=e&&(">"!==e[0]||t.parentNode===n)&&f(t,e)||o&&t===n)return t}while(t!==n&&(t=g(t)))}return null}var m,v=/\s+/g;function k(t,e,n){var o;t&&e&&(t.classList?t.classList[n?"add":"remove"](e):(o=(" "+t.className+" ").replace(v," ").replace(" "+e+" "," "),t.className=(o+(n?" "+e:"")).replace(v," ")))}function R(t,e,n){var o=t&&t.style;if(o){if(void 0===n)return document.defaultView&&document.defaultView.getComputedStyle?n=document.defaultView.getComputedStyle(t,""):t.currentStyle&&(n=t.currentStyle),void 0===e?n:n[e];o[e=!(e in o||-1!==e.indexOf("webkit"))?"-webkit-"+e:e]=n+("string"==typeof n?"":"px")}}function b(t,e){var n="";if("string"==typeof t)n=t;else do{var o=R(t,"transform")}while(o&&"none"!==o&&(n=o+" "+n),!e&&(t=t.parentNode));var i=window.DOMMatrix||window.WebKitCSSMatrix||window.CSSMatrix||window.MSCSSMatrix;return i&&new i(n)}function D(t,e,n){if(t){var o=t.getElementsByTagName(e),i=0,r=o.length;if(n)for(;i<r;i++)n(o[i],i);return o}return[]}function O(){var t=document.scrollingElement;return t||document.documentElement}function X(t,e,n,o,i){if(t.getBoundingClientRect||t===window){var r,a,l,s,c,u,d=t!==window&&t.parentNode&&t!==O()?(a=(r=t.getBoundingClientRect()).top,l=r.left,s=r.bottom,c=r.right,u=r.height,r.width):(l=a=0,s=window.innerHeight,c=window.innerWidth,u=window.innerHeight,window.innerWidth);if((e||n)&&t!==window&&(i=i||t.parentNode,!y))do{if(i&&i.getBoundingClientRect&&("none"!==R(i,"transform")||n&&"static"!==R(i,"position"))){var h=i.getBoundingClientRect();a-=h.top+parseInt(R(i,"border-top-width")),l-=h.left+parseInt(R(i,"border-left-width")),s=a+r.height,c=l+r.width;break}}while(i=i.parentNode);return o&&t!==window&&(o=(e=b(i||t))&&e.a,t=e&&e.d,e&&(s=(a/=t)+(u/=t),c=(l/=o)+(d/=o))),{top:a,left:l,bottom:s,right:c,width:d,height:u}}}function Y(t,e,n){for(var o=M(t,!0),i=X(t)[e];o;){var r=X(o)[n];if(!("top"===n||"left"===n?r<=i:i<=r))return o;if(o===O())break;o=M(o,!1)}return!1}function B(t,e,n,o){for(var i=0,r=0,a=t.children;r<a.length;){if("none"!==a[r].style.display&&a[r]!==jt.ghost&&(o||a[r]!==jt.dragged)&&P(a[r],n.draggable,t,!1)){if(i===e)return a[r];i++}r++}return null}function F(t,e){for(var n=t.lastElementChild;n&&(n===jt.ghost||"none"===R(n,"display")||e&&!f(n,e));)n=n.previousElementSibling;return n||null}function j(t,e){var n=0;if(!t||!t.parentNode)return-1;for(;t=t.previousElementSibling;)"TEMPLATE"===t.nodeName.toUpperCase()||t===jt.clone||e&&!f(t,e)||n++;return n}function E(t){var e=0,n=0,o=O();if(t)do{var i=b(t),r=i.a,i=i.d}while(e+=t.scrollLeft*r,n+=t.scrollTop*i,t!==o&&(t=t.parentNode));return[e,n]}function M(t,e){if(!t||!t.getBoundingClientRect)return O();var n=t,o=!1;do{if(n.clientWidth<n.scrollWidth||n.clientHeight<n.scrollHeight){var i=R(n);if(n.clientWidth<n.scrollWidth&&("auto"==i.overflowX||"scroll"==i.overflowX)||n.clientHeight<n.scrollHeight&&("auto"==i.overflowY||"scroll"==i.overflowY)){if(!n.getBoundingClientRect||n===document.body)return O();if(o||e)return n;o=!0}}}while(n=n.parentNode);return O()}function S(t,e){return Math.round(t.top)===Math.round(e.top)&&Math.round(t.left)===Math.round(e.left)&&Math.round(t.height)===Math.round(e.height)&&Math.round(t.width)===Math.round(e.width)}function _(e,n){return function(){var t;m||(1===(t=arguments).length?e.call(this,t[0]):e.apply(this,t),m=setTimeout(function(){m=void 0},n))}}function H(t,e,n){t.scrollLeft+=e,t.scrollTop+=n}function C(t){var e=window.Polymer,n=window.jQuery||window.Zepto;return e&&e.dom?e.dom(t).cloneNode(!0):n?n(t).clone(!0)[0]:t.cloneNode(!0)}function T(t,e){R(t,"position","absolute"),R(t,"top",e.top),R(t,"left",e.left),R(t,"width",e.width),R(t,"height",e.height)}function x(t){R(t,"position",""),R(t,"top",""),R(t,"left",""),R(t,"width",""),R(t,"height","")}function L(n,o,i){var r={};return Array.from(n.children).forEach(function(t){var e;P(t,o.draggable,n,!1)&&!t.animated&&t!==i&&(e=X(t),r.left=Math.min(null!==(t=r.left)&&void 0!==t?t:1/0,e.left),r.top=Math.min(null!==(t=r.top)&&void 0!==t?t:1/0,e.top),r.right=Math.max(null!==(t=r.right)&&void 0!==t?t:-1/0,e.right),r.bottom=Math.max(null!==(t=r.bottom)&&void 0!==t?t:-1/0,e.bottom))}),r.width=r.right-r.left,r.height=r.bottom-r.top,r.x=r.left,r.y=r.top,r}var K="Sortable"+(new Date).getTime();function A(){var e,o=[];return{captureAnimationState:function(){o=[],this.options.animation&&[].slice.call(this.el.children).forEach(function(t){var e,n;"none"!==R(t,"display")&&t!==jt.ghost&&(o.push({target:t,rect:X(t)}),e=I({},o[o.length-1].rect),!t.thisAnimationDuration||(n=b(t,!0))&&(e.top-=n.f,e.left-=n.e),t.fromRect=e)})},addAnimationState:function(t){o.push(t)},removeAnimationState:function(t){o.splice(function(t,e){for(var n in t)if(t.hasOwnProperty(n))for(var o in e)if(e.hasOwnProperty(o)&&e[o]===t[n][o])return Number(n);return-1}(o,{target:t}),1)},animateAll:function(t){var c=this;if(!this.options.animation)return clearTimeout(e),void("function"==typeof t&&t());var u=!1,d=0;o.forEach(function(t){var e=0,n=t.target,o=n.fromRect,i=X(n),r=n.prevFromRect,a=n.prevToRect,l=t.rect,s=b(n,!0);s&&(i.top-=s.f,i.left-=s.e),n.toRect=i,n.thisAnimationDuration&&S(r,i)&&!S(o,i)&&(l.top-i.top)/(l.left-i.left)==(o.top-i.top)/(o.left-i.left)&&(t=l,s=r,r=a,a=c.options,e=Math.sqrt(Math.pow(s.top-t.top,2)+Math.pow(s.left-t.left,2))/Math.sqrt(Math.pow(s.top-r.top,2)+Math.pow(s.left-r.left,2))*a.animation),S(i,o)||(n.prevFromRect=o,n.prevToRect=i,e=e||c.options.animation,c.animate(n,l,i,e)),e&&(u=!0,d=Math.max(d,e),clearTimeout(n.animationResetTimer),n.animationResetTimer=setTimeout(function(){n.animationTime=0,n.prevFromRect=null,n.fromRect=null,n.prevToRect=null,n.thisAnimationDuration=null},e),n.thisAnimationDuration=e)}),clearTimeout(e),u?e=setTimeout(function(){"function"==typeof t&&t()},d):"function"==typeof t&&t(),o=[]},animate:function(t,e,n,o){var i,r;o&&(R(t,"transition",""),R(t,"transform",""),i=(r=b(this.el))&&r.a,r=r&&r.d,i=(e.left-n.left)/(i||1),r=(e.top-n.top)/(r||1),t.animatingX=!!i,t.animatingY=!!r,R(t,"transform","translate3d("+i+"px,"+r+"px,0)"),this.forRepaintDummy=t.offsetWidth,R(t,"transition","transform "+o+"ms"+(this.options.easing?" "+this.options.easing:"")),R(t,"transform","translate3d(0,0,0)"),"number"==typeof t.animated&&clearTimeout(t.animated),t.animated=setTimeout(function(){R(t,"transition",""),R(t,"transform",""),t.animated=!1,t.animatingX=!1,t.animatingY=!1},o))}}}var N=[],W={initializeByDefault:!0},z={mount:function(e){for(var t in W)!W.hasOwnProperty(t)||t in e||(e[t]=W[t]);N.forEach(function(t){if(t.pluginName===e.pluginName)throw"Sortable: Cannot mount plugin ".concat(e.pluginName," more than once")}),N.push(e)},pluginEvent:function(e,n,o){var t=this;this.eventCanceled=!1,o.cancel=function(){t.eventCanceled=!0};var i=e+"Global";N.forEach(function(t){n[t.pluginName]&&(n[t.pluginName][i]&&n[t.pluginName][i](I({sortable:n},o)),n.options[t.pluginName]&&n[t.pluginName][e]&&n[t.pluginName][e](I({sortable:n},o)))})},initializePlugins:function(n,o,i,t){for(var e in N.forEach(function(t){var e=t.pluginName;(n.options[e]||t.initializeByDefault)&&((t=new t(n,o,n.options)).sortable=n,t.options=n.options,n[e]=t,a(i,t.defaults))}),n.options){var r;n.options.hasOwnProperty(e)&&(void 0!==(r=this.modifyOption(n,e,n.options[e]))&&(n.options[e]=r))}},getEventProperties:function(e,n){var o={};return N.forEach(function(t){"function"==typeof t.eventProperties&&a(o,t.eventProperties.call(n[t.pluginName],e))}),o},modifyOption:function(e,n,o){var i;return N.forEach(function(t){e[t.pluginName]&&t.optionListeners&&"function"==typeof t.optionListeners[n]&&(i=t.optionListeners[n].call(e[t.pluginName],o))}),i}};function G(t){var e=t.sortable,n=t.rootEl,o=t.name,i=t.targetEl,r=t.cloneEl,a=t.toEl,l=t.fromEl,s=t.oldIndex,c=t.newIndex,u=t.oldDraggableIndex,d=t.newDraggableIndex,h=t.originalEvent,p=t.putSortable,f=t.extraEventProperties;if(e=e||n&&n[K]){var g,m=e.options,t="on"+o.charAt(0).toUpperCase()+o.substr(1);!window.CustomEvent||y||w?(g=document.createEvent("Event")).initEvent(o,!0,!0):g=new CustomEvent(o,{bubbles:!0,cancelable:!0}),g.to=a||n,g.from=l||n,g.item=i||n,g.clone=r,g.oldIndex=s,g.newIndex=c,g.oldDraggableIndex=u,g.newDraggableIndex=d,g.originalEvent=h,g.pullMode=p?p.lastPutMode:void 0;var v,b=I(I({},f),z.getEventProperties(o,e));for(v in b)g[v]=b[v];n&&n.dispatchEvent(g),m[t]&&m[t].call(e,g)}}function U(t,e){var n=(o=2<arguments.length&&void 0!==arguments[2]?arguments[2]:{}).evt,o=i(o,q);z.pluginEvent.bind(jt)(t,e,I({dragEl:Z,parentEl:$,ghostEl:Q,rootEl:J,nextEl:tt,lastDownEl:et,cloneEl:nt,cloneHidden:ot,dragStarted:mt,putSortable:ct,activeSortable:jt.active,originalEvent:n,oldIndex:it,oldDraggableIndex:at,newIndex:rt,newDraggableIndex:lt,hideGhostForTarget:Xt,unhideGhostForTarget:Yt,cloneNowHidden:function(){ot=!0},cloneNowShown:function(){ot=!1},dispatchSortableEvent:function(t){V({sortable:e,name:t,originalEvent:n})}},o))}var q=["evt"];function V(t){G(I({putSortable:ct,cloneEl:nt,targetEl:Z,rootEl:J,oldIndex:it,oldDraggableIndex:at,newIndex:rt,newDraggableIndex:lt},t))}var Z,$,Q,J,tt,et,nt,ot,it,rt,at,lt,st,ct,ut,dt,ht,pt,ft,gt,mt,vt,bt,yt,wt,Dt=!1,Et=!1,St=[],_t=!1,Ct=!1,Tt=[],xt=!1,Ot=[],Mt="undefined"!=typeof document,At=c,Nt=w||y?"cssFloat":"float",It=Mt&&!n&&!c&&"draggable"in document.createElement("div"),Pt=function(){if(Mt){if(y)return!1;var t=document.createElement("x");return t.style.cssText="pointer-events:auto","auto"===t.style.pointerEvents}}(),kt=function(t,e){var n=R(t),o=parseInt(n.width)-parseInt(n.paddingLeft)-parseInt(n.paddingRight)-parseInt(n.borderLeftWidth)-parseInt(n.borderRightWidth),i=B(t,0,e),r=B(t,1,e),a=i&&R(i),l=r&&R(r),s=a&&parseInt(a.marginLeft)+parseInt(a.marginRight)+X(i).width,t=l&&parseInt(l.marginLeft)+parseInt(l.marginRight)+X(r).width;if("flex"===n.display)return"column"===n.flexDirection||"column-reverse"===n.flexDirection?"vertical":"horizontal";if("grid"===n.display)return n.gridTemplateColumns.split(" ").length<=1?"vertical":"horizontal";if(i&&a.float&&"none"!==a.float){e="left"===a.float?"left":"right";return!r||"both"!==l.clear&&l.clear!==e?"horizontal":"vertical"}return i&&("block"===a.display||"flex"===a.display||"table"===a.display||"grid"===a.display||o<=s&&"none"===n[Nt]||r&&"none"===n[Nt]&&o<s+t)?"vertical":"horizontal"},Rt=function(t){function l(r,a){return function(t,e,n,o){var i=t.options.group.name&&e.options.group.name&&t.options.group.name===e.options.group.name;if(null==r&&(a||i))return!0;if(null==r||!1===r)return!1;if(a&&"clone"===r)return r;if("function"==typeof r)return l(r(t,e,n,o),a)(t,e,n,o);e=(a?t:e).options.group.name;return!0===r||"string"==typeof r&&r===e||r.join&&-1<r.indexOf(e)}}var e={},n=t.group;n&&"object"==o(n)||(n={name:n}),e.name=n.name,e.checkPull=l(n.pull,!0),e.checkPut=l(n.put),e.revertClone=n.revertClone,t.group=e},Xt=function(){!Pt&&Q&&R(Q,"display","none")},Yt=function(){!Pt&&Q&&R(Q,"display","")};Mt&&!n&&document.addEventListener("click",function(t){if(Et)return t.preventDefault(),t.stopPropagation&&t.stopPropagation(),t.stopImmediatePropagation&&t.stopImmediatePropagation(),Et=!1},!0);function Bt(t){if(Z){t=t.touches?t.touches[0]:t;var e=(i=t.clientX,r=t.clientY,St.some(function(t){var e=t[K].options.emptyInsertThreshold;if(e&&!F(t)){var n=X(t),o=i>=n.left-e&&i<=n.right+e,e=r>=n.top-e&&r<=n.bottom+e;return o&&e?a=t:void 0}}),a);if(e){var n,o={};for(n in t)t.hasOwnProperty(n)&&(o[n]=t[n]);o.target=o.rootEl=e,o.preventDefault=void 0,o.stopPropagation=void 0,e[K]._onDragOver(o)}}var i,r,a}function Ft(t){Z&&Z.parentNode[K]._isOutsideThisEl(t.target)}function jt(t,e){if(!t||!t.nodeType||1!==t.nodeType)throw"Sortable: `el` must be an HTMLElement, not ".concat({}.toString.call(t));this.el=t,this.options=e=a({},e),t[K]=this;var n,o,i={group:null,sort:!0,disabled:!1,store:null,handle:null,draggable:/^[uo]l$/i.test(t.nodeName)?">li":">*",swapThreshold:1,invertSwap:!1,invertedSwapThreshold:null,removeCloneOnHide:!0,direction:function(){return kt(t,this.options)},ghostClass:"sortable-ghost",chosenClass:"sortable-chosen",dragClass:"sortable-drag",ignore:"a, img",filter:null,preventOnFilter:!0,animation:0,easing:null,setData:function(t,e){t.setData("Text",e.textContent)},dropBubble:!1,dragoverBubble:!1,dataIdAttr:"data-id",delay:0,delayOnTouchOnly:!1,touchStartThreshold:(Number.parseInt?Number:window).parseInt(window.devicePixelRatio,10)||1,forceFallback:!1,fallbackClass:"sortable-fallback",fallbackOnBody:!1,fallbackTolerance:0,fallbackOffset:{x:0,y:0},supportPointer:!1!==jt.supportPointer&&"PointerEvent"in window&&(!u||c),emptyInsertThreshold:5};for(n in z.initializePlugins(this,t,i),i)n in e||(e[n]=i[n]);for(o in Rt(e),this)"_"===o.charAt(0)&&"function"==typeof this[o]&&(this[o]=this[o].bind(this));this.nativeDraggable=!e.forceFallback&&It,this.nativeDraggable&&(this.options.touchStartThreshold=1),e.supportPointer?h(t,"pointerdown",this._onTapStart):(h(t,"mousedown",this._onTapStart),h(t,"touchstart",this._onTapStart)),this.nativeDraggable&&(h(t,"dragover",this),h(t,"dragenter",this)),St.push(this.el),e.store&&e.store.get&&this.sort(e.store.get(this)||[]),a(this,A())}function Ht(t,e,n,o,i,r,a,l){var s,c,u=t[K],d=u.options.onMove;return!window.CustomEvent||y||w?(s=document.createEvent("Event")).initEvent("move",!0,!0):s=new CustomEvent("move",{bubbles:!0,cancelable:!0}),s.to=e,s.from=t,s.dragged=n,s.draggedRect=o,s.related=i||e,s.relatedRect=r||X(e),s.willInsertAfter=l,s.originalEvent=a,t.dispatchEvent(s),c=d?d.call(u,s,a):c}function Lt(t){t.draggable=!1}function Kt(){xt=!1}function Wt(t){return setTimeout(t,0)}function zt(t){return clearTimeout(t)}jt.prototype={constructor:jt,_isOutsideThisEl:function(t){this.el.contains(t)||t===this.el||(vt=null)},_getDirection:function(t,e){return"function"==typeof this.options.direction?this.options.direction.call(this,t,e,Z):this.options.direction},_onTapStart:function(e){if(e.cancelable){var n=this,o=this.el,t=this.options,i=t.preventOnFilter,r=e.type,a=e.touches&&e.touches[0]||e.pointerType&&"touch"===e.pointerType&&e,l=(a||e).target,s=e.target.shadowRoot&&(e.path&&e.path[0]||e.composedPath&&e.composedPath()[0])||l,c=t.filter;if(!function(t){Ot.length=0;var e=t.getElementsByTagName("input"),n=e.length;for(;n--;){var o=e[n];o.checked&&Ot.push(o)}}(o),!Z&&!(/mousedown|pointerdown/.test(r)&&0!==e.button||t.disabled)&&!s.isContentEditable&&(this.nativeDraggable||!u||!l||"SELECT"!==l.tagName.toUpperCase())&&!((l=P(l,t.draggable,o,!1))&&l.animated||et===l)){if(it=j(l),at=j(l,t.draggable),"function"==typeof c){if(c.call(this,e,l,this))return V({sortable:n,rootEl:s,name:"filter",targetEl:l,toEl:o,fromEl:o}),U("filter",n,{evt:e}),void(i&&e.preventDefault())}else if(c=c&&c.split(",").some(function(t){if(t=P(s,t.trim(),o,!1))return V({sortable:n,rootEl:t,name:"filter",targetEl:l,fromEl:o,toEl:o}),U("filter",n,{evt:e}),!0}))return void(i&&e.preventDefault());t.handle&&!P(s,t.handle,o,!1)||this._prepareDragStart(e,a,l)}}},_prepareDragStart:function(t,e,n){var o,i=this,r=i.el,a=i.options,l=r.ownerDocument;n&&!Z&&n.parentNode===r&&(o=X(n),J=r,$=(Z=n).parentNode,tt=Z.nextSibling,et=n,st=a.group,ut={target:jt.dragged=Z,clientX:(e||t).clientX,clientY:(e||t).clientY},ft=ut.clientX-o.left,gt=ut.clientY-o.top,this._lastX=(e||t).clientX,this._lastY=(e||t).clientY,Z.style["will-change"]="all",o=function(){U("delayEnded",i,{evt:t}),jt.eventCanceled?i._onDrop():(i._disableDelayedDragEvents(),!s&&i.nativeDraggable&&(Z.draggable=!0),i._triggerDragStart(t,e),V({sortable:i,name:"choose",originalEvent:t}),k(Z,a.chosenClass,!0))},a.ignore.split(",").forEach(function(t){D(Z,t.trim(),Lt)}),h(l,"dragover",Bt),h(l,"mousemove",Bt),h(l,"touchmove",Bt),a.supportPointer?(h(l,"pointerup",i._onDrop),this.nativeDraggable||h(l,"pointercancel",i._onDrop)):(h(l,"mouseup",i._onDrop),h(l,"touchend",i._onDrop),h(l,"touchcancel",i._onDrop)),s&&this.nativeDraggable&&(this.options.touchStartThreshold=4,Z.draggable=!0),U("delayStart",this,{evt:t}),!a.delay||a.delayOnTouchOnly&&!e||this.nativeDraggable&&(w||y)?o():jt.eventCanceled?this._onDrop():(a.supportPointer?(h(l,"pointerup",i._disableDelayedDrag),h(l,"pointercancel",i._disableDelayedDrag)):(h(l,"mouseup",i._disableDelayedDrag),h(l,"touchend",i._disableDelayedDrag),h(l,"touchcancel",i._disableDelayedDrag)),h(l,"mousemove",i._delayedDragTouchMoveHandler),h(l,"touchmove",i._delayedDragTouchMoveHandler),a.supportPointer&&h(l,"pointermove",i._delayedDragTouchMoveHandler),i._dragStartTimer=setTimeout(o,a.delay)))},_delayedDragTouchMoveHandler:function(t){t=t.touches?t.touches[0]:t;Math.max(Math.abs(t.clientX-this._lastX),Math.abs(t.clientY-this._lastY))>=Math.floor(this.options.touchStartThreshold/(this.nativeDraggable&&window.devicePixelRatio||1))&&this._disableDelayedDrag()},_disableDelayedDrag:function(){Z&&Lt(Z),clearTimeout(this._dragStartTimer),this._disableDelayedDragEvents()},_disableDelayedDragEvents:function(){var t=this.el.ownerDocument;p(t,"mouseup",this._disableDelayedDrag),p(t,"touchend",this._disableDelayedDrag),p(t,"touchcancel",this._disableDelayedDrag),p(t,"pointerup",this._disableDelayedDrag),p(t,"pointercancel",this._disableDelayedDrag),p(t,"mousemove",this._delayedDragTouchMoveHandler),p(t,"touchmove",this._delayedDragTouchMoveHandler),p(t,"pointermove",this._delayedDragTouchMoveHandler)},_triggerDragStart:function(t,e){e=e||"touch"==t.pointerType&&t,!this.nativeDraggable||e?this.options.supportPointer?h(document,"pointermove",this._onTouchMove):h(document,e?"touchmove":"mousemove",this._onTouchMove):(h(Z,"dragend",this),h(J,"dragstart",this._onDragStart));try{document.selection?Wt(function(){document.selection.empty()}):window.getSelection().removeAllRanges()}catch(t){}},_dragStarted:function(t,e){var n;Dt=!1,J&&Z?(U("dragStarted",this,{evt:e}),this.nativeDraggable&&h(document,"dragover",Ft),n=this.options,t||k(Z,n.dragClass,!1),k(Z,n.ghostClass,!0),jt.active=this,t&&this._appendGhost(),V({sortable:this,name:"start",originalEvent:e})):this._nulling()},_emulateDragOver:function(){if(dt){this._lastX=dt.clientX,this._lastY=dt.clientY,Xt();for(var t=document.elementFromPoint(dt.clientX,dt.clientY),e=t;t&&t.shadowRoot&&(t=t.shadowRoot.elementFromPoint(dt.clientX,dt.clientY))!==e;)e=t;if(Z.parentNode[K]._isOutsideThisEl(t),e)do{if(e[K])if(e[K]._onDragOver({clientX:dt.clientX,clientY:dt.clientY,target:t,rootEl:e})&&!this.options.dragoverBubble)break}while(e=g(t=e));Yt()}},_onTouchMove:function(t){if(ut){var e=this.options,n=e.fallbackTolerance,o=e.fallbackOffset,i=t.touches?t.touches[0]:t,r=Q&&b(Q,!0),a=Q&&r&&r.a,l=Q&&r&&r.d,e=At&&wt&&E(wt),a=(i.clientX-ut.clientX+o.x)/(a||1)+(e?e[0]-Tt[0]:0)/(a||1),l=(i.clientY-ut.clientY+o.y)/(l||1)+(e?e[1]-Tt[1]:0)/(l||1);if(!jt.active&&!Dt){if(n&&Math.max(Math.abs(i.clientX-this._lastX),Math.abs(i.clientY-this._lastY))<n)return;this._onDragStart(t,!0)}Q&&(r?(r.e+=a-(ht||0),r.f+=l-(pt||0)):r={a:1,b:0,c:0,d:1,e:a,f:l},r="matrix(".concat(r.a,",").concat(r.b,",").concat(r.c,",").concat(r.d,",").concat(r.e,",").concat(r.f,")"),R(Q,"webkitTransform",r),R(Q,"mozTransform",r),R(Q,"msTransform",r),R(Q,"transform",r),ht=a,pt=l,dt=i),t.cancelable&&t.preventDefault()}},_appendGhost:function(){if(!Q){var t=this.options.fallbackOnBody?document.body:J,e=X(Z,!0,At,!0,t),n=this.options;if(At){for(wt=t;"static"===R(wt,"position")&&"none"===R(wt,"transform")&&wt!==document;)wt=wt.parentNode;wt!==document.body&&wt!==document.documentElement?(wt===document&&(wt=O()),e.top+=wt.scrollTop,e.left+=wt.scrollLeft):wt=O(),Tt=E(wt)}k(Q=Z.cloneNode(!0),n.ghostClass,!1),k(Q,n.fallbackClass,!0),k(Q,n.dragClass,!0),R(Q,"transition",""),R(Q,"transform",""),R(Q,"box-sizing","border-box"),R(Q,"margin",0),R(Q,"top",e.top),R(Q,"left",e.left),R(Q,"width",e.width),R(Q,"height",e.height),R(Q,"opacity","0.8"),R(Q,"position",At?"absolute":"fixed"),R(Q,"zIndex","100000"),R(Q,"pointerEvents","none"),jt.ghost=Q,t.appendChild(Q),R(Q,"transform-origin",ft/parseInt(Q.style.width)*100+"% "+gt/parseInt(Q.style.height)*100+"%")}},_onDragStart:function(t,e){var n=this,o=t.dataTransfer,i=n.options;U("dragStart",this,{evt:t}),jt.eventCanceled?this._onDrop():(U("setupClone",this),jt.eventCanceled||((nt=C(Z)).removeAttribute("id"),nt.draggable=!1,nt.style["will-change"]="",this._hideClone(),k(nt,this.options.chosenClass,!1),jt.clone=nt),n.cloneId=Wt(function(){U("clone",n),jt.eventCanceled||(n.options.removeCloneOnHide||J.insertBefore(nt,Z),n._hideClone(),V({sortable:n,name:"clone"}))}),e||k(Z,i.dragClass,!0),e?(Et=!0,n._loopId=setInterval(n._emulateDragOver,50)):(p(document,"mouseup",n._onDrop),p(document,"touchend",n._onDrop),p(document,"touchcancel",n._onDrop),o&&(o.effectAllowed="move",i.setData&&i.setData.call(n,o,Z)),h(document,"drop",n),R(Z,"transform","translateZ(0)")),Dt=!0,n._dragStartId=Wt(n._dragStarted.bind(n,e,t)),h(document,"selectstart",n),mt=!0,window.getSelection().removeAllRanges(),u&&R(document.body,"user-select","none"))},_onDragOver:function(n){var o,i,r,t,e,a=this.el,l=n.target,s=this.options,c=s.group,u=jt.active,d=st===c,h=s.sort,p=ct||u,f=this,g=!1;if(!xt){if(void 0!==n.preventDefault&&n.cancelable&&n.preventDefault(),l=P(l,s.draggable,a,!0),O("dragOver"),jt.eventCanceled)return g;if(Z.contains(n.target)||l.animated&&l.animatingX&&l.animatingY||f._ignoreWhileAnimating===l)return A(!1);if(Et=!1,u&&!s.disabled&&(d?h||(i=$!==J):ct===this||(this.lastPutMode=st.checkPull(this,u,Z,n))&&c.checkPut(this,u,Z,n))){if(r="vertical"===this._getDirection(n,l),o=X(Z),O("dragOverValid"),jt.eventCanceled)return g;if(i)return $=J,M(),this._hideClone(),O("revert"),jt.eventCanceled||(tt?J.insertBefore(Z,tt):J.appendChild(Z)),A(!0);var m=F(a,s.draggable);if(m&&(S=n,c=r,x=X(F((E=this).el,E.options.draggable)),E=L(E.el,E.options,Q),!(c?S.clientX>E.right+10||S.clientY>x.bottom&&S.clientX>x.left:S.clientY>E.bottom+10||S.clientX>x.right&&S.clientY>x.top)||m.animated)){if(m&&(t=n,e=r,C=X(B((_=this).el,0,_.options,!0)),_=L(_.el,_.options,Q),e?t.clientX<_.left-10||t.clientY<C.top&&t.clientX<C.right:t.clientY<_.top-10||t.clientY<C.bottom&&t.clientX<C.left)){var v=B(a,0,s,!0);if(v===Z)return A(!1);if(D=X(l=v),!1!==Ht(J,a,Z,o,l,D,n,!1))return M(),a.insertBefore(Z,v),$=a,N(),A(!0)}else if(l.parentNode===a){var b,y,w,D=X(l),E=Z.parentNode!==a,S=(S=Z.animated&&Z.toRect||o,x=l.animated&&l.toRect||D,_=(e=r)?S.left:S.top,t=e?S.right:S.bottom,C=e?S.width:S.height,v=e?x.left:x.top,S=e?x.right:x.bottom,x=e?x.width:x.height,!(_===v||t===S||_+C/2===v+x/2)),_=r?"top":"left",C=Y(l,"top","top")||Y(Z,"top","top"),v=C?C.scrollTop:void 0;if(vt!==l&&(y=D[_],_t=!1,Ct=!S&&s.invertSwap||E),0!==(b=function(t,e,n,o,i,r,a,l){var s=o?t.clientY:t.clientX,c=o?n.height:n.width,t=o?n.top:n.left,o=o?n.bottom:n.right,n=!1;if(!a)if(l&&yt<c*i){if(_t=!_t&&(1===bt?t+c*r/2<s:s<o-c*r/2)?!0:_t)n=!0;else if(1===bt?s<t+yt:o-yt<s)return-bt}else if(t+c*(1-i)/2<s&&s<o-c*(1-i)/2)return function(t){return j(Z)<j(t)?1:-1}(e);if((n=n||a)&&(s<t+c*r/2||o-c*r/2<s))return t+c/2<s?1:-1;return 0}(n,l,D,r,S?1:s.swapThreshold,null==s.invertedSwapThreshold?s.swapThreshold:s.invertedSwapThreshold,Ct,vt===l)))for(var T=j(Z);(w=$.children[T-=b])&&("none"===R(w,"display")||w===Q););if(0===b||w===l)return A(!1);bt=b;var x=(vt=l).nextElementSibling,E=!1,S=Ht(J,a,Z,o,l,D,n,E=1===b);if(!1!==S)return 1!==S&&-1!==S||(E=1===S),xt=!0,setTimeout(Kt,30),M(),E&&!x?a.appendChild(Z):l.parentNode.insertBefore(Z,E?x:l),C&&H(C,0,v-C.scrollTop),$=Z.parentNode,void 0===y||Ct||(yt=Math.abs(y-X(l)[_])),N(),A(!0)}}else{if(m===Z)return A(!1);if((l=m&&a===n.target?m:l)&&(D=X(l)),!1!==Ht(J,a,Z,o,l,D,n,!!l))return M(),m&&m.nextSibling?a.insertBefore(Z,m.nextSibling):a.appendChild(Z),$=a,N(),A(!0)}if(a.contains(Z))return A(!1)}return!1}function O(t,e){U(t,f,I({evt:n,isOwner:d,axis:r?"vertical":"horizontal",revert:i,dragRect:o,targetRect:D,canSort:h,fromSortable:p,target:l,completed:A,onMove:function(t,e){return Ht(J,a,Z,o,t,X(t),n,e)},changed:N},e))}function M(){O("dragOverAnimationCapture"),f.captureAnimationState(),f!==p&&p.captureAnimationState()}function A(t){return O("dragOverCompleted",{insertion:t}),t&&(d?u._hideClone():u._showClone(f),f!==p&&(k(Z,(ct||u).options.ghostClass,!1),k(Z,s.ghostClass,!0)),ct!==f&&f!==jt.active?ct=f:f===jt.active&&ct&&(ct=null),p===f&&(f._ignoreWhileAnimating=l),f.animateAll(function(){O("dragOverAnimationComplete"),f._ignoreWhileAnimating=null}),f!==p&&(p.animateAll(),p._ignoreWhileAnimating=null)),(l===Z&&!Z.animated||l===a&&!l.animated)&&(vt=null),s.dragoverBubble||n.rootEl||l===document||(Z.parentNode[K]._isOutsideThisEl(n.target),t||Bt(n)),!s.dragoverBubble&&n.stopPropagation&&n.stopPropagation(),g=!0}function N(){rt=j(Z),lt=j(Z,s.draggable),V({sortable:f,name:"change",toEl:a,newIndex:rt,newDraggableIndex:lt,originalEvent:n})}},_ignoreWhileAnimating:null,_offMoveEvents:function(){p(document,"mousemove",this._onTouchMove),p(document,"touchmove",this._onTouchMove),p(document,"pointermove",this._onTouchMove),p(document,"dragover",Bt),p(document,"mousemove",Bt),p(document,"touchmove",Bt)},_offUpEvents:function(){var t=this.el.ownerDocument;p(t,"mouseup",this._onDrop),p(t,"touchend",this._onDrop),p(t,"pointerup",this._onDrop),p(t,"pointercancel",this._onDrop),p(t,"touchcancel",this._onDrop),p(document,"selectstart",this)},_onDrop:function(t){var e=this.el,n=this.options;rt=j(Z),lt=j(Z,n.draggable),U("drop",this,{evt:t}),$=Z&&Z.parentNode,rt=j(Z),lt=j(Z,n.draggable),jt.eventCanceled||(_t=Ct=Dt=!1,clearInterval(this._loopId),clearTimeout(this._dragStartTimer),zt(this.cloneId),zt(this._dragStartId),this.nativeDraggable&&(p(document,"drop",this),p(e,"dragstart",this._onDragStart)),this._offMoveEvents(),this._offUpEvents(),u&&R(document.body,"user-select",""),R(Z,"transform",""),t&&(mt&&(t.cancelable&&t.preventDefault(),n.dropBubble||t.stopPropagation()),Q&&Q.parentNode&&Q.parentNode.removeChild(Q),(J===$||ct&&"clone"!==ct.lastPutMode)&&nt&&nt.parentNode&&nt.parentNode.removeChild(nt),Z&&(this.nativeDraggable&&p(Z,"dragend",this),Lt(Z),Z.style["will-change"]="",mt&&!Dt&&k(Z,(ct||this).options.ghostClass,!1),k(Z,this.options.chosenClass,!1),V({sortable:this,name:"unchoose",toEl:$,newIndex:null,newDraggableIndex:null,originalEvent:t}),J!==$?(0<=rt&&(V({rootEl:$,name:"add",toEl:$,fromEl:J,originalEvent:t}),V({sortable:this,name:"remove",toEl:$,originalEvent:t}),V({rootEl:$,name:"sort",toEl:$,fromEl:J,originalEvent:t}),V({sortable:this,name:"sort",toEl:$,originalEvent:t})),ct&&ct.save()):rt!==it&&0<=rt&&(V({sortable:this,name:"update",toEl:$,originalEvent:t}),V({sortable:this,name:"sort",toEl:$,originalEvent:t})),jt.active&&(null!=rt&&-1!==rt||(rt=it,lt=at),V({sortable:this,name:"end",toEl:$,originalEvent:t}),this.save())))),this._nulling()},_nulling:function(){U("nulling",this),J=Z=$=Q=tt=nt=et=ot=ut=dt=mt=rt=lt=it=at=vt=bt=ct=st=jt.dragged=jt.ghost=jt.clone=jt.active=null,Ot.forEach(function(t){t.checked=!0}),Ot.length=ht=pt=0},handleEvent:function(t){switch(t.type){case"drop":case"dragend":this._onDrop(t);break;case"dragenter":case"dragover":Z&&(this._onDragOver(t),function(t){t.dataTransfer&&(t.dataTransfer.dropEffect="move");t.cancelable&&t.preventDefault()}(t));break;case"selectstart":t.preventDefault()}},toArray:function(){for(var t,e=[],n=this.el.children,o=0,i=n.length,r=this.options;o<i;o++)P(t=n[o],r.draggable,this.el,!1)&&e.push(t.getAttribute(r.dataIdAttr)||function(t){var e=t.tagName+t.className+t.src+t.href+t.textContent,n=e.length,o=0;for(;n--;)o+=e.charCodeAt(n);return o.toString(36)}(t));return e},sort:function(t,e){var n={},o=this.el;this.toArray().forEach(function(t,e){e=o.children[e];P(e,this.options.draggable,o,!1)&&(n[t]=e)},this),e&&this.captureAnimationState(),t.forEach(function(t){n[t]&&(o.removeChild(n[t]),o.appendChild(n[t]))}),e&&this.animateAll()},save:function(){var t=this.options.store;t&&t.set&&t.set(this)},closest:function(t,e){return P(t,e||this.options.draggable,this.el,!1)},option:function(t,e){var n=this.options;if(void 0===e)return n[t];var o=z.modifyOption(this,t,e);n[t]=void 0!==o?o:e,"group"===t&&Rt(n)},destroy:function(){U("destroy",this);var t=this.el;t[K]=null,p(t,"mousedown",this._onTapStart),p(t,"touchstart",this._onTapStart),p(t,"pointerdown",this._onTapStart),this.nativeDraggable&&(p(t,"dragover",this),p(t,"dragenter",this)),Array.prototype.forEach.call(t.querySelectorAll("[draggable]"),function(t){t.removeAttribute("draggable")}),this._onDrop(),this._disableDelayedDragEvents(),St.splice(St.indexOf(this.el),1),this.el=t=null},_hideClone:function(){ot||(U("hideClone",this),jt.eventCanceled||(R(nt,"display","none"),this.options.removeCloneOnHide&&nt.parentNode&&nt.parentNode.removeChild(nt),ot=!0))},_showClone:function(t){"clone"===t.lastPutMode?ot&&(U("showClone",this),jt.eventCanceled||(Z.parentNode!=J||this.options.group.revertClone?tt?J.insertBefore(nt,tt):J.appendChild(nt):J.insertBefore(nt,Z),this.options.group.revertClone&&this.animate(Z,nt),R(nt,"display",""),ot=!1)):this._hideClone()}},Mt&&h(document,"touchmove",function(t){(jt.active||Dt)&&t.cancelable&&t.preventDefault()}),jt.utils={on:h,off:p,css:R,find:D,is:function(t,e){return!!P(t,e,t,!1)},extend:function(t,e){if(t&&e)for(var n in e)e.hasOwnProperty(n)&&(t[n]=e[n]);return t},throttle:_,closest:P,toggleClass:k,clone:C,index:j,nextTick:Wt,cancelNextTick:zt,detectDirection:kt,getChild:B,expando:K},jt.get=function(t){return t[K]},jt.mount=function(){for(var t=arguments.length,e=new Array(t),n=0;n<t;n++)e[n]=arguments[n];(e=e[0].constructor===Array?e[0]:e).forEach(function(t){if(!t.prototype||!t.prototype.constructor)throw"Sortable: Mounted plugin must be a constructor function, not ".concat({}.toString.call(t));t.utils&&(jt.utils=I(I({},jt.utils),t.utils)),z.mount(t)})},jt.create=function(t,e){return new jt(t,e)};var Gt,Ut,qt,Vt,Zt,$t,Qt=[],Jt=!(jt.version="1.15.6");function te(){Qt.forEach(function(t){clearInterval(t.pid)}),Qt=[]}function ee(){clearInterval($t)}var ne,oe=_(function(n,t,e,o){if(t.scroll){var i,r=(n.touches?n.touches[0]:n).clientX,a=(n.touches?n.touches[0]:n).clientY,l=t.scrollSensitivity,s=t.scrollSpeed,c=O(),u=!1;Ut!==e&&(Ut=e,te(),Gt=t.scroll,i=t.scrollFn,!0===Gt&&(Gt=M(e,!0)));var d=0,h=Gt;do{var p=h,f=X(p),g=f.top,m=f.bottom,v=f.left,b=f.right,y=f.width,w=f.height,D=void 0,E=void 0,S=p.scrollWidth,_=p.scrollHeight,C=R(p),T=p.scrollLeft,f=p.scrollTop,E=p===c?(D=y<S&&("auto"===C.overflowX||"scroll"===C.overflowX||"visible"===C.overflowX),w<_&&("auto"===C.overflowY||"scroll"===C.overflowY||"visible"===C.overflowY)):(D=y<S&&("auto"===C.overflowX||"scroll"===C.overflowX),w<_&&("auto"===C.overflowY||"scroll"===C.overflowY)),T=D&&(Math.abs(b-r)<=l&&T+y<S)-(Math.abs(v-r)<=l&&!!T),f=E&&(Math.abs(m-a)<=l&&f+w<_)-(Math.abs(g-a)<=l&&!!f);if(!Qt[d])for(var x=0;x<=d;x++)Qt[x]||(Qt[x]={});Qt[d].vx==T&&Qt[d].vy==f&&Qt[d].el===p||(Qt[d].el=p,Qt[d].vx=T,Qt[d].vy=f,clearInterval(Qt[d].pid),0==T&&0==f||(u=!0,Qt[d].pid=setInterval(function(){o&&0===this.layer&&jt.active._onTouchMove(Zt);var t=Qt[this.layer].vy?Qt[this.layer].vy*s:0,e=Qt[this.layer].vx?Qt[this.layer].vx*s:0;"function"==typeof i&&"continue"!==i.call(jt.dragged.parentNode[K],e,t,n,Zt,Qt[this.layer].el)||H(Qt[this.layer].el,e,t)}.bind({layer:d}),24))),d++}while(t.bubbleScroll&&h!==c&&(h=M(h,!1)));Jt=u}},30),n=function(t){var e=t.originalEvent,n=t.putSortable,o=t.dragEl,i=t.activeSortable,r=t.dispatchSortableEvent,a=t.hideGhostForTarget,t=t.unhideGhostForTarget;e&&(i=n||i,a(),e=e.changedTouches&&e.changedTouches.length?e.changedTouches[0]:e,e=document.elementFromPoint(e.clientX,e.clientY),t(),i&&!i.el.contains(e)&&(r("spill"),this.onSpill({dragEl:o,putSortable:n})))};function ie(){}function re(){}ie.prototype={startIndex:null,dragStart:function(t){t=t.oldDraggableIndex;this.startIndex=t},onSpill:function(t){var e=t.dragEl,n=t.putSortable;this.sortable.captureAnimationState(),n&&n.captureAnimationState();t=B(this.sortable.el,this.startIndex,this.options);t?this.sortable.el.insertBefore(e,t):this.sortable.el.appendChild(e),this.sortable.animateAll(),n&&n.animateAll()},drop:n},a(ie,{pluginName:"revertOnSpill"}),re.prototype={onSpill:function(t){var e=t.dragEl,t=t.putSortable||this.sortable;t.captureAnimationState(),e.parentNode&&e.parentNode.removeChild(e),t.animateAll()},drop:n},a(re,{pluginName:"removeOnSpill"});var ae,le,se,ce,ue,de=[],he=[],pe=!1,fe=!1,ge=!1;function me(n,o){he.forEach(function(t,e){e=o.children[t.sortableIndex+(n?Number(e):0)];e?o.insertBefore(t,e):o.appendChild(t)})}function ve(){de.forEach(function(t){t!==se&&t.parentNode&&t.parentNode.removeChild(t)})}return jt.mount(new function(){function t(){for(var t in this.defaults={scroll:!0,forceAutoScrollFallback:!1,scrollSensitivity:30,scrollSpeed:10,bubbleScroll:!0},this)"_"===t.charAt(0)&&"function"==typeof this[t]&&(this[t]=this[t].bind(this))}return t.prototype={dragStarted:function(t){t=t.originalEvent;this.sortable.nativeDraggable?h(document,"dragover",this._handleAutoScroll):this.options.supportPointer?h(document,"pointermove",this._handleFallbackAutoScroll):t.touches?h(document,"touchmove",this._handleFallbackAutoScroll):h(document,"mousemove",this._handleFallbackAutoScroll)},dragOverCompleted:function(t){t=t.originalEvent;this.options.dragOverBubble||t.rootEl||this._handleAutoScroll(t)},drop:function(){this.sortable.nativeDraggable?p(document,"dragover",this._handleAutoScroll):(p(document,"pointermove",this._handleFallbackAutoScroll),p(document,"touchmove",this._handleFallbackAutoScroll),p(document,"mousemove",this._handleFallbackAutoScroll)),ee(),te(),clearTimeout(m),m=void 0},nulling:function(){Zt=Ut=Gt=Jt=$t=qt=Vt=null,Qt.length=0},_handleFallbackAutoScroll:function(t){this._handleAutoScroll(t,!0)},_handleAutoScroll:function(e,n){var o,i=this,r=(e.touches?e.touches[0]:e).clientX,a=(e.touches?e.touches[0]:e).clientY,t=document.elementFromPoint(r,a);Zt=e,n||this.options.forceAutoScrollFallback||w||y||u?(oe(e,this.options,t,n),o=M(t,!0),!Jt||$t&&r===qt&&a===Vt||($t&&ee(),$t=setInterval(function(){var t=M(document.elementFromPoint(r,a),!0);t!==o&&(o=t,te()),oe(e,i.options,t,n)},10),qt=r,Vt=a)):this.options.bubbleScroll&&M(t,!0)!==O()?oe(e,this.options,M(t,!1),!1):te()}},a(t,{pluginName:"scroll",initializeByDefault:!0})}),jt.mount(re,ie),jt.mount(new function(){function t(){this.defaults={swapClass:"sortable-swap-highlight"}}return t.prototype={dragStart:function(t){t=t.dragEl;ne=t},dragOverValid:function(t){var e=t.completed,n=t.target,o=t.onMove,i=t.activeSortable,r=t.changed,a=t.cancel;i.options.swap&&(t=this.sortable.el,i=this.options,n&&n!==t&&(t=ne,ne=!1!==o(n)?(k(n,i.swapClass,!0),n):null,t&&t!==ne&&k(t,i.swapClass,!1)),r(),e(!0),a())},drop:function(t){var e,n,o=t.activeSortable,i=t.putSortable,r=t.dragEl,a=i||this.sortable,l=this.options;ne&&k(ne,l.swapClass,!1),ne&&(l.swap||i&&i.options.swap)&&r!==ne&&(a.captureAnimationState(),a!==o&&o.captureAnimationState(),n=ne,t=(e=r).parentNode,l=n.parentNode,t&&l&&!t.isEqualNode(n)&&!l.isEqualNode(e)&&(i=j(e),r=j(n),t.isEqualNode(l)&&i<r&&r++,t.insertBefore(n,t.children[i]),l.insertBefore(e,l.children[r])),a.animateAll(),a!==o&&o.animateAll())},nulling:function(){ne=null}},a(t,{pluginName:"swap",eventProperties:function(){return{swapItem:ne}}})}),jt.mount(new function(){function t(o){for(var t in this)"_"===t.charAt(0)&&"function"==typeof this[t]&&(this[t]=this[t].bind(this));o.options.avoidImplicitDeselect||(o.options.supportPointer?h(document,"pointerup",this._deselectMultiDrag):(h(document,"mouseup",this._deselectMultiDrag),h(document,"touchend",this._deselectMultiDrag))),h(document,"keydown",this._checkKeyDown),h(document,"keyup",this._checkKeyUp),this.defaults={selectedClass:"sortable-selected",multiDragKey:null,avoidImplicitDeselect:!1,setData:function(t,e){var n="";de.length&&le===o?de.forEach(function(t,e){n+=(e?", ":"")+t.textContent}):n=e.textContent,t.setData("Text",n)}}}return t.prototype={multiDragKeyDown:!1,isMultiDrag:!1,delayStartGlobal:function(t){t=t.dragEl;se=t},delayEnded:function(){this.isMultiDrag=~de.indexOf(se)},setupClone:function(t){var e=t.sortable,t=t.cancel;if(this.isMultiDrag){for(var n=0;n<de.length;n++)he.push(C(de[n])),he[n].sortableIndex=de[n].sortableIndex,he[n].draggable=!1,he[n].style["will-change"]="",k(he[n],this.options.selectedClass,!1),de[n]===se&&k(he[n],this.options.chosenClass,!1);e._hideClone(),t()}},clone:function(t){var e=t.sortable,n=t.rootEl,o=t.dispatchSortableEvent,t=t.cancel;this.isMultiDrag&&(this.options.removeCloneOnHide||de.length&&le===e&&(me(!0,n),o("clone"),t()))},showClone:function(t){var e=t.cloneNowShown,n=t.rootEl,t=t.cancel;this.isMultiDrag&&(me(!1,n),he.forEach(function(t){R(t,"display","")}),e(),ue=!1,t())},hideClone:function(t){var e=this,n=(t.sortable,t.cloneNowHidden),t=t.cancel;this.isMultiDrag&&(he.forEach(function(t){R(t,"display","none"),e.options.removeCloneOnHide&&t.parentNode&&t.parentNode.removeChild(t)}),n(),ue=!0,t())},dragStartGlobal:function(t){t.sortable;!this.isMultiDrag&&le&&le.multiDrag._deselectMultiDrag(),de.forEach(function(t){t.sortableIndex=j(t)}),de=de.sort(function(t,e){return t.sortableIndex-e.sortableIndex}),ge=!0},dragStarted:function(t){var e,n=this,t=t.sortable;this.isMultiDrag&&(this.options.sort&&(t.captureAnimationState(),this.options.animation&&(de.forEach(function(t){t!==se&&R(t,"position","absolute")}),e=X(se,!1,!0,!0),de.forEach(function(t){t!==se&&T(t,e)}),pe=fe=!0)),t.animateAll(function(){pe=fe=!1,n.options.animation&&de.forEach(function(t){x(t)}),n.options.sort&&ve()}))},dragOver:function(t){var e=t.target,n=t.completed,t=t.cancel;fe&&~de.indexOf(e)&&(n(!1),t())},revert:function(t){var n,o,e=t.fromSortable,i=t.rootEl,r=t.sortable,a=t.dragRect;1<de.length&&(de.forEach(function(t){r.addAnimationState({target:t,rect:fe?X(t):a}),x(t),t.fromRect=a,e.removeAnimationState(t)}),fe=!1,n=!this.options.removeCloneOnHide,o=i,de.forEach(function(t,e){e=o.children[t.sortableIndex+(n?Number(e):0)];e?o.insertBefore(t,e):o.appendChild(t)}))},dragOverCompleted:function(t){var e,n=t.sortable,o=t.isOwner,i=t.insertion,r=t.activeSortable,a=t.parentEl,l=t.putSortable,t=this.options;i&&(o&&r._hideClone(),pe=!1,t.animation&&1<de.length&&(fe||!o&&!r.options.sort&&!l)&&(e=X(se,!1,!0,!0),de.forEach(function(t){t!==se&&(T(t,e),a.appendChild(t))}),fe=!0),o||(fe||ve(),1<de.length?(o=ue,r._showClone(n),r.options.animation&&!ue&&o&&he.forEach(function(t){r.addAnimationState({target:t,rect:ce}),t.fromRect=ce,t.thisAnimationDuration=null})):r._showClone(n)))},dragOverAnimationCapture:function(t){var e=t.dragRect,n=t.isOwner,t=t.activeSortable;de.forEach(function(t){t.thisAnimationDuration=null}),t.options.animation&&!n&&t.multiDrag.isMultiDrag&&(ce=a({},e),e=b(se,!0),ce.top-=e.f,ce.left-=e.e)},dragOverAnimationComplete:function(){fe&&(fe=!1,ve())},drop:function(t){var o,i,r,a,n,e,l,s=t.originalEvent,c=t.rootEl,u=t.parentEl,d=t.sortable,h=t.dispatchSortableEvent,p=t.oldIndex,t=t.putSortable,f=t||this.sortable;s&&(o=this.options,i=u.children,ge||(o.multiDragKey&&!this.multiDragKeyDown&&this._deselectMultiDrag(),k(se,o.selectedClass,!~de.indexOf(se)),~de.indexOf(se)?(de.splice(de.indexOf(se),1),ae=null,G({sortable:d,rootEl:c,name:"deselect",targetEl:se,originalEvent:s})):(de.push(se),G({sortable:d,rootEl:c,name:"select",targetEl:se,originalEvent:s}),s.shiftKey&&ae&&d.el.contains(ae)?(r=j(ae),a=j(se),~r&&~a&&r!==a&&function(){for(var e,t=r<a?(e=r,a):(e=a,r+1),n=o.filter;e<t;e++)~de.indexOf(i[e])||P(i[e],o.draggable,u,!1)&&(n&&("function"==typeof n?n.call(d,s,i[e],d):n.split(",").some(function(t){return P(i[e],t.trim(),u,!1)}))||(k(i[e],o.selectedClass,!0),de.push(i[e]),G({sortable:d,rootEl:c,name:"select",targetEl:i[e],originalEvent:s})))}()):ae=se,le=f)),ge&&this.isMultiDrag&&(fe=!1,(u[K].options.sort||u!==c)&&1<de.length&&(n=X(se),e=j(se,":not(."+this.options.selectedClass+")"),!pe&&o.animation&&(se.thisAnimationDuration=null),f.captureAnimationState(),pe||(o.animation&&(se.fromRect=n,de.forEach(function(t){var e;t.thisAnimationDuration=null,t!==se&&(e=fe?X(t):n,t.fromRect=e,f.addAnimationState({target:t,rect:e}))})),ve(),de.forEach(function(t){i[e]?u.insertBefore(t,i[e]):u.appendChild(t),e++}),p===j(se)&&(l=!1,de.forEach(function(t){t.sortableIndex!==j(t)&&(l=!0)}),l&&(h("update"),h("sort")))),de.forEach(function(t){x(t)}),f.animateAll()),le=f),(c===u||t&&"clone"!==t.lastPutMode)&&he.forEach(function(t){t.parentNode&&t.parentNode.removeChild(t)}))},nullingGlobal:function(){this.isMultiDrag=ge=!1,he.length=0},destroyGlobal:function(){this._deselectMultiDrag(),p(document,"pointerup",this._deselectMultiDrag),p(document,"mouseup",this._deselectMultiDrag),p(document,"touchend",this._deselectMultiDrag),p(document,"keydown",this._checkKeyDown),p(document,"keyup",this._checkKeyUp)},_deselectMultiDrag:function(t){if(!(void 0!==ge&&ge||le!==this.sortable||t&&P(t.target,this.options.draggable,this.sortable.el,!1)||t&&0!==t.button))for(;de.length;){var e=de[0];k(e,this.options.selectedClass,!1),de.shift(),G({sortable:this.sortable,rootEl:this.sortable.el,name:"deselect",targetEl:e,originalEvent:t})}},_checkKeyDown:function(t){t.key===this.options.multiDragKey&&(this.multiDragKeyDown=!0)},_checkKeyUp:function(t){t.key===this.options.multiDragKey&&(this.multiDragKeyDown=!1)}},a(t,{pluginName:"multiDrag",utils:{select:function(t){var e=t.parentNode[K];e&&e.options.multiDrag&&!~de.indexOf(t)&&(le&&le!==e&&(le.multiDrag._deselectMultiDrag(),le=e),k(t,e.options.selectedClass,!0),de.push(t))},deselect:function(t){var e=t.parentNode[K],n=de.indexOf(t);e&&e.options.multiDrag&&~n&&(k(t,e.options.selectedClass,!1),de.splice(n,1))}},eventProperties:function(){var n=this,o=[],i=[];return de.forEach(function(t){var e;o.push({multiDragElement:t,index:t.sortableIndex}),e=fe&&t!==se?-1:fe?j(t,":not(."+n.options.selectedClass+")"):j(t),i.push({multiDragElement:t,index:e})}),{items:r(de),clones:[].concat(he),oldIndicies:o,newIndicies:i}},optionListeners:{multiDragKey:function(t){return"ctrl"===(t=t.toLowerCase())?t="Control":1<t.length&&(t=t.charAt(0).toUpperCase()+t.substr(1)),t}}})}),jt});'''
QRCODE_JS = r"""var qrcode=function(){var t=function(t,r){var e=t,n=g[r],o=null,i=0,a=null,u=[],f={},c=function(t,r){o=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(i=4*e+17),l(0,0),l(i-7,0),l(0,i-7),s(),h(),d(t,r),e>=7&&v(t),null==a&&(a=p(e,n,u)),w(a,r)},l=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||i<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||i<=r+n||(o[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},h=function(){for(var t=8;t<i-8;t+=1)null==o[t][6]&&(o[t][6]=t%2==0);for(var r=8;r<i-8;r+=1)null==o[6][r]&&(o[6][r]=r%2==0)},s=function(){for(var t=B.getPatternPosition(e),r=0;r<t.length;r+=1)for(var n=0;n<t.length;n+=1){var i=t[r],a=t[n];if(null==o[i][a])for(var u=-2;u<=2;u+=1)for(var f=-2;f<=2;f+=1)o[i+u][a+f]=-2==u||2==u||-2==f||2==f||0==u&&0==f}},v=function(t){for(var r=B.getBCHTypeNumber(e),n=0;n<18;n+=1){var a=!t&&1==(r>>n&1);o[Math.floor(n/3)][n%3+i-8-3]=a}for(n=0;n<18;n+=1){a=!t&&1==(r>>n&1);o[n%3+i-8-3][Math.floor(n/3)]=a}},d=function(t,r){for(var e=n<<3|r,a=B.getBCHTypeInfo(e),u=0;u<15;u+=1){var f=!t&&1==(a>>u&1);u<6?o[u][8]=f:u<8?o[u+1][8]=f:o[i-15+u][8]=f}for(u=0;u<15;u+=1){f=!t&&1==(a>>u&1);u<8?o[8][i-u-1]=f:u<9?o[8][15-u-1+1]=f:o[8][15-u-1]=f}o[i-8][8]=!t},w=function(t,r){for(var e=-1,n=i-1,a=7,u=0,f=B.getMaskFunction(r),c=i-1;c>0;c-=2)for(6==c&&(c-=1);;){for(var g=0;g<2;g+=1)if(null==o[n][c-g]){var l=!1;u<t.length&&(l=1==(t[u]>>>a&1)),f(n,c-g)&&(l=!l),o[n][c-g]=l,-1==(a-=1)&&(u+=1,a=7)}if((n+=e)<0||i<=n){n-=e,e=-e;break}}},p=function(t,r,e){for(var n=A.getRSBlocks(t,r),o=b(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=k(i[u],l.getLength()-1).mod(l);for(a[u]=new Array(l.getLength()-1),g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=s>=0?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};f.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=M(t);break;case"Alphanumeric":e=x(t);break;case"Byte":e=m(t);break;case"Kanji":e=L(t);break;default:throw"mode:"+r}u.push(e),a=null},f.isDark=function(t,r){if(t<0||i<=t||r<0||i<=r)throw t+","+r;return o[t][r]},f.getModuleCount=function(){return i},f.make=function(){if(e<1){for(var t=1;t<40;t++){for(var r=A.getRSBlocks(t,n),o=b(),i=0;i<u.length;i++){var a=u[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var g=0;for(i=0;i<r.length;i++)g+=r[i].dataCount;if(o.getLengthInBits()<=8*g)break}e=t}c(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){c(!0,e);var n=B.getLostPoint(f);(0==e||t>n)&&(t=n,r=e)}return r}())},f.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<f.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<f.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=f.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},f.createSvgTag=function(t,r,e,n){var o={};"object"==typeof arguments[0]&&(t=(o=arguments[0]).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,c,g=f.getModuleCount()*t+2*r,l="";for(c="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",l+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',l+=o.scalable?"":' width="'+g+'px" height="'+g+'px"',l+=' viewBox="0 0 '+g+" "+g+'" ',l+=' preserveAspectRatio="xMinYMin meet"',l+=n.text||e.text?' role="img" aria-labelledby="'+y([n.id,e.id].join(" ").trim())+'"':"",l+=">",l+=n.text?'<title id="'+y(n.id)+'">'+y(n.text)+"</title>":"",l+=e.text?'<description id="'+y(e.id)+'">'+y(e.text)+"</description>":"",l+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',l+='<path d="',a=0;a<f.getModuleCount();a+=1)for(u=a*t+r,i=0;i<f.getModuleCount();i+=1)f.isDark(a,i)&&(l+="M"+(i*t+r)+","+u+c);return l+='" stroke="transparent" fill="black"/>',l+="</svg>"},f.createDataURL=function(t,r){t=t||2,r=void 0===r?4*t:r;var e=f.getModuleCount()*t+2*r,n=r,o=e-r;return I(e,e,(function(r,e){if(n<=r&&r<o&&n<=e&&e<o){var i=Math.floor((r-n)/t),a=Math.floor((e-n)/t);return f.isDark(a,i)?0:1}return 1}))},f.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=f.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=f.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=y(e),o+='"'),o+="/>"};var y=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return f.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*f.getModuleCount()+2*t,u=t,c=a-t,g={"██":"█","█ ":"▀"," █":"▄","  ":" "},l={"██":"▀","█ ":"▀"," █":" ","  ":" "},h="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<c&&u<=r&&r<c&&f.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<c&&u<=r+1&&r+1<c&&f.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",h+=t<1&&r+1>=c?l[i]:g[i];h+="\n"}return a%2&&t>0?h.substring(0,h.length-a-1)+Array(a+1).join("▀"):h.substring(0,h.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=f.getModuleCount()*t+2*r,u=r,c=a-r,g=Array(t+1).join("██"),l=Array(t+1).join("  "),h="",s="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),s="",n=0;n<a;n+=1)i=1,u<=n&&n<c&&u<=e&&e<c&&f.isDark(o,Math.floor((n-u)/t))&&(i=0),s+=i?g:l;for(o=0;o<t;o+=1)h+=s+"\n"}return h.substring(0,h.length-1)},f.renderTo2dContext=function(t,r){r=r||2;for(var e=f.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=f.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},f};t.stringToBytes=(t.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,t.createStringToBytes=function(t,r){var e=function(){for(var e=S(t),n=function(){var t=e.read();if(-1==t)throw"eof";return t},o=0,i={};;){var a=e.read();if(-1==a)break;var u=n(),f=n()<<8|n();i[String.fromCharCode(a<<8|u)]=f,o+=1}if(o!=r)throw o+" != "+r;return i}(),n="?".charCodeAt(0);return function(t){for(var r=[],o=0;o<t.length;o+=1){var i=t.charCodeAt(o);if(i<128)r.push(i);else{var a=e[t.charAt(o)];"number"==typeof a?(255&a)==a?r.push(a):(r.push(a>>>8),r.push(255&a)):r.push(n)}}return r}};var r,e,n,o,i,a=1,u=2,f=4,c=8,g={L:1,M:0,Q:3,H:2},l=0,h=1,s=2,v=3,d=4,w=5,p=6,y=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],e=1335,n=7973,i=function(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r},(o={}).getBCHTypeInfo=function(t){for(var r=t<<10;i(r)-i(e)>=0;)r^=e<<i(r)-i(e);return 21522^(t<<10|r)},o.getBCHTypeNumber=function(t){for(var r=t<<12;i(r)-i(n)>=0;)r^=n<<i(r)-i(n);return t<<12|r},o.getPatternPosition=function(t){return r[t-1]},o.getMaskFunction=function(t){switch(t){case l:return function(t,r){return(t+r)%2==0};case h:return function(t,r){return t%2==0};case s:return function(t,r){return r%3==0};case v:return function(t,r){return(t+r)%3==0};case d:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case w:return function(t,r){return t*r%2+t*r%3==0};case p:return function(t,r){return(t*r%2+t*r%3)%2==0};case y:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},o.getErrorCorrectPolynomial=function(t){for(var r=k([1],0),e=0;e<t;e+=1)r=r.multiply(k([1,C.gexp(e)],0));return r},o.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case f:case c:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case f:return 16;case c:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case f:return 16;case c:return 12;default:throw"mode:"+t}}},o.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);i>5&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},o),C=function(){for(var t=new Array(256),r=new Array(256),e=0;e<8;e+=1)t[e]=1<<e;for(e=8;e<256;e+=1)t[e]=t[e-4]^t[e-5]^t[e-6]^t[e-8];for(e=0;e<255;e+=1)r[t[e]]=e;var n={glog:function(t){if(t<1)throw"glog("+t+")";return r[t]},gexp:function(r){for(;r<0;)r+=255;for(;r>=256;)r-=255;return t[r]}};return n}();function k(t,r){if(void 0===t.length)throw t.length+"/"+r;var e=function(){for(var e=0;e<t.length&&0==t[e];)e+=1;for(var n=new Array(t.length-e+r),o=0;o<t.length-e;o+=1)n[o]=t[o+e];return n}(),n={getAt:function(t){return e[t]},getLength:function(){return e.length},multiply:function(t){for(var r=new Array(n.getLength()+t.getLength()-1),e=0;e<n.getLength();e+=1)for(var o=0;o<t.getLength();o+=1)r[e+o]^=C.gexp(C.glog(n.getAt(e))+C.glog(t.getAt(o)));return k(r,0)},mod:function(t){if(n.getLength()-t.getLength()<0)return n;for(var r=C.glog(n.getAt(0))-C.glog(t.getAt(0)),e=new Array(n.getLength()),o=0;o<n.getLength();o+=1)e[o]=n.getAt(o);for(o=0;o<t.getLength();o+=1)e[o]^=C.gexp(C.glog(t.getAt(o))+r);return k(e,0).mod(t)}};return n}var A=function(){var t=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],r=function(t,r){var e={};return e.totalCount=t,e.dataCount=r,e},e={};return e.getRSBlocks=function(e,n){var o=function(r,e){switch(e){case g.L:return t[4*(r-1)+0];case g.M:return t[4*(r-1)+1];case g.Q:return t[4*(r-1)+2];case g.H:return t[4*(r-1)+3];default:return}}(e,n);if(void 0===o)throw"bad rs block @ typeNumber:"+e+"/errorCorrectionLevel:"+n;for(var i=o.length/3,a=[],u=0;u<i;u+=1)for(var f=o[3*u+0],c=o[3*u+1],l=o[3*u+2],h=0;h<f;h+=1)a.push(r(c,l));return a},e}(),b=function(){var t=[],r=0,e={getBuffer:function(){return t},getAt:function(r){var e=Math.floor(r/8);return 1==(t[e]>>>7-r%8&1)},put:function(t,r){for(var n=0;n<r;n+=1)e.putBit(1==(t>>>r-n-1&1))},getLengthInBits:function(){return r},putBit:function(e){var n=Math.floor(r/8);t.length<=n&&t.push(0),e&&(t[n]|=128>>>r%8),r+=1}};return e},M=function(t){var r=a,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+2<r.length;)t.put(o(r.substring(n,n+3)),10),n+=3;n<r.length&&(r.length-n==1?t.put(o(r.substring(n,n+1)),4):r.length-n==2&&t.put(o(r.substring(n,n+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return n},x=function(t){var r=u,e=t,n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=e,n=0;n+1<r.length;)t.put(45*o(r.charAt(n))+o(r.charAt(n+1)),11),n+=2;n<r.length&&t.put(o(r.charAt(n)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return n},m=function(r){var e=f,n=t.stringToBytes(r),o={getMode:function(){return e},getLength:function(t){return n.length},write:function(t){for(var r=0;r<n.length;r+=1)t.put(n[r],8)}};return o},L=function(r){var e=c,n=t.stringToBytesFuncs.SJIS;if(!n)throw"sjis not supported.";!function(){var t=n("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=n(r),i={getMode:function(){return e},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return i},D=function(){var t=[],r={writeByte:function(r){t.push(255&r)},writeShort:function(t){r.writeByte(t),r.writeByte(t>>>8)},writeBytes:function(t,e,n){e=e||0,n=n||t.length;for(var o=0;o<n;o+=1)r.writeByte(t[o+e])},writeString:function(t){for(var e=0;e<t.length;e+=1)r.writeByte(t.charCodeAt(e))},toByteArray:function(){return t},toString:function(){var r="";r+="[";for(var e=0;e<t.length;e+=1)e>0&&(r+=","),r+=t[e];return r+="]"}};return r},S=function(t){var r=t,e=0,n=0,o=0,i={read:function(){for(;o<8;){if(e>=r.length){if(0==o)return-1;throw"unexpected end of file./"+o}var t=r.charAt(e);if(e+=1,"="==t)return o=0,-1;t.match(/^\s$/)||(n=n<<6|a(t.charCodeAt(0)),o+=6)}var i=n>>>o-8&255;return o-=8,i}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return i},I=function(t,r,e){for(var n=function(t,r){var e=t,n=r,o=new Array(t*r),i={setPixel:function(t,r,n){o[r*e+t]=n},write:function(t){t.writeString("GIF87a"),t.writeShort(e),t.writeShort(n),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(e),t.writeShort(n),t.writeByte(0);var r=a(2);t.writeByte(2);for(var o=0;r.length-o>255;)t.writeByte(255),t.writeBytes(r,o,255),o+=255;t.writeByte(r.length-o),t.writeBytes(r,o,r.length-o),t.writeByte(0),t.writeString(";")}},a=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,i=u(),a=0;a<r;a+=1)i.add(String.fromCharCode(a));i.add(String.fromCharCode(r)),i.add(String.fromCharCode(e));var f,c,g,l=D(),h=(f=l,c=0,g=0,{write:function(t,r){if(t>>>r!=0)throw"length over";for(;c+r>=8;)f.writeByte(255&(t<<c|g)),r-=8-c,t>>>=8-c,g=0,c=0;g|=t<<c,c+=r},flush:function(){c>0&&f.writeByte(g)}});h.write(r,n);var s=0,v=String.fromCharCode(o[s]);for(s+=1;s<o.length;){var d=String.fromCharCode(o[s]);s+=1,i.contains(v+d)?v+=d:(h.write(i.indexOf(v),n),i.size()<4095&&(i.size()==1<<n&&(n+=1),i.add(v+d)),v=d)}return h.write(i.indexOf(v),n),h.write(e,n),h.flush(),l.toByteArray()},u=function(){var t={},r=0,e={add:function(n){if(e.contains(n))throw"dup key:"+n;t[n]=r,r+=1},size:function(){return r},indexOf:function(r){return t[r]},contains:function(r){return void 0!==t[r]}};return e};return i}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=D();n.write(a);for(var u=function(){var t=0,r=0,e=0,n="",o={},i=function(t){n+=String.fromCharCode(a(63&t))},a=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return o.writeByte=function(n){for(t=t<<8|255&n,r+=8,e+=1;r>=6;)i(t>>>r-6),r-=6},o.flush=function(){if(r>0&&(i(t<<6-r),t=0,r=0),e%3!=0)for(var o=3-e%3,a=0;a<o;a+=1)n+="="},o.toString=function(){return n},o}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return t}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||n>=57344?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}((function(){return qrcode}));"""


def parse_tamizdat_uri(uri, tag_override=None):
    """Parse tamizdat://host:port/?sni=...&pubkey=...&shortid=...&fp=mix[#tag]."""
    uri = (uri or "").strip()
    u = urlparse(uri)
    if u.scheme != "tamizdat":
        raise ValueError("Unsupported URI. Phase 1 supports tamizdat:// and direct only")
    if not u.hostname:
        raise ValueError("tamizdat URI must include host")
    try:
        port = u.port
    except ValueError as e:
        raise ValueError(f"bad port: {e}")
    if not port:
        raise ValueError("tamizdat URI must include host:port")
    if u.path not in ("", "/"):
        raise ValueError("tamizdat URI path must be empty or /")
    params = parse_qs(u.query, keep_blank_values=True)
    sni = (params.get("sni", [""])[0] or params.get("server_name", [""])[0] or u.hostname).strip()
    pub = (params.get("pubkey", [""])[0] or params.get("public_key", [""])[0] or params.get("pbk", [""])[0]).strip()
    sid = (params.get("shortid", [""])[0] or params.get("sid", [""])[0] or (unquote(u.username) if u.username else "")).strip()
    fp = (params.get("fp", ["mix"])[0] or "mix").strip()
    bootstrap = (params.get("bootstrap", [""])[0] or "").strip()
    pub = _fixed_hex(pub, 32, "pubkey")
    sid = _fixed_hex(sid, 8, "shortid")
    tag = _valid_tag(tag_override or (unquote(u.fragment) if u.fragment else f"tamizdat-{u.hostname}"))
    out = {
        "type": "tamizdat",
        "kind": "tamizdat",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(port),
        "public_key": pub,
        "short_id": sid,
        "server_name": sni,
        "fingerprint": fp,
        "tls": {"enabled": True, "server_name": sni},
        "uri": uri,
    }
    if bootstrap:
        out["bootstrap_sni"] = bootstrap
    return out


def parse_uri(uri, tag_override=None):
    uri = (uri or "").strip()
    if uri.startswith("tamizdat://"):
        return parse_tamizdat_uri(uri, tag_override=tag_override)
    if uri.startswith("{") or uri.startswith("balancer://"):
        cfg = parse_balancer_config(uri)
        if tag_override:
            cfg["tag"] = _valid_tag(tag_override)
        return cfg
    return None


def _normalize_balancer_mode(mode):
    mode = (mode or "").strip().lower()
    if mode in ("", "alive", "failover", "first_alive", "first-alive"):
        return "alive"
    if mode in ("round_robin", "round-robin", "rr"):
        return "round_robin"
    raise ValueError(f"unsupported balancer mode {mode!r}")


def _balancer_member_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        raise ValueError("balancer outbounds must be a list or comma-separated string")
    out = []
    for item in items:
        tag = (str(item) if item is not None else "").strip()
        if tag:
            out.append(_valid_tag(tag))
    return out


def _boolish(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on", "enabled")


def _first_positive_int(*values):
    for v in values:
        try:
            n = int(v)
        except Exception:
            continue
        if n > 0:
            return n
    return 0


def _balancer_uri_payload(mode, members, failover_on_high_rtt=False, rtt_threshold_ms=0):
    payload = {"mode": mode, "outbounds": members}
    if failover_on_high_rtt and int(rtt_threshold_ms or 0) > 0:
        payload["failover_on_high_rtt"] = True
        payload["rtt_threshold_ms"] = int(rtt_threshold_ms)
    return payload


def parse_balancer_config(raw, tag_override=None):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("balancer config is required")
    failover_on_high_rtt = False
    rtt_threshold_ms = 0
    if raw.startswith("{"):
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("balancer JSON must be an object")
        mode = _normalize_balancer_mode(data.get("mode"))
        members = _balancer_member_list(data.get("outbounds") or data.get("members") or data.get("targets"))
        failover_on_high_rtt = _boolish(data.get("failover_on_high_rtt"))
        rtt_threshold_ms = _first_positive_int(data.get("rtt_threshold_ms"), data.get("high_rtt_ms"), data.get("max_rtt_ms"))
    elif raw.startswith("balancer://"):
        u = urlparse(raw)
        params = parse_qs(u.query, keep_blank_values=True)
        mode = _normalize_balancer_mode((params.get("mode", [""])[0] or u.netloc or "").strip())
        members_raw = (params.get("outbounds", [""])[0] or params.get("members", [""])[0] or params.get("targets", [""])[0])
        members = _balancer_member_list(members_raw)
        failover_on_high_rtt = _boolish(params.get("failover_on_high_rtt", [""])[0])
        rtt_threshold_ms = _first_positive_int(
            params.get("rtt_threshold_ms", [""])[0],
            params.get("high_rtt_ms", [""])[0],
            params.get("max_rtt_ms", [""])[0],
        )
    else:
        raise ValueError("balancer config must be JSON or balancer:// URI")
    if not members:
        raise ValueError("balancer must include at least one outbound")
    tag = _valid_tag(tag_override or "balancer")
    failover_on_high_rtt = bool(failover_on_high_rtt and rtt_threshold_ms > 0)
    payload = _balancer_uri_payload(mode, members, failover_on_high_rtt, rtt_threshold_ms)
    return {
        "type": "balancer",
        "kind": "balancer",
        "tag": tag,
        "mode": mode,
        "outbounds": members,
        "failover_on_high_rtt": failover_on_high_rtt,
        "rtt_threshold_ms": rtt_threshold_ms if failover_on_high_rtt else 0,
        "uri": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def make_balancer_config(body, tag_override=None):
    uri = (body.get("uri") or "").strip() if isinstance(body, dict) else ""
    has_inline = any(k in body for k in ("mode", "outbounds", "members", "targets", "failover_on_high_rtt", "rtt_threshold_ms", "high_rtt_ms", "max_rtt_ms")) if isinstance(body, dict) else False
    if uri and not has_inline:
        return parse_balancer_config(uri, tag_override=tag_override)
    if not isinstance(body, dict):
        raise ValueError("balancer config body must be an object")
    mode = _normalize_balancer_mode(body.get("mode"))
    members = _balancer_member_list(body.get("outbounds") or body.get("members") or body.get("targets"))
    if not members:
        raise ValueError("balancer must include at least one outbound")
    tag = _valid_tag(body.get("tag") or tag_override or "balancer")
    failover_on_high_rtt = _boolish(body.get("failover_on_high_rtt"))
    rtt_threshold_ms = _first_positive_int(body.get("rtt_threshold_ms"), body.get("high_rtt_ms"), body.get("max_rtt_ms"))
    failover_on_high_rtt = bool(failover_on_high_rtt and rtt_threshold_ms > 0)
    payload = _balancer_uri_payload(mode, members, failover_on_high_rtt, rtt_threshold_ms)
    return {
        "type": "balancer",
        "kind": "balancer",
        "tag": tag,
        "mode": mode,
        "outbounds": members,
        "failover_on_high_rtt": failover_on_high_rtt,
        "rtt_threshold_ms": rtt_threshold_ms if failover_on_high_rtt else 0,
        "uri": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def make_outbound_uri(ob):
    t = ob.get("type") or ob.get("kind") or ""
    if t == "direct":
        return "direct://"
    if t == "balancer":
        if ob.get("uri"):
            return ob["uri"]
        cfg = make_balancer_config(ob, tag_override=ob.get("tag") or "balancer")
        return cfg["uri"]
    if t == "tamizdat" and ob.get("uri"):
        return ob["uri"]
    if t == "tamizdat":
        host = ob.get("server", "")
        port = int(ob.get("server_port") or 443)
        sni = ob.get("server_name") or ob.get("sni") or host
        pub = ob.get("public_key", "")
        sid = ob.get("short_id") or ob.get("shortid") or ""
        fp = ob.get("fingerprint") or "mix"
        bootstrap = (ob.get("bootstrap_sni") or "").strip()
        tag = quote(ob.get("tag", ""), safe="")
        base = f"tamizdat://{host}:{port}/?sni={quote(sni, safe='')}&pubkey={pub}&shortid={sid}&fp={quote(fp, safe='')}"
        if bootstrap:
            base += f"&bootstrap={quote(bootstrap, safe='')}"
        return base + f"#{tag}"
    return ""


def _row_to_outbound(row):
    tag = row["tag"]
    kind = row["kind"]
    bind_iface = ""
    try:
        bind_iface = row["bind_iface"] or ""
    except (IndexError, KeyError):
        pass
    # Per-outbound byte accounting (2026-05-12). load_config() COALESCEs
    # the bytes_* columns to 0, so reads always succeed even on older DBs
    # mid-migration. We surface them as dl (download = target→server) and
    # ul (upload = server→target) for parity with the user-side fields.
    bytes_up = 0
    bytes_down = 0
    h2_peak = 0
    h2_peak_tcp = 0
    h2_peak_udp = 0
    h2_peak_at = 0
    try:
        bytes_up = int(row["bytes_up"] or 0)
        bytes_down = int(row["bytes_down"] or 0)
    except (IndexError, KeyError, TypeError, ValueError):
        pass
    try:
        h2_peak = int(row["h2_peak_streams"] or 0)
        h2_peak_tcp = int(row["h2_peak_tcp_streams"] or 0)
        h2_peak_udp = int(row["h2_peak_udp_streams"] or 0)
        h2_peak_at = int(row["h2_peak_at"] or 0)
    except (IndexError, KeyError, TypeError, ValueError):
        pass
    relay_metrics = {
        "h2_peak_streams": h2_peak,
        "h2_peak_tcp_streams": h2_peak_tcp,
        "h2_peak_udp_streams": h2_peak_udp,
        "h2_peak_at": h2_peak_at,
        "h2_live_streams": 0,
        "h2_live_tcp_streams": 0,
        "h2_live_udp_streams": 0,
        "h2_dial_failed_tcp_streams": 0,
        "h2_dial_failed_udp_streams": 0,
        "h2_dial_failed_at": 0,
        "h2_dial_failed_network": "",
        "h2_dial_failed_error": "",
    }
    if kind == "direct":
        return {
            "type": "direct", "kind": "direct", "tag": "direct",
            "server": "", "server_port": 0, "uri": "direct://",
            "note": row["note"] or "", "bind_iface": bind_iface,
            "dl": bytes_down, "ul": bytes_up,
            **relay_metrics,
        }
    if kind == "balancer":
        item = {
            "type": "balancer", "kind": "balancer", "tag": tag,
            "server": "balancer", "server_port": 0,
            "uri": row["uri"] or "", "note": row["note"] or "",
            "bind_iface": bind_iface,
            "dl": bytes_down, "ul": bytes_up,
            **relay_metrics,
        }
        if row["uri"]:
            try:
                parsed = parse_balancer_config(row["uri"], tag_override=tag)
                item.update(parsed)
                item["note"] = row["note"] or ""
                item["dl"] = bytes_down
                item["ul"] = bytes_up
            except Exception as e:
                item["parse_error"] = str(e)
        return item
    item = {
        "type": kind, "kind": kind, "tag": tag,
        "uri": row["uri"] or "", "note": row["note"] or "",
        "bind_iface": bind_iface,
        "dl": bytes_down, "ul": bytes_up,
        **relay_metrics,
    }
    if kind == "tamizdat" and row["uri"]:
        try:
            parsed = parse_tamizdat_uri(row["uri"], tag_override=tag)
            item.update(parsed)
            item["note"] = row["note"] or ""
            # parse_tamizdat_uri may overwrite dl/ul with stale values;
            # restore the freshly-fetched DB counters as the authority.
            item["dl"] = bytes_down
            item["ul"] = bytes_up
        except Exception as e:
            item["parse_error"] = str(e)
    return item


def load_config():
    ensure_db()
    with db_conn() as con:
        rows = con.execute(
            "SELECT tag, kind, uri, note, bind_iface, "
            "COALESCE(bytes_up, 0) AS bytes_up, "
            "COALESCE(bytes_down, 0) AS bytes_down, "
            "COALESCE(h2_peak_streams, 0) AS h2_peak_streams, "
            "COALESCE(h2_peak_tcp_streams, 0) AS h2_peak_tcp_streams, "
            "COALESCE(h2_peak_udp_streams, 0) AS h2_peak_udp_streams, "
            "COALESCE(h2_peak_at, 0) AS h2_peak_at, "
            "created_at, updated_at "
            "FROM outbounds ORDER BY tag='direct' DESC, tag"
        ).fetchall()
        default_tag = _setting(con, "default_outbound_tag", "direct") or "direct"
        inbounds_json = _setting(con, "panel_inbounds_json", "[]")
        rules_json = _setting(con, "panel_route_rules_json", "[]")
    try:
        inbounds = json.loads(inbounds_json)
    except Exception:
        inbounds = []
    try:
        rules = json.loads(rules_json)
    except Exception:
        rules = []
    outbounds = _merge_live_outbound_counts([_row_to_outbound(r) for r in rows], _live_outbounds_from_expvar())
    return {"outbounds": outbounds, "route": {"final": default_tag, "rules": rules}, "inbounds": inbounds}


def save_config(config):
    ensure_db()
    now = int(time.time())
    outbounds = config.get("outbounds", [])
    default_tag = (config.get("route", {}) or {}).get("final", "direct") or "direct"
    keep_tags = {"direct"}
    with db_conn() as con:
        for ob in outbounds:
            tag = _valid_tag(ob.get("tag") or ("direct" if (ob.get("type") or ob.get("kind")) == "direct" else ""))
            kind = (ob.get("kind") or ob.get("type") or "").strip().lower()
            if tag == "direct" or kind == "direct":
                keep_tags.add("direct")
                con.execute("INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES('direct', 'direct', NULL, 'Direct dial from server IP', ?, ?)", (now, now))
                continue
            if kind == "balancer":
                parsed = make_balancer_config(ob, tag_override=tag)
                keep_tags.add(tag)
                existing = con.execute("SELECT created_at FROM outbounds WHERE tag=?", (tag,)).fetchone()
                created_at = existing["created_at"] if existing else now
                con.execute("INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?) "
                            "ON CONFLICT(tag) DO UPDATE SET kind=excluded.kind, uri=excluded.uri, note=excluded.note, updated_at=excluded.updated_at",
                            (tag, "balancer", parsed["uri"], ob.get("note", ""), created_at, now))
                continue
            if kind != "tamizdat":
                continue
            parsed = parse_tamizdat_uri(ob.get("uri") or make_outbound_uri(ob), tag_override=tag)
            keep_tags.add(tag)
            existing = con.execute("SELECT created_at FROM outbounds WHERE tag=?", (tag,)).fetchone()
            created_at = existing["created_at"] if existing else now
            con.execute("INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(tag) DO UPDATE SET kind=excluded.kind, uri=excluded.uri, note=excluded.note, updated_at=excluded.updated_at",
                        (tag, "tamizdat", parsed["uri"], ob.get("note", ""), created_at, now))
        for row in con.execute("SELECT tag FROM outbounds WHERE tag <> 'direct'").fetchall():
            if row["tag"] not in keep_tags:
                con.execute("DELETE FROM outbounds WHERE tag=?", (row["tag"],))
        if not con.execute("SELECT 1 FROM outbounds WHERE tag=?", (default_tag,)).fetchone():
            default_tag = "direct"
        _set_setting(con, "default_outbound_tag", default_tag)
        _set_setting(con, "panel_inbounds_json", json.dumps(config.get("inbounds", []), ensure_ascii=False))
        _set_setting(con, "panel_route_rules_json", json.dumps((config.get("route", {}) or {}).get("rules", []), ensure_ascii=False))
    _sighup_server()


def _sighup_server():
    try:
        if SERVER_PIDFILE and os.path.exists(SERVER_PIDFILE):
            with open(SERVER_PIDFILE, "r", encoding="utf-8") as f:
                pid_s = f.read().strip()
            if pid_s:
                os.kill(int(pid_s), signal.SIGHUP)
                return
    except Exception as e:
        print(f"pidfile SIGHUP warning: {e}")
    try:
        # 2026-05-13: must use `-f` (match full cmdline) not `-x` (match exe
        # name only). Linux's TASK_COMM_LEN caps the kernel-visible name at
        # 15 chars; `tamizdat-server-app` is 19, so `pkill -x` silently
        # matches zero processes — the operator saves a routing rule in the
        # panel UI, the panel "successfully" sends SIGHUP, the server never
        # actually reloads, and the rule looks ignored. -f matches against
        # /proc/<pid>/cmdline which has no length cap.
        subprocess.run(["pkill", "-HUP", "-f", SERVER_BIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception as e:
        print(f"pkill SIGHUP warning: {e}")


def _set_outbound_bind_iface(tag, bind_iface):
    """Update outbounds.bind_iface for tag. None or empty clears it.
    No-op if the column doesn't exist (defensive against partial migrate)."""
    ensure_db()
    with db_conn() as con:
        cols = {r["name"] for r in con.execute("PRAGMA table_info(outbounds)").fetchall()}
        if "bind_iface" not in cols:
            return
        v = bind_iface if bind_iface else None
        con.execute("UPDATE outbounds SET bind_iface=?, updated_at=? WHERE tag=?", (v, int(time.time()), tag))


def upsert_outbound_with_iface(body, old_tag=None):
    """Wrap upsert_outbound: persist bind_iface alongside the regular
    outbound write. The plain upsert_outbound does not know about the
    bind_iface column (kept narrow on purpose); this wrapper writes it
    after the main row is committed.
    """
    res = upsert_outbound(body, old_tag=old_tag)
    bi = (body.get("bind_iface") or "").strip()
    tag = (body.get("tag") or "direct" if (body.get("kind") or body.get("type")) == "direct" else (res or {}).get("tag")) if isinstance(res, dict) else None
    # Most reliable: re-derive tag the same way upsert_outbound does.
    kind_in = (body.get("kind") or body.get("type") or "tamizdat").strip().lower()
    if kind_in == "direct" or body.get("tag") == "direct":
        tag = "direct"
    elif isinstance(res, dict) and res.get("tag"):
        tag = res["tag"]
    if tag:
        _set_outbound_bind_iface(tag, bi or None)
    return res


def upsert_outbound(body, old_tag=None):
    ensure_db()
    kind = (body.get("kind") or body.get("type") or "tamizdat").strip().lower()
    bind_iface_val = (body.get("bind_iface") or "").strip() or None
    if kind == "direct" or body.get("tag") == "direct":
        tag = "direct"
        uri = None
        note = body.get("note", "Direct dial from server IP")
        kind = "direct"
    elif kind == "blackhole":
        # Blackhole outbound: drops all traffic. No URI required, just a tag
        # the operator picks (e.g. 'block', 'ads-sink', 'win-telemetry-sink').
        tag = _valid_tag(body.get("tag") or "block")
        uri = None
        note = body.get("note", "Blackhole — drops every connection")
    elif kind == "balancer":
        parsed = make_balancer_config(body, tag_override=body.get("tag") or old_tag)
        tag = parsed["tag"]
        uri = parsed["uri"]
        note = body.get("note", "")
        kind = "balancer"
    else:
        uri = (body.get("uri") or "").strip()
        if not uri:
            # Backward-compatible edit form payload.
            host = (body.get("server") or "").strip()
            port = int(body.get("server_port") or 443)
            pub = (body.get("auth") or body.get("public_key") or "").strip()
            sid = (body.get("short_id") or body.get("shortid") or "").strip()
            sni = (body.get("sni") or body.get("server_name") or host).strip()
            fp = (body.get("fingerprint") or "mix").strip()
            bootstrap = (body.get("bootstrap_sni") or "").strip()
            uri = f"tamizdat://{host}:{port}/?sni={quote(sni, safe='')}&pubkey={pub}&shortid={sid}&fp={quote(fp, safe='')}"
            if bootstrap:
                uri += f"&bootstrap={quote(bootstrap, safe='')}"
        parsed = parse_tamizdat_uri(uri, tag_override=body.get("tag") or old_tag)
        tag = parsed["tag"]
        note = body.get("note", "")
        kind = "tamizdat"
    if old_tag:
        old_tag = _valid_tag(old_tag)
        if old_tag == "direct" and tag != "direct":
            raise ValueError("cannot rename direct")
        if old_tag == "block" and tag != "block":
            raise ValueError("cannot rename block (built-in blackhole)")
    now = int(time.time())
    with db_conn() as con:
        if kind == "balancer":
            cfg = json.loads(uri or "{}")
            for member_tag in cfg.get("outbounds", []):
                if member_tag == tag:
                    raise ValueError("balancer cannot reference itself")
                if not con.execute("SELECT 1 FROM outbounds WHERE tag=?", (member_tag,)).fetchone():
                    raise ValueError(f"balancer member {member_tag!r} does not exist")
        if old_tag and old_tag != tag:
            if con.execute("SELECT 1 FROM outbounds WHERE tag=?", (tag,)).fetchone():
                raise ValueError("Tag taken")
            row = con.execute("SELECT created_at FROM outbounds WHERE tag=?", (old_tag,)).fetchone()
            if not row:
                raise ValueError("Not found")
            con.execute("DELETE FROM outbounds WHERE tag=?", (old_tag,))
            con.execute("INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)", (tag, kind, uri, note, row["created_at"], now))
            con.execute("UPDATE settings SET value=? WHERE key='default_outbound_tag' AND value=?", (tag, old_tag))
        else:
            existing = con.execute("SELECT created_at FROM outbounds WHERE tag=?", (tag,)).fetchone()
            if old_tag and not existing:
                raise ValueError("Not found")
            created_at = existing["created_at"] if existing else now
            con.execute("INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(tag) DO UPDATE SET kind=excluded.kind, uri=excluded.uri, note=excluded.note, updated_at=excluded.updated_at",
                        (tag, kind, uri, note, created_at, now))
    _sighup_server()
    return {"ok": True, "tag": tag}


def delete_outbound(tag):
    tag = _valid_tag(tag)
    if tag == "direct":
        raise ValueError("Cannot delete direct outbound")
    if tag == "block":
        # Protected like 'direct': auto-recreated by ensure_db on every boot
        # and is the only kind=blackhole outbound the panel ships out of the
        # box. Operators can still create additional blackhole tags (e.g.
        # 'ads-sink', 'win-telemetry') via Add outbound → kind=blackhole.
        raise ValueError("Cannot delete the default 'block' outbound (it is the built-in blackhole sink)")
    ensure_db()
    with db_conn() as con:
        active = _setting(con, "default_outbound_tag", "direct")
        if active == tag:
            raise ValueError("Cannot delete active outbound")
        cur = con.execute("DELETE FROM outbounds WHERE tag=?", (tag,))
        if cur.rowcount == 0:
            raise ValueError("not found")
    _sighup_server()
    return {"ok": True}


def set_active_outbound(config_or_tag, tag=None):
    if tag is None:
        tag = config_or_tag
        cfg = None
    else:
        cfg = config_or_tag
    tag = _valid_tag(tag)
    ensure_db()
    with db_conn() as con:
        if not con.execute("SELECT 1 FROM outbounds WHERE tag=?", (tag,)).fetchone():
            raise ValueError("Outbound not found")
        _set_setting(con, "default_outbound_tag", tag)
    if isinstance(cfg, dict):
        cfg.setdefault("route", {})["final"] = tag
    _sighup_server()
    return {"ok": True, "active": tag}


def get_outbounds(config):
    return config.get("outbounds", [])


def get_active_outbound(config):
    return config.get("route", {}).get("final", "direct")


def outbound_api_entry(o, user_count=0):
    """Return the JSON shape used by GET /api/outbounds.

    Keep this as the single frontend-facing projection so fields parsed from
    stored balancer JSON (mode/outbounds/high-RTT settings) are not silently
    dropped by the route handler after load_config() already surfaced them.
    """
    tag = o.get("tag", "")
    entry = {"tag": tag, "type": o.get("type", ""),
             "server": o.get("server", ""), "server_port": o.get("server_port", 0),
             "password": o.get("password", ""),
             "user_count": int(user_count or 0),
             "dl": int(o.get("dl") or 0), "ul": int(o.get("ul") or 0),
             "h2_peak_streams": int(o.get("h2_peak_streams") or 0),
             "h2_peak_tcp_streams": int(o.get("h2_peak_tcp_streams") or 0),
             "h2_peak_udp_streams": int(o.get("h2_peak_udp_streams") or 0),
             "h2_peak_at": int(o.get("h2_peak_at") or 0),
             "h2_live_streams": int(o.get("h2_live_streams") or 0),
             "h2_live_tcp_streams": int(o.get("h2_live_tcp_streams") or 0),
             "h2_live_udp_streams": int(o.get("h2_live_udp_streams") or 0),
             "h2_dial_failed_tcp_streams": int(o.get("h2_dial_failed_tcp_streams") or 0),
             "h2_dial_failed_udp_streams": int(o.get("h2_dial_failed_udp_streams") or 0),
             "h2_dial_failed_at": int(o.get("h2_dial_failed_at") or 0),
             "h2_dial_failed_network": o.get("h2_dial_failed_network") or "",
             "h2_dial_failed_error": o.get("h2_dial_failed_error") or ""}
    if o.get("tls"):
        entry["tls"] = o["tls"]
    if o.get("uuid"):
        entry["uuid"] = o["uuid"]
    if o.get("auth_str"):
        entry["auth_str"] = o["auth_str"]
    if o.get("public_key"):
        entry["public_key"] = o["public_key"]
    if o.get("short_id"):
        entry["short_id"] = o["short_id"]
    if o.get("server_name"):
        entry["server_name"] = o["server_name"]
    if o.get("mode"):
        entry["mode"] = o["mode"]
    if o.get("outbounds"):
        entry["outbounds"] = o["outbounds"]
    entry["failover_on_high_rtt"] = bool(o.get("failover_on_high_rtt"))
    entry["rtt_threshold_ms"] = int(o.get("rtt_threshold_ms") or 0)
    entry["uri"] = make_outbound_uri(o)
    return entry


def get_users(config):
    return []


def set_users(config, users):
    return None


def set_user_outbound(config, name, tag):
    return None


def rename_user_in_rules(config, old, new):
    return None


def remove_outbound_from_rules(config, tag):
    return None


def count_users_per_outbound(config):
    return {}


def make_uri(password, outbound=None):
    if outbound == "direct":
        label = "Обход белых списков"
    elif outbound:
        label = "Обход блокировок"
    else:
        label = f"tamizdat-{SERVER_PORT}"
    return ""


def _probe_tls_ms(host, port, sni=None, timeout=5):
    """TCP connect + TLS handshake + close. Returns wall-clock ms or -1."""
    import socket, ssl as _ssl, time as _time
    if not host:
        return -1
    t0 = _time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return -1
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        wrapped = ctx.wrap_socket(sock, server_hostname=sni or host)
        try:
            _ = wrapped.version()
        finally:
            try: wrapped.close()
            except Exception: pass
    except Exception:
        try: sock.close()
        except Exception: pass
        return -1
    return int((_time.time() - t0) * 1000)


def _parse_test_target(target):
    """Resolve panel_test_target into (scheme, host, port, path) for probing.

    Accepts both forms:
      - URL:   http://www.gstatic.com/generate_204  → ("http",  host, 80, path)
               https://example.com:8443/healthz     → ("https", host, 8443, path)
      - Legacy host:port:  www.gstatic.com:443      → ("tls",   host, 443, "/")
      - Bare host (no port, no scheme): example.com → ("tls",   host, 443, "/")

    Returns (scheme, host, port, path) or (None, None, None, None) on parse
    failure. scheme="tls" means raw TLS handshake (no HTTP); "http"/"https"
    means HTTP GET probe.
    """
    from urllib.parse import urlparse
    if not target:
        return (None, None, None, None)
    target = target.strip()
    if "://" in target:
        u = urlparse(target)
        scheme = (u.scheme or "").lower()
        host = (u.hostname or "").strip("[]")
        port = u.port or (443 if scheme == "https" else 80 if scheme == "http" else 443)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        if not host:
            return (None, None, None, None)
        return (scheme, host, port, path)
    # No scheme: legacy host:port or bare host
    if ":" in target:
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            host, port = target, 443
    else:
        host, port = target, 443
    host = host.strip("[]")
    return ("tls", host, port, "/")


def _probe_http_ms(scheme, host, port, path, timeout=5):
    """HTTP/HTTPS GET probe. Returns ms on 2xx/3xx, -1 otherwise."""
    import socket, ssl as _ssl, time as _time
    if not host:
        return -1
    t0 = _time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return -1
    try:
        if scheme == "https":
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "User-Agent: tamizdat-panel-probe/1\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n\r\n"
        ).encode("ascii", errors="replace")
        sock.sendall(req)
        sock.settimeout(timeout)
        head = b""
        # Read up to the end of the status line (\r\n) — sufficient for status code.
        while b"\r\n" not in head and len(head) < 1024:
            chunk = sock.recv(256)
            if not chunk:
                break
            head += chunk
        status_line = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        # "HTTP/1.1 204 No Content" → parts[1] = "204"
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return -1
        code = int(parts[1])
        if 200 <= code < 400:
            return int((_time.time() - t0) * 1000)
        return -1
    except Exception:
        return -1
    finally:
        try: sock.close()
        except Exception: pass


def test_outbound_delay(tag):
    """Probe an outbound's reachability + handshake/HTTP-GET time, in ms.

    direct      → dial settings.panel_test_target. URL form probes via
                  HTTP/HTTPS GET (success = 2xx/3xx); legacy host:port
                  form probes via raw TLS handshake. Operator can compare
                  bare-server latency against the proxied paths.
    tamizdat    → dial the upstream proxy host:port from the URI. Measures
                  reachability + upstream's TLS handshake time, NOT a full
                  end-to-end path through the tunnel.
    other kinds → 0 (n/a).
    Failure modes (DNS, refused, timeout, TLS error, non-success HTTP) → -1.
    """
    if tag == "direct":
        with db_conn() as con:
            target = _setting(con, "panel_test_target", "http://www.gstatic.com/generate_204")
        scheme, host, port, path = _parse_test_target(target)
        if not host:
            return -1
        if scheme in ("http", "https"):
            return _probe_http_ms(scheme, host, port, path, timeout=5)
        # Raw TLS handshake fallback (legacy host:port or scheme-less).
        return _probe_tls_ms(host, port, sni=host, timeout=5)
    try:
        with db_conn() as con:
            row = con.execute("SELECT kind, uri FROM outbounds WHERE tag=?", (tag,)).fetchone()
        if not row:
            return -1
        kind = row["kind"]
        uri = row["uri"] or ""
        if kind != "tamizdat" or not uri:
            return 0
        parsed = parse_tamizdat_uri(uri, tag_override=tag)
        host = parsed.get("server") or ""
        port = int(parsed.get("server_port") or 443)
        sni = parsed.get("sni") or host
        return _probe_tls_ms(host, port, sni=sni, timeout=5)
    except Exception:
        return -1


# --- HTML Templates ---

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Sign in · Tamizdat Panel</title>
<style>
:root{
  --bg:#F5F7FA;--surface:#FFFFFF;--border:#E5E7EB;--text:#1F2937;--text-2:#4B5563;--muted:#9CA3AF;
  --primary:#4F46E5;--primary-hover:#3F37C9;--primary-soft:#EEEDFB;--primary-soft-2:#DCDAF7;
  --danger:#E11D48;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",PingFangSC,"Helvetica Neue",Arial,sans-serif;font-size:14px;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px;
  background-image:radial-gradient(circle at 20% 0%,rgba(0,135,113,.06),transparent 50%),radial-gradient(circle at 80% 100%,rgba(0,135,113,.05),transparent 45%);
}
.box{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:32px;width:100%;max-width:380px;box-shadow:0 12px 32px rgba(16,24,40,.06),0 1px 2px rgba(16,24,40,.04)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.brand-mark{width:42px;height:42px;border-radius:12px;background:var(--primary);color:#fff;display:grid;place-items:center;font-weight:700;font-size:18px;letter-spacing:.5px}
.brand-name{font-weight:600;font-size:17px}
.brand-name span{color:var(--muted);font-weight:500;font-size:11px;display:block;margin-top:2px;text-transform:uppercase;letter-spacing:.5px}
h2{font-size:18px;font-weight:600;margin-bottom:4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
label{display:block;color:var(--text-2);font-size:12.5px;font-weight:500;margin:14px 0 6px}
input{width:100%;padding:11px 14px;background:var(--surface);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;font-family:inherit;transition:.15s}
input::placeholder{color:var(--muted)}
input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
button{width:100%;margin-top:20px;padding:11px 16px;background:var(--primary);color:#fff;border:none;border-radius:999px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;transition:.15s;display:inline-flex;align-items:center;justify-content:center;gap:8px}
button:hover{background:var(--primary-hover)}
button svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2}
.err{color:var(--danger);font-size:12.5px;margin-top:14px;min-height:1em;text-align:center}
.foot{text-align:center;color:var(--muted);font-size:11.5px;margin-top:18px}
</style>
</head>
<body>
<div class="box">
  <div class="brand">
    <div class="brand-mark">T</div>
    <div class="brand-name">Tamizdat<span>Panel</span></div>
  </div>
  <h2>Sign in</h2>
  <div class="sub">Enter your credentials to access the panel.</div>
  <form method="POST" action="LOGIN_ACTION">
    <label>Username</label><input type="text" name="username" autofocus autocomplete="username" placeholder="admin">
    <label>Password</label><input type="password" name="password" autocomplete="current-password" placeholder="••••••••">
    <button type="submit">
      Sign in
      <svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
    <div class="err">ERROR_MSG</div>
  </form>
  <div class="foot">Tamizdat · proxy server panel</div>
</div>
</body>
</html>"""

PANEL_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Tamizdat Panel</title>
<style>
/* ---------- 3x-ui inspired light theme ---------- */
:root{
  --bg:#F5F7FA;
  --surface:#FFFFFF;
  --surface-2:#F8FAFB;
  --border:#E5E7EB;
  --border-strong:#D1D5DB;
  --text:#1F2937;
  --text-2:#4B5563;
  --muted:#9CA3AF;
  --primary:#4F46E5;
  --primary-hover:#3F37C9;
  --primary-soft:#EEEDFB;
  --primary-soft-2:#DCDAF7;
  --danger:#E11D48;
  --danger-soft:#FEE2E7;
  --warn:#D97706;
  --warn-soft:#FEF3E2;
  --info:#2563EB;
  --info-soft:#E0EAFE;
  --purple:#7C3AED;
  --purple-soft:#EDE9FE;
  --shadow-sm:0 1px 2px rgba(16,24,40,.04);
  --shadow:0 1px 3px rgba(16,24,40,.06),0 1px 2px rgba(16,24,40,.04);
  /* 2026 accent palette — Future Dusk periwinkle + Apricot Crush + Honey + Mauve.
     Primary buttons stay green; these tokens drive selection, badges and stat icons. */
  --dusk:#5B5BD6;
  --dusk-soft:#EEEDFB;
  --dusk-soft-2:#DCDAF7;
  --coral:#E76F51;
  --coral-soft:#FBE7E0;
  --honey:#C58B2E;
  --honey-soft:#FBEFD6;
  --mauve:#9D5CC9;
  --mauve-soft:#F2E9FA;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",PingFangSC,"Helvetica Neue",Arial,sans-serif;font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased}

/* ---- App shell ---- */
.app{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:20px 14px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;padding:6px 10px 18px}
.brand-mark{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--primary) 0%,var(--dusk) 100%);color:#fff;display:grid;place-items:center;font-weight:700;font-size:15px;letter-spacing:.5px}
.brand-name{font-weight:600;font-size:16px;color:var(--text);letter-spacing:.2px}
.brand-name span{color:var(--muted);font-weight:500;font-size:11px;display:block;margin-top:1px;letter-spacing:.4px;text-transform:uppercase}
.nav{display:flex;flex-direction:column;gap:2px;margin-top:6px;flex:1}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--text-2);text-decoration:none;font-size:14px;font-weight:500;cursor:pointer;transition:.12s}
.nav a:hover{background:var(--surface-2);color:var(--text)}
.nav a.active{background:var(--dusk-soft);color:var(--dusk)}
.nav a.active svg{stroke:var(--dusk)}
.nav svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.8;flex-shrink:0}
.nav-spacer{flex:1}
.nav-foot{border-top:1px solid #ececf2;padding:12px;margin-top:auto}
.user-chip{display:flex;align-items:center;gap:10px;padding:6px;border-radius:10px}
.user-avatar{width:34px;height:34px;flex-shrink:0;border-radius:50%;background:#ece9ff;color:#4a3fd1;display:grid;place-items:center;font-weight:700;font-size:13px;text-transform:uppercase}
.user-name{flex:1;min-width:0;font-weight:600;font-size:14px;color:#1e1b4b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.logout-btn{width:32px;height:32px;flex-shrink:0;border-radius:8px;display:grid;place-items:center;color:#8a8aa3;text-decoration:none;transition:background .12s, color .12s}
.logout-btn:hover{background:#fdecec;color:#d64545}

.main{padding:24px 28px 60px;overflow-x:hidden;max-width:100%}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap}
.page-title{font-size:22px;font-weight:600;color:var(--text);letter-spacing:-.2px}
.page-sub{font-size:13px;color:var(--muted);margin-top:2px}

/* ---- Stat cards row ---- */
.stat-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}
/* Resource-ring widget: CPU / RAM / Swap / Disk, SVG ring per metric.
   Ring uses a viewBox-26 unit circle (circumference 2π·15.9155 ≈ 100)
   so stroke-dasharray="pct,100" maps directly to the percentage. */
.res-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 14px}
.res-card{display:flex;flex-direction:column;align-items:center;gap:8px}
.res-ring{width:130px;height:130px;display:block}
.res-bg{fill:none;stroke:var(--border);stroke-width:2.6}
.res-fg{fill:none;stroke:#22a06b;stroke-width:2.6;stroke-linecap:round;transform:rotate(-90deg);transform-origin:18px 18px;transition:stroke-dasharray .6s ease, stroke .3s ease}
.res-fg.warn{stroke:#e2a72f}
.res-fg.crit{stroke:#d54855}
.res-pct{font-family:ui-monospace,monospace;font-size:6.5px;text-anchor:middle;dominant-baseline:middle;fill:var(--text)}
.res-label{font-size:12.5px;color:var(--muted);text-align:center}
@media (max-width:900px){
  .res-row{grid-template-columns:repeat(2,1fr)}
}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px;display:flex;align-items:center;gap:14px;box-shadow:var(--shadow-sm)}
.stat-icon{width:42px;height:42px;border-radius:12px;background:var(--primary-soft);color:var(--primary);display:grid;place-items:center;flex-shrink:0}
.stat-icon svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.8}
.stat-label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;font-weight:500;margin-bottom:3px}
.stat-value{font-size:18px;font-weight:600;color:var(--text);display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}
.stat-value small{font-size:12px;color:var(--muted);font-weight:500}
.stat.green .stat-icon{background:var(--primary-soft);color:var(--primary)}
.stat.blue .stat-icon{background:var(--dusk-soft);color:var(--dusk)}
.stat.purple .stat-icon{background:var(--mauve-soft);color:var(--mauve)}
.stat.orange .stat-icon{background:var(--coral-soft);color:var(--coral)}
.stat .stat-body{flex:1;min-width:0}
.stat-svc-btn{margin-left:auto;flex-shrink:0}

/* ---- Cards / sections ---- */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow-sm);margin-bottom:16px;overflow:hidden}
.card-pad{padding:16px 18px}
.card-head{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.card-title{font-size:15px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:10px}
.card-title-meta{font-size:12px;color:var(--muted);font-weight:500}
.card-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.quota-input-row{display:flex;gap:8px;align-items:stretch}
.quota-input-row input{flex:1;min-width:0}
.quota-input-row select{flex:0 0 auto;min-width:74px;width:auto}
@media (max-width:640px){
  /* Mobile: stack the card head so action buttons get full width and
     don't clip off the right edge (operator screenshot 2026-05-10). */
  .card-head{flex-wrap:wrap;gap:12px}
  .card-head .card-actions{width:100%;justify-content:stretch}
  .card-head .card-actions .btn{flex:1;justify-content:center}
}
.section-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:14px 4px 10px;display:flex;align-items:center;gap:10px}
.section-title .count{background:var(--dusk-soft);color:var(--dusk);padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}

/* ---- Service status bar ---- */
.svc-bar{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px 18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;box-shadow:var(--shadow-sm);margin-bottom:18px}
.svc-bar .svc-label{font-weight:600;color:var(--text);font-size:14px;display:flex;align-items:center;gap:10px}
.svc-bar .svc-dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.svc-bar.svc-ok .svc-dot{background:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
.svc-bar.svc-down .svc-dot{background:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}
.svc-status{font-weight:600;font-size:13.5px}
.svc-active{color:var(--primary)}
.svc-inactive{color:var(--danger)}
.svc-loading{color:var(--muted)}
.svc-uptime{color:var(--muted);font-size:13px}
.svc-bar .right{margin-left:auto;display:flex;gap:8px;align-items:center}

/* ---- Buttons ---- */
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid transparent;border-radius:999px;padding:8px 16px;font-size:13px;font-weight:600;cursor:pointer;transition:.15s;font-family:inherit;line-height:1;white-space:nowrap}
.btn:focus{outline:2px solid var(--primary-soft-2);outline-offset:1px}
.btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2}
.btn-primary{background:var(--primary);color:#fff;border-color:var(--primary)}
.btn-primary:hover{background:var(--primary-hover);border-color:var(--primary-hover)}
.btn-ghost{background:var(--surface);color:var(--text-2);border-color:var(--border)}
.btn-ghost:hover{background:var(--surface-2);color:var(--text);border-color:var(--border-strong)}
.btn-danger{background:#fff;color:var(--danger);border-color:#fbcfd8}
.btn-danger:hover{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-danger.solid{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-danger.solid:hover{background:#be123c;border-color:#be123c}
.btn-sm{padding:5px 12px;font-size:12px;border-radius:999px;font-weight:600}
.btn-sm svg{width:12px;height:12px}
.btn-icon{width:34px;height:34px;border-radius:10px;padding:0;display:inline-grid;place-items:center;background:var(--surface);color:var(--text-2);border:1px solid var(--border)}
.btn-icon:hover{background:var(--surface-2);color:var(--primary);border-color:var(--border-strong)}
.btn-icon svg{width:16px;height:16px}
/* Small inline icon button used next to the Traffic ↓↑ counters for the
   quota-reset-split 🔄 hard-zero affordance. Subtle by design (matches
   .cell-meta visual weight); the loud "Reset Quota" pill stays in the
   Limits column. */
.btn-icon-sm{width:24px;height:24px;border-radius:6px;padding:0;font-size:13px;line-height:1;display:inline-grid;place-items:center;background:transparent;color:var(--text-2);border:0;opacity:.6;cursor:pointer;vertical-align:middle;margin-left:6px;transition:opacity .15s,color .15s}
.btn-icon-sm:hover{opacity:1;color:var(--primary)}
th .btn-icon-sm{margin-left:2px;width:18px;height:18px;font-size:14px}

/* Tag-coloured action buttons in user/outbound rows */
.btn-edit{background:#fff;color:var(--warn);border:1px solid #fcd9b6}
.btn-edit:hover{background:var(--warn);color:#fff;border-color:var(--warn)}
.btn-qr{background:#fff;color:var(--primary);border:1px solid var(--primary-soft-2)}
.btn-qr:hover{background:var(--primary);color:#fff;border-color:var(--primary)}
.btn-copy{background:#fff;color:var(--primary);border:1px solid var(--primary-soft-2)}
.btn-copy:hover{background:var(--primary);color:#fff;border-color:var(--primary)}
.btn-del{background:#fff;color:var(--danger);border:1px solid #fbcfd8}
.btn-del:hover{background:var(--danger);color:#fff;border-color:var(--danger)}
/* .btn-activate removed in panel-cleanup CL-2 — "Set default" button gone. */
.btn-reset{background:var(--purple-soft);color:var(--purple);border:1px solid #ddd1fa;padding:2px 8px;font-size:11px}
.btn-reset:hover{background:var(--purple);color:#fff;border-color:var(--purple)}
.btn-svc{padding:7px 14px;font-size:13px}
.btn-start{background:var(--primary);color:#fff;border-color:var(--primary)}
.btn-start:hover{background:var(--primary-hover);border-color:var(--primary-hover)}
.btn-stop{background:#fff;color:var(--danger);border-color:#fbcfd8}
.btn-stop:hover{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-gear{width:34px;height:34px;border-radius:10px;padding:0;background:var(--surface);color:var(--text-2);border:1px solid var(--border);display:inline-grid;place-items:center;cursor:pointer;transition:.18s}
.btn-gear:hover{background:var(--primary-soft);color:var(--primary);border-color:var(--primary-soft-2);transform:rotate(45deg)}
.btn-gear svg{width:16px;height:16px}

/* ---- Inputs ---- */
input[type=text],input[type=number],input[type=password],input[type=date],textarea,select{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:9px 12px;color:var(--text);font-size:13.5px;font-family:inherit;transition:.15s;width:100%
}
input::placeholder,textarea::placeholder{color:var(--muted)}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
select{cursor:pointer;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236B7280' stroke-width='2'><polyline points='6 9 12 15 18 9'/></svg>");background-repeat:no-repeat;background-position:right 10px center;padding-right:32px;-webkit-appearance:none;appearance:none}

.form-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.form-row > input,.form-row > select{flex:1;min-width:160px}
.form-row > input.tag-input{max-width:220px}

/* ---- Tables ---- */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 16px;color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;background:var(--surface-2);border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:13px 16px;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text)}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .12s}
tbody tr:hover{background:var(--surface-2)}
.user-name{font-weight:600;color:var(--text);font-size:14px}
.actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}

/* ---- Status / dots ---- */
.status-cell{display:grid;grid-template-columns:64px max-content;align-items:center;column-gap:6px;min-width:104px;min-height:22px;color:var(--text-2)}
.status-dots{display:inline-flex;align-items:center;gap:8px;width:64px;min-width:64px}
.online-dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:middle;background:#C9CEDB}
.online-dot.on{background:#5B5FE4;box-shadow:none}
.online-dot.off{background:#C9CEDB}
.online-dot.expired{background:#F59E0B}
.status-more{font-size:10.5px;font-weight:700;color:#5B5FE4;line-height:1}
.transport-badge{display:inline-flex;align-items:center;justify-content:center;min-width:28px;padding:3px 9px;border-radius:8px;font-size:12px;line-height:1;font-weight:800;letter-spacing:.02em;text-transform:uppercase}
.transport-badge.turn{background:#FFF1D6;color:#F59E0B}
.transport-badge.h2{background:#ECE8FF;color:#5B5FE4}

/* ---- Traffic / badges ---- */
.traf{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;white-space:nowrap;display:inline-flex;gap:8px;align-items:center}
.traf-d{color:var(--dusk)}
.traf-u{color:var(--primary)}
.proto-badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.3px}
.proto-tamizdat{background:var(--info-soft);color:var(--info)}
.proto-vless{background:var(--info-soft);color:var(--info)}
.proto-hysteria2,.proto-hy2{background:var(--purple-soft);color:var(--purple)}
.proto-hysteria{background:var(--purple-soft);color:var(--purple)}
.proto-direct{background:#F1F5F9;color:#475569}
.proto-unknown{background:#F1F5F9;color:#475569}
.proto-freedom{background:#F1F5F9;color:#475569}
.proto-blackhole{background:var(--danger);color:#fff;opacity:.85}
.proto-socks{background:var(--purple-soft);color:var(--purple)}
.active-tag{display:inline-block;background:var(--primary);color:#fff;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;margin-left:8px;letter-spacing:.4px}
.ob-server{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--text-2)}
.ob-users-badge{display:inline-grid;place-items:center;min-width:24px;height:24px;padding:0 7px;border-radius:12px;background:var(--primary-soft);color:var(--primary);font-size:12px;font-weight:700}
.ob-users-badge.zero{background:#F1F5F9;color:var(--muted)}
.ob-latency{font-size:11px;color:var(--muted);margin-left:6px;display:inline-block;min-width:50px}

/* user outbound select inline */
.user-ob-sel{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:5px 28px 5px 10px;color:var(--text);font-size:12.5px;min-width:130px;cursor:pointer;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%236B7280' stroke-width='2'><polyline points='6 9 12 15 18 9'/></svg>");background-repeat:no-repeat;background-position:right 8px center;-webkit-appearance:none;appearance:none}
.user-ob-sel:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
.user-ob-sel.non-default{border-color:var(--warn);color:var(--warn);background-color:var(--warn-soft)}

/* meta sub-rows under limits cell */
.cell-meta{font-size:11.5px;color:var(--muted);margin-top:2px}
.cell-meta.empty{color:var(--border-strong)}
.h2-cell{font-size:12px;line-height:1.35;color:var(--text);white-space:nowrap}
/* "Reset Quota" pill housing inside the Limits column (quota-reset-split,
   2026-05-10). Small top gap so the pill doesn't crowd the quota bar. */
.reset-row{margin-top:6px}

/* quota usage bar (multi-user-cleanup I-4): X used / Y cap with rolling 30-day window */
.quota-bar{height:6px;background:#eef0f4;border-radius:3px;overflow:hidden;margin-top:4px}
.quota-bar .quota-fill{height:100%;background:var(--primary);transition:width .25s}
.quota-bar.warn .quota-fill{background:var(--warn)}
.quota-bar.burned .quota-fill{background:var(--danger);width:100% !important}
.quota-tag.burned{display:inline-block;padding:0 6px;border-radius:8px;background:var(--danger);color:#fff;font-size:10.5px;font-weight:600;margin-left:4px}

/* status placeholder rows */
.status{padding:32px 18px;color:var(--muted);font-size:13.5px;text-align:center}
.status b{color:var(--primary);font-weight:600}

/* helper text */
.help{color:var(--muted);font-size:12.5px;line-height:1.55}
.bal-member-list{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px;max-height:160px;overflow:auto;border:1px solid var(--border);border-radius:10px;padding:8px;background:var(--surface-2)}
.bal-member{display:flex;align-items:center;gap:7px;padding:7px 8px;border-radius:8px;background:var(--surface);font-size:12.5px;color:var(--text-2);cursor:pointer;user-select:none}
.bal-member:hover{background:var(--primary-soft)}
.bal-member input{width:auto;margin:0}
.bal-member .kind{margin-left:auto;color:var(--muted);font-size:11px}
.bal-order-list{margin-top:8px;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);padding:8px;display:flex;flex-direction:column;gap:6px;max-height:150px;overflow:auto}
.bal-order-row{display:grid;grid-template-columns:28px 1fr auto;gap:8px;align-items:center;padding:7px 8px;border-radius:8px;background:var(--surface);font-size:12.5px;color:var(--text-2)}
.bal-order-row .rank{font-weight:700;color:var(--primary);font-variant-numeric:tabular-nums}
.bal-order-row .tag{font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bal-order-actions{display:flex;gap:4px}
.bal-order-actions button{width:26px;height:24px;border:1px solid var(--border);border-radius:7px;background:var(--surface);color:var(--text-2);cursor:pointer;font-size:13px;line-height:1;padding:0}
.bal-order-actions button:hover:not(:disabled){background:var(--primary-soft);color:var(--primary)}
.bal-order-actions button:disabled{opacity:.35;cursor:not-allowed}

/* ---- Modals ---- */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(15,23,42,.42);z-index:100;justify-content:center;align-items:center;backdrop-filter:blur(4px);padding:20px}
#geoHelpModal{z-index:110}  /* nested above ruleModal which is z:100 */
.modal-bg.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:480px;width:100%;box-shadow:0 20px 50px rgba(0,0,0,.18);max-height:92vh;overflow-y:auto}
.modal.confirm-dialog{max-width:360px;padding:20px}
.confirm-dialog h4{font-size:15px;font-weight:600;margin:0 0 8px;line-height:1.35}
.confirm-dialog .confirm-msg{font-size:13.5px;color:var(--text-2);line-height:1.5;margin:0 0 18px;white-space:pre-line}
.confirm-dialog .modal-foot{display:flex;gap:8px;justify-content:flex-end;margin:0}
.confirm-dialog .btn{padding:7px 14px;font-size:13px;font-weight:500;border-radius:8px}
.confirm-dialog .btn-danger{background:var(--danger);color:#fff;border:1px solid var(--danger)}
.confirm-dialog .btn-danger:hover{filter:brightness(.93)}
.modal h3{margin-bottom:6px;font-size:16px;font-weight:600;color:var(--text)}
.modal-sub{color:var(--muted);font-size:12.5px;margin-bottom:14px}
.modal label{display:block;color:var(--text-2);font-size:12.5px;font-weight:500;margin:12px 0 5px}
.modal-foot{margin-top:18px;display:flex;gap:8px;justify-content:flex-end}
.modal svg.qr{display:block;max-width:240px;max-height:240px;margin:14px auto;background:#fff;border-radius:10px;padding:8px;border:1px solid var(--border)}
.modal .uri-text{margin:10px 0 14px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;word-break:break-all;max-height:90px;overflow-y:auto}

/* settings modal sections */
.set-section{background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;margin:10px 0}
.set-section > summary{cursor:pointer;font-weight:600;color:var(--text);font-size:13.5px;list-style:none;display:flex;align-items:center;gap:10px;user-select:none}
.set-section > summary::-webkit-details-marker{display:none}
.set-section > summary::before{content:"";width:6px;height:6px;border-right:1.5px solid var(--text-2);border-bottom:1.5px solid var(--text-2);transform:rotate(-45deg);transition:.18s;display:inline-block}
.set-section[open] > summary::before{transform:rotate(45deg)}
.set-section > summary .pill{margin-left:auto;font-size:11px;color:var(--muted);font-weight:500;background:var(--surface);border:1px solid var(--border);padding:2px 8px;border-radius:8px}
.set-section .body{margin-top:12px;display:flex;flex-direction:column;gap:2px}

/* toast */
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--text);color:#fff;padding:10px 18px;border-radius:10px;font-size:13px;font-weight:500;opacity:0;pointer-events:none;transition:.25s;z-index:200;box-shadow:0 10px 24px rgba(0,0,0,.18)}
.toast.show{opacity:1}

/* row variants */
#userTable,#obTable{overflow-x:auto;-webkit-overflow-scrolling:touch}
#userTable table,#obTable table{min-width:760px}
.profile-row td{border-bottom:1px solid var(--border)}
.tok-row td{border-bottom:1px dashed var(--border)}
.tok-row td:first-child,.tok-row td:nth-child(2){border-bottom:none}
.btn-add-tok{background:var(--info-soft);color:var(--info);border:none;border-radius:50%;width:22px;height:22px;cursor:pointer;font-size:14px;font-weight:700;line-height:1;margin-left:6px;display:inline-grid;place-items:center;transition:.15s;padding:0}
.btn-add-tok:hover{background:var(--info);color:#fff}
.pending-sel{background:var(--info-soft);border:1px dashed var(--info);border-radius:8px;padding:4px 8px;color:var(--info);font-size:12px;min-width:120px}
.pending-sel:focus{outline:none;border-style:solid}

/* ---- Responsive ---- */
@media (max-width:1100px){
  .stat-row{grid-template-columns:repeat(2,1fr)}
}
/* ---- Mobile burger trigger (hidden on desktop) ---- */
.burger{display:none;background:none;border:0;padding:10px;border-radius:10px;cursor:pointer;color:var(--text-2);align-self:center}
/* ---- Drag-and-drop reorder for routing rules (Sortable.js 2026-05-10) ---- */
.drag-handle{display:inline-grid;place-items:center;width:24px;height:24px;color:var(--muted);cursor:grab;user-select:none;touch-action:none;font-weight:700;font-size:18px;line-height:1}
.drag-handle:hover{color:var(--text)}
.drag-handle:active{cursor:grabbing}
.drag-col{width:32px;padding-left:8px;padding-right:0;text-align:center}
.group-pill{display:inline-flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text)}
.group-pill.ungrouped{color:var(--muted);font-weight:500}
.group-meta{display:inline-block;padding:1px 8px;border-radius:10px;background:var(--surface);color:var(--muted);font-size:11px;font-weight:500}
/* ---- New div/grid layout for Sortable.js (replaces table) ----
   The drag UX now uses Sortable.js (vendored inline above as
   SORTABLE_JS_INLINE).  Two-tier nesting: .rt-root is the top-level
   queue (folders + ungrouped rules siblings); each folder has its own
   .rt-folder-body Sortable so children can be reordered inside it OR
   dragged across folders.  CSS grid keeps the columns visually aligned
   between folder heads, ungrouped rules, and rules nested inside a
   folder body — same column widths everywhere. */
.rt-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
.rt-root{display:flex;flex-direction:column;gap:6px;min-width:560px}
.rt-folder{border:1px solid var(--border);border-radius:10px;background:var(--surface-2);overflow:hidden}
.rt-folder.folder-disabled{opacity:.55}
.rt-folder-body{display:flex;flex-direction:column;gap:4px;padding:6px 8px 6px 30px;min-height:32px;position:relative}
.rt-folder-body::before{content:"";position:absolute;left:18px;top:6px;bottom:6px;width:2px;background:var(--border);border-radius:1px}
.rt-folder-body:empty::after{content:"(drop rules here)";color:var(--muted);font-size:12px;font-style:italic;padding:6px 4px}
.rt-row{display:grid;grid-template-columns:32px 60px 1fr 180px 230px;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px}
.rt-folder .rt-folder-head.rt-row{border:0;border-radius:0;padding:10px 12px;background:var(--surface-2);font-weight:600}
.rt-row .rt-actions{justify-self:end;display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.rt-row .rt-desc{font-weight:500;color:var(--text);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rt-row .rt-pri{color:var(--text);font-weight:600}
.rt-drag{cursor:grab;user-select:none;color:var(--muted);font-size:14px;touch-action:none;line-height:1;display:inline-grid;place-items:center;width:24px;height:24px;font-weight:700}
.rt-drag:hover{color:var(--text)}
.rt-drag:active{cursor:grabbing}
.sortable-ghost{opacity:.4}
.sortable-chosen{box-shadow:0 0 0 2px var(--primary) inset}
.sortable-drag{opacity:.85;transform:rotate(.3deg)}
@media (max-width:560px){
  .rt-row{grid-template-columns:28px 50px 1fr;gap:6px}
  .rt-row > .rt-outbound,.rt-row > .rt-actions{grid-column:1 / -1;padding-left:78px;padding-top:0;justify-self:start}
}
/* ---- Geo presets help button + modal ---- */
.label-with-help{display:flex;align-items:flex-end;justify-content:space-between;gap:8px;margin:14px 0 6px}
.label-with-help label{flex:1;min-width:0}
.help-btn{display:inline-grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--surface-2);color:var(--text-2);border:0;font-size:14px;font-weight:700;cursor:pointer;flex-shrink:0;touch-action:manipulation}
.help-btn:hover{background:var(--primary);color:#fff}
.geo-preset{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;margin-bottom:6px}
.geo-preset .info{flex:1;min-width:0}
.geo-preset .name{font-weight:600;font-size:13.5px;color:var(--text)}
.geo-preset .name code{font-family:ui-monospace,monospace;font-size:12.5px;background:var(--surface-2);padding:1px 6px;border-radius:4px;margin-right:6px}
.geo-preset .desc{font-size:12px;color:var(--muted);margin-top:2px}
input:disabled{opacity:.6;cursor:not-allowed;background:var(--surface-2)}
.burger:hover{background:var(--surface-2)}
.burger svg{width:22px;height:22px;stroke:currentColor;stroke-width:2;fill:none}
.nav-backdrop{display:none;position:fixed;inset:0;background:rgba(15,23,42,0.42);z-index:60;backdrop-filter:blur(2px);opacity:0;transition:opacity 120ms ease-out}
body.nav-open .nav-backdrop{display:block;opacity:1}

@media (max-width:860px){
  /* CSS Grid dropped on mobile. iOS Safari has a known bug where
     position:sticky on a Grid ITEM uses the grid-row as its
     containing block instead of the scrolling viewport. When the
     URL bar collapses, the visual viewport extends but the sticky
     element's top:0 anchors to the grid-row top (document y=0),
     which can land BEHIND the iOS Safari URL bar / dynamic island
     during the URL-bar collapse animation — clipping the rounded
     top corners of the brand mark.

     With display:block, .sidebar is a normal flow block whose
     sticky containing block is body — and body's scrolling
     viewport on iOS Safari IS the visual viewport. top:0 then
     reliably anchors to the visual viewport top across URL-bar
     collapse/expand. */
  .app{display:block;min-height:100vh}
  /* Compact 56px sticky top-bar.
     - position:sticky in body context (not grid track) — fixes iOS Safari clip.
     - Reserves 56px in document flow when scrolled to top, floats over
       content as user scrolls. No padding-top on .main needed.
     - z-index:70 keeps it above page content + the nav-backdrop (z-index:60). */
  .sidebar{
    /* Mobile topbar: [Tamizdat brand RIGHT]. The burger lives outside
       this flex row as position:fixed (see .burger rule below) so it's
       always visible regardless of scroll position and stays tappable
       even when the drawer is open. */
    position:relative;
    height:56px;
    min-height:56px;
    width:100%;
    flex-direction:row;align-items:center;
    padding:0 12px;gap:0;
    border-right:0;border-bottom:1px solid var(--border);
    background:var(--surface);
  }
  /* Brand pins to the right edge; burger is fixed-positioned so it's
     no longer in this flex row. */
  .sidebar .brand{padding:0;flex:0 1 auto;min-width:0;margin-left:auto}
  .sidebar .brand-name{font-size:14px}
  .sidebar .brand-name span{display:none}
  /* Burger is FIXED at top-left of the viewport with z-index 80 — above
     both the drawer (z:65) and the backdrop (z:60). That means tapping
     it ALWAYS toggles the drawer, even while the drawer is open
     overlaying the page. Floating button look: surface bg + shadow so
     it reads against page content when topbar has scrolled away. */
  .burger{
    position:fixed;top:8px;left:8px;z-index:80;
    display:inline-grid;place-items:center;
    width:44px;height:44px;border-radius:10px;
    background:var(--surface);
    border:1px solid var(--border);
    box-shadow:0 4px 12px rgba(15,23,42,.08);
    color:var(--text-2);
  }
  .burger:hover,.burger:focus{background:var(--surface-2);color:var(--text)}
  /* Visual hint that burger doubles as a close-button when drawer is open. */
  body.nav-open .burger{background:var(--surface-2);color:var(--primary);border-color:var(--primary-soft-2)}
  /* Main: with sticky sidebar above (display:block flow), no
     padding-top hack needed. The sidebar reserves 56px in document
     flow when scrolled to top and stays glued during scroll. */
  .main{padding:16px 16px 60px}
  /* Drawer slides in from the LEFT (Material navigation drawer pattern).
     Width 280px (max 85vw on small screens); full viewport height; drops
     in from x=-100% to x=0 via translateX. The backdrop covers the rest
     of the screen and dims it. */
  .nav{
    position:fixed;left:0;top:0;right:auto;bottom:0;
    width:280px;max-width:85vw;
    background:var(--surface);
    border-right:1px solid var(--border);
    box-shadow:8px 0 28px rgba(15,23,42,.24);
    flex-direction:column;gap:0;
    /* padding-top:60 keeps the first link clear of the floating burger
       (top:8 + size:44 + 8 breathing = 60). Burger remains tappable on
       top of the drawer, but no link gets visually covered by it. */
    margin:0;padding:60px 0 12px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform 220ms ease-out;
    pointer-events:none;
    z-index:65;
  }
  body.nav-open .nav{transform:translateX(0);pointer-events:auto}
  .nav a{
    height:48px;padding:0 18px;border-radius:0;
    font-size:15px;
  }
  .nav a.active{background:var(--dusk-soft)}
  .nav-spacer{display:none}
  /* Footer pill (logged-in user) inside drawer. */
  .nav-foot{padding:10px}
  .user-name{font-size:13.5px}
  .page-title{font-size:18px}
  .stat{padding:12px 14px;gap:10px}
  .stat-icon{width:36px;height:36px;border-radius:10px}
  .stat-value{font-size:15px}
  .stat-row{gap:10px}
  table{font-size:12.5px}
  th{padding:8px 10px;font-size:10.5px}
  td{padding:10px 10px}
  .actions{gap:4px}
  .actions .btn{padding:5px 10px;font-size:11.5px}
}
@media (max-width:560px){
  .stat-row{grid-template-columns:1fr}
  .modal{padding:18px}
  .form-row > input.tag-input{max-width:none}
}

/* =================================================================
   Settings page mockup port (2026-05-11)
   All classes prefixed with `.s-` or scoped under `#page-settings`
   so they cannot collide with legacy Settings CSS or other pages.
   ================================================================= */
#page-settings .set-shell{display:grid;grid-template-columns:240px minmax(0,1fr);gap:28px;align-items:flex-start;max-width:1200px}

/* sub-rail */
#page-settings .sub-rail{position:sticky;top:24px;display:flex;flex-direction:column;gap:2px}
#page-settings .sub-rail-head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:12px;gap:8px}
#page-settings .sub-rail-title{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
#page-settings .sub-link{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--text-2);text-decoration:none;font-size:13.5px;font-weight:500;cursor:pointer;transition:.12s;border-left:2px solid transparent;position:relative}
#page-settings .sub-link:hover{background:var(--surface-2);color:var(--text)}
#page-settings .sub-link.active{background:var(--surface);color:var(--primary);border-left-color:var(--primary);box-shadow:var(--shadow-sm)}
#page-settings .sub-link .glyph{width:22px;height:22px;border-radius:6px;background:var(--surface-2);display:grid;place-items:center;flex-shrink:0;transition:.12s}
#page-settings .sub-link.active .glyph{background:var(--primary-soft);color:var(--primary)}
#page-settings .sub-link .glyph svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}
#page-settings .sub-link .dot{margin-left:auto;width:6px;height:6px;border-radius:50%;background:var(--warn);opacity:0;transition:.18s}
#page-settings .sub-link.dirty .dot{opacity:1}
#page-settings .sub-meta{margin-top:14px;padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:11.5px;color:var(--muted);line-height:1.55}
#page-settings .sub-meta b{display:block;color:var(--text);font-size:12px;font-weight:600;margin-bottom:4px;letter-spacing:.2px}
#page-settings .sub-meta .row{display:flex;justify-content:space-between;align-items:center;padding:3px 0}
#page-settings .sub-meta .row span:last-child{color:var(--text-2);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}

/* page-head (uses existing) — only overrides we need */
#page-settings .page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:20px;flex-wrap:wrap}
#page-settings .crumb{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);margin-bottom:6px}
#page-settings .crumb a{color:var(--muted);text-decoration:none}
#page-settings .crumb a:hover{color:var(--text-2)}
#page-settings .crumb svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2}

/* group cards */
#page-settings .group{background:var(--surface);border:1px solid var(--border);border-radius:16px;margin-bottom:16px;overflow:hidden;box-shadow:var(--shadow-sm)}
#page-settings .group-head{padding:18px 22px 4px;display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap}
#page-settings .group-title{display:flex;align-items:center;gap:12px}
#page-settings .group-title h2{font-size:16px;font-weight:600;color:var(--text);letter-spacing:-.1px;margin:0}
#page-settings .group-title .desc{font-size:13px;color:var(--muted);margin-top:3px;line-height:1.5}
#page-settings .group-title .glyph{width:36px;height:36px;border-radius:10px;background:var(--primary-soft);color:var(--primary);display:grid;place-items:center;flex-shrink:0}
#page-settings .group-title .glyph svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.8}
#page-settings .group-pill{font-size:11px;font-weight:600;letter-spacing:.3px;padding:3px 9px;border-radius:6px;text-transform:uppercase}
#page-settings .pill-live{background:var(--ok-soft);color:var(--ok)}
#page-settings .pill-restart{background:var(--warn-soft);color:var(--warn)}
#page-settings .pill-self{background:var(--info-soft);color:var(--info)}
#page-settings .pill-beta{background:var(--mauve-soft);color:var(--mauve)}

/* field list */
#page-settings .fields{padding:8px 22px 18px}
#page-settings .field{display:grid;grid-template-columns:240px minmax(0,1fr);gap:24px;padding:14px 0;border-bottom:1px solid var(--border)}
#page-settings .field:last-child{border-bottom:none}
#page-settings .field.row-stack{grid-template-columns:1fr}
#page-settings .field-lbl{padding-top:8px}
#page-settings .field-lbl .lbl{font-size:13.5px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
#page-settings .field-lbl .hint{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.5}
#page-settings .tag{display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border-radius:5px;font-size:10.5px;font-weight:600;letter-spacing:.2px;text-transform:uppercase}
#page-settings .tag-restart{background:var(--warn-soft);color:var(--warn)}
#page-settings .tag-env{background:var(--surface-3);color:var(--text-2)}
#page-settings .tag-readonly{background:var(--surface-3);color:var(--muted)}
#page-settings .tag-required{background:var(--danger-soft);color:var(--danger)}
#page-settings .tag-auto{background:var(--info-soft);color:var(--info)}
#page-settings .field-ctrl{display:flex;flex-direction:column;gap:6px;min-width:0}

/* inputs — scope to Settings so they don't override existing forms */
#page-settings input[type=text],#page-settings input[type=number],#page-settings input[type=password],#page-settings textarea,#page-settings select{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 12px;color:var(--text);font-size:13.5px;font-family:inherit;transition:.15s;width:100%
}
#page-settings input::placeholder,#page-settings textarea::placeholder{color:var(--muted)}
#page-settings input:focus,#page-settings textarea:focus,#page-settings select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
#page-settings input.mono,#page-settings textarea.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
#page-settings input[readonly],#page-settings textarea[readonly]{background:var(--surface-2);color:var(--text-2)}
#page-settings textarea{resize:vertical;min-height:64px}
#page-settings select{cursor:pointer;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236B7280' stroke-width='2'><polyline points='6 9 12 15 18 9'/></svg>");background-repeat:no-repeat;background-position:right 10px center;padding-right:32px;-webkit-appearance:none;appearance:none}

/* segmented control */
#page-settings .seg{display:inline-flex;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:3px;gap:2px;flex-wrap:wrap}
#page-settings .seg button{background:transparent;border:none;padding:6px 12px;font-size:12.5px;font-weight:600;color:var(--text-2);border-radius:7px;cursor:pointer;font-family:inherit;transition:.12s;display:inline-flex;align-items:center;gap:5px}
#page-settings .seg button:hover{color:var(--text)}
#page-settings .seg button.on{background:var(--surface);color:var(--primary);box-shadow:var(--shadow-sm)}
#page-settings .seg button svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}

/* toggle */
#page-settings .s-toggle{position:relative;display:inline-flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
#page-settings .s-toggle input{position:absolute;opacity:0;pointer-events:none}
#page-settings .s-toggle .track{width:36px;height:20px;background:var(--border-strong);border-radius:999px;position:relative;transition:.18s;flex-shrink:0}
#page-settings .s-toggle .track::after{content:"";position:absolute;left:2px;top:2px;width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.18);transition:.18s}
#page-settings .s-toggle input:checked + .track{background:var(--primary)}
#page-settings .s-toggle input:checked + .track::after{left:18px}
#page-settings .s-toggle .lbl{font-weight:600;font-size:13.5px;color:var(--text)}
#page-settings .s-toggle .lbl small{display:block;font-weight:500;color:var(--muted);font-size:11.5px;margin-top:1px}

/* chip pool */
#page-settings .chips{display:flex;flex-wrap:wrap;gap:6px;padding:8px 10px;background:var(--surface);border:1px solid var(--border);border-radius:10px;min-height:40px;align-items:center;cursor:text}
#page-settings .chips:focus-within{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft-2)}
#page-settings .chip{display:inline-flex;align-items:center;gap:4px;padding:3px 4px 3px 8px;background:var(--primary-soft);color:var(--primary);border-radius:6px;font-size:12px;font-weight:500;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
#page-settings .chip .x{width:14px;height:14px;border-radius:3px;display:grid;place-items:center;cursor:pointer;opacity:.6;transition:.1s}
#page-settings .chip .x:hover{background:var(--primary);color:#fff;opacity:1}
#page-settings .chip .x svg{width:9px;height:9px;stroke:currentColor;fill:none;stroke-width:2.5}
#page-settings .chips input{border:none;background:transparent;flex:1;min-width:120px;padding:3px 4px;font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;box-shadow:none}
#page-settings .chips input:focus{outline:none;box-shadow:none}

/* line list (geo URLs etc.) */
#page-settings .line-list{display:flex;flex-direction:column;gap:6px}
#page-settings .line-row{display:flex;gap:6px;align-items:center}
#page-settings .line-row input{flex:1}
#page-settings .line-row .btn-mini{width:32px;height:32px;border-radius:8px;background:var(--surface);border:1px solid var(--border);color:var(--text-2);cursor:pointer;display:grid;place-items:center;flex-shrink:0;transition:.12s}
#page-settings .line-row .btn-mini:hover{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-soft)}
#page-settings .line-row .btn-mini svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}
#page-settings .line-list .btn-add{align-self:flex-start;background:transparent;border:1px dashed var(--border-strong);color:var(--text-2);padding:6px 12px;font-size:12px;border-radius:8px;cursor:pointer;display:inline-flex;gap:5px;align-items:center;font-weight:600;font-family:inherit;transition:.12s}
#page-settings .line-list .btn-add:hover{border-color:var(--primary);color:var(--primary);background:var(--primary-soft)}
#page-settings .line-list .btn-add svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2.5}

/* advanced reveal */
#page-settings .adv-toggle{margin-top:8px;background:transparent;border:none;color:var(--muted);font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;font-family:inherit;padding:6px 0}
#page-settings .adv-toggle:hover{color:var(--text-2)}
#page-settings .adv-toggle svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2.5;transition:.18s}
#page-settings .adv-toggle.open svg{transform:rotate(180deg)}
#page-settings .adv-body{display:none;padding-top:4px}
#page-settings .adv-body.open{display:block}

/* danger zone */
#page-settings .danger-card{border:1px solid #fbcfd8;background:linear-gradient(to right, #fff 0%, #FEF7F9 100%)}
#page-settings .danger-card .group-title .glyph{background:var(--danger-soft);color:var(--danger)}

/* sticky save bar */
.save-bar{position:fixed;bottom:18px;left:50%;transform:translateX(-50%) translateY(120%);transition:.28s cubic-bezier(.2,.7,.2,1);background:var(--text);color:#fff;padding:10px 10px 10px 18px;border-radius:14px;box-shadow:var(--shadow-lg);display:flex;align-items:center;gap:16px;z-index:90;min-width:480px;max-width:calc(100% - 36px)}
.save-bar.show{transform:translateX(-50%) translateY(0)}
.save-bar .sb-info{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:500}
.save-bar .sb-dot{width:8px;height:8px;border-radius:50%;background:#FBBF24;box-shadow:0 0 0 3px rgba(251,191,36,.25);animation:savebarPulse 1.6s infinite}
@keyframes savebarPulse{0%,100%{box-shadow:0 0 0 3px rgba(251,191,36,.25)}50%{box-shadow:0 0 0 6px rgba(251,191,36,.05)}}
.save-bar .sb-changes{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:#FBBF24;background:rgba(251,191,36,.12);padding:2px 8px;border-radius:5px}
.save-bar .sb-spacer{flex:1}
.save-bar .sb-btn{padding:8px 14px;font-size:13px;font-weight:600;border-radius:9px;border:none;cursor:pointer;font-family:inherit;display:inline-flex;gap:5px;align-items:center;transition:.12s}
.save-bar .sb-discard{background:transparent;color:#D1D5DB}
.save-bar .sb-discard:hover{color:#fff;background:rgba(255,255,255,.08)}
.save-bar .sb-save{background:var(--primary);color:#fff}
.save-bar .sb-save:hover{background:var(--primary-hover)}
.save-bar .sb-save svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2.5}

/* helpers — scoped */
#page-settings .row-flex{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
#page-settings .row-flex > *{flex:1;min-width:140px}
#page-settings .split-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
#page-settings .btn-soft{background:var(--surface-2);border:1px solid var(--border);color:var(--text-2);padding:7px 12px;border-radius:8px;font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;gap:5px;align-items:center;font-family:inherit;transition:.12s}
#page-settings .btn-soft:hover{background:var(--primary-soft);color:var(--primary);border-color:var(--primary-soft-2)}
#page-settings .btn-soft svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2}

/* responsive — settings sub-rail collapses to grid */
@media (max-width:1100px){
  #page-settings .set-shell{grid-template-columns:1fr}
  #page-settings .sub-rail{position:static;display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px}
  #page-settings .sub-rail-head,#page-settings .sub-meta{grid-column:1/-1}
}
@media (max-width:860px){
  #page-settings .field{grid-template-columns:1fr;gap:8px}
  .save-bar{min-width:0;width:calc(100% - 32px)}
}
</style>
</head>
<body>

<div class="app">

  <!-- ============ Sidebar ============ -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">T</div>
      <div class="brand-name">Tamizdat<span>Panel</span></div>
    </div>
    <button class="burger" id="navBurger" aria-label="Menu" aria-expanded="false" aria-controls="navList" onclick="toggleNav()">
      <svg viewBox="0 0 24 24"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/></svg>
    </button>
    <nav class="nav" id="navList" role="navigation">
      <a class="active" data-route="overview" href="#overview">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>
        Overview
      </a>
      <a data-route="outbounds" href="#outbounds">
        <svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="M13 5l7 7-7 7"/><circle cx="4" cy="12" r="1.5"/></svg>
        Outbounds
      </a>
      <a data-route="routing" href="#routing">
        <svg viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M3 12h12"/><path d="M3 18h6"/><circle cx="20" cy="12" r="1.5"/><circle cx="20" cy="18" r="1.5"/></svg>
        Routing
      </a>
      <a data-route="settings" href="#settings">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        Settings
      </a>
      <div class="nav-spacer"></div>
      <div class="nav-foot">
        <div class="user-chip">
          <div class="user-avatar">LOGGED_USER_INITIAL</div>
          <div class="user-name">LOGGED_USER</div>
          <a class="logout-btn" href="LOGOUT_URL" title="Log out" aria-label="Log out">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <path d="M16 17l5-5-5-5"/>
              <path d="M21 12H9"/>
            </svg>
          </a>
        </div>
      </div>
    </nav>
  </aside>

  <div class="nav-backdrop" onclick="toggleNav(false)"></div>

  <!-- ============ Main ============ -->
  <main class="main">

    <!-- ============ Overview page ============ -->
    <section class="page" id="page-overview">
    <div class="page-head">
      <div>
        <div class="page-title">Overview</div>
        <div class="page-sub">Server health and users.</div>
      </div>
    </div>

    <!-- Stat cards -->
    <div class="stat-row">
      <div class="stat green" id="svcBar">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="stat-body">
          <div class="stat-label">Service</div>
          <div class="stat-value" id="statSvc">— <small id="statSvcUptime"></small></div>
        </div>
        <button class="btn btn-svc btn-stop stat-svc-btn" id="btnToggle" onclick="svcAction(this.dataset.action)" data-action="stop">Stop</button>
      </div>
      <div class="stat blue">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        </div>
        <div>
          <div class="stat-label">Users</div>
          <div class="stat-value" id="statUsers">0 <small>online / 0 total</small></div>
        </div>
      </div>
      <div class="stat purple">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
        </div>
        <div>
          <div class="stat-label">Total traffic</div>
          <div class="stat-value" id="statTraffic">↓0 B <small>↑0 B</small></div>
        </div>
      </div>
      <div class="stat orange">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        </div>
        <div>
          <div class="stat-label">Outbounds</div>
          <div class="stat-value" id="statOutbounds">0 <small>configured</small></div>
        </div>
      </div>
    </div>

    <!-- Resource rings (CPU / RAM / Swap / Disk) — polled every 5 s -->
    <div class="res-row" id="resRow">
      <div class="res-card"><svg class="res-ring" viewBox="0 0 36 36"><path class="res-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="res-fg" id="resCpuArc" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-dasharray="0,100"/><text class="res-pct" id="resCpuPct" x="18" y="20.5">0.00%</text></svg><div class="res-label">CPU</div></div>
      <div class="res-card"><svg class="res-ring" viewBox="0 0 36 36"><path class="res-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="res-fg" id="resMemArc" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-dasharray="0,100"/><text class="res-pct" id="resMemPct" x="18" y="20.5">0.00%</text></svg><div class="res-label" id="resMemLabel">память: — / —</div></div>
      <div class="res-card"><svg class="res-ring" viewBox="0 0 36 36"><path class="res-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="res-fg" id="resSwapArc" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-dasharray="0,100"/><text class="res-pct" id="resSwapPct" x="18" y="20.5">0.00%</text></svg><div class="res-label" id="resSwapLabel">Swap: — / —</div></div>
      <div class="res-card"><svg class="res-ring" viewBox="0 0 36 36"><path class="res-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/><path class="res-fg" id="resDiskArc" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" stroke-dasharray="0,100"/><text class="res-pct" id="resDiskPct" x="18" y="20.5">0.00%</text></svg><div class="res-label" id="resDiskLabel">жесткий диск: — / —</div></div>
    </div>

    <!-- ============ Users section ============ -->
    <div class="section-title" id="users">Users <span class="count" id="userCounts">0 / 0</span></div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
          Add user
        </div>
        <div class="card-actions">
          <button class="btn btn-primary" onclick="openAddUser()">
            <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add user
          </button>
        </div>
      </div>
      <div id="userTable"><div class="status">Loading…</div></div>
    </div>

    </section>
    <!-- ============ /Overview page ============ -->

    <!-- ============ Outbounds page ============ -->
    <section class="page" id="page-outbounds" style="display:none">
      <div class="page-head">
        <div>
          <div class="page-title">Outbounds</div>
          <div class="page-sub">Outbound chain management — import tamizdat URIs, set the default route, edit or delete entries.</div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="card-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="1.8"><path d="M5 12h14"/><path d="M13 5l7 7-7 7"/></svg>
            Import outbound
          </div>
        </div>
        <div class="card-pad">
          <div class="form-row">
            <input type="text" id="obTag" class="tag-input" placeholder="tag (optional)">
            <input type="text" id="obUri" placeholder="tamizdat://...">
            <button class="btn btn-primary" onclick="importOutbound()">
              <svg viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
              Import
            </button>
            <button class="btn btn-ghost" onclick="openAddBalancer()">
              <svg viewBox="0 0 24 24"><path d="M4 6h5l3 6-3 6H4"/><path d="M15 6h5"/><path d="M15 18h5"/><path d="M12 12h8"/></svg>
              Add balancer
            </button>
          </div>
        </div>
      </div>

      <div class="card">
        <div id="obTable"><div class="status">Loading…</div></div>
      </div>
    </section>
    <!-- ============ /Outbounds page ============ -->

    <!-- ============ Routing page ============ -->
    <section class="page" id="page-routing" style="display:none">
      <div class="page-head">
        <div>
          <div class="page-title">Routing</div>
          <div class="page-sub">Правила маршрутизации — first-match-wins. Меняются на лету (SIGHUP), без перезапуска.</div>
        </div>
        <div class="card-actions">
          <button class="btn btn-ghost" onclick="openNewRoutingFolder()" title="Create folder">
            <svg viewBox="0 0 24 24"><path d="M3 7h6l2 2h10v9a2 2 0 0 1-2 2H3V7z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
            New folder
          </button>
          <button class="btn btn-primary" onclick="openAddRoutingRule()">
            <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add rule
          </button>
        </div>
      </div>

      <div class="card">
        <div id="routingTable"><div class="status">Loading…</div></div>
      </div>
    </section>
    <!-- ============ /Routing page ============ -->

    <!-- ============ Settings page ============ -->
    <!-- 2026-05-11: Surgical port of the designer mockup
         (Downloads/Settings (1).html) into the existing PANEL_HTML.
         Sub-rail navigation, group cards, sticky save bar, dirty-tracking.
         All field IDs match the existing loadSettings()/saveTamizdatServer()/
         savePanel() handlers so the wiring is preserved.
         2026-05-25 cleanup: dropped two groups + pool segmented + per-user
         caps; moved the sniff toggle into Routing data; added the User
         group with the change-password form. See git log for the dropped
         block names. -->

    <section class="page" id="page-settings" style="display:none">

      <div class="page-head">
        <div>
          <div class="crumb">
            <a>Panel</a>
            <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
            <span>Settings</span>
          </div>
          <div class="page-title">Settings</div>
          <div class="page-sub">Конфигурация tamizdat-server и inbound'ов. Изменения применяются после Save.</div>
        </div>
      </div>

      <div class="set-shell">

        <!-- ===== Sub-rail ===== -->
        <aside class="sub-rail" id="subRail">
          <div class="sub-rail-head">
            <span class="sub-rail-title">Settings</span>
          </div>
          <a class="sub-link active" data-target="g-server">
            <span class="glyph"><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></span>
            Server
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-wgturn">
            <span class="glyph"><svg viewBox="0 0 24 24"><path d="M4 12h16"/><path d="M12 4v16"/><circle cx="12" cy="12" r="9"/></svg></span>
            WG TURN
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-tls">
            <span class="glyph"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
            Identity &amp; TLS
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-masq">
            <span class="glyph"><svg viewBox="0 0 24 24"><circle cx="9" cy="12" r="3"/><circle cx="15" cy="12" r="3"/><path d="M2 12c0-4 4-7 10-7s10 3 10 7-4 7-10 7-10-3-10-7z"/></svg></span>
            Masquerade
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-routing">
            <span class="glyph"><svg viewBox="0 0 24 24"><polyline points="3 6 9 6 12 12 15 6 21 6"/><path d="M3 18h18"/></svg></span>
            Routing data
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-panel">
            <span class="glyph"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/></svg></span>
            Panel
            <span class="dot"></span>
          </a>
          <a class="sub-link" data-target="g-broadcast">
            <span class="glyph"><svg viewBox="0 0 24 24"><path d="M3 11l18-8v18l-18-8z"/><line x1="11" y1="11" x2="11" y2="18"/></svg></span>
            Broadcast
          </a>
          <a class="sub-link" data-target="g-user">
            <span class="glyph"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
            User
          </a>

          <div class="sub-meta">
            <b>Service</b>
            <div class="row"><span>Status</span><span id="setSvcStatus" style="color:var(--ok)">● —</span></div>
            <div class="row"><span>Panel</span><span id="setPanelVersionMini">—</span></div>
          </div>
        </aside>

        <!-- ===== Settings content ===== -->
        <div class="set-content">

          <!-- ===== Group: Server ===== -->
          <section class="group" id="g-server">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph"><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/></svg></div>
                <div>
                  <h2>Server <span class="group-pill pill-live">live reload</span></h2>
                  <div class="desc">Где tamizdat-server слушает входящие подключения и какой порт виден клиенту.</div>
                </div>
              </div>
              <!-- Inbound toggle removed 2026-05-11: was a UI-only lie —
                   saved inbound_bundle_enabled to DB but tamizdat-server-app
                   has no reader for that key. To actually kill the inbound,
                   `systemctl stop tamizdat-server` from the host shell.
                   Dead-mine audit reference: §3 (b). -->
            </div>
            <div class="fields">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Listen address</div>
                  <div class="hint"><code>0.0.0.0</code> — все интерфейсы, <code>127.0.0.1</code> — только локальные подключения (через nginx).</div>
                </div>
                <div class="field-ctrl">
                  <div class="seg" id="bindSeg">
                    <button type="button" data-val="127.0.0.1"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Local (127.0.0.1)</button>
                    <button type="button" data-val="0.0.0.0"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>All (0.0.0.0)</button>
                    <button type="button" data-val="custom">Custom…</button>
                  </div>
                  <input type="text" id="tamListenAddr" value="" class="mono" placeholder="0.0.0.0">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Internal port</div>
                  <div class="hint">Порт на который слушает tamizdat-server. За nginx — обычно проксируется на 443.</div>
                </div>
                <div class="field-ctrl">
                  <input type="number" id="tamListenPort" class="mono" placeholder="7780">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Public port <span class="tag tag-auto">uri hint</span></div>
                  <div class="hint">Порт, который клиент увидит в <code>tamizdat://host:PORT/</code>. Не меняет где сервер слушает.</div>
                </div>
                <div class="field-ctrl">
                  <input type="number" id="tamPublicPort" class="mono" placeholder="443">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">H2 max streams per TCP</div>
                  <div class="hint">HTTP/2 <code>SETTINGS_MAX_CONCURRENT_STREAMS</code> для одного H2-соединения.</div>
                </div>
                <div class="field-ctrl">
                  <input type="number" id="tamMaxStreams" class="mono" placeholder="1000">
                </div>
              </div>

            </div>
          </section>

          <!-- ===== Group: WG TURN ===== -->
          <section class="group" id="g-wgturn">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--info-soft);color:var(--info)"><svg viewBox="0 0 24 24"><path d="M4 12h16"/><path d="M12 4v16"/><circle cx="12" cy="12" r="9"/></svg></div>
                <div>
                  <h2>WG TURN <span class="group-pill pill-restart">restart</span></h2>
                  <div class="desc">WireGuard-over-DTLS-over-TURN inbound. Existing user shortIDs can authenticate this transport; routed flows use normal outbounds/rules.</div>
                </div>
              </div>
            </div>
            <div class="fields">
              <div class="field">
                <div class="field-lbl"><div class="lbl">Enable WG TURN</div><div class="hint">Writes server settings; restart applies listener changes. Keep disabled on gateway unless explicitly needed.</div></div>
                <div class="field-ctrl"><label class="switch"><input type="checkbox" id="wgTurnEnabled"><span></span></label></div>
              </div>
              <div class="field">
                <div class="field-lbl"><div class="lbl">DTLS listen</div><div class="hint">Example: <code>0.0.0.0:5000</code>. Empty disables even if toggle is on.</div></div>
                <div class="field-ctrl"><input type="text" id="wgTurnListen" class="mono" placeholder="0.0.0.0:5000"></div>
              </div>
              <div class="field">
                <div class="field-lbl"><div class="lbl">Shared fallback password</div><div class="hint">Optional legacy password. Preferred client auth is per-user Tamizdat shortID.</div></div>
                <div class="field-ctrl"><input type="password" id="wgTurnPassword" class="mono" placeholder="optional"></div>
              </div>
              <div class="field">
                <div class="field-lbl"><div class="lbl">Fixed fallback outbound</div><div class="hint">Optional tag such as <code>fallback-example</code>. Empty = normal routing/default outbound.</div></div>
                <div class="field-ctrl"><input type="text" id="wgTurnOutboundTag" class="mono" placeholder="fallback-example"></div>
              </div>
              <div class="field row-stack">
                <div class="split-2">
                  <div><div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">WG UDP port</div><input type="number" id="wgTurnWGPort" class="mono" placeholder="56001"></div>
                  <div><div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Config dir</div><input type="text" id="wgTurnConfigDir" class="mono" placeholder="/etc/tamizdat/wgturn"></div>
                </div>
                <div class="split-2" style="margin-top:8px">
                  <div><div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Subnet</div><input type="text" id="wgTurnSubnet" class="mono" placeholder="10.66.66.0/24"></div>
                  <div><div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Server IP</div><input type="text" id="wgTurnServerIP" class="mono" placeholder="10.66.66.1"></div>
                </div>
              </div>
            </div>
          </section>

          <!-- ===== Group: Identity & TLS ===== -->
          <section class="group" id="g-tls">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--mauve-soft);color:var(--mauve)"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
                <div>
                  <h2>Identity &amp; TLS</h2>
                  <div class="desc">Ключевая пара tamizdat-сервера и пути к TLS-сертификатам.</div>
                </div>
              </div>
              <span class="group-pill pill-restart">restart</span>
            </div>
            <div class="fields">

              <div class="field row-stack">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:4px">
                  <div>
                    <div class="lbl" style="font-size:13.5px;font-weight:600">Keypair <span class="tag tag-required">required</span></div>
                    <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">X25519. Public key выдаётся клиентам через URI.</div>
                  </div>
                  <div style="display:flex;gap:6px">
                    <button type="button" class="btn-soft" onclick="genTamKeypair()"><svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Generate new</button>
                    <button type="button" class="btn-soft" id="copyPub"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy pubkey</button>
                  </div>
                </div>
                <div class="split-2">
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Private <span class="tag tag-required" style="margin-left:4px">secret</span></div>
                    <input type="password" id="tamPriv" class="mono" placeholder="(оставь пустым чтобы сохранить текущее)">
                  </div>
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Public <span class="tag tag-readonly" style="margin-left:4px">derived</span></div>
                    <input type="text" id="tamPub" readonly class="mono">
                  </div>
                </div>
              </div>

              <div class="field row-stack">
                <div>
                  <div class="lbl" style="font-size:13.5px;font-weight:600">TLS certificate &amp; key</div>
                  <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Пара cert+key для TLS-терминации. acme или вручную.</div>
                </div>
                <div class="split-2" style="margin-top:4px">
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">cert.pem path</div>
                    <input type="text" id="tamCert" class="mono" placeholder="/etc/tamizdat/cert.pem">
                  </div>
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">key.pem path</div>
                    <input type="text" id="tamKey" class="mono" placeholder="/etc/tamizdat/key.pem">
                  </div>
                </div>
              </div>

              <div class="field row-stack">
                <div>
                  <div class="lbl" style="font-size:13.5px;font-weight:600">Master URI <span class="tag tag-readonly">derived</span></div>
                  <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Master URI inbound'а — для каждого пользователя выдавай URI из Users tab.</div>
                </div>
                <textarea id="tamUri" readonly class="mono" style="min-height:54px"></textarea>
              </div>

            </div>
          </section>

          <!-- ===== Group: Masquerade ===== -->
          <section class="group" id="g-masq">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--info-soft);color:var(--info)"><svg viewBox="0 0 24 24"><circle cx="9" cy="12" r="3"/><circle cx="15" cy="12" r="3"/><path d="M2 12c0-4 4-7 10-7s10 3 10 7-4 7-10 7-10-3-10-7z"/></svg></div>
                <div>
                  <h2>Masquerade</h2>
                  <div class="desc">SNI-маскировка, под какие домены сервер прикидывается.</div>
                </div>
              </div>
              <span class="group-pill pill-live">live reload</span>
            </div>
            <div class="fields">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Cover SNI</div>
                  <div class="hint">Базовый домен, виден в TLS ClientHello.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="tamMasq" class="mono" placeholder="ya.ru">
                </div>
              </div>

              <div class="field row-stack">
                <div>
                  <div class="lbl" style="font-size:13.5px;font-weight:600">SNI rotation pool</div>
                  <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Пул через который SNI-варианты ротируются. Формат <code>sni=host:port</code>.</div>
                </div>
                <div class="chips" id="sniChips" tabindex="0">
                  <input type="text" placeholder="add host=ip:port…">
                </div>
                <!-- Backing textarea — kept in sync with chips via JS. Hidden from layout. -->
                <textarea id="tamMasqPool" style="display:none"></textarea>
                <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px"><span id="chipCount">0</span> hosts · нажмите <kbd style="font-size:10px;border:1px solid var(--border);padding:1px 4px;border-radius:3px;background:var(--surface-2);font-family:ui-monospace,monospace">Enter</kbd> чтобы добавить</div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Bootstrap SNI <span class="tag tag-auto">uri hint</span></div>
                  <div class="hint">SNI для первой инициирующей connection на стороне КЛИЕНТА. Подставляется в выдаваемые пользователям URI. Пусто — клиент берёт hostname из URI.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="tamBootstrap" placeholder="empty = URI host" class="mono">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">uTLS fingerprint <span class="tag tag-auto">uri hint</span></div>
                  <div class="hint">Какой браузер имитировать в TLS-handshake на стороне КЛИЕНТА. Подставляется в URI как <code>&amp;fp=</code>; сервер сам этим не пользуется.</div>
                </div>
                <div class="field-ctrl">
                  <div class="seg" id="utlsSeg">
                    <button type="button" data-val="mix">Mix</button>
                    <button type="button" data-val="chrome">Chrome</button>
                    <button type="button" data-val="firefox">Firefox</button>
                    <button type="button" data-val="safari">Safari</button>
                  </div>
                  <select id="tamFp" style="display:none">
                    <option value="mix">mix</option>
                    <option value="chrome">chrome</option>
                    <option value="firefox">firefox</option>
                    <option value="safari">safari</option>
                  </select>
                </div>
              </div>

              <!-- Pool segmented control removed from Settings 2026-05-25:
                   hardcoded operator policy is V1; inbound_pool_variant DB
                   key preserved for compat. Hidden input below keeps
                   saveTamizdatServer() happy without re-introducing a UI
                   choice the operator does not want surfaced. -->
              <input type="hidden" id="tamPoolVariant" value="v1">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Default H2 transports per user</div>
                  <div class="hint">Used when creating a user without an explicit dropdown choice. Range <code>1..4</code>.</div>
                </div>
                <div class="field-ctrl">
                  <input type="number" id="tamPoolSizeDefault" class="mono" min="1" max="4" placeholder="1">
                </div>
              </div>

            </div>
          </section>

          <!-- Group removed from Settings 2026-05-25: jitter / fallback
               fields were dead-mine UI without backend readers.
               inbound_jitter_ms / inbound_fallback_server /
               inbound_fallback_port DB keys preserved. Hidden inputs keep
               the existing saveTamizdatServer() payload intact. The TLS
               SNI / HTTP Host sniff toggle moved to the Routing data
               block - it controls whether routing rules see the sniffed
               hostname. -->
          <input type="hidden" id="tamJitter" value="0">
          <input type="hidden" id="jitterRange" value="0">

          <!-- ===== Group: Routing data ===== -->
          <section class="group" id="g-routing">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--ok-soft);color:var(--ok)"><svg viewBox="0 0 24 24"><polyline points="3 6 9 6 12 12 15 6 21 6"/><path d="M3 18h18"/></svg></div>
                <div>
                  <h2>Routing data</h2>
                  <div class="desc">Источники <code>geoip.dat</code> и <code>geosite.dat</code> для routing-правил.</div>
                </div>
              </div>
            </div>
            <div class="fields">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">TLS SNI / HTTP Host sniff <span class="tag tag-auto">server push</span></div>
                  <div class="hint">Server peek-ит первые ~4KB клиентского потока, достаёт SNI/Host, использует как hostname для <code>domain:</code> routing-правил. Без sniff iOS sing-tun / full-tunnel клиенты, которые шлют уже резолвленные IP, мимо domain-rules. Default ON.</div>
                </div>
                <div class="field-ctrl">
                  <label style="display:inline-flex;gap:8px;align-items:center;cursor:pointer">
                    <input type="checkbox" id="tamSniffEnabled" style="width:18px;height:18px;accent-color:var(--primary)">
                    <span>Enabled</span>
                  </label>
                </div>
              </div>

              <div class="field row-stack">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                  <div>
                    <div class="lbl" style="font-size:13.5px;font-weight:600">GeoIP sources</div>
                    <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Один URL geoip.dat на строку. Пусто = выгрузить из памяти, geoip-поля заблокируются.</div>
                  </div>
                </div>
                <div class="line-list" id="geoipList">
                  <button type="button" class="btn-add" onclick="addGeoLine(this,'geoip')"><svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Add URL</button>
                </div>
                <!-- Backing textarea — kept in sync with line-list via JS. Auto-saved on blur per legacy onblur handler. -->
                <textarea id="setGeoipUrl" style="display:none" onblur="saveGeoUrl(\'inbound_geoip_url\', this.value)"></textarea>
              </div>

              <div class="field row-stack">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                  <div>
                    <div class="lbl" style="font-size:13.5px;font-weight:600">Geosite sources</div>
                    <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Один URL geosite.dat на строку. Данные ВСЕХ источников объединяются по тегам.</div>
                  </div>
                </div>
                <div class="line-list" id="geositeList">
                  <button type="button" class="btn-add" onclick="addGeoLine(this,'geosite')"><svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Add URL</button>
                </div>
                <textarea id="setGeositeUrl" style="display:none" onblur="saveGeoUrl(\'inbound_geosite_url\', this.value)"></textarea>
              </div>

            </div>
          </section>

          <!-- ===== Group: Panel ===== -->
          <section class="group" id="g-panel">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--info-soft);color:var(--info)"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/></svg></div>
                <div>
                  <h2>Panel <span class="group-pill pill-self">self-config</span></h2>
                  <div class="desc">Эта самая панель — где она слушает и кому открыта.</div>
                </div>
              </div>
            </div>
            <div class="fields">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Public hostname</div>
                  <div class="hint">Что попадает в URI пользователей. Меняется без restart.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="setPanelHostname" class="mono" placeholder="server.example.com">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Listen port <span class="tag tag-restart">restart</span></div>
                  <div class="hint">После сохранения панель перезагрузится по новой ссылке.</div>
                </div>
                <div class="field-ctrl">
                  <input type="number" id="setPanelPort" min="1" max="65535" class="mono" placeholder="8888">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Base path <span class="tag tag-restart">restart</span></div>
                  <div class="hint">Префикс маршрута. Например <code>/abyss-41de996a</code>; пусто = корень.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="setPanelBasePath" class="mono" placeholder="/abyss-41de996a">
                </div>
              </div>

              <div class="field row-stack">
                <div>
                  <div class="lbl" style="font-size:13.5px;font-weight:600">Panel TLS <span class="tag tag-env">optional</span></div>
                  <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Пара cert+key — панель сама терминирует HTTPS. Пусто = HTTP (через nginx).</div>
                </div>
                <div class="split-2">
                  <input type="text" id="setPanelTlsCert" placeholder="/path/to/cert.pem" class="mono">
                  <input type="text" id="setPanelTlsKey" placeholder="/path/to/key.pem" class="mono">
                </div>
              </div>

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Test target</div>
                  <div class="hint">URL для пробы <em>direct</em> в TEST; HTTP GET; auto-save on blur.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="setTestTarget" class="mono" placeholder="http://www.gstatic.com/generate_204" onblur="saveTestTarget()">
                </div>
              </div>

              <button type="button" class="adv-toggle" id="advPanel">
                Advanced
                <svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
              </button>
              <div class="adv-body" id="advPanelBody">

                <div class="field">
                  <div class="field-lbl">
                    <div class="lbl">Panel admins <span class="tag tag-readonly">local DB</span></div>
                    <div class="hint">Логины панели хранятся в <code>panel_admins</code> как PBKDF2-хэши. Меняются через <code>tamizdat-panel.py --set-admin</code> или install script.</div>
                  </div>
                  <div class="field-ctrl">
                    <input type="text" id="setPanelAdmins" class="mono" readonly>
                  </div>
                </div>

                <div class="field">
                  <div class="field-lbl">
                    <div class="lbl">Managed service <span class="tag tag-env">env-only</span></div>
                    <div class="hint"><code>SERVICE_NAME</code> env — имя systemd-юнита tamizdat-server.</div>
                  </div>
                  <div class="field-ctrl">
                    <input type="text" id="setPanelServiceName" class="mono" readonly>
                  </div>
                </div>

                <div class="field">
                  <div class="field-lbl">
                    <div class="lbl">Panel version <span class="tag tag-readonly">readonly</span></div>
                    <div class="hint">Build info.</div>
                  </div>
                  <div class="field-ctrl">
                    <input type="text" id="setPanelVersion" class="mono" readonly>
                  </div>
                </div>

              </div>

            </div>
          </section>

          <!-- ===== Group: Broadcast ===== -->
          <section class="group" id="g-broadcast">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--warn-soft);color:var(--warn)"><svg viewBox="0 0 24 24"><path d="M3 11l18-8v18l-18-8z"/><line x1="11" y1="11" x2="11" y2="18"/></svg></div>
                <div>
                  <h2>Broadcast notification <span class="group-pill pill-beta">phase C</span></h2>
                  <div class="desc">Покажется ВСЕМ пользователям через bundle при следующем connect.</div>
                </div>
              </div>
            </div>
            <div class="fields">
              <div class="field row-stack">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                  <div class="lbl" style="font-size:13.5px;font-weight:600">Сообщение</div>
                  <span style="font-size:11px;color:var(--muted);font-family:ui-monospace,monospace"><span id="msgLen">0</span> / 512 байт</span>
                </div>
                <textarea id="setBroadcastText" maxlength="512" placeholder="Сервер на профилактике 2026-05-11 03:00 UTC" style="min-height:80px"></textarea>
                <div class="hint" style="font-size:12px;color:var(--muted)">Пусто = очистить очередь у всех.</div>
                <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
                  <button type="button" class="btn-soft" onclick="clearBroadcast()">Clear queue</button>
                  <button type="button" class="btn-soft" style="background:var(--primary);color:#fff;border-color:var(--primary)" onclick="sendBroadcast()">
                    <svg viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                    Send to all
                  </button>
                </div>
              </div>
            </div>
          </section>

          <!-- Group removed 2026-05-25 (operator override). The POST
               /api/reset-all endpoint is preserved for future use. -->

          <!-- ===== Group: User ===== -->
          <section class="group" id="g-user">
            <div class="group-head">
              <div class="group-title">
                <div class="glyph" style="background:var(--mauve-soft);color:var(--mauve)"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></div>
                <div>
                  <h2>User <span class="group-pill pill-self">account</span></h2>
                  <div class="desc">Управление текущим логином панели.</div>
                </div>
              </div>
            </div>
            <div class="fields">

              <div class="field">
                <div class="field-lbl">
                  <div class="lbl">Signed in as</div>
                  <div class="hint">Логин, под которым открыта эта сессия панели.</div>
                </div>
                <div class="field-ctrl">
                  <input type="text" id="setAccountUser" class="mono" readonly>
                </div>
              </div>

              <div class="field row-stack">
                <div>
                  <div class="lbl" style="font-size:13.5px;font-weight:600">Change password</div>
                  <div class="hint" style="font-size:12px;color:var(--muted);margin-top:2px">Пароль хранится как PBKDF2-хэш в <code>panel_admins</code>. Сторонние сессии разлогинятся.</div>
                </div>
                <div class="split-2" style="margin-top:4px">
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Current password</div>
                    <input type="password" id="setAccountCurrent" class="mono" autocomplete="current-password" placeholder="••••••••">
                  </div>
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">New password</div>
                    <input type="password" id="setAccountNew" class="mono" autocomplete="new-password" placeholder="новый пароль">
                  </div>
                </div>
                <div class="split-2" style="margin-top:8px">
                  <div></div>
                  <div>
                    <div style="font-size:11.5px;color:var(--muted);font-weight:600;margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px">Confirm new password</div>
                    <input type="password" id="setAccountConfirm" class="mono" autocomplete="new-password" placeholder="ещё раз">
                  </div>
                </div>
                <div id="setAccountMsg" style="font-size:12px;margin-top:8px;min-height:16px"></div>
                <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
                  <button type="button" class="btn-soft" style="background:var(--primary);color:#fff;border-color:var(--primary)" onclick="changeAccountPassword()">
                    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Update password
                  </button>
                </div>
              </div>

            </div>
          </section>

        </div>
      </div>

    </section>
    <!-- ============ /Settings page ============ -->

    <!-- ============ Sticky save bar (only visible on Settings) ============ -->
    <div class="save-bar" id="saveBar">
      <span class="sb-dot"></span>
      <div class="sb-info">
        Unsaved changes
        <span class="sb-changes"><span id="changeCount">0</span> fields modified</span>
      </div>
      <div class="sb-spacer"></div>
      <button type="button" class="sb-btn sb-discard" id="btnDiscard">Discard</button>
      <button type="button" class="sb-btn sb-save" id="btnSave">
        <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
        Save all
      </button>
    </div>

  </main>
</div>

<!-- ============ QR Modal ============ -->
<div class="modal-bg" id="qrModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="text-align:center">
    <h3 id="qrTitle"></h3>
    <div class="modal-sub">Scan or copy this URI for the client.</div>
    <div id="qrTabs" style="display:flex;gap:6px;justify-content:center;margin-bottom:6px"></div>
    <div id="qrImage"></div>
    <div class="uri-text" id="qrUri"></div>
    <div class="modal-foot" style="justify-content:center">
      <button class="btn btn-primary" onclick="copyText(gid('qrUri').textContent)">
        <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy URI
      </button>
      <button class="btn btn-ghost" onclick="gid('qrModal').classList.remove('show')">Close</button>
    </div>
  </div>
</div>

<!-- ============ Add User Modal ============ -->
<div class="modal-bg" id="addUserModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3>New user</h3>
    <div class="modal-sub">Создать нового пользователя со своим shortid.</div>
    <label>Имя</label><input type="text" id="addUserName" placeholder="petrov">
    <label>H2 transports <span style="color:var(--muted);font-weight:400">(1..4; server opens this many parallel H2 pipes per user)</span></label>
    <select id="addUserPoolSize">
      <option value="1">1</option>
      <option value="2">2</option>
      <option value="3">3</option>
      <option value="4">4</option>
    </select>
    <label>Quota <span style="color:var(--muted);font-weight:400">(пусто = unlimited; rolling 30-day window)</span></label>
    <div class="quota-input-row">
      <input type="number" id="addUserQuotaValue" min="0" step="0.1" placeholder="0">
      <select id="addUserQuotaUnit">
        <option value="MB">MB</option>
        <option value="GB" selected>GB</option>
        <option value="TB">TB</option>
      </select>
    </div>
    <label>Expires at <span style="color:var(--muted);font-weight:400">(date, или пусто)</span></label><input type="date" id="addUserExpires">
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('addUserModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" onclick="submitAddUser()">Create user</button>
    </div>
  </div>
</div>

<!-- ============ Confirm Dialog (native confirm() replacement) ============ -->
<div class="modal-bg" id="confirmDialog" onclick="if(event.target===this)_confirmResolve(false)">
  <div class="modal confirm-dialog">
    <h4 id="confirmTitle"></h4>
    <div class="confirm-msg" id="confirmMsg"></div>
    <div class="modal-foot">
      <button class="btn btn-ghost" id="confirmCancelBtn" onclick="_confirmResolve(false)"></button>
      <button class="btn btn-primary" id="confirmOkBtn" onclick="_confirmResolve(true)"></button>
    </div>
  </div>
</div>

<!-- ============ Edit User Modal ============ -->
<div class="modal-bg" id="editModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3>Edit user</h3>
    <input type="hidden" id="editOld">
    <label>Имя</label><input type="text" id="editName">
    <label>H2 transports <span style="color:var(--muted);font-weight:400">(1..4; server opens this many parallel H2 pipes per user)</span></label>
    <select id="editPoolSize">
      <option value="1">1</option>
      <option value="2">2</option>
      <option value="3">3</option>
      <option value="4">4</option>
    </select>
    <label>Quota <span style="color:var(--muted);font-weight:400">(пусто = unlimited; rolling 30-day window)</span></label>
    <div class="quota-input-row">
      <input type="number" id="editQuotaValue" min="0" step="0.1" placeholder="0">
      <select id="editQuotaUnit">
        <option value="MB">MB</option>
        <option value="GB">GB</option>
        <option value="TB">TB</option>
      </select>
    </div>
    <label>Rate limit <span style="color:var(--muted);font-weight:400">(Mbit/s, пусто или 0 = unlimited)</span></label>
    <input type="number" id="editRateMbps" min="0" step="1" placeholder="0">
    <label>Expires at</label><input type="date" id="editExpires">
    <label>Notification <span style="color:var(--muted);font-weight:400;font-size:12px">(до 512 байт; покажется клиенту через bundle при следующем connect; пусто = очистить)</span></label>
    <textarea id="editNotification" maxlength="512" placeholder="" style="min-height:48px;font-size:13px;width:100%;box-sizing:border-box;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);resize:vertical"></textarea>
    <label>VK TURN room <span style="color:var(--muted);font-weight:400;font-size:12px">(вставьте ссылку/хэш VK комнаты; клиент получит через H2 или TURN и обновит поля автоматически)</span></label>
    <div style="display:flex;gap:8px;align-items:center">
      <input type="text" id="editTurnRoom" placeholder="https://vk.com/call/join/..." style="flex:1;min-width:0">
      <button type="button" class="btn btn-ghost" onclick="pushTurnRoomFromEdit()">Send</button>
    </div>
    <div class="cell-meta" id="editTurnRoomStatus" style="margin-top:4px"></div>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('editModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" onclick="saveEdit()">Save changes</button>
    </div>
  </div>
</div>

<!-- ============ Edit Direct Outbound Modal ============ -->
<div class="modal-bg" id="obEditDirectModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3>Edit direct outbound</h3>
    <p style="color:var(--muted);font-size:13px;margin:0 0 14px">Direct outbound uses the server's default route. Pin to a specific interface (multi-IP boxes, amnezia/wireguard tunnels) so this outbound's traffic exits via that NIC. Empty = OS default route.</p>
    <label>Bind to interface</label>
    <select id="obDirectIface">
      <option value="">— OS default route —</option>
    </select>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('obEditDirectModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" onclick="saveDirectOutbound()">Save</button>
    </div>
  </div>
</div>

<!-- ============ Add Balancer Outbound Modal ============ -->
<div class="modal-bg" id="addBalancerModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3 id="balModalTitle">Add balancer outbound</h3>
    <div class="modal-sub">Create or edit an outbound that tries existing outbounds as a group. Nested balancers are intentionally not selectable.</div>
    <input type="hidden" id="balOldTag">
    <label>Tag</label><input type="text" id="balTag" placeholder="balancer">
    <label>Mode</label>
    <select id="balMode">
      <option value="alive">First alive / failover</option>
      <option value="round_robin">Round robin</option>
    </select>
    <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
      <input type="checkbox" id="balHighRttEnabled" style="width:auto;margin:0">
      Switch when selected outbound RTT is high
    </label>
    <label>RTT threshold, ms</label><input type="number" id="balRttThresholdMs" min="1" step="1" placeholder="750">
    <div class="help" style="margin-top:6px">Uses the continuously sampled outbound tunnel RTT. Above threshold, the member is skipped behind in-threshold backups; it returns when RTT drops below ~90% of threshold. If all members are high RTT, the fastest one is tried first.</div>
    <label>Members</label>
    <div id="balMembers" class="bal-member-list"></div>
    <label>Priority order <span style="color:var(--muted);font-weight:400">(#1 is tried first)</span></label>
    <div id="balOrder" class="bal-order-list"></div>
    <div class="help" style="margin-top:8px">Выбери members выше и выставь порядок стрелками. First alive / failover всегда пробует #1 первым и переходит к следующему только при ошибке; round robin вращает стартовую точку.</div>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('addBalancerModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" id="balSubmitBtn" onclick="submitAddBalancer()">Create balancer</button>
    </div>
  </div>
</div>

<!-- ============ Edit Outbound Modal ============ -->
<div class="modal-bg" id="obEditModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3 id="obEditTitle">Edit Outbound</h3>
    <input type="hidden" id="obEditOldTag">
    <input type="hidden" id="obEditType" value="tamizdat">
    <label>Tag</label><input type="text" id="obEditTag">
    <label id="obEditUriLabel">Tamizdat URI</label><textarea id="obEditUri" style="font-family:ui-monospace,monospace;font-size:12px;min-height:90px" placeholder="tamizdat://host:port/?sni=…&pubkey=…&shortid=…&fp=mix"></textarea>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('obEditModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" onclick="saveOutbound()">Save</button>
    </div>
  </div>
</div>

<!-- ============ Geo Help Modal ============ -->
<div class="modal-bg" id="geoHelpModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="max-width:600px">
    <h3 id="geoHelpTitle">Готовые наборы</h3>
    <p style="color:var(--muted);font-size:13px;margin:0 0 10px">Поиск по live-распарсенным <code>geoip*.dat</code> / <code>geosite*.dat</code> на сервере. Клик «Use» — добавляет в поле, окно остаётся открытым; уже добавленные помечены ✓. URL источников: Settings → GeoIP URL / Geosite URL.</p>
    <input type="text" id="geoHelpSearch" placeholder="Поиск: blocked, ru, google, telegram, category-bank, ..." style="width:100%;padding:9px;font-size:13.5px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px" autocomplete="off">
    <div id="geoHelpCount" style="color:var(--muted);font-size:11.5px;margin-bottom:6px"></div>
    <div id="geoPresetList" style="max-height:50vh;overflow-y:auto"></div>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('geoHelpModal').classList.remove('show')">Close</button>
    </div>
  </div>
</div>

<!-- ============ Routing Rule Modal ============ -->
<div class="modal-bg" id="ruleModal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="max-width:560px">
    <h3 id="ruleModalTitle">Add routing rule</h3>
    <div class="modal-sub">Match-criteria: AND across categories, OR within each list. First match wins.</div>
    <input type="hidden" id="ruleId">
    <label>Folder <span style="color:var(--muted);font-weight:400">(папка — все правила в папке двигаются вместе при reorder; пусто = ungrouped)</span></label>
    <select id="ruleFolderSel" style="width:100%;padding:9px;font-size:13.5px"></select>
    <input type="hidden" id="ruleGroup" value="">
    <label>Description override <span style="color:var(--muted);font-weight:400">(пусто = авто из match-полей)</span></label>
    <input type="text" id="ruleDesc" placeholder="auto">
    <div class="label-with-help">
      <label style="margin:0">GeoIP <span style="color:var(--muted);font-weight:400">(comma list — <code>telegram,private,google</code>; формат: <code>geoip:NAME</code> в правилах сервера)</span></label>
      <button type="button" class="help-btn" onclick="openGeoHelp('geoip')" title="Показать готовые наборы">?</button>
    </div>
    <input type="text" id="ruleGeoIP" placeholder="telegram, private">
    <div class="label-with-help">
      <label style="margin:0">Geosite <span style="color:var(--muted);font-weight:400">(comma list — <code>openai, ads</code>; формат: <code>geosite:NAME</code>)</span></label>
      <button type="button" class="help-btn" onclick="openGeoHelp('geosite')" title="Показать готовые наборы">?</button>
    </div>
    <input type="text" id="ruleGeosite" placeholder="openai">
    <label>IP CIDR <span style="color:var(--muted);font-weight:400">(comma list — <code>10.0.0.0/8, 1.1.1.1/32</code>)</span></label>
    <input type="text" id="ruleIP" placeholder="10.0.0.0/8">
    <label>Domain <span style="color:var(--muted);font-weight:400">(comma list — <code>example.com, domain:foo.com, regexp:^x</code>)</span></label>
    <input type="text" id="ruleDomain" placeholder="example.com">
    <label>User <span style="color:var(--muted);font-weight:400">(comma list of usernames; пусто = все)</span></label>
    <input type="text" id="ruleUser" placeholder="alice, bob">
    <label>Source CIDR <span style="color:var(--muted);font-weight:400">(client peer IP)</span></label>
    <input type="text" id="ruleSource" placeholder="192.168.1.0/24">
    <label>Port</label>
    <input type="text" id="rulePort" placeholder="443 or 80,443 or 1000-2000">
    <label>Network</label>
    <select id="ruleNetwork">
      <option value="">tcp+udp (any)</option>
      <option value="tcp">tcp</option>
      <option value="udp">udp</option>
    </select>
    <label>Inbound tag <span style="color:var(--muted);font-weight:400">(comma list)</span></label>
    <input type="text" id="ruleInbound" placeholder="tamizdat-in">
    <label>Outbound</label>
    <select id="ruleOutbound" class="user-ob-sel" style="width:100%;min-width:0;padding-top:9px;padding-bottom:9px;font-size:13.5px"></select>
    <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input type="checkbox" id="ruleEnabled" checked style="width:auto"> Enabled</label>
    <div class="modal-foot">
      <button class="btn btn-ghost" onclick="gid('ruleModal').classList.remove('show')">Cancel</button>
      <button class="btn btn-primary" onclick="saveRoutingRule()">Save</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script src="QRCODE_SRC_URL"></script>
<!-- Sortable.js 1.15.6 vendored inline; the marker on the next line is
     replaced server-side in do_GET with the contents of SORTABLE_JS_INLINE
     (45 KB minified). Marker chosen so it cannot accidentally collide
     with anything in the upstream JS. -->
<script>__SORTABLE_JS_INLINE_MARKER__</script>
<script>
const H = location.origin + location.pathname.replace(/\/+$/,'');

// Mobile nav drawer toggle (≤860px). On desktop the .burger is display:none
// and toggleNav is a no-op visually. Force-arg lets routes call
// toggleNav(false) to close after navigation regardless of current state.
function toggleNav(force){
  const burger = document.getElementById('navBurger');
  const open = (typeof force === 'boolean')
    ? force
    : !document.body.classList.contains('nav-open');
  document.body.classList.toggle('nav-open', open);
  if(burger) burger.setAttribute('aria-expanded', String(open));
  if(open){
    // Move focus into the first nav item for keyboard users.
    const first = document.querySelector('.nav a');
    if(first) first.focus({preventScroll:true});
  } else if(burger){
    burger.focus({preventScroll:true});
  }
}
// Escape closes the drawer.
document.addEventListener('keydown', e => {
  if(e.key === 'Escape' && document.body.classList.contains('nav-open')){
    toggleNav(false);
  }
});
// Close drawer after a route click.
document.addEventListener('click', e => {
  if(e.target.closest('.nav a')) toggleNav(false);
});
const gid = id => document.getElementById(id);
let users = [], outbounds = [], activeOb = 'direct', userStats = {};
let _lastIps = {};
// _obLatency persists across F5 via localStorage with a 5-min TTL.
// Operator-reported 2026-05-11: previously a plain JS object, every page
// reload wiped the column. Now we hydrate from localStorage on init and
// rewrite on each probe. Stale entries (>300s old) are dropped silently
// so the column shows "—" instead of misleading 30-min-old latency.
const _OB_LATENCY_LS_KEY = 'tamizdat.obLatency.v1';
const _OB_LATENCY_TTL_MS = 5 * 60 * 1000;
let _obLatency = (function(){
  try {
    const raw = localStorage.getItem(_OB_LATENCY_LS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    const now = Date.now();
    const out = {};
    for (const k in parsed) {
      const v = parsed[k];
      if (v && typeof v === 'object' && (now - (v.time || 0)) < _OB_LATENCY_TTL_MS) {
        out[k] = v;
      }
    }
    return out;
  } catch (e) { return {}; }
})();
function _persistObLatency(){
  try { localStorage.setItem(_OB_LATENCY_LS_KEY, JSON.stringify(_obLatency)); } catch (e) {}
}
let _pending = {};

function toast(m){const t=gid('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}

// Modal click-outside-to-close: don't fire when the mousedown started INSIDE
// the modal content and the cursor was dragged out onto the backdrop (typical
// text-selection that ends past the modal edge). Without this, every drag
// past the edge slammed the modal shut mid-selection (operator-reported,
// 2026-05-11). Capture-phase + stopImmediatePropagation suppresses the
// pre-existing inline `onclick="if(event.target===this)…"` handlers without
// having to touch every modal individually.
document.addEventListener('mousedown', function(e){
  const bg = e.target.closest && e.target.closest('.modal-bg');
  if (bg) bg._mouseDownTarget = e.target;
}, true);
document.addEventListener('click', function(e){
  const bg = e.target.closest && e.target.closest('.modal-bg');
  if (!bg) return;
  // Only intervene on backdrop-target clicks (the close-trigger). If mousedown
  // was inside content (not on backdrop itself), this click is the tail end of
  // a drag-select — keep the modal open.
  if (e.target === bg && bg._mouseDownTarget && bg._mouseDownTarget !== bg) {
    e.stopImmediatePropagation();
  }
  bg._mouseDownTarget = null;
}, true);

let _confirmResolveFn = null;
function _confirmResolve(v){
  if(!_confirmResolveFn) return;
  const f = _confirmResolveFn; _confirmResolveFn = null;
  gid('confirmDialog').classList.remove('show');
  document.removeEventListener('keydown', _confirmKeyHandler);
  f(v);
}
function _confirmKeyHandler(e){
  if(e.key === 'Escape') _confirmResolve(false);
  else if(e.key === 'Enter') _confirmResolve(true);
}
// In-page replacement for window.confirm. Returns a Promise<bool>.
//   await confirmDialog({title, message, ok='OK', cancel='Cancel', danger=false})
function confirmDialog(opts){
  opts = opts || {};
  return new Promise(resolve => {
    _confirmResolveFn = resolve;
    gid('confirmTitle').textContent = opts.title || 'Confirm';
    gid('confirmMsg').textContent   = opts.message || '';
    gid('confirmOkBtn').textContent     = opts.ok || 'OK';
    gid('confirmCancelBtn').textContent = opts.cancel || 'Cancel';
    const okBtn = gid('confirmOkBtn');
    okBtn.classList.toggle('btn-danger', !!opts.danger);
    okBtn.classList.toggle('btn-primary', !opts.danger);
    gid('confirmDialog').classList.add('show');
    document.addEventListener('keydown', _confirmKeyHandler);
    setTimeout(() => okBtn.focus(), 50);
  });
}
// Copy-to-clipboard with HTTP-safe fallback. navigator.clipboard.writeText
// is gated on Secure Context (HTTPS or localhost); on a plain http://
// panel it can be undefined OR return a Promise that rejects with no
// useful error. We try the Promise path first, and on ANY failure
// (sync TypeError, async reject) drop down to the textarea+execCommand
// trick — which still works on Firefox/Chrome HTTP as long as it runs
// inside a user-gesture handler (the onclick that calls us is one).
function copyText(t){
  const fallback = () => {
    const a = document.createElement('textarea');
    a.value = t;
    a.setAttribute('readonly','');
    a.style.position = 'fixed';
    a.style.top = '0';
    a.style.left = '0';
    a.style.opacity = '0';
    document.body.appendChild(a);
    a.focus();
    a.select();
    a.setSelectionRange(0, t.length);
    let ok = false;
    try { ok = document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(a);
    toast(ok ? 'Copied!' : 'Copy failed — long-press the URI to select manually');
  };
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(t)
        .then(() => toast('Copied!'))
        .catch(() => fallback());
      return;
    }
  } catch(e) {}
  fallback();
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function fb(b){
  // Bytes formatter. Operator policy (2026-05-10): values < 1 GB hide the
  // decimal fraction (KB/MB rendered as integers; GB and TB keep one
  // decimal). Cuts visual noise in Traffic + Quota cells where ".0" /
  // ".4" carry no useful information at MB resolution.
  if(!b||b===0)return'0 B';
  const u=['B','KB','MB','GB','TB'];
  const i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),u.length-1);
  const decimals = i >= 3 ? 1 : 0;   // GB(3), TB(4) get .X; B/KB/MB do not.
  return (b/Math.pow(1024,i)).toFixed(decimals)+' '+u[i];
}
function protoBadge(t){return `<span class="proto-badge proto-${t}">${t}</span>`}

// Pill for an outbound TAG (e.g. "outbound-example") in routing-rule rows: always
// returns a styled pill, colored by the OUTBOUND'S underlying protocol
// kind (tamizdat/direct/...), so every tag gets a consistent background.
// Falls back to a neutral surface tone when the outbounds list hasn't
// loaded yet or the tag is missing (orphaned rule).
function outboundBadge(tag){
  if(!tag) return '<span class="proto-badge proto-unknown">—</span>';
  const o = (typeof outbounds !== 'undefined' && Array.isArray(outbounds))
    ? outbounds.find(x => x.tag === tag) : null;
  const kind = o ? (o.kind || o.type || 'unknown') : (tag === 'direct' ? 'direct' : 'unknown');
  return `<span class="proto-badge proto-${esc(kind)}" title="${esc(tag)} (${esc(kind)})">${esc(tag)}</span>`;
}
function latencyBadge(tag){
  const l=_obLatency[tag];
  if(!l) return '';                                          // no probe yet → cell shows —
  if(l.ms===-2) return '<span class="ob-latency" style="color:var(--muted)">testing…</span>';
  if(l.ms===0)  return '<span class="ob-latency" style="color:var(--muted)">n/a</span>';
  if(l.ms<0)    return '<span class="ob-latency" style="color:var(--danger)">error</span>';
  const c=l.ms<300?'var(--primary)':l.ms<1000?'var(--warn)':'var(--danger)';
  return `<span class="ob-latency" style="color:${c}">${l.ms}ms</span>`;
}

// obSelectHtml + setUserOutbound removed in panel-cleanup CL-3 (2026-05-10):
// the legacy per-user "outbound pin" selector was already dead code (no
// renderer called obSelectHtml). Operator confirmed users should not be
// pinned to outbounds via user settings — routing rules are the only
// mechanism for outbound selection. The users.outbound_tag column +
// PUT /api/users/<id> outbound_tag handler stay in place because the
// schema is shared with the Go server (internal/userdb/registry.go) —
// the panel just stops surfacing the selector.

function statusDots(u){
  // Online detection has two signals:
  //   - online_sessions: count of user_sessions rows updated in last 90s. Reliable
  //     for long-lived TUN connections, unreliable for SOCKS+browser where each
  //     H2/HTTP stream creates a short TLS connection that ends quickly.
  //   - last_seen_at: every server-side bytes flush bumps it. If <90s ago, the
  //     user almost certainly has at least one active flow, even if the session
  //     row was deleted between flushes.
  const n = u.online_sessions || 0;
  const lastSeen = u.last_seen_at || 0;
  const ageSec = lastSeen ? (Math.floor(Date.now()/1000) - lastSeen) : Infinity;
  const recentlyActive = n === 0 && lastSeen > 0 && ageSec <= 5;
  const expired = u.expires_at && (u.expires_at*1000 < Date.now());
  const tr = (u.active_transport || '').toLowerCase();
  const badge = (tr === 'turn' || tr === 'h2')
    ? '<span class="transport-badge '+tr+'">'+tr.toUpperCase()+'</span>'
    : '';
  const dotClass = expired ? 'expired' : ((n > 0 || recentlyActive) ? 'on' : 'off');
  const title = expired ? 'expired' : (n > 0 ? n + ' active session(s)' : (recentlyActive ? 'active '+ageSec+'s ago' : 'offline'));
  if(n === 0 && !recentlyActive){
    return '<span class="status-cell"><span class="status-dots"><span class="online-dot '+dotClass+'" title="'+title+'"></span></span>'+badge+'</span>';
  }
  let dots = '';
  const count = Math.min(n || 1, 4);
  for(let i=0;i<count;i++) dots += '<span class="online-dot on" title="' + title + '"></span>';
  return '<span class="status-cell"><span class="status-dots">'+dots+'</span>'+badge+'</span>';
}

function fmtBytes(b){return fb(b||0)}

function fmtExpires(t){
  if(!t || t === 0) return 'never';
  return new Date(t*1000).toLocaleDateString();
}

function fmtDateTime(t){
  if(!t || t === 0) return '';
  return new Date(t*1000).toLocaleString();
}

function fmtBandwidth(cap){
  if(!cap || cap === 0) return 'unlimited';
  // BandwidthCap is the rolling 30-day quota total (multi-user-cleanup
  // I-4); the legacy /day suffix would mislead. Render as "X / 30d".
  return fmtBytes(cap)+' / 30d';
}

function quotaBar(u){
  // Renders a usage bar widget X GB / Y GB for users with a BandwidthCap.
  // Shows red + "burned" tag when notification_pending is set (server
  // flipped it on a recent over-quota auth-time reject). Returns empty
  // string for unlimited users so the column does not bloat.
  //
  // quota-reset-split (2026-05-10): the bar uses
  //   used = max(0, bytes_up+bytes_down - quota_baseline)
  // so the operator's "Reset Quota" button (which sets baseline =
  // current total) restarts the bar from 0 while the lifetime ↓↑ display
  // in the Traffic column keeps showing the full bytes_up/bytes_down.
  if(!u.bandwidth_cap) return '';
  const baseline = u.quota_baseline || 0;
  const used = Math.max(0, (u.bytes_up||0) + (u.bytes_down||0) - baseline);
  const cap = u.bandwidth_cap;
  const pct = Math.min(100, Math.floor(100*used/cap));
  const over = used >= cap;
  const burned = u.notification_pending;
  // Three-state precedence:
  //   - burned (server-confirmed reject + push-pending) — strongest signal
  //   - blocked (used >= cap, server WILL reject next auth even if user has not tried yet)
  //   - warn (>=90%) — soft heads-up
  let cls, tag;
  if(burned){
    cls = 'quota-bar burned'; tag = ' <span class="quota-tag burned">burned</span>';
  } else if(over){
    cls = 'quota-bar burned'; tag = ' <span class="quota-tag burned">blocked</span>';
  } else if(pct >= 90){
    cls = 'quota-bar warn'; tag = '';
  } else {
    cls = 'quota-bar'; tag = '';
  }
  return '<div class="'+cls+'" title="'+pct+'% of 30-day cap"><div class="quota-fill" style="width:'+pct+'%"></div></div>'
    + '<div class="cell-meta">'+fmtBytes(used)+' / '+fmtBytes(cap)+tag+'</div>';
}

function renderUsers(){
  const el=gid('userTable');
  const ae=document.activeElement;
  if(ae && (ae.tagName==='SELECT' || ae.tagName==='INPUT') && el.contains(ae)) return;
  if(!users.length){el.innerHTML='<div class="status">No users yet — click <b>+ Add user</b></div>';return}
  let h='<table><thead><tr><th style="width:120px">Status</th><th>Name</th><th>Traffic</th><th>Streams</th><th>Limits</th><th style="text-align:right">Actions</th></tr></thead><tbody>';
  for(const u of users){
    const dl = fmtBytes(u.bytes_down);
    const ul = fmtBytes(u.bytes_up);
    h += '<tr class="profile-row">';
    h += `<td>${statusDots(u)}</td>`;
    h += `<td><span class="user-name">${esc(u.name)}</span></td>`;
    // Traffic cell: lifetime ↓↑ counters + small 🔄 icon-button that
    // hard-zeros bytes_up/bytes_down/quota_baseline (the OLD reset-bytes
    // semantic). The everyday "unblock without erasing" affordance lives
    // in the Limits column below.
    h += `<td><span class="traf"><span class="traf-d">↓ ${dl}</span><span class="traf-u">↑ ${ul}</span></span><button class="btn-icon-sm" onclick="resetUserBytes('${esc(u.id)}')" title="Reset traffic counters to zero (clears ↓↑ display)">↻</button></td>`;
    const streamPeakTCP = u.h2_peak_tcp_streams || 0;
    const streamPeakUDP = u.h2_peak_udp_streams || 0;
    const streamLiveTCP = u.h2_live_tcp_streams || 0;
    const streamLiveUDP = u.h2_live_udp_streams || 0;
    const streamWhen = u.h2_peak_at ? `<div class="cell-meta">${esc(fmtDateTime(u.h2_peak_at))}</div>` : '';
    const h2Transports = Math.max(1, u.pool_size || 1);
    h += `<td title="Actual concurrent inbound H2 streams for this user. Use this for H2 stream cap sizing.">
      <div><span class="cell-meta" style="font-weight:700;color:var(--text)">MAX</span> <span class="cell-meta">tcp ${streamPeakTCP} / udp ${streamPeakUDP}</span></div>
      ${streamWhen}
      <div class="cell-meta">H2 transports ${h2Transports}</div>
      <div style="margin-top:5px"><span class="cell-meta" style="font-weight:700;color:var(--text)">LIVE</span> <span class="cell-meta">tcp ${streamLiveTCP} / udp ${streamLiveUDP}</span></div>
    </td>`;
    const exp = u.expires_at ? '<div class="cell-meta">expires '+esc(fmtExpires(u.expires_at))+'</div>' : '';
    const cap = u.bandwidth_cap ? '<div class="cell-meta">cap '+esc(fmtBandwidth(u.bandwidth_cap))+'</div>' : '';
    const bar = quotaBar(u);
    // "Reset Quota" pill: only meaningful for capped users. Sets
    // quota_baseline = current bytes total so the rolling-window cap
    // restarts from a clean slate while the lifetime traffic display
    // (rendered above) is preserved.
    const resetBtn = u.bandwidth_cap ? `<div class="reset-row"><button class="btn btn-reset" onclick="resetUserQuota('${esc(u.id)}')" title="Restart quota window without erasing traffic stats">Reset Quota</button></div>` : '';
    const limitsBody = (exp||cap||bar) ? (exp+cap+bar) : '<span class="cell-meta empty">no limits</span>';
    h += `<td>${limitsBody}${resetBtn}</td>`;
    h += `<td><div class="actions">
      <button class="btn btn-edit btn-sm" onclick="editUser('${esc(u.id)}')">Edit</button>
      <button class="btn btn-qr btn-sm" onclick="showUserUri('${esc(u.id)}')">URI</button>
      <button class="btn btn-del btn-sm" onclick="delUser('${esc(u.id)}')">Del</button>
    </div></td></tr>`;
  }
  el.innerHTML=h+'</tbody></table>';
}

function _updateStats(){
  // Update stat cards
  const total = users.length;
  const online = users.reduce((acc,u)=>acc + (u.online_sessions||0), 0);
  const dl = users.reduce((a,u)=>a+(u.bytes_down||0),0);
  const ul = users.reduce((a,u)=>a+(u.bytes_up||0),0);
  const elU = gid('statUsers');
  if(elU) elU.innerHTML = online + ' <small>online / ' + total + ' total</small>';
  const elT = gid('statTraffic');
  if(elT) elT.innerHTML = '↓'+fb(dl)+' <small>↑'+fb(ul)+'</small>';
  const elO = gid('statOutbounds');
  if(elO) elO.innerHTML = outbounds.length + ' <small>configured</small>';
  // Header pill counts
  const cnts = gid('userCounts');
  if(cnts) cnts.textContent = online+' / '+total;
}

// ---- Resource rings (CPU / RAM / Swap / Disk) ----
function _setRing(arcId, pctId, pct, label, labelId){
  const arc = gid(arcId);
  if(arc){
    arc.setAttribute('stroke-dasharray', pct.toFixed(2)+',100');
    arc.classList.toggle('warn', pct >= 75 && pct < 90);
    arc.classList.toggle('crit', pct >= 90);
  }
  const tx = gid(pctId);
  if(tx) tx.textContent = pct.toFixed(2)+'%';
  if(labelId){
    const lb = gid(labelId);
    if(lb) lb.textContent = label;
  }
}

async function loadSysinfo(){
  try{
    const r = await fetch(H+'/api/sysinfo?t='+Date.now(), {cache:'no-store'});
    if(!r.ok) return;
    const d = await r.json();
    _setRing('resCpuArc',  'resCpuPct',  d.cpu_pct  || 0, null,                                             null);
    _setRing('resMemArc',  'resMemPct',  d.mem_pct  || 0, 'память: '+fb(d.mem_used)+' / '+fb(d.mem_total), 'resMemLabel');
    _setRing('resSwapArc', 'resSwapPct', d.swap_pct || 0, 'Swap: '+fb(d.swap_used)+' / '+fb(d.swap_total), 'resSwapLabel');
    _setRing('resDiskArc', 'resDiskPct', d.disk_pct || 0, 'жесткий диск: '+fb(d.disk_used)+' / '+fb(d.disk_total), 'resDiskLabel');
  }catch(e){}
}

// CPU-only refresh — much cheaper than the full /api/sysinfo (skips
// /proc/meminfo parsing + statvfs syscall + JSON for 9 fields). Used by the
// 500 ms fast-tick so the CPU gauge feels responsive without paying the
// memory/disk read cost every half-second.
async function loadCpuOnly(){
  try{
    const r = await fetch(H+'/api/sysinfo/cpu?t='+Date.now(), {cache:'no-store'});
    if(!r.ok) return;
    const d = await r.json();
    _setRing('resCpuArc', 'resCpuPct', d.cpu_pct || 0, null, null);
  }catch(e){}
}

// Two-tier polling: CPU updates every 500 ms so the operator can see real
// activity spikes; RAM/Swap/Disk only every 5 s since they change slowly
// and the syscalls for them (statvfs + /proc/meminfo parse) are heavier.
// Both are paused via the document.hidden check so a backgrounded tab
// doesn't burn the panel's CPU budget.
let _sysinfoTimer = null;
let _sysinfoCpuTimer = null;
function _startSysinfo(){
  if(_sysinfoTimer) return;
  loadSysinfo();                                     // first sample (everything)
  _sysinfoTimer = setInterval(()=>{
    if(!document.hidden) loadSysinfo();
  }, 5000);
  _sysinfoCpuTimer = setInterval(()=>{
    if(!document.hidden) loadCpuOnly();
  }, 500);
}

async function loadUsers(){
  try{
    const r=await fetch(H+'/api/users?t='+Date.now());
    if(r.status===401){location.reload();return}
    const d=await r.json();
    users = d.users || [];
    renderUsers();
    _updateStats();
  }catch(e){}
}

// Bytes per unit. _UNIT_ORDER drives best-fit auto-pick when prefilling
// from an existing bytes value.
const _QUOTA_UNIT_BYTES = {MB: 1048576, GB: 1073741824, TB: 1099511627776};
const _QUOTA_UNIT_ORDER = ['TB', 'GB', 'MB'];

// bytesToQuotaParts: convert an int byte count to {value, unit} for the
// modal inputs. Picks the largest unit that yields a reasonable display
// (whole multiple if possible; otherwise 1-decimal).
function bytesToQuotaParts(bytes){
  if(!bytes || bytes <= 0) return {value:'', unit:'GB'};
  for(const u of _QUOTA_UNIT_ORDER){
    const m = _QUOTA_UNIT_BYTES[u];
    if(bytes >= m){
      const exact = bytes / m;
      // If exact divisor → integer display; else 1-decimal.
      if(bytes % m === 0) return {value: String(exact), unit: u};
      return {value: exact.toFixed(1), unit: u};
    }
  }
  // Below 1 MB: keep MB with decimals.
  return {value: (bytes/_QUOTA_UNIT_BYTES.MB).toFixed(2), unit:'MB'};
}

// quotaPartsToBytes: parse modal inputs to int byte count. Empty / 0 / NaN
// returns 0 → caller treats as "unlimited".
function quotaPartsToBytes(valueStr, unit){
  const v = parseFloat(String(valueStr || '').trim());
  if(isNaN(v) || v <= 0) return 0;
  const m = _QUOTA_UNIT_BYTES[unit] || _QUOTA_UNIT_BYTES.MB;
  return Math.floor(v * m);
}

function openAddUser(){
  gid('addUserName').value='';
  const defaultPool = gid('tamPoolSizeDefault') ? parseInt(gid('tamPoolSizeDefault').value || '1', 10) || 1 : 1;
  gid('addUserPoolSize').value = String(Math.min(4, Math.max(1, defaultPool)));
  gid('addUserQuotaValue').value='';
  gid('addUserQuotaUnit').value='GB';
  gid('addUserExpires').value='';
  gid('addUserModal').classList.add('show');
}

async function submitAddUser(){
  const name = gid('addUserName').value.trim();
  if(!name){toast('Введите имя');return}
  const expRaw = gid('addUserExpires').value.trim();
  const body = { name, pool_size: parseInt(gid('addUserPoolSize').value || '1', 10) || 1 };
  if(expRaw){
    const t = Math.floor(new Date(expRaw).getTime()/1000);
    if(!isNaN(t)) body.expires_at = t;
  }
  const capBytes = quotaPartsToBytes(gid('addUserQuotaValue').value, gid('addUserQuotaUnit').value);
  if(capBytes > 0) body.bandwidth_cap = capBytes;
  try{
    const r = await fetch(H+'/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    gid('addUserModal').classList.remove('show');
    toast('Created: '+name);
    if(d.uri){
      gid('qrTitle').textContent = name;
      gid('qrTabs').innerHTML = '';
      _renderQrFor(d.uri);
      gid('qrModal').classList.add('show');
    }
    loadUsers();
  }catch(e){toast('Error: '+e)}
}

// setUserOutbound removed in panel-cleanup CL-3 — see comment above
// where obSelectHtml used to live.

async function delUser(uid){
  const u = users.find(x => x.id === uid);
  if(!u) return;
  if(!await confirmDialog({title:'Delete user',message:'Delete '+u.name+'?',ok:'Delete',danger:true})) return;
  await fetch(H+'/api/users/'+encodeURIComponent(uid),{method:'DELETE'});
  toast('Deleted');
  loadUsers();
}

async function resetUserBytes(uid){
  // 🔄 icon next to the Traffic ↓↑ counters: hard-zero bytes_up,
  // bytes_down AND quota_baseline. Visible drop in the lifetime ticker;
  // operator should reach for resetUserQuota below for the everyday
  // "unblock without erasing" path.
  const u = users.find(x => x.id === uid);
  if(!u) return;
  if(!await confirmDialog({title:'Zero traffic counters?',message:'Zero traffic counters for '+u.name+'?\n\nThis erases the lifetime ↓↑ display. Use "Reset Quota" instead if you only want to unblock a capped user without losing the traffic history.',ok:'Zero counters',danger:true})) return;
  await fetch(H+'/api/users/'+encodeURIComponent(uid)+'/reset-bytes',{method:'POST'});
  toast('Traffic counters zeroed');
  loadUsers();
}

async function resetUserQuota(uid){
  // "Reset Quota" pill in the Limits column: stamps quota_baseline =
  // current bytes_up+bytes_down so the over-quota check (which subtracts
  // the baseline) restarts from a clean slate. Lifetime ↓↑ stays visible.
  const u = users.find(x => x.id === uid);
  if(!u) return;
  if(!await confirmDialog({title:'Reset 30-day quota?',message:'Reset quota for '+u.name+'?\n\nUnblocks the user; lifetime traffic stats stay visible.',ok:'Reset quota'})) return;
  await fetch(H+'/api/users/'+encodeURIComponent(uid)+'/reset-quota',{method:'POST'});
  toast('Quota reset — user unblocked');
  loadUsers();
}

// rotateEpoch removed in quota-reset-split (2026-05-10): the panel UI
// no longer surfaces shortid regeneration. Server endpoint
// /api/users/<id>/rotate-epoch + Python rotate_user_epoch are preserved
// for direct-API operator use; only the button + JS wrapper are gone.

function editUser(uid){
  const u = users.find(x => x.id === uid);
  if(!u) return;
  gid('editOld').value = uid;
  gid('editName').value = u.name;
  gid('editPoolSize').value = String(Math.min(4, Math.max(1, u.pool_size || 1)));
  // Convert cap bytes → {value, unit} for the number + dropdown pair.
  const parts = bytesToQuotaParts(u.bandwidth_cap || 0);
  gid('editQuotaValue').value = parts.value;
  gid('editQuotaUnit').value  = parts.unit;
  gid('editRateMbps').value = u.rate_limit_mbps || 0;
  gid('editExpires').value = u.expires_at ? new Date(u.expires_at*1000).toISOString().slice(0,10) : '';
  // Phase C iOS-notify pipeline (2026-05-10): per-user manual notification.
  // Strip the BROADCAST: prefix so the operator edits raw text; saveEdit
  // sends back without the prefix (panel adds it only on broadcast).
  let nt = (u.notification_text || '');
  if(nt.startsWith('BROADCAST: ')) nt = nt.substring('BROADCAST: '.length);
  gid('editNotification').value = nt;
  gid('editTurnRoom').value = u.turn_room_link || '';
  const st = gid('editTurnRoomStatus');
  if(st){
    const ver = u.turn_profile_version || 0;
    const pending = u.turn_profile_pending ? 'queued for client' : (ver ? 'last sent v'+ver : 'not sent yet');
    st.textContent = pending;
  }
  // URI/QR moved back to a dedicated row button (showUserUri); Edit modal
  // stays focused on name + quota + expires + notification.
  gid('editModal').classList.add('show');
}

async function saveEdit(){
  const uid = gid('editOld').value;
  const name = gid('editName').value.trim();
  if(!name){toast('Введите имя');return}
  const expRaw = gid('editExpires').value.trim();
  const body = { name, pool_size: parseInt(gid('editPoolSize').value || '1', 10) || 1 };
  body.bandwidth_cap = quotaPartsToBytes(gid('editQuotaValue').value, gid('editQuotaUnit').value);
  body.rate_limit_mbps = parseInt(gid('editRateMbps').value || '0', 10) || 0;
  body.expires_at = expRaw ? Math.floor(new Date(expRaw).getTime()/1000) : 0;
  body.notification_text = gid('editNotification').value;
  const r = await fetch(H+'/api/users/'+encodeURIComponent(uid),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d = await r.json();
  if(d.error){toast(d.error);return}
  gid('editModal').classList.remove('show');
  toast('Saved');
  loadUsers();
}

async function pushTurnRoomFromEdit(){
  const uid = gid('editOld').value;
  const link = (gid('editTurnRoom').value || '').trim();
  if(!uid){ return; }
  if(!link){ toast('Вставьте ссылку или hash VK комнаты'); return; }
  const btnStatus = gid('editTurnRoomStatus');
  if(btnStatus) btnStatus.textContent = 'sending…';
  const body = { turn_room_link: link };
  try{
    const r = await fetch(H+'/api/users/'+encodeURIComponent(uid),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    if(d.error){ toast(d.error); if(btnStatus) btnStatus.textContent = d.error; return; }
    toast('TURN room queued for client');
    if(btnStatus) btnStatus.textContent = 'queued for client (v'+(d.turn_profile_version||'')+')';
    await loadUsers();
  }catch(e){
    toast(String(e));
    if(btnStatus) btnStatus.textContent = String(e);
  }
}

function _renderQrFor(uri){
  gid('qrUri').textContent = uri;
  try{
    const q = qrcode(0,'L'); q.addData(uri,'Byte'); q.make();
    gid('qrImage').innerHTML = q.createSvgTag({cellSize:4,margin:1,scalable:true}).replace('<svg ','<svg class="qr" ');
  }catch(e){
    gid('qrImage').innerHTML = '<div style="color:var(--danger)">QR generation failed</div>';
  }
}

// Restored 2026-05-10 evening per operator: the standalone URI button on
// each user row opens this modal directly (URI text + QR + Copy). The
// Edit-user modal no longer carries URI/QR fields.
async function showUserUri(uid){
  const u = users.find(x => x.id === uid);
  if(!u) return;
  gid('qrTitle').textContent = u.name || 'User URI';
  gid('qrTabs').innerHTML = '';
  gid('qrImage').innerHTML = '<div style="color:var(--muted);font-size:12px">loading…</div>';
  gid('qrUri').textContent = '';
  gid('qrModal').classList.add('show');
  try{
    const r = await fetch(H+'/api/users/'+encodeURIComponent(uid)+'/uri');
    const d = await r.json();
    if(d.error){
      gid('qrImage').innerHTML = '<div style="color:var(--danger)">'+esc(d.error)+'</div>';
      return;
    }
    _renderQrFor(d.uri || '');
  }catch(e){
    gid('qrImage').innerHTML = '<div style="color:var(--danger)">'+esc(String(e))+'</div>';
  }
}

function renderOutbounds(){
  const el=gid('obTable');
  const ae=document.activeElement;
  if(ae && ae.tagName==='SELECT' && el.contains(ae)) return;
  if(!outbounds.length){el.innerHTML='<div class="status">No outbounds</div>';return}
  // CL-3 (2026-05-10): "Users" column removed. Users are no longer pinned
  // to outbounds via user settings; routing rules are the only mechanism
  // for outbound selection. The /api/outbounds payload still carries
  // user_count for backward compat — the panel just stops rendering it.
  // Traffic column restored 2026-05-13 (after the wrap-conn approach was
  // replaced with io.Copy-return accounting in server.go — no more
  // tun2socks type-assert hazard). dl/ul come from outbounds.bytes_down /
  // bytes_up via /api/outbounds; the Reset button zeroes both columns
  // via POST /api/reset-outbound.
  let h='<table><thead><tr><th>Tag</th><th>Type</th><th>Server</th><th>Traffic</th><th>Test <button class="btn-icon-sm" onclick="testAllOb()" title="Re-test every outbound + direct">↻</button></th><th style="text-align:right">Actions</th></tr></thead><tbody>';
  for(const o of outbounds){
    const isActive = o.tag === activeOb;
    const activeBadge = (isActive && o.tag !== 'direct') ? '<span class="active-tag">DEFAULT</span>'+latencyBadge(o.tag) : '';
    let server;
    if(o.type === 'direct'){
      server = '—';
    } else if(o.type === 'balancer'){
      const rttFail = o.failover_on_high_rtt ? `; RTT>${parseInt(o.rtt_threshold_ms||0,10)||0}ms failover` : '';
      server = `${esc(o.mode||'alive')}: ${esc((o.outbounds||[]).join(' → '))}${esc(rttFail)}`;
    } else {
      server = `${esc(o.server||'')}:${o.server_port||443}`;
    }
    const dl = o.dl||0, ul = o.ul||0;
    let trafCell;
    if(dl>0||ul>0){
      trafCell=`<span class="traf"><span class="traf-d">↓ ${fb(dl)}</span><span class="traf-u">↑ ${fb(ul)}</span></span><button class="btn-icon-sm" onclick="resetOb('${esc(o.tag)}')" title="Zero this outbound's byte counters">↻</button>`;
    }else{
      trafCell='<span style="color:var(--muted);font-size:12.5px">—</span>';
    }
    h+=`<tr>
      <td><span class="user-name">${esc(o.tag)}</span>${activeBadge}</td>
      <td>${protoBadge(o.type)}</td>
      <td class="ob-server">${server}</td>
      <td>${trafCell}</td>
      <td>${latencyBadge(o.tag) || '<span style="color:var(--muted);font-size:12px">—</span>'}</td>
      <td><div class="actions">
        <button class="btn btn-ghost btn-sm" onclick="testOb('${esc(o.tag)}')">Test</button>
        ${o.type==='direct'
          ? `<button class="btn btn-edit btn-sm" onclick="editDirectOutbound()">Edit</button>`
          : `<button class="btn btn-edit btn-sm" onclick="editOutbound('${esc(o.tag)}')">Edit</button>`}
        ${(!isActive && o.tag !== 'block')?`<button class="btn btn-del btn-sm" onclick="delOutbound('${esc(o.tag)}')">Del</button>`:''}
      </div></td></tr>`;
  }
  el.innerHTML=h+'</tbody></table>';
}

async function resetOb(tag){
  if(!await confirmDialog({title:'Reset outbound traffic?',message:'Reset traffic for outbound '+tag+'?',ok:'Reset'}))return;
  await fetch(H+'/api/reset-outbound',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tag})});
  toast('Traffic reset');loadOutbounds();
}

async function loadOutbounds(){
  try{
    const r=await fetch(H+'/api/outbounds?t='+Date.now());
    const d=await r.json();
    outbounds=d.outbounds||[];
    activeOb=d.active||'direct';
    renderOutbounds();
    renderUsers();
    _updateStats();
    _startObAutoTest();
  }catch(e){}
}

// Auto-refresh outbound latency badges. Fires every 60s in the background
// regardless of which tab is active, so when the operator switches to
// Outbounds the badges are already current — no need to manually click ↻.
// Paused when the tab is hidden (visibility API) so a backgrounded panel
// doesn't burn handshake-limiter budget on the upstream.
let _obAutoTimer = null;
function _startObAutoTest(){
  if(_obAutoTimer) return;
  const tick = () => {
    if(document.hidden) return;
    if(!Array.isArray(outbounds) || !outbounds.length) return;
    testAllOb().catch(()=>{});
  };
  _obAutoTimer = setInterval(tick, 60000);
  setTimeout(tick, 5000);
  document.addEventListener('visibilitychange', () => {
    if(!document.hidden) tick();
  });
}

async function testAllOb(){
  // Click ↻ in TEST column header. Probing strategy:
  //   - Probes against the SAME upstream (host:port) MUST serialize so
  //     they don't race each other against tamizdat-server's handshake
  //     rate limiter (≤3 / 20s per server-IP) or trigger local TLS-
  //     socket churn (TIME_WAIT, half-open).
  //   - Probes against DIFFERENT upstreams run in parallel — no point
  //     making the operator wait when there's no shared bottleneck.
  // Implementation: group by host:port, run each group sequentially
  // with a 200 ms inter-probe gap, all groups in parallel.
  const groups = new Map();
  for(const o of outbounds){
    const key = (o.server || '') + ':' + (o.server_port || 0);
    if(!groups.has(key)) groups.set(key, []);
    groups.get(key).push(o.tag);
  }
  const tasks = [];
  for(const [, tags] of groups){
    tasks.push((async () => {
      for(let i=0;i<tags.length;i++){
        await testOb(tags[i]);
        if(i < tags.length-1) await new Promise(r => setTimeout(r, 200));
      }
    })());
  }
  await Promise.all(tasks);
}

async function editDirectOutbound(){
  const direct = (outbounds || []).find(o => o.tag === 'direct');
  const sel = gid('obDirectIface');
  // Populate dropdown from /api/system/interfaces. Repopulate every open
  // so newly-attached tunnels (wg-amnezia spawn, etc.) show up without
  // a panel refresh.
  sel.innerHTML = '<option value="">— OS default route —</option>';
  try{
    const r = await fetch(H+'/api/system/interfaces?t='+Date.now());
    const d = await r.json();
    // Prefer the new "details" field (with IPv4 per iface). Fall back to
    // the bare "interfaces" name list for back-compat.
    const details = Array.isArray(d.details) ? d.details : (d.interfaces || []).map(n => ({name:n, ipv4:[]}));
    for(const e of details){
      const opt = document.createElement('option');
      opt.value = e.name;
      const ipsText = (e.ipv4 && e.ipv4.length) ? ' — ' + e.ipv4.join(', ') : '';
      opt.textContent = e.name + ipsText;
      sel.appendChild(opt);
    }
  }catch(e){ /* offline / panel restart — leave dropdown empty */ }
  sel.value = (direct && direct.bind_iface) || '';
  gid('obEditDirectModal').classList.add('show');
}

async function saveDirectOutbound(){
  const iface = (gid('obDirectIface').value || '').trim();
  // upsert_outbound on the server defaults kind to "tamizdat" when neither
  // tag nor kind is in the body; without these explicit fields it would
  // fall through to the tamizdat URI parser and error out with
  // "tamizdat URI must include host". Send tag+kind so the direct
  // branch fires; bind_iface is then captured by upsert_outbound_with_iface.
  try{
    const r = await fetch(H+'/api/outbounds/direct',{
      method:'PUT',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tag:'direct', kind:'direct', bind_iface: iface}),
    });
    const d = await r.json();
    if(d.error){ toast(d.error); return; }
    toast(iface ? ('Direct pinned to '+iface) : 'Direct → OS default route');
    gid('obEditDirectModal').classList.remove('show');
    loadOutbounds();
  }catch(e){ toast('Save failed'); }
}

async function testOb(tag){
  _obLatency[tag]={ms:-2,time:Date.now()};_persistObLatency();renderOutbounds();
  try{
    const r=await fetch(H+'/api/outbound-test/'+encodeURIComponent(tag),{method:'POST'});
    const d=await r.json();
    _obLatency[tag]={ms:d.delay!=null?d.delay:-1,time:Date.now()};
  }catch(e){_obLatency[tag]={ms:-1,time:Date.now()}}
  _persistObLatency();
  renderOutbounds();
}

function _nextBalancerTag(){
  const used = new Set((outbounds || []).map(o => o.tag));
  if(!used.has('balancer')) return 'balancer';
  for(let i=2;i<100;i++){
    const tag = 'balancer'+i;
    if(!used.has(tag)) return tag;
  }
  return 'balancer-'+Date.now();
}

let _balMemberOrder = [];

function _balancerCandidates(){
  return (outbounds || []).filter(o => (o.type || o.kind) !== 'balancer');
}

function _renderBalancerMembers(selected){
  const candidates = _balancerCandidates();
  const candidateTags = new Set(candidates.map(o => o.tag));
  _balMemberOrder = (selected || []).filter(tag => candidateTags.has(tag));
  const selectedSet = new Set(_balMemberOrder);
  const box = gid('balMembers');
  if(!candidates.length){
    box.innerHTML = '<div class="status">No member outbounds yet</div>';
    _renderBalancerOrder();
    return;
  }
  box.innerHTML = candidates.map(o => {
    const checked = selectedSet.has(o.tag) ? ' checked' : '';
    return `
      <label class="bal-member">
        <input type="checkbox" class="balMemberCheck" value="${esc(o.tag)}"${checked} onchange="toggleBalancerMember(this.value,this.checked)">
        <span>${esc(o.tag)}</span>
        <span class="kind">${esc(o.type || o.kind || '')}</span>
      </label>`;
  }).join('');
  _renderBalancerOrder();
}

function _renderBalancerOrder(){
  const box = gid('balOrder');
  if(!box) return;
  if(!_balMemberOrder.length){
    box.innerHTML = '<div class="status" style="padding:12px 8px">No selected members</div>';
    return;
  }
  box.innerHTML = _balMemberOrder.map((tag, i) => {
    const o = (outbounds || []).find(x => x.tag === tag);
    const kind = o ? (o.type || o.kind || '') : 'missing';
    return `<div class="bal-order-row">
      <span class="rank">#${i+1}</span>
      <span class="tag">${esc(tag)} <span class="kind">${esc(kind)}</span></span>
      <span class="bal-order-actions">
        <button type="button" onclick="moveBalancerMember(${i},-1)" ${i===0?'disabled':''} title="Move up">↑</button>
        <button type="button" onclick="moveBalancerMember(${i},1)" ${i===_balMemberOrder.length-1?'disabled':''} title="Move down">↓</button>
      </span>
    </div>`;
  }).join('');
}

function toggleBalancerMember(tag, checked){
  tag = String(tag || '');
  if(!tag) return;
  if(checked){
    if(!_balMemberOrder.includes(tag)) _balMemberOrder.push(tag);
  }else{
    _balMemberOrder = _balMemberOrder.filter(t => t !== tag);
  }
  _renderBalancerOrder();
}

function moveBalancerMember(index, delta){
  const j = index + delta;
  if(index < 0 || j < 0 || index >= _balMemberOrder.length || j >= _balMemberOrder.length) return;
  const tmp = _balMemberOrder[index];
  _balMemberOrder[index] = _balMemberOrder[j];
  _balMemberOrder[j] = tmp;
  _renderBalancerOrder();
}

function _currentBalancerMembers(){
  const checked = Array.from(document.querySelectorAll('#balMembers .balMemberCheck:checked')).map(e => e.value);
  const checkedSet = new Set(checked);
  _balMemberOrder = _balMemberOrder.filter(tag => checkedSet.has(tag));
  for(const tag of checked){
    if(!_balMemberOrder.includes(tag)) _balMemberOrder.push(tag);
  }
  return _balMemberOrder.slice();
}

function openAddBalancer(){
  gid('balOldTag').value = '';
  gid('balModalTitle').textContent = 'Add balancer outbound';
  gid('balSubmitBtn').textContent = 'Create balancer';
  gid('balTag').value = _nextBalancerTag();
  gid('balMode').value = 'alive';
  gid('balHighRttEnabled').checked = false;
  gid('balRttThresholdMs').value = '750';
  _renderBalancerMembers([]);
  gid('addBalancerModal').classList.add('show');
}

function openEditBalancer(o){
  if(!o) return;
  gid('balOldTag').value = o.tag || '';
  gid('balModalTitle').textContent = 'Edit balancer outbound: '+(o.tag || '');
  gid('balSubmitBtn').textContent = 'Save balancer';
  gid('balTag').value = o.tag || '';
  gid('balMode').value = o.mode || 'alive';
  gid('balHighRttEnabled').checked = !!o.failover_on_high_rtt;
  gid('balRttThresholdMs').value = o.rtt_threshold_ms || '';
  _renderBalancerMembers(o.outbounds || []);
  gid('addBalancerModal').classList.add('show');
}

async function submitAddBalancer(){
  const oldTag = gid('balOldTag').value.trim();
  const editing = !!oldTag;
  const tag = gid('balTag').value.trim();
  const mode = gid('balMode').value || 'alive';
  const members = _currentBalancerMembers();
  const failover_on_high_rtt = !!gid('balHighRttEnabled').checked;
  const rtt_threshold_ms = parseInt(gid('balRttThresholdMs').value || '0', 10) || 0;
  if(!tag){toast('Enter balancer tag');return}
  if((outbounds || []).some(o => o.tag === tag && o.tag !== oldTag)){toast('Tag taken');return}
  if(members.includes(tag)){toast('Balancer cannot reference itself');return}
  if(!members.length){toast('Select at least one outbound');return}
  if(failover_on_high_rtt && rtt_threshold_ms <= 0){toast('Enter RTT threshold in ms');return}
  const cfg = {mode, outbounds: members};
  if(failover_on_high_rtt){ cfg.failover_on_high_rtt = true; cfg.rtt_threshold_ms = rtt_threshold_ms; }
  const uri = JSON.stringify(cfg);
  const optimistic = {tag, type:'balancer', kind:'balancer', server:'balancer', server_port:0, mode, outbounds:members, failover_on_high_rtt, rtt_threshold_ms: failover_on_high_rtt ? rtt_threshold_ms : 0, uri};
  const backup = outbounds.slice();
  if(editing){
    outbounds = outbounds.map(o => o.tag === oldTag ? optimistic : o);
  }else{
    outbounds.push(optimistic);
  }
  renderOutbounds();
  try{
    const url = editing ? H+'/api/outbounds/'+encodeURIComponent(oldTag) : H+'/api/outbounds';
    const method = editing ? 'PUT' : 'POST';
    const r=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify({tag,type:'balancer',mode,outbounds:members,failover_on_high_rtt,rtt_threshold_ms})});
    const d=await r.json();
    if(d.error){toast(d.error);outbounds=backup;renderOutbounds();return}
    gid('addBalancerModal').classList.remove('show');
    toast((editing ? 'Updated balancer: ' : 'Created balancer: ')+d.tag);
  }catch(e){outbounds=backup;renderOutbounds();toast(editing ? 'Update balancer failed' : 'Create balancer failed');return}
  loadOutbounds();
}

async function importOutbound(){
  let uri=gid('obUri').value.trim();
  const tagInput=gid('obTag').value.trim();
  if(!uri){toast('Paste tamizdat URI');return}
  if(uri.startsWith('{') || uri.startsWith('balancer://')){
    const tag = tagInput;
    if(!tag){toast('Enter tag for balancer outbound');return}
    outbounds.push({tag,type:'balancer',server:'balancer',server_port:0,uri});renderOutbounds();
    gid('obUri').value='';gid('obTag').value='';
    try{
      const r=await fetch(H+'/api/outbounds',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tag,uri,type:'balancer'})});
      const d=await r.json();
      if(d.error){toast(d.error);outbounds.pop();renderOutbounds();return}
      toast('Imported balancer: '+d.tag);
    }catch(e){outbounds.pop();renderOutbounds();return}
    loadOutbounds();
    return;
  }
  if(!uri.startsWith('tamizdat://')){toast('Only tamizdat:// or balancer JSON/URI outbounds are supported');return}
  const m=uri.match(/#(.+)$/);
  // Tag fallback chain: explicit input > URI #fragment > URI hostname.
  let tag = tagInput || (m ? decodeURIComponent(m[1]) : '');
  if(!tag){
    try{
      const url = new URL(uri.replace(/^tamizdat:/, 'https:'));
      tag = (url.hostname || '').toLowerCase();
    }catch(e){}
  }
  if(!tag){toast('Could not derive tag from URI \u2014 enter one manually');return}
  const proto='tamizdat';
  outbounds.push({tag,type:proto,server:'...',server_port:0,uri});renderOutbounds();
  gid('obUri').value='';gid('obTag').value='';
  try{
    const r=await fetch(H+'/api/outbounds',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tag,uri})});
    const d=await r.json();
    if(d.error){toast(d.error);outbounds.pop();renderOutbounds();return}
    toast('Imported: '+d.tag);
  }catch(e){outbounds.pop();renderOutbounds();return}
  loadOutbounds();
}

function editOutbound(tag){
  const o=outbounds.find(x=>x.tag===tag);if(!o)return;
  const typ = o.type || o.kind || 'tamizdat';
  if(typ==='direct'){toast('direct cannot be edited');return}
  if(typ==='balancer'){openEditBalancer(o);return}
  gid('obEditOldTag').value=tag;
  gid('obEditType').value=typ;
  gid('obEditTag').value=o.tag;
  gid('obEditUri').value=o.uri||'';
  gid('obEditUriLabel').textContent = 'Tamizdat URI';
  gid('obEditUri').placeholder = 'tamizdat://host:port/?sni=…&pubkey=…&shortid=…&fp=mix';
  gid('obEditTitle').textContent='Edit outbound: '+tag;
  gid('obEditModal').classList.add('show');
}

async function saveOutbound(){
  const oldTag=gid('obEditOldTag').value;
  const typ=gid('obEditType').value||'tamizdat';
  const body={tag:gid('obEditTag').value.trim(), uri:gid('obEditUri').value.trim(), type:typ};
  if(!body.tag||!body.uri){toast('Tag and URI/config required');return}
  const r=await fetch(H+'/api/outbounds/'+encodeURIComponent(oldTag),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(d.error){toast(d.error);return}
  gid('obEditModal').classList.remove('show');toast('Updated');loadOutbounds();
}

// setActiveOb removed in panel-cleanup CL-2 (2026-05-10): the per-row
// "Set default" button no longer exists. The default outbound is now a
// routing concern — operator picks it via the routing-rules page (a
// catch-all rule auto-created on fresh install pins the default to
// tamizdat). The default_outbound_tag setting row stays in the DB
// because the Go server reads it as the fallback when no routing rule
// matches — see internal/outbounds/registry.go and
// cmd/tamizdat-server/main.go. The /api/outbounds/active POST endpoint
// + set_active_outbound() Python helper are no longer reachable from
// the UI; they remain for direct-API operator use until a future cleanup.

async function delOutbound(tag){
  if(!await confirmDialog({title:'Delete outbound',message:'Delete outbound '+tag+'?',ok:'Delete',danger:true}))return;
  const backup=outbounds.slice();
  outbounds=outbounds.filter(o=>o.tag!==tag);renderOutbounds();
  try{
    const r=await fetch(H+'/api/outbounds/'+encodeURIComponent(tag),{method:'DELETE'});
    const d=await r.json();
    if(d.error){toast(d.error);outbounds=backup;renderOutbounds();return}
    toast('Deleted');
  }catch(e){outbounds=backup;renderOutbounds()}
  loadOutbounds();
}

let liveClients={};
async function loadClients(){
  try{
    const r=await fetch(H+'/api/clients?t='+Date.now());
    if(r.redirected||r.status===401){location.reload();return}
    const d=await r.json();
    liveClients=d.clients||{};
    const newStats=d.user_stats||{};
    for(const u in newStats){if(newStats[u].online&&newStats[u].ips&&newStats[u].ips.length)_lastIps[u]=newStats[u].ips}
    userStats=newStats;
    renderUsers();
  }catch(e){}
}

async function loadSvcStatus(){
  try{
    const r=await fetch(H+'/api/service?t='+Date.now());
    const d=await r.json();
    const tb=gid('btnToggle');
    if(tb){
      if(d.status==='active'){tb.textContent='Stop';tb.dataset.action='stop';tb.className='btn btn-svc btn-stop stat-svc-btn'}
      else{tb.textContent='Start';tb.dataset.action='start';tb.className='btn btn-svc btn-start stat-svc-btn'}
    }
    // Service stat card
    const ss=gid('statSvc');
    if(ss){
      const color = d.status==='active' ? 'var(--primary)' : d.status==='inactive' ? 'var(--danger)' : 'var(--muted)';
      ss.innerHTML = '<span style="color:'+color+'">'+d.status+'</span> <small>'+(d.uptime||'')+'</small>';
    }
  }catch(e){}
}

// Settings refactor Phase 2 (2026-05-11): two flat blocks. Tamizdat server
// (Block 1) is fed by GET /api/tamizdat which now returns flat inbound_*
// keys; Panel (Block 2) by GET /api/panel.
async function loadSettings(){
  // Block 1: Tamizdat server.
  try{
    const tr=await fetch(H+'/api/tamizdat?t='+Date.now());
    const t=await tr.json();
    if(t.error){toast(t.error)}
    else{
      // tamEnabled toggle dropped 2026-05-11 (dead-mine).
      gid('tamListenAddr').value = t.listen_addr || '0.0.0.0';
      gid('tamListenPort').value = t.listen_port || 7780;
      gid('tamPublicPort').value = t.public_port || 443;
      // Priv key field stays empty on first paint — server already has it,
      // typing here only overwrites. Public key (auto-derived) is read-only.
      gid('tamPriv').value = '';
      gid('tamPub').value  = t.public_key || '';
      gid('tamCert').value = t.cert_path || '';
      gid('tamKey').value  = t.key_path || '';
      gid('tamMasq').value = t.masquerade_domain || '';
      gid('tamMasqPool').value = t.masquerade_pool || '';
      gid('tamBootstrap').value = t.bootstrap_sni || '';
      gid('tamFp').value = t.fingerprint || 'mix';
      gid('tamMaxStreams').value = t.max_streams || 1000;
      gid('tamPoolSizeDefault').value = t.pool_size_default || 1;
      gid('tamJitter').value = t.jitter_ms || 0;
      // Sniff toggle (2026-05-25 cleanup): explicitly seed the checkbox
      // from the server value. Was relying on default-unchecked which
      // visually disagreed with the persisted server state.
      const _se = gid('tamSniffEnabled');
      if(_se) _se.checked = (t.sniff_enabled === true || t.sniff_enabled === 1 || t.sniff_enabled === '1');
      // tamFallServ/tamFallPort dropped 2026-05-11 (dead-mine).
      const gip = gid('setGeoipUrl');   if(gip) gip.value = (t.geoip_url   != null ? t.geoip_url   : '');
      const gst = gid('setGeositeUrl'); if(gst) gst.value = (t.geosite_url != null ? t.geosite_url : '');
      const wge = gid('wgTurnEnabled'); if(wge) wge.checked = (t.wgturn_enabled === true || t.wgturn_enabled === 1 || t.wgturn_enabled === '1');
      const wgl = gid('wgTurnListen'); if(wgl) wgl.value = t.wgturn_listen || '';
      const wgpw = gid('wgTurnPassword'); if(wgpw) wgpw.value = t.wgturn_password || '';
      const wgwp = gid('wgTurnWGPort'); if(wgwp) wgwp.value = t.wgturn_wg_port || 56001;
      const wgcd = gid('wgTurnConfigDir'); if(wgcd) wgcd.value = t.wgturn_config_dir || '/etc/tamizdat/wgturn';
      const wgsn = gid('wgTurnSubnet'); if(wgsn) wgsn.value = t.wgturn_subnet || '10.66.66.0/24';
      const wgip = gid('wgTurnServerIP'); if(wgip) wgip.value = t.wgturn_server_ip || '10.66.66.1';
      const wgot = gid('wgTurnOutboundTag'); if(wgot) wgot.value = t.wgturn_outbound_tag || '';
      gid('tamUri').value = t.uri || '(no master URI — set private_key + cert/key first)';
    }
  }catch(e){toast('Failed to load Tamizdat server settings')}
  // Block 2: Panel.
  try{
    const pr=await fetch(H+'/api/panel?t='+Date.now());
    const p=await pr.json();
    if(p.error){toast(p.error)}
    else{
      gid('setPanelHostname').value = p.hostname || '';
      gid('setPanelPort').value     = p.port || 8888;
      gid('setPanelBasePath').value = p.base_path || '';
      gid('setPanelTlsCert').value  = p.tls_cert_path || '';
      gid('setPanelTlsKey').value   = p.tls_key_path  || '';
      gid('setPanelAdmins').value = p.admin_users || '';
      gid('setPanelServiceName').value  = p.service_name || '';
      gid('setTestTarget').value    = p.test_target || 'http://www.gstatic.com/generate_204';
      gid('setPanelVersion').value  = p.version || '?';
    }
  }catch(e){toast('Failed to load Panel settings')}
  // Block 3: current user. Used by the Settings → User block for the
  // "Signed in as" field next to the change-password form.
  try{
    const mr = await fetch(H+'/api/me?t='+Date.now());
    const me = await mr.json();
    if(!me.error){
      const su = gid('setAccountUser');
      if(su) su.value = me.username || '';
    }
  }catch(e){ /* non-fatal */ }
  // Settings mockup port (2026-05-11): re-render chips + line-lists from
  // the freshly loaded values, ensure mockup interactions are wired, then
  // snapshot a clean baseline + clear dirty state (so Save bar starts hidden).
  chipsRender(gid('tamMasqPool') ? gid('tamMasqPool').value : '');
  lineListRender('geoipList',   gid('setGeoipUrl')   ? gid('setGeoipUrl').value   : '');
  lineListRender('geositeList', gid('setGeositeUrl') ? gid('setGeositeUrl').value : '');
  initSettingsMockup();
  syncSettingsUIControls();
  snapshotSettingsBaseline();
  settingsClearDirty();
  // Service status pill in sub-rail meta (best effort — uses statSvc field
  // populated by the existing loadSvcStatus poller).
  const ss = gid('statSvc');
  const sm = gid('setSvcStatus');
  if(ss && sm){
    const t = (ss.textContent || '').trim();
    sm.textContent = t ? ('● ' + t) : '● —';
  }
}

async function genTamKeypair(){
  try{
    const r=await fetch(H+'/api/tamizdat/keypair',{method:'POST'});
    const d=await r.json();
    if(d.error){toast(d.error);return}
    gid('tamPriv').value=d.private_key;
    gid('tamPub').value=d.public_key;
    toast('Tamizdat keypair generated (не забудь Save)');
  }catch(e){toast('Generation failed')}
}

// Settings refactor Phase 2 (2026-05-11): renamed from saveTamizdat. Hits
// PUT /api/tamizdat which now routes to put_inbound_settings under flat keys.
async function saveTamizdatServer(opts){
  opts = opts || {};
  const body={
    // enabled toggle dropped 2026-05-11 (dead-mine).
    listen_addr:       gid('tamListenAddr').value.trim() || '0.0.0.0',
    listen_port:       parseInt(gid('tamListenPort').value)||7780,
    public_port:       parseInt(gid('tamPublicPort').value)||443,
    private_key:       gid('tamPriv').value.trim(),  // empty = preserve existing
    cert_path:         gid('tamCert').value.trim(),
    key_path:          gid('tamKey').value.trim(),
    masquerade_domain: gid('tamMasq').value.trim(),
    masquerade_pool:   gid('tamMasqPool').value.trim(),
    bootstrap_sni:     gid('tamBootstrap').value.trim(),
    fingerprint:       gid('tamFp').value,
    pool_variant:      gid('tamPoolVariant') ? gid('tamPoolVariant').value : 'v1',
    pool_size_default: parseInt(gid('tamPoolSizeDefault').value || '1', 10) || 1,
    sniff_enabled:     gid('tamSniffEnabled') ? (gid('tamSniffEnabled').checked ? 1 : 0) : 1,
    max_streams:       parseInt(gid('tamMaxStreams').value)||1000,
    jitter_ms:         parseInt(gid('tamJitter').value)||0,
    // fallback_server/_port dropped 2026-05-11 (dead-mine, no Go reader).
    geoip_url:         gid('setGeoipUrl').value,
    geosite_url:       gid('setGeositeUrl').value,
    wgturn_enabled:    gid('wgTurnEnabled') ? (gid('wgTurnEnabled').checked ? 1 : 0) : 0,
    wgturn_listen:     gid('wgTurnListen') ? gid('wgTurnListen').value.trim() : '',
    wgturn_password:   gid('wgTurnPassword') ? gid('wgTurnPassword').value.trim() : '',
    wgturn_wg_port:    parseInt(gid('wgTurnWGPort') ? gid('wgTurnWGPort').value : '56001', 10) || 56001,
    wgturn_config_dir: gid('wgTurnConfigDir') ? gid('wgTurnConfigDir').value.trim() : '/etc/tamizdat/wgturn',
    wgturn_subnet:     gid('wgTurnSubnet') ? gid('wgTurnSubnet').value.trim() : '10.66.66.0/24',
    wgturn_server_ip:  gid('wgTurnServerIP') ? gid('wgTurnServerIP').value.trim() : '10.66.66.1',
    wgturn_outbound_tag: gid('wgTurnOutboundTag') ? gid('wgTurnOutboundTag').value.trim() : '',
  };
  try{
    const r=await fetch(H+'/api/tamizdat',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.error){
      if(!opts.quiet) toast(d.error);
      throw new Error(d.error);
    }
    if(d.uri) gid('tamUri').value=d.uri;
    // Clear the priv-key field after save so it doesn't get auto-resubmitted.
    gid('tamPriv').value = '';
    if(!opts.quiet) toast(d.restart_required ? 'Saved — tamizdat-server restart pending' : 'Saved');
    setTimeout(loadSvcStatus,1500);
    return d;
  }catch(e){
    if(!opts.quiet) toast('Save failed');
    throw e;
  }
}

// Settings refactor Phase 2 (2026-05-11): panel self-config save. port /
// base_path / TLS-path changes → modal with new URL → POST /api/panel/restart.
async function savePanel(opts){
  opts = opts || {};
  const body={
    hostname:      gid('setPanelHostname').value.trim(),
    port:          parseInt(gid('setPanelPort').value)||8888,
    base_path:     gid('setPanelBasePath').value.trim(),
    tls_cert_path: gid('setPanelTlsCert').value.trim(),
    tls_key_path:  gid('setPanelTlsKey').value.trim(),
  };
  try{
    const r=await fetch(H+'/api/panel',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.error){
      if(!opts.quiet) toast(d.error);
      throw new Error(d.error);
    }
    if(d.restart_required){
      const newUrl = d.new_url || '(URL не вычислен — открой панель вручную)';
      if(opts.quiet){
        d.new_url = newUrl;
      }else{
        const ok = await confirmDialog({
          title: 'Panel restart needed',
          message: 'Listen port / base_path / TLS-paths changed.\n\nПосле restart открой:\n'+newUrl+'\n\nТекущая страница станет 404. Restart now?',
          ok: 'Restart panel',
          danger: true,
        });
        if(ok){
          await fetch(H+'/api/panel/restart',{method:'POST'});
          toast('Panel restart triggered — переключайся на '+newUrl);
        }else{
          toast('Saved — restart deferred (изменения вступят в силу при следующем рестарте)');
        }
      }
    }else if(!opts.quiet){
      toast('Saved');
    }
    return d;
  }catch(e){
    if(!opts.quiet) toast('Save failed');
    throw e;
  }
}

async function saveTestTarget(){
  const v = (gid('setTestTarget').value || '').trim();
  if(!v) return;
  try{
    await fetch(H+'/api/inbound',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({panel_test_target: v})});
    toast('Test target saved');
  }catch(e){ toast('Save failed'); }
}

// Generic geo-URL saver. Empty value is intentional (disable loading,
// free memory) and is sent through unchanged.
async function saveGeoUrl(key, value){
  const v = (value || '').trim();
  try{
    const body = {}; body[key] = v;
    await fetch(H+'/api/inbound',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    toast(v ? (key.replace('inbound_','')+' saved') : (key.replace('inbound_','')+' cleared (memory freed on next reload)'));
  }catch(e){ toast('Save failed'); }
}

// Phase C iOS-notify pipeline (2026-05-10): broadcast notification to ALL users.
async function sendBroadcast(){
  const text = gid('setBroadcastText').value.trim();
  if(!text){toast('Введите текст или нажмите Clear queue');return}
  if(!await confirmDialog({title:'Broadcast to all users?',message:'Покажется ВСЕМ пользователям при следующем connect:\n\n'+text,ok:'Send'}))return;
  try{
    const r = await fetch(H+'/api/users/broadcast-notification',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    gid('setBroadcastText').value='';
    toast('Broadcast sent to all users');
  }catch(e){toast('Broadcast failed')}
}

async function clearBroadcast(){
  if(!await confirmDialog({title:'Clear pending notifications?',message:'У всех пользователей очистится notification_text и notification_pending.',ok:'Clear',danger:true}))return;
  try{
    const r = await fetch(H+'/api/users/broadcast-notification',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:''})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    gid('setBroadcastText').value='';
    toast('Cleared all pending notifications');
  }catch(e){toast('Clear failed')}
}

// =================================================================
// Settings mockup port (2026-05-11) — UI interactions
// Sub-rail scrollspy, segmented controls, chip pool for masquerade,
// line-list for geo URLs, advanced reveal, dirty-tracker, sticky save
// bar. Wires to the existing /api/tamizdat + /api/panel handlers.
// =================================================================

let _setMockupInit = false;
let _setBaseline = null;   // snapshot of last loaded form values (for Discard).
const _dirtyFields = new Set();

// Markdirty for the save-bar. Called by every input listener wired below.
function settingsMarkDirty(field){
  if(field) _dirtyFields.add(field);
  const sb = gid('saveBar');
  const cc = gid('changeCount');
  if(cc) cc.textContent = _dirtyFields.size;
  if(sb) sb.classList.toggle('show', _dirtyFields.size > 0);
  // Highlight sub-rail items whose group has any dirty input.
  const dirtyGroups = new Set();
  document.querySelectorAll('#page-settings .group').forEach(g => {
    if(g.dataset.dirty) dirtyGroups.add(g.id);
  });
  document.querySelectorAll('#page-settings .sub-link').forEach(l => {
    l.classList.toggle('dirty', dirtyGroups.has(l.dataset.target));
  });
}
function settingsClearDirty(){
  _dirtyFields.clear();
  document.querySelectorAll('#page-settings .group').forEach(g => delete g.dataset.dirty);
  const sb = gid('saveBar'); if(sb) sb.classList.remove('show');
  document.querySelectorAll('#page-settings .sub-link').forEach(l => l.classList.remove('dirty'));
}

// Chip pool ↔ hidden textarea sync for the SNI rotation pool.
// Backing format is the same comma-separated `sni=host:port,...`
// that put_inbound_settings already accepts via masquerade_pool.
function chipsSerialize(){
  const chips = document.querySelectorAll('#sniChips .chip');
  return Array.from(chips).map(c => c.dataset.val).filter(Boolean).join(',');
}
function chipsRender(text){
  const chipsEl = gid('sniChips');
  if(!chipsEl) return;
  // Wipe out everything except the input.
  Array.from(chipsEl.querySelectorAll('.chip')).forEach(c => c.remove());
  const input = chipsEl.querySelector('input');
  const items = (text || '').split(',').map(s => s.trim()).filter(Boolean);
  for(const v of items){
    const ch = document.createElement('span');
    ch.className = 'chip';
    ch.dataset.val = v;
    ch.innerHTML = escHtml(v) + '<span class="x"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="9" height="9"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></span>';
    if(input) chipsEl.insertBefore(ch, input);
    else chipsEl.appendChild(ch);
  }
  const cc = gid('chipCount');
  if(cc) cc.textContent = chipsEl.querySelectorAll('.chip').length;
  // Sync backing textarea.
  const ta = gid('tamMasqPool');
  if(ta) ta.value = chipsSerialize();
}
function escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Line-list ↔ hidden textarea sync (newline-separated URLs).
function lineListSerialize(listId){
  const list = gid(listId);
  if(!list) return '';
  return Array.from(list.querySelectorAll('input[type=text]'))
    .map(i => i.value.trim())
    .filter(Boolean)
    .join('\n');
}
function lineListRender(listId, text){
  const list = gid(listId);
  if(!list) return;
  // Drop all rows except the "Add URL" button.
  Array.from(list.querySelectorAll('.line-row')).forEach(r => r.remove());
  const addBtn = list.querySelector('.btn-add');
  const lines = (text || '').split('\n').map(s => s.trim()).filter(Boolean);
  for(const v of lines){
    const row = document.createElement('div');
    row.className = 'line-row';
    row.innerHTML = '<input type="text" value="'+escHtml(v)+'" class="mono">'+
      '<button type="button" class="btn-mini" onclick="this.closest(\'.line-row\').remove();settingsMarkDirty();syncGeoLists()"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>';
    if(addBtn) list.insertBefore(row, addBtn);
    else list.appendChild(row);
    // Wire input → sync.
    row.querySelector('input').addEventListener('input', () => { syncGeoLists(); markGroupDirty(row); });
  }
}
function syncGeoLists(){
  const gip = gid('setGeoipUrl');
  const gst = gid('setGeositeUrl');
  if(gip) gip.value = lineListSerialize('geoipList');
  if(gst) gst.value = lineListSerialize('geositeList');
}

// Hooks "Add URL" buttons in the line-lists.
window.addGeoLine = function(btn, kind){
  const list = btn.parentNode;
  const row = document.createElement('div');
  row.className = 'line-row';
  row.innerHTML = '<input type="text" placeholder="https://..." class="mono">'+
    '<button type="button" class="btn-mini" onclick="this.closest(\'.line-row\').remove();settingsMarkDirty();syncGeoLists()"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>';
  list.insertBefore(row, btn);
  const inp = row.querySelector('input');
  inp.focus();
  inp.addEventListener('input', () => { syncGeoLists(); markGroupDirty(row); });
  settingsMarkDirty(row);
};

function markGroupDirty(el){
  const g = el && el.closest ? el.closest('.group') : null;
  if(g) g.dataset.dirty = '1';
  settingsMarkDirty(el);
}

// Initialise mockup interactions once the Settings page is first shown.
// (Wiring happens once per page load; safe to call repeatedly.)
function initSettingsMockup(){
  if(_setMockupInit) return;
  _setMockupInit = true;

  // ---- Sub-rail scrollspy.
  const subLinks = document.querySelectorAll('#page-settings .sub-link');
  subLinks.forEach(l => l.addEventListener('click', e => {
    e.preventDefault();
    const t = document.getElementById(l.dataset.target);
    if(!t) return;
    window.scrollTo({top: t.getBoundingClientRect().top + window.scrollY - 18, behavior:'smooth'});
  }));
  const groups = Array.from(document.querySelectorAll('#page-settings .group'));
  function spy(){
    if(gid('page-settings').style.display === 'none') return;
    const y = window.scrollY + 80;
    let active = groups[0];
    for(const g of groups){ if(g.offsetTop <= y) active = g; }
    if(!active) return;
    subLinks.forEach(l => l.classList.toggle('active', l.dataset.target === active.id));
  }
  window.addEventListener('scroll', spy, {passive:true});

  // ---- Segmented controls (bindSeg → tamListenAddr, utlsSeg → tamFp).
  document.querySelectorAll('#page-settings .seg').forEach(seg => {
    seg.addEventListener('click', e => {
      const b = e.target.closest('button');
      if(!b) return;
      seg.querySelectorAll('button').forEach(x => x.classList.toggle('on', x===b));
      const v = b.dataset.val;
      if(seg.id === 'bindSeg'){
        const inp = gid('tamListenAddr');
        if(v === 'custom'){ inp.style.display='block'; inp.value=''; inp.focus(); }
        else { inp.style.display='none'; inp.value = v; }
      } else if(seg.id === 'utlsSeg'){
        gid('tamFp').value = v;
      } else if(seg.id === 'poolVarSeg'){
        gid('tamPoolVariant').value = v;
      }
      markGroupDirty(seg);
    });
  });

  // ---- Inbound toggle removed 2026-05-11 (dead-mine, no Go reader).

  // ---- Jitter range ↔ number sync.
  const jr = gid('jitterRange'), jv = gid('tamJitter');
  if(jr && jv){
    jr.addEventListener('input', () => { jv.value = jr.value; markGroupDirty(jr); });
    jv.addEventListener('input', () => { jr.value = jv.value || 0; markGroupDirty(jv); });
  }

  // ---- Fallback toggle / target row removed 2026-05-11 (dead-mine).

  // ---- Chip pool input.
  const chipsEl = gid('sniChips');
  if(chipsEl){
    const chipInput = chipsEl.querySelector('input');
    chipsEl.addEventListener('click', e => {
      if(e.target.closest('.x')){
        e.target.closest('.chip').remove();
        const cc = gid('chipCount'); if(cc) cc.textContent = chipsEl.querySelectorAll('.chip').length;
        const ta = gid('tamMasqPool'); if(ta) ta.value = chipsSerialize();
        markGroupDirty(chipsEl);
      } else if(e.target === chipsEl && chipInput) chipInput.focus();
    });
    if(chipInput){
      chipInput.addEventListener('keydown', e => {
        if(e.key === 'Enter' && chipInput.value.trim()){
          e.preventDefault();
          const v = chipInput.value.trim();
          const ch = document.createElement('span');
          ch.className = 'chip';
          ch.dataset.val = v;
          ch.innerHTML = escHtml(v) + '<span class="x"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="9" height="9"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></span>';
          chipsEl.insertBefore(ch, chipInput);
          chipInput.value = '';
          const cc = gid('chipCount'); if(cc) cc.textContent = chipsEl.querySelectorAll('.chip').length;
          const ta = gid('tamMasqPool'); if(ta) ta.value = chipsSerialize();
          markGroupDirty(chipsEl);
        } else if(e.key === 'Backspace' && !chipInput.value){
          const last = chipsEl.querySelectorAll('.chip');
          if(last.length){
            last[last.length-1].remove();
            const cc = gid('chipCount'); if(cc) cc.textContent = chipsEl.querySelectorAll('.chip').length;
            const ta = gid('tamMasqPool'); if(ta) ta.value = chipsSerialize();
            markGroupDirty(chipsEl);
          }
        }
      });
    }
  }

  // ---- Advanced reveal (Panel group).
  const adv = gid('advPanel');
  if(adv) adv.addEventListener('click', () => {
    adv.classList.toggle('open');
    const body = gid('advPanelBody');
    if(body) body.classList.toggle('open');
  });

  // ---- Copy pubkey button.
  const cp = gid('copyPub');
  if(cp) cp.addEventListener('click', () => {
    const p = gid('tamPub'); if(p && p.value) window.copyText ? window.copyText(p.value) : (navigator.clipboard.writeText(p.value).then(()=>toast('Copied')));
  });

  // ---- Broadcast counter.
  const bcMsg = gid('setBroadcastText');
  if(bcMsg) bcMsg.addEventListener('input', e => {
    const ml = gid('msgLen');
    if(ml) ml.textContent = new Blob([e.target.value]).size;
  });

  // ---- Wire every input/textarea/select in #page-settings to mark-dirty.
  //      User-block fields (current/new/confirm password) live in their own
  //      submit flow (changeAccountPassword) — they must NOT show up in the
  //      sticky save bar or get clobbered by Discard.
  const _settingsDirtyExclude = new Set(['setAccountCurrent','setAccountNew','setAccountConfirm','setAccountUser']);
  document.querySelectorAll('#page-settings input, #page-settings textarea, #page-settings select').forEach(el => {
    if(el.readOnly || el.disabled) return;
    if(el.id && _settingsDirtyExclude.has(el.id)) return;
    el.addEventListener('input', () => markGroupDirty(el));
  });

  // ---- Save-all + Discard.
  const btnSave = gid('btnSave');
  const btnDiscard = gid('btnDiscard');
  if(btnSave) btnSave.addEventListener('click', settingsSaveAll);
  if(btnDiscard) btnDiscard.addEventListener('click', () => {
    if(_setBaseline) populateSettingsFromBaseline(_setBaseline);
    settingsClearDirty();
    toast('Changes discarded');
  });
}

// Snapshot current form state so Discard can revert.
function snapshotSettingsBaseline(){
  _setBaseline = {
    // 2026-05-11 dead-mine cleanup: dropped tamEnabled, tamFallServ,
    // tamFallPort, fallbackOn from baseline (UI fields no longer rendered).
    listen_addr:       gid('tamListenAddr') ? gid('tamListenAddr').value : '',
    listen_port:       gid('tamListenPort') ? gid('tamListenPort').value : '',
    public_port:       gid('tamPublicPort') ? gid('tamPublicPort').value : '',
    cert_path:         gid('tamCert') ? gid('tamCert').value : '',
    key_path:          gid('tamKey') ? gid('tamKey').value : '',
    masquerade_domain: gid('tamMasq') ? gid('tamMasq').value : '',
    masquerade_pool:   gid('tamMasqPool') ? gid('tamMasqPool').value : '',
    bootstrap_sni:     gid('tamBootstrap') ? gid('tamBootstrap').value : '',
    fingerprint:       gid('tamFp') ? gid('tamFp').value : 'mix',
    pool_variant:      gid('tamPoolVariant') ? gid('tamPoolVariant').value : 'v1',
    pool_size_default:  gid('tamPoolSizeDefault') ? gid('tamPoolSizeDefault').value : '',
    sniff_enabled:     gid('tamSniffEnabled') ? (gid('tamSniffEnabled').checked ? 1 : 0) : 1,
    max_streams:       gid('tamMaxStreams') ? gid('tamMaxStreams').value : '',
    jitter_ms:         gid('tamJitter') ? gid('tamJitter').value : '0',
    geoip_url:         gid('setGeoipUrl') ? gid('setGeoipUrl').value : '',
    geosite_url:       gid('setGeositeUrl') ? gid('setGeositeUrl').value : '',
    hostname:          gid('setPanelHostname') ? gid('setPanelHostname').value : '',
    panel_port:        gid('setPanelPort') ? gid('setPanelPort').value : '',
    base_path:         gid('setPanelBasePath') ? gid('setPanelBasePath').value : '',
    tls_cert_path:     gid('setPanelTlsCert') ? gid('setPanelTlsCert').value : '',
    tls_key_path:      gid('setPanelTlsKey') ? gid('setPanelTlsKey').value : '',
    test_target:       gid('setTestTarget') ? gid('setTestTarget').value : '',
  };
}
function populateSettingsFromBaseline(b){
  if(gid('tamListenAddr'))  gid('tamListenAddr').value = b.listen_addr || '';
  if(gid('tamListenPort'))  gid('tamListenPort').value = b.listen_port || '';
  if(gid('tamPublicPort'))  gid('tamPublicPort').value = b.public_port || '';
  if(gid('tamCert'))        gid('tamCert').value = b.cert_path || '';
  if(gid('tamKey'))         gid('tamKey').value = b.key_path || '';
  if(gid('tamMasq'))        gid('tamMasq').value = b.masquerade_domain || '';
  if(gid('tamMasqPool'))    gid('tamMasqPool').value = b.masquerade_pool || '';
  chipsRender(b.masquerade_pool || '');
  if(gid('tamBootstrap'))   gid('tamBootstrap').value = b.bootstrap_sni || '';
  if(gid('tamFp'))          gid('tamFp').value = b.fingerprint || 'mix';
  if(gid('tamPoolVariant')) gid('tamPoolVariant').value = b.pool_variant || 'v1';
  if(gid('tamPoolSizeDefault')) gid('tamPoolSizeDefault').value = b.pool_size_default || '';
  if(gid('tamSniffEnabled')) gid('tamSniffEnabled').checked = (b.sniff_enabled === true || b.sniff_enabled === 1 || b.sniff_enabled === '1');
  if(gid('tamMaxStreams'))  gid('tamMaxStreams').value = b.max_streams || '';
  if(gid('tamJitter'))      gid('tamJitter').value = b.jitter_ms || 0;
  if(gid('jitterRange'))    gid('jitterRange').value = b.jitter_ms || 0;
  if(gid('setGeoipUrl'))    gid('setGeoipUrl').value = b.geoip_url || '';
  if(gid('setGeositeUrl'))  gid('setGeositeUrl').value = b.geosite_url || '';
  lineListRender('geoipList',   b.geoip_url || '');
  lineListRender('geositeList', b.geosite_url || '');
  if(gid('setPanelHostname'))  gid('setPanelHostname').value = b.hostname || '';
  if(gid('setPanelPort'))      gid('setPanelPort').value = b.panel_port || '';
  if(gid('setPanelBasePath'))  gid('setPanelBasePath').value = b.base_path || '';
  if(gid('setPanelTlsCert'))   gid('setPanelTlsCert').value = b.tls_cert_path || '';
  if(gid('setPanelTlsKey'))    gid('setPanelTlsKey').value = b.tls_key_path || '';
  if(gid('setTestTarget'))     gid('setTestTarget').value = b.test_target || '';
  // Sync segmented controls to reflect restored values.
  syncSettingsUIControls();
}

// Sync UI-only controls (segmented buttons, toggle small-text, jitter slider,
// fallback gating) from current form values. Called after loadSettings()
// finishes AND after Discard.
function syncSettingsUIControls(){
  // bindSeg ← tamListenAddr.
  const addr = gid('tamListenAddr') ? gid('tamListenAddr').value : '';
  const bindSeg = gid('bindSeg');
  if(bindSeg){
    let matched = false;
    bindSeg.querySelectorAll('button').forEach(b => {
      const on = b.dataset.val === addr;
      b.classList.toggle('on', on);
      if(on) matched = true;
    });
    const inp = gid('tamListenAddr');
    if(!matched){
      // Custom address — show input, mark Custom button on.
      const cb = bindSeg.querySelector('button[data-val=custom]');
      if(cb) cb.classList.add('on');
      if(inp) inp.style.display = 'block';
    } else {
      if(inp) inp.style.display = 'none';
    }
  }
  // utlsSeg ← tamFp.
  const fp = gid('tamFp') ? gid('tamFp').value : 'mix';
  const utlsSeg = gid('utlsSeg');
  if(utlsSeg){
    utlsSeg.querySelectorAll('button').forEach(b => {
      b.classList.toggle('on', b.dataset.val === fp);
    });
  }
  // poolVarSeg ← tamPoolVariant.
  const poolVar = gid('tamPoolVariant') ? gid('tamPoolVariant').value : 'v1';
  const poolVarSeg = gid('poolVarSeg');
  if(poolVarSeg){
    poolVarSeg.querySelectorAll('button').forEach(b => {
      b.classList.toggle('on', b.dataset.val === poolVar);
    });
  }
  // Inbound toggle + Fallback toggle removed 2026-05-11 (dead-mines).
  // Jitter range mirrors number input.
  const jr = gid('jitterRange'), jv = gid('tamJitter');
  if(jr && jv) jr.value = jv.value || 0;
  // Chip count.
  const cc = gid('chipCount'); const chipsEl = gid('sniChips');
  if(cc && chipsEl) cc.textContent = chipsEl.querySelectorAll('.chip').length;
  // Broadcast msg-len.
  const bcMsg = gid('setBroadcastText');
  if(bcMsg){
    const ml = gid('msgLen');
    if(ml) ml.textContent = new Blob([bcMsg.value || '']).size;
  }
  // Panel version mini in sub-rail.
  const pv = gid('setPanelVersion');
  const pvm = gid('setPanelVersionMini');
  if(pv && pvm) pvm.textContent = pv.value || '—';
}

// Save-all collects every editable value and dispatches the same payloads
// that the legacy saveTamizdatServer() + savePanel() handlers used.
async function settingsSaveAll(){
  // Push chip / line-list state into hidden textareas just before serializing.
  if(gid('tamMasqPool') && gid('sniChips')) gid('tamMasqPool').value = chipsSerialize();
  syncGeoLists();
  let tamizdatResult = null;
  let panelResult = null;
  const errors = [];
  try{
    tamizdatResult = await saveTamizdatServer({quiet:true});
  }catch(e){ errors.push('tamizdat-server'); }
  try{
    panelResult = await savePanel({quiet:true});
  }catch(e){ errors.push('panel'); }
  if(errors.length){
    toast('Save failed: '+errors.join(', '));
    return;
  }
  // Take a fresh baseline + clear dirty.
  snapshotSettingsBaseline();
  settingsClearDirty();

  const needsTamizdatRestart = !!(tamizdatResult && tamizdatResult.restart_required);
  const needsPanelRestart = !!(panelResult && panelResult.restart_required);
  if(!needsTamizdatRestart && !needsPanelRestart){
    toast('Saved');
    return;
  }

  const lines = ['Saved. Reboot is required for the changed settings to take effect.'];
  if(needsTamizdatRestart){
    lines.push('', 'tamizdat-server: changed startup parameters');
  }
  if(needsPanelRestart){
    const newUrl = (panelResult && panelResult.new_url) || '(URL не вычислен — открой панель вручную)';
    lines.push('', 'panel: port/base path/TLS changed', 'After panel reboot open:', newUrl);
  }
  const ok = await confirmDialog({
    title: 'Reboot required',
    message: lines.join('\n'),
    ok: needsTamizdatRestart && needsPanelRestart ? 'Reboot services' : (needsPanelRestart ? 'Reboot panel' : 'Reboot server'),
    cancel: 'Later',
    danger: true,
  });
  if(!ok){
    toast('Saved — reboot deferred');
    return;
  }
  try{
    if(needsTamizdatRestart){
      await fetch(H+'/api/service',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'restart'})});
    }
    if(needsPanelRestart){
      await fetch(H+'/api/panel/restart',{method:'POST'});
      toast('Reboot triggered — reopen panel after it comes back');
    }else{
      toast('tamizdat-server reboot triggered');
      setTimeout(loadSvcStatus,1500);
    }
  }catch(e){
    toast('Reboot request failed');
  }
}

// Wire reset-all-counters — button moved out of Settings 2026-05-25. The
// /api/reset-all endpoint is preserved; this stub keeps prior callers safe
// against ReferenceError if any external override re-wires it later.
async function dangerResetCounters(){
  if(!await confirmDialog({title:'Reset ALL traffic counters?',message:'bytes_up / bytes_down обнулятся для ВСЕХ пользователей. Безвозвратно.',ok:'Reset',danger:true}))return;
  try{
    const r=await fetch(H+'/api/reset-all',{method:'POST'});
    const d=await r.json();
    if(d.error){toast(d.error);return}
    toast('All traffic counters reset');
  }catch(e){toast('Reset failed')}
}

// Change-password form (Settings → User). Posts current + new password to
// /api/account/password. On success: keeps the current session valid
// (cookie unchanged), shows confirmation inline + as toast, clears the
// fields. On failure: surfaces the server error inline (red) without
// dropping the typed values.
async function changeAccountPassword(){
  const msg = gid('setAccountMsg');
  const cur = (gid('setAccountCurrent').value || '');
  const nw  = (gid('setAccountNew').value || '');
  const cf  = (gid('setAccountConfirm').value || '');
  msg.textContent = '';
  msg.style.color = 'var(--muted)';
  if(!cur || !nw){
    msg.textContent = 'Введите текущий и новый пароль';
    msg.style.color = 'var(--danger)';
    return;
  }
  if(nw !== cf){
    msg.textContent = 'New password и Confirm не совпадают';
    msg.style.color = 'var(--danger)';
    return;
  }
  if(nw.length < 4){
    msg.textContent = 'Новый пароль слишком короткий (минимум 4 символа)';
    msg.style.color = 'var(--danger)';
    return;
  }
  try{
    const r = await fetch(H+'/api/account/password',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({current: cur, new: nw}),
    });
    const d = await r.json();
    if(!r.ok || d.error){
      msg.textContent = d.error || ('HTTP '+r.status);
      msg.style.color = 'var(--danger)';
      return;
    }
    gid('setAccountCurrent').value = '';
    gid('setAccountNew').value = '';
    gid('setAccountConfirm').value = '';
    msg.textContent = 'Password updated';
    msg.style.color = 'var(--ok)';
    toast('Password updated');
  }catch(e){
    msg.textContent = 'Update failed';
    msg.style.color = 'var(--danger)';
  }
}

async function svcAction(action){
  if(action==='stop'&&!await confirmDialog({title:'Stop tamizdat-server?',message:'Port 443 will go down.\nPanel will be available at:\nhttps://'+location.hostname+':8443/p/\n\nContinue?',ok:'Stop',danger:true}))return;
  const ss=gid('statSvc');
  if(ss) ss.innerHTML='<span style="color:var(--muted)">...</span>';
  try{
    const r=await fetch(H+'/api/service',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
    const d=await r.json();
    if(d.error){toast(d.error);return}
    toast(action==='start'?'Started':action==='stop'?'Stopped':'Restarted');
    if(action==='stop'){setTimeout(()=>{location.href='https://'+location.hostname+':8443/p/'},1500)}
  }catch(e){toast('Error')}
  setTimeout(loadSvcStatus,1500);
}

gid('obUri').addEventListener('keydown',e=>{if(e.key==='Enter')importOutbound()});
gid('obTag').addEventListener('keydown',e=>{if(e.key==='Enter')importOutbound()});

// ---- Routing rules (Panel v5) ----
let routingRules = [];
// folders v1 (2026-05-10): folders are first-class siblings of
// ungrouped rules in the global priority queue.
let routingFolders = [];

function _ruleAutoDesc(m){
  const parts = [];
  for (const cat of ['geoip','geosite']){
    for (const v of (m[cat]||[])) {
      // Tolerate both "openai" and already-prefixed "geosite:openai".
      // Without this check, "geosite:openai" rendered as
      // "geosite:geosite:openai" in the description.
      parts.push(v.includes(':') ? v : (cat+':'+v));
    }
  }
  for (const v of (m.ip||[])) parts.push('ip:'+v);
  for (const v of (m.domain||[])) parts.push('domain:'+v);
  for (const v of (m.user||[])) parts.push('User:'+v);
  for (const v of (m.source||[])) parts.push('src:'+v);
  if (m.port) parts.push('port:'+m.port);
  if (m.network) parts.push('net:'+m.network);
  for (const v of (m.inbound_tag||[])) parts.push('in:'+v);
  return parts.length ? parts.join(', ') : '(match all)';
}

function renderRoutingRules(){
  const el = gid('routingTable');
  // folders v1 (2026-05-10): hierarchical render. Each "global queue
  // item" is either a folder (renders header row + indented children)
  // or an ungrouped rule. Order = folder.priority OR rule.priority for
  // ungrouped (both use the same global slot space). When two items
  // tie on priority the folder wins (id-stable), but in practice
  // priorities should be distinct after migrations + insert helpers.
  //
  // Sortable.js (2026-05-10): rendered as nested <div>s so Sortable can
  // target .rt-root (top-level: folders + ungrouped rules siblings) and
  // each .rt-folder-body (intra-folder reorder + cross-folder drop
  // target). Visual columns kept aligned via CSS grid (see .rt-row in
  // the <style> block).
  if(!routingRules.length && !routingFolders.length){
    // Show the actual default outbound the server falls back to when no
    // rule matches — that's the "active route" right now even though the
    // rules list is empty. Operator can then decide whether to add a
    // matching rule or leave the implicit default. (Previous hint about
    // "import outbound → auto-create rule" was misleading because the
    // bootstrap marker fires once: deleting all rules afterwards doesn't
    // re-trigger it, so the promise was a lie.)
    const def = (activeOb && activeOb !== 'direct') ? activeOb : 'direct';
    el.innerHTML = '<div class="status">Нет правил. Весь трафик идёт через <b>' + esc(def) + '</b> (default outbound).<br>Нажмите <b>+ Add rule</b> чтобы перехватить часть трафика на другой outbound, или <b>+ New folder</b> чтобы сгруппировать правила.</div>';
    return;
  }
  // Bucket: folder_id → [rule, rule, ...] sorted by intra priority asc
  const byFolder = new Map();
  const ungrouped = [];
  for(const r of routingRules){
    if(r.folder_id){
      if(!byFolder.has(r.folder_id)) byFolder.set(r.folder_id, []);
      byFolder.get(r.folder_id).push(r);
    } else {
      ungrouped.push(r);
    }
  }
  for(const arr of byFolder.values()) arr.sort((a,b)=> (a.priority - b.priority) || (a.id - b.id));
  // Build the global queue: ungrouped rules + folders, sorted by priority.
  const queue = [];
  for(const f of routingFolders) queue.push({kind:'folder', priority:f.priority, folder:f, rules:byFolder.get(f.id)||[]});
  for(const r of ungrouped) queue.push({kind:'rule', priority:r.priority, rule:r});
  queue.sort((a,b)=>{
    if(a.priority !== b.priority) return a.priority - b.priority;
    if(a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1;
    return 0;
  });
  const _ruleRow = (r, indentLeft) => {
    const desc = r.description_override || _ruleAutoDesc(r.match || {});
    const enabled = r.enabled ? '' : ' <span class="cell-meta empty">(disabled)</span>';
    const fidAttr = r.folder_id ? ` data-folder-id="${r.folder_id}"` : '';
    return `<div class="rt-row rt-rule" data-rule-id="${r.id}"${fidAttr}>
      <span class="rt-drag drag-handle" title="Drag to reorder">⋮⋮</span>
      <span class="rt-pri user-name">${r.priority}</span>
      <span class="rt-desc">${esc(desc)}${enabled}</span>
      <span class="rt-outbound">${outboundBadge(r.outbound_tag)}</span>
      <div class="rt-actions actions">
        <button class="btn btn-ghost btn-sm" onclick="moveRoutingRule(${r.id},'up')" title="Move up">↑</button>
        <button class="btn btn-ghost btn-sm" onclick="moveRoutingRule(${r.id},'down')" title="Move down">↓</button>
        <button class="btn btn-edit btn-sm" onclick="editRoutingRule(${r.id})">Edit</button>
        <button class="btn btn-del btn-sm" onclick="delRoutingRule(${r.id})">Del</button>
      </div>
    </div>`;
  };
  let h = '<div class="rt-scroll"><div class="rt-root" id="rtRoot">';
  for(const item of queue){
    if(item.kind === 'folder'){
      const f = item.folder;
      const folderEnabledClass = f.enabled ? '' : ' folder-disabled';
      const folderEnabledLabel = f.enabled ? 'Enabled' : 'Disabled';
      const togglePill = f.enabled ? '⏻' : '⊘';
      h += `<div class="rt-folder${folderEnabledClass}" data-folder-id="${f.id}">`;
      h += `<div class="rt-row rt-folder-head" data-folder-id="${f.id}">
        <span class="rt-drag drag-handle folder-drag-handle" title="Drag folder">⋮⋮</span>
        <span class="rt-pri user-name">${f.priority}</span>
        <span class="rt-desc"><span class="group-pill">📁 ${esc(f.name)} <span class="group-meta">${item.rules.length}</span></span> <span class="cell-meta">${folderEnabledLabel}</span></span>
        <span class="rt-outbound"></span>
        <div class="rt-actions actions">
          <button class="btn btn-ghost btn-sm" onclick="moveRoutingFolder(${f.id},'up')" title="Move folder up">↑</button>
          <button class="btn btn-ghost btn-sm" onclick="moveRoutingFolder(${f.id},'down')" title="Move folder down">↓</button>
          <button class="btn btn-ghost btn-sm" onclick="toggleRoutingFolder(${f.id}, ${f.enabled?0:1})" title="${folderEnabledLabel}">${togglePill}</button>
          <button class="btn btn-edit btn-sm" onclick="renameRoutingFolder(${f.id})" title="Rename">✎</button>
          <button class="btn btn-edit btn-sm" onclick="addRuleInFolder(${f.id})" title="Add rule inside">＋</button>
          <button class="btn btn-del btn-sm" onclick="delRoutingFolder(${f.id})" title="Delete">🗑</button>
        </div>
      </div>`;
      h += `<div class="rt-folder-body" data-folder-id="${f.id}">`;
      for(const r of item.rules) h += _ruleRow(r, true);
      h += `</div></div>`;
    } else {
      h += _ruleRow(item.rule, false);
    }
  }
  h += '</div></div>';
  el.innerHTML = h;
  _wireRoutingDrag(el);
}

// Sortable.js based drag for routing rules. Replaces the legacy Pointer
// Events implementation. Two Sortable instances cover:
//   - .rt-root          → top-level queue (folders + ungrouped siblings)
//   - .rt-folder-body   → one per folder, for intra-folder reorder +
//                          cross-folder drop target
// All share group:'routing' so a rule can drag between them. A folder
// CANNOT be dropped into a folder body (onMove veto below).
//
// On every successful drop persistRoutingLayout() walks the DOM, builds
// the canonical layout descriptor, and POSTs it to
// /api/routing/layout. The server re-renders the snapshot and returns
// the fresh rules+folders so the JS re-renders without an extra fetch.
function _wireRoutingDrag(container){
  if(typeof Sortable === 'undefined') return;   // vendored copy missing — fall back to up/down arrows
  const root = container.querySelector('.rt-root');
  if(!root) return;
  const blockFolderIntoBody = (evt) => {
    const dragged = evt.dragged;
    const to = evt.to;
    if(!dragged || !to) return true;
    if(dragged.classList.contains('rt-folder') && to.classList.contains('rt-folder-body')) return false;
    return true;
  };
  const opts = {
    group: 'routing',
    handle: '.rt-drag',
    animation: 180,
    fallbackOnBody: true,
    swapThreshold: 0.6,
    ghostClass: 'sortable-ghost',
    chosenClass: 'sortable-chosen',
    dragClass: 'sortable-drag',
    onMove: blockFolderIntoBody,
    onEnd: persistRoutingLayout,
  };
  Sortable.create(root, opts);
  container.querySelectorAll('.rt-folder-body').forEach((body) => {
    Sortable.create(body, opts);
  });
}

async function persistRoutingLayout(){
  const root = document.querySelector('#rtRoot');
  if(!root) return;
  const layout = [];
  for(const child of root.children){
    if(child.classList.contains('rt-folder')){
      const fid = Number(child.dataset.folderId);
      const childIds = [];
      const body = child.querySelector('.rt-folder-body');
      if(body){
        for(const ruleEl of body.children){
          if(ruleEl.classList.contains('rt-rule')) childIds.push(Number(ruleEl.dataset.ruleId));
        }
      }
      layout.push({kind:'folder', id: fid, children: childIds});
    } else if(child.classList.contains('rt-rule')){
      layout.push({kind:'rule', id: Number(child.dataset.ruleId)});
    }
  }
  try{
    const r = await fetch(H+'/api/routing/layout',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({layout}),
    });
    const d = await r.json();
    if(d.error){ toast(d.error); loadRoutingRules(); return; }
    if(Array.isArray(d.rules)) routingRules = d.rules;
    if(Array.isArray(d.folders)) routingFolders = d.folders;
    renderRoutingRules();
  } catch(e){ toast('Reorder failed'); loadRoutingRules(); }
}

// (Legacy Pointer-Events drag implementation deleted 2026-05-10 — see
// _wireRoutingDrag + persistRoutingLayout above for the Sortable.js
// rewrite. The /api/routing/reorder, /api/routing/folders/reorder, and
// /api/routing/.../move endpoints remain wired for the up/down arrow
// buttons + any external callers.)

async function loadRoutingRules(){
  try{
    const r = await fetch(H+'/api/routing?t='+Date.now());
    if(r.status===401){location.reload();return}
    const d = await r.json();
    routingRules = d.rules || [];
    routingFolders = d.folders || [];
    renderRoutingRules();
  }catch(e){}
}

function _populateRuleOutboundSelect(currentTag){
  const sel = gid('ruleOutbound');
  let opts = '';
  for (const o of outbounds){
    opts += `<option value="${esc(o.tag)}"${o.tag===currentTag?' selected':''}>${esc(o.tag)}</option>`;
  }
  // sentinel: block (drop the connection)
  opts += `<option value="block"${currentTag==='block'?' selected':''}>block</option>`;
  sel.innerHTML = opts || '<option value="direct">direct</option>';
}

function _populateRuleFolderSelect(currentId){
  const sel = gid('ruleFolderSel');
  if(!sel) return;
  let opts = '<option value="">— ungrouped —</option>';
  for(const f of routingFolders){
    const sel_attr = (currentId !== null && currentId !== undefined && Number(currentId) === f.id) ? ' selected' : '';
    opts += `<option value="${f.id}"${sel_attr}>📁 ${esc(f.name)}</option>`;
  }
  sel.innerHTML = opts;
}

function openAddRoutingRule(){
  gid('ruleModalTitle').textContent = 'Add routing rule';
  const g = gid('ruleGroup'); if(g) g.value = '';
  gid('ruleId').value = '';
  gid('ruleDesc').value = '';
  gid('ruleGeoIP').value = '';
  gid('ruleGeosite').value = '';
  gid('ruleIP').value = '';
  gid('ruleDomain').value = '';
  gid('ruleUser').value = '';
  gid('ruleSource').value = '';
  gid('rulePort').value = '';
  gid('ruleNetwork').value = '';
  gid('ruleInbound').value = '';
  gid('ruleEnabled').checked = true;
  _populateRuleOutboundSelect('direct');
  _populateRuleFolderSelect(null);
  _refreshGeoFieldEnable();
  gid('ruleModal').classList.add('show');
}

function editRoutingRule(id){
  const r = routingRules.find(x => x.id === id);
  if(!r) return;
  const m = r.match || {};
  gid('ruleModalTitle').textContent = 'Edit routing rule';
  const g = gid('ruleGroup'); if(g) g.value = r.group_name || '';
  gid('ruleId').value = String(id);
  gid('ruleDesc').value = r.description_override || '';
  gid('ruleGeoIP').value = (m.geoip||[]).join(', ');
  gid('ruleGeosite').value = (m.geosite||[]).join(', ');
  gid('ruleIP').value = (m.ip||[]).join(', ');
  gid('ruleDomain').value = (m.domain||[]).join(', ');
  gid('ruleUser').value = (m.user||[]).join(', ');
  gid('ruleSource').value = (m.source||[]).join(', ');
  gid('rulePort').value = m.port || '';
  gid('ruleNetwork').value = m.network || '';
  gid('ruleInbound').value = (m.inbound_tag||[]).join(', ');
  gid('ruleEnabled').checked = !!r.enabled;
  _populateRuleOutboundSelect(r.outbound_tag);
  _populateRuleFolderSelect(r.folder_id);
  _refreshGeoFieldEnable();
  gid('ruleModal').classList.add('show');
}

function _csvList(s){
  s = (s||'').trim();
  if(!s) return [];
  return s.split(',').map(x => x.trim()).filter(Boolean);
}

async function saveRoutingRule(){
  const id = gid('ruleId').value.trim();
  const match = {};
  const geoip = _csvList(gid('ruleGeoIP').value); if(geoip.length) match.geoip = geoip;
  const geosite = _csvList(gid('ruleGeosite').value); if(geosite.length) match.geosite = geosite;
  const ip = _csvList(gid('ruleIP').value); if(ip.length) match.ip = ip;
  const dom = _csvList(gid('ruleDomain').value); if(dom.length) match.domain = dom;
  const usr = _csvList(gid('ruleUser').value); if(usr.length) match.user = usr;
  const src = _csvList(gid('ruleSource').value); if(src.length) match.source = src;
  const inb = _csvList(gid('ruleInbound').value); if(inb.length) match.inbound_tag = inb;
  const port = gid('rulePort').value.trim(); if(port) match.port = port;
  const nw = gid('ruleNetwork').value.trim(); if(nw) match.network = nw;
  const fSel = gid('ruleFolderSel');
  const folderRaw = fSel ? (fSel.value || '').trim() : '';
  const folderId = folderRaw === '' ? null : Number(folderRaw);
  const body = {
    outbound_tag: gid('ruleOutbound').value,
    match,
    description_override: gid('ruleDesc').value.trim(),
    enabled: gid('ruleEnabled').checked,
    group_name: (gid('ruleGroup')||{}).value || '',
    folder_id: folderId,
  };
  try{
    const url = id ? H+'/api/routing/'+encodeURIComponent(id) : H+'/api/routing';
    const method = id ? 'PUT' : 'POST';
    const r = await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    gid('ruleModal').classList.remove('show');
    toast(id ? 'Rule saved' : 'Rule created');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

async function delRoutingRule(id){
  const r = routingRules.find(x => x.id === id);
  if(!r) return;
  const desc = r.description_override || _ruleAutoDesc(r.match || {});
  if(!await confirmDialog({title:'Delete routing rule',message:'Delete rule '+r.priority+': '+desc+'?',ok:'Delete',danger:true})) return;
  try{
    const resp = await fetch(H+'/api/routing/'+encodeURIComponent(id),{method:'DELETE'});
    const d = await resp.json();
    if(d.error){toast(d.error);return}
    toast('Rule deleted');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

// Curated geo presets. Each preset has the bare NAME (no prefix) and a
// human description; the modal injects the geoip:/geosite: prefix when
// the operator picks it.
const _GEO_PRESETS = {
  geoip: [
    // Tags ниже = имена tag-секций в geoip.dat от Loyalsoldier/v2ray-rules-dat.
    // Полный список тегов: github.com/Loyalsoldier/v2ray-rules-dat → geoip.dat
    {name: 'telegram',    desc: 'Telegram CIDR (Mobile/MTProto, DC-1..5)'},
    {name: 'google',      desc: 'Google services (Search, Maps, Drive, Workspace)'},
    {name: 'youtube',     desc: 'YouTube CDN ranges'},
    {name: 'twitter',     desc: 'Twitter / X CIDRs'},
    {name: 'facebook',    desc: 'Facebook / Instagram / WhatsApp / Meta CDN'},
    {name: 'netflix',     desc: 'Netflix CDN'},
    {name: 'apple',       desc: 'Apple iCloud / App Store / iMessage'},
    {name: 'microsoft',   desc: 'Microsoft / Outlook / Office365 / Azure'},
    {name: 'github',      desc: 'GitHub + GitHub Pages CDN'},
    {name: 'cloudflare',  desc: 'Cloudflare CDN ranges (popular front-domain target)'},
    {name: 'akamai',      desc: 'Akamai CDN'},
    {name: 'amazon',      desc: 'Amazon AWS / CloudFront'},
    {name: 'private',     desc: 'RFC1918 + LAN (10/8, 172.16/12, 192.168/16, 127/8)'},
    {name: 'cn',          desc: 'China-resident IPs (geolite "country=CN")'},
    {name: 'ru',          desc: 'Russia-resident IPs (geolite "country=RU")'},
    {name: 'us',          desc: 'United States-resident IPs'},
    {name: 'ir',          desc: 'Iran-resident IPs'},
  ],
  geosite: [
    // geosite.dat от Loyalsoldier — github.com/Loyalsoldier/v2ray-rules-dat
    // category-* теги смотри: github.com/Loyalsoldier/domain-list-custom
    {name: 'telegram',          desc: 'Telegram домены (telegram.org / t.me / web.telegram.org)'},
    {name: 'openai',            desc: 'OpenAI / ChatGPT (openai.com, chat.openai.com)'},
    {name: 'category-ai-!cn',   desc: 'AI-сервисы кроме CN (популярные LLM/search/code providers)'},
    {name: 'google',            desc: 'Google домены (gstatic, googleapis, gvt1, …)'},
    {name: 'youtube',           desc: 'YouTube + youtu.be + ytimg'},
    {name: 'twitter',           desc: 'Twitter / X / x.com'},
    {name: 'facebook',          desc: 'Facebook / Instagram / WhatsApp / Meta'},
    {name: 'discord',           desc: 'Discord'},
    {name: 'tiktok',            desc: 'TikTok / ByteDance'},
    {name: 'github',            desc: 'GitHub'},
    {name: 'microsoft',         desc: 'Microsoft / Outlook / Office365 / Azure'},
    {name: 'apple',             desc: 'Apple iCloud / iTunes / App Store'},
    {name: 'netflix',           desc: 'Netflix'},
    {name: 'twitch',            desc: 'Twitch'},
    {name: 'category-porn',     desc: 'Adult content (block-by-default список)'},
    {name: 'category-ads-all',  desc: 'Все рекламные сети + трекеры (Loyalsoldier)'},
    {name: 'category-ads',      desc: 'Меньший анти-рекламный набор'},
    {name: 'category-gov-ru',   desc: 'gov.ru / mil.ru — что Россия блочит из вне'},
    {name: 'category-gov-cn',   desc: 'gov.cn / china-government'},
    {name: 'category-gov-us',   desc: '*.gov / *.mil — US government'},
    {name: 'cn',                desc: 'CN-resident домены (gov, baidu, weibo, …)'},
    {name: 'geolocation-!cn',   desc: 'Все НЕ-CN домены (для GFW-bypass routing)'},
    // Windows-телеметрия. Loyalsoldier их НЕ имеет — нужен runetfreedom-set
    // или multi-source merge (Phase 4). Если вписать сейчас — правило не
    // сматчит ничего пока источник не сменён. Помечены как [WSB].
    {name: 'win-spy',           desc: '[WSB] Telemetry/analytics (нужен WindowsSpyBlocker .dat или merge)'},
    {name: 'win-update',        desc: '[WSB] Windows Update endpoints (KB delivery, defender)'},
    {name: 'win-extra',         desc: '[WSB] Прочие MS-домены (store, edge, bing)'},
  ],
};

// In-memory cache of server-side geo categories, plus per-open-session
// state for which entries the operator already clicked "Use" on (so we
// can hide their Use button — operator wanted ✓ marker + no double-add).
let _geoCatsCache = null;
let _geoModalKind = '';
let _geoModalUsed = new Set();

async function _loadGeoCats(){
  if(_geoCatsCache) return _geoCatsCache;
  try{
    const r = await fetch(H+'/api/geo-categories?t='+Date.now());
    _geoCatsCache = await r.json();
    if(!_geoCatsCache || !Array.isArray(_geoCatsCache.geoip)) _geoCatsCache = {geoip:[], geosite:[]};
  }catch(e){
    _geoCatsCache = {geoip:[], geosite:[]};
  }
  return _geoCatsCache;
}

function _curatedMap(kind){
  const m = new Map();
  for(const p of (_GEO_PRESETS[kind] || [])) m.set(p.name, p.desc);
  return m;
}

function _renderGeoList(kind, q){
  const cats = (_geoCatsCache && _geoCatsCache[kind]) || [];
  const curated = _curatedMap(kind);
  const order = (_GEO_PRESETS[kind] || []).map(p => p.name);
  q = (q||'').trim().toLowerCase();
  // Filter: empty query → curated first then alphabetic. Query → substring
  // match on category name, no curated boost (operator typed a refining
  // word so they care about content not ordering).
  let filtered;
  if(q){
    filtered = cats.filter(c => c.indexOf(q) !== -1);
  }else{
    const seen = new Set();
    filtered = [];
    for(const n of order){
      if(cats.includes(n) && !seen.has(n)){ filtered.push(n); seen.add(n); }
    }
    for(const c of cats){
      if(!seen.has(c)){ filtered.push(c); seen.add(c); }
    }
  }
  const limit = 200;
  const slice = filtered.slice(0, limit);
  const parts = [];
  for(const name of slice){
    const desc = curated.get(name);
    const used = _geoModalUsed.has(name);
    const descHtml = desc ? '<div class="desc">'+esc(desc)+'</div>' : '';
    const btn = used
      ? '<span style="color:var(--ok,#16a34a);font-weight:600;font-size:12.5px;padding:2px 8px">✓ added</span>'
      : '<button class="btn btn-primary btn-sm" type="button" data-geo-name="'+esc(name)+'">Use</button>';
    parts.push('<div class="geo-preset"><div class="info"><div class="name"><code>'+kind+':'+esc(name)+'</code></div>'+descHtml+'</div>'+btn+'</div>');
  }
  if(filtered.length > limit){
    parts.push('<div style="text-align:center;padding:8px;font-size:12px;color:var(--muted)">…ещё '+(filtered.length-limit)+' совпадений — уточни поиск</div>');
  }
  if(!parts.length){
    parts.push('<div style="text-align:center;padding:20px;color:var(--muted);font-size:13px">Ничего не найдено</div>');
  }
  gid('geoPresetList').innerHTML = parts.join('');
  gid('geoHelpCount').textContent = 'Найдено: '+filtered.length+' / '+cats.length+(q ? ' (фильтр: "'+q+'")' : '');
  // Wire Use buttons. Each click appends to target field + flips the
  // entry to ✓ added without closing the modal (operator wanted multi-
  // pick).
  for(const btn of gid('geoPresetList').querySelectorAll('button[data-geo-name]')){
    btn.addEventListener('click', () => {
      const name = btn.getAttribute('data-geo-name');
      const target = (_geoModalKind === 'geoip') ? gid('ruleGeoIP') : gid('ruleGeosite');
      const cur = (target.value || '').trim();
      const tokens = cur ? cur.split(/\s*,\s*/).filter(Boolean) : [];
      if(!tokens.includes(name)) tokens.push(name);
      target.value = tokens.join(', ');
      _geoModalUsed.add(name);
      _renderGeoList(_geoModalKind, gid('geoHelpSearch').value);
    });
  }
}

async function openGeoHelp(kind){
  _geoModalKind = kind;
  _geoModalUsed = new Set();
  gid('geoHelpTitle').textContent = (kind === 'geoip') ? 'GeoIP — наборы (поиск)' : 'Geosite — наборы (поиск)';
  gid('geoHelpSearch').value = '';
  gid('geoPresetList').innerHTML = '<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">Загрузка категорий…</div>';
  gid('geoHelpCount').textContent = '';
  gid('geoHelpModal').classList.add('show');
  // Pre-populate tokens already in the target field so they show as ✓ added.
  const cur = ((kind === 'geoip') ? gid('ruleGeoIP').value : gid('ruleGeosite').value) || '';
  for(const t of cur.split(/\s*,\s*/)) if(t) _geoModalUsed.add(t);
  await _loadGeoCats();
  _renderGeoList(kind, '');
  setTimeout(() => gid('geoHelpSearch').focus(), 50);
}

// Search input handler — debounced lightly to avoid re-rendering 200 rows
// on every keystroke for slow browsers.
let _geoSearchTimer = null;
document.addEventListener('input', (e) => {
  if(e.target && e.target.id === 'geoHelpSearch'){
    clearTimeout(_geoSearchTimer);
    _geoSearchTimer = setTimeout(() => _renderGeoList(_geoModalKind, e.target.value), 80);
  }
});

// Disable GeoIP/Geosite fields in the rule modal when the corresponding
// URL is empty in Settings (operator turned off geo loading to free
// memory). Tooltip points them at Settings.
async function _refreshGeoFieldEnable(){
  try{
    const r = await fetch(H+'/api/inbound?t='+Date.now());
    const d = await r.json();
    // Phase 4 (2026-05-10): inbound_geoip_url / inbound_geosite_url may be
    // multi-line. Match the server's splitGeoURLs filter: drop blanks and
    // "# comment" lines. Field is "disabled" only when zero real URLs.
    const _hasUrl = (s) => (s || '').split('\n').some(ln => {
      const t = ln.trim(); return t !== '' && !t.startsWith('#');
    });
    const gipDisabled = !_hasUrl(d.inbound_geoip_url);
    const gstDisabled = !_hasUrl(d.inbound_geosite_url);
    const gip = gid('ruleGeoIP'); if(gip){
      gip.disabled = gipDisabled;
      gip.title = gipDisabled ? 'GeoIP отключён в Settings (URL пуст). Зайди в Settings → GeoIP URL.' : '';
    }
    const gst = gid('ruleGeosite'); if(gst){
      gst.disabled = gstDisabled;
      gst.title = gstDisabled ? 'Geosite отключён в Settings (URL пуст). Зайди в Settings → Geosite URL.' : '';
    }
  }catch(e){ /* offline — leave fields enabled */ }
}

async function moveRoutingRule(id, direction){
  try{
    const r = await fetch(H+'/api/routing/'+encodeURIComponent(id)+'/move',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({direction})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    if(d.noop){toast('Already at '+(direction==='up'?'top':'bottom'));return}
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

// ---- Folders v1 (2026-05-10) ----
async function moveRoutingFolder(id, direction){
  try{
    const r = await fetch(H+'/api/routing/folders/'+encodeURIComponent(id)+'/move',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({direction})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    if(d.noop){toast('Already at '+(direction==='up'?'top':'bottom'));return}
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

async function toggleRoutingFolder(id, enabled){
  try{
    const r = await fetch(H+'/api/routing/folders/'+encodeURIComponent(id),{
      method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled: enabled === 1 || enabled === true})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    toast(d.enabled ? 'Folder enabled' : 'Folder disabled');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

async function renameRoutingFolder(id){
  const f = routingFolders.find(x => x.id === id);
  if(!f) return;
  const name = prompt('Folder name', f.name);
  if(name === null) return;
  if(name.trim() === '' || name.trim() === f.name) return;
  try{
    const r = await fetch(H+'/api/routing/folders/'+encodeURIComponent(id),{
      method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name: name.trim()})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    toast('Renamed');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

async function delRoutingFolder(id){
  const f = routingFolders.find(x => x.id === id);
  if(!f) return;
  const childCount = routingRules.filter(r => r.folder_id === id).length;
  const msg = childCount
    ? `Delete folder "${f.name}"? It contains ${childCount} rule(s) — they will become ungrouped (NOT deleted).`
    : `Delete folder "${f.name}"?`;
  if(!await confirmDialog({title:'Delete folder',message:msg,ok:'Delete',danger:true})) return;
  try{
    const resp = await fetch(H+'/api/routing/folders/'+encodeURIComponent(id),{method:'DELETE'});
    const d = await resp.json();
    if(d.error){toast(d.error);return}
    toast(d.orphaned_rules ? `Deleted (${d.orphaned_rules} rules ungrouped)` : 'Folder deleted');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

async function openNewRoutingFolder(){
  const name = prompt('Folder name (e.g. "Windows Telemetry", "RU Mobile")');
  if(name === null) return;
  if(name.trim() === '') return;
  try{
    const r = await fetch(H+'/api/routing/folders',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name: name.trim()})});
    const d = await r.json();
    if(d.error){toast(d.error);return}
    toast('Folder created');
    loadRoutingRules();
  }catch(e){toast('Error: '+e)}
}

function addRuleInFolder(folderId){
  // Open the rule modal pre-seeded with folder_id so the new rule
  // lands inside this folder at the bottom of its intra-folder queue.
  openAddRoutingRule();
  const sel = gid('ruleFolderSel');
  if(sel){
    sel.value = String(folderId);
  }
}

// ---- Hash-based SPA router ----
const ROUTES = ['overview','outbounds','routing','settings'];
let _settingsLoaded = false;
let _routingLoaded = false;
function currentRoute(){
  const h = (location.hash || '').replace(/^#/,'');
  return ROUTES.indexOf(h) >= 0 ? h : 'overview';
}
function showRoute(route){
  for(const r of ROUTES){
    const pg = gid('page-'+r);
    if(pg) pg.style.display = (r===route ? '' : 'none');
  }
  document.querySelectorAll('.nav a[data-route]').forEach(a=>{
    a.classList.toggle('active', a.dataset.route===route);
  });
  if(route==='settings' && !_settingsLoaded){
    _settingsLoaded = true;
    loadSettings();
  }
  if(route==='routing'){
    if(!_routingLoaded){
      _routingLoaded = true;
    }
    loadRoutingRules();
  }
  // Hide the Settings sticky save-bar on every page-change. loadSettings()
  // re-shows it only if there are unsaved changes (via settingsClearDirty
  // → settingsMarkDirty toggling).
  const sb = gid('saveBar');
  if(sb && route !== 'settings') sb.classList.remove('show');
}
window.addEventListener('hashchange', ()=>showRoute(currentRoute()));
showRoute(currentRoute());

loadOutbounds().then(()=>{loadUsers();if(activeOb&&activeOb!=='direct')testOb(activeOb)});loadSvcStatus();
_startSysinfo();
setInterval(loadUsers, 1500);
setInterval(()=>{loadOutbounds()},3000);
setInterval(loadSvcStatus,5000);
setInterval(()=>{if(currentRoute()==='routing')loadRoutingRules()},4000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def get_session_user(self):
        c = http.cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        if "session" not in c:
            return None
        return _session_username(c["session"].value)

    def send_json(self, data, code=200):
        try:
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_html(self, html, code=200, extra_headers=None):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, url, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", url)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _path(self):
        p = urlparse(self.path).path
        if BASE_PATH and p.startswith(BASE_PATH):
            p = p[len(BASE_PATH):]
        return p.rstrip("/") or "/"

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        path = self._path()
        user = self.get_session_user()
        if path == "/qrcode.js":
            body = QRCODE_JS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/login":
            self.send_html(LOGIN_HTML.replace("ERROR_MSG", "").replace("LOGIN_ACTION", BASE_PATH + "/login")); return
        if path == "/logout":
            c = http.cookies.SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
                if "session" in c: sessions.pop(c["session"].value, None); _save_sessions()
            except: pass
            self.send_redirect(BASE_PATH + "/login", {"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + COOKIE_SECURE_FLAG}); return
        if not user:
            # API endpoints expect JSON. Sending 302 → HTML login page
            # breaks `await fetch().json()` with cryptic "Unexpected token
            # '<'" SyntaxError shown in red inside dialogs/toasts. Return
            # 401 JSON for /api/* so frontend can handle gracefully.
            if path.startswith("/api/"):
                self.send_json({"error": "unauthenticated", "login": BASE_PATH + "/login"}, 401)
            else:
                self.send_redirect(BASE_PATH + "/login")
            return

        if path in ("/", ""):
            qr_ver = _hl.md5(QRCODE_JS.encode()).hexdigest()[:8]
            # LOGGED_USER_INITIAL must be replaced BEFORE LOGGED_USER —
            # otherwise the prefix match on "LOGGED_USER" eats the
            # placeholder and leaves a stray "_INITIAL" in the avatar.
            self.send_html(PANEL_HTML.replace("LOGGED_USER_INITIAL", (user[:1] or "?").upper()).replace("LOGGED_USER", user).replace("LOGOUT_URL", BASE_PATH + "/logout").replace("QRCODE_SRC_URL", f"{BASE_PATH}/qrcode.js?v={qr_ver}").replace("__SORTABLE_JS_INLINE_MARKER__", SORTABLE_JS_INLINE))
        elif path == "/api/me":
            # Settings → User block (2026-05-25): the panel needs the
            # currently signed-in username to render the "Signed in as"
            # field next to the change-password form. We avoid leaking
            # other admin usernames here — /api/panel already exposes the
            # full list via admin_users.
            self.send_json({"username": user})
        elif path == "/api/users":
            try:
                self.send_json({"users": list_users()})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
        elif path.startswith("/api/users/") and path.endswith("/uri"):
            uid = unquote(path[len("/api/users/"):-len("/uri")])
            u = get_user(uid)
            if not u:
                self.send_json({"error": "user not found"}, 404)
                return
            uri = make_user_uri(u)
            if not uri:
                self.send_json({"error": "inbound_priv_key/path not yet configured"}, 400)
                return
            # I-3 (multi-user-cleanup): the URI already embeds shortid via
            # ?shortid=<...>; surfacing it as a separate field was redundant.
            self.send_json({"id": u["id"], "name": u["name"], "uri": uri})
        elif path.startswith("/api/users/"):
            uid = unquote(path[len("/api/users/"):])
            u = get_user(uid)
            if not u:
                self.send_json({"error": "user not found"}, 404)
                return
            self.send_json(u)
        elif path == "/api/inbound":
            self.send_json(get_inbound_settings())
        elif path == "/api/system/interfaces":
            # Enumerate Linux network interfaces with their IPv4 addresses
            # so the panel's direct-outbound bind_iface dropdown can render
            # "ens18 — 203.0.113.10, 198.51.100.10" labels. Tries iproute2
            # 'ip -j addr show' first (Bullseye+ has it), falls back to
            # name-only enumeration via /proc/net/dev when ip / json missing.
            import json as _json, subprocess as _sub
            entries = []
            try:
                proc = _sub.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=2)
                if proc.returncode == 0 and proc.stdout.strip():
                    data = _json.loads(proc.stdout)
                    for ifc in data:
                        name = ifc.get("ifname", "")
                        if not name or name == "lo":
                            continue
                        ips = [a.get("local") for a in ifc.get("addr_info", []) if a.get("family") == "inet" and a.get("local")]
                        entries.append({"name": name, "ipv4": ips})
            except Exception:
                pass
            if not entries:
                # Fallback: name-only from /proc/net/dev.
                try:
                    with open("/proc/net/dev") as f:
                        f.readline(); f.readline()
                        for line in f:
                            n = line.split(":", 1)[0].strip()
                            if n and n != "lo":
                                entries.append({"name": n, "ipv4": []})
                except Exception:
                    pass
            entries.sort(key=lambda e: e["name"])
            # Backwards-compat field "interfaces" = list of names; new
            # callers consume "details" for IP info.
            self.send_json({
                "interfaces": [e["name"] for e in entries],
                "details": entries,
            })
            return
        elif path == "/api/outbounds":
            cfg = load_config()
            counts = count_users_per_outbound(cfg)
            obs = []
            for o in get_outbounds(cfg):
                tag = o.get("tag", "")
                # dl/ul come straight from the outbounds table now —
                # _row_to_outbound already populated them from the
                # bytes_down / bytes_up columns. The legacy _ob_traffic
                # dict-based path is gone (it was a Phase 1 stub that
                # returned constant zeros, see internal/userdb/accounting.go
                # for the real flush path). Use outbound_api_entry() so
                # parsed balancer fields (including high-RTT failover) are
                # not dropped before the JS edit modal reopens.
                obs.append(outbound_api_entry(o, counts.get(tag, 0)))
            self.send_json({"outbounds": obs, "active": get_active_outbound(cfg)})
        elif path == "/api/clients":
            result = {"clients": {}, "user_stats": {}, "dl_total": 0, "ul_total": 0, "traffic_available": False}
            _clients_cache["data"] = result
            _clients_cache["time"] = time.time()
            self.send_json(result)
        elif path == "/api/geo-categories":
            # Full list of every category tag found in the on-disk geoip*.dat
            # and geosite*.dat files. Powers the search-driven preset picker
            # in the routing-rule modal. Cached + invalidated on file mtime.
            self.send_json(_load_geo_categories())
        elif path == "/api/service":
            try:
                r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
                status = r.stdout.strip() or "unknown"
                uptime = ""
                if status == "active":
                    r2 = subprocess.run(["systemctl", "show", SERVICE_NAME, "--property=ActiveEnterTimestamp"], capture_output=True, text=True)
                    ts = r2.stdout.strip().split("=", 1)[-1]
                    if ts:
                        uptime = f"since {ts}"
                self.send_json({"status": status, "uptime": uptime, "traffic_dl": 0, "traffic_ul": 0, "traffic_available": False})
            except Exception as e:
                self.send_json({"status": "unknown", "error": str(e), "traffic_dl": 0, "traffic_ul": 0, "traffic_available": False})
        elif path == "/api/sysinfo":
            # CPU/RAM/Swap/Disk for the Overview resource ring widget.
            self.send_json(get_sysinfo())
        elif path == "/api/sysinfo/cpu":
            # Lightweight cousin of /api/sysinfo — returns ONLY the CPU
            # gauge so the frontend can poll it at 500 ms without paying
            # for /proc/meminfo parsing + statvfs on every tick. The cpu_pct
            # read uses the same _sysinfo_prev cache so quick consecutive
            # calls compute a per-window instantaneous rate.
            self.send_json({"cpu_pct": _read_cpu_pct()})
        elif path == "/api/settings":
            cfg = load_config()
            for ib in cfg.get("inbounds", []):
                if ib.get("type") in ("tamizdat", "anytls"):
                    tls = ib.get("tls", {})
                    fb = ib.get("fallback", {})
                    self.send_json({
                        "listen_port": ib.get("listen_port", 443),
                        "jitter_ms": ib.get("server_jitter_ms", 0),
                        "fallback_server": fb.get("server", ""),
                        "fallback_port": fb.get("server_port", 0),
                        "tls_cert": tls.get("certificate_path", ""),
                        "tls_key": tls.get("key_path", ""),
                    })
                    return
            self.send_json({"error": "no tamizdat inbound"}, 404)
        elif path == "/api/routing":
            try:
                # folders v1: surface folders alongside rules so the
                # panel JS can render the hierarchy in one round-trip.
                self.send_json({
                    "rules": list_routing_rules(),
                    "folders": list_routing_folders(),
                })
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return
        elif path == "/api/routing/folders":
            try:
                self.send_json({"folders": list_routing_folders()})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return
        elif path == "/api/tamizdat":
            # Settings refactor Phase 2 (2026-05-11): the response is built
            # from the flat inbound_* settings table (not the legacy
            # panel_inbounds_json blob). private_key is resolved from
            # inbound_priv_key, falling back to reading inbound_priv_key_path
            # so existing operators who store the key in a file keep working.
            # public_key is auto-derived from the private key for display.
            ensure_db()
            s = get_inbound_settings()
            priv = (s.get("inbound_priv_key", "") or "").strip()
            if not priv:
                priv_path = (s.get("inbound_priv_key_path", "") or "").strip()
                if priv_path and os.path.exists(priv_path):
                    try:
                        with open(priv_path, "r") as f:
                            priv = f.read().strip()
                    except Exception:
                        priv = ""
            pub = ""
            if priv and len(priv) == 64:
                pub = x25519_public_from_private(priv) or ""

            def _int(key, default):
                try:
                    return int(s.get(key) or default)
                except (TypeError, ValueError):
                    return default

            try:
                enabled = int(s.get("inbound_bundle_enabled", "1") or "0") != 0
            except (TypeError, ValueError):
                enabled = True
            self.send_json({
                "enabled":           enabled,
                "listen_addr":       s.get("inbound_listen_addr", "0.0.0.0"),
                "listen_port":       _int("inbound_listen_port", 7780),
                "public_port":       _int("inbound_public_port", 443),
                "private_key":       priv,
                "private_key_path":  s.get("inbound_priv_key_path", ""),
                "public_key":        pub,
                "cert_path":         s.get("inbound_cert_path", ""),
                "key_path":          s.get("inbound_key_path", ""),
                "masquerade_domain": s.get("inbound_masquerade_domain", ""),
                "masquerade_pool":   s.get("inbound_masquerade_pool", ""),
                "bootstrap_sni":     s.get("inbound_bootstrap_sni", ""),
                "fingerprint":       s.get("inbound_fingerprint", "mix"),
                "pool_variant":      s.get("inbound_pool_variant", "v1"),
                "pool_size_default": _int("pool_size_default", 1),
                "sniff_enabled":     s.get("inbound_sniff_enabled", "1") == "1",
                "max_streams":       _int("inbound_max_streams", 1000),
                "jitter_ms":         _int("inbound_jitter_ms", 0),
                "fallback_server":   s.get("inbound_fallback_server", ""),
                "fallback_port":     _int("inbound_fallback_port", 0),
                "geoip_url":         s.get("inbound_geoip_url", ""),
                "geosite_url":       s.get("inbound_geosite_url", ""),
                "wgturn_enabled":     s.get("wgturn_enabled", "0") == "1",
                "wgturn_listen":      s.get("wgturn_listen", ""),
                "wgturn_password":    s.get("wgturn_password", ""),
                "wgturn_wg_port":     _int("wgturn_wg_port", 56001),
                "wgturn_config_dir":  s.get("wgturn_config_dir", "/etc/tamizdat/wgturn"),
                "wgturn_subnet":      s.get("wgturn_subnet", "10.66.66.0/24"),
                "wgturn_server_ip":   s.get("wgturn_server_ip", "10.66.66.1"),
                "wgturn_outbound_tag": s.get("wgturn_outbound_tag", ""),
                "uri":               make_master_uri_from_settings(),
            })
            return
        elif path == "/api/panel":
            # Settings refactor Phase 2: panel self-config. Returns the
            # editable panel_* settings + readonly display values
            # (admin_users, service_name) + the version stamp.
            ensure_db()
            with db_conn() as con:
                hostname  = _setting(con, "panel_hostname",       "") or os.environ.get("TAMIZDAT_PANEL_SERVER_HOST", "")
                port_s    = _setting(con, "panel_port",           "") or os.environ.get("TAMIZDAT_PANEL_PORT", "8888")
                base_path = _setting(con, "panel_base_path",      "") or os.environ.get("TAMIZDAT_PANEL_BASE_PATH", "")
                tls_cert  = _setting(con, "panel_tls_cert_path",  "")
                tls_key   = _setting(con, "panel_tls_key_path",   "")
                test_t    = _setting(con, "panel_test_target",
                                     DEFAULT_SETTINGS.get("panel_test_target", ""))
            try:
                port_i = int(port_s)
            except (TypeError, ValueError):
                port_i = 8888
            self.send_json({
                "hostname":         hostname,
                "port":             port_i,
                "base_path":        base_path,
                "tls_cert_path":    tls_cert,
                "tls_key_path":     tls_key,
                "test_target":      test_t,
                "admin_users":      ",".join(panel_admin_usernames()),
                "service_name":     SERVICE_NAME,
                "version":          PANEL_VERSION,
            })
            return
        else:
            self.send_error(404)

    def do_POST(self):
        path = self._path()
        if path == "/login":
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            p = parse_qs(body)
            username = p.get("username", [""])[0].strip()
            password = p.get("password", [""])[0]
            if not check_panel_password(username, password):
                self.send_html(LOGIN_HTML.replace("ERROR_MSG", "Login incorrect").replace("LOGIN_ACTION", BASE_PATH + "/login"), 401); return
            token = secrets.token_hex(32)
            sessions[token] = username
            _save_sessions()
            self.send_redirect(BASE_PATH + "/", {"Set-Cookie": f"session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{COOKIE_SECURE_FLAG}"}); return

        user = self.get_session_user()
        if not user: self.send_json({"error": "unauthorized"}, 401); return

        if path == "/api/account/password":
            # Change-password form (Settings → User, 2026-05-25). Verifies
            # the supplied current password against the same PBKDF2 path
            # that --set-admin uses, then rewrites panel_admins via
            # set_panel_admin(). The CLI helper drops every session for
            # this user (both from panel_sessions and the in-memory dict)
            # — the right thing for a remote operator running
            # --set-admin, but in the panel-driven change-password flow we
            # want THIS browser to stay signed in. So after set_panel_admin
            # we re-issue the current cookie's session row in DB and
            # restore the in-memory entry. Other sessions stay revoked.
            try:
                body = self._read_body() or {}
            except Exception:
                self.send_json({"error": "invalid json"}, 400); return
            current_pw = (body.get("current") or "")
            new_pw = (body.get("new") or "")
            if not current_pw or not new_pw:
                self.send_json({"error": "current and new password required"}, 400); return
            if len(new_pw) < 4:
                self.send_json({"error": "new password too short (min 4 chars)"}, 400); return
            if not check_panel_password(user, current_pw):
                self.send_json({"error": "current password incorrect"}, 401); return
            if new_pw == current_pw:
                self.send_json({"error": "new password must differ from current"}, 400); return
            current_token = None
            try:
                c = http.cookies.SimpleCookie()
                c.load(self.headers.get("Cookie", ""))
                if "session" in c:
                    current_token = c["session"].value
            except Exception:
                current_token = None
            try:
                set_panel_admin(user, new_pw)
            except ValueError as e:
                self.send_json({"error": str(e)}, 400); return
            except Exception as e:
                self.send_json({"error": str(e)}, 500); return
            # set_panel_admin just nuked every session for this user. Put
            # the current cookie back so the browser stays signed in;
            # everyone else stays logged out.
            if current_token:
                now_ts = int(time.time())
                try:
                    ensure_db()
                    with db_conn() as con:
                        con.execute(
                            "INSERT OR REPLACE INTO panel_sessions(token, username, created_at, expires_at) "
                            "VALUES(?,?,?,?)",
                            (current_token, user, now_ts, now_ts + SESSION_TTL),
                        )
                    sessions[current_token] = user
                except Exception:
                    pass
            self.send_json({"ok": True})
            return

        if path == "/api/users":
            try:
                u = create_user(self._read_body())
                uri = make_user_uri(u)
                resp = dict(u)
                if uri:
                    resp["uri"] = uri
                self.send_json(resp)
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.endswith("/reset-bytes") and path.startswith("/api/users/"):
            uid = unquote(path[len("/api/users/"):-len("/reset-bytes")])
            try:
                reset_user_bytes(uid)
                self.send_json({"ok": True})
            except ValueError as e:
                self.send_json({"error": str(e)}, 404)
            return

        if path.endswith("/reset-quota") and path.startswith("/api/users/"):
            # quota-reset-split (2026-05-10): unblock a capped user without
            # erasing the lifetime bytes_up/bytes_down counters. Sets
            # quota_baseline = current bytes total + bumps bytes_reset_at +
            # clears notification_pending. The /reset-bytes endpoint above
            # remains the hard-zero variant.
            uid = unquote(path[len("/api/users/"):-len("/reset-quota")])
            try:
                reset_user_quota(uid)
                self.send_json({"ok": True})
            except ValueError as e:
                self.send_json({"error": str(e)}, 404)
            return

        if path == "/api/users/broadcast-notification":
            # Phase C iOS-notify pipeline (2026-05-10): set the same
            # notification on every user. Empty body clears all pending
            # notifications. Body: {"text": "..."} (<=512 bytes).
            try:
                body = self._read_body() or {}
                broadcast_notification(body.get("text", ""))
                self.send_json({"ok": True})
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.endswith("/rotate-epoch") and path.startswith("/api/users/"):
            # Endpoint URL preserved for backward-compat with JS. Post shortid
            # full-B simplification (2026-05-09) the underlying primitive is
            # "regenerate master_shortid"; epoch_key is also overwritten for
            # transitional cleanliness but no longer consulted by the server.
            uid = unquote(path[len("/api/users/"):-len("/rotate-epoch")])
            try:
                new_master = rotate_user_epoch(uid)
                self.send_json({"ok": True, "master_shortid": new_master})
            except ValueError as e:
                self.send_json({"error": str(e)}, 404)
            return

        if path == "/api/outbounds":
            try:
                self.send_json(upsert_outbound_with_iface(self._read_body()))
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if path == "/api/routing":
            try:
                self.send_json(create_routing_rule(self._read_body()))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/routing/reload":
            try:
                self.send_json(reload_routing_signal())
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/routing/reorder":
            try:
                body = self._read_body()
                self.send_json(reorder_routing_rules(body.get("ids", [])))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # Sortable.js (2026-05-10): atomic whole-layout submit. Accepts
        # {"layout": [{"kind":"folder","id":F,"children":[R,R]},
        #             {"kind":"rule","id":R}, ...]}.  Server re-stamps
        # folder.priority + rule.priority + rule.folder_id in a single
        # transaction and returns the fresh rules+folders snapshot.
        if path == "/api/routing/layout":
            try:
                body = self._read_body() or {}
                self.send_json(set_routing_layout(body.get("layout", [])))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # folders v1 (2026-05-10): folder CRUD + reorder + move.  The
        # /move and /reorder endpoints sit under /api/routing/folders so
        # they don't collide with rule-level /api/routing/<rid>/move.
        if path == "/api/routing/folders":
            try:
                self.send_json(create_routing_folder(self._read_body()))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/routing/folders/reorder":
            try:
                body = self._read_body()
                self.send_json(reorder_routing_folders(body.get("ids", [])))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/routing/folders/") and path.endswith("/move"):
            try:
                fid = int(unquote(path[len("/api/routing/folders/"):-len("/move")]))
                body = self._read_body()
                self.send_json(move_routing_folder(fid, body.get("direction", "")))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/routing/") and path.endswith("/move"):
            try:
                rid = int(unquote(path[len("/api/routing/"):-len("/move")]))
                body = self._read_body()
                self.send_json(move_routing_rule(rid, body.get("direction", "")))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/service":
            body = self._read_body()
            action = body.get("action", "")
            if action not in ("start", "stop", "restart"):
                self.send_json({"error": "Invalid action"}, 400); return
            try:
                subprocess.Popen(["systemctl", action, SERVICE_NAME])
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/reset-user":
            body = self._read_body()
            name = body.get("name", "").strip()
            if not name: self.send_json({"error": "Name required"}, 400); return
            _reset_user_traffic(name)
            self.send_json({"ok": True})
            return

        if path == "/api/reset-all":
            _reset_all_traffic()
            self.send_json({"ok": True})
            return

        if path == "/api/tamizdat/keypair":
            priv, pub = generate_x25519_keypair()
            if not priv:
                self.send_json({"error": "cryptography package missing on server"}, 500); return
            self.send_json({"private_key": priv, "public_key": pub})
            return

        if path == "/api/tamizdat/shortid":
            # Generate a fresh 16-hex-char master shortid for tamizdat.
            self.send_json({"master_short_id": secrets.token_hex(8)})
            return

        if path == "/api/reset-outbound":
            body = self._read_body()
            tag = body.get("tag", "").strip()
            if not tag: self.send_json({"error": "Tag required"}, 400); return
            _reset_ob_traffic(tag)
            self.send_json({"ok": True})
            return

        # /api/outbounds/active POST removed in panel-cleanup CL-2
        # (2026-05-10) along with the per-row "Set default" button. The
        # Go server still reads the default_outbound_tag setting from
        # SQLite directly (see internal/outbounds/registry.go), so the
        # storage is preserved — only the panel-side write path is gone.

        if path.startswith("/api/outbound-test/"):
            tag = unquote(path[19:])
            delay = test_outbound_delay(tag)
            self.send_json({"delay": delay})
            return

        if path == "/api/panel/restart":
            # Settings refactor Phase 2: triggered by the Panel block after
            # a port / base_path / TLS-paths change. systemctl restart is
            # spawned in a detached subprocess so we can reply 200 before
            # the panel process dies — the browser shows a modal with the
            # new URL and the operator clicks through to reconnect.
            #
            # The systemd unit name defaults to "tamizdat-panel.service"
            # and is overridable via TAMIZDAT_PANEL_SELF_SERVICE env (env
            # only, not DB — operator must own the unit file).
            panel_unit = os.environ.get("TAMIZDAT_PANEL_SELF_SERVICE", "tamizdat-panel.service")
            try:
                # Detach via Popen + start_new_session so the SIGHUP from
                # systemctl doesn't kill us before we ACK. ~500 ms delay so
                # the JSON response is fully flushed first.
                cmd = ("sleep 0.5 && systemctl restart " + panel_unit) if panel_unit else "true"
                subprocess.Popen(
                    ["/bin/sh", "-c", cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self.send_json({"ok": True, "service": panel_unit})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        self.send_error(404)

    def do_PUT(self):
        user = self.get_session_user()
        if not user: self.send_json({"error": "unauthorized"}, 401); return
        path = self._path()

        if path.startswith("/api/outbounds/"):
            old_tag = unquote(path[15:])
            try:
                self.send_json(upsert_outbound_with_iface(self._read_body(), old_tag=old_tag))
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if path.startswith("/api/routing/folders/"):
            try:
                fid = int(unquote(path[len("/api/routing/folders/"):]))
                self.send_json(update_routing_folder(fid, self._read_body()))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/routing/"):
            try:
                rid = int(unquote(path[len("/api/routing/"):]))
                self.send_json(update_routing_rule(rid, self._read_body()))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/users/"):
            uid = unquote(path[len("/api/users/"):])
            try:
                u = update_user(uid, self._read_body())
                self.send_json(u)
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/inbound":
            try:
                changed = put_inbound_settings(self._read_body())
                self.send_json({
                    "ok": True,
                    "changed": changed,
                    "restart_required": tamizdat_restart_required(changed),
                })
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if path == "/api/tamizdat":
            # Settings refactor Phase 2 (2026-05-11): /api/tamizdat PUT no
            # longer touches the legacy panel_inbounds_json. The form body
            # uses JS-friendly key names (listen_port, private_key, …) which
            # we map onto flat inbound_* settings rows. inbound_priv_key is
            # accepted only when non-empty — empty preserves the existing
            # value (so reading the form back and saving doesn't clobber a
            # priv key the operator never re-typed).
            try:
                body = self._read_body() or {}
                mapping = {
                    "enabled":           "inbound_bundle_enabled",
                    "listen_addr":       "inbound_listen_addr",
                    "listen_port":       "inbound_listen_port",
                    "public_port":       "inbound_public_port",
                    "private_key":       "inbound_priv_key",
                    "cert_path":         "inbound_cert_path",
                    "key_path":          "inbound_key_path",
                    "masquerade_domain": "inbound_masquerade_domain",
                    "masquerade_pool":   "inbound_masquerade_pool",
                    "bootstrap_sni":     "inbound_bootstrap_sni",
                    "fingerprint":       "inbound_fingerprint",
                    "pool_variant":      "inbound_pool_variant",
                    "pool_size_default": "pool_size_default",
                    "sniff_enabled":     "inbound_sniff_enabled",
                    "max_streams":       "inbound_max_streams",
                    "jitter_ms":         "inbound_jitter_ms",
                    "fallback_server":   "inbound_fallback_server",
                    "fallback_port":     "inbound_fallback_port",
                    "geoip_url":         "inbound_geoip_url",
                    "geosite_url":       "inbound_geosite_url",
                    "wgturn_enabled":    "wgturn_enabled",
                    "wgturn_listen":     "wgturn_listen",
                    "wgturn_password":   "wgturn_password",
                    "wgturn_wg_port":    "wgturn_wg_port",
                    "wgturn_config_dir": "wgturn_config_dir",
                    "wgturn_subnet":     "wgturn_subnet",
                    "wgturn_server_ip":  "wgturn_server_ip",
                    "wgturn_outbound_tag": "wgturn_outbound_tag",
                }
                flat = {}
                for jk, v in body.items():
                    if jk not in mapping:
                        continue
                    if jk == "private_key" and (v is None or str(v).strip() == ""):
                        # Empty priv-key field on save = "keep existing" (very
                        # common — operator opens Settings, saves a port
                        # tweak, leaves the priv-key alone).
                        continue
                    flat[mapping[jk]] = v
                changed = put_inbound_settings(flat)
                self.send_json({
                    "ok": True,
                    "changed": changed,
                    "restart_required": tamizdat_restart_required(changed),
                    "uri": make_master_uri_from_settings(),
                })
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if path == "/api/panel":
            try:
                body = self._read_body() or {}
                # Map JS-friendly → DB key names. test_target piggybacks on
                # the inbound PUT path because it's already auto-saved from
                # the form (kept in PANEL_EDITABLE's adjacent block).
                mapping = {
                    "hostname":      "panel_hostname",
                    "port":          "panel_port",
                    "base_path":     "panel_base_path",
                    "tls_cert_path": "panel_tls_cert_path",
                    "tls_key_path":  "panel_tls_key_path",
                }
                flat = {mapping[k]: v for k, v in body.items() if k in mapping}
                result = put_panel_settings(flat)
                new_url = None
                if result["restart_required"]:
                    # Compute the new URL the operator must open. Prefers the
                    # panel_hostname row (just-saved), falls back to
                    # X-Forwarded-Host if behind a proxy, else Host header.
                    with db_conn() as con:
                        host = _setting(con, "panel_hostname", "") or self.headers.get("X-Forwarded-Host", "") or self.headers.get("Host", "")
                        bp   = _setting(con, "panel_base_path", "")
                        ps   = _setting(con, "panel_port",      "")
                        cert = _setting(con, "panel_tls_cert_path", "")
                    # Strip any existing port from Host header so we don't
                    # double-stack ports when we append our own.
                    host = host.split(":", 1)[0] if ":" in host else host
                    scheme = "https" if cert else "http"
                    try:
                        port_i = int(ps)
                    except (TypeError, ValueError):
                        port_i = PANEL_PORT
                    # Hide standard ports for cleaner URLs.
                    if (scheme == "https" and port_i == 443) or (scheme == "http" and port_i == 80):
                        port_seg = ""
                    else:
                        port_seg = f":{port_i}"
                    new_url = f"{scheme}://{host}{port_seg}{bp}/" if host else None
                resp = {"ok": True, **result}
                if new_url:
                    resp["new_url"] = new_url
                self.send_json(resp)
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
            return

        if path == "/api/settings":
            # Backward-compat stub: pre-Phase-2 external scripts may still
            # PUT here. Real persistence now lives at /api/inbound + the
            # new /api/tamizdat + /api/panel endpoints.
            self.send_json({"ok": True, "note": "Use /api/inbound + /api/tamizdat + /api/panel in Phase 2"})
            return

        self.send_error(404)

    def do_DELETE(self):
        user = self.get_session_user()
        if not user: self.send_json({"error": "unauthorized"}, 401); return
        path = self._path()

        if path == "/api/tamizdat":
            cfg = load_config()
            cfg["inbounds"] = [ib for ib in cfg.get("inbounds", []) if ib.get("type") != "tamizdat"]
            save_config(cfg)
            self.send_json({"ok": True})
        elif path.startswith("/api/users/"):
            uid = unquote(path[len("/api/users/"):])
            try:
                delete_user(uid)
                self.send_json({"ok": True})
            except ValueError as e:
                self.send_json({"error": str(e)}, 404)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
        elif path.startswith("/api/outbounds/"):
            tag = unquote(path[15:])
            try:
                self.send_json(delete_outbound(tag))
            except Exception as e:
                self.send_json({"error": str(e)}, 400)
        elif path.startswith("/api/routing/folders/"):
            try:
                fid = int(unquote(path[len("/api/routing/folders/"):]))
                self.send_json(delete_routing_folder(fid))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
        elif path.startswith("/api/routing/"):
            try:
                rid = int(unquote(path[len("/api/routing/"):]))
                self.send_json(delete_routing_rule(rid))
            except ValueError as e:
                self.send_json({"error": str(e)}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
        else:
            self.send_error(404)


def _read_cli_password(args):
    if getattr(args, "password_stdin", False):
        return sys.stdin.read().rstrip("\r\n")
    if getattr(args, "password", None) is not None:
        return args.password
    return None


def _handle_cli_args(argv):
    if not argv:
        return False
    import argparse
    parser = argparse.ArgumentParser(description="Tamizdat panel utility")
    parser.add_argument("--set-admin", metavar="USERNAME", help="create/update a panel admin login")
    parser.add_argument("--password", help="admin password (prefer --password-stdin in scripts)")
    parser.add_argument("--password-stdin", action="store_true", help="read admin password from stdin")
    parser.add_argument("--panel-port", help="persist panel_port")
    parser.add_argument("--panel-bind-addr", help="persist panel_bind_addr")
    parser.add_argument("--panel-hostname", help="persist panel_hostname")
    parser.add_argument("--panel-base-path", help="persist panel_base_path")
    parser.add_argument("--inbound-priv-key", help="persist inbound_priv_key and write the key file")
    parser.add_argument("--inbound-cert-path", help="persist inbound_cert_path")
    parser.add_argument("--inbound-key-path", help="persist inbound_key_path")
    parser.add_argument("--inbound-priv-key-path", help="persist inbound_priv_key_path")
    parser.add_argument("--inbound-shortid-path", help="persist inbound_shortid_path")
    parser.add_argument("--inbound-listen-addr", help="persist inbound_listen_addr")
    parser.add_argument("--inbound-listen-port", help="persist inbound_listen_port")
    parser.add_argument("--inbound-public-port", help="persist inbound_public_port")
    args = parser.parse_args(argv)

    changed = []
    panel_body = {}
    if args.panel_port is not None:
        panel_body["panel_port"] = args.panel_port
    if args.panel_bind_addr is not None:
        panel_body["panel_bind_addr"] = args.panel_bind_addr
    if args.panel_hostname is not None:
        panel_body["panel_hostname"] = args.panel_hostname
    if args.panel_base_path is not None:
        panel_body["panel_base_path"] = args.panel_base_path
    if panel_body:
        result = put_panel_settings(panel_body)
        changed.extend(result.get("changed", []))

    inbound_body = {}
    if args.inbound_priv_key is not None:
        inbound_body["inbound_priv_key"] = args.inbound_priv_key
    if args.inbound_cert_path is not None:
        inbound_body["inbound_cert_path"] = args.inbound_cert_path
    if args.inbound_key_path is not None:
        inbound_body["inbound_key_path"] = args.inbound_key_path
    if args.inbound_priv_key_path is not None:
        inbound_body["inbound_priv_key_path"] = args.inbound_priv_key_path
    if args.inbound_shortid_path is not None:
        inbound_body["inbound_shortid_path"] = args.inbound_shortid_path
    if args.inbound_listen_addr is not None:
        inbound_body["inbound_listen_addr"] = args.inbound_listen_addr
    if args.inbound_listen_port is not None:
        inbound_body["inbound_listen_port"] = args.inbound_listen_port
    if args.inbound_public_port is not None:
        inbound_body["inbound_public_port"] = args.inbound_public_port
    if inbound_body:
        changed.extend(put_inbound_settings(inbound_body))

    if args.set_admin:
        password = _read_cli_password(args)
        if password is None:
            parser.error("--set-admin requires --password or --password-stdin")
        set_panel_admin(args.set_admin, password)
        print(f"panel admin updated: {args.set_admin}")
    elif args.password is not None or args.password_stdin:
        parser.error("password supplied without --set-admin")

    if changed:
        print("settings updated: " + ",".join(changed))
    return True


if __name__ == "__main__":
    if _handle_cli_args(sys.argv[1:]):
        sys.exit(0)
    ensure_db()
    # Settings refactor Phase 2: bind config comes from the DB (panel_*
    # settings) first, env vars second, hard-coded defaults third. Operators
    # can hot-swap port + base_path through the UI; restart is required so
    # the new HTTPServer binds the new port — handled by POST /api/panel/restart.
    _eff_port_s     = _panel_setting_with_env_fallback("panel_port",       "TAMIZDAT_PANEL_PORT",      str(PANEL_PORT))
    _eff_bind_addr  = _panel_setting_with_env_fallback("panel_bind_addr",  "TAMIZDAT_PANEL_BIND_ADDR", "").strip()
    _eff_base_path  = _panel_setting_with_env_fallback("panel_base_path",  "TAMIZDAT_PANEL_BASE_PATH", BASE_PATH).rstrip("/")
    _eff_hostname   = _panel_setting_with_env_fallback("panel_hostname",   "TAMIZDAT_PANEL_SERVER_HOST", SERVER_HOST)
    try:
        _eff_port = int(_eff_port_s)
    except (TypeError, ValueError):
        _eff_port = PANEL_PORT
    # Mutate the module-level globals so the Handler picks up the resolved
    # values (BASE_PATH is referenced from _path / send_redirect / login).
    PANEL_PORT  = _eff_port
    BASE_PATH   = _eff_base_path
    SERVER_HOST = _eff_hostname or SERVER_HOST

    with db_conn() as _c:
        _tls_cert = _setting(_c, "panel_tls_cert_path", "")
        _tls_key  = _setting(_c, "panel_tls_key_path",  "")
    _bind_addr = _eff_bind_addr or ("0.0.0.0" if (_tls_cert and _tls_key) else "127.0.0.1")
    print(f"Tamizdat Panel {_bind_addr}:{PANEL_PORT} | db={PANEL_DB} | host={SERVER_HOST} base_path={BASE_PATH or '(none)'} tls={'on' if (_tls_cert and _tls_key) else 'off'}")
    # ThreadingHTTPServer (2026-05-11): single-threaded HTTPServer
    # deadlocks under concurrent TLS handshakes (browser opens 6+ parallel
    # connections for CSS/JS/font; accept-loop blocks on each). Threaded
    # variant processes each connection in its own daemon thread.
    server = ThreadingHTTPServer((_bind_addr, PANEL_PORT), Handler)
    if _tls_cert and _tls_key and os.path.exists(_tls_cert) and os.path.exists(_tls_key):
        # Optional panel-side TLS termination (operator skipping nginx). Use
        # SSLContext over the deprecated ssl.wrap_socket — same effect, no
        # 3.12+ DeprecationWarning. Server-side only, defaults are sane.
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=_tls_cert, keyfile=_tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
