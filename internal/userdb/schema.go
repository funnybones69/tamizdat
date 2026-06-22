package userdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
)

const DefaultLegacyShortIDPath = "/etc/tamizdat/shortid.hex"

const schemaSQL = `
CREATE TABLE IF NOT EXISTS outbounds (
    tag TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    uri TEXT,
    note TEXT,
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

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    master_shortid       TEXT NOT NULL UNIQUE,
    epoch_key            TEXT,                         -- DEPRECATED post-2026-05-09 shortid full-B simplification; kept nullable for backward-compat with existing DB rows.
    pool_size            INTEGER,                      -- DEPRECATED: same vintage as epoch_key.
    outbound_tag         TEXT NOT NULL DEFAULT 'direct',
    bytes_up             INTEGER NOT NULL DEFAULT 0,
    bytes_down           INTEGER NOT NULL DEFAULT 0,
    bytes_reset_at       INTEGER,                      -- rolling-quota anchor (unix sec); 0/NULL means since-creation.
    expires_at           INTEGER,
    bandwidth_cap        INTEGER,                      -- total-byte quota (since bytes_reset_at). 0/NULL = no quota.
    rate_limit_mbps      INTEGER,                      -- token-bucket cap in Mbits/sec; 0/NULL = unlimited. Added 2026-05-13.
    last_seen_at         INTEGER,
    notification_pending INTEGER NOT NULL DEFAULT 0,   -- set 1 on quota-overrun masquerade; deferred client-push reads + clears.
    notification_text    TEXT,                          -- panel-pushed per-user notification body; "BROADCAST: " prefix marks system-wide; empty = no manual notification.
    quota_baseline       INTEGER NOT NULL DEFAULT 0,   -- bytes_up+bytes_down at last "Reset Quota"; IsOverQuota subtracts this so traffic stats stay visible.
    h2_peak_streams      INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 CONNECT streams observed for this user (tcp+udp).
    h2_peak_tcp_streams  INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 TCP CONNECT streams observed for this user.
    h2_peak_udp_streams  INTEGER NOT NULL DEFAULT 0,   -- max concurrent H2 UDP CONNECT streams observed for this user.
    h2_peak_at           INTEGER NOT NULL DEFAULT 0,   -- unix sec when one of the H2 peak counters last advanced.
    h2_relay_peak_streams      INTEGER NOT NULL DEFAULT 0,   -- max concurrent streams this user's traffic opened toward an outbound/next hop.
    h2_relay_peak_tcp_streams  INTEGER NOT NULL DEFAULT 0,
    h2_relay_peak_udp_streams  INTEGER NOT NULL DEFAULT 0,
    h2_relay_peak_at           INTEGER NOT NULL DEFAULT 0,
    turn_room_link       TEXT,                         -- operator-pushed TURN room/link; delivered to clients via bundle.
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

CREATE TABLE IF NOT EXISTS routing_rules (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    priority             INTEGER NOT NULL,
    match_json           TEXT NOT NULL,
    outbound_tag         TEXT NOT NULL,
    description_override TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at           INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_routing_priority ON routing_rules(priority);
`

var defaultSettings = map[string]string{
	"default_outbound_tag":      "direct",
	"inbound_listen_port":       "7780",
	"inbound_listen_addr":       "127.0.0.1",
	"inbound_public_port":       "443",
	"inbound_max_streams":       "1000",
	"inbound_jitter_ms":         "0",
	"inbound_cert_path":         "/etc/tamizdat/cert.pem",
	"inbound_key_path":          "/etc/tamizdat/key.pem",
	"inbound_priv_key":          "",
	"inbound_masquerade_domain": "cover.example.com",
	"inbound_masquerade_pool":   "cover.example.com=cover.example.com:443,ok.ru=ok.ru:443,vk.com=vk.com:443,mail.ru=mail.ru:443,yandex.ru=yandex.ru:443",
	"inbound_fingerprint":       "mix",
	// inbound_proxy_protocol defaults OFF: existing prod (example-outbound) runs raw
	// tamizdat-server with no fronting nginx, so a default of "1" combined
	// with trust-list "127.0.0.1/32" would silently reject all real clients
	// during schema upgrade. Fronting deployments (ru2 / nginx -> tamizdat
	// hop) must explicitly set inbound_proxy_protocol=1 in the panel, OR
	// pass -proxy-protocol on systemd ExecStart (CLI overrides DB).
	"inbound_proxy_protocol":      "0",
	"inbound_proxy_protocol_from": "127.0.0.1/32",
	"fragpoc_dynamic_enabled":     "0",
	"fragpoc_dynamic_max_ports":   "0",
	"fragpoc_dynamic_mode":        "random",
	"fragpoc_dynamic_pool":        "",

	// VK TURN relay credential manager (vkcreds integration).
	"turn_vk_enabled":        "0",
	"turn_vk_app_id":         "",
	"turn_vk_app_secret":     "",
	"turn_vk_device_id":      "",
	"turn_vk_call_hash":      "",
	"turn_vk_secondary_hash": "",
	"turn_vk_max_retries":    "5",
	"turn_vk_concurrency":    "2",

	// WireGuard-over-DTLS-over-TURN inbound. Empty listen disables it.
	"wgturn_enabled":      "0",
	"wgturn_listen":       "",
	"wgturn_password":     "",
	"wgturn_wg_port":      "56001",
	"wgturn_config_dir":   "/etc/tamizdat/wgturn",
	"wgturn_subnet":       "10.66.66.0/24",
	"wgturn_server_ip":    "10.66.66.1",
	"wgturn_outbound_tag": "",
}

func EnsureSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("nil sqlite db")
	}
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if _, err := conn.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	// Migration v2 → v3 (multi-user-cleanup, 2026-05-10):
	//   - users.epoch_key: relax the legacy NOT NULL constraint so the
	//     post-pool panel/server can omit it. ALTER TABLE DROP COLUMN is not
	//     portable, so we rebuild the table when the legacy NOT NULL is
	//     detected via PRAGMA table_info.
	//   - users.notification_pending: ensure the column exists (deferred
	//     client-push of quota overrun).
	if err := migrateUsersV3(ctx, conn); err != nil {
		return err
	}
	// Migration v3 → v4 (quota-reset-split, 2026-05-10):
	//   - users.quota_baseline: ensure the column exists. Stores
	//     bytes_up+bytes_down at the last operator "Reset Quota" click; the
	//     IsOverQuota check subtracts this so historical traffic stats
	//     remain visible while the rolling window restarts.
	if err := migrateUsersV4(ctx, conn); err != nil {
		return err
	}
	// Migration v4 → v5 (Phase C iOS-notify pipeline, 2026-05-10):
	//   - users.notification_text: ensure the column exists. Carries the
	//     per-user message body (panel-pushed manual or "BROADCAST: " prefix
	//     for system-wide). Server reads it during the bundle endpoint and
	//     clears notification_pending after delivery.
	if err := migrateUsersV5(ctx, conn); err != nil {
		return err
	}
	// Migration v5 → v6 (per-outbound accounting, 2026-05-12):
	//   - outbounds.bytes_up, outbounds.bytes_down: accumulated by
	//     userdb.Accounting.Flush() in the same SQLite transaction as the
	//     per-user counters. DEFAULT 0 + NOT NULL means existing rows get
	//     0 on the ALTER. Panel duplicates this migration as
	//     _migrate_outbounds_bytes_counters; both probe via PRAGMA so a
	//     race between the two daemons just no-ops the second one.
	if err := migrateOutboundsV6(ctx, conn); err != nil {
		return err
	}
	// Migration v6 → v7 (per-user rate limit, 2026-05-13):
	//   - users.rate_limit_mbps: INTEGER NULL token-bucket cap in Mbits/sec
	//     (0/NULL = unlimited). Distinct from bandwidth_cap which is a total
	//     byte quota; this one paces a single user's throughput so one client
	//     can't saturate a shared upstream link.
	if err := migrateUsersV7(ctx, conn); err != nil {
		return err
	}
	// Migration v7 → v8 (user_sessions broken FK repair, 2026-05-13):
	//   - The v2→v3 users rebuild renamed the legacy users table to
	//     users_v2_legacy and then DROPped it. SQLite captured the FK on
	//     pre-existing user_sessions rows pointing at the renamed table, so
	//     post-migration every StartSession/EndSession fails with
	//     "no such table: main.users_v2_legacy" because SQLite resolves FKs
	//     by name lookup at statement execution when foreign_keys=ON. The
	//     errors don't block the server but they cost a per-CONNECT SQL
	//     round-trip + log line AND mean session accounting was silently
	//     broken on every server that migrated through v2→v3 since
	//     2026-05-10. Fix: rebuild user_sessions with the correct FK and
	//     copy its rows across. Idempotent via the FK introspection probe.
	if err := migrateUserSessionsV8(ctx, conn); err != nil {
		return err
	}
	// Migration v8 -> v9 (H2 stream diagnostics, 2026-05-17):
	//   - users.h2_peak_*: per-user maximum concurrent H2 CONNECT streams
	//     observed by the server. Diagnostic only; does not affect caps.
	if err := migrateUsersV9(ctx, conn); err != nil {
		return err
	}
	// Migration v9 -> v10 (per-user TURN profile push, 2026-05-26):
	//   - users.turn_*: VK/Yandex room link/hash staged by panel and delivered
	//     through the authenticated config bundle.
	if err := migrateUsersV10(ctx, conn); err != nil {
		return err
	}
	// Migration v10 -> v11 (session transport label, 2026-05-26):
	//   - user_sessions.transport: h2/turn badge for panel status.
	if err := migrateUserSessionsV11(ctx, conn); err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES('direct', 'direct', NULL, 'Direct dial from server IP', ?, ?)`, now, now); err != nil {
		return err
	}
	for k, v := range defaultSettings {
		if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)`, k, v); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', '11')`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM settings WHERE key='schema_version'`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

// migrateUsersV3 upgrades a v2 users table:
//   - drops NOT NULL on epoch_key (rebuilds the table; SQLite cannot ALTER
//     COLUMN NULL/NOT NULL in place).
//   - adds notification_pending INTEGER NOT NULL DEFAULT 0 if missing.
//
// All migration probes consult PRAGMA table_info so re-running the migration
// on an already-v3 schema is a no-op.
func migrateUsersV3(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type col struct {
		Name    string
		NotNull int
		Type    string
	}
	cols := make(map[string]col)
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = col{Name: name, NotNull: notNull, Type: ctype}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Empty cols means the CREATE TABLE IF NOT EXISTS just ran on a fresh DB
	// → already v3. Nothing to migrate.
	if len(cols) == 0 {
		return nil
	}

	// Detect legacy NOT NULL on epoch_key.
	if ek, ok := cols["epoch_key"]; ok && ek.NotNull == 1 {
		// Rebuild users table with epoch_key nullable. The rebuilt schema
		// already includes quota_baseline so the v3→v4 step below is a no-op
		// when the v2→v3 rebuild path runs.
		stmts := []string{
			`ALTER TABLE users RENAME TO users_v2_legacy`,
			`CREATE TABLE users (
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
            )`,
			`INSERT INTO users (id, name, master_shortid, epoch_key, pool_size, outbound_tag,
                bytes_up, bytes_down, bytes_reset_at, expires_at, bandwidth_cap, last_seen_at,
                notification_pending, notification_text, quota_baseline, created_at, updated_at)
                SELECT id, name, master_shortid, epoch_key, pool_size, outbound_tag,
                       bytes_up, bytes_down, bytes_reset_at, expires_at, bandwidth_cap, last_seen_at,
                       0 AS notification_pending, NULL AS notification_text, 0 AS quota_baseline, created_at, updated_at
                FROM users_v2_legacy`,
			`DROP TABLE users_v2_legacy`,
			`CREATE INDEX IF NOT EXISTS idx_users_master ON users(master_shortid)`,
		}
		for _, s := range stmts {
			if _, err := conn.ExecContext(ctx, s); err != nil {
				return fmt.Errorf("migrate users v3 (%q): %w", s[:min(len(s), 60)], err)
			}
		}
		return nil
	}

	// epoch_key already nullable (v3 path). Just ensure notification_pending
	// exists on legacy v3-without-notif rows.
	if _, ok := cols["notification_pending"]; !ok {
		if _, err := conn.ExecContext(ctx, `ALTER TABLE users ADD COLUMN notification_pending INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add notification_pending: %w", err)
		}
	}
	return nil
}

// migrateUsersV4 adds users.quota_baseline if missing. The v2→v3 rebuild path
// in migrateUsersV3 already includes the column in the rebuilt CREATE TABLE,
// so this only fires on a DB that was previously v3 (post-multi-user-cleanup
// schema) and is being upgraded to v4 (quota-reset-split, 2026-05-10).
//
// Idempotent: PRAGMA-driven, re-runs are no-ops on already-v4 schemas.
func migrateUsersV4(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, ok := cols["quota_baseline"]; ok {
		return nil
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE users ADD COLUMN quota_baseline INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("add quota_baseline: %w", err)
	}
	return nil
}

// migrateUsersV5 adds users.notification_text if missing. Phase C, 2026-05-10:
// the column carries the per-user notification body (manual operator-set or
// "BROADCAST: " prefix for system-wide). Server reads via the bundle endpoint
// and clears notification_pending after a successful body write.
//
// Idempotent: PRAGMA-driven, re-runs are no-ops on already-v5 schemas.
func migrateUsersV5(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, ok := cols["notification_text"]; ok {
		return nil
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE users ADD COLUMN notification_text TEXT`); err != nil {
		return fmt.Errorf("add notification_text: %w", err)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// migrateOutboundsV6 adds the per-outbound byte-accounting columns
// (bytes_up, bytes_down) to the outbounds table. PRAGMA-probed + ALTER —
// fresh DBs created via this path get the columns, older DBs upgraded.
// Idempotent: re-runs on already-v6 schemas no-op.
//
// The panel (panel/tamizdat-panel.py::_migrate_outbounds_bytes_counters)
// performs the same probe + ALTER from the Python side, so a race between
// panel start and tamizdat-server start is safe — whoever wins, the other
// observes the columns and skips.
func migrateOutboundsV6(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(outbounds)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, ok := cols["bytes_up"]; !ok {
		if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN bytes_up INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add outbounds.bytes_up: %w", err)
		}
	}
	if _, ok := cols["bytes_down"]; !ok {
		if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN bytes_down INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add outbounds.bytes_down: %w", err)
		}
	}
	return nil
}

// migrateUsersV7 adds users.rate_limit_mbps (INTEGER, NULL = unlimited)
// for the per-user token-bucket throughput cap. PRAGMA-probed + ALTER —
// idempotent (re-runs on already-v7 schemas no-op).
func migrateUsersV7(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, ok := cols["rate_limit_mbps"]; ok {
		return nil
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE users ADD COLUMN rate_limit_mbps INTEGER`); err != nil {
		return fmt.Errorf("add users.rate_limit_mbps: %w", err)
	}
	return nil
}

// migrateUserSessionsV8 repairs a broken FOREIGN KEY on user_sessions whose
// target table users_v2_legacy was dropped by migrateUsersV3. Detection: read
// `sql` from sqlite_master for table=user_sessions and look for the
// substring users_v2_legacy. When present, rebuild user_sessions with a FK
// pointing at the current users table and copy rows across in one
// transaction (the caller already runs us inside BEGIN IMMEDIATE).
func migrateUserSessionsV8(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var ddl sql.NullString
	if err := conn.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='user_sessions'`).Scan(&ddl); err != nil {
		// No user_sessions table at all (fresh DB pre-schemaSQL CREATE?) →
		// schemaSQL at the top of EnsureSchema will create it correctly.
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("probe user_sessions ddl: %w", err)
	}
	if !ddl.Valid || !strings.Contains(ddl.String, "users_v2_legacy") {
		// FK is fine (or table missing). Nothing to do.
		return nil
	}
	// Rebuild. SQLite cannot ALTER TABLE to change FK target; standard
	// fix is create-new + INSERT SELECT + DROP + RENAME.
	stmts := []string{
		`CREATE TABLE user_sessions_v8 (
            user_id        TEXT NOT NULL,
            session_id     TEXT NOT NULL,
            started_at     INTEGER NOT NULL,
            bytes_up       INTEGER NOT NULL DEFAULT 0,
            bytes_down     INTEGER NOT NULL DEFAULT 0,
            last_active_at INTEGER NOT NULL,
            pool_index     INTEGER,
            PRIMARY KEY (user_id, session_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
		`INSERT INTO user_sessions_v8 (user_id, session_id, started_at,
            bytes_up, bytes_down, last_active_at, pool_index)
            SELECT user_id, session_id, started_at, bytes_up, bytes_down,
                   last_active_at, pool_index
            FROM user_sessions
            WHERE user_id IN (SELECT id FROM users)`,
		`DROP TABLE user_sessions`,
		`ALTER TABLE user_sessions_v8 RENAME TO user_sessions`,
		`CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(last_active_at)`,
	}
	for _, s := range stmts {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("rebuild user_sessions (%q): %w", s[:min(len(s), 60)], err)
		}
	}
	return nil
}

// migrateUsersV9 adds H2 diagnostic peak counters to users. These counters are
// updated only when an authenticated H2 CONNECT raises a user's all-time
// concurrent-stream peak; they are not admission-control inputs.
func migrateUsersV9(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	add := []struct {
		name string
		sql  string
	}{
		{"h2_peak_streams", `ALTER TABLE users ADD COLUMN h2_peak_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_peak_tcp_streams", `ALTER TABLE users ADD COLUMN h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_peak_udp_streams", `ALTER TABLE users ADD COLUMN h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_peak_at", `ALTER TABLE users ADD COLUMN h2_peak_at INTEGER NOT NULL DEFAULT 0`},
		{"h2_relay_peak_streams", `ALTER TABLE users ADD COLUMN h2_relay_peak_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_relay_peak_tcp_streams", `ALTER TABLE users ADD COLUMN h2_relay_peak_tcp_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_relay_peak_udp_streams", `ALTER TABLE users ADD COLUMN h2_relay_peak_udp_streams INTEGER NOT NULL DEFAULT 0`},
		{"h2_relay_peak_at", `ALTER TABLE users ADD COLUMN h2_relay_peak_at INTEGER NOT NULL DEFAULT 0`},
	}
	for _, col := range add {
		if _, ok := cols[col.name]; ok {
			continue
		}
		if _, err := conn.ExecContext(ctx, col.sql); err != nil {
			return fmt.Errorf("add users.%s: %w", col.name, err)
		}
	}
	return nil
}

func migrateUsersV10(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	add := []struct {
		name string
		sql  string
	}{
		{"turn_room_link", `ALTER TABLE users ADD COLUMN turn_room_link TEXT`},
		{"turn_room_hash", `ALTER TABLE users ADD COLUMN turn_room_hash TEXT`},
		{"turn_profile_pending", `ALTER TABLE users ADD COLUMN turn_profile_pending INTEGER NOT NULL DEFAULT 0`},
		{"turn_profile_version", `ALTER TABLE users ADD COLUMN turn_profile_version INTEGER NOT NULL DEFAULT 0`},
		{"turn_profile_updated_at", `ALTER TABLE users ADD COLUMN turn_profile_updated_at INTEGER NOT NULL DEFAULT 0`},
	}
	for _, col := range add {
		if _, ok := cols[col.name]; ok {
			continue
		}
		if _, err := conn.ExecContext(ctx, col.sql); err != nil {
			return fmt.Errorf("add users.%s: %w", col.name, err)
		}
	}
	return nil
}

func migrateUserSessionsV11(ctx context.Context, conn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(user_sessions)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, ok := cols["transport"]; ok {
		return nil
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE user_sessions ADD COLUMN transport TEXT NOT NULL DEFAULT 'h2'`); err != nil {
		return fmt.Errorf("add user_sessions.transport: %w", err)
	}
	return nil
}

func GetSetting(db *sql.DB, key, def string) string {
	var value string
	if db == nil {
		return def
	}
	if err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&value); err != nil {
		return def
	}
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}

func LoadSettings(db *sql.DB) (map[string]string, error) {
	if err := EnsureSchema(db); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for k, v := range defaultSettings {
		out[k] = v
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// BootstrapLegacyShortID converts the pre-Phase-2 single-shortid file
// (/etc/tamizdat/shortid.hex) into one default user "default" if the users
// table is empty. Idempotent: re-runs are no-ops once any user exists.
func BootstrapLegacyShortID(db *sql.DB, path string) (bool, error) {
	if path == "" {
		path = DefaultLegacyShortIDPath
	}
	if err := EnsureSchema(db); err != nil {
		return false, err
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	master, err := NormalizeShortIDHex(string(data))
	if err != nil {
		return false, nil
	}
	id, err := GenerateUserID()
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO users(id, name, master_shortid, outbound_tag, created_at, updated_at)
        VALUES(?, 'default', ?, 'direct', ?, ?)`, id, master, now, now)
	if err != nil {
		return false, err
	}
	_, err = db.Exec(`INSERT OR REPLACE INTO schema_meta(key, value) VALUES('migrated_from_v1', ?)`, fmt.Sprint(now))
	if err != nil {
		return false, err
	}
	return true, nil
}
