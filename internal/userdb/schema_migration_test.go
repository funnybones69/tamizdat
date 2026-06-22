package userdb

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrateUsersV3_LegacyV2DB verifies that a DB created with the legacy
// users.epoch_key NOT NULL constraint is rebuilt by EnsureSchema so that:
//  1. epoch_key column becomes nullable (notnull == 0)
//  2. notification_pending column is added (default 0)
//  3. all pre-existing user rows are preserved verbatim
func TestMigrateUsersV3_LegacyV2DB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-v2.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	// Build a v2-style users table with epoch_key NOT NULL.
	if _, err := db.Exec(`
        CREATE TABLE outbounds (tag TEXT PRIMARY KEY, kind TEXT NOT NULL, uri TEXT, note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        INSERT INTO outbounds VALUES('direct','direct',NULL,'',0,0);
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            master_shortid TEXT NOT NULL UNIQUE,
            epoch_key TEXT NOT NULL,
            pool_size INTEGER,
            outbound_tag TEXT NOT NULL DEFAULT 'direct',
            bytes_up INTEGER NOT NULL DEFAULT 0,
            bytes_down INTEGER NOT NULL DEFAULT 0,
            bytes_reset_at INTEGER,
            expires_at INTEGER,
            bandwidth_cap INTEGER,
            last_seen_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (outbound_tag) REFERENCES outbounds(tag)
        );
    `); err != nil {
		t.Fatalf("create v2 schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users(id, name, master_shortid, epoch_key, pool_size, outbound_tag, bytes_up, bytes_down, created_at, updated_at)
        VALUES('uid1','legacy','1acad6addd6eab4a',?,50,'direct',1024,2048,0,0)`, "a-fake-epoch-key-32-bytes-hex-blob-pad"); err != nil {
		t.Fatalf("seed v2 row: %v", err)
	}

	// EnsureSchema must migrate v2 → v3 idempotently.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	// Verify epoch_key is now nullable.
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info: %v", err)
	}
	defer rows.Close()
	colNotNull := make(map[string]int)
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan PRAGMA: %v", err)
		}
		colNotNull[name] = notNull
	}
	if nn, ok := colNotNull["epoch_key"]; !ok || nn != 0 {
		t.Fatalf("epoch_key.notnull = %d (ok=%v); want 0 (nullable)", nn, ok)
	}
	if _, ok := colNotNull["notification_pending"]; !ok {
		t.Fatalf("notification_pending column missing post-migration")
	}
	if _, ok := colNotNull["quota_baseline"]; !ok {
		t.Fatalf("quota_baseline column missing post-migration (v4)")
	}

	// Pre-existing row preserved.
	var name string
	var bytesUp int64
	var epoch sql.NullString
	if err := db.QueryRow(`SELECT name, bytes_up, epoch_key FROM users WHERE id='uid1'`).Scan(&name, &bytesUp, &epoch); err != nil {
		t.Fatalf("query preserved row: %v", err)
	}
	if name != "legacy" || bytesUp != 1024 {
		t.Fatalf("v2 row not preserved: name=%q bytes_up=%d", name, bytesUp)
	}
	if !epoch.Valid {
		t.Fatalf("legacy epoch_key payload should be preserved (it was non-NULL pre-migration)")
	}

	// Idempotency: a second EnsureSchema must be a no-op + still pass.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema (re-run): %v", err)
	}
}

// TestMigrateUsersV3_FreshDB ensures a fresh DB created via EnsureSchema is
// directly v3-shaped (no migration loop needed).
func TestMigrateUsersV3_FreshDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("PRAGMA: %v", err)
	}
	defer rows.Close()
	cols := make(map[string]int)
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[name] = notNull
	}
	if nn, ok := cols["epoch_key"]; !ok || nn != 0 {
		t.Fatalf("fresh DB epoch_key.notnull=%d (ok=%v); want 0", nn, ok)
	}
	if _, ok := cols["notification_pending"]; !ok {
		t.Fatalf("fresh DB missing notification_pending column")
	}
	if _, ok := cols["quota_baseline"]; !ok {
		t.Fatalf("fresh DB missing quota_baseline column (v4)")
	}
	for _, col := range []string{"h2_peak_streams", "h2_peak_tcp_streams", "h2_peak_udp_streams", "h2_peak_at", "h2_relay_peak_streams", "h2_relay_peak_tcp_streams", "h2_relay_peak_udp_streams", "h2_relay_peak_at"} {
		if _, ok := cols[col]; !ok {
			t.Fatalf("fresh DB missing %s column (v9)", col)
		}
	}
}

func TestMigrateUsersV9_H2PeakColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-v8.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	if _, err := db.Exec(`
        CREATE TABLE outbounds (tag TEXT PRIMARY KEY, kind TEXT NOT NULL, uri TEXT, note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        INSERT INTO outbounds VALUES('direct','direct',NULL,'',0,0);
        CREATE TABLE users (
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
            rate_limit_mbps      INTEGER,
            last_seen_at         INTEGER,
            notification_pending INTEGER NOT NULL DEFAULT 0,
            notification_text    TEXT,
            quota_baseline       INTEGER NOT NULL DEFAULT 0,
            created_at           INTEGER NOT NULL,
            updated_at           INTEGER NOT NULL,
            FOREIGN KEY (outbound_tag) REFERENCES outbounds(tag)
        );
        INSERT INTO users(id, name, master_shortid, outbound_tag, created_at, updated_at)
            VALUES('uid1','prev-user','1acad6addd6eab4a','direct',0,0);
    `); err != nil {
		t.Fatalf("seed v8 schema: %v", err)
	}

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	cols := make(map[string]struct{})
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("PRAGMA: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[name] = struct{}{}
	}
	for _, col := range []string{"h2_peak_streams", "h2_peak_tcp_streams", "h2_peak_udp_streams", "h2_peak_at", "h2_relay_peak_streams", "h2_relay_peak_tcp_streams", "h2_relay_peak_udp_streams", "h2_relay_peak_at"} {
		if _, ok := cols[col]; !ok {
			t.Fatalf("legacy v8 DB missing %s post-migration", col)
		}
	}
	var total, tcp, udp, at, relayTotal, relayTCP, relayUDP, relayAt int64
	if err := db.QueryRow(`SELECT h2_peak_streams, h2_peak_tcp_streams, h2_peak_udp_streams, h2_peak_at,
        h2_relay_peak_streams, h2_relay_peak_tcp_streams, h2_relay_peak_udp_streams, h2_relay_peak_at
        FROM users WHERE id='uid1'`).Scan(&total, &tcp, &udp, &at, &relayTotal, &relayTCP, &relayUDP, &relayAt); err != nil {
		t.Fatalf("query h2 peaks: %v", err)
	}
	if total != 0 || tcp != 0 || udp != 0 || at != 0 || relayTotal != 0 || relayTCP != 0 || relayUDP != 0 || relayAt != 0 {
		t.Fatalf("h2 peak defaults = total=%d tcp=%d udp=%d at=%d relay_total=%d relay_tcp=%d relay_udp=%d relay_at=%d", total, tcp, udp, at, relayTotal, relayTCP, relayUDP, relayAt)
	}
}

// TestMigrateUsersV4_LegacyV3DB verifies that a DB created at the v3 shape
// (post multi-user-cleanup, pre quota-reset-split) gains the quota_baseline
// column without rebuilding the whole table.
func TestMigrateUsersV4_LegacyV3DB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-v3.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	// Build a v3-style users table: epoch_key nullable, notification_pending
	// present, quota_baseline absent.
	if _, err := db.Exec(`
        CREATE TABLE outbounds (tag TEXT PRIMARY KEY, kind TEXT NOT NULL, uri TEXT, note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        INSERT INTO outbounds VALUES('direct','direct',NULL,'',0,0);
        CREATE TABLE users (
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
            created_at           INTEGER NOT NULL,
            updated_at           INTEGER NOT NULL,
            FOREIGN KEY (outbound_tag) REFERENCES outbounds(tag)
        );
        INSERT INTO users(id, name, master_shortid, outbound_tag, bytes_up, bytes_down, created_at, updated_at)
            VALUES('uid1','prev-user','1acad6addd6eab4a','direct',9999,8888,0,0);
    `); err != nil {
		t.Fatalf("seed v3 schema: %v", err)
	}

	// EnsureSchema must add quota_baseline without breaking the row.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("PRAGMA: %v", err)
	}
	defer rows.Close()
	cols := make(map[string]int)
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cols[name] = notNull
	}
	if _, ok := cols["quota_baseline"]; !ok {
		t.Fatalf("legacy v3 DB missing quota_baseline post-migration")
	}

	// Existing user row preserved with quota_baseline = 0 by default.
	var bytesUp, baseline int64
	if err := db.QueryRow(`SELECT bytes_up, quota_baseline FROM users WHERE id='uid1'`).Scan(&bytesUp, &baseline); err != nil {
		t.Fatalf("query preserved row: %v", err)
	}
	if bytesUp != 9999 {
		t.Fatalf("v3 row bytes_up not preserved: got %d want 9999", bytesUp)
	}
	if baseline != 0 {
		t.Fatalf("quota_baseline default should be 0, got %d", baseline)
	}

	// Idempotency.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema (re-run): %v", err)
	}
}

// TestMigrateUserSessionsV8_BrokenFK verifies that a DB whose user_sessions
// table has a stale FOREIGN KEY pointing at the renamed-and-dropped
// users_v2_legacy table (the bug seen on ru2 2026-05-13) gets repaired by
// EnsureSchema so that StartSession no longer returns
// "no such table: main.users_v2_legacy".
func TestMigrateUserSessionsV8_BrokenFK(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "broken-fk.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	// Simulate the on-disk state ru2 ended up in: users table exists at v3
	// shape, but user_sessions still carries the FK SQLite re-wrote during
	// the legacy ALTER TABLE RENAME TO users_v2_legacy step.
	if _, err := db.Exec(`
        CREATE TABLE outbounds (tag TEXT PRIMARY KEY, kind TEXT NOT NULL, uri TEXT, note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        INSERT INTO outbounds VALUES('direct','direct',NULL,'',0,0);
        CREATE TABLE users (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, master_shortid TEXT NOT NULL UNIQUE,
            epoch_key TEXT, pool_size INTEGER,
            outbound_tag TEXT NOT NULL DEFAULT 'direct',
            bytes_up INTEGER NOT NULL DEFAULT 0, bytes_down INTEGER NOT NULL DEFAULT 0,
            bytes_reset_at INTEGER, expires_at INTEGER, bandwidth_cap INTEGER,
            last_seen_at INTEGER, notification_pending INTEGER NOT NULL DEFAULT 0,
            notification_text TEXT, quota_baseline INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        INSERT INTO users(id,name,master_shortid,created_at,updated_at) VALUES('u1','alice','aa11',0,0);
        CREATE TABLE user_sessions (
            user_id TEXT NOT NULL, session_id TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            bytes_up INTEGER NOT NULL DEFAULT 0, bytes_down INTEGER NOT NULL DEFAULT 0,
            last_active_at INTEGER NOT NULL, pool_index INTEGER,
            PRIMARY KEY (user_id, session_id),
            FOREIGN KEY (user_id) REFERENCES users_v2_legacy(id) ON DELETE CASCADE
        );
    `); err != nil {
		t.Fatalf("seed broken-FK schema: %v", err)
	}

	// Sanity: before repair, a StartSession-style INSERT fails.
	if _, err := db.Exec(`INSERT OR REPLACE INTO user_sessions(user_id, session_id, started_at, bytes_up, bytes_down, last_active_at, pool_index) VALUES('u1','sess-x',0,0,0,0,NULL)`); err == nil {
		t.Fatalf("expected pre-migration INSERT to fail with missing users_v2_legacy table")
	}

	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	// Post-migration: the DDL must no longer reference users_v2_legacy.
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='user_sessions'`).Scan(&ddl); err != nil {
		t.Fatalf("read post-migration ddl: %v", err)
	}
	if strings.Contains(ddl, "users_v2_legacy") {
		t.Fatalf("user_sessions DDL still references users_v2_legacy: %s", ddl)
	}

	// And a fresh StartSession-style INSERT succeeds.
	if _, err := db.Exec(`INSERT OR REPLACE INTO user_sessions(user_id, session_id, started_at, bytes_up, bytes_down, last_active_at, pool_index) VALUES('u1','sess-y',0,0,0,0,NULL)`); err != nil {
		t.Fatalf("post-migration INSERT: %v", err)
	}

	// Idempotency: re-running EnsureSchema must not error and must keep the
	// row we just inserted.
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema re-run: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE session_id='sess-y'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("post re-run row count: n=%d err=%v", n, err)
	}
}
