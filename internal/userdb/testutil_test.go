package userdb

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func writeFileBytes(path string, content []byte) error {
	return os.WriteFile(path, content, 0o644)
}

// openTestDB opens a freshly-created temp SQLite DB with the same DSN options
// outbounds.OpenSQLite uses (busy_timeout/journal_mode=WAL/foreign_keys=on)
// without taking the import dependency on the outbounds package.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.db")
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// insertUser inserts one user row directly via SQL for tests that drive the
// registry/sessions layer without exercising the panel-style CRUD.
func insertUser(t *testing.T, db *sql.DB, id, name, master, outbound string, expiresAt int64, poolSize ...int) {
	t.Helper()
	if outbound == "" {
		outbound = "direct"
	}
	var ex any
	if expiresAt > 0 {
		ex = expiresAt
	}
	ps := 1
	if len(poolSize) > 0 && poolSize[0] > 0 {
		ps = poolSize[0]
	}
	_, err := db.Exec(`INSERT INTO users(id, name, master_shortid, pool_size, outbound_tag, expires_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, name, master, ps, outbound, ex, 0, 0)
	if err != nil {
		t.Fatalf("insert user %s: %v", name, err)
	}
}
