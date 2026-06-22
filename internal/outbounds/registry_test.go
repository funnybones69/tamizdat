package outbounds

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenSQLite(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenSQLiteEnablesWALAndEnsureSchemaCreatesSharedTables(t *testing.T) {
	db := openTestDB(t)
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	for _, table := range []string{"outbounds", "settings", "panel_sessions", "schema_meta"} {
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("missing table %s: %v", table, err)
		}
	}
	var schemaVersion string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&schemaVersion); err != nil {
		t.Fatalf("schema_meta schema_version missing: %v", err)
	}
	if schemaVersion != "1" {
		t.Fatalf("schema_meta schema_version = %q, want 1", schemaVersion)
	}
	var oldSettingsVersion int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='schema_version'`).Scan(&oldSettingsVersion); err != nil {
		t.Fatalf("settings schema_version count: %v", err)
	}
	if oldSettingsVersion != 0 {
		t.Fatalf("settings schema_version rows = %d, want 0", oldSettingsVersion)
	}
}

func TestEnsureSchemaKeepsExistingDirectAndDefaultRows(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	if _, err := db.Exec(`UPDATE outbounds SET note='operator edited', updated_at=updated_at+1 WHERE tag='direct'`); err != nil {
		t.Fatalf("update direct: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES('default_outbound_tag', 'via') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatalf("update default: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema second call: %v", err)
	}
	var note string
	if err := db.QueryRow(`SELECT note FROM outbounds WHERE tag='direct'`).Scan(&note); err != nil {
		t.Fatalf("select direct note: %v", err)
	}
	if note != "operator edited" {
		t.Fatalf("direct note = %q, want operator edited", note)
	}
	var defaultTag string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='default_outbound_tag'`).Scan(&defaultTag); err != nil {
		t.Fatalf("select default_outbound_tag: %v", err)
	}
	if defaultTag != "via" {
		t.Fatalf("default_outbound_tag = %q, want via", defaultTag)
	}
}

func TestRegistry_ConcurrentFirstRun_NoLockError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server.db")
	const workers = 10

	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			db, err := OpenSQLite(dbPath)
			if err != nil {
				errs <- fmt.Errorf("worker %d OpenSQLite: %w", worker, err)
				return
			}
			defer db.Close()
			if err := EnsureSchema(db); err != nil {
				errs <- fmt.Errorf("worker %d EnsureSchema: %w", worker, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	db, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite verify: %v", err)
	}
	defer db.Close()

	var directRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbounds WHERE tag='direct'`).Scan(&directRows); err != nil {
		t.Fatalf("count direct rows: %v", err)
	}
	if directRows != 1 {
		t.Fatalf("direct rows = %d, want 1", directRows)
	}

	var defaultRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='default_outbound_tag'`).Scan(&defaultRows); err != nil {
		t.Fatalf("count default_outbound_tag rows: %v", err)
	}
	if defaultRows != 1 {
		t.Fatalf("default_outbound_tag rows = %d, want 1", defaultRows)
	}
}

func TestRegistry_SchemaUpgradeFromV0Cleanup(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`
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
INSERT INTO settings(key, value) VALUES('schema_version', '0');
`); err != nil {
		t.Fatalf("seed v0 schema: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema upgrade: %v", err)
	}

	var oldRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='schema_version'`).Scan(&oldRows); err != nil {
		t.Fatalf("settings schema_version count: %v", err)
	}
	if oldRows != 0 {
		t.Fatalf("settings schema_version rows = %d, want 0", oldRows)
	}

	var schemaVersion string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&schemaVersion); err != nil {
		t.Fatalf("schema_meta schema_version missing: %v", err)
	}
	if schemaVersion != "1" {
		t.Fatalf("schema_meta schema_version = %q, want 1", schemaVersion)
	}
}

func TestRegistryReloadBootstrapsEmptyDB(t *testing.T) {
	db := openTestDB(t)
	r := NewRegistry(func(configurl.Config) (Client, error) { return &fakeClient{}, nil })
	if err := r.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	d, tag := r.Resolve("")
	defer d.Close()
	if tag != "direct" {
		t.Fatalf("default tag = %q", tag)
	}
	if _, ok := d.(*leasedDialer); !ok {
		t.Fatalf("Resolve should return a leased dialer, got %T", d)
	}
}

func TestRegistryLoadsTamizdatOutboundAndDefault(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`, "via", "tamizdat", goodURI, "test", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES('default_outbound_tag', 'via') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	r := NewRegistry(func(configurl.Config) (Client, error) { calls.Add(1); return &fakeClient{}, nil })
	if err := r.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	d, tag := r.Resolve("")
	defer d.Close()
	if tag != "via" {
		t.Fatalf("default tag = %q", tag)
	}
	if calls.Load() != 0 {
		t.Fatalf("tamizdat client should be lazy, factory calls=%d", calls.Load())
	}
	c, err := d.DialContext(context.Background(), "tcp", "target:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = c.Close()
	if calls.Load() != 1 {
		t.Fatalf("factory calls after dial=%d", calls.Load())
	}
}

func TestRegistryReloadRetiresOldDialerAfterLeaseRelease(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`, "via", "tamizdat", goodURI, "test", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES('default_outbound_tag', 'via') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	clients := []*fakeClient{{}, {}}
	var idx atomic.Int32
	r := NewRegistry(func(configurl.Config) (Client, error) {
		i := int(idx.Add(1)) - 1
		if i >= len(clients) {
			i = len(clients) - 1
		}
		return clients[i], nil
	})
	if err := r.Reload(db); err != nil {
		t.Fatal(err)
	}
	oldLease, oldTag := r.Resolve("")
	if oldTag != "via" {
		t.Fatalf("old tag = %q", oldTag)
	}
	oldConn, err := oldLease.DialContext(context.Background(), "tcp", "old-target:443")
	if err != nil {
		t.Fatalf("old dial: %v", err)
	}

	if _, err := db.Exec(`UPDATE outbounds SET uri=? WHERE tag='via'`, goodURI+"&x=1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(db); err != nil {
		t.Fatal(err)
	}
	if clients[0].closed.Load() != 0 {
		t.Fatalf("old client closed while lease active")
	}

	_ = oldConn.Close()
	_ = oldLease.Close()
	if clients[0].closed.Load() != 1 {
		t.Fatalf("old client close count after lease release=%d", clients[0].closed.Load())
	}

	newLease, _ := r.Resolve("")
	defer newLease.Close()
	c, err := newLease.DialContext(context.Background(), "tcp", "new-target:443")
	if err != nil {
		t.Fatalf("new dial: %v", err)
	}
	_ = c.Close()
	if clients[1].dials.Load() != 1 {
		t.Fatalf("new client dials=%d", clients[1].dials.Load())
	}
}
