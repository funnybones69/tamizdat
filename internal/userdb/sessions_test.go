package userdb

import (
	"testing"
	"time"
)

func TestSessions_StartEnd(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "sess-A", -1); err != nil {
		t.Fatalf("StartSession A: %v", err)
	}
	if err := StartSession(db, "u1", "sess-B", 7); err != nil {
		t.Fatalf("StartSession B: %v", err)
	}
	n, err := CountSessions(db, "u1")
	if err != nil || n != 2 {
		t.Fatalf("CountSessions got %d, err %v", n, err)
	}
	now := time.Now().Unix()
	online, poolMax, err := OnlineCounts(db, now-90)
	if err != nil {
		t.Fatalf("OnlineCounts: %v", err)
	}
	if online["u1"] != 2 {
		t.Fatalf("online got %d want 2", online["u1"])
	}
	// MAX(pool_index) ignores NULL → should be 7 (the dynamic). But COALESCE
	// returns -1 only when ALL rows are NULL; with one numeric row, MAX takes it.
	if poolMax["u1"] != 7 {
		t.Fatalf("poolMax got %d want 7", poolMax["u1"])
	}
	if err := EndSession(db, "u1", "sess-A"); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
	n, _ = CountSessions(db, "u1")
	if n != 1 {
		t.Fatalf("CountSessions after end got %d want 1", n)
	}
}

func TestSessions_CascadeOnUserDelete(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id='u1'`); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE user_id='u1'`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("FK cascade did not fire: %d sessions remain", n)
	}
}

func TestSessions_TouchUpdates(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	// Force last_active_at to be in the past, then touch.
	if _, err := db.Exec(`UPDATE user_sessions SET last_active_at=? WHERE user_id='u1' AND session_id='s1'`, 1); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := TouchSession(db, "u1", "s1"); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	var la int64
	if err := db.QueryRow(`SELECT last_active_at FROM user_sessions WHERE user_id='u1' AND session_id='s1'`).Scan(&la); err != nil {
		t.Fatalf("query: %v", err)
	}
	if la <= 1 {
		t.Fatalf("TouchSession did not update: %d", la)
	}
}

func TestBootstrapLegacyShortID(t *testing.T) {
	db := openTestDB(t)
	tmp := t.TempDir() + "/shortid.hex"
	if err := writeFile(tmp, "1acad6addd6eab4a\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	migrated, err := BootstrapLegacyShortID(db, tmp)
	if err != nil {
		t.Fatalf("BootstrapLegacyShortID: %v", err)
	}
	if !migrated {
		t.Fatalf("expected migration to happen")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE name='default'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatalf("user count = %d want 1", n)
	}
	var marker string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key='migrated_from_v1'`).Scan(&marker); err != nil {
		t.Fatalf("schema_meta migrated_from_v1 missing: %v", err)
	}
	if marker == "" {
		t.Fatalf("marker is empty")
	}

	// Idempotent: running again is a no-op.
	migrated2, err := BootstrapLegacyShortID(db, tmp)
	if err != nil || migrated2 {
		t.Fatalf("second migrate got %v %v want false nil", migrated2, err)
	}
}

func TestBootstrapLegacyShortID_NoFile(t *testing.T) {
	db := openTestDB(t)
	migrated, err := BootstrapLegacyShortID(db, t.TempDir()+"/nonexistent")
	if err != nil {
		t.Fatalf("BootstrapLegacyShortID: %v", err)
	}
	if migrated {
		t.Fatalf("expected no-op migration")
	}
}

// writeFile helper.
func writeFile(path, content string) error {
	return writeFileBytes(path, []byte(content))
}
