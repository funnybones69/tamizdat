package userdb

import (
	"testing"
	"time"
)

func TestExpvarSnapshot_Shape(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	insertUser(t, db, "u2", "bob", testMasterB, "direct", 0)
	if _, err := db.Exec(`UPDATE users SET
        h2_peak_streams=7, h2_peak_tcp_streams=6, h2_peak_udp_streams=2, h2_peak_at=12345,
        h2_relay_peak_streams=5, h2_relay_peak_tcp_streams=4, h2_relay_peak_udp_streams=3, h2_relay_peak_at=12346
        WHERE id='u1'`); err != nil {
		t.Fatalf("seed h2 peaks: %v", err)
	}
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if err := StartSession(db, "u1", "s2", 3); err != nil {
		t.Fatalf("StartSession 2: %v", err)
	}
	reg := NewRegistry(50)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	acc := NewAccounting(db)
	acc.Add("u1", "", 100, 200)

	out, total, online := ExpvarSnapshot(db, reg, acc)
	if total != 2 {
		t.Fatalf("total got %d want 2", total)
	}
	if online != 2 {
		t.Fatalf("online got %d want 2", online)
	}
	u1, ok := out["u1"].(map[string]any)
	if !ok {
		t.Fatalf("u1 missing")
	}
	if u1["name"].(string) != "alice" {
		t.Fatalf("u1 name = %v", u1["name"])
	}
	if u1["online_sessions"].(int) != 2 {
		t.Fatalf("u1 online_sessions = %v", u1["online_sessions"])
	}
	if u1["bytes_up"].(int64) != 100 || u1["bytes_down"].(int64) != 200 {
		t.Fatalf("u1 bytes = %v / %v", u1["bytes_up"], u1["bytes_down"])
	}
	if u1["h2_peak_streams"].(int64) != 7 || u1["h2_peak_tcp_streams"].(int64) != 6 || u1["h2_peak_udp_streams"].(int64) != 2 || u1["h2_peak_at"].(int64) != 12345 {
		t.Fatalf("u1 h2 peaks = %+v", u1)
	}
	if u1["h2_relay_peak_streams"].(int64) != 5 || u1["h2_relay_peak_tcp_streams"].(int64) != 4 || u1["h2_relay_peak_udp_streams"].(int64) != 3 || u1["h2_relay_peak_at"].(int64) != 12346 {
		t.Fatalf("u1 relay h2 peaks = %+v", u1)
	}
	// u2 has no sessions, no pending bytes.
	u2, ok := out["u2"].(map[string]any)
	if !ok {
		t.Fatalf("u2 missing")
	}
	if u2["online_sessions"].(int) != 0 {
		t.Fatalf("u2 online_sessions = %v", u2["online_sessions"])
	}
}

func TestExpvarSnapshot_StaleSessionsExcluded(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	// Force last_active_at into the deep past.
	if _, err := db.Exec(`UPDATE user_sessions SET last_active_at=? WHERE user_id='u1'`, time.Now().Add(-1*time.Hour).Unix()); err != nil {
		t.Fatalf("update: %v", err)
	}
	reg := NewRegistry(50)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	acc := NewAccounting(db)
	_, _, online := ExpvarSnapshot(db, reg, acc)
	if online != 0 {
		t.Fatalf("online got %d want 0 (session is stale)", online)
	}
}
