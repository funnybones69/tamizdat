package userdb

import (
	"testing"
	"time"
)

func TestActiveTransportsPrefersTURN(t *testing.T) {
	db := openTestDB(t)
	userID := "u-transport-a"
	insertUser(t, db, userID, "alice", testMasterA, "direct", 0)
	if err := StartSessionWithTransport(db, userID, "h2-session", -1, "h2"); err != nil {
		t.Fatalf("StartSessionWithTransport h2: %v", err)
	}
	if err := StartSessionWithTransport(db, userID, "turn-session", -1, "turn"); err != nil {
		t.Fatalf("StartSessionWithTransport turn: %v", err)
	}
	got, err := ActiveTransports(db, time.Now().Add(-time.Minute).Unix())
	if err != nil {
		t.Fatalf("ActiveTransports: %v", err)
	}
	if got[userID] != "turn" {
		t.Fatalf("transport = %q, want turn", got[userID])
	}
}

func TestStartSessionDefaultsTransportToH2(t *testing.T) {
	db := openTestDB(t)
	userID := "u-transport-b"
	insertUser(t, db, userID, "bob", testMasterB, "direct", 0)
	if err := StartSession(db, userID, "legacy-session", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	got, err := ActiveTransports(db, time.Now().Add(-time.Minute).Unix())
	if err != nil {
		t.Fatalf("ActiveTransports: %v", err)
	}
	if got[userID] != "h2" {
		t.Fatalf("transport = %q, want h2", got[userID])
	}
}
