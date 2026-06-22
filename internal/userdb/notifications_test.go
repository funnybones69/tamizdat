package userdb

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// newNotifTestDB returns an in-memory DB with EnsureSchema applied and one
// test user inserted. Used by GetNotificationPending / Clear / Set tests.
func newNotifTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	uid := "user-notif-test"
	_, err = db.Exec(`INSERT INTO users
        (id, name, master_shortid, outbound_tag, notification_pending,
         quota_baseline, created_at, updated_at)
        VALUES (?, 'notif-test', 'aabbccddeeff0011', 'direct', 0, 0, 1, 1)`, uid)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return db, uid
}

func TestGetNotificationPending_DefaultZero(t *testing.T) {
	db, uid := newNotifTestDB(t)
	got, err := GetNotificationPending(context.Background(), db, uid)
	if err != nil {
		t.Fatalf("GetNotificationPending: %v", err)
	}
	if got {
		t.Fatalf("fresh user notification_pending should be false, got true")
	}
}

func TestGetNotificationPending_UnknownUserNoError(t *testing.T) {
	db, _ := newNotifTestDB(t)
	got, err := GetNotificationPending(context.Background(), db, "nonexistent-id")
	if err != nil {
		t.Fatalf("unexpected error for unknown user: %v", err)
	}
	if got {
		t.Fatalf("unknown user should return false")
	}
}

func TestSetAndClearNotificationPending_Roundtrip(t *testing.T) {
	db, uid := newNotifTestDB(t)
	ctx := context.Background()

	if err := SetNotificationPending(ctx, db, uid, 100); err != nil {
		t.Fatalf("SetNotificationPending: %v", err)
	}
	got, err := GetNotificationPending(ctx, db, uid)
	if err != nil || !got {
		t.Fatalf("after Set: got=%v err=%v, want got=true err=nil", got, err)
	}

	if err := ClearNotificationPending(ctx, db, uid, 200); err != nil {
		t.Fatalf("ClearNotificationPending: %v", err)
	}
	got, err = GetNotificationPending(ctx, db, uid)
	if err != nil || got {
		t.Fatalf("after Clear: got=%v err=%v, want got=false err=nil", got, err)
	}
}

func TestSetNotificationPending_UnknownUserErrors(t *testing.T) {
	db, _ := newNotifTestDB(t)
	err := SetNotificationPending(context.Background(), db, "nope", 1)
	if err == nil {
		t.Fatalf("expected error for unknown user, got nil")
	}
}

func TestClearNotificationPending_Idempotent(t *testing.T) {
	db, uid := newNotifTestDB(t)
	ctx := context.Background()
	// Clearing a never-set flag is a no-op success.
	if err := ClearNotificationPending(ctx, db, uid, 1); err != nil {
		t.Fatalf("clear when already 0: %v", err)
	}
	if err := SetNotificationPending(ctx, db, uid, 2); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := ClearNotificationPending(ctx, db, uid, 3); err != nil {
		t.Fatalf("first clear: %v", err)
	}
	// Second clear: still no-op success.
	if err := ClearNotificationPending(ctx, db, uid, 4); err != nil {
		t.Fatalf("double clear: %v", err)
	}
	got, _ := GetNotificationPending(ctx, db, uid)
	if got {
		t.Fatalf("after double-clear, want false; got true")
	}
}
