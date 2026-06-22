package userdb

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestAccounting_Single(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	acc := NewAccounting(db)
	acc.Add("u1", "s1", 1024, 2048)
	up, down := acc.Pending("u1")
	if up != 1024 || down != 2048 {
		t.Fatalf("pending got %d/%d", up, down)
	}
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	up, down = acc.Pending("u1")
	if up != 0 || down != 0 {
		t.Fatalf("pending after flush got %d/%d", up, down)
	}
	var bytesUp, bytesDown int64
	if err := db.QueryRow(`SELECT bytes_up, bytes_down FROM users WHERE id='u1'`).Scan(&bytesUp, &bytesDown); err != nil {
		t.Fatalf("query: %v", err)
	}
	if bytesUp != 1024 || bytesDown != 2048 {
		t.Fatalf("DB bytes got %d/%d", bytesUp, bytesDown)
	}
	var sUp, sDown int64
	if err := db.QueryRow(`SELECT bytes_up, bytes_down FROM user_sessions WHERE user_id='u1' AND session_id='s1'`).Scan(&sUp, &sDown); err != nil {
		t.Fatalf("session query: %v", err)
	}
	if sUp != 1024 || sDown != 2048 {
		t.Fatalf("session bytes got %d/%d", sUp, sDown)
	}
}

func TestAccounting_ConcurrentRace(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	if err := StartSession(db, "u1", "s1", -1); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	acc := NewAccounting(db)

	var wg sync.WaitGroup
	const writers = 8
	const perWriter = 1000
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				acc.Add("u1", "s1", 7, 13)
			}
		}()
	}
	wg.Wait()
	wantUp := int64(writers * perWriter * 7)
	wantDown := int64(writers * perWriter * 13)
	up, down := acc.Pending("u1")
	if up != wantUp || down != wantDown {
		t.Fatalf("pending got %d/%d want %d/%d", up, down, wantUp, wantDown)
	}
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var bytesUp, bytesDown int64
	if err := db.QueryRow(`SELECT bytes_up, bytes_down FROM users WHERE id='u1'`).Scan(&bytesUp, &bytesDown); err != nil {
		t.Fatalf("query: %v", err)
	}
	if bytesUp != wantUp || bytesDown != wantDown {
		t.Fatalf("DB bytes got %d/%d want %d/%d", bytesUp, bytesDown, wantUp, wantDown)
	}
}

func TestAccounting_BackgroundFlush(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	acc := NewAccounting(db)
	acc.Start(ctx, 50*time.Millisecond)
	acc.Add("u1", "", 100, 200)

	// wait up to 1s for background goroutine to flush
	deadline := time.Now().Add(1 * time.Second)
	var bytesUp int64
	for time.Now().Before(deadline) {
		_ = db.QueryRow(`SELECT bytes_up FROM users WHERE id='u1'`).Scan(&bytesUp)
		if bytesUp == 100 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if bytesUp != 100 {
		t.Fatalf("background flush did not write: bytes_up=%d", bytesUp)
	}
}

func TestAccounting_NoOpZeroDelta(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	acc := NewAccounting(db)
	acc.Add("u1", "", 0, 0)
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func TestAccounting_NilSafe(t *testing.T) {
	var acc *Accounting
	acc.Add("u1", "s1", 1, 2)
	if up, down := acc.Pending("u1"); up != 0 || down != 0 {
		t.Fatalf("nil pending got %d/%d", up, down)
	}
	if err := acc.Flush(); err != nil {
		t.Fatalf("nil Flush: %v", err)
	}
}

// TestAccounting_FlushRollbackRestoresDeltas verifies Finding 2: when the DB
// transaction errors out, the swapped-out byte deltas are restored back into
// the in-memory accumulator so the next Flush retries instead of dropping
// the bytes on the floor.
func TestAccounting_FlushRollbackRestoresDeltas(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)

	acc := NewAccounting(db)
	acc.Add("u1", "s1", 4096, 8192)

	// Close the DB underneath the accounter. The next Begin() call will
	// fail; Flush MUST restore the deltas to Pending.
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	if err := acc.Flush(); err == nil {
		t.Fatalf("Flush expected to fail after db.Close")
	}
	up, down := acc.Pending("u1")
	if up != 4096 || down != 8192 {
		t.Fatalf("after rollback: pending got %d/%d want 4096/8192", up, down)
	}
}
