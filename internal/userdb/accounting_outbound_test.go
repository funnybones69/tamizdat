package userdb

import (
	"database/sql"
	"sync"
	"testing"
)

// outboundsSchema mirrors the post-migration shape of the outbounds table
// owned by internal/outbounds/registry.go. Duplicated here (instead of
// importing the outbounds package) to keep userdb dependency-free and
// avoid a circular-import path through server.go.
const outboundsSchema = `
CREATE TABLE IF NOT EXISTS outbounds (
    tag TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    uri TEXT,
    note TEXT,
    bind_iface TEXT,
    bytes_up INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
`

func ensureOutboundsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(outboundsSchema); err != nil {
		t.Fatalf("create outbounds table: %v", err)
	}
}

func insertOutbound(t *testing.T, db *sql.DB, tag, kind string) {
	t.Helper()
	_, err := db.Exec(`INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		tag, kind, nil, "", 0, 0)
	if err != nil {
		t.Fatalf("insert outbound %s: %v", tag, err)
	}
}

func readOutboundBytes(t *testing.T, db *sql.DB, tag string) (int64, int64) {
	t.Helper()
	var up, down int64
	err := db.QueryRow(`SELECT bytes_up, bytes_down FROM outbounds WHERE tag=?`, tag).Scan(&up, &down)
	if err != nil {
		t.Fatalf("query outbound bytes for %s: %v", tag, err)
	}
	return up, down
}

func TestAccounting_OutboundSingle(t *testing.T) {
	db := openTestDB(t)
	ensureOutboundsTable(t, db)
	insertOutbound(t, db, "direct", "direct")

	acc := NewAccounting(db)
	acc.AddOutbound("direct", 100, 200)
	up, down := acc.PendingOutbound("direct")
	if up != 100 || down != 200 {
		t.Fatalf("pending outbound got %d/%d, want 100/200", up, down)
	}

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	up, down = acc.PendingOutbound("direct")
	if up != 0 || down != 0 {
		t.Fatalf("pending after flush got %d/%d, want 0/0", up, down)
	}
	dbUp, dbDown := readOutboundBytes(t, db, "direct")
	if dbUp != 100 || dbDown != 200 {
		t.Fatalf("DB outbound bytes got %d/%d, want 100/200", dbUp, dbDown)
	}
}

func TestAccounting_OutboundAccumulates(t *testing.T) {
	db := openTestDB(t)
	ensureOutboundsTable(t, db)
	insertOutbound(t, db, "via", "tamizdat")

	acc := NewAccounting(db)
	// Three windows: AddOutbound + Flush, repeat. Verify counters
	// monotonically grow on the row (bytes_up=bytes_up+? semantics in
	// Flush()).
	for i := 0; i < 3; i++ {
		acc.AddOutbound("via", 50, 70)
		if err := acc.Flush(); err != nil {
			t.Fatalf("Flush %d: %v", i, err)
		}
	}
	up, down := readOutboundBytes(t, db, "via")
	if up != 150 || down != 210 {
		t.Fatalf("accumulated bytes got %d/%d, want 150/210", up, down)
	}
}

func TestAccounting_OutboundConcurrent(t *testing.T) {
	db := openTestDB(t)
	ensureOutboundsTable(t, db)
	insertOutbound(t, db, "tag-a", "tamizdat")
	insertOutbound(t, db, "tag-b", "tamizdat")

	acc := NewAccounting(db)
	var wg sync.WaitGroup
	const writers = 8
	const perWriter = 1000
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				// Alternate between tags to ensure the in-memory map
				// per-tag counter contention doesn't lose bytes.
				if (id+i)%2 == 0 {
					acc.AddOutbound("tag-a", 3, 5)
				} else {
					acc.AddOutbound("tag-b", 7, 11)
				}
			}
		}(w)
	}
	wg.Wait()

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	upA, downA := readOutboundBytes(t, db, "tag-a")
	upB, downB := readOutboundBytes(t, db, "tag-b")
	totalRows := writers * perWriter
	// Each writer/iter pair pushes one Add to one of two tags. Half of
	// (writers*perWriter) goes to tag-a, half to tag-b — but the exact
	// split depends on (id+i)%2 and is deterministic across runs.
	wantHalves := totalRows / 2
	wantUpA := int64(wantHalves * 3)
	wantDownA := int64(wantHalves * 5)
	wantUpB := int64(wantHalves * 7)
	wantDownB := int64(wantHalves * 11)
	if upA != wantUpA || downA != wantDownA {
		t.Fatalf("tag-a got %d/%d, want %d/%d", upA, downA, wantUpA, wantDownA)
	}
	if upB != wantUpB || downB != wantDownB {
		t.Fatalf("tag-b got %d/%d, want %d/%d", upB, downB, wantUpB, wantDownB)
	}
}

func TestAccounting_OutboundResetThenAdd(t *testing.T) {
	// Models the panel "Reset outbound traffic" flow: external UPDATE
	// zeroes the row, then fresh AddOutbound + Flush accumulates on top
	// of 0 rather than the pre-reset total.
	db := openTestDB(t)
	ensureOutboundsTable(t, db)
	insertOutbound(t, db, "direct", "direct")

	acc := NewAccounting(db)
	acc.AddOutbound("direct", 1000, 2000)
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Simulate panel "Reset" — direct UPDATE outside accounting.
	if _, err := db.Exec(`UPDATE outbounds SET bytes_up=0, bytes_down=0 WHERE tag='direct'`); err != nil {
		t.Fatalf("reset UPDATE: %v", err)
	}
	// Confirm reset.
	up, down := readOutboundBytes(t, db, "direct")
	if up != 0 || down != 0 {
		t.Fatalf("post-reset bytes got %d/%d, want 0/0", up, down)
	}
	// Subsequent traffic accumulates on top of 0.
	acc.AddOutbound("direct", 7, 9)
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush after reset: %v", err)
	}
	up, down = readOutboundBytes(t, db, "direct")
	if up != 7 || down != 9 {
		t.Fatalf("post-reset add bytes got %d/%d, want 7/9", up, down)
	}
}

func TestAccounting_OutboundMissingTagSilentSkip(t *testing.T) {
	// Routing rule fires for a tag that gets deleted between dial-time
	// and flush-time. UPDATE matches 0 rows → no error → no in-memory
	// retry-bouncing. Bytes are dropped silently (acceptable: deleted
	// outbound = nobody to attribute them to).
	db := openTestDB(t)
	ensureOutboundsTable(t, db)

	acc := NewAccounting(db)
	acc.AddOutbound("never-existed", 100, 200)
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush should not error on missing tag: %v", err)
	}
	up, down := acc.PendingOutbound("never-existed")
	if up != 0 || down != 0 {
		t.Fatalf("pending after Flush-with-missing-row got %d/%d, want 0/0 (bytes silently dropped)", up, down)
	}
}
