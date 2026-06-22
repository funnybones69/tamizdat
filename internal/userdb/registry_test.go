package userdb

import (
	"sync"
	"testing"
)

const (
	testMasterA = "1acad6addd6eab4a"
	testMasterB = "0123456789abcdef"
)

func TestRegistry_LoadAndLookup(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u-default", "default", testMasterA, "direct", 0, 3)
	insertUser(t, db, "u-petrov", "petrov", testMasterB, "direct", 0, 1)

	reg := NewRegistry(50)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reg.Count() != 2 {
		t.Fatalf("Count=%d want 2", reg.Count())
	}

	// Master shortid lookup → PoolIndex == -1.
	lk, u, ok := reg.LookupHex(testMasterA)
	if !ok {
		t.Fatalf("master lookup miss")
	}
	if lk.UserID != "u-default" || lk.PoolIndex != -1 {
		t.Fatalf("master lookup got %+v", lk)
	}
	if u.Name != "default" {
		t.Fatalf("user name mismatch %s", u.Name)
	}
	if u.PoolSize != 3 {
		t.Fatalf("pool size = %d, want 3", u.PoolSize)
	}

	// Unknown shortid.
	if _, _, ok := reg.LookupHex("ffffffffffffffff"); ok {
		t.Fatalf("expected miss on unknown")
	}
}

func TestRegistry_ShortIDCount(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	insertUser(t, db, "u2", "bob", testMasterB, "direct", 0)

	reg := NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// shortid full-B simplification: each user contributes exactly one shortid.
	if reg.ShortIDCount() != 2 {
		t.Fatalf("ShortIDCount=%d want 2", reg.ShortIDCount())
	}
	if reg.ShortIDCount() != reg.Count() {
		t.Fatalf("ShortIDCount=%d != Count=%d (post-simplification they must match)", reg.ShortIDCount(), reg.Count())
	}
}

func TestRegistry_AtomicSwapOnReload(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)

	reg := NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload1: %v", err)
	}
	gen1 := reg.Generation()

	// Add a second user.
	insertUser(t, db, "u2", "bob", testMasterB, "direct", 0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload2: %v", err)
	}
	if reg.Generation() != gen1+1 {
		t.Fatalf("Generation expected to bump")
	}
	if reg.Count() != 2 {
		t.Fatalf("Count=%d want 2", reg.Count())
	}
}

func TestRegistry_ConcurrentLookupsDuringReload(t *testing.T) {
	db := openTestDB(t)
	for i := 0; i < 10; i++ {
		master, _ := GenerateMasterShortID()
		insertUser(t, db, "uid-"+master, "user"+master[:4], master, "direct", 0)
	}
	reg := NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	master := testMasterA
	insertUser(t, db, "extra", "extra", master, "direct", 0)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _, _ = reg.LookupHex(master)
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if err := reg.Reload(db); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Reload[%d]: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestRegistry_CollisionRejected(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u1", "alice", testMasterA, "direct", 0)
	// UNIQUE constraint on master_shortid catches the duplicate at insert time.
	_, err := db.Exec(`INSERT INTO users(id, name, master_shortid, outbound_tag, created_at, updated_at) VALUES('u2', 'bob', ?, 'direct', 0, 0)`, testMasterA)
	if err == nil {
		t.Fatalf("expected UNIQUE failure on master_shortid")
	}
}

func TestRegistry_NilSafe(t *testing.T) {
	var reg *UserRegistry
	if reg.Count() != 0 || reg.ShortIDCount() != 0 || reg.Generation() != 0 {
		t.Fatalf("nil registry should report 0")
	}
	if _, _, ok := reg.LookupHex("aaaaaaaaaaaaaaaa"); ok {
		t.Fatalf("nil registry must miss")
	}
}

func TestNormalizeShortIDHex(t *testing.T) {
	got, err := NormalizeShortIDHex(" 1ACAD6ADDD6EAB4A\n")
	if err != nil {
		t.Fatalf("NormalizeShortIDHex: %v", err)
	}
	if got != "1acad6addd6eab4a" {
		t.Fatalf("got %q want lower-cased trimmed", got)
	}
	if _, err := NormalizeShortIDHex("short"); err == nil {
		t.Fatalf("expected length error")
	}
	if _, err := NormalizeShortIDHex("ZZACAD6ADDD6EAB4A"); err == nil {
		t.Fatalf("expected hex error")
	}
}

func TestGenerators(t *testing.T) {
	uid, err := GenerateUserID()
	if err != nil || len(uid) != 16 {
		t.Fatalf("GenerateUserID: %s %v", uid, err)
	}
	mid, err := GenerateMasterShortID()
	if err != nil || len(mid) != 16 {
		t.Fatalf("GenerateMasterShortID: %s %v", mid, err)
	}
}
