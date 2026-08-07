package userdb

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRegistryLoadsLocalUserButDoesNotAuthenticateIt(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Unix()
	const shortID = "cccccccccccccccc"
	_, err := db.Exec(`INSERT INTO users(
		id,name,master_shortid,user_kind,outbound_tag,
		local_enabled,local_iface,local_tun_name,local_tun_addr,local_tun_mtu,
		local_auto_route,local_bypass_private,local_block_quic,local_sniff,
		created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"local-1", "router-lan", shortID, "local_tun", "direct",
		1, "br-lan", "taml0", "198.18.0.1/24", 1280,
		1, 1, 1, 1, now, now)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(1)
	if err := reg.Reload(db); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := reg.LookupHex(shortID); ok {
		t.Fatal("local TUN user must not authenticate as a remote shortid user")
	}
	u, ok := reg.User("local-1")
	if !ok {
		t.Fatal("local user missing from registry by ID")
	}
	if u.Kind != "local_tun" || !u.LocalEnabled || u.LocalInterface != "br-lan" {
		t.Fatalf("local user fields = %+v", u)
	}
	if !u.LocalAutoRoute || !u.LocalBypassPrivate || !u.LocalBlockQUIC || !u.LocalSniff || u.LocalFailClosed {
		t.Fatalf("local policy fields = %+v", u)
	}
	var version string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "13" {
		t.Fatalf("schema version = %q, want 13", version)
	}
}

func TestOnlyOneLocalTunUserCanBeCreatedConcurrently(t *testing.T) {
	db := openTestDB(t)
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := db.Exec(`INSERT INTO users(id,name,master_shortid,user_kind,outbound_tag,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?)`, fmt.Sprintf("local-%d", i), fmt.Sprintf("router-%d", i), fmt.Sprintf("%016x", i+1), "local_tun", "direct", time.Now().Unix(), time.Now().Unix())
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent local_tun inserts succeeded %d times, want exactly 1", successes)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE user_kind='local_tun'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("local_tun rows = %d, want 1", count)
	}
}
