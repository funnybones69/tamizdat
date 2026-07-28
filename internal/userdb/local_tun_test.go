package userdb

import (
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
	if !u.LocalAutoRoute || !u.LocalBypassPrivate || !u.LocalBlockQUIC || !u.LocalSniff {
		t.Fatalf("local policy fields = %+v", u)
	}
	var version string
	if err := db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "12" {
		t.Fatalf("schema version = %q, want 12", version)
	}
}
