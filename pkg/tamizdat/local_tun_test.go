package tamizdat

import (
	"path/filepath"
	"testing"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/userdb"
)

func TestLocalTUNConfigsExposeUserFallbackOutbound(t *testing.T) {
	db, err := obreg.OpenSQLite(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO outbounds(tag,kind,uri,created_at,updated_at)
		VALUES('balancer','balancer','{"mode":"alive","outbounds":["direct"]}',0,0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users(
		id,name,master_shortid,user_kind,outbound_tag,local_enabled,local_iface,created_at,updated_at)
		VALUES('local-1','router-lan','cccccccccccccccc','local_tun','balancer',1,'br-lan',0,0)`); err != nil {
		t.Fatal(err)
	}

	registry := userdb.NewRegistry(0)
	if err := registry.Reload(db); err != nil {
		t.Fatal(err)
	}
	server := &Server{userRegistry: registry}
	configs := server.LocalTUNConfigs()
	if len(configs) != 1 {
		t.Fatalf("local TUN config count = %d, want 1", len(configs))
	}
	if got := configs[0].FallbackTag; got != "balancer" {
		t.Fatalf("local TUN fallback = %q, want balancer", got)
	}
}
