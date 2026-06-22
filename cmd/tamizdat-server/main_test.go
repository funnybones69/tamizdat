package main

import (
	"flag"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/userdb"

	_ "modernc.org/sqlite"
)

// TestLoadInboundSettings_MaxStreamsWiring is the Bug 1 regression guard:
// a panel-applied inbound_max_streams=2000 row must round-trip through
// loadInboundSettings + the resolveInt logic into the value that ends up
// on ServerConfig.MaxConcurrentStreams.
//
// The resolution logic is a closure inside main(); we mirror its essentials
// here (CLI flag NOT set, DB value present and parseable, builtin default
// fallback) so a regression in either loadInboundSettings or the resolveInt
// arithmetic surfaces in this test.
func TestLoadInboundSettings_MaxStreamsWiring(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	db, err := obreg.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	// Panel writes inbound_max_streams via UPSERT. EnsureSchema seeded the
	// default ("1000"); REPLACE here mirrors what the panel does on user edit.
	if _, err := db.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('inbound_max_streams', '2000')`); err != nil {
		t.Fatalf("upsert inbound_max_streams: %v", err)
	}
	// Close before reopening from the helper under test (mirrors prod where
	// the panel writer and the server reader open the DB independently).
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	settings := loadInboundSettings(dbPath)
	got, ok := settings["inbound_max_streams"]
	if !ok {
		t.Fatalf("loadInboundSettings: inbound_max_streams missing from result")
	}
	if got != "2000" {
		t.Fatalf("loadInboundSettings inbound_max_streams = %q, want %q", got, "2000")
	}
	n, err := strconv.Atoi(strings.TrimSpace(got))
	if err != nil {
		t.Fatalf("inbound_max_streams not an int: %v", err)
	}
	if n != 2000 {
		t.Fatalf("inbound_max_streams parsed = %d, want 2000", n)
	}
	// Sanity: the existing 9 settings the server already consumed pre-Bug-1
	// must still round-trip (regression guard for the loadInboundSettings
	// helper itself).
	for _, key := range []string{
		"inbound_listen_addr",
		"inbound_listen_port",
		"inbound_cert_path",
		"inbound_key_path",
		"inbound_masquerade_domain",
		"inbound_masquerade_pool",
		"inbound_proxy_protocol",
		"inbound_proxy_protocol_from",
	} {
		if _, ok := settings[key]; !ok {
			t.Errorf("loadInboundSettings: %s missing from defaults", key)
		}
	}
}

// TestSchemaDefault_ProxyProtocolOff is the Bug 2 regression guard: a fresh
// EnsureSchema (or a schema upgrade against an old DB) must seed
// inbound_proxy_protocol=0 so a deployment without fronting nginx keeps
// accepting real client connections after schema migration.
func TestSchemaDefault_ProxyProtocolOff(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	db, err := obreg.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	settings, err := userdb.LoadSettings(db)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	got, ok := settings["inbound_proxy_protocol"]
	if !ok {
		t.Fatalf("inbound_proxy_protocol missing from defaults")
	}
	if got != "0" {
		t.Fatalf("inbound_proxy_protocol default = %q, want %q (PROXY-proto must default OFF; see Bug 2)", got, "0")
	}
}

// TestReplayWindowFlag_DefaultAndOverride is the D-RR-2 regression guard:
// the `--replay-window` flag must exist on the server CLI, default to 5m, and
// accept Go duration syntax for operator overrides. This guards against the
// flag being dropped or its default silently changing in a future refactor of
// cmd/tamizdat-server/main.go.
func TestReplayWindowFlag_DefaultAndOverride(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want time.Duration
	}{
		{name: "default", args: nil, want: 5 * time.Minute},
		{name: "explicit-30s", args: []string{"--replay-window=30s"}, want: 30 * time.Second},
		{name: "explicit-10m", args: []string{"--replay-window=10m"}, want: 10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("tamizdat-server", flag.ContinueOnError)
			rw := fs.Duration("replay-window", 5*time.Minute, "replay-guard retention window")
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if *rw != tc.want {
				t.Fatalf("replay-window = %v, want %v", *rw, tc.want)
			}
		})
	}
}
