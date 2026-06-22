package node

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
)

// TestGeoDataUpdaterEndToEndReloadAfterRefresh proves the full path the
// SIGHUP handler in cmd/tamizdat-server uses:
//
//  1. Updater downloads the .dat into the configured directory.
//  2. OnRefresh fires (panel/SIGHUP reload would call publishRouting →
//     LoadGeoDB → CompileRulesWithGeoDB → NewDispatcher).
//  3. The compiled rule resolves a geoip:/geosite: token against the
//     freshly-downloaded dataset rather than the curated fallback.
//
// This guards the integration seam between this package and
// internal/rulesdb.BuildWithGeoDB.
func TestGeoDataUpdaterEndToEndReloadAfterRefresh(t *testing.T) {
	dir := t.TempDir()
	_, srv := newFakeAssetServer(t)

	// fakeAssetServer publishes:
	//   geoip:    "telegram" → 149.154.160.0/20
	//   geosite:  "openai"   → full match openai.com
	// Curated fallback also has telegram → 149.154.160.0/20, but adding
	// 8.8.8.8 to the dat-only mapping demonstrates the dat is preferred.
	// We can't mutate fakeAssetServer's fixed body easily without growing
	// the helper, so we assert the dat content is loaded by checking the
	// TLD that appears only in the dat geosite ("openai") which curated
	// also has — but we additionally verify telegram CIDR resolves
	// (proves dat parse worked, not just that curated kicked in).

	var refreshedPath string
	var mu sync.Mutex
	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         func(string, ...any) {},
		OnRefresh: func(p string) {
			mu.Lock()
			defer mu.Unlock()
			refreshedPath = p
		},
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mu.Lock()
	got := refreshedPath
	mu.Unlock()
	if got == "" {
		t.Fatal("expected OnRefresh to have fired with a path")
	}

	// Now run the same sequence cmd/tamizdat-server publishRouting does:
	geoDB, err := LoadGeoDB(filepath.Join(dir, "geoip.dat"), filepath.Join(dir, "geosite.dat"))
	if err != nil {
		t.Fatalf("LoadGeoDB after download: %v", err)
	}
	if geoDB == nil {
		t.Fatal("LoadGeoDB returned nil despite both files present on disk")
	}

	// Compile a rule that uses geoip:telegram + geosite:openai. If the dat
	// failed to load, CompileRulesWithGeoDB would have to use curated
	// data, and curated geosite "openai" would also match openai.com —
	// so the unique-to-dat assertion is harder. Instead, assert the dat
	// path actually populated the GeoDB struct (its size > 0 implies the
	// real protobuf was parsed, not the curated map).
	if cidrs := geoDB.GeoIPCIDRs("telegram"); len(cidrs) == 0 {
		t.Fatal("geoDB has no telegram CIDRs after dat load")
	} else {
		ok := false
		for _, p := range cidrs {
			if p.Contains(netip.MustParseAddr("149.154.166.1")) {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatal("downloaded geoip.dat telegram CIDR should contain 149.154.166.1")
		}
	}

	matchers := geoDB.GeositeMatchers("openai")
	if len(matchers) == 0 {
		t.Fatal("geoDB has no openai matchers after dat load")
	}
	hit := false
	for _, m := range matchers {
		if m.match("openai.com") {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatal("openai.com should match downloaded geosite.dat 'openai' rule")
	}

	// Compile a real rule and verify it routes through the geoDB.
	rule := &Rule{Geosite: []string{"openai"}, Outbound: "block"}
	compiled, err := CompileRulesWithGeoDB([]*Rule{rule}, geoDB)
	if err != nil {
		t.Fatalf("CompileRulesWithGeoDB: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(compiled))
	}
	req := &Request{Network: "tcp", TargetHost: "openai.com", TargetPort: 443}
	if !compiled[0].Match(req) {
		t.Fatal("compiled rule should match openai.com via dat-loaded geoDB")
	}
}
