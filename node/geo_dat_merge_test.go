package node

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Phase 4 (2026-05-10): LoadGeoDBMulti merges multiple .dat sources.
// Uses the testGeoIPList / testGeoSiteList builders defined alongside the
// single-source tests in geo_dat_test.go.

func writeGeoIPDatBytes(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadGeoDBMulti_GeoIPUnionPrefixes(t *testing.T) {
	dir := t.TempDir()
	a := writeGeoIPDatBytes(t, dir, "geoip.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("10.0.0.0", 8)),
	))
	b := writeGeoIPDatBytes(t, dir, "geoip-1.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("11.0.0.0", 8), testCIDR("12.0.0.0", 8)),
	))

	db, err := LoadGeoDBMulti([]string{a, b}, nil)
	if err != nil {
		t.Fatalf("LoadGeoDBMulti: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil db")
	}
	got := db.GeoIPCIDRs("RU")
	gotStrs := make([]string, len(got))
	for i, p := range got {
		gotStrs[i] = p.String()
	}
	sort.Strings(gotStrs)
	want := []string{"10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8"}
	if !reflect.DeepEqual(gotStrs, want) {
		t.Fatalf("RU CIDRs: got %v want %v", gotStrs, want)
	}
}

func TestLoadGeoDBMulti_GeoIPDeduplicates(t *testing.T) {
	dir := t.TempDir()
	a := writeGeoIPDatBytes(t, dir, "geoip.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("10.0.0.0", 8), testCIDR("11.0.0.0", 8)),
	))
	b := writeGeoIPDatBytes(t, dir, "geoip-1.dat", testGeoIPList(
		// 10.0.0.0/8 appears in both — must NOT be duplicated.
		testGeoIP("RU", testCIDR("10.0.0.0", 8), testCIDR("12.0.0.0", 8)),
	))

	db, err := LoadGeoDBMulti([]string{a, b}, nil)
	if err != nil {
		t.Fatalf("LoadGeoDBMulti: %v", err)
	}
	got := db.GeoIPCIDRs("RU")
	if len(got) != 3 {
		t.Fatalf("expected 3 dedup'd CIDRs, got %d (%v)", len(got), got)
	}
}

func TestLoadGeoDBMulti_GeoIPDistinctCountries(t *testing.T) {
	dir := t.TempDir()
	a := writeGeoIPDatBytes(t, dir, "geoip.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("10.0.0.0", 8)),
	))
	b := writeGeoIPDatBytes(t, dir, "geoip-1.dat", testGeoIPList(
		testGeoIP("CN", testCIDR("20.0.0.0", 8)),
	))

	db, err := LoadGeoDBMulti([]string{a, b}, nil)
	if err != nil {
		t.Fatalf("LoadGeoDBMulti: %v", err)
	}
	if got := db.GeoIPCIDRs("RU"); len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("RU: got %v want [10.0.0.0/8]", got)
	}
	if got := db.GeoIPCIDRs("CN"); len(got) != 1 || got[0].String() != "20.0.0.0/8" {
		t.Fatalf("CN: got %v want [20.0.0.0/8]", got)
	}
}

func TestLoadGeoDBMulti_MissingFileTolerated(t *testing.T) {
	dir := t.TempDir()
	a := writeGeoIPDatBytes(t, dir, "geoip.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("10.0.0.0", 8)),
	))
	missing := filepath.Join(dir, "geoip-99.dat") // intentionally not created

	db, err := LoadGeoDBMulti([]string{a, missing}, nil)
	if err != nil {
		t.Fatalf("LoadGeoDBMulti tolerates missing: %v", err)
	}
	if got := db.GeoIPCIDRs("RU"); len(got) != 1 {
		t.Fatalf("expected RU intact when 2nd source missing: %v", got)
	}
}

func TestLoadGeoDBMulti_NoSourcesReturnsNil(t *testing.T) {
	db, err := LoadGeoDBMulti(nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if db != nil {
		t.Fatal("expected nil db when no sources")
	}

	db, err = LoadGeoDBMulti([]string{"", "  "}, []string{""})
	if err != nil {
		t.Fatalf("err on whitespace-only sources: %v", err)
	}
	if db != nil {
		t.Fatal("expected nil db on whitespace-only sources")
	}
}

func TestLoadGeoDBMulti_GeoSiteDedupByTypeValue(t *testing.T) {
	dir := t.TempDir()
	// DomainRule.Type proto enum values: 0=Plain, 1=Regex, 2=RootDomain, 3=Full
	const rootDomain = 2
	a := writeGeoIPDatBytes(t, dir, "geosite.dat", testGeoSiteList(
		testGeoSite("ads",
			testDomainRule(rootDomain, "doubleclick.net"),
			testDomainRule(rootDomain, "googleadservices.com"),
		),
	))
	b := writeGeoIPDatBytes(t, dir, "geosite-1.dat", testGeoSiteList(
		testGeoSite("ads",
			testDomainRule(rootDomain, "doubleclick.net"), // dup → must dedup
			testDomainRule(rootDomain, "googlesyndication.com"),
		),
	))

	db, err := LoadGeoDBMulti(nil, []string{a, b})
	if err != nil {
		t.Fatalf("LoadGeoDBMulti: %v", err)
	}
	rules, ok := geositeRulesFor(db, "ads")
	if !ok {
		t.Fatal("geosite ads not found after merge")
	}
	want := map[string]bool{
		"doubleclick.net":       true,
		"googleadservices.com":  true,
		"googlesyndication.com": true,
	}
	got := make(map[string]bool, len(rules))
	for _, r := range rules {
		got[r.Value] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged rules: got %v want %v", got, want)
	}
	if len(rules) != 3 {
		t.Fatalf("expected exactly 3 dedup'd rules, got %d (%v)", len(rules), rules)
	}
}

// LoadGeoDB (single-source wrapper) still works after the multi-source
// refactor — important for callers that haven't migrated to Multi yet.
func TestLoadGeoDB_BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	a := writeGeoIPDatBytes(t, dir, "geoip.dat", testGeoIPList(
		testGeoIP("RU", testCIDR("10.0.0.0", 8)),
	))

	db, err := LoadGeoDB(a, "")
	if err != nil {
		t.Fatalf("LoadGeoDB single-source: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil db")
	}
	if got := db.GeoIPCIDRs("RU"); len(got) != 1 {
		t.Fatalf("RU CIDRs got %v want 1", got)
	}
}
