package node

import (
	"path/filepath"
	"reflect"
	"testing"
)

// Phase 4 (2026-05-10): GeoDataUpdater multi-URL path resolution tests.
// These cover the legacy single-source backward-compat path, the
// multi-URL path-index scheme, and the empty-list fallback.

func TestEffectiveURLs_MultiWins(t *testing.T) {
	got := effectiveURLs(
		[]string{"https://a", "https://b"},
		"https://singular",
		"https://default",
	)
	want := []string{"https://a", "https://b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi wins: got %v want %v", got, want)
	}
}

func TestEffectiveURLs_BlankMultiFallsToSingular(t *testing.T) {
	got := effectiveURLs(
		[]string{"", "  "},
		"https://singular",
		"https://default",
	)
	want := []string{"https://singular"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("singular fallback: got %v want %v", got, want)
	}
}

func TestEffectiveURLs_NoMultiNoSingularFallsToDefault(t *testing.T) {
	got := effectiveURLs(nil, "", "https://default")
	want := []string{"https://default"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default fallback: got %v want %v", got, want)
	}
}

func TestEffectiveURLs_AllEmptyReturnsNil(t *testing.T) {
	got := effectiveURLs(nil, "", "")
	if got != nil {
		t.Fatalf("expected nil when no defaults available, got %v", got)
	}
}

func TestEffectiveURLs_FiltersBlankLinesAndTrims(t *testing.T) {
	got := effectiveURLs(
		[]string{"  https://a ", "", "https://b\n", "\t"},
		"",
		"",
	)
	want := []string{"https://a", "https://b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filter+trim: got %v want %v", got, want)
	}
}

func TestTargetForIndex_LegacyVsIndexed(t *testing.T) {
	dir := "/etc/tamizdat"
	if got := targetForIndex(dir, "geoip", 0); got != filepath.Join(dir, "geoip.dat") {
		t.Fatalf("index 0 should keep legacy name: got %q", got)
	}
	if got := targetForIndex(dir, "geoip", 1); got != filepath.Join(dir, "geoip-1.dat") {
		t.Fatalf("index 1: got %q", got)
	}
	if got := targetForIndex(dir, "geosite", 7); got != filepath.Join(dir, "geosite-7.dat") {
		t.Fatalf("index 7: got %q", got)
	}
}

func TestGeoIPPaths_RespectsMultiAndSingular(t *testing.T) {
	dir := t.TempDir()

	// Empty → just the legacy default-URL path.
	u := &GeoDataUpdater{Dir: dir}
	got := u.GeoIPPaths()
	want := []string{filepath.Join(dir, "geoip.dat")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default: got %v want %v", got, want)
	}

	// Multi: 3 URLs → 3 paths (idx 0 = geoip.dat, idx 1+ = geoip-N.dat).
	u = &GeoDataUpdater{Dir: dir, GeoIPURLs: []string{"a", "b", "c"}}
	got = u.GeoIPPaths()
	want = []string{
		filepath.Join(dir, "geoip.dat"),
		filepath.Join(dir, "geoip-1.dat"),
		filepath.Join(dir, "geoip-2.dat"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi: got %v want %v", got, want)
	}
}
