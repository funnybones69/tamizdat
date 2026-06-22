package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Phase 4 (2026-05-10): splitGeoURLs parses newline-separated multi-URL
// strings from the panel and filters blanks + "#" comment lines.

func TestSplitGeoURLs_SingleURL(t *testing.T) {
	got := splitGeoURLs("https://example.com/geoip.dat")
	want := []string{"https://example.com/geoip.dat"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("single: got %v want %v", got, want)
	}
}

func TestSplitGeoURLs_MultipleNewlines(t *testing.T) {
	got := splitGeoURLs("https://a\nhttps://b\n  https://c  \n")
	want := []string{"https://a", "https://b", "https://c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi: got %v want %v", got, want)
	}
}

func TestSplitGeoURLs_BlankLinesAndComments(t *testing.T) {
	got := splitGeoURLs("https://a\n\n# this is a comment\nhttps://b\n#another\n")
	want := []string{"https://a", "https://b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filter: got %v want %v", got, want)
	}
}

func TestSplitGeoURLs_EmptyReturnsNil(t *testing.T) {
	if got := splitGeoURLs(""); got != nil {
		t.Fatalf("empty: got %v want nil", got)
	}
	if got := splitGeoURLs("\n\n  \n# only comments\n"); got != nil {
		t.Fatalf("blank+comments: got %v want nil", got)
	}
}

// collectGeoDatPaths returns the legacy <base>.dat path first, then any
// existing <base>-N.dat siblings for N in [1..maxGeoMultiSources].
func TestCollectGeoDatPaths_LegacyOnly(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("x"), 0o600)
	got := collectGeoDatPaths(dir, "geoip")
	want := []string{filepath.Join(dir, "geoip.dat")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy-only: got %v want %v", got, want)
	}
}

func TestCollectGeoDatPaths_PicksUpIndexed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "geoip-1.dat"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "geoip-3.dat"), []byte("x"), 0o600)
	// gap at 2 is fine — collector just probes 1..N and skips missing.
	got := collectGeoDatPaths(dir, "geoip")
	want := []string{
		filepath.Join(dir, "geoip.dat"),
		filepath.Join(dir, "geoip-1.dat"),
		filepath.Join(dir, "geoip-3.dat"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("indexed: got %v want %v", got, want)
	}
}

func TestCollectGeoDatPaths_NoFiles(t *testing.T) {
	dir := t.TempDir() // empty
	got := collectGeoDatPaths(dir, "geoip")
	// Always includes the legacy path even when missing; LoadGeoDBMulti
	// tolerates ENOENT. The caller does not need to gate on file existence.
	want := []string{filepath.Join(dir, "geoip.dat")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty dir: got %v want %v", got, want)
	}
}
