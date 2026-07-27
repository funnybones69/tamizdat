package tamizdat

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/funnybones69/tamizdat/internal/bundlecache"
)

// TestPickFingerprintFallsBackToRotator verifies that when no
// fingerprint_pool has been pushed by the server, the client uses its
// local fingerprintRotator (driven by ClientConfig.Fingerprint).
func TestPickFingerprintFallsBackToRotator(t *testing.T) {
	c := &Client{config: ClientConfig{Fingerprint: "chrome"}}
	c.fingerprintChooser = newFingerprintRotator("chrome", nil)
	got := c.pickFingerprint()
	if got.Client == "" {
		t.Fatalf("pickFingerprint returned empty HelloID: %+v", got)
	}
}

// TestPickFingerprintUsesPushedPool verifies that when the server pushes a
// fingerprint_pool, repeated picks select from it. Rotator default is
// "firefox" (not in pushed pool) so a chrome HelloID can only come from
// the pushed pool, proving wiring.
func TestPickFingerprintUsesPushedPool(t *testing.T) {
	c := &Client{config: ClientConfig{Fingerprint: "firefox"}}
	c.fingerprintChooser = newFingerprintRotator("firefox", nil)
	pool := []FingerprintEntry{{ID: "chrome_auto", Weight: 100}}
	c.serverPushedFingerprintPool.Store(&pool)
	gotChrome := false
	for i := 0; i < 50; i++ {
		hello := c.pickFingerprint()
		if hello.Client == "Chrome" {
			gotChrome = true
			break
		}
	}
	if !gotChrome {
		t.Fatal("pushed fingerprint_pool with chrome_auto never produced a Chrome HelloID")
	}
}

// TestPickFingerprintIgnoresUnknownIDs verifies that a server-pushed
// fingerprint_pool with unknown IDs falls back to the rotator entirely
// (no zero-HelloID dial leaks through).
func TestPickFingerprintIgnoresUnknownIDs(t *testing.T) {
	c := &Client{config: ClientConfig{Fingerprint: "chrome"}}
	c.fingerprintChooser = newFingerprintRotator("chrome", nil)
	// applyCoverConfigBundle filters unknowns, so the atomic stays empty.
	bundle := &CoverConfigBundle{Version: 1, FingerprintPool: []FingerprintEntry{{ID: "unknown_one", Weight: 1}, {ID: "fictional_900", Weight: 1}}}
	c.applyCoverConfigBundle(bundle)
	got := c.pickFingerprint()
	if got.Client == "" {
		t.Fatalf("pickFingerprint returned empty HelloID after unknown-only pool: %+v", got)
	}
}

// TestApplyCoverConfigBundleStoresFingerprintPool verifies that
// applyCoverConfigBundle filters known fingerprints into the atomic
// pointer and excludes unknowns.
func TestApplyCoverConfigBundleStoresFingerprintPool(t *testing.T) {
	c := &Client{config: ClientConfig{Fingerprint: "chrome"}}
	c.fingerprintChooser = newFingerprintRotator("chrome", nil)
	bundle := &CoverConfigBundle{
		Version: 1,
		FingerprintPool: []FingerprintEntry{
			{ID: "chrome_auto", Weight: 5},
			{ID: "fictional_900", Weight: 1},
			{ID: "firefox_120", Weight: 3},
		},
	}
	c.applyCoverConfigBundle(bundle)
	got := c.serverPushedFingerprintPool.Load()
	if got == nil {
		t.Fatal("fingerprint pool not stored")
	}
	ids := make(map[string]int, len(*got))
	for _, e := range *got {
		ids[e.ID] = e.Weight
	}
	if ids["chrome_auto"] != 5 || ids["firefox_120"] != 3 {
		t.Fatalf("unexpected pool entries: %v", ids)
	}
	if _, present := ids["fictional_900"]; present {
		t.Fatalf("unknown fingerprint id leaked into pool: %v", ids)
	}
}

// TestBundleCacheReplaySeedsPools verifies that NewClient picks up an
// on-disk bundle and seeds the in-memory pools without doing a network
// fetch.
func TestBundleCacheReplaySeedsPools(t *testing.T) {
	dir := t.TempDir()
	master := shortIDFromHex(t, "0001020304050607")
	cache := bundlecache.New(dir)
	body := []byte(`{"version":1,"sni_pool":[{"sni":"yandex.ru","weight":100}],"fingerprint_pool":[{"id":"chrome_auto","weight":1}]}`)
	if err := cache.Save(bundlecache.Key{Host: "127.0.0.1", ShortID: master}, body, `"v1"`); err != nil {
		t.Fatalf("Save: %v", err)
	}

	pubKey := bytes.Repeat([]byte{0x01}, 32)
	cfg := ClientConfig{
		ServerAddr:             "127.0.0.1:8443",
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              pubKey,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		BundleCacheDir:         dir,
		BundleEnabled:          true,
		BundleEnabledSet:       true,
		DisableDefaultSecurity: true,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	pushed := client.serverPushedSNIPool.Load()
	if pushed == nil || len(*pushed) == 0 || (*pushed)[0].SNI != "yandex.ru" {
		t.Fatalf("on-disk bundle did not seed SNI pool: %v", pushed)
	}
	fp := client.serverPushedFingerprintPool.Load()
	if fp == nil || len(*fp) != 1 || (*fp)[0].ID != "chrome_auto" {
		t.Fatalf("on-disk bundle did not seed fingerprint pool: %v", fp)
	}
}

// TestBundleCacheReplaySkipsExpired verifies that an expired bundle
// (expires_at in the past) does NOT seed pools but still loads ETag for
// conditional refresh.
func TestBundleCacheReplaySkipsExpired(t *testing.T) {
	dir := t.TempDir()
	master := shortIDFromHex(t, "0001020304050607")
	cache := bundlecache.New(dir)
	// Use 1 (way in the past) for expires_at.
	body := []byte(`{"version":1,"ttl_seconds":3600,"expires_at":1,"sni_pool":[{"sni":"yandex.ru","weight":100}]}`)
	if err := cache.Save(bundlecache.Key{Host: "127.0.0.1", ShortID: master}, body, `"vexpired"`); err != nil {
		t.Fatalf("Save: %v", err)
	}

	pubKey := bytes.Repeat([]byte{0x01}, 32)
	client, err := NewClient(ClientConfig{
		ServerAddr:             "127.0.0.1:8443",
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              pubKey,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		BundleCacheDir:         dir,
		BundleEnabled:          true,
		BundleEnabledSet:       true,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	pushed := client.serverPushedSNIPool.Load()
	if pushed != nil && len(*pushed) > 0 {
		t.Fatalf("expired bundle leaked into SNI pool: %v", pushed)
	}
	if etagPtr := client.bundleETag.Load(); etagPtr == nil || *etagPtr != `"vexpired"` {
		t.Fatalf("ETag not preserved across expired-bundle load: %v", etagPtr)
	}
}

// TestFetchAndApplyBundleSendsIfNoneMatch verifies that the client
// includes If-None-Match in the bundle CONNECT when an ETag is cached.
func TestFetchAndApplyBundleSendsIfNoneMatch(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	var sawIfNoneMatch atomic.Bool
	tr := &h2Transport{
		serverAddr: "server.example:443",
		h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("If-None-Match") == `"cached"` {
				sawIfNoneMatch.Store(true)
				return &http.Response{StatusCode: http.StatusNotModified, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"version":1}`))}, nil
		}),
	}
	c := &Client{config: ClientConfig{MasterShortID: master, PrimarySNI: "ok.ru", ServerName: "ok.ru"}}
	etag := `"cached"`
	c.bundleETag.Store(&etag)
	if err := c.fetchAndApplyBundle(context.Background(), tr); err != nil {
		t.Fatalf("fetchAndApplyBundle: %v", err)
	}
	if !sawIfNoneMatch.Load() {
		t.Fatal("client did not send If-None-Match header")
	}
}

// TestFetchAndApplyBundlePersistsToCache verifies the body+ETag landed on
// disk after a successful fetch.
func TestFetchAndApplyBundlePersistsToCache(t *testing.T) {
	dir := t.TempDir()
	master := shortIDFromHex(t, "0001020304050607")
	body := `{"version":1,"sni_pool":[{"sni":"vk.com","weight":1000}]}`
	tr := &h2Transport{
		serverAddr: "server.example:443",
		h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Etag": []string{`"v2"`}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}),
	}
	c := &Client{
		config: ClientConfig{
			ServerAddr:    "server.example:443",
			MasterShortID: master,
			PrimarySNI:    "ok.ru",
			ServerName:    "ok.ru",
			BundleEnabled: true,
		},
	}
	c.bundleCache = bundlecache.New(dir)
	if err := c.fetchAndApplyBundle(context.Background(), tr); err != nil {
		t.Fatalf("fetchAndApplyBundle: %v", err)
	}
	got, gotEtag, err := c.bundleCache.Load(bundlecache.Key{Host: "server.example", ShortID: master})
	if err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	if string(got) != body {
		t.Fatalf("cached body = %q, want %q", got, body)
	}
	if gotEtag != `"v2"` {
		t.Fatalf("cached etag = %q, want \"v2\"", gotEtag)
	}
	// And in-memory ETag pointer is set so next fetch sends If-None-Match.
	if etagPtr := c.bundleETag.Load(); etagPtr == nil || *etagPtr != `"v2"` {
		t.Fatalf("in-memory ETag not stored: %v", etagPtr)
	}
}

// TestBundleCacheHostKeyStripsPort verifies that the cache key drops the
// port so two ports on the same host share one slot.
func TestBundleCacheHostKeyStripsPort(t *testing.T) {
	if got := bundleCacheHostKey("ya.ru:443"); got != "ya.ru" {
		t.Fatalf("bundleCacheHostKey = %q, want ya.ru", got)
	}
	if got := bundleCacheHostKey("invalid-no-port"); got != "invalid-no-port" {
		t.Fatalf("malformed addr = %q", got)
	}
}

// TestNewClientCreatesCacheLazyEnsureDir ensures BundleCacheDir is
// honoured even when the directory does not exist yet.
func TestNewClientCreatesCacheLazyEnsureDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "missing")
	master := shortIDFromHex(t, "0001020304050607")
	pubKey := bytes.Repeat([]byte{0x01}, 32)
	c, err := NewClient(ClientConfig{
		ServerAddr:             "127.0.0.1:443",
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              pubKey,
		MasterShortID:          master,
		BundleCacheDir:         dir,
		BundleEnabled:          true,
		BundleEnabledSet:       true,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if c.bundleCache == nil || !c.bundleCache.Enabled() {
		t.Fatalf("cache not enabled despite BundleCacheDir set")
	}
}
