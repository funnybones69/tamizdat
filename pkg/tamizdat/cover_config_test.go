package tamizdat

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCoverConfigTestFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadCoverConfigValid(t *testing.T) {
	// Shortid full-B simplification (2026-05-09): epoch_key + shortid_pool_size
	// fields are tolerated in on-disk bundles for backward-compat (encoding/json
	// silently ignores unknown fields). Only sni_pool/cover_targets/gaps are
	// modelled and used now.
	path := writeCoverConfigTestFile(t, `{
		"version":1,
		"epoch_key":"ep-2026-05-01-rotated",
		"shortid_pool_size":100,
		"sni_pool":[{"sni":"yandex.ru","weight":100},{"sni":"vk.com","weight":90}],
		"cover_targets":["mc.yandex.ru:443","an.yandex.ru:443"],
		"cover_gap_min_ms":30000,
		"cover_gap_max_ms":90000
	}`)
	bundle, err := LoadCoverConfigWithMasquerade(path, map[string]string{"yandex.ru": "yandex.ru", "vk.com": "vk.com"})
	if err != nil {
		t.Fatalf("LoadCoverConfigWithMasquerade: %v", err)
	}
	if bundle.Version != 1 {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
	if len(bundle.SNIPool) != 2 || len(bundle.CoverTargets) != 2 {
		t.Fatalf("pool lengths: sni=%d cover=%d", len(bundle.SNIPool), len(bundle.CoverTargets))
	}
}

func TestLoadCoverConfigInvalid(t *testing.T) {
	cases := map[string]struct {
		body     string
		pathOnly string
		masq     map[string]string
	}{
		"empty file":                     {body: ""},
		"file-not-found":                 {pathOnly: filepath.Join(t.TempDir(), "missing.json")},
		"JSON-parse-error":               {body: `{"version":`},
		"version!=1":                     {body: `{"version":2}`},
		"missing-required-field":         {body: `{}`},
		"sni-not-in-masq-pool":           {body: `{"version":1,"sni_pool":[{"sni":"vk.com","weight":1}]}`, masq: map[string]string{"ok.ru": "ok.ru"}},
		"cover-target-bad-port":          {body: `{"version":1,"cover_targets":["mc.yandex.ru:70000"]}`},
		"cover-gap-min-greater-than-max": {body: `{"version":1,"cover_gap_min_ms":90000,"cover_gap_max_ms":30000}`},
		// Shortid full-B simplification (2026-05-09): epoch_key + shortid_pool_size
		// validation cases removed — fields no longer modelled, parser silently
		// drops them via encoding/json's default unknown-field behaviour.
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := tc.pathOnly
			if path == "" {
				path = writeCoverConfigTestFile(t, tc.body)
			}
			if tc.masq == nil {
				tc.masq = map[string]string{"vk.com": "vk.com", "ok.ru": "ok.ru"}
			}
			if _, err := LoadCoverConfigWithMasquerade(path, tc.masq); err == nil {
				t.Fatalf("LoadCoverConfigWithMasquerade succeeded for %s", name)
			}
		})
	}
}

func TestLoadCoverConfigBackwardCompatTolerantOfLegacyFields(t *testing.T) {
	// Shortid full-B simplification (2026-05-09): old on-disk bundles may still
	// carry the deprecated epoch_key / shortid_pool_size JSON fields. The
	// parser must accept them silently (encoding/json default behaviour).
	path := writeCoverConfigTestFile(t, `{"version":1,"epoch_key":"ep-old","shortid_pool_size":100}`)
	bundle, err := LoadCoverConfig(path)
	if err != nil {
		t.Fatalf("LoadCoverConfig: %v", err)
	}
	if bundle.Version != 1 {
		t.Fatalf("bundle.Version = %d, want 1", bundle.Version)
	}
}

func TestBundleSizeCapServerSide(t *testing.T) {
	path := writeCoverConfigTestFile(t, strings.Repeat(" ", MaxCoverConfigBundleBytes+1))
	if _, err := LoadCoverConfig(path); err == nil {
		t.Fatal("oversized bundle accepted")
	}
}

func TestBundleVersionUnknown(t *testing.T) {
	path := writeCoverConfigTestFile(t, `{"version":99}`)
	if _, err := LoadCoverConfig(path); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestServerCoverConfigCachesBundleJSON(t *testing.T) {
	// Shortid full-B simplification (2026-05-09): server no longer derives a
	// shortid pool from epoch_key. The bundle's legacy fields (epoch_key,
	// shortid_pool_size) are tolerated for backward-compat with on-disk
	// bundles but ignored by the server. This test verifies the JSON is
	// cached intact for client distribution and the bundle is still parsed.
	master := shortIDFromHex(t, "0001020304050607")
	path := writeCoverConfigTestFile(t, `{"version":1,"epoch_key":"ep-current","shortid_pool_size":4}`)
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	server, err := NewServer(ServerConfig{
		PrivateKey:      priv,
		MasterShortID:   master,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		CoverConfigPath: path,
		Handler:         func(ctx context.Context, conn net.Conn, destination string) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if string(server.coverConfigJSON) == "" {
		t.Fatalf("coverConfigJSON not cached: %q", string(server.coverConfigJSON))
	}
}

func TestCoverConfigJSONRoundTrip(t *testing.T) {
	// Shortid full-B simplification (2026-05-09): epoch_key + shortid_pool_size
	// fields removed from CoverConfigBundle struct; the marshalled JSON must no
	// longer carry them.
	bundle := CoverConfigBundle{Version: 1, CoverTargets: []string{"mc.yandex.ru:443"}}
	buf, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(buf), "epoch_key") || strings.Contains(string(buf), "shortid_pool_size") {
		t.Fatalf("legacy fields leaked into marshalled bundle: %s", buf)
	}
	if !strings.Contains(string(buf), `"version":1`) {
		t.Fatalf("missing version field: %s", buf)
	}
}

func TestBundleETagStableAcrossExpiryRewrites(t *testing.T) {
	// Server-pushes-pool (2026-05-09): expires_at must be excluded from the
	// ETag hash so the same bundle re-marshalled with a fresh expires_at
	// stays cache-coherent for clients that did a HEAD If-None-Match probe.
	bundle := CoverConfigBundle{
		Version:    1,
		TTLSeconds: 3600,
		ExpiresAt:  1700000000,
		SNIPool:    []SNIEntry{{SNI: "yandex.ru", Weight: 100}},
	}
	tag1 := bundle.ETag()
	bundle.ExpiresAt = 1700009999
	tag2 := bundle.ETag()
	if tag1 == "" || tag1 != tag2 {
		t.Fatalf("ETag changed across expires_at update: %q vs %q", tag1, tag2)
	}
	bundle.SNIPool = append(bundle.SNIPool, SNIEntry{SNI: "vk.com", Weight: 90})
	tag3 := bundle.ETag()
	if tag3 == tag1 {
		t.Fatalf("ETag unchanged after pool edit: %q", tag3)
	}
}

func TestBundleMarshalForWireWithExpiry(t *testing.T) {
	// MarshalForWireWithExpiry must inject expires_at = now+ttl when ttl>0
	// and leave the static fields untouched.
	bundle := CoverConfigBundle{Version: 1, TTLSeconds: 60, SNIPool: []SNIEntry{{SNI: "ok.ru", Weight: 100}}}
	now := time.Unix(1700000000, 0)
	wire, err := bundle.MarshalForWireWithExpiry(now)
	if err != nil {
		t.Fatalf("MarshalForWireWithExpiry: %v", err)
	}
	var got CoverConfigBundle
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	if got.ExpiresAt != now.Add(60*time.Second).Unix() {
		t.Fatalf("expires_at = %d, want %d", got.ExpiresAt, now.Add(60*time.Second).Unix())
	}
	if got.TTLSeconds != 60 {
		t.Fatalf("ttl_seconds = %d, want 60", got.TTLSeconds)
	}
	// Original bundle struct unchanged.
	if bundle.ExpiresAt != 0 {
		t.Fatalf("source bundle ExpiresAt mutated: %d", bundle.ExpiresAt)
	}
}

func TestBundleValidateFingerprintPool(t *testing.T) {
	bundle := CoverConfigBundle{
		Version:         1,
		FingerprintPool: []FingerprintEntry{{ID: "chrome_auto", Weight: 5}, {ID: "chrome_131", Weight: 3}},
	}
	if err := bundle.Validate(nil, false); err != nil {
		t.Fatalf("valid fingerprint_pool rejected: %v", err)
	}
	bundle.FingerprintPool = []FingerprintEntry{{ID: "", Weight: 1}}
	if err := bundle.Validate(nil, false); err == nil {
		t.Fatal("empty fingerprint id accepted")
	}
	bundle.FingerprintPool = []FingerprintEntry{{ID: "chrome_120", Weight: -1}}
	if err := bundle.Validate(nil, false); err == nil {
		t.Fatal("negative weight accepted")
	}
}

func TestBundleValidateTTLBounds(t *testing.T) {
	bundle := CoverConfigBundle{Version: 1, TTLSeconds: -1}
	if err := bundle.Validate(nil, false); err == nil {
		t.Fatal("negative ttl_seconds accepted")
	}
	bundle.TTLSeconds = 86401
	if err := bundle.Validate(nil, false); err == nil {
		t.Fatal("ttl_seconds > 86400 accepted")
	}
	bundle.TTLSeconds = 3600
	if err := bundle.Validate(nil, false); err != nil {
		t.Fatalf("ttl_seconds=3600 rejected: %v", err)
	}
}
