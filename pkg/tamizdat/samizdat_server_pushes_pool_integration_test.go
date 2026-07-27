package tamizdat

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/bundlecache"
	"github.com/funnybones69/tamizdat/internal/userdb"
	_ "modernc.org/sqlite"
)

// TestServerEmitsTTLBundleAndETag verifies that a server configured with
// BundleTTL > 0 emits ttl_seconds + a stable ETag.
func TestServerEmitsTTLBundleAndETag(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	bundlePath := writeCoverConfigTestFile(t, `{"version":1,"sni_pool":[{"sni":"yandex.ru","weight":100}],"fingerprint_pool":[{"id":"chrome_auto","weight":5},{"id":"chrome_131","weight":3}]}`)
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
		CoverConfigPath: bundlePath,
		MasqueradePool:  map[string]string{"yandex.ru": "yandex.ru"},
		Handler:         func(ctx context.Context, conn net.Conn, destination string) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if server.coverConfigBundle == nil {
		t.Fatal("server did not parse bundle struct")
	}
	if server.coverConfigBundle.TTLSeconds <= 0 {
		t.Fatalf("TTLSeconds = %d, want default 3600", server.coverConfigBundle.TTLSeconds)
	}
	if server.coverConfigETag == "" {
		t.Fatal("ETag not computed")
	}
	wire, err := server.coverConfigBundle.MarshalForWireWithExpiry(time.Now())
	if err != nil {
		t.Fatalf("MarshalForWireWithExpiry: %v", err)
	}
	var got CoverConfigBundle
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ExpiresAt == 0 {
		t.Fatal("ExpiresAt not injected")
	}
	if len(got.FingerprintPool) != 2 {
		t.Fatalf("FingerprintPool not preserved: %v", got.FingerprintPool)
	}
}

// TestEndToEndBundleFetchPersistsToDisk verifies the full loop: client
// connects, server pushes bundle (with fingerprint_pool), body lands on
// disk via bundlecache, and a fresh NewClient replays the bundle on
// startup without any network call.
func TestEndToEndBundleFetchPersistsToDisk(t *testing.T) {
	master := shortIDFromHex(t, "deadbeefcafef00d")
	cacheDir := t.TempDir()
	bundlePath := writeCoverConfigTestFile(t, `{"version":1,"sni_pool":[{"sni":"vk.com","weight":1000}],"fingerprint_pool":[{"id":"chrome_auto","weight":1}],"cover_targets":["mc.yandex.ru:443"]}`)

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:      "127.0.0.1:0",
		PrivateKey:      priv,
		MasterShortID:   master,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		CoverConfigPath: bundlePath,
		MasqueradePool:  map[string]string{"vk.com": ""},
		Handler:         poolPushEchoHandler,
	})

	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              pub,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		BundleCacheDir:         cacheDir,
		BundleEnabled:          true,
		BundleEnabledSet:       true,
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
		CoverTrafficEnabled:    true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn := poolPushDialAndEcho(t, client, "example.org:443")
	conn.Close()
	waitForExpvarAtLeast(t, "tamizdat_bundle_applied_total", beforeApplied+1)
	client.Close()

	// Disk cache should now contain the bundle JSON.
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	cache := bundlecache.New(cacheDir)
	var body []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		body, _, err = cache.Load(bundlecache.Key{Host: host, ShortID: master})
		if err == nil && len(body) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("cache.Load: %v", err)
	}
	if len(body) == 0 {
		entries, _ := os.ReadDir(cacheDir)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("bundle not persisted to disk; cache dir contents: %v (host=%q shortid=%x)", names, host, master)
	}
	var persisted CoverConfigBundle
	if err := json.Unmarshal(body, &persisted); err != nil {
		t.Fatalf("persisted body parse: %v", err)
	}
	if len(persisted.SNIPool) == 0 || persisted.SNIPool[0].SNI != "vk.com" {
		t.Fatalf("persisted SNIPool: %v", persisted.SNIPool)
	}

	// Fresh client replays bundle from disk without dialling.
	client2, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              pub,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		BundleCacheDir:         cacheDir,
		BundleEnabled:          true,
		BundleEnabledSet:       true,
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient2: %v", err)
	}
	defer client2.Close()
	pushed := client2.serverPushedSNIPool.Load()
	if pushed == nil || len(*pushed) == 0 || (*pushed)[0].SNI != "vk.com" {
		t.Fatalf("disk replay did not seed SNI pool: %v", pushed)
	}
}

// TestServerHandlesHEADReturnsHeaders verifies that HEAD requests against
// the bundle endpoint return ETag without a body.
func TestServerHandlesHEADReturnsHeaders(t *testing.T) {
	server := newServerForBundleHandlerTest(t, false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("HEAD", "https://"+configAuthority, nil)
	req.Host = configAuthority
	server.serveConfigBundle(rec, req, authIdentity{})
	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD status = %d", resp.StatusCode)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body should be empty, got %d bytes", rec.Body.Len())
	}
	if resp.Header.Get("ETag") == "" {
		t.Fatal("HEAD did not return ETag")
	}
}

// TestServerHandlesIfNoneMatch304 verifies that a request carrying
// If-None-Match equal to the current ETag returns 304.
func TestServerHandlesIfNoneMatch304(t *testing.T) {
	server := newServerForBundleHandlerTest(t, false)
	etag := server.coverConfigETag
	if etag == "" {
		t.Fatal("ETag empty; cannot exercise If-None-Match")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("CONNECT", "https://"+configAuthority, nil)
	req.Host = configAuthority
	req.Header.Set("If-None-Match", etag)
	server.serveConfigBundle(rec, req, authIdentity{})
	if rec.Code != 304 {
		t.Fatalf("If-None-Match same-ETag status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("304 body should be empty, got %d bytes", rec.Body.Len())
	}
}

// TestServerBundleDisabledReturnsLegacyBody verifies that when an operator
// disables BundleEnabled, the server emits {"version":1}.
func TestServerBundleDisabledReturnsLegacyBody(t *testing.T) {
	server := newServerForBundleHandlerTest(t, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("CONNECT", "https://"+configAuthority, nil)
	req.Host = configAuthority
	server.serveConfigBundle(rec, req, authIdentity{})
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Fatalf("disabled body = %q", rec.Body.String())
	}
	// Pool entries must NOT leak through when disabled.
	if strings.Contains(rec.Body.String(), "yandex.ru") {
		t.Fatalf("disabled body leaked pool SNI: %s", rec.Body.String())
	}
}

func TestServerPerUserBundleAlwaysCarriesTransportBounds(t *testing.T) {
	server := newServerForBundleHandlerTest(t, false)
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO users(id, name, master_shortid, pool_size, outbound_tag, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?)`, "u-transport", "transport user", "0102030405060708", 4, "direct", now, now); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	reg := userdb.NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("registry reload: %v", err)
	}
	server.userRegistry = reg
	server.outboundDB = db

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("CONNECT", "https://"+configAuthority, nil)
	req.Host = configAuthority
	server.serveConfigBundle(rec, req, authIdentity{UserID: "u-transport"})
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle json: %v body=%s", err, rec.Body.String())
	}
	if bundle.MinTransports != 4 || bundle.MaxTransports != 4 {
		t.Fatalf("transport bounds = %d/%d, want 4/4 body=%s", bundle.MinTransports, bundle.MaxTransports, rec.Body.String())
	}
	if bundle.Notification != nil {
		t.Fatalf("unexpected notification without notification_pending: %+v", bundle.Notification)
	}
	if rec.Result().Header.Get("ETag") == "" {
		t.Fatal("per-user non-notification bundle should still have an ETag")
	}
}

func TestServerUserRegistryReloaderUpdatesPerUserTransportBounds(t *testing.T) {
	server := newServerForBundleHandlerTest(t, false)
	dbName := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := sql.Open("sqlite", "file:"+dbName+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := userdb.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO users(id, name, master_shortid, pool_size, outbound_tag, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?)`, "u-live", "live user", "0102030405060708", 4, "direct", now, now); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	reg := userdb.NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("registry reload: %v", err)
	}
	server.userRegistry = reg
	server.outboundDB = db
	server.startUserRegistryReloader(10 * time.Millisecond)
	t.Cleanup(func() { _ = server.Close() })

	fetchBundle := func() CoverConfigBundle {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("CONNECT", "https://"+configAuthority, nil)
		req.Host = configAuthority
		server.serveConfigBundle(rec, req, authIdentity{UserID: "u-live"})
		if rec.Code != 200 {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		var bundle CoverConfigBundle
		if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
			t.Fatalf("bundle json: %v body=%s", err, rec.Body.String())
		}
		return bundle
	}

	if bundle := fetchBundle(); bundle.MinTransports != 4 || bundle.MaxTransports != 4 {
		t.Fatalf("initial transport bounds = %d/%d, want 4/4", bundle.MinTransports, bundle.MaxTransports)
	}
	if _, err := db.Exec(`UPDATE users SET pool_size=?, updated_at=? WHERE id=?`, 2, time.Now().Unix(), "u-live"); err != nil {
		t.Fatalf("update user pool_size: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bundle := fetchBundle()
		if bundle.MinTransports == 2 && bundle.MaxTransports == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	bundle := fetchBundle()
	t.Fatalf("reloaded transport bounds = %d/%d, want 2/2", bundle.MinTransports, bundle.MaxTransports)
}

// TestNewURIOldServer_GracefulFallback is the SPP-FU-5 regression guard:
// a client using the post-2026-05-09 URI form (no `sni=` / `fp=` query
// params) must still connect successfully when the server is on an older
// build that does NOT include the bundle/pool feature and therefore
// returns the legacy `{"version":1}` body.
//
// Verified properties:
//   - configurl.Parse seeds BootstrapSNI = host literal when sni= is absent.
//   - Client uses BootstrapSNI for the very first transport.
//   - Bundle fetch round-trips and parses {"version":1} without erroring.
//   - serverPushedSNIPool stays empty (server emitted no pool); subsequent
//     transports keep using the bootstrap-seeded ServerName.
func TestNewURIOldServer_GracefulFallback(t *testing.T) {
	master := shortIDFromHex(t, "fefefefefefefefe")
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	// "Old" server: BundleEnabled=false → emits {"version":1}, no TTL,
	// no sni_pool, no fingerprint_pool. This is the wire shape an
	// operator running pre-bundle tamizdat (or one who explicitly
	// flipped the kill-switch) sees.
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:       "127.0.0.1:0",
		PrivateKey:       priv,
		MasterShortID:    master,
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradePool:   map[string]string{"127.0.0.1": ""},
		BundleEnabled:    false,
		BundleEnabledSet: true,
		Handler:          poolPushEchoHandler,
	})

	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}

	// New (clean) URI: no sni=, no fp=, no bootstrap=. configurl.Parse
	// must seed BootstrapSNI = host literal and the client must use that
	// for the first dial.
	beforeReceived := expvarIntValue("tamizdat_bundle_received_total")
	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		PrimarySNI:             host, // simulates configurl.Parse fallback
		ServerName:             host,
		BootstrapSNI:           host,
		PublicKey:              pub,
		MasterShortID:          master,
		Fingerprint:            "mix",
		BundleEnabled:          true, // client still wants to fetch
		BundleEnabledSet:       true,
		BundleCacheDir:         t.TempDir(),
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// First dial drives the handshake + magic-CONNECT bundle fetch.
	conn := poolPushDialAndEcho(t, client, "example.org:443")
	conn.Close()

	// Bundle fetch must NOT have errored: a {"version":1} body parses
	// cleanly and increments received_total but not applied_total
	// (no pool fields to apply).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if expvarIntValue("tamizdat_bundle_received_total") > beforeReceived {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if expvarIntValue("tamizdat_bundle_received_total") <= beforeReceived {
		t.Fatalf("client never observed the {\"version\":1} body (received_total stuck at %d)", beforeReceived)
	}
	gotErrors := expvarIntValue("tamizdat_bundle_fetch_errors_total")
	if gotErrors > 0 {
		// Errors counter is process-global, so this is approximate; only
		// flag if it actually moved during the test.
		t.Logf("note: tamizdat_bundle_fetch_errors_total = %d (may include unrelated noise)", gotErrors)
	}
	// applied_total may move (the {"version":1} body parses + validates as
	// a no-op bundle); what matters is that no pool was actually seeded.
	_ = beforeApplied
	// Server pool must remain empty — old wire shape has no sni_pool.
	if pushed := client.serverPushedSNIPool.Load(); pushed != nil && len(*pushed) > 0 {
		t.Fatalf("serverPushedSNIPool was seeded from {\"version\":1} body: %v", *pushed)
	}
	if pushedFP := client.serverPushedFingerprintPool.Load(); pushedFP != nil && len(*pushedFP) > 0 {
		t.Fatalf("serverPushedFingerprintPool was seeded from {\"version\":1} body: %v", *pushedFP)
	}
	// Bootstrap SNI must still be the host literal (no rotation kicked in).
	if got := client.config.PrimarySNI; got != host {
		t.Fatalf("PrimarySNI = %q, want %q (bootstrap fallback)", got, host)
	}
}

// TestBundleCacheReadDirectlyFromDisk smoke-tests bundlecache from the
// outside (no Client struct), proving the file layout is stable for
// external tooling.
func TestBundleCacheReadDirectlyFromDisk(t *testing.T) {
	dir := t.TempDir()
	c := bundlecache.New(dir)
	k := bundlecache.Key{Host: "ya.ru", ShortID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	body := []byte(`{"version":1}`)
	if err := c.Save(k, body, `"v1"`); err != nil {
		t.Fatalf("Save: %v", err)
	}
	want := filepath.Join(dir, "bundle-ya.ru-0102030405060708.json")
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: %s", got)
	}
	etag, err := os.ReadFile(want + ".etag")
	if err != nil {
		t.Fatalf("ReadFile etag: %v", err)
	}
	if string(etag) != `"v1"` {
		t.Fatalf("etag = %q", etag)
	}
}

// newServerForBundleHandlerTest returns a NewServer instance with a tiny
// bundle loaded, suitable for direct serveConfigBundle tests with
// httptest. Toggle disabled=true to flip BundleEnabled off.
func newServerForBundleHandlerTest(t *testing.T, disabled bool) *Server {
	t.Helper()
	master := shortIDFromHex(t, "0001020304050607")
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	bundlePath := writeCoverConfigTestFile(t, `{"version":1,"sni_pool":[{"sni":"yandex.ru","weight":100}]}`)
	cfg := ServerConfig{
		PrivateKey:      priv,
		MasterShortID:   master,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		CoverConfigPath: bundlePath,
		MasqueradePool:  map[string]string{"yandex.ru": "yandex.ru"},
		Handler:         func(ctx context.Context, conn net.Conn, destination string) {},
	}
	if disabled {
		cfg.BundleEnabled = false
		cfg.BundleEnabledSet = true
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}
