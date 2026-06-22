package node

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGeoIP / fakeGeoSite produce minimal but parser-valid .dat content.
// Reusing the unexported writeTestDat helpers from geo_dat_test.go keeps
// the byte format aligned with what the runtime parser expects.
func fakeGeoIPDat() []byte {
	return testGeoIPList(testGeoIP("telegram", testCIDR("149.154.160.0", 20)))
}

func fakeGeoSiteDat() []byte {
	return testGeoSiteList(testGeoSite("openai", testDomainRule(3, "openai.com")))
}

// captureLogger collects log lines for assertion. Always thread-safe.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureLogger) Logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *captureLogger) Snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

func anyLineContains(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// fakeAssetServer serves geoip.dat / geosite.dat. Tracks counts of HEAD
// and GET requests so tests can assert no-update means no GET, etc.
// Optional Last-Modified header lets tests simulate "upstream is newer".
type fakeAssetServer struct {
	geoip   []byte
	geosite []byte

	mu           sync.Mutex
	lastModified time.Time
	headCount    atomic.Int64
	getCount     atomic.Int64
	failOnce     atomic.Bool // when true, next GET returns 500 then auto-resets
}

func (f *fakeAssetServer) setLastModified(t time.Time) {
	f.mu.Lock()
	f.lastModified = t
	f.mu.Unlock()
}

func (f *fakeAssetServer) lm() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastModified
}

func (f *fakeAssetServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "geoip.dat"):
			body = f.geoip
		case strings.HasSuffix(r.URL.Path, "geosite.dat"):
			body = f.geosite
		default:
			http.NotFound(w, r)
			return
		}
		if lm := f.lm(); !lm.IsZero() {
			w.Header().Set("Last-Modified", lm.UTC().Format(http.TimeFormat))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		switch r.Method {
		case http.MethodHead:
			f.headCount.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		case http.MethodGet:
			f.getCount.Add(1)
			if f.failOnce.Swap(false) {
				http.Error(w, "kaboom", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
}

func newFakeAssetServer(t *testing.T) (*fakeAssetServer, *httptest.Server) {
	t.Helper()
	f := &fakeAssetServer{
		geoip:   fakeGeoIPDat(),
		geosite: fakeGeoSiteDat(),
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv
}

func TestGeoDataUpdaterDownloadsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1, // no periodic loop
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}

	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s to be downloaded: %v", path, err)
		}
		if st.Size() == 0 {
			t.Fatalf("downloaded %s is empty", path)
		}
	}
	if got := f.getCount.Load(); got != 2 {
		t.Fatalf("expected 2 GETs (one per file), got %d", got)
	}
}

func TestGeoDataUpdaterSkipsGetWhenLastModifiedNotNewer(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	// Pre-populate target with stable content; set its mtime to "now" so
	// the server's Last-Modified ("a minute ago") is OLDER, meaning no
	// download should occur.
	geoipPath := filepath.Join(dir, "geoip.dat")
	geositePath := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(geoipPath, fakeGeoIPDat(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geositePath, fakeGeoSiteDat(), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(geoipPath, now, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(geositePath, now, now); err != nil {
		t.Fatal(err)
	}
	f.setLastModified(now.Add(-1 * time.Minute))

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if got := f.getCount.Load(); got != 0 {
		t.Fatalf("expected 0 GETs (Last-Modified is older), got %d", got)
	}
	if got := f.headCount.Load(); got < 2 {
		t.Fatalf("expected at least 2 HEADs, got %d", got)
	}
	if !anyLineContains(logger.Snapshot(), "up-to-date") {
		t.Fatalf("expected 'up-to-date' log line; got %v", logger.Snapshot())
	}
}

func TestGeoDataUpdaterRefreshesWhenUpstreamNewer(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	geoipPath := filepath.Join(dir, "geoip.dat")
	geositePath := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(geoipPath, fakeGeoIPDat(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geositePath, fakeGeoSiteDat(), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(geoipPath, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(geositePath, old, old); err != nil {
		t.Fatal(err)
	}
	f.setLastModified(time.Now()) // upstream is "now", local is 2h old

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := f.getCount.Load(); got != 2 {
		t.Fatalf("expected 2 GETs (upstream newer), got %d", got)
	}
}

func TestGeoDataUpdaterPreservesOldFileOnDownloadFailure(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	// Pre-populate. The server is configured to fail the next GET; the old
	// file content + mtime must survive untouched.
	geoipPath := filepath.Join(dir, "geoip.dat")
	original := []byte("OLD-PLACEHOLDER-DO-NOT-DELETE")
	if err := os.WriteFile(geoipPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(geoipPath, old, old)
	f.setLastModified(time.Now())
	f.failOnce.Store(true)

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     "", // skip geosite for this test
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got, err := os.ReadFile(geoipPath)
	if err != nil {
		t.Fatalf("read geoip.dat: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("old file was overwritten on failed download: %q", got)
	}
	// .tmp must be cleaned up
	if _, err := os.Stat(geoipPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected .tmp removed; stat err=%v", err)
	}
	if !anyLineContains(logger.Snapshot(), "refresh failed") {
		t.Fatalf("expected 'refresh failed' warning; got %v", logger.Snapshot())
	}
}

func TestGeoDataUpdaterPreservesOldFileOnValidationFailure(t *testing.T) {
	dir := t.TempDir()
	logger := &captureLogger{}

	// Custom server that returns junk content (will fail protobuf parse).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not a valid protobuf at all just plain text"))
		}
	}))
	t.Cleanup(srv.Close)

	geoipPath := filepath.Join(dir, "geoip.dat")
	original := fakeGeoIPDat()
	if err := os.WriteFile(geoipPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(geoipPath, old, old)

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     "",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got, err := os.ReadFile(geoipPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(original) {
		t.Fatal("old geoip.dat was overwritten despite validation failure")
	}
	if _, err := os.Stat(geoipPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected .tmp removed on validation failure; stat err=%v", err)
	}
}

func TestGeoDataUpdaterOnRefreshHookFires(t *testing.T) {
	dir := t.TempDir()
	_, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	var seen []string
	var mu sync.Mutex
	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
		OnRefresh: func(p string) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, filepath.Base(p))
		},
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected 2 OnRefresh calls, got %d (%v)", len(seen), seen)
	}
}

func TestGeoDataUpdaterRefreshNowReloadsOnDemand(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := f.getCount.Load()
	if first != 2 {
		t.Fatalf("startup pass should GET both files, got %d", first)
	}

	// Bump server's Last-Modified beyond local mtime so RefreshNow re-fetches.
	f.setLastModified(time.Now().Add(1 * time.Minute))
	// Set local mtime back so we definitely see "remote newer".
	old := time.Now().Add(-1 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, "geoip.dat"), old, old)
	_ = os.Chtimes(filepath.Join(dir, "geosite.dat"), old, old)

	if err := u.RefreshNow(context.Background()); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}
	if got := f.getCount.Load(); got != first+2 {
		t.Fatalf("RefreshNow should issue 2 fresh GETs, got total %d (was %d)", got, first)
	}
}

func TestGeoDataUpdaterDoubleStartReturnsError(t *testing.T) {
	dir := t.TempDir()
	_, srv := newFakeAssetServer(t)
	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         func(string, ...any) {},
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := u.Start(context.Background()); err == nil {
		t.Fatal("second Start should fail")
	}
}

func TestGeoDataUpdaterPeriodicLoopRefreshes(t *testing.T) {
	dir := t.TempDir()
	f, srv := newFakeAssetServer(t)
	logger := &captureLogger{}

	// Local files exist with mtime in the past; server's Last-Modified is
	// "now", so every tick will re-download.
	geoipPath := filepath.Join(dir, "geoip.dat")
	geositePath := filepath.Join(dir, "geosite.dat")
	_ = os.WriteFile(geoipPath, fakeGeoIPDat(), 0o644)
	_ = os.WriteFile(geositePath, fakeGeoSiteDat(), 0o644)
	old := time.Now().Add(-1 * time.Hour)
	_ = os.Chtimes(geoipPath, old, old)
	_ = os.Chtimes(geositePath, old, old)
	f.setLastModified(time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     srv.URL + "/geosite.dat",
		UpdateInterval: 50 * time.Millisecond,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Startup pass = 2 GETs; one tick = 2 more. Wait for >=4.
		if f.getCount.Load() >= 4 {
			break
		}
		// Bump LastModified each iteration so HEAD continues to return
		// "newer-than-local" (we advance the file mtime back too via
		// rename — actually rename preserves mtime from the response.
		// Simpler: just keep incrementing server LM faster than ticker).
		f.setLastModified(time.Now())
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if got := f.getCount.Load(); got < 4 {
		t.Fatalf("periodic loop should have refreshed at least once after startup; total GETs=%d", got)
	}
}

func TestGeoDataUpdaterEmptyResponseFails(t *testing.T) {
	dir := t.TempDir()
	logger := &captureLogger{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// no body — len(data) == 0 path
	}))
	t.Cleanup(srv.Close)

	u := &GeoDataUpdater{
		Dir:            dir,
		GeoIPURL:       srv.URL + "/geoip.dat",
		GeoSiteURL:     "",
		UpdateInterval: -1,
		HTTPClient:     srv.Client(),
		Logger:         logger.Logf,
	}
	if err := u.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Server boot does NOT fail on download error.
	if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); !os.IsNotExist(err) {
		t.Fatalf("expected no geoip.dat written from empty response; stat err=%v", err)
	}
	if !anyLineContains(logger.Snapshot(), "refresh failed") {
		t.Fatalf("expected 'refresh failed' log line; got %v", logger.Snapshot())
	}
}
