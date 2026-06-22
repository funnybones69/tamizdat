package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Default sources. Loyalsoldier/v2ray-rules-dat is the de-facto-standard
// xray geoip+geosite bundle, which is what 3x-ui ships by default. Operators
// can override either URL via GeoDataUpdater fields (e.g. point at
// runetfreedom/russia-v2ray-rules-dat instead).
const (
	DefaultGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	DefaultGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

	// DefaultGeoDataDir is where downloaded .dat files land. Same path the
	// node Config defaults to so node.LoadGeoDB picks them up automatically.
	DefaultGeoDataDir = "/etc/tamizdat"

	// DefaultGeoDataInterval is the periodic refresh cadence. 7 days mirrors
	// 3x-ui's "weekly auto-update" UX.
	DefaultGeoDataInterval = 7 * 24 * time.Hour

	// downloadTimeout is the per-request HTTP deadline. Loyalsoldier release
	// assets are ~5 MB combined; 5 minutes is generous for slow connections
	// while still bounding hung sockets.
	downloadTimeout = 5 * time.Minute

	// userAgent identifies tamizdat to GitHub. GitHub's release-asset CDN
	// answers anonymous browsers fine, but having a UA lets ops correlate
	// fetches in their proxy logs.
	userAgent = "tamizdat-geodata-updater/1"
)

// validator decides whether a freshly-downloaded .dat blob is structurally
// valid. Returning a non-nil error keeps the existing on-disk file in place
// and the .tmp is deleted.
type validator func(data []byte) error

// GeoDataUpdater downloads + periodically refreshes geoip.dat / geosite.dat
// from a GitHub-style release asset URL. It is safe to construct with the
// zero value plus a Dir; Start applies defaults.
//
// Lifecycle: Start launches one goroutine that owns the ticker and the
// in-flight HTTP requests. Cancelling ctx stops the goroutine; the function
// returned by Start blocks for the goroutine to exit.
//
// Failure policy: a download error is logged at warning level and does NOT
// cause server boot to fail. Existing on-disk files (or the in-tree curated
// shortlist via geoDB.GeoIPCIDRs fallback) keep serving.
type GeoDataUpdater struct {
	// Dir is where geoip.dat / geosite.dat are written. Required.
	Dir string

	// GeoIPURL / GeoSiteURL override the Loyalsoldier defaults. Set either
	// to "" (empty string) to skip downloading that file entirely — useful
	// when an operator wants only geoip but ships geosite via a different
	// pipeline.
	//
	// Phase 4 (2026-05-10): GeoIPURLs / GeoSiteURLs supersede the singular
	// fields when non-empty. When the slice has 0 entries the singular
	// field is used (1-source backward compat). When the slice has 1
	// entry it behaves exactly like the singular form. When the slice has
	// 2+ entries, each URL is downloaded to a distinct path
	// (geoip-<index>.dat / geosite-<index>.dat for index>0; index 0 keeps
	// the legacy geoip.dat / geosite.dat names so existing on-disk caches
	// and consumers keep working). The loader (LoadGeoDBMulti) merges
	// entries across files keyed by CountryCode.
	GeoIPURL    string
	GeoSiteURL  string
	GeoIPURLs   []string
	GeoSiteURLs []string

	// UpdateInterval is how often Start re-checks each URL after the first
	// pass. 0 ⇒ DefaultGeoDataInterval. Negative is treated as "no periodic
	// refresh, only the startup pass".
	UpdateInterval time.Duration

	// HTTPClient lets tests inject a httptest.Server-backed client. nil ⇒
	// a default client with a 5 min per-request timeout is used.
	HTTPClient *http.Client

	// Logger is called for warnings and informational lines. nil ⇒ log.Printf.
	Logger func(format string, args ...any)

	// OnRefresh, when non-nil, is invoked after a successful download with
	// the absolute path of the file that changed. The server uses this hook
	// to trigger a SIGHUP-equivalent dispatcher rebuild without waiting for
	// the operator. Errors from OnRefresh are logged at warning level only.
	OnRefresh func(path string)

	mu      sync.Mutex
	started bool
}

// effectiveURLs resolves which URL set to use for one side (geoip or
// geosite). Phase 4 multi-source rule: a non-empty multi-URL slice wins;
// otherwise the singular field is taken; otherwise the default URL.
// Empty entries within the slice are filtered out (operator may have
// left a blank line in the textarea).
func effectiveURLs(multi []string, single, defaultURL string) []string {
	out := make([]string, 0, len(multi))
	for _, u := range multi {
		if s := stringsTrim(u); s != "" {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	if stringsTrim(single) != "" {
		return []string{stringsTrim(single)}
	}
	if defaultURL != "" {
		return []string{defaultURL}
	}
	return nil
}

// stringsTrim is a tiny wrapper so we don't have to import strings just
// for one trim call (this file already pulls in plenty).
func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 {
		last := s[len(s)-1]
		if last == ' ' || last == '\t' || last == '\r' || last == '\n' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s
}

// targetForIndex picks the on-disk filename for the n-th URL of one side.
// Index 0 uses the legacy `<base>.dat` filename so single-source operators
// see no change. Index >= 1 uses `<base>-<index>.dat` so multi-source
// downloads coexist in the same directory.
func targetForIndex(dir, base string, index int) string {
	if index == 0 {
		return filepath.Join(dir, base+".dat")
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%d.dat", base, index))
}

// GeoIPPaths returns the on-disk paths the loader should read for the
// updater's effective GeoIP URL list. Includes the legacy `<dir>/geoip.dat`
// at index 0; subsequent paths follow the `<dir>/geoip-<n>.dat` pattern.
// Exposed for cmd/tamizdat-server (and tests) so the loader is aligned
// with whatever the updater wrote out.
func (u *GeoDataUpdater) GeoIPPaths() []string {
	dir := u.Dir
	if dir == "" {
		dir = DefaultGeoDataDir
	}
	urls := effectiveURLs(u.GeoIPURLs, u.GeoIPURL, DefaultGeoIPURL)
	out := make([]string, len(urls))
	for i := range urls {
		out[i] = targetForIndex(dir, "geoip", i)
	}
	return out
}

// GeoSitePaths mirrors GeoIPPaths for the geosite side.
func (u *GeoDataUpdater) GeoSitePaths() []string {
	dir := u.Dir
	if dir == "" {
		dir = DefaultGeoDataDir
	}
	urls := effectiveURLs(u.GeoSiteURLs, u.GeoSiteURL, DefaultGeoSiteURL)
	out := make([]string, len(urls))
	for i := range urls {
		out[i] = targetForIndex(dir, "geosite", i)
	}
	return out
}

// Start kicks off the updater goroutine. It does NOT block. The first refresh
// pass runs synchronously inside Start so callers can check that boot-time
// download succeeded (best-effort: errors are logged and Start still returns
// nil). Returns an error only when the configured directory cannot be
// created — that is a setup bug worth surfacing.
func (u *GeoDataUpdater) Start(ctx context.Context) error {
	u.mu.Lock()
	if u.started {
		u.mu.Unlock()
		return errors.New("geodata updater already started")
	}
	u.started = true
	u.mu.Unlock()

	dir := u.Dir
	if dir == "" {
		dir = DefaultGeoDataDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("geodata: mkdir %s: %w", dir, err)
	}

	geoipURLs := effectiveURLs(u.GeoIPURLs, u.GeoIPURL, DefaultGeoIPURL)
	geositeURLs := effectiveURLs(u.GeoSiteURLs, u.GeoSiteURL, DefaultGeoSiteURL)
	interval := u.UpdateInterval
	if interval == 0 {
		interval = DefaultGeoDataInterval
	}
	client := u.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: downloadTimeout}
	}
	logf := u.Logger
	if logf == nil {
		logf = log.Printf
	}

	// First-pass download (best effort; never propagates an error to caller).
	u.refreshOnce(ctx, client, logf, dir, geoipURLs, geositeURLs)

	if interval > 0 {
		go u.loop(ctx, client, logf, dir, geoipURLs, geositeURLs, interval)
	}
	return nil
}

// RefreshNow triggers an immediate refresh attempt on the same goroutine
// the caller runs in. It is safe to call concurrently with the periodic
// loop — the underlying file ops are atomic via .tmp+rename. Returns nil
// even when individual downloads fail; check logs for warnings.
func (u *GeoDataUpdater) RefreshNow(ctx context.Context) error {
	dir := u.Dir
	if dir == "" {
		dir = DefaultGeoDataDir
	}
	geoipURLs := effectiveURLs(u.GeoIPURLs, u.GeoIPURL, DefaultGeoIPURL)
	geositeURLs := effectiveURLs(u.GeoSiteURLs, u.GeoSiteURL, DefaultGeoSiteURL)
	client := u.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: downloadTimeout}
	}
	logf := u.Logger
	if logf == nil {
		logf = log.Printf
	}
	u.refreshOnce(ctx, client, logf, dir, geoipURLs, geositeURLs)
	return nil
}

func (u *GeoDataUpdater) loop(ctx context.Context, client *http.Client,
	logf func(string, ...any), dir string, geoipURLs, geositeURLs []string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.refreshOnce(ctx, client, logf, dir, geoipURLs, geositeURLs)
		}
	}
}

// refreshOnce iterates over the effective URL list per side. Index 0 keeps
// the legacy `geoip.dat` / `geosite.dat` filename so existing single-source
// deployments are bit-for-bit unchanged on disk. Index >= 1 uses an
// indexed suffix so multi-source downloads coexist.
func (u *GeoDataUpdater) refreshOnce(ctx context.Context, client *http.Client,
	logf func(string, ...any), dir string, geoipURLs, geositeURLs []string) {
	for i, url := range geoipURLs {
		if url == "" {
			continue
		}
		target := targetForIndex(dir, "geoip", i)
		u.maybeDownload(ctx, client, logf, fmt.Sprintf("geoip[%d]", i), url, target, validateGeoIPDat)
	}
	for i, url := range geositeURLs {
		if url == "" {
			continue
		}
		target := targetForIndex(dir, "geosite", i)
		u.maybeDownload(ctx, client, logf, fmt.Sprintf("geosite[%d]", i), url, target, validateGeositeDat)
	}
}

// maybeDownload runs a HEAD-then-GET dance. If the server's Last-Modified
// or ETag matches what we already have on disk, we skip the GET. Otherwise
// we GET to ${target}.tmp, validate, and atomic-rename over target.
//
// All non-fatal errors (network, validation, rename) are logged as warnings
// and leave the existing target untouched.
func (u *GeoDataUpdater) maybeDownload(ctx context.Context, client *http.Client,
	logf func(string, ...any), name, url, target string, valid validator) {
	want, err := u.hasUpdate(ctx, client, url, target)
	if err != nil {
		logf("geodata %s: HEAD %s failed: %v (will try GET anyway)", name, url, err)
		want = true // be pessimistic: try the GET; it might still succeed.
	}
	if !want {
		logf("geodata %s: up-to-date (%s)", name, target)
		return
	}
	if err := u.downloadOne(ctx, client, url, target, valid); err != nil {
		logf("geodata %s: refresh failed: %v (keeping existing %s)", name, err, target)
		return
	}
	logf("geodata %s: refreshed %s from %s", name, target, url)
	if u.OnRefresh != nil {
		// Run hook on the same goroutine; callers should keep it lightweight
		// (atomic-store of a Snapshot is enough; the slow path is reload
		// itself, and that already runs under the SIGHUP goroutine in main).
		func() {
			defer func() {
				if r := recover(); r != nil {
					logf("geodata %s: OnRefresh panic: %v", name, r)
				}
			}()
			u.OnRefresh(target)
		}()
	}
}

// hasUpdate sends a HEAD request and compares Last-Modified against the
// local file's mtime. Returns true when the local file is missing OR when
// the server's Last-Modified is strictly after the local mtime. Returns
// (true, nil) if the server omits Last-Modified entirely (we can't tell, so
// fetch).
func (u *GeoDataUpdater) hasUpdate(ctx context.Context, client *http.Client,
	url, target string) (bool, error) {
	st, statErr := os.Stat(target)
	if statErr != nil {
		// Local missing → always download.
		return true, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return true, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	// Drain body if any (HEAD bodies are usually empty but be defensive).
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return true, fmt.Errorf("HEAD %s: %s", url, resp.Status)
	}

	// GitHub's release-asset URL redirects to objects.githubusercontent.com
	// which DOES set Last-Modified. http.Client follows redirects for us.
	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return true, nil
	}
	remote, err := http.ParseTime(lm)
	if err != nil {
		return true, nil
	}
	return remote.After(st.ModTime()), nil
}

// downloadOne writes ${target}.tmp, validates, then atomically renames.
// Errors leave .tmp removed and target untouched.
func (u *GeoDataUpdater) downloadOne(ctx context.Context, client *http.Client,
	url, target string, valid validator) error {
	tmp := target + ".tmp"
	// Pre-clean any stale tmp from a crashed previous run.
	_ = os.Remove(tmp)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		cleanup()
		return fmt.Errorf("re-read %s: %w", tmp, err)
	}
	if len(data) == 0 {
		cleanup()
		return fmt.Errorf("empty download from %s", url)
	}
	if err := valid(data); err != nil {
		cleanup()
		return fmt.Errorf("validate %s: %w", url, err)
	}

	if err := os.Rename(tmp, target); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmp, target, err)
	}
	return nil
}

// validateGeoIPDat parses the blob with the same protobuf reader the
// runtime uses (parseGeoIPList in geo_dat.go). A truncated or scrambled
// download fails fast here rather than after rename.
func validateGeoIPDat(data []byte) error {
	entries, err := parseGeoIPList(data)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("zero geoip entries")
	}
	return nil
}

func validateGeositeDat(data []byte) error {
	entries, err := parseGeoSiteList(data)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("zero geosite entries")
	}
	return nil
}
