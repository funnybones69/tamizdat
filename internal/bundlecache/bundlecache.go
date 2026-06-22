// Package bundlecache persists the latest server-pushed config bundle to
// disk so a long-lived client survives restarts without re-fetching the
// bundle on every cold start. The cache is keyed by (server-host,
// master-shortid) so a single host running multiple tamizdat clients
// against different deployments never crosses streams.
//
// Layout:
//
//	<cache-dir>/bundle-<host>-<shortid8hex>.json     // wire JSON body
//	<cache-dir>/bundle-<host>-<shortid8hex>.etag     // strong ETag (server-supplied)
//
// Files are written via temp+rename for crash-safety. The ETag is stored
// alongside the body so the next dial can issue HEAD If-None-Match without
// re-parsing the body to recompute the hash.
package bundlecache

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Key identifies a single (server-host, master-shortid) bundle slot. The
// host portion is the URI host literal (DNS name or IP) without port — two
// deployments on the same host but different ports are considered the same
// auth principal.
type Key struct {
	Host    string
	ShortID [8]byte
}

func (k Key) filename() string {
	host := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k.Host)), string(filepath.Separator), "_")
	host = strings.ReplaceAll(host, ":", "_")
	return fmt.Sprintf("bundle-%s-%s.json", host, hex.EncodeToString(k.ShortID[:]))
}

// Cache persists bundle bodies + ETags under a single root directory.
type Cache struct {
	dir string
}

// New returns a Cache rooted at dir. The directory is created on first
// write (Save), so passing a path that does not yet exist is allowed.
// Pass empty string to disable persistence; Load/Save become no-ops.
func New(dir string) *Cache {
	return &Cache{dir: strings.TrimSpace(dir)}
}

// Enabled reports whether the cache will persist bundles to disk.
func (c *Cache) Enabled() bool { return c != nil && c.dir != "" }

// Load returns the cached body and ETag for the given key. Returns
// (nil, "", nil) when the cache is disabled or no entry exists; returns a
// non-nil error only when the cache directory exists but the entry is
// unreadable for some other reason (permission, partial-write recovery,
// etc.).
func (c *Cache) Load(k Key) (body []byte, etag string, err error) {
	if !c.Enabled() {
		return nil, "", nil
	}
	bodyPath := filepath.Join(c.dir, k.filename())
	etagPath := bodyPath + ".etag"
	body, err = os.ReadFile(bodyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("bundlecache: read body: %w", err)
	}
	if etagBuf, etagErr := os.ReadFile(etagPath); etagErr == nil {
		etag = strings.TrimSpace(string(etagBuf))
	}
	return body, etag, nil
}

// Save persists body+etag for the given key. The body file is written via
// temp+rename so a crash mid-write cannot leave a partial file in place
// (readers see either the previous version or the new one). When etag is
// empty the .etag sidecar is removed so a stale ETag never lingers.
func (c *Cache) Save(k Key, body []byte, etag string) error {
	if !c.Enabled() {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("bundlecache: mkdir: %w", err)
	}
	bodyPath := filepath.Join(c.dir, k.filename())
	tmp, err := os.CreateTemp(c.dir, "bundle-*.tmp")
	if err != nil {
		return fmt.Errorf("bundlecache: tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// best-effort cleanup if rename never happened (Close already
		// handles the regular case via tmp.Sync+rename below).
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bundlecache: write body: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bundlecache: sync body: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bundlecache: close body: %w", err)
	}
	if err := os.Rename(tmpPath, bodyPath); err != nil {
		return fmt.Errorf("bundlecache: rename body: %w", err)
	}
	etagPath := bodyPath + ".etag"
	if strings.TrimSpace(etag) == "" {
		_ = os.Remove(etagPath)
		return nil
	}
	if err := os.WriteFile(etagPath, []byte(etag), 0o600); err != nil {
		return fmt.Errorf("bundlecache: write etag: %w", err)
	}
	return nil
}

// Delete removes the body+etag pair for the given key. Errors are returned
// only when the file existed but could not be removed.
func (c *Cache) Delete(k Key) error {
	if !c.Enabled() {
		return nil
	}
	bodyPath := filepath.Join(c.dir, k.filename())
	etagPath := bodyPath + ".etag"
	for _, p := range []string{bodyPath, etagPath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("bundlecache: remove %s: %w", p, err)
		}
	}
	return nil
}
