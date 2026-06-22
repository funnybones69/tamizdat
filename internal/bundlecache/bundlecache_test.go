package bundlecache

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCacheDisabled(t *testing.T) {
	c := New("")
	if c.Enabled() {
		t.Fatal("empty dir should be disabled")
	}
	body, etag, err := c.Load(Key{Host: "ya.ru", ShortID: [8]byte{1}})
	if err != nil || body != nil || etag != "" {
		t.Fatalf("disabled cache load: body=%v etag=%q err=%v", body, etag, err)
	}
	if err := c.Save(Key{Host: "ya.ru"}, []byte("x"), "tag"); err != nil {
		t.Fatalf("disabled cache save returned err: %v", err)
	}
	if err := c.Delete(Key{Host: "ya.ru"}); err != nil {
		t.Fatalf("disabled cache delete: %v", err)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	if !c.Enabled() {
		t.Fatal("non-empty dir should be enabled")
	}
	k := Key{Host: "Server.Example", ShortID: [8]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33}}
	body := []byte(`{"version":1,"sni_pool":[{"sni":"yandex.ru","weight":100}]}`)
	etag := `"abc123def456"`
	if err := c.Save(k, body, etag); err != nil {
		t.Fatalf("Save: %v", err)
	}
	gotBody, gotEtag, err := c.Load(k)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body mismatch: got %s want %s", gotBody, body)
	}
	if gotEtag != etag {
		t.Fatalf("etag = %q, want %q", gotEtag, etag)
	}
	// Filename should normalise host casing and shortid.
	want := "bundle-server.example-deadbeef00112233.json"
	files, _ := os.ReadDir(dir)
	found := false
	for _, f := range files {
		if f.Name() == want {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.Name())
		}
		t.Fatalf("expected file %q in %v", want, names)
	}
}

func TestCacheSaveRewriteAtomic(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	k := Key{Host: "h", ShortID: [8]byte{1}}
	if err := c.Save(k, []byte("v1"), "tag1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(k, []byte("v2"), "tag2"); err != nil {
		t.Fatal(err)
	}
	body, etag, err := c.Load(k)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(body) != "v2" || etag != "tag2" {
		t.Fatalf("unexpected: body=%q etag=%q", body, etag)
	}
	// No leftover .tmp files lying around after both writes.
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".tmp") {
			t.Fatalf("leftover tmp file: %s", f.Name())
		}
	}
}

func TestCacheDeleteRemovesBoth(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	k := Key{Host: "h", ShortID: [8]byte{2}}
	if err := c.Save(k, []byte("body"), "tag"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(k); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	body, etag, err := c.Load(k)
	if err != nil || body != nil || etag != "" {
		t.Fatalf("Load after delete: body=%v etag=%q err=%v", body, etag, err)
	}
}

func TestCacheLoadMissingNoError(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	body, etag, err := c.Load(Key{Host: "missing", ShortID: [8]byte{9}})
	if err != nil {
		t.Fatalf("Load missing: err=%v", err)
	}
	if body != nil || etag != "" {
		t.Fatalf("Load missing returned body=%v etag=%q", body, etag)
	}
}

func TestCacheKeyFilenameSafe(t *testing.T) {
	// Ensure separators in host don't escape the cache dir.
	k := Key{Host: "../escape", ShortID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	name := k.filename()
	if filepath.Base(name) != name {
		t.Fatalf("filename escapes dir: %q", name)
	}
	if strings.Contains(name, string(filepath.Separator)) {
		t.Fatalf("filename contains separator: %q", name)
	}
}
