package vkturn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, cachePath string) *Client {
	t.Helper()
	var sid [ShortIDLen]byte
	sid[0] = 1
	c, err := NewClient(ClientConfig{
		ServerAddr:    "127.0.0.1:9",
		ShortID:       sid,
		VKHashes:      []string{"testhash"},
		CredCachePath: cachePath,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func makeCreds(lifetime int) *Credentials {
	return &Credentials{
		User:     "u",
		Pass:     "p",
		TurnURLs: []string{"turn.example:3478"},
		Lifetime: lifetime,
		Fetched:  time.Now(),
	}
}

func TestPersistentCredsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Nested path exercises MkdirAll.
	path := filepath.Join(dir, "sub", "vkturn-creds.json")
	exp := time.Now().Add(time.Hour).Round(time.Second)
	in := &persistentCreds{
		User:       "user-x",
		Pass:       "pass-x",
		TurnURLs:   []string{"a.example:3478", "b.example:3478"},
		Lifetime:   3600,
		HashDigest: "deadbeef",
		FetchedAt:  time.Now().Round(time.Second),
		ExpiresAt:  exp,
	}
	if err := savePersistentCreds(path, in); err != nil {
		t.Fatalf("savePersistentCreds: %v", err)
	}
	out, err := loadPersistentCreds(path)
	if err != nil {
		t.Fatalf("loadPersistentCreds: %v", err)
	}
	if out.User != in.User || out.Pass != in.Pass || out.Lifetime != in.Lifetime || out.HashDigest != in.HashDigest {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
	if len(out.TurnURLs) != 2 || out.TurnURLs[0] != "a.example:3478" {
		t.Fatalf("urls mismatch: %v", out.TurnURLs)
	}
	if !out.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry mismatch: %v vs %v", out.ExpiresAt, exp)
	}

	// On POSIX the file must be 0600 — it holds secret-capable TURN creds.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("cred cache perm = %o, want 0600", perm)
		}
	}
}

func TestLoadPersistentCredsRejectsIncomplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	if err := os.WriteFile(path, []byte(`{"turn_user":"u"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPersistentCreds(path); err == nil {
		t.Fatal("expected error for creds missing pass/urls")
	}
}

func TestCredBackoffDurationSchedule(t *testing.T) {
	cases := []struct {
		fails int
		want  time.Duration
	}{
		{0, 0},
		{1, 30 * time.Second},
		{2, time.Minute},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 8 * time.Minute},
		{6, 16 * time.Minute},
		{7, 30 * time.Minute}, // 32m capped to 30m
		{20, 30 * time.Minute},
	}
	for _, tc := range cases {
		if got := credBackoffDuration(tc.fails); got != tc.want {
			t.Errorf("credBackoffDuration(%d) = %v, want %v", tc.fails, got, tc.want)
		}
	}
}

func TestCredExpiry(t *testing.T) {
	now := time.Now()
	if got := credExpiry(&Credentials{Lifetime: 3600}, now); !got.Equal(now.Add(3480 * time.Second)) {
		t.Errorf("lifetime 3600: got %v, want now+3480s", got)
	}
	if got := credExpiry(&Credentials{Lifetime: 60}, now); !got.Equal(now.Add(defaultCredReuse)) {
		t.Errorf("lifetime 60: got %v, want now+%v", got, defaultCredReuse)
	}
	if got := credExpiry(&Credentials{Lifetime: 0}, now); !got.Equal(now.Add(defaultCredReuse)) {
		t.Errorf("lifetime 0: got %v, want now+%v", got, defaultCredReuse)
	}
}

func TestGetCredentialsPreSharedBypassesAcquire(t *testing.T) {
	var sid [ShortIDLen]byte
	sid[0] = 1
	c, err := NewClient(ClientConfig{ServerAddr: "127.0.0.1:9", ShortID: sid, Credentials: makeCreds(3600)})
	if err != nil {
		t.Fatal(err)
	}
	c.acquire = func(context.Context) (*Credentials, error) {
		t.Fatal("acquire must not run with pre-shared credentials")
		return nil, nil
	}
	got, err := c.getCredentials(context.Background())
	if err != nil || got == nil || got.User != "u" {
		t.Fatalf("getCredentials = %v, %v", got, err)
	}
}

// TestGetCredentialsSingleflight proves concurrent dials share ONE acquisition
// instead of each launching a parallel VK captcha flow.
func TestGetCredentialsSingleflight(t *testing.T) {
	c := testClient(t, "")
	var calls int32
	enter := make(chan struct{})
	proceed := make(chan struct{})
	c.acquire = func(context.Context) (*Credentials, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(enter)
		}
		<-proceed
		return makeCreds(3600), nil
	}

	var wg sync.WaitGroup
	get := func() {
		defer wg.Done()
		if _, err := c.getCredentials(context.Background()); err != nil {
			t.Errorf("getCredentials: %v", err)
		}
	}

	// Leader enters acquire and blocks; credInflight is now set.
	wg.Add(1)
	go get()
	<-enter

	// Followers must join the in-flight acquisition.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go get()
	}
	time.Sleep(50 * time.Millisecond) // let followers queue on credInflight
	close(proceed)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("acquire called %d times, want 1 (singleflight)", got)
	}
}

// TestGetCredentialsAcquisitionOutlivesCallerTimeout is the Keenetic captcha
// storm regression: the first health probe may have a short timeout, but the
// one shared VK credential acquisition must keep running in the background. A
// later dial should join/reuse that same future, not create a second captcha.
func TestGetCredentialsAcquisitionOutlivesCallerTimeout(t *testing.T) {
	c := testClient(t, "")
	var calls int32
	enter := make(chan struct{})
	proceed := make(chan struct{})
	c.acquire = func(ctx context.Context) (*Credentials, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(enter)
		}
		select {
		case <-proceed:
			return makeCreds(3600), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.getCredentials(ctx)
		done <- err
	}()

	<-enter
	cancel()
	if err := <-done; err == nil {
		t.Fatal("expected first caller to cancel while acquisition continues")
	}

	close(proceed)
	got, err := c.getCredentials(context.Background())
	if err != nil {
		t.Fatalf("second caller should receive completed shared acquisition: %v", err)
	}
	if got == nil || got.User != "u" {
		t.Fatalf("unexpected creds: %v", got)
	}
	if gotCalls := atomic.LoadInt32(&calls); gotCalls != 1 {
		t.Fatalf("acquire called %d times, want 1", gotCalls)
	}
}

// TestGetCredentialsBackoffStopsHammering proves that after a failure, dials in
// the backoff window do NOT re-call VK — the core fix for the captcha storm.
func TestGetCredentialsBackoffStopsHammering(t *testing.T) {
	c := testClient(t, "")
	var calls int32
	c.acquire = func(context.Context) (*Credentials, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("BOT")
	}

	if _, err := c.getCredentials(context.Background()); err == nil {
		t.Fatal("expected failure on first acquisition")
	}
	for i := 0; i < 5; i++ {
		if _, err := c.getCredentials(context.Background()); err == nil {
			t.Fatal("expected backoff error")
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("acquire called %d times, want 1 (backoff must suppress retries)", got)
	}
}

// TestGetCredentialsServesStaleDuringBackoff proves a known-stale credential is
// served while in backoff rather than triggering another captcha.
func TestGetCredentialsServesStaleDuringBackoff(t *testing.T) {
	c := testClient(t, "")
	c.creds = makeCreds(0)
	c.credsExpiry = time.Now().Add(-time.Minute) // expired
	var calls int32
	c.acquire = func(context.Context) (*Credentials, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("BOT")
	}

	// First call: cache expired, not yet in backoff → tries acquire → fails.
	if _, err := c.getCredentials(context.Background()); err == nil {
		t.Fatal("expected failure on refresh attempt")
	}
	// Second call: in backoff → serve the stale credential, no acquire.
	got, err := c.getCredentials(context.Background())
	if err != nil {
		t.Fatalf("expected stale creds served during backoff, got error: %v", err)
	}
	if got == nil || got.User != "u" {
		t.Fatalf("expected stale creds, got %v", got)
	}
	if calls != 1 {
		t.Fatalf("acquire called %d times, want 1", calls)
	}
}

// TestGetCredentialsLoadsCacheOnStart proves a valid on-disk cache lets the
// first dial after a restart use the relay with zero VK contact.
func TestGetCredentialsLoadsCacheOnStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	pc := &persistentCreds{
		User: "cached", Pass: "p", TurnURLs: []string{"t:3478"},
		Lifetime: 3600, FetchedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := savePersistentCreds(path, pc); err != nil {
		t.Fatal(err)
	}

	c := testClient(t, path) // NewClient loads the cache
	c.acquire = func(context.Context) (*Credentials, error) {
		t.Fatal("acquire must not run when a valid cache is loaded")
		return nil, nil
	}
	got, err := c.getCredentials(context.Background())
	if err != nil {
		t.Fatalf("getCredentials: %v", err)
	}
	if got.User != "cached" {
		t.Fatalf("expected cached creds, got %v", got)
	}
}

// TestGetCredentialsWriteThrough proves a successful acquisition is persisted.
func TestGetCredentialsWriteThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	c := testClient(t, path)
	c.acquire = func(context.Context) (*Credentials, error) { return makeCreds(3600), nil }

	if _, err := c.getCredentials(context.Background()); err != nil {
		t.Fatalf("getCredentials: %v", err)
	}
	out, err := loadPersistentCreds(path)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	if out.User != "u" || out.Lifetime != 3600 {
		t.Fatalf("persisted creds mismatch: %+v", out)
	}
	// Expiry derives from lifetime (3600s) minus the 120s rotate margin = 58m,
	// which must be well past the 30m default-reuse fallback.
	if out.ExpiresAt.Before(time.Now().Add(50 * time.Minute)) {
		t.Fatalf("expiry not persisted from lifetime: %v", out.ExpiresAt)
	}
}

// TestGetCredentialsAdoptsSeededFile proves the break-glass path: an external
// solver (panel captcha in a real browser) writes the cache file, and a running
// client adopts it without any VK contact.
func TestGetCredentialsAdoptsSeededFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	c := testClient(t, path) // no file at startup, no creds
	var calls int32
	c.acquire = func(context.Context) (*Credentials, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("BOT")
	}

	// Simulate the panel writing freshly human-solved creds.
	seed := &persistentCreds{
		User: "seeded", Pass: "p", TurnURLs: []string{"t:3478"},
		Lifetime: 3600, FetchedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := savePersistentCreds(path, seed); err != nil {
		t.Fatal(err)
	}

	got, err := c.getCredentials(context.Background())
	if err != nil {
		t.Fatalf("expected seeded creds to be adopted, got error: %v", err)
	}
	if got.User != "seeded" {
		t.Fatalf("expected seeded creds, got %v", got)
	}
	if calls != 0 {
		t.Fatalf("acquire ran %d times; a seeded file must short-circuit VK", calls)
	}
}
