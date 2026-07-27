package tamizdat

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
	"time"
)

// TestUserRateLimiterThrottlesRead verifies that a 10 Mbps limiter actually
// pauses to honour the cap when fed a sustained read load. We send 5 MB
// (= 40 Mbits) through a limiter sized at 10 Mbits/sec; total wall time
// should be in the 3-5 s window (40 Mbits / 10 Mbps = 4 s ideal). A loose
// upper bound catches a regression where the limiter is bypassed or
// silently returns immediately.
func TestUserRateLimiterThrottlesRead(t *testing.T) {
	url := newUserRateLimiters()
	url.setMbps("u1", 10) // 10 Mbps = 1_250_000 bytes/sec
	lim := url.limiter("u1")
	if lim == nil {
		t.Fatal("expected non-nil limiter for capped user")
	}

	// 5 MB random source.
	src := bytes.NewReader(make([]byte, 5*1024*1024))
	rl := newRateLimitedReader(src, lim)

	start := time.Now()
	n, err := io.Copy(io.Discard, rl)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != 5*1024*1024 {
		t.Fatalf("expected 5 MiB, got %d", n)
	}
	// 5 MiB = 5*1024*1024 bytes = 41.94 Mbits / 10 Mbps = 4.19 s ideal.
	// Accept anywhere in [3s, 8s] — generous either way so a slightly
	// off-by-one bucket sizing doesn't fail the test, but a "no throttle"
	// regression (would finish in ~0 s) trips the lower bound hard.
	if elapsed < 3*time.Second {
		t.Errorf("rate limiter let traffic through too fast: %v < 3s", elapsed)
	}
	if elapsed > 8*time.Second {
		t.Errorf("rate limiter throttled too hard: %v > 8s", elapsed)
	}
}

// TestUserRateLimiterUnlimited verifies setMbps(0) drops the limiter so
// unlimited users see no throttling.
func TestUserRateLimiterUnlimited(t *testing.T) {
	url := newUserRateLimiters()
	url.setMbps("u2", 10)
	if url.limiter("u2") == nil {
		t.Fatal("expected limiter after setMbps(10)")
	}
	url.setMbps("u2", 0)
	if l := url.limiter("u2"); l != nil {
		t.Errorf("setMbps(0) should drop limiter, got %v", l)
	}
}

// TestUserRateLimiterReuseOnSameMbps confirms calling setMbps with an
// unchanged value preserves the existing token-bucket state — important
// for SIGHUP-driven reloads where the user's cap hasn't actually changed
// but the reload path re-publishes everything.
func TestUserRateLimiterReuseOnSameMbps(t *testing.T) {
	url := newUserRateLimiters()
	url.setMbps("u3", 50)
	first := url.limiter("u3")
	url.setMbps("u3", 50)
	second := url.limiter("u3")
	if first != second {
		t.Errorf("same-value setMbps should keep the same limiter pointer; first=%p second=%p", first, second)
	}
	url.setMbps("u3", 100)
	third := url.limiter("u3")
	if first == third {
		t.Errorf("changing mbps should swap limiter pointer; got same %p", first)
	}
}

func TestUserRateLimiterNilSafe(t *testing.T) {
	var url *userRateLimiters
	url.setMbps("x", 10)                 // no panic
	if l := url.limiter("x"); l != nil { // nil-receiver returns nil
		t.Errorf("nil receiver should return nil limiter, got %v", l)
	}
	url2 := newUserRateLimiters()
	if l := url2.limiter(""); l != nil { // empty userID returns nil
		t.Errorf("empty userID should return nil limiter, got %v", l)
	}
}

// drainShim — quick sanity that rand.Reader pumping into the rate-limited
// reader doesn't deadlock with a tiny burst.
func TestRateLimitedReaderTinyBurst(t *testing.T) {
	url := newUserRateLimiters()
	url.setMbps("u4", 1) // 1 Mbps -> burst = 125_000 bytes
	lim := url.limiter("u4")
	rl := newRateLimitedReader(rand.New(rand.NewSource(1)), lim)
	buf := make([]byte, 32*1024)
	if _, err := rl.Read(buf); err != nil {
		t.Errorf("read: %v", err)
	}
}
