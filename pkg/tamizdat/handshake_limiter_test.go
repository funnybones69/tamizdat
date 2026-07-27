package tamizdat

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHandshakeLimiterBlocksFourthUntilWindowSlides(t *testing.T) {
	lim := newHandshakeLimiterWithConfig(3, 50*time.Millisecond)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := lim.Wait(ctx, "203.0.113.10:443"); err != nil {
			t.Fatalf("Wait #%d: %v", i+1, err)
		}
	}

	start := time.Now()
	if err := lim.Wait(ctx, "203.0.113.10:443"); err != nil {
		t.Fatalf("fourth Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("fourth Wait returned too early: %s", elapsed)
	}
	// Upper bound = window (50ms) + max jitter (200ms) + scheduler slack.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("fourth Wait blocked too long: %s", elapsed)
	}
}

func TestHandshakeLimiterContextCancelReturnsRateLimited(t *testing.T) {
	lim := newHandshakeLimiterWithConfig(1, time.Second)
	if err := lim.Wait(context.Background(), "203.0.113.20:443"); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := lim.Wait(ctx, "203.0.113.20:443")
	if !errors.Is(err, ErrHandshakeRateLimited) {
		t.Fatalf("Wait after cancel = %v, want ErrHandshakeRateLimited", err)
	}
}

// J-RR-1: events map is bounded under flood and evicts least-recently-used keys.
func TestHandshakeLimiter_BoundedMapUnderFlood(t *testing.T) {
	lim := newHandshakeLimiterWithConfig(3, time.Hour) // long window so events stick
	ctx := context.Background()

	const flood = 10000
	for i := 0; i < flood; i++ {
		key := fmt.Sprintf("203.0.113.%d:%d", i%256, 1024+i)
		if err := lim.Wait(ctx, key); err != nil {
			t.Fatalf("Wait #%d (%s): %v", i, key, err)
		}
	}

	lim.mu.Lock()
	mapSize := len(lim.events)
	lruSize := lim.lruList.Len()
	idxSize := len(lim.lruIdx)
	lim.mu.Unlock()

	if mapSize > clientLimiterMapCap {
		t.Fatalf("events map exceeded cap: got %d, want <= %d", mapSize, clientLimiterMapCap)
	}
	if mapSize != clientLimiterMapCap {
		t.Fatalf("events map should be at cap after flood: got %d, want %d", mapSize, clientLimiterMapCap)
	}
	if lruSize != mapSize || idxSize != mapSize {
		t.Fatalf("LRU bookkeeping out of sync: events=%d lruList=%d lruIdx=%d",
			mapSize, lruSize, idxSize)
	}

	// Oldest keys (i=0..flood-1-cap) must have been evicted.
	earlyKey := fmt.Sprintf("203.0.113.%d:%d", 0%256, 1024+0)
	lim.mu.Lock()
	_, present := lim.events[earlyKey]
	_, idxPresent := lim.lruIdx[earlyKey]
	lim.mu.Unlock()
	if present || idxPresent {
		t.Fatalf("oldest key %q should have been evicted (events=%v idx=%v)",
			earlyKey, present, idxPresent)
	}

	// Most-recent key must be tracked.
	latestKey := fmt.Sprintf("203.0.113.%d:%d", (flood-1)%256, 1024+flood-1)
	lim.mu.Lock()
	_, latestPresent := lim.events[latestKey]
	lim.mu.Unlock()
	if !latestPresent {
		t.Fatalf("latest key %q should still be tracked", latestKey)
	}
}

// J-RR-1: Wait after rate-limit kick must add random jitter, breaking the
// deterministic redial cadence. We measure 32 forced waits and assert that
// they aren't all clustered at the no-jitter point.
func TestHandshakeLimiter_WaitHasJitter(t *testing.T) {
	const samples = 32
	const window = 30 * time.Millisecond

	durations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		lim := newHandshakeLimiterWithConfig(1, window)
		ctx := context.Background()
		if err := lim.Wait(ctx, "203.0.113.30:443"); err != nil {
			t.Fatalf("first Wait #%d: %v", i, err)
		}
		start := time.Now()
		if err := lim.Wait(ctx, "203.0.113.30:443"); err != nil {
			t.Fatalf("second Wait #%d: %v", i, err)
		}
		durations = append(durations, time.Since(start))
	}

	// All durations must be at least ~window (the slot expiry).
	for i, d := range durations {
		if d < window-5*time.Millisecond {
			t.Fatalf("sample %d below window: %s", i, d)
		}
	}

	// Compute mean and variance. Without jitter, every sample sits within a
	// few ms of `window`; with [0,200ms] jitter, variance >> 100 ms^2.
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	mean := sum / time.Duration(samples)

	var sumSq float64
	for _, d := range durations {
		diff := float64(d-mean) / float64(time.Millisecond)
		sumSq += diff * diff
	}
	variance := sumSq / float64(samples)

	// Floor: even with bad luck on the RNG, a [0,200ms] uniform should give
	// variance well above 100 ms^2 (theoretical = 200^2/12 ≈ 3333 ms^2).
	const minVariance = 100.0
	if variance < minVariance {
		t.Fatalf("Wait jitter variance too low: got %.1f ms^2, want >= %.1f ms^2 "+
			"(durations: %v)", variance, minVariance, durations)
	}
}
