package tamizdat

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func shortIDFromSeed(seed byte) [8]byte {
	var k [8]byte
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// TestReviewD2_SingleShortIDBurstThenRefill verifies a single shortid can
// burn through `burst` allows back-to-back, then refills at `rate` per second.
func TestReviewD2_SingleShortIDBurstThenRefill(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newShortIDLimiterWithConfig(2.0 /* tokens/sec */, 5 /* burst */, 1024)
	l.now = func() time.Time { return now }

	id := shortIDFromSeed(1)
	// Burst: 5 successive Allow() calls all succeed (one consumed at
	// bucket-create time leaves burst-1 in the bucket; refilled to
	// burst on subsequent calls only after time passes, but the
	// initial 5 calls draw down the burst pool).
	got := 0
	for i := 0; i < 5; i++ {
		if l.Allow(id) {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("burst Allow count = %d, want 5", got)
	}
	// 6th immediate call must fail (bucket empty, no time elapsed).
	if l.Allow(id) {
		t.Fatal("6th immediate Allow succeeded; expected rate-limit reject")
	}

	// Advance 1 second -> 2 tokens added (rate=2/s). Two more Allow()
	// must succeed; the third must fail.
	now = now.Add(1 * time.Second)
	pass := 0
	if l.Allow(id) {
		pass++
	}
	if l.Allow(id) {
		pass++
	}
	if pass != 2 {
		t.Fatalf("post-refill 2 Allows succeeded count = %d, want 2", pass)
	}
	if l.Allow(id) {
		t.Fatal("third Allow after 1s refill succeeded; bucket should be empty again")
	}
}

// TestReviewD2_DistinctShortIDsDoNotShareBucket verifies that two distinct
// shortids each have their own bucket and do not block each other.
func TestReviewD2_DistinctShortIDsDoNotShareBucket(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newShortIDLimiterWithConfig(1.0, 3, 1024)
	l.now = func() time.Time { return now }

	a := shortIDFromSeed(10)
	b := shortIDFromSeed(20)

	// Drain a's bucket.
	for i := 0; i < 3; i++ {
		if !l.Allow(a) {
			t.Fatalf("a Allow %d unexpectedly rejected", i)
		}
	}
	if l.Allow(a) {
		t.Fatal("a 4th Allow succeeded; should be rate-limited")
	}

	// b's bucket must still be full (independent of a).
	for i := 0; i < 3; i++ {
		if !l.Allow(b) {
			t.Fatalf("b Allow %d rejected; b should not share bucket with a", i)
		}
	}
}

// TestReviewD2_LRUEvictsAtCapacity verifies that inserting capacity+1 distinct
// shortids triggers LRU eviction of the least-recently-used entry, keeping
// the bucket count bounded.
func TestReviewD2_LRUEvictsAtCapacity(t *testing.T) {
	const cap = 8
	now := time.Unix(1700000000, 0)
	l := newShortIDLimiterWithConfig(1.0, 1, cap)
	l.now = func() time.Time { return now }

	// Allocate cap distinct buckets (each call draws 1 token, leaving
	// 0 in each bucket -- which is fine; the LRU evict path only fires
	// on bucket *create* via map-len check).
	for i := byte(0); i < cap; i++ {
		l.Allow(shortIDFromSeed(i))
	}
	if got := l.size(); got != cap {
		t.Fatalf("after %d Allows, size = %d, want %d", cap, got, cap)
	}

	// One more distinct shortid -> evicts LRU -> size still == cap.
	l.Allow(shortIDFromSeed(cap))
	if got := l.size(); got != cap {
		t.Fatalf("after capacity+1 Allows, size = %d, want %d (LRU eviction failed)", got, cap)
	}
}

// TestReviewD2_ConcurrentAllowRaceClean stresses the limiter under many
// goroutines hitting overlapping shortids. The race detector must not flag
// this run.
func TestReviewD2_ConcurrentAllowRaceClean(t *testing.T) {
	l := newShortIDLimiterWithConfig(100, 1000, 4096)

	var wg sync.WaitGroup
	const goroutines = 64
	const perGoroutine = 200
	var allows int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := shortIDFromSeed(byte(seed*7 + i))
				if l.Allow(id) {
					atomic.AddInt64(&allows, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	if allows == 0 {
		t.Fatal("concurrent run produced zero Allow=true; impossible under burst=1000")
	}
}

// TestReviewD2_NilLimiterAllowsAll verifies the nil-receiver fast path so
// callers (or tests) that build a Server with shortIDLimiter==nil do not
// reject every connection.
func TestReviewD2_NilLimiterAllowsAll(t *testing.T) {
	var l *shortIDLimiter
	for i := 0; i < 100; i++ {
		if !l.Allow(shortIDFromSeed(byte(i))) {
			t.Fatalf("nil-receiver Allow rejected at i=%d", i)
		}
	}
}

// TestReviewD2_RefillCappedAtBurst verifies that idle buckets do not grow
// past `burst` after long elapsed time -- i.e. the refill clamp works.
func TestReviewD2_RefillCappedAtBurst(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := newShortIDLimiterWithConfig(10, 5, 1024)
	l.now = func() time.Time { return now }

	id := shortIDFromSeed(99)
	// Create bucket (consumes one), drain rest.
	for i := 0; i < 5; i++ {
		l.Allow(id)
	}
	// Wait many seconds -- 100s * 10 = 1000 tokens, but cap is 5.
	now = now.Add(100 * time.Second)
	pass := 0
	for i := 0; i < 100; i++ {
		if l.Allow(id) {
			pass++
		}
	}
	// At most 5 should pass before bucket re-empties.
	if pass != 5 {
		t.Fatalf("post-100s-idle drained %d, want exactly 5 (burst cap)", pass)
	}
}
