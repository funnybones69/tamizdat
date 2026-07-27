package tamizdat

import (
	"container/heap"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"fmt"
	"sync"
	"testing"
	"time"
)

func replayTestKey(seed byte) [16]byte {
	var key [16]byte
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func replayKeyFromSessionAndEphemeral(sessionID, ephemeralPublicKey []byte) [16]byte {
	digest := sha256.Sum256(append(append([]byte{}, sessionID...), ephemeralPublicKey...))
	var key [16]byte
	copy(key[:], digest[:16])
	return key
}

func resetReplayExpvarsForTest() {
	initReplayExpvars()
	replayHits.Set(0)
	replayWindowSize.Set(0)
	replayEvictions.Set(0)
}

func TestReplayKeyV1SHA256TruncatedVectorAndRandomCollisionSmoke(t *testing.T) {
	sessionID := make([]byte, 32)
	ephemeralPublicKey := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i)
		ephemeralPublicKey[i] = byte(0xa0 + i)
	}
	key := replayKeyFromSessionAndEphemeral(sessionID, ephemeralPublicKey)
	if got, want := hex.EncodeToString(key[:]), "60dcbc828060c044579c4b6c671582e3"; got != want {
		t.Fatalf("SHA-256(SessionID || eph_pub)[:16] = %s, want %s", got, want)
	}

	seen := make(map[[16]byte]struct{}, 10000)
	buf := make([]byte, 64)
	for i := 0; i < 10000; i++ {
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		key := replayKeyFromSessionAndEphemeral(buf[:32], buf[32:])
		if _, ok := seen[key]; ok {
			t.Fatalf("unexpected 16-byte replay-key collision after %d randomized inputs: %x", i+1, key)
		}
		seen[key] = struct{}{}
	}
}

func TestReplayGuardInsertAndSeen(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	now := time.Unix(1000, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		g.Insert(replayTestKey(byte(i)), now)
	}
	for i := 0; i < 100; i++ {
		if !g.Seen(replayTestKey(byte(i))) {
			t.Fatalf("key %d was not seen after insert", i)
		}
	}
	if g.Seen(replayTestKey(200)) {
		t.Fatal("random non-inserted key reported as seen")
	}
	if got := expvar.Get("tamizdat.replay.hits").String(); got != "100" {
		t.Fatalf("hits counter = %s, want 100", got)
	}
	if got := expvar.Get("tamizdat.replay.window_size").String(); got != "100" {
		t.Fatalf("window_size counter = %s, want 100", got)
	}
}

func TestReplayGuardWindowExpiryFiveMinutes(t *testing.T) {
	resetReplayExpvarsForTest()
	base := time.Unix(0, 0)
	g := newReplayGuard(0)
	now := base
	g.now = func() time.Time { return now }
	key := replayTestKey(1)
	g.Insert(key, base)

	now = base.Add(4*time.Minute + 59*time.Second)
	if !g.Seen(key) {
		t.Fatal("key expired before five-minute replay window elapsed")
	}

	now = base.Add(5*time.Minute + time.Second)
	if g.Seen(key) {
		t.Fatal("key still seen after five-minute replay window elapsed")
	}
	if got := expvar.Get("tamizdat.replay.evictions").String(); got != "1" {
		t.Fatalf("evictions counter = %s, want 1", got)
	}
}

func TestReplayGuardHardCapEvictsOldest(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	base := time.Unix(1000, 0)
	now := base
	g.now = func() time.Time { return now }
	oldest := replayTestKey(0)
	g.Insert(oldest, base)
	for i := 1; i <= replayHardCap; i++ {
		var key [16]byte
		copy(key[:], []byte(fmt.Sprintf("key-%08d----", i)))
		g.Insert(key, base.Add(time.Duration(i)*time.Nanosecond))
	}
	if g.Seen(oldest) {
		t.Fatal("oldest key still present after inserting hard-cap+1 entries")
	}
	if got := g.size(); got != replayHardCap {
		t.Fatalf("window size = %d, want %d", got, replayHardCap)
	}
	if got := expvar.Get("tamizdat.replay.evictions").String(); got != "1" {
		t.Fatalf("evictions counter = %s, want 1", got)
	}
	if got := expvar.Get("tamizdat.replay.window_size").String(); got != fmt.Sprint(replayHardCap) {
		t.Fatalf("window_size counter = %s, want %d", got, replayHardCap)
	}
}

func TestReplayGuardCheckV1AllowsSharedSessionIDDifferentEphemeral(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	sessionID := make([]byte, 32)
	ephemeralA := make([]byte, 32)
	ephemeralB := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i)
		ephemeralA[i] = byte(0x40 + i)
		ephemeralB[i] = byte(0x80 + i)
	}
	keyA := replayKeyFromSessionAndEphemeral(sessionID, ephemeralA)
	keyB := replayKeyFromSessionAndEphemeral(sessionID, ephemeralB)
	if !g.checkV1(keyA) {
		t.Fatal("first v1 replay key was rejected")
	}
	if !g.checkV1(keyB) {
		t.Fatal("distinct eph_pub with shared SessionID should use a distinct replay key bucket")
	}
	if g.checkV1(keyA) {
		t.Fatal("duplicate v1 replay key was accepted")
	}
}

func TestReplayGuardConcurrency(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				var key [16]byte
				copy(key[:], []byte(fmt.Sprintf("%02d-%012d", worker, i)))
				if !g.checkV1(key) {
					t.Errorf("fresh key rejected for worker=%d i=%d", worker, i)
				}
			}
		}()
	}
	wg.Wait()
	// After hardcap was bumped from 4096 to 65536, 16 workers x 1000 keys = 16000
	// no longer triggers cap eviction. Assert the cap is an upper bound; a separate
	// test (TestReplayGuardEvictsAtCap) validates eviction with a small cap.
	if got := g.size(); got > replayHardCap {
		t.Fatalf("window size = %d > hard cap %d", got, replayHardCap)
	}

	var replayed [16]byte
	copy(replayed[:], []byte("same-key--------"))
	accepted := 0
	wg = sync.WaitGroup{}
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.checkV1(replayed) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("same-key race accepted %d calls, want exactly 1", accepted)
	}
}

// TestReplayGuardEvictsAtCap verifies that the LRU eviction triggers when
// the window exceeds the configured hard cap. Uses a manually-constructed
// guard with a tiny capacity so we don't have to insert 65k keys.
func TestReplayGuardEvictsAtCap(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	g.hardCap = 8 // override default for the test only
	for i := 0; i < 100; i++ {
		var key [16]byte
		copy(key[:], []byte(fmt.Sprintf("key-%012d", i)))
		_ = g.checkV1(key)
	}
	if got := g.size(); got > g.hardCap {
		t.Fatalf("size %d > hardCap %d (LRU eviction did not run)", got, g.hardCap)
	}
}

func TestReplayGuardMinHeapOrdersEntriesByInsertTime(t *testing.T) {
	base := time.Unix(1700000000, 0)
	var h replayMinHeap
	heap.Push(&h, replayHeapEntry{insertTime: base.Add(30 * time.Second), key: replayTestKey(3)})
	heap.Push(&h, replayHeapEntry{insertTime: base.Add(10 * time.Second), key: replayTestKey(1)})
	heap.Push(&h, replayHeapEntry{insertTime: base.Add(20 * time.Second), key: replayTestKey(2)})

	for _, want := range []byte{1, 2, 3} {
		got := heap.Pop(&h).(replayHeapEntry)
		if got.key != replayTestKey(want) {
			t.Fatalf("heap pop key = %x, want seed %d", got.key, want)
		}
	}
}

func TestReplayGuardHeapEvictionSkipsStaleEntriesFromReap(t *testing.T) {
	resetReplayExpvarsForTest()
	base := time.Unix(1700000000, 0)
	now := base
	g := newReplayGuard(time.Second)
	g.hardCap = 3
	g.now = func() time.Time { return now }

	stale := replayTestKey(0)
	g.Insert(stale, base)
	now = base.Add(2 * time.Second)
	if g.Seen(stale) {
		t.Fatal("stale key should have been reaped from the map")
	}

	g.window = time.Hour
	live := []struct {
		seed byte
		t    time.Time
	}{
		{1, now.Add(1 * time.Second)},
		{2, now.Add(2 * time.Second)},
		{3, now.Add(3 * time.Second)},
		{4, now.Add(4 * time.Second)},
	}
	for _, entry := range live {
		g.Insert(replayTestKey(entry.seed), entry.t)
	}
	now = now.Add(5 * time.Second)

	if g.Seen(replayTestKey(1)) {
		t.Fatal("oldest live key remained after hard-cap eviction")
	}
	for _, seed := range []byte{2, 3, 4} {
		if !g.Seen(replayTestKey(seed)) {
			t.Fatalf("live key with seed %d missing after heap eviction", seed)
		}
	}
	if got := g.size(); got != g.hardCap {
		t.Fatalf("window size = %d, want hardCap %d", got, g.hardCap)
	}
}

// TestReviewD3_HeapDrainsStaleEntriesByTime targets the steady-state slow
// leak: at sustained auth rates below the hard cap, evictOverCapLocked
// never fires, the map is pruned by reapLocked, but the heap retains
// stale entries forever. After D-3 the heap also drains by time inside
// reapLocked, so map and heap are equivalent at all times.
func TestReviewD3_HeapDrainsStaleEntriesByTime(t *testing.T) {
	resetReplayExpvarsForTest()
	base := time.Unix(1700000000, 0)
	now := base
	g := newReplayGuard(time.Minute)
	// Hard cap well above what we will insert -- we want to verify
	// the time-based heap drain, not the cap-based eviction.
	g.hardCap = 100000
	g.now = func() time.Time { return now }

	// Insert 1000 distinct entries spread across a 50-second window
	// (one per 50ms). All entries fit inside the 60-second TTL when
	// the window opens. We synthesize unique 16-byte keys via
	// big-endian uint16 encoding so the keyspace exceeds 256.
	const n = 1000
	makeKey := func(i int) [16]byte {
		var k [16]byte
		k[0] = byte(i >> 8)
		k[1] = byte(i)
		return k
	}
	for i := 0; i < n; i++ {
		now = base.Add(time.Duration(i) * 50 * time.Millisecond)
		g.Insert(makeKey(i), now)
	}
	if got := g.size(); got != n {
		t.Fatalf("after %d inserts, size = %d", n, got)
	}
	// Heap should also hold n entries pre-prune.
	if got := len(g.evictionHeap); got != n {
		t.Fatalf("heap pre-prune len = %d, want %d", got, n)
	}

	// Advance past the window for ALL inserted entries.
	// Last insert was at base + 999*50ms = base + 49.95s.
	// Window is 1 min, so insert@49.95s expires at 49.95s + 60s = 109.95s.
	// Jump to base + 5 min so every entry is decisively stale.
	now = base.Add(5 * time.Minute)

	// One Seen() call triggers reapLocked. Pass throttle=false path
	// by invoking via the public Seen method on a key not in the map.
	var missingKey [16]byte
	missingKey[15] = 0xFF
	if g.Seen(missingKey) {
		t.Fatal("freshly-fabricated key reported as seen")
	}

	if got := g.size(); got != 0 {
		t.Fatalf("post-reap map size = %d, want 0", got)
	}
	// THIS is the D-3 invariant. Pre-D-3 the heap retained all
	// 1000 stale entries here; post-D-3 it drains in lockstep.
	if got := len(g.evictionHeap); got != 0 {
		t.Fatalf("post-reap heap len = %d, want 0 (review-D-3 leak invariant violated)", got)
	}
}

// TestReviewD3_HeapPartialDrainStopsAtFirstFreshEntry verifies that the
// heap drain stops at the first non-stale entry (it is a min-heap on
// insertTime, so once the front is fresh, every later entry is also
// fresh). The test inserts a mix of stale and fresh entries and checks
// the heap retains exactly the fresh ones.
func TestReviewD3_HeapPartialDrainStopsAtFirstFreshEntry(t *testing.T) {
	resetReplayExpvarsForTest()
	base := time.Unix(1700000000, 0)
	now := base
	g := newReplayGuard(time.Minute)
	g.hardCap = 1000
	g.now = func() time.Time { return now }

	// 5 stale entries (will be aged out).
	for i := 0; i < 5; i++ {
		ti := base.Add(time.Duration(i) * time.Second)
		g.Insert(replayTestKey(byte(i)), ti)
	}
	// Advance enough that those 5 are stale but later ones will not be.
	now = base.Add(2 * time.Minute)
	// 3 fresh entries (relative to the new "now").
	for i := 5; i < 8; i++ {
		g.Insert(replayTestKey(byte(i)), now)
	}

	// Trigger reap via Seen on a missing key.
	if g.Seen(replayTestKey(254)) {
		t.Fatal("fabricated key reported as seen")
	}

	if got := g.size(); got != 3 {
		t.Fatalf("post-reap map size = %d, want 3 fresh", got)
	}
	if got := len(g.evictionHeap); got != 3 {
		t.Fatalf("post-reap heap len = %d, want 3 fresh (D-3 partial drain invariant)", got)
	}
	// Sanity: peek front, it should be one of the fresh keys (5/6/7).
	front := g.evictionHeap[0]
	if front.key[0] < 5 {
		t.Fatalf("heap front key seed = %d, want >=5 (stale entry survived drain)", front.key[0])
	}
}
