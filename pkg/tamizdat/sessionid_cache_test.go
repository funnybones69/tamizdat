package tamizdat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fixedRNG is a deterministic Reader that yields a repeating byte pattern.
// Used by tests that need to assert "same stable random emerged from two
// Acquires"; the cache reseeds rng for new entries / on TTL expiry.
type fixedRNG struct {
	mu    sync.Mutex
	bytes []byte
	idx   int
}

func newFixedRNG(seed []byte) *fixedRNG {
	if len(seed) == 0 {
		seed = []byte{0xAA}
	}
	return &fixedRNG{bytes: seed}
}

func (r *fixedRNG) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		p[i] = r.bytes[r.idx%len(r.bytes)]
		r.idx++
	}
	return len(p), nil
}

// failingRNG returns a fixed error from the first Read.
type failingRNG struct{}

func (failingRNG) Read(p []byte) (int, error) { return 0, errors.New("forced rng failure") }

// TestSessionIDCache_StablePrefixAcrossDials asserts that two Acquire calls for
// the same (server_addr, shortID) within TTL hand back the same 6-byte stable
// prefix; only the trailing 2-byte counter changes. This is the core behaviour
// guarding review-C tell #12 — Chrome reuses its SessionID across reconnects
// within session-ticket lifetime, and the cache makes our SessionID prefix
// match that pattern.
func TestSessionIDCache_StablePrefixAcrossDials(t *testing.T) {
	cache := newSessionIDCache()
	cache.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	cache.rng = newFixedRNG([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04})

	server := "tamizdat.example:443"
	short := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}

	first, err := cache.Acquire(server, short)
	if err != nil {
		t.Fatalf("Acquire #1: %v", err)
	}
	second, err := cache.Acquire(server, short)
	if err != nil {
		t.Fatalf("Acquire #2: %v", err)
	}
	if !bytes.Equal(first[:stableRandomLen], second[:stableRandomLen]) {
		t.Fatalf("stable prefix not preserved across dials: first=%x second=%x", first[:stableRandomLen], second[:stableRandomLen])
	}
	c1 := binary.BigEndian.Uint16(first[stableRandomLen:])
	c2 := binary.BigEndian.Uint16(second[stableRandomLen:])
	if c2 != c1+1 {
		t.Fatalf("counter expected to bump by 1, got %d -> %d", c1, c2)
	}
}

// TestSessionIDCache_DistinctServerOrShortIDAreIndependent: per-(server,
// shortID) cache is keyed correctly — different server addresses or different
// shortIDs MUST get different stable randoms so the server-side replay-key
// space is partitioned cleanly per credential.
func TestSessionIDCache_DistinctServerOrShortIDAreIndependent(t *testing.T) {
	cache := newSessionIDCache()
	cache.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	// rng is deterministic but advances per Read; consecutive entries get
	// disjoint byte windows.
	cache.rng = newFixedRNG([]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
		0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
	})

	shortA := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	shortB := [shortIDLen]byte{9, 9, 9, 9, 9, 9, 9, 9}

	a, err := cache.Acquire("alpha:443", shortA)
	if err != nil {
		t.Fatalf("Acquire alpha/A: %v", err)
	}
	b, err := cache.Acquire("beta:443", shortA)
	if err != nil {
		t.Fatalf("Acquire beta/A: %v", err)
	}
	c, err := cache.Acquire("alpha:443", shortB)
	if err != nil {
		t.Fatalf("Acquire alpha/B: %v", err)
	}
	if bytes.Equal(a[:stableRandomLen], b[:stableRandomLen]) {
		t.Fatalf("distinct server should yield distinct stable prefix")
	}
	if bytes.Equal(a[:stableRandomLen], c[:stableRandomLen]) {
		t.Fatalf("distinct shortID should yield distinct stable prefix")
	}
}

// TestSessionIDCache_TTLExpiryReseeds: after the entry expires the next
// Acquire reseeds with fresh bytes from rng — ensures we don't outlive a real
// browser ticket lifetime indefinitely.
func TestSessionIDCache_TTLExpiryReseeds(t *testing.T) {
	cache := newSessionIDCache()
	currentTime := time.Unix(1_700_000_000, 0)
	cache.now = func() time.Time { return currentTime }
	cache.rng = newFixedRNG([]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // entry 1 random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // entry 1 TTL jitter
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, // entry 2 random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, // entry 2 TTL jitter
	})

	server := "tamizdat.example:443"
	short := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}

	first, err := cache.Acquire(server, short)
	if err != nil {
		t.Fatalf("Acquire pre-expiry: %v", err)
	}
	// Skip well past TTLMax to force reseed.
	currentTime = currentTime.Add(sessionIDCacheTTLMax + time.Hour)
	second, err := cache.Acquire(server, short)
	if err != nil {
		t.Fatalf("Acquire post-expiry: %v", err)
	}
	if bytes.Equal(first[:stableRandomLen], second[:stableRandomLen]) {
		t.Fatalf("TTL expiry should reseed stable prefix; first=%x second=%x", first[:stableRandomLen], second[:stableRandomLen])
	}
}

// TestSessionIDCache_RNGFailureSurfaces: rng read errors propagate to caller
// instead of silently returning a zero nonce.
func TestSessionIDCache_RNGFailureSurfaces(t *testing.T) {
	cache := newSessionIDCache()
	cache.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	cache.rng = failingRNG{}

	short := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	_, err := cache.Acquire("tamizdat.example:443", short)
	if err == nil {
		t.Fatal("expected error on rng failure, got nil")
	}
}

// TestSessionIDCache_ConcurrentAcquireUniqueCounters: spawn N goroutines that
// each Acquire the same (server, shortID) M times. All N*M observed counter
// values must be unique — atomicity is provided by the cache's internal
// mutex around the bump-and-emit.
func TestSessionIDCache_ConcurrentAcquireUniqueCounters(t *testing.T) {
	cache := newSessionIDCache()
	cache.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	// Use the real RNG — concurrency, not determinism, is what we are
	// stressing here.

	server := "tamizdat.example:443"
	short := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}

	const goroutines = 8
	const perGoroutine = 64

	var seenMu sync.Mutex
	seen := make(map[uint16]struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				nonce, err := cache.Acquire(server, short)
				if err != nil {
					errCh <- err
					return
				}
				seenMu.Lock()
				ctr := binary.BigEndian.Uint16(nonce[stableRandomLen:])
				if _, dup := seen[ctr]; dup {
					seenMu.Unlock()
					errCh <- io.ErrUnexpectedEOF // marker; actual cause logged below
					t.Errorf("duplicate counter %d", ctr)
					return
				}
				seen[ctr] = struct{}{}
				seenMu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("concurrent Acquire: %v", err)
		}
	}
	if got, want := len(seen), goroutines*perGoroutine; got != want {
		t.Fatalf("unique counters seen=%d want=%d", got, want)
	}
}
