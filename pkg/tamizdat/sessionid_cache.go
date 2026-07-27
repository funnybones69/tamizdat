package tamizdat

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// sessionIDCacheTTL is the per-entry validity window for a (server_addr, shortID)
// stable-random-6 cache entry. Real Chrome reuses its session-ticket-derived
// SessionID across reconnects until the ticket lifetime expires, typically in
// the 30 min - 2 hour band. Per-entry TTL is randomized in
// [sessionIDCacheTTLMin, sessionIDCacheTTLMax] to avoid a synchronized-expiry
// tell where every entry rolls over together.
const (
	sessionIDCacheTTLMin = 30 * time.Minute
	sessionIDCacheTTLMax = 120 * time.Minute
	// stableRandomLen is how many bytes of the 8-byte SessionID nonce field
	// stay stable across reconnects (per-cache-entry). The remaining
	// 8-stableRandomLen = 2 bytes are a uint16-be counter incremented
	// per-dial so the replay-key (SHA-256(SessionID || eph_pub)[:16]) stays
	// unique across dials. 6+2 split balances entropy in the stable prefix
	// (48 bits) with a counter range of 65536 dials per (server, shortID)
	// per cache lifetime.
	stableRandomLen = 6
	counterLen      = nonceLen - stableRandomLen
)

// sessionIDCacheKey is the cache lookup key — a (server_addr, shortID) tuple.
// Distinct servers and distinct shortIDs MUST get distinct stable randoms so
// that the server-side replay-key bucket is keyed cleanly per-credential.
type sessionIDCacheKey struct {
	ServerAddr string
	ShortID    [shortIDLen]byte
}

type sessionIDCacheEntry struct {
	// stableRandom is the 6-byte prefix that survives across reconnects.
	stableRandom [stableRandomLen]byte
	// counter is the per-dial monotonic counter; bumped atomically on
	// every Acquire. Wraps at 65535 — when the counter would overflow we
	// roll the stableRandom (re-seed the entry) so the SessionID stays
	// unique on the wire.
	counter uint16
	// expiresAt is the wall-clock time at which the entry must be
	// re-seeded. Randomized at insert time in [TTLMin, TTLMax] so multiple
	// entries do not roll over in lock-step.
	expiresAt time.Time
}

// sessionIDCache is a small bounded LRU-ish cache that hands out 8-byte
// nonces composed of a stable 6-byte random plus a 2-byte counter, keyed by
// (server_addr, shortID).
//
// Thread-safety: all methods take an internal mutex. Concurrent dials from
// the same Client to the same (server, shortID) get distinct counter values
// — atomicity is provided by the lock around the bump.
type sessionIDCache struct {
	mu      sync.Mutex
	entries map[sessionIDCacheKey]*sessionIDCacheEntry
	now     func() time.Time
	// rng is the entropy source for stable-random bytes and TTL jitter.
	// Tests override with a deterministic reader.
	rng io.Reader
}

// newSessionIDCache returns a fresh cache. now and rng are normally
// time.Now / rand.Reader; tests override.
func newSessionIDCache() *sessionIDCache {
	return &sessionIDCache{
		entries: make(map[sessionIDCacheKey]*sessionIDCacheEntry),
		now:     time.Now,
		rng:     rand.Reader,
	}
}

// Acquire returns the 8-byte nonce to embed in the next SessionIDv2 dial
// for (server_addr, shortID). Layout: stable_random_6 || counter_uint16_be.
// Side-effect: bumps the counter atomically so two concurrent dials never
// see the same counter value.
//
// Errors out only on rng failure (rand.Read), which on production is
// fatal anyway — caller can fall back to v1 or fail the dial.
func (c *sessionIDCache) Acquire(serverAddr string, shortID [shortIDLen]byte) ([nonceLen]byte, error) {
	var nonce [nonceLen]byte
	c.mu.Lock()
	defer c.mu.Unlock()

	key := sessionIDCacheKey{ServerAddr: serverAddr, ShortID: shortID}
	entry, ok := c.entries[key]
	now := c.now()
	needReseed := !ok || now.After(entry.expiresAt) || entry.counter == ^uint16(0)
	if needReseed {
		newEntry := &sessionIDCacheEntry{}
		if _, err := io.ReadFull(c.rng, newEntry.stableRandom[:]); err != nil {
			return nonce, err
		}
		ttl, err := c.randomTTL()
		if err != nil {
			return nonce, err
		}
		newEntry.expiresAt = now.Add(ttl)
		entry = newEntry
		c.entries[key] = entry
	}

	copy(nonce[:stableRandomLen], entry.stableRandom[:])
	binary.BigEndian.PutUint16(nonce[stableRandomLen:], entry.counter)
	entry.counter++
	return nonce, nil
}

// PeekStableRandom returns the cached 6-byte stable prefix for
// (server_addr, shortID), or false if no entry exists / it has expired.
// Used by tests to assert that two consecutive Acquire calls within TTL
// share the same stable random.
func (c *sessionIDCache) PeekStableRandom(serverAddr string, shortID [shortIDLen]byte) ([stableRandomLen]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero [stableRandomLen]byte
	entry, ok := c.entries[sessionIDCacheKey{ServerAddr: serverAddr, ShortID: shortID}]
	if !ok {
		return zero, false
	}
	if c.now().After(entry.expiresAt) {
		return zero, false
	}
	return entry.stableRandom, true
}

// Forget drops the cache entry for (server_addr, shortID). Used when the
// server reports a hard reject so the next dial reseeds.
func (c *sessionIDCache) Forget(serverAddr string, shortID [shortIDLen]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, sessionIDCacheKey{ServerAddr: serverAddr, ShortID: shortID})
}

// randomTTL picks a TTL in [TTLMin, TTLMax]. Read 8 bytes of entropy and
// reduce; not a security-critical RNG, just spreads expiry across cache
// instances.
func (c *sessionIDCache) randomTTL() (time.Duration, error) {
	var b [8]byte
	if _, err := io.ReadFull(c.rng, b[:]); err != nil {
		return 0, err
	}
	span := uint64(sessionIDCacheTTLMax - sessionIDCacheTTLMin)
	if span == 0 {
		return sessionIDCacheTTLMin, nil
	}
	jitter := time.Duration(binary.BigEndian.Uint64(b[:]) % span)
	return sessionIDCacheTTLMin + jitter, nil
}
