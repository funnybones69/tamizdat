package tamizdat

import (
	"container/list"
	"sync"
	"time"
)

// shortIDLimiter is a server-side per-shortid token-bucket rate limiter that
// gates the expensive PSK-derive + HMAC-verify path. It is consulted in
// Server.handleConnection AFTER the 8-byte SessionID prefix is parsed but
// BEFORE PSK derivation, so a flood of bogus ClientHellos cannot drive
// the server's CPU budget at curve25519 cost per packet.
//
// Why per-shortid instead of per-source-IP (the original review-D-2
// formulation): tamizdat is fronted by haproxy/nginx and PROXY-protocol
// passthrough is not configured for production deployments, so all
// inbound connections look like they originate from a single haproxy
// IP. A per-IP cap would either be useless (one bucket for the entire
// upstream LB) or actively harmful (block legitimate users behind the
// same LB). Per-shortid is the natural level of attribution we already
// have at the point we make this decision.
//
// Properties:
//   - Bogus shortids: each random 8-byte candidate seeds its own bucket
//     with `burst` tokens. The attacker's first attempt succeeds (they
//     fall through to PSK derive + HMAC verify, which fails harmlessly
//     and bills one curve25519 op), but the bucket is then evicted by
//     LRU long before it could be re-used. Memory is bounded at
//     `capacity` entries (default 65536 -- same as replay_guard's
//     hard cap).
//   - Spammed-known-shortid: legitimate shortid replayed thousands of
//     times per second hits the bucket cap fast (~burst tokens immediate,
//     then `rate` tokens/sec sustained). Real users dial maybe 20/min
//     in heavy news-site browsing, so the ceiling is well above the
//     legitimate ceiling.
//   - Concurrent legitimate users sharing one source IP: each has their
//     own shortid -> own bucket -> no false-positive blocking.
type shortIDLimiter struct {
	mu       sync.Mutex
	buckets  map[[8]byte]*shortIDBucketEntry
	lruList  *list.List // *list.Element holds [8]byte key; front = most recent
	capacity int
	rate     float64 // tokens / second
	burst    float64
	now      func() time.Time
}

type shortIDBucketEntry struct {
	tokens   float64
	lastFill time.Time
	elem     *list.Element // back-pointer into lruList for O(1) move-to-front
}

const (
	// 100 dials per minute = 5/3 per second. Real-user browsing in
	// fontanka.ru-class news sites peaks at ~20 connections/minute when
	// the cold pool is filling; 100/min sustained is comfortably above
	// any legitimate workload but well below an attacker rate of
	// thousands/sec.
	defaultShortIDLimiterRate float64 = 100.0 / 60.0
	// Allow brief flurries during page load without paying refill latency.
	defaultShortIDLimiterBurst float64 = 20
	// Same memory bound as replay_guard.go's hard cap.
	defaultShortIDLimiterCapacity = 65536
)

func newShortIDLimiter() *shortIDLimiter {
	return newShortIDLimiterWithConfig(defaultShortIDLimiterRate, defaultShortIDLimiterBurst, defaultShortIDLimiterCapacity)
}

func newShortIDLimiterWithConfig(rate, burst float64, capacity int) *shortIDLimiter {
	if rate <= 0 {
		rate = defaultShortIDLimiterRate
	}
	if burst <= 0 {
		burst = defaultShortIDLimiterBurst
	}
	if capacity <= 0 {
		capacity = defaultShortIDLimiterCapacity
	}
	return &shortIDLimiter{
		buckets:  make(map[[8]byte]*shortIDBucketEntry),
		lruList:  list.New(),
		capacity: capacity,
		rate:     rate,
		burst:    burst,
		now:      time.Now,
	}
}

// Allow refills the bucket for shortID at the configured rate (capped at
// burst), consumes one token, and returns true when consumption succeeds.
// A false return means the rate cap has been hit and the caller should
// reject the handshake (without paying PSK derivation cost).
//
// Safe under concurrent goroutines.
func (l *shortIDLimiter) Allow(shortID [8]byte) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.currentTime()
	entry, ok := l.buckets[shortID]
	if !ok {
		// New bucket: seed with `burst-1` tokens (one consumed for this
		// request) so a single-shot probe always succeeds and the bucket
		// then drains naturally if abused.
		entry = &shortIDBucketEntry{
			tokens:   l.burst - 1,
			lastFill: now,
		}
		entry.elem = l.lruList.PushFront(shortID)
		l.buckets[shortID] = entry
		l.evictLocked()
		return true
	}

	// Refill: linear since lastFill, capped at burst.
	elapsed := now.Sub(entry.lastFill).Seconds()
	if elapsed > 0 {
		entry.tokens += elapsed * l.rate
		if entry.tokens > l.burst {
			entry.tokens = l.burst
		}
		entry.lastFill = now
	}

	// Touch LRU (move-to-front) so this bucket is least likely to be evicted.
	l.lruList.MoveToFront(entry.elem)

	if entry.tokens >= 1 {
		entry.tokens -= 1
		return true
	}
	// Empty: cap hit. Do not refund; refill will resume on the next
	// Allow call after time passes.
	return false
}

// evictLocked drops the least-recently-used entries until len(buckets) <= capacity.
// Called only from Allow with l.mu held.
func (l *shortIDLimiter) evictLocked() {
	for len(l.buckets) > l.capacity {
		back := l.lruList.Back()
		if back == nil {
			return
		}
		key := back.Value.([8]byte)
		l.lruList.Remove(back)
		delete(l.buckets, key)
	}
}

func (l *shortIDLimiter) currentTime() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *shortIDLimiter) size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
