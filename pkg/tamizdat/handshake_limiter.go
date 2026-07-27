package tamizdat

import (
	"container/list"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var ErrHandshakeRateLimited = errors.New("tamizdat: handshake rate limited")

const (
	defaultHandshakeLimit  = 3
	defaultHandshakeWindow = 20 * time.Second
	clientLimiterMapCap    = 1024
	waitJitterMaxMs        = 200
)

type handshakeLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	events  map[string][]time.Time
	lruList *list.List
	lruIdx  map[string]*list.Element
	mapCap  int
}

func newHandshakeLimiter() *handshakeLimiter {
	return newHandshakeLimiterWithConfig(defaultHandshakeLimit, defaultHandshakeWindow)
}

func newHandshakeLimiterWithConfig(limit int, window time.Duration) *handshakeLimiter {
	if limit <= 0 {
		limit = defaultHandshakeLimit
	}
	if window <= 0 {
		window = defaultHandshakeWindow
	}
	return &handshakeLimiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		events:  make(map[string][]time.Time),
		lruList: list.New(),
		lruIdx:  make(map[string]*list.Element),
		mapCap:  clientLimiterMapCap,
	}
}

func (l *handshakeLimiter) Wait(ctx context.Context, key string) error {
	if l == nil {
		return nil
	}
	if key == "" {
		key = "default"
	}
	for {
		wait := l.reserveOrDelay(key)
		if wait <= 0 {
			return nil
		}
		// J-RR-1: add random [0, waitJitterMaxMs] ms jitter so the redial
		// cadence after a rate-limit kick is not a deterministic 20-second
		// metronome (censor signature).
		wait += time.Duration(cryptoRandIntn(waitJitterMaxMs+1)) * time.Millisecond
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrHandshakeRateLimited
		case <-timer.C:
		}
	}
}

func (l *handshakeLimiter) reserveOrDelay(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.currentTime()
	cutoff := now.Add(-l.window)
	events := l.events[key]
	keep := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) < l.limit {
		l.events[key] = append(keep, now)
		l.touchLRULocked(key)
		return 0
	}
	// Limit hit: keep events list trimmed but unchanged in length, and bump LRU
	// so the active key isn't a stale eviction candidate.
	l.events[key] = keep
	l.touchLRULocked(key)
	oldest := keep[0]
	wait := oldest.Add(l.window).Sub(now)
	if wait < 0 {
		return 0
	}
	return wait
}

// touchLRULocked moves key to MRU position; if the map exceeds cap it evicts
// the least-recently-touched key. Caller must hold l.mu.
func (l *handshakeLimiter) touchLRULocked(key string) {
	if elem, ok := l.lruIdx[key]; ok {
		l.lruList.MoveToFront(elem)
		return
	}
	elem := l.lruList.PushFront(key)
	l.lruIdx[key] = elem
	for l.lruList.Len() > l.mapCap {
		tail := l.lruList.Back()
		if tail == nil {
			break
		}
		evict := tail.Value.(string)
		l.lruList.Remove(tail)
		delete(l.lruIdx, evict)
		delete(l.events, evict)
	}
}

func (l *handshakeLimiter) currentTime() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// cryptoRandIntn returns a uniformly random int in [0, n) using crypto/rand.
// On read failure (extremely unlikely) it falls back to 0 so jitter is
// degraded-but-safe rather than panicking the calling goroutine.
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}
