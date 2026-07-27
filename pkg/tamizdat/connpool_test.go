package tamizdat

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnPoolMaxTransportsCap(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(1, time.Minute, 1, 2, 0, -1, func(ctx context.Context) (*h2Transport, error) {
		created.Add(1)
		return &h2Transport{maxStreams: 1}, nil
	})
	defer pool.close()

	if _, err := pool.getTransport(context.Background()); err != nil {
		t.Fatalf("first getTransport: %v", err)
	}
	if _, err := pool.getTransport(context.Background()); err != nil {
		t.Fatalf("second getTransport: %v", err)
	}
	_, err := pool.getTransport(context.Background())
	if err == nil || !strings.Contains(err.Error(), "MaxTransports") {
		t.Fatalf("third getTransport err = %v, want MaxTransports cap", err)
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created = %d, want 2", got)
	}
}

func TestConnPoolTopUpRespectsMaxTransports(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(100, time.Minute, 3, 3, 0, -1, func(ctx context.Context) (*h2Transport, error) {
		created.Add(1)
		return &h2Transport{maxStreams: 100}, nil
	})
	defer pool.close()
	pool.maxTransports = 2 // exercise topUp's cap branch directly.

	pool.topUp()
	pool.mu.Lock()
	got := len(pool.transports)
	pool.mu.Unlock()
	if got != 2 {
		t.Fatalf("topUp transports = %d, want 2", got)
	}
	if created.Load() != 2 {
		t.Fatalf("created = %d, want 2", created.Load())
	}
}

func TestConnPoolResizeTopUpsImmediately(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(100, time.Minute, 1, 1, 0, -1, func(ctx context.Context) (*h2Transport, error) {
		created.Add(1)
		return &h2Transport{maxStreams: 100}, nil
	})
	defer pool.close()

	pool.resize(3, 3)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		got := len(pool.transports)
		pool.mu.Unlock()
		if got == 3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	pool.mu.Lock()
	got := len(pool.transports)
	pool.mu.Unlock()
	t.Fatalf("resize top-up transports = %d, want 3 (created=%d)", got, created.Load())
}

func TestConnPoolResizeShrinksIdleTransportsImmediately(t *testing.T) {
	pool := newConnPool(100, time.Minute, 4, 4, 0, -1, func(ctx context.Context) (*h2Transport, error) {
		return &h2Transport{maxStreams: 100}, nil
	})
	defer pool.close()
	pool.mu.Lock()
	pool.transports = []*h2Transport{
		{maxStreams: 100},
		{maxStreams: 100},
		{maxStreams: 100},
		{maxStreams: 100},
	}
	pool.mu.Unlock()

	pool.resize(2, 2)

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if got := len(pool.transports); got != 2 {
		t.Fatalf("transports after shrink = %d, want 2", got)
	}
	for i, tr := range pool.transports {
		if tr.isClosed() || tr.isDraining() {
			t.Fatalf("kept transport %d closed/draining", i)
		}
	}
}

func TestConnPoolResizeDrainsBusyExcessTransports(t *testing.T) {
	pool := newConnPool(100, time.Minute, 4, 4, 0, -1, func(ctx context.Context) (*h2Transport, error) {
		return &h2Transport{maxStreams: 100}, nil
	})
	defer pool.close()
	busy1 := &h2Transport{maxStreams: 100}
	busy2 := &h2Transport{maxStreams: 100}
	if !busy1.reserveStreamSlot() || !busy2.reserveStreamSlot() {
		t.Fatal("reserve busy stream slots")
	}
	pool.mu.Lock()
	pool.transports = []*h2Transport{
		{maxStreams: 100},
		{maxStreams: 100},
		busy1,
		busy2,
	}
	pool.mu.Unlock()

	pool.resize(2, 2)

	pool.mu.Lock()
	defer pool.mu.Unlock()
	usable := 0
	for _, tr := range pool.transports {
		if !tr.isClosed() && !tr.isDraining() {
			usable++
		}
	}
	if usable != 2 {
		t.Fatalf("usable transports after shrink = %d, want 2", usable)
	}
	if !busy1.isDraining() || !busy2.isDraining() {
		t.Fatalf("busy excess transports should drain: busy1=%v busy2=%v", busy1.isDraining(), busy2.isDraining())
	}
}

func TestRandomizedBytesSoftCapRangeAndVaries(t *testing.T) {
	const base = int64(13312)
	seen := make(map[int64]struct{})
	for i := 0; i < 100; i++ {
		cap := randomizedBytesSoftCap(base)
		if cap < base || cap > base+1536 {
			t.Fatalf("cap %d outside [%d,%d]", cap, base, base+1536)
		}
		seen[cap] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("randomized caps did not vary: %v", seen)
	}
}
