package tamizdat

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// review-A P3: after Register + a brief settle window, the pool should
// fill to its configured size against a real loopback listener.
func TestPrewarmedPoolFillsAfterStartup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	pool := newPrewarmedPool(3, 30*time.Second, nil)
	defer pool.Close()
	pool.Register(ln.Addr().String())

	if !waitForPoolSize(pool, ln.Addr().String(), 3, time.Second) {
		t.Fatalf("pool did not fill within 1s: stats = %v", pool.stats())
	}
}

// review-A P3: Take returns one of the prewarmed conns when the pool has
// inventory. The dialer counter should NOT increment on the take itself
// (it incremented during fill).
func TestPrewarmedPoolTakeReturnsPrewarmConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	var dials atomic.Int64
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		d := net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	pool := newPrewarmedPool(3, 30*time.Second, dialer)
	defer pool.Close()
	pool.Register(ln.Addr().String())

	if !waitForPoolSize(pool, ln.Addr().String(), 3, time.Second) {
		t.Fatalf("pool did not fill: stats = %v", pool.stats())
	}
	dialsAfterFill := dials.Load()

	conn, err := pool.Take(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	defer conn.Close()
	if got := dials.Load(); got != dialsAfterFill {
		t.Errorf("Take from full pool dialed extra %d times (was %d, now %d)", got-dialsAfterFill, dialsAfterFill, got)
	}
	if pool.stats()[ln.Addr().String()] >= 3 {
		t.Errorf("pool size did not decrement after Take: %v", pool.stats())
	}
}

// review-A P3: Take falls back to a fresh dial when the origin is not
// registered.
func TestPrewarmedPoolTakeUnregisteredFallsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	var dials atomic.Int64
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		d := net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	pool := newPrewarmedPool(3, 30*time.Second, dialer)
	defer pool.Close()
	// NOT registering ln.Addr() — Take should fall back.

	conn, err := pool.Take(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Take fallback dial failed: %v", err)
	}
	defer conn.Close()
	if dials.Load() != 1 {
		t.Errorf("expected exactly 1 fallback dial, got %d", dials.Load())
	}
}

// review-A P3: Take falls back to a fresh dial when the registered
// origin's pool is empty (e.g. mid-burst between refills).
func TestPrewarmedPoolEmptyChannelFallsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	var dials atomic.Int64
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		d := net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	pool := newPrewarmedPool(3, 30*time.Second, dialer)
	defer pool.Close()
	pool.Register(ln.Addr().String())

	if !waitForPoolSize(pool, ln.Addr().String(), 3, time.Second) {
		t.Fatalf("pool did not fill: stats = %v", pool.stats())
	}
	// Drain.
	for i := 0; i < 5; i++ {
		c, err := pool.Take(context.Background(), ln.Addr().String())
		if err != nil {
			t.Fatalf("Take %d: %v", i, err)
		}
		_ = c.Close()
	}
	// We've taken at least 5 conns total. dials must reflect both the
	// initial fill (3) and at least 2 fallback dials post-drain.
	if got := dials.Load(); got < 5 {
		t.Errorf("expected at least 5 dials after draining + fallback, got %d", got)
	}
}

// review-A P3: stale conns past maxAge are dropped, not returned. Use a
// 50ms maxAge and sleep past it.
func TestPrewarmedPoolDropsStaleConns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	var dials atomic.Int64
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		d := net.Dialer{Timeout: time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	pool := newPrewarmedPool(3, 50*time.Millisecond, dialer)
	defer pool.Close()
	pool.Register(ln.Addr().String())

	if !waitForPoolSize(pool, ln.Addr().String(), 1, time.Second) {
		t.Fatalf("pool did not fill: stats = %v", pool.stats())
	}
	dialsAfterFill := dials.Load()

	// Sleep past maxAge so all parked conns are stale.
	time.Sleep(120 * time.Millisecond)

	// Take should drop the stale conns and dial fresh.
	conn, err := pool.Take(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	_ = conn.Close()
	if dials.Load() <= dialsAfterFill {
		t.Errorf("Take did not fall back to fresh dial despite stale pool entries (dials before=%d after=%d)", dialsAfterFill, dials.Load())
	}
}

// review-A P3: Close drains the channels and shuts down replenishers.
func TestPrewarmedPoolCloseDrains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	pool := newPrewarmedPool(3, 30*time.Second, nil)
	pool.Register(ln.Addr().String())
	if !waitForPoolSize(pool, ln.Addr().String(), 1, time.Second) {
		t.Fatalf("pool did not fill: stats = %v", pool.stats())
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := pool.stats(); len(got) != 0 {
		t.Errorf("origins map not emptied after Close: %v", got)
	}
	// Idempotent.
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// review-A P3: concurrent Take + replenisher activity must be race-clean.
// We spam Take from many goroutines while the pool is filling.
func TestPrewarmedPoolConcurrentTakeIsRaceClean(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptForever(ln)

	pool := newPrewarmedPool(5, 30*time.Second, nil)
	defer pool.Close()
	pool.Register(ln.Addr().String())

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				c, err := pool.Take(ctx, ln.Addr().String())
				cancel()
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						continue
					}
					return
				}
				_ = c.Close()
			}
		}()
	}
	wg.Wait()
}

// review-A P3: nil DialOrigin keeps the legacy direct-dial path on
// Masquerade.proxyTo. Assert that NewMasquerade leaves DialOrigin nil so
// embedded callers without server pre-warm still work as before.
func TestMasqueradeDialOriginNilPreservesLegacyPath(t *testing.T) {
	m := NewMasquerade("ok.ru", "", 0, 0)
	if m.DialOrigin != nil {
		t.Fatal("NewMasquerade installed a DialOrigin hook by default; legacy callers expect nil")
	}
}

// acceptForever keeps accepting and immediately reading from connections
// so the kernel doesn't reset our prewarm conns mid-test.
func acceptForever(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			for {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}(c)
	}
}

// waitForPoolSize blocks until the named origin's channel reaches `want`
// or `budget` elapses. Returns true if the size was reached.
func waitForPoolSize(p *prewarmedPool, origin string, want int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if p.stats()[origin] >= want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
