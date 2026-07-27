package tamizdat

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// review-A A-RR-2: shadowDialOrigin must target the SAME origin that the
// masquerade-forward path would use for a given probe SNI. Otherwise a
// probe with SNI=ya.ru would shadow-dial the default origin (e.g. ok.ru)
// while the failure path would forward to ya.ru — the resulting RTT
// divergence between auth-success and auth-fail paths is exactly the
// timing oracle the shadow dial is meant to close.
//
// Setup: two listeners (default origin + pool-mapped origin), each
// counting accepted connections. Server is configured with
// MasqueradeAddr=defaultLn, MasqueradePool={"ya.ru": poolLn}. We invoke
// shadowDialOrigin with SNI="ya.ru" and assert the pool listener saw
// the dial, default did not.
func TestShadowDialOriginUsesPoolForKnownSNI(t *testing.T) {
	defaultDials, defaultStop := countingListener(t)
	defer defaultStop()
	poolDials, poolStop := countingListener(t)
	defer poolStop()

	srv := newShadowDialTestServer(t, ShadowDialPoolFixture{
		DefaultAddr: defaultDials.addr,
		PoolEntries: map[string]string{"ya.ru": poolDials.addr},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.shadowDialOrigin(ctx, "ya.ru")

	// Pool origin must have observed exactly one dial; default origin none.
	if got := poolDials.waitForDial(time.Second); !got {
		t.Fatal("shadow dial did not hit pool-mapped origin for SNI=ya.ru")
	}
	if hits := atomic.LoadInt64(defaultDials.count); hits != 0 {
		t.Errorf("default origin received %d unexpected dials", hits)
	}
}

// A-RR-2 case-insensitive: probe with SNI=YA.RU still hits the pool
// origin. Inherits A-RR-1 case-fold via lookupMasqueradeOrigin.
func TestShadowDialOriginUsesPoolCaseInsensitive(t *testing.T) {
	defaultDials, defaultStop := countingListener(t)
	defer defaultStop()
	poolDials, poolStop := countingListener(t)
	defer poolStop()

	srv := newShadowDialTestServer(t, ShadowDialPoolFixture{
		DefaultAddr: defaultDials.addr,
		PoolEntries: map[string]string{"ya.ru": poolDials.addr},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.shadowDialOrigin(ctx, "YA.RU")

	if got := poolDials.waitForDial(time.Second); !got {
		t.Fatal("shadow dial did not hit pool-mapped origin for upper-case SNI")
	}
	if hits := atomic.LoadInt64(defaultDials.count); hits != 0 {
		t.Errorf("default origin received %d dials on case-permuted SNI", hits)
	}
}

// A-RR-2 fallback: probe with an SNI that does NOT match any pool entry
// must fall through to the default OriginAddr — we still want to absorb
// some RTT rather than skip the shadow dial entirely.
func TestShadowDialOriginFallsBackToDefaultOnUnknownSNI(t *testing.T) {
	defaultDials, defaultStop := countingListener(t)
	defer defaultStop()
	poolDials, poolStop := countingListener(t)
	defer poolStop()

	srv := newShadowDialTestServer(t, ShadowDialPoolFixture{
		DefaultAddr: defaultDials.addr,
		PoolEntries: map[string]string{"ya.ru": poolDials.addr},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.shadowDialOrigin(ctx, "completely-unknown.invalid")

	if got := defaultDials.waitForDial(time.Second); !got {
		t.Fatal("shadow dial did not fall back to default origin on unknown SNI")
	}
	if hits := atomic.LoadInt64(poolDials.count); hits != 0 {
		t.Errorf("pool origin received %d dials on unknown SNI", hits)
	}
}

// A-RR-2 empty SNI: when the buffered ClientHello had no SNI extension
// (parse returned ""), shadowDialOrigin must dial the default origin —
// preserving legacy P5-era behaviour for SNI-less probes.
func TestShadowDialOriginFallsBackToDefaultOnEmptySNI(t *testing.T) {
	defaultDials, defaultStop := countingListener(t)
	defer defaultStop()
	poolDials, poolStop := countingListener(t)
	defer poolStop()

	srv := newShadowDialTestServer(t, ShadowDialPoolFixture{
		DefaultAddr: defaultDials.addr,
		PoolEntries: map[string]string{"ya.ru": poolDials.addr},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.shadowDialOrigin(ctx, "")

	if got := defaultDials.waitForDial(time.Second); !got {
		t.Fatal("shadow dial did not fall back to default origin on empty SNI")
	}
	if hits := atomic.LoadInt64(poolDials.count); hits != 0 {
		t.Errorf("pool origin received %d dials on empty SNI", hits)
	}
}

// ShadowDialPoolFixture wires up just enough Server state for
// shadowDialOrigin to run without a full Serve loop.
type ShadowDialPoolFixture struct {
	DefaultAddr string
	PoolEntries map[string]string
}

func newShadowDialTestServer(t *testing.T, f ShadowDialPoolFixture) *Server {
	t.Helper()
	srv := &Server{
		config: ServerConfig{
			MasqueradePool: f.PoolEntries,
		},
		masquerade: &Masquerade{
			OriginAddr:  f.DefaultAddr,
			DialTimeout: 1 * time.Second,
		},
	}
	return srv
}

type countingLn struct {
	addr  string
	count *int64
	hit   chan struct{}
}

func (l *countingLn) waitForDial(d time.Duration) bool {
	select {
	case <-l.hit:
		return true
	case <-time.After(d):
		return false
	}
}

func countingListener(t *testing.T) (*countingLn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var n int64
	cl := &countingLn{
		addr:  ln.Addr().String(),
		count: &n,
		hit:   make(chan struct{}, 4),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&n, 1)
			select {
			case cl.hit <- struct{}{}:
			default:
			}
			_ = c.Close()
		}
	}()
	return cl, func() { _ = ln.Close() }
}
