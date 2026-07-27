package tamizdat

import (
	"context"
	"net"
	"sync"
	"time"
)

// review-A P3: pre-warmed connection pool to masquerade origins.
//
// Without pre-warm, each rate-limit-passed probe pays the TCP-SYN RTT
// (5..25 ms on RU mobile networks, occasionally 100+ ms on cold paths)
// to dial the cover origin. That latency floor makes auth-fail vs
// auth-OK timing distinguishable to a probe-timing attacker. Pre-warming
// keeps a small bank of already-established TCP connections per origin;
// a forward gets to skip the SYN.
//
// Design:
//   - poolSize conns per origin in a buffered channel
//   - Per-origin replenisher goroutine spawns fresh dials when the
//     channel falls below capacity; periodic refresh on a 1-second tick.
//   - Conns are tagged with insertion time; on take we drop those older
//     than maxAge so we never hand out a stale half-open conn that the
//     origin already closed.
//   - Take is non-blocking: if the pool is empty (or only holds stale
//     conns) we fall back to a fresh DialContext.
//   - Close drains all channels and closes everything in flight.

// prewarmConn pairs a connection with the timestamp it was inserted into
// the pool, so Take can drop conns past maxAge.
type prewarmConn struct {
	conn   net.Conn
	bornAt time.Time
}

// prewarmedPool keeps a fixed-size bank of TCP connections per origin.
// Origin keys are typically "host:port" so they're directly dial-able.
type prewarmedPool struct {
	poolSize int
	maxAge   time.Duration
	dialer   func(ctx context.Context, addr string) (net.Conn, error)

	mu      sync.Mutex
	origins map[string]chan *prewarmConn

	// stop signals all replenisher goroutines to exit. closeOnce ensures
	// Close is idempotent.
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// newPrewarmedPool constructs a pool with the given per-origin slot count
// and stale-conn max age. dialer is the dial primitive used for refills;
// pass nil to use the default tamizdat dialer.
func newPrewarmedPool(poolSize int, maxAge time.Duration, dialer func(ctx context.Context, addr string) (net.Conn, error)) *prewarmedPool {
	if poolSize <= 0 {
		poolSize = 3
	}
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	if dialer == nil {
		dialer = defaultPrewarmDialer
	}
	return &prewarmedPool{
		poolSize: poolSize,
		maxAge:   maxAge,
		dialer:   dialer,
		origins:  make(map[string]chan *prewarmConn),
		stop:     make(chan struct{}),
	}
}

// defaultPrewarmDialer is the fallback dialer used when the operator does
// not supply one. 5-second per-dial budget matches the TCP retransmit
// envelope on shaky mobile-RU paths without holding the replenisher
// goroutine forever.
func defaultPrewarmDialer(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// Register adds an origin key to the pool and starts its replenisher.
// Calling Register on the same origin twice is a no-op. Origins not
// registered fall through to direct-dial in Take.
func (p *prewarmedPool) Register(origin string) {
	if origin == "" {
		return
	}
	p.mu.Lock()
	if _, exists := p.origins[origin]; exists {
		p.mu.Unlock()
		return
	}
	ch := make(chan *prewarmConn, p.poolSize)
	p.origins[origin] = ch
	p.mu.Unlock()

	p.wg.Add(1)
	go p.replenisher(origin, ch)
}

// replenisher keeps the per-origin channel topped up. It refills on a
// 1-second cadence — frequent enough that a take-then-burst pattern
// recovers quickly, infrequent enough that a dead origin doesn't pin
// the goroutine in a tight dial loop.
func (p *prewarmedPool) replenisher(origin string, ch chan *prewarmConn) {
	defer p.wg.Done()

	// Initial fill.
	p.fill(origin, ch)

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.fill(origin, ch)
		}
	}
}

// fill tries to bring the channel up to poolSize. Each missing slot gets
// one dial attempt per tick — failures bail this tick to avoid hammering
// a downed origin. Returns early on shutdown.
func (p *prewarmedPool) fill(origin string, ch chan *prewarmConn) {
	for {
		// Capacity check before dialing so we don't burn a SYN we'd just
		// throw away.
		if len(ch) >= cap(ch) {
			return
		}
		// Bail before each dial if shutdown raced.
		select {
		case <-p.stop:
			return
		default:
		}
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := p.dialer(dialCtx, origin)
		cancel()
		if err != nil {
			// Failed dial → leave the slot empty, try again next tick.
			return
		}
		select {
		case ch <- &prewarmConn{conn: conn, bornAt: time.Now()}:
		default:
			// Channel raced full between len() check and send — close the
			// excess conn rather than leak it.
			_ = conn.Close()
			return
		}
	}
}

// Take returns a pre-warmed conn for `origin` if one is available and
// fresh, otherwise dials a new one. ctx bounds the fallback dial.
func (p *prewarmedPool) Take(ctx context.Context, origin string) (net.Conn, error) {
	p.mu.Lock()
	ch, ok := p.origins[origin]
	p.mu.Unlock()

	if ok {
		now := time.Now()
		// Drain stale entries non-blockingly. Loop exits via the default
		// branch when the channel is empty.
		for {
			select {
			case pw := <-ch:
				if now.Sub(pw.bornAt) > p.maxAge {
					_ = pw.conn.Close()
					continue
				}
				return pw.conn, nil
			default:
				return p.dialer(ctx, origin)
			}
		}
	}

	return p.dialer(ctx, origin)
}

// Close drains every per-origin channel and closes all conns in flight.
// Idempotent; safe to call multiple times.
func (p *prewarmedPool) Close() error {
	p.closeOnce.Do(func() {
		close(p.stop)
	})
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	for origin, ch := range p.origins {
		drainPrewarmChannel(ch)
		delete(p.origins, origin)
	}
	return nil
}

// drainPrewarmChannel non-blockingly closes every conn left in ch.
func drainPrewarmChannel(ch chan *prewarmConn) {
	for {
		select {
		case pw := <-ch:
			_ = pw.conn.Close()
		default:
			return
		}
	}
}

// stats returns (origin, count) pairs for diagnostic use. Only used by
// tests and the optional Debug expvar; not on the hot path.
func (p *prewarmedPool) stats() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.origins))
	for origin, ch := range p.origins {
		out[origin] = len(ch)
	}
	return out
}
