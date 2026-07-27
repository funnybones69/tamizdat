package tamizdat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// connPool manages a pool of H2 transports to a server, tracking active
// stream counts and cleaning up idle connections.
//
// Design note (audit fix): the previous implementation closed any transport
// whose streamCount was 0 every 30 s regardless of the configured
// IdleTimeout. For a SOCKS5 client serving a browsing session (lots of
// short streams) this produced a cadence of TCP 443 reconnects — exactly
// the per-IP behaviour TSPU #546 polices. This version
//
//	(a) only reaps a zero-stream transport after it has been idle for
//	    IdleTimeout wallclock (default 5 m, set by ClientConfig), and
//	(b) uses a slower tick (60 s) so the pool does not itself emit a 30 s
//	    heartbeat signature.
var ErrPoolBackpressure = errors.New("tamizdat: pool at MaxTransports cap")

var poolDebugLog atomic.Bool

func poolLogf(format string, args ...any) {
	if poolDebugLog.Load() {
		log.Printf(format, args...)
	}
}

type connPool struct {
	mu          sync.Mutex
	transports  []*h2Transport
	maxStreams  int
	idleTimeout time.Duration
	createFunc  func(ctx context.Context) (*h2Transport, error)
	closed      bool
	closeCh     chan struct{}
	// Multi-conn fallback (#6 / compass P1.2):
	minTransports            int   // pre-warm + reaper target
	maxTransports            int   // hard cap on simultaneous transports
	creating                 int   // transports being dialed outside p.mu
	bytesSoftCap             int64 // close transport at outbound bytes >= cap (0=disabled)
	rotationOverlapAllowance int   // extra transient bulk slots while a capped transport drains
	roundRobin               int   // round-robin index into transports for getTransport
}

// newConnPool creates a connection pool that creates new transports via createFunc.
// minTransports >= 1: pre-warm pool and keep at least N transports alive
// (compass P1.2 multi-conn fallback against TSPU detector #490). bytesSoftCap
// > 0 marks a transport draining once outbound bytes cross threshold.
func newConnPool(maxStreams int, idleTimeout time.Duration, minTransports int, maxTransports int, bytesSoftCap int64, rotationOverlapAllowance int, createFunc func(ctx context.Context) (*h2Transport, error)) *connPool {
	if minTransports < 1 {
		minTransports = 1
	}
	if maxTransports == 0 {
		maxTransports = minTransports
	}
	if maxTransports < minTransports {
		maxTransports = minTransports
	}
	if rotationOverlapAllowance < 0 {
		if maxTransports == 1 && bytesSoftCap > 0 {
			rotationOverlapAllowance = 1
		} else {
			rotationOverlapAllowance = 0
		}
	}
	p := &connPool{
		maxStreams:               maxStreams,
		idleTimeout:              idleTimeout,
		createFunc:               createFunc,
		closeCh:                  make(chan struct{}),
		minTransports:            minTransports,
		maxTransports:            maxTransports,
		bytesSoftCap:             bytesSoftCap,
		rotationOverlapAllowance: rotationOverlapAllowance,
	}

	go p.cleanupLoop()
	go p.reaperLoop()

	return p
}

// resize updates the live pool's min/max transport target (2026-05-11
// server-authoritative pool variant). Increases top up immediately; shrinks
// close idle excess transports and drain busy excess transports so the new
// cap is reflected without waiting for the 60s cleanup tick.
func (p *connPool) resize(newMin, newMax int) {
	if newMin < 1 {
		newMin = 1
	}
	if newMax < newMin {
		newMax = newMin
	}
	p.mu.Lock()
	if p.minTransports == newMin && p.maxTransports == newMax {
		p.mu.Unlock()
		return
	}
	oldMin := p.minTransports
	oldMax := p.maxTransports
	p.minTransports = newMin
	p.maxTransports = newMax
	if newMax < oldMax {
		p.enforceMaxTransportsLocked()
	}
	p.updatePoolGaugesLocked()
	p.mu.Unlock()
	if newMin > oldMin || newMax > oldMax {
		go p.topUp()
	}
}

func (p *connPool) enforceMaxTransportsLocked() {
	if p.maxTransports < 1 {
		p.maxTransports = 1
	}
	usable := 0
	alive := make([]*h2Transport, 0, len(p.transports))
	for _, t := range p.transports {
		if t == nil || t.isClosed() {
			continue
		}
		if t.isDraining() {
			alive = append(alive, t)
			continue
		}
		if usable < p.maxTransports {
			usable++
			alive = append(alive, t)
			continue
		}
		if t.streamCount() == 0 {
			t.close()
			continue
		}
		t.markDraining()
		alive = append(alive, t)
	}
	p.transports = alive
}

// getTransport returns a transport with available capacity, creating a new
// one if needed within MaxTransports. Round-robins across the existing
// transports to spread streams.
func (p *connPool) getTransport(ctx context.Context) (*h2Transport, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}

		if t := p.reserveLocked(); t != nil {
			p.mu.Unlock()
			t.touch()
			return t, nil
		}

		capacity := p.maxTransportsWithRotationOverlapLocked()
		if len(p.transports)+p.creating >= capacity {
			if p.creating > 0 {
				p.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			// Inline-cleanup: dead/draining-with-zero-streams transports occupy
			// pool slots but cannot serve new requests. Remove them here so a
			// fresh spawn can proceed instead of erroring out with cap=1.
			// Without this fix, V1 (cap=1) blocks indefinitely when the single
			// transport gets closed (e.g., server-side reset) until the 60s
			// cleanup tick runs, killing parallel HTTPS apps that retry within
			// seconds.
			//
			// Gated to the cap=1 case only — multi-transport variants expect
			// rotation-overlap accounting to backpressure when capacity is
			// exhausted, even with a draining-zero-stream transport sitting in
			// the slot.
			if p.maxTransports != 1 {
				p.mu.Unlock()
				return nil, fmt.Errorf("%w: cap=%d", ErrPoolBackpressure, capacity)
			}
			alive := p.transports[:0:0]
			for _, t := range p.transports {
				if t == nil || t.isClosed() {
					continue
				}
				if t.isDraining() && t.streamCount() == 0 {
					t.close()
					continue
				}
				alive = append(alive, t)
			}
			if len(alive) != len(p.transports) {
				p.transports = alive
				p.updatePoolGaugesLocked()
				if len(p.transports)+p.creating < capacity {
					// Slot freed, retry the spawn loop.
					p.mu.Unlock()
					continue
				}
			}
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: cap=%d", ErrPoolBackpressure, capacity)
		}

		p.creating++
		p.mu.Unlock()

		t, err := p.createFunc(ctx)
		p.mu.Lock()
		p.creating--
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		t.bytesSoftCap = randomizedBytesSoftCap(p.bytesSoftCap)
		if !t.reserveStreamSlot() {
			t.close()
			return nil, fmt.Errorf("freshly created transport rejects reservation (closed/drain/cap=0)")
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			t.close()
			return nil, context.Canceled
		}
		if len(p.transports) >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			t.close()
			continue
		}
		p.transports = append(p.transports, t)
		p.updatePoolGaugesLocked()
		p.mu.Unlock()

		return t, nil
	}
}

func (p *connPool) maxTransportsWithRotationOverlapLocked() int {
	capacity := p.maxTransports
	if p.rotationOverlapAllowance > 0 && p.hasDrainingLocked() {
		capacity += p.rotationOverlapAllowance
	}
	return capacity
}

func (p *connPool) hasDrainingLocked() bool {
	for _, t := range p.transports {
		if t != nil && t.isDraining() {
			return true
		}
	}
	return false
}

func (p *connPool) reserveLocked() *h2Transport {
	n := len(p.transports)
	if n == 0 {
		return nil
	}
	start := p.roundRobin % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		t := p.transports[idx]
		if t.reserveStreamSlot() {
			p.roundRobin = (idx + 1) % n
			return t
		}
	}
	return nil
}

// activeSNIs returns the SNIs of all currently-alive transports in the pool.
// Used by client.createTransport to call pickServerNameExcluding so a
// freshly-spawned transport gets a different cover SNI than its peers.
func (p *connPool) activeSNIs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.transports) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.transports))
	for _, t := range p.transports {
		if t == nil || t.isClosed() {
			continue
		}
		if t.sni != "" {
			out = append(out, t.sni)
		}
	}
	return out
}

func (p *connPool) updatePoolGaugesLocked() {
	alive := 0
	for _, t := range p.transports {
		if t.isClosed() || t.isDraining() {
			continue
		}
		alive++
	}
	setPoolTransportGauges(alive)
}

// cleanupLoop periodically removes closed and idle transports. The tick
// interval is intentionally looser than the client-visible IdleTimeout to
// avoid being the 30 s heartbeat observable.
func (p *connPool) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.closeCh:
			return
		}
	}
}

// cleanup removes closed transports and closes ones that have been idle for
// longer than idleTimeout. A transport is "idle" only when it has zero
// active streams AND its lastActive timestamp is older than idleTimeout.
func (p *connPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	alive := make([]*h2Transport, 0, len(p.transports))
	for _, t := range p.transports {
		if t.isClosed() {
			continue
		}
		if t.isDraining() && t.streamCount() == 0 {
			t.close()
			continue
		}
		if t.streamCount() == 0 {
			last := t.lastActive()
			if !last.IsZero() && time.Since(last) > p.idleTimeout {
				t.close()
				continue
			}
		}
		alive = append(alive, t)
	}
	p.transports = alive
	p.updatePoolGaugesLocked()
}

// reaperLoop tops up the pool to minTransports. If the byte soft-cap was hit
// on a transport (drained itself), reaper notices and dials a replacement.
// Heartbeat 5s -- not too aggressive (don't burn dial budgets) but fast
// enough to recover from a TSPU-induced transport teardown within ~5s.
func (p *connPool) reaperLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.closeCh:
			return
		case <-t.C:
			p.topUp()
			p.observeCurtainSignal()
		}
	}
}

// observeCurtainSignal samples bytes-per-flow buckets and emits a debug-only
// hint if the 5-15KB bucket starts dominating (= #490 enforcement signal).
// Deliberately does NOT auto-adjust MinTransports -- operator decides:
// expanding the pool is the right move under #490 but the wrong move under
// #546 (parallel TLS-conn policing), and detecting which is which requires
// active probing the operator may not want to authorise. This is a tuning
// hint, not a control loop.
func (p *connPool) observeCurtainSignal() {
	// Use the package-level expvars directly instead of forking telemetry plumbing.
	if bytesPerFlow5_15KB == nil || bytesPerFlowSub5KB == nil {
		return
	}
	mid := bytesPerFlow5_15KB.Value()
	low := bytesPerFlowSub5KB.Value()
	if mid < 50 {
		return
	}
	// If 5-15KB closures outnumber sub-5KB by >2x, it's the #490 signature.
	if mid > 2*low {
		// Future: emit log line via a registered logf hook. For now the hint
		// is observable via the buckets alone in /debug/vars; operators with
		// MinTransports=1 should consider raising it to 3-4 with
		// BytesPerTransportSoftCap=10000 to ride out the #490 curtain.
		_ = mid
	}
}

// topUp dials new transports until len(transports) >= minTransports.
// Best-effort: dial errors silent (next tick retries). Caller must NOT hold
// p.mu (createFunc dials outside the lock).
func (p *connPool) topUp() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}

		alive := 0
		for _, tr := range p.transports {
			if !tr.isClosed() && !tr.isDraining() {
				alive++
			}
		}
		if alive >= p.minTransports || len(p.transports)+p.creating >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			return
		}
		p.creating++
		p.mu.Unlock()

		tr, err := p.createFunc(ctx)
		p.mu.Lock()
		p.creating--
		p.mu.Unlock()
		if err != nil {
			return
		}
		tr.bytesSoftCap = randomizedBytesSoftCap(p.bytesSoftCap)

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			tr.close()
			return
		}
		if len(p.transports) >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			tr.close()
			return
		}
		p.transports = append(p.transports, tr)
		p.updatePoolGaugesLocked()
		p.mu.Unlock()
	}
}

// close shuts down all transports in the pool.
func (p *connPool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closeCh)

	for _, t := range p.transports {
		t.close()
	}
	p.transports = nil
	setPoolTransportGauges(0)
	return nil
}
