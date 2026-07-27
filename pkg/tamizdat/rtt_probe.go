package tamizdat

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// rttProbe periodically dials a fixed reference target through the tunnel
// and records the connect-time as a tunnel-RTT proxy. Operator-visible:
// see p50/p99 via expvar — direct evidence of how much latency the
// obfuscation costs.
type rttProbe struct {
	client     *Client
	target     string        // e.g. "1.1.1.1:80"
	period     time.Duration // e.g. 1s
	timeout    time.Duration // per-dial timeout
	maxSamples int           // ring size
	cancel     context.CancelFunc

	mu      sync.Mutex
	samples []time.Duration
}

func newRTTProbe(c *Client) *rttProbe {
	return &rttProbe{
		client:     c,
		target:     "1.1.1.1:80",
		period:     1 * time.Second,
		timeout:    3 * time.Second,
		maxSamples: 60,
	}
}

func (p *rttProbe) start() {
	if p == nil || p.client == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.run(ctx)
}

func (p *rttProbe) stop() {
	if p == nil || p.cancel == nil {
		return
	}
	p.cancel()
}

func (p *rttProbe) run(ctx context.Context) {
	t := time.NewTicker(p.period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.doProbe(ctx)
	}
}

func (p *rttProbe) doProbe(ctx context.Context) {
	dctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	start := time.Now()
	conn, err := p.client.DialContext(dctx, "tcp", p.target)
	rtt := time.Since(start)
	if err != nil {
		return
	}
	_ = conn.Close()
	p.mu.Lock()
	p.samples = appendCap(p.samples, rtt, p.maxSamples)
	p.mu.Unlock()
}

func appendCap(s []time.Duration, v time.Duration, cap int) []time.Duration {
	s = append(s, v)
	if len(s) > cap {
		s = s[len(s)-cap:]
	}
	return s
}

// Snapshot returns p50 (in ms, integer rounded) plus most-recent sample.
// Returns -1 fields when no samples have been collected yet.
type RTTProbeStats struct {
	P50Ms  int64
	Count  int
	LastMs int64
}

func (p *rttProbe) Snapshot() RTTProbeStats {
	if p == nil {
		return RTTProbeStats{P50Ms: -1, LastMs: -1}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := RTTProbeStats{
		P50Ms:  -1,
		LastMs: -1,
		Count:  len(p.samples),
	}
	if len(p.samples) > 0 {
		st.P50Ms = percentileMs(p.samples, 50)
		last := p.samples[len(p.samples)-1]
		st.LastMs = int64(last / time.Millisecond)
	}
	return st
}

func percentileMs(d []time.Duration, p int) int64 {
	if len(d) == 0 {
		return 0
	}
	tmp := make([]time.Duration, len(d))
	copy(tmp, d)
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	idx := (len(tmp) * p) / 100
	if idx >= len(tmp) {
		idx = len(tmp) - 1
	}
	return int64(tmp[idx] / time.Millisecond)
}

// dummy-use net package
var _ = net.Dialer{}
