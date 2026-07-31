package wgturnclient

import "time"

const (
	// DefaultWorkerRateBPS is intentionally expressed in bytes per second.
	// The flag name is retained for OpenWrt init compatibility.
	DefaultWorkerRateBPS = 7250
	workerBurstBytes     = 4500
	shaperLogInterval    = 10 * time.Second
)

// workerTokenBucket belongs to one WorkerSlot and is only mutated while the
// dispatcher mutex is held. Latency packets may drive tokens negative; bulk
// traffic resumes only after that debt is repaid.
type workerTokenBucket struct {
	rateBytesPerSecond float64
	burst              float64
	tokens             float64
	lastRefill         time.Time
	now                func() time.Time
}

func newWorkerTokenBucket(rateBPS int, now func() time.Time) *workerTokenBucket {
	if rateBPS <= 0 {
		rateBPS = DefaultWorkerRateBPS
	}
	if now == nil {
		now = time.Now
	}
	current := now()
	return &workerTokenBucket{
		rateBytesPerSecond: float64(rateBPS),
		burst:              workerBurstBytes,
		tokens:             workerBurstBytes,
		lastRefill:         current,
		now:                now,
	}
}

func (b *workerTokenBucket) refill() {
	if b == nil {
		return
	}
	now := b.now()
	if now.After(b.lastRefill) {
		b.tokens += now.Sub(b.lastRefill).Seconds() * b.rateBytesPerSecond
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.lastRefill = now
}

func (b *workerTokenBucket) admit(size int, latency bool) bool {
	if b == nil || size < 0 {
		return false
	}
	b.refill()
	need := float64(size)
	if latency {
		b.tokens -= need
		return true
	}
	if b.tokens < need {
		return false
	}
	b.tokens -= need
	return true
}

func (b *workerTokenBucket) refund(size int) {
	if b == nil || size <= 0 {
		return
	}
	b.tokens += float64(size)
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}
