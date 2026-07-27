package tamizdat

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReserveStreamSlot_NoOversubscription exercises HIGH-4: concurrent
// reservers must not exceed maxStreams.
func TestReserveStreamSlot_NoOversubscription(t *testing.T) {
	maxStreams := 50
	t1 := &h2Transport{
		maxStreams: maxStreams,
	}

	const goroutines = 200
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if t1.reserveStreamSlot() {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()

	if winners.Load() != int32(maxStreams) {
		t.Errorf("expected exactly %d winners, got %d (oversubscription bug)", maxStreams, winners.Load())
	}
}

// TestConnPool_TopUpDialsToMin verifies that the reaperLoop / topUp will
// dial transports until len(transports) >= minTransports.
func TestConnPool_TopUpDialsToMin(t *testing.T) {
	dialCount := atomic.Int32{}
	create := func(ctx context.Context) (*h2Transport, error) {
		dialCount.Add(1)
		return &h2Transport{maxStreams: 100}, nil
	}

	p := newConnPool(100, 5*time.Minute, 3, 3, 0, -1, create)
	// pool/transport stubs are intentionally bare; no close() to avoid nil-deref

	// Manually trigger topUp (don't wait for the 5s ticker).
	p.topUp()

	p.mu.Lock()
	got := len(p.transports)
	p.mu.Unlock()
	if got < 3 {
		t.Errorf("after topUp expected len(transports) >= 3, got %d (dials=%d)", got, dialCount.Load())
	}
}
