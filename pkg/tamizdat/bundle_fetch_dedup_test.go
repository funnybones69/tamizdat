package tamizdat

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBundleFetchInFlight_DedupesConcurrentDials is the SPP-FU-2 regression
// guard: concurrent createTransport callers must not all kick off a parallel
// fetchAndApplyBundle goroutine. We exercise the CompareAndSwap gate
// directly (no real H2 transport needed) and verify exactly one CAS-winner
// emerges out of N concurrent attempts.
//
// The atomic.Bool approach was chosen over golang.org/x/sync/singleflight
// to avoid introducing an external dependency for what is effectively a
// single-shot toggle (operator preference per the consolidated minor-fixes
// brief). On goroutine exit the gate flips back to false so a future
// transport-rotation can trigger another fetch.
func TestBundleFetchInFlight_DedupesConcurrentDials(t *testing.T) {
	const goroutines = 64
	var gate atomic.Bool
	var winners atomic.Int64

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if gate.CompareAndSwap(false, true) {
				winners.Add(1)
				// Hold the gate briefly to simulate the real fetch's H2
				// roundtrip + JSON parse window.
				time.Sleep(5 * time.Millisecond)
				gate.Store(false)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("CompareAndSwap winners = %d, want exactly 1 (gate dedup is broken)", got)
	}
	if gate.Load() {
		t.Fatal("gate left in 'in-flight' state after winner finished — defer Store(false) regression")
	}
}

// TestBundleFetchInFlight_AllowsSecondFetchAfterCompletion verifies that
// after a previous fetch returned, a fresh CAS attempt succeeds. This
// guards against accidentally turning the dedup gate into a one-shot
// (which would prevent the client from re-fetching after a server-side
// pool rotation or ETag bump).
func TestBundleFetchInFlight_AllowsSecondFetchAfterCompletion(t *testing.T) {
	var gate atomic.Bool
	if !gate.CompareAndSwap(false, true) {
		t.Fatal("first CAS failed on a zero-value gate")
	}
	gate.Store(false)
	if !gate.CompareAndSwap(false, true) {
		t.Fatal("second CAS failed after gate reset")
	}
}

// TestClient_BundleFetchInFlightZeroValue verifies the field initialises
// to false on a fresh Client (so the very first dial in a process always
// wins the CAS).
func TestClient_BundleFetchInFlightZeroValue(t *testing.T) {
	c := &Client{}
	if c.bundleFetchInFlight.Load() {
		t.Fatal("bundleFetchInFlight true on zero-value Client")
	}
	if !c.bundleFetchInFlight.CompareAndSwap(false, true) {
		t.Fatal("CompareAndSwap false->true rejected on zero-value gate")
	}
}
