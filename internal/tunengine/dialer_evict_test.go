package tunengine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// evictTestDialer builds a dialer whose active-slot semaphore has the given
// capacity. The blockingProxyClient has a pre-closed release channel, so dials
// resolve immediately and the only thing under test is active-slot admission.
func evictTestDialer(activeCap int) *tamizdatProxyDialer {
	client := &blockingProxyClient{release: make(chan struct{})}
	close(client.release)
	return &tamizdatProxyDialer{
		client:             client,
		dialAttemptTimeout: time.Second,
		activeSlots:        make(chan struct{}, activeCap),
		activeConns:        make(map[*activeSlotConn]struct{}),
		targetGates:        make(map[string]*targetGate),
	}
}

// dialActiveSlotConn runs one DialContext and returns the resulting
// *activeSlotConn, failing the test on any error.
func dialActiveSlotConn(t *testing.T, d *tamizdatProxyDialer) *activeSlotConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, reaperTestMetadata())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	asc, ok := conn.(*activeSlotConn)
	if !ok {
		t.Fatalf("dialed conn type = %T, want *activeSlotConn", conn)
	}
	return asc
}

func assertTracked(t *testing.T, d *tamizdatProxyDialer, when string, want map[*activeSlotConn]bool) {
	t.Helper()
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	for conn, shouldExist := range want {
		if _, exists := d.activeConns[conn]; exists != shouldExist {
			t.Fatalf("%s: conn tracked=%v, want %v", when, exists, shouldExist)
		}
	}
}

// TestAcquireActiveSlotEvictsStaleConnUnderPressure: when every active slot is
// pinned by a connection idle past activeSlotSoftEvictIdle, a new dial must
// reclaim a slot by evicting the stalest one rather than blocking until its
// context expires. This is the keepalive-deadlock fix — a long-lived
// background socket can no longer wedge the tunnel against a foreground dial.
func TestAcquireActiveSlotEvictsStaleConnUnderPressure(t *testing.T) {
	dialer := evictTestDialer(1)

	stale := dialActiveSlotConn(t, dialer)
	stale.lastActivity.Store(time.Now().Add(-activeSlotSoftEvictIdle - time.Second).UnixNano())

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := dialer.DialContext(ctx, reaperTestMetadata())
	cancel()
	if err != nil {
		t.Fatalf("dial under slot pressure did not evict: %v", err)
	}
	defer conn.Close()

	if elapsed := time.Since(start); elapsed < activeSlotEvictWait {
		t.Fatalf("dial returned in %s, want >= %s — eviction path was skipped", elapsed, activeSlotEvictWait)
	}
	if got := dialer.activeEvictions.Load(); got != 1 {
		t.Fatalf("activeEvictions = %d, want 1", got)
	}
	if got := len(dialer.activeSlots); got != 1 {
		t.Fatalf("active slot held after eviction = %d, want 1 (new conn holds it)", got)
	}
	dialer.activeMu.Lock()
	_, staleTracked := dialer.activeConns[stale]
	tracked := len(dialer.activeConns)
	dialer.activeMu.Unlock()
	if staleTracked {
		t.Fatal("evicted stale conn is still tracked in activeConns")
	}
	if tracked != 1 {
		t.Fatalf("tracked active conns = %d, want 1", tracked)
	}
}

// TestAcquireActiveSlotKeepsActiveConnUnderPressure: a connection with recent
// I/O (idle below activeSlotSoftEvictIdle) must never be evicted. With every
// slot held by a genuinely-active flow, a new dial waits — bounded only by its
// context — and must not kill a live flow to force its way in.
func TestAcquireActiveSlotKeepsActiveConnUnderPressure(t *testing.T) {
	dialer := evictTestDialer(1)

	live := dialActiveSlotConn(t, dialer)
	defer live.Close()
	// live was just dialed: lastActivity is fresh, far below the threshold.

	// ctx spans several activeSlotEvictWait cycles so the evict path runs more
	// than once; every run must find nothing evictable.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, reaperTestMetadata())
	if !errors.Is(err, context.DeadlineExceeded) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("dial error = %v, want context.DeadlineExceeded", err)
	}
	if got := dialer.activeEvictions.Load(); got != 0 {
		t.Fatalf("activeEvictions = %d, want 0 — a fresh conn must not be evicted", got)
	}
	if got := len(dialer.activeSlots); got != 1 {
		t.Fatalf("active slot = %d, want 1 (live conn still holds it)", got)
	}
	dialer.activeMu.Lock()
	_, liveTracked := dialer.activeConns[live]
	dialer.activeMu.Unlock()
	if !liveTracked {
		t.Fatal("live conn is no longer tracked — it was wrongly evicted")
	}
}

// TestEvictOneIdleActiveConnEvictsStalestOnly: evictOneIdleActiveConn closes
// exactly one victim per call — the stalest connection past the soft
// threshold — and never touches a fresh flow.
func TestEvictOneIdleActiveConnEvictsStalestOnly(t *testing.T) {
	dialer := evictTestDialer(3)

	fresh := dialActiveSlotConn(t, dialer)
	defer fresh.Close()
	stalest := dialActiveSlotConn(t, dialer)
	stale := dialActiveSlotConn(t, dialer)

	now := time.Now()
	fresh.lastActivity.Store(now.Add(-3 * time.Second).UnixNano())
	stalest.lastActivity.Store(now.Add(-activeSlotSoftEvictIdle - time.Minute).UnixNano())
	stale.lastActivity.Store(now.Add(-activeSlotSoftEvictIdle - time.Second).UnixNano())

	// First call evicts the single stalest conn; the stale-but-newer one and
	// the fresh one survive.
	dialer.evictOneIdleActiveConn()
	assertTracked(t, dialer, "after 1st evict", map[*activeSlotConn]bool{
		fresh: true, stalest: false, stale: true,
	})
	if got := dialer.activeEvictions.Load(); got != 1 {
		t.Fatalf("activeEvictions after 1st call = %d, want 1", got)
	}

	// Second call evicts the next-stalest; the fresh conn still survives.
	dialer.evictOneIdleActiveConn()
	assertTracked(t, dialer, "after 2nd evict", map[*activeSlotConn]bool{
		fresh: true, stale: false,
	})
	if got := dialer.activeEvictions.Load(); got != 2 {
		t.Fatalf("activeEvictions after 2nd call = %d, want 2", got)
	}

	// Only the fresh conn remains — a third call must evict nothing.
	dialer.evictOneIdleActiveConn()
	if got := dialer.activeEvictions.Load(); got != 2 {
		t.Fatalf("activeEvictions after 3rd call = %d, want 2 — fresh conn must survive", got)
	}
	if got := len(dialer.activeSlots); got != 1 {
		t.Fatalf("active slots held = %d, want 1 (only the fresh conn)", got)
	}
}
