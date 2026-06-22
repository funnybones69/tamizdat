package tunengine

import (
	"context"
	"net/netip"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

func reaperTestMetadata() *M.Metadata {
	return &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}
}

// TestDialerReapsIdleActiveConn: the idle reaper must force-close a flow that
// has held its active slot with no I/O past activeSlotIdleTimeout, releasing
// the slot so a subsequent dial can proceed. Backstop anti-stick guarantee:
// without it an abandoned flow pins its slot forever and, once every slot is
// pinned, the whole emergency transport wedges.
func TestDialerReapsIdleActiveConn(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	close(client.release)
	dialer := &tamizdatProxyDialer{
		client:             client,
		dialAttemptTimeout: time.Second,
		activeSlots:        make(chan struct{}, 1),
		activeConns:        make(map[*activeSlotConn]struct{}),
		targetGates:        make(map[string]*targetGate),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := dialer.DialContext(ctx, reaperTestMetadata())
	cancel()
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	if got := len(dialer.activeSlots); got != 1 {
		t.Fatalf("active slot held = %d, want 1", got)
	}

	// A fresh dial must be blocked while the only slot is pinned.
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, blockedErr := dialer.DialContext(blockedCtx, reaperTestMetadata())
	blockedCancel()
	if blockedErr == nil {
		t.Fatal("second dial succeeded while the only active slot was pinned")
	}

	// Back-date the flow's last activity past the idle timeout, then reap.
	asc, ok := conn.(*activeSlotConn)
	if !ok {
		t.Fatalf("dialed conn type = %T, want *activeSlotConn", conn)
	}
	asc.lastActivity.Store(time.Now().Add(-activeSlotIdleTimeout - time.Second).UnixNano())
	dialer.reapIdleActiveConns()

	if got := len(dialer.activeSlots); got != 0 {
		t.Fatalf("idle reaper did not release the slot: held = %d, want 0", got)
	}
	dialer.activeMu.Lock()
	tracked := len(dialer.activeConns)
	dialer.activeMu.Unlock()
	if tracked != 0 {
		t.Fatalf("reaped conn still tracked: %d, want 0", tracked)
	}

	// The slot is free again — a new dial must now succeed.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	conn2, err := dialer.DialContext(ctx, reaperTestMetadata())
	cancel()
	if err != nil {
		t.Fatalf("dial after reap: %v", err)
	}
	_ = conn2.Close()
	_ = conn.Close() // double-close of the already-reaped conn must be safe
}

// TestDialerKeepsFreshActiveConn: the reaper must NOT close a flow whose last
// activity is within activeSlotIdleTimeout.
func TestDialerKeepsFreshActiveConn(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	close(client.release)
	dialer := &tamizdatProxyDialer{
		client:             client,
		dialAttemptTimeout: time.Second,
		activeSlots:        make(chan struct{}, 1),
		activeConns:        make(map[*activeSlotConn]struct{}),
		targetGates:        make(map[string]*targetGate),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := dialer.DialContext(ctx, reaperTestMetadata())
	cancel()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// conn was just dialed — its lastActivity is fresh.
	dialer.reapIdleActiveConns()
	if got := len(dialer.activeSlots); got != 1 {
		t.Fatalf("reaper closed a fresh flow: slot held = %d, want 1", got)
	}
	dialer.activeMu.Lock()
	tracked := len(dialer.activeConns)
	dialer.activeMu.Unlock()
	if tracked != 1 {
		t.Fatalf("fresh conn no longer tracked: %d, want 1", tracked)
	}
}
