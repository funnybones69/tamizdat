package tunengine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/node"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type recordingOutbound struct {
	tag      string
	requests []*node.Request
	peers    []net.Conn
}

type blockingProxyClient struct {
	calls   atomic.Int32
	release chan struct{}
}

type failingProxyClient struct {
	calls atomic.Int32
	err   error
}

func TestRetryableDialErrorRecognizesCarrierOpenFailures(t *testing.T) {
	cases := []error{
		errors.New("read tcp 172.20.10.2:50123->203.0.113.10:31502: i/o timeout"),
		errors.New("read tcp 172.20.10.2:50123->203.0.113.10:31502: wsarecv: An existing connection was forcibly closed by the remote host."),
		errors.New("EOF"),
		context.DeadlineExceeded,
		errors.New("fragpoc: scheduler backpressure"),
	}
	for _, err := range cases {
		if !isRetryableDialError(err) {
			t.Fatalf("isRetryableDialError(%q) = false, want true", err)
		}
	}
	if isRetryableDialError(errors.New("permission denied")) {
		t.Fatal("isRetryableDialError(permission denied) = true, want false")
	}
}

func TestPrivateDestinationDetection(t *testing.T) {
	private := []string{
		"10.255.0.255",
		"172.20.10.1",
		"192.168.2.1",
	}
	for _, ip := range private {
		if !isPrivateDestination(netip.MustParseAddr(ip)) {
			t.Fatalf("isPrivateDestination(%s) = false, want true", ip)
		}
	}
	if isPrivateDestination(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("isPrivateDestination(203.0.113.10) = true, want false")
	}
}

func TestBlockedEndpointDetection(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.10")
	d := &tamizdatProxyDialer{
		blockedEndpoints: map[netip.AddrPort]struct{}{
			netip.AddrPortFrom(addr, 31502): {},
		},
	}
	if !d.isBlockedEndpoint(addr, 31502) {
		t.Fatal("isBlockedEndpoint(server:31502) = false, want true")
	}
	if d.isBlockedEndpoint(addr, 443) {
		t.Fatal("isBlockedEndpoint(server:443) = true, want false")
	}
}

func TestDialerDropsNonDNSUDPWhenPolicyEnabled(t *testing.T) {
	d := &tamizdatProxyDialer{dropNonDNSUDP: true}
	metadata := &M.Metadata{
		Network: M.UDP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		DstPort: 443,
	}
	if _, err := d.DialUDP(metadata); !errors.Is(err, errNonDNSUDP) {
		t.Fatalf("DialUDP non-DNS error = %v, want errNonDNSUDP", err)
	}
}

func TestDialerDropsAllUDPWhenPolicyOff(t *testing.T) {
	d := &tamizdatProxyDialer{dropAllUDP: true}
	metadata := &M.Metadata{
		Network: M.UDP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		DstPort: 53,
	}
	if _, err := d.DialUDP(metadata); !errors.Is(err, errNonDNSUDP) {
		t.Fatalf("DialUDP disabled error = %v, want errNonDNSUDP", err)
	}
}

func (r *recordingOutbound) Tag() string { return r.tag }
func (r *recordingOutbound) Dial(ctx context.Context, req *node.Request) (net.Conn, error) {
	r.requests = append(r.requests, req)
	client, peer := net.Pipe()
	r.peers = append(r.peers, peer)
	return client, nil
}
func (r *recordingOutbound) Close() error {
	for _, peer := range r.peers {
		_ = peer.Close()
	}
	return nil
}

func (c *blockingProxyClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.calls.Add(1)
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	client, peer := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, peer)
		_ = peer.Close()
	}()
	return client, nil
}

func (c *blockingProxyClient) DialUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (c *blockingProxyClient) Close() error { return nil }

func (c *failingProxyClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.calls.Add(1)
	return nil, c.err
}

func (c *failingProxyClient) DialUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (c *failingProxyClient) Close() error { return nil }

// TestDialerTargetGateCapsConcurrentOpens: the per-target gate admits up to
// maxConcurrentPerTarget simultaneous opens so a page can parallelize its
// connections to one CDN IP, and blocks the next open until a slot frees.
func TestDialerTargetGateCapsConcurrentOpens(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown: time.Second,
		targetGates:        make(map[string]*targetGate),
	}
	target := "203.0.113.20:443"
	releases := make([]func(bool), 0, maxConcurrentPerTarget)
	for i := 0; i < maxConcurrentPerTarget; i++ {
		release, err := dialer.acquireTargetGate(context.Background(), target)
		if err != nil {
			t.Fatalf("concurrent open %d within cap: %v", i, err)
		}
		releases = append(releases, release)
	}
	// Cap full — the next open must block until a slot frees.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err := dialer.acquireTargetGate(ctx, target)
	cancel()
	if !errors.Is(err, errTargetAdmission) {
		t.Fatalf("open past the cap = %v, want errTargetAdmission", err)
	}
	// Free one slot; the next open is admitted immediately.
	releases[0](true)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := dialer.acquireTargetGate(ctx2, target); err != nil {
		t.Fatalf("open after a slot freed: %v", err)
	}
}

// TestDialerTargetCooldownNeedsConsecutiveFailures: a target is cooled down
// only after targetFailuresBeforeCooldown consecutive failed opens. A single
// transient failure on the restricted path must not block the destination.
func TestDialerTargetCooldownNeedsConsecutiveFailures(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown:    time.Second,
		dialTargetCooldownMax: 30 * time.Second,
		targetGates:           make(map[string]*targetGate),
	}
	target := "203.0.113.21:443"
	// Failures below the threshold leave the target admitting immediately.
	for i := 0; i < targetFailuresBeforeCooldown-1; i++ {
		release, err := dialer.acquireTargetGate(context.Background(), target)
		if err != nil {
			t.Fatalf("sub-threshold open %d: %v", i, err)
		}
		release(false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	release, err := dialer.acquireTargetGate(ctx, target)
	cancel()
	if err != nil {
		t.Fatalf("target cooled down before %d consecutive failures: %v", targetFailuresBeforeCooldown, err)
	}
	// This failure reaches the threshold and arms the cooldown.
	release(false)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 40*time.Millisecond)
	_, err = dialer.acquireTargetGate(ctx2, target)
	cancel2()
	if !errors.Is(err, errTargetAdmission) {
		t.Fatalf("target not cooled after %d consecutive failures = %v, want errTargetAdmission", targetFailuresBeforeCooldown, err)
	}
}

func TestNegativeTargetCooldownSerializesWithoutCooldown(t *testing.T) {
	errClient := &failingProxyClient{err: context.DeadlineExceeded}
	dialer := &tamizdatProxyDialer{
		client:             errClient,
		dialAttemptTimeout: time.Millisecond,
		dialTargetCooldown: -time.Millisecond,
		targetGates:        make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, _ = dialer.DialContext(ctx, metadata)
		cancel()
	}
	if got := errClient.calls.Load(); got < 2 {
		t.Fatalf("negative cooldown should not suppress sequential retries; calls = %d, want at least 2", got)
	}
}

func TestDialerActiveConcurrencyReleasesOnClose(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	close(client.release)
	dialer := &tamizdatProxyDialer{
		client:             client,
		dialAttemptTimeout: time.Second,
		activeSlots:        make(chan struct{}, 1),
		targetGates:        make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := dialer.DialContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer conn.Close()

	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = dialer.DialContext(blockedCtx, metadata)
	blockedCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second dial while active slot is held = %v, want context deadline", err)
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("blocked active dial reached client; calls = %d, want 1", got)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close first conn: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	conn, err = dialer.DialContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("dial after close: %v", err)
	}
	_ = conn.Close()
	if got := client.calls.Load(); got != 2 {
		t.Fatalf("dial after close calls = %d, want 2", got)
	}
}

// TestTargetCooldownIsFlatAndClamped: the per-target cooldown is a flat value
// (no escalation), clamped by dialTargetCooldownMax. An escalating cooldown
// turned transient restricted-network failures into long blocks on the page.
func TestTargetCooldownIsFlatAndClamped(t *testing.T) {
	flat := &tamizdatProxyDialer{
		dialTargetCooldown:    500 * time.Millisecond,
		dialTargetCooldownMax: 30 * time.Second,
	}
	if got, want := flat.targetCooldownDuration(), 500*time.Millisecond; got != want {
		t.Fatalf("flat cooldown = %s, want %s", got, want)
	}
	clamped := &tamizdatProxyDialer{
		dialTargetCooldown:    10 * time.Second,
		dialTargetCooldownMax: 2 * time.Second,
	}
	if got, want := clamped.targetCooldownDuration(), 2*time.Second; got != want {
		t.Fatalf("clamped cooldown = %s, want %s", got, want)
	}
	disabled := &tamizdatProxyDialer{dialTargetCooldown: -time.Millisecond}
	if got := disabled.targetCooldownDuration(); got != 0 {
		t.Fatalf("disabled cooldown = %s, want 0", got)
	}
}

func TestTargetCooldownResetsAfterSuccess(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown:    time.Second,
		dialTargetCooldownMax: 30 * time.Second,
		targetGates:           make(map[string]*targetGate),
	}
	target := "8.47.69.0:443"
	release, err := dialer.acquireTargetGate(context.Background(), target)
	if err != nil {
		t.Fatalf("acquire target: %v", err)
	}
	release(false)
	release, err = dialer.acquireTargetGate(context.Background(), target)
	if err != nil {
		t.Fatalf("acquire target after first cooldown: %v", err)
	}
	release(false)
	dialer.targetMu.Lock()
	if got := dialer.targetGates[target].failures; got != 2 {
		dialer.targetMu.Unlock()
		t.Fatalf("failures after two failures = %d, want 2", got)
	}
	dialer.targetGates[target].cooldownUntil = time.Time{}
	dialer.targetMu.Unlock()
	release, err = dialer.acquireTargetGate(context.Background(), target)
	if err != nil {
		t.Fatalf("acquire target before success: %v", err)
	}
	release(true)
	dialer.targetMu.Lock()
	g, exists := dialer.targetGates[target]
	var failures int
	var cooling bool
	if exists {
		failures = g.failures
		cooling = !g.cooldownUntil.IsZero()
	}
	dialer.targetMu.Unlock()
	// The gate may linger while its rate window is live, but a successful
	// open must clear the failure count and the failure cooldown.
	if exists && (failures != 0 || cooling) {
		t.Fatalf("target gate not reset after success: failures=%d cooling=%t", failures, cooling)
	}
}

// TestDialerNoisyTargetThrottledAfterThreshold: a destination granted more
// than noisyTargetThreshold opens within one rate window is paced with a
// cooldown even though every open succeeded.
func TestDialerNoisyTargetThrottledAfterThreshold(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown: time.Second, // positive → noisy suppression active
		targetGates:        make(map[string]*targetGate),
	}
	target := "203.0.113.7:443"
	for i := 0; i <= noisyTargetThreshold; i++ {
		release, err := dialer.acquireTargetGate(context.Background(), target)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		release(true)
	}
	// The gate is now throttled: an acquire with a short deadline must hit the
	// noisy cooldown instead of being granted.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := dialer.acquireTargetGate(ctx, target); !errors.Is(err, errTargetAdmission) {
		t.Fatalf("noisy target acquire = %v, want errTargetAdmission", err)
	}
	if dialer.noisyThrottles.Load() == 0 {
		t.Fatal("noisyThrottles counter not incremented for a noisy target")
	}
}

// TestDialerQuietTargetNotThrottled: a destination opened fewer than
// noisyTargetThreshold times stays un-throttled — its next open is immediate.
func TestDialerQuietTargetNotThrottled(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown: time.Second,
		targetGates:        make(map[string]*targetGate),
	}
	target := "203.0.113.8:443"
	for i := 0; i < noisyTargetThreshold-2; i++ {
		release, err := dialer.acquireTargetGate(context.Background(), target)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		release(true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	release, err := dialer.acquireTargetGate(ctx, target)
	if err != nil {
		t.Fatalf("quiet target acquire = %v, want grant", err)
	}
	release(true)
	if elapsed := time.Since(start); elapsed >= 30*time.Millisecond {
		t.Fatalf("quiet target acquire took %s, want immediate", elapsed)
	}
	if got := dialer.noisyThrottles.Load(); got != 0 {
		t.Fatalf("noisyThrottles = %d for a quiet target, want 0", got)
	}
}

// TestTargetGateRateWindowRolls: noteOpen accumulates within a window and
// isNoisy fires past the threshold; an open after the window rolls the count.
func TestTargetGateRateWindowRolls(t *testing.T) {
	g := &targetGate{}
	base := time.Now()
	for i := 0; i < noisyTargetThreshold+5; i++ {
		g.noteOpen(base)
	}
	if !g.isNoisy(base) {
		t.Fatalf("targetGate not noisy after %d opens in one window", noisyTargetThreshold+5)
	}
	rolled := base.Add(noisyTargetWindow + time.Second)
	g.noteOpen(rolled)
	if g.isNoisy(rolled) {
		t.Fatal("targetGate still noisy after the rate window rolled")
	}
}

// TestTargetGateRateWindowStale: a gate with no window or an elapsed window is
// stale; one with a live window is not.
func TestTargetGateRateWindowStale(t *testing.T) {
	g := &targetGate{}
	base := time.Now()
	if !g.rateWindowStale(base) {
		t.Fatal("targetGate with no rate window should be stale")
	}
	g.noteOpen(base)
	if g.rateWindowStale(base) {
		t.Fatal("targetGate with a live window reported stale")
	}
	if !g.rateWindowStale(base.Add(noisyTargetWindow)) {
		t.Fatal("targetGate window should be stale once noisyTargetWindow elapsed")
	}
}

// TestDialerReapsStaleTargetGates: reapStaleTargetGates drops idle gates but
// keeps gates that are in-flight or still inside a live rate window.
func TestDialerReapsStaleTargetGates(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialTargetCooldown: time.Second,
		targetGates:        make(map[string]*targetGate),
	}
	now := time.Now()
	dialer.targetGates["stale:443"] = &targetGate{
		changed:     make(chan struct{}),
		windowStart: now.Add(-2 * noisyTargetWindow),
	}
	dialer.targetGates["live:443"] = &targetGate{
		changed:     make(chan struct{}),
		windowStart: now,
	}
	dialer.targetGates["inflight:443"] = &targetGate{
		changed:     make(chan struct{}),
		inFlight:    1,
		windowStart: now.Add(-2 * noisyTargetWindow),
	}
	dialer.targetGates["cooling:443"] = &targetGate{
		changed:       make(chan struct{}),
		windowStart:   now.Add(-2 * noisyTargetWindow),
		cooldownUntil: now.Add(time.Hour),
	}
	dialer.reapStaleTargetGates()
	dialer.targetMu.Lock()
	defer dialer.targetMu.Unlock()
	if _, ok := dialer.targetGates["stale:443"]; ok {
		t.Fatal("stale gate not reaped")
	}
	for _, keep := range []string{"live:443", "inflight:443", "cooling:443"} {
		if _, ok := dialer.targetGates[keep]; !ok {
			t.Fatalf("%s wrongly reaped", keep)
		}
	}
}

func TestDialerRejectsLateOuterDialAttempts(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	dialer := &tamizdatProxyDialer{
		client:               client,
		dialAttemptTimeout:   500 * time.Millisecond,
		dialMinAttemptBudget: 200 * time.Millisecond,
		targetGates:          make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := dialer.DialContext(ctx, metadata)
	if !errors.Is(err, errAttemptBudget) {
		t.Fatalf("late dial error = %v, want errAttemptBudget", err)
	}
	if got := client.calls.Load(); got != 0 {
		t.Fatalf("late dial reached client %d times, want 0", got)
	}
}

func TestDialerRejectsLateAttemptAfterTargetQueue(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	dialer := &tamizdatProxyDialer{
		client:               client,
		dialAttemptTimeout:   500 * time.Millisecond,
		dialTargetCooldown:   time.Millisecond,
		dialMinAttemptBudget: 300 * time.Millisecond,
		targetGates:          make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	firstErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, metadata)
		if conn != nil {
			_ = conn.Close()
		}
		firstErr <- err
	}()
	deadline := time.Now().Add(time.Second)
	for client.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("first dial calls = %d, want 1", got)
	}

	secondCtx, secondCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer secondCancel()
	secondErr := make(chan error, 1)
	go func() {
		_, err := dialer.DialContext(secondCtx, metadata)
		secondErr <- err
	}()
	time.Sleep(80 * time.Millisecond)
	close(client.release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first dial error = %v", err)
	}
	if err := <-secondErr; !errors.Is(err, errAttemptBudget) {
		t.Fatalf("second late queued dial error = %v, want errAttemptBudget", err)
	}
	if got := client.calls.Load(); got != 1 {
		t.Fatalf("late queued dial reached client %d times, want 1", got)
	}
}

func TestDialerRecoveryBackoffTripsAfterFailures(t *testing.T) {
	errClient := &failingProxyClient{err: errors.New("fragpoc: scheduler backpressure")}
	dialer := &tamizdatProxyDialer{
		client:                errClient,
		dialAttemptTimeout:    time.Millisecond,
		dialRecoveryThreshold: 2,
		dialRecoveryBackoff:   200 * time.Millisecond,
		targetGates:           make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = dialer.DialContext(ctx, metadata)
		cancel()
	}
	callsAfterFailures := errClient.calls.Load()
	if callsAfterFailures == 0 {
		t.Fatal("failing dials did not reach client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := dialer.DialContext(ctx, metadata)
	if !errors.Is(err, errRecoveryBackoff) {
		t.Fatalf("recovery dial error = %v, want errRecoveryBackoff", err)
	}
	if got := errClient.calls.Load(); got != callsAfterFailures {
		t.Fatalf("recovery backoff reached client; calls = %d, want %d", got, callsAfterFailures)
	}
}

func TestDialerRecoveryBackoffResetsAfterSuccess(t *testing.T) {
	client := &blockingProxyClient{release: make(chan struct{})}
	close(client.release)
	dialer := &tamizdatProxyDialer{
		client:                client,
		dialAttemptTimeout:    time.Second,
		dialRecoveryThreshold: 2,
		dialRecoveryBackoff:   time.Second,
		targetGates:           make(map[string]*targetGate),
	}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("8.47.69.0"),
		DstPort: 443,
	}

	dialer.recordDialAdmission(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := dialer.DialContext(ctx, metadata)
	cancel()
	if err != nil {
		t.Fatalf("successful dial: %v", err)
	}
	_ = conn.Close()
	dialer.recordDialAdmission(false)
	if err := dialer.waitRecoveryWindow(context.Background()); err != nil {
		t.Fatalf("recovery tripped after success reset: %v", err)
	}
}

func TestDialerRecoveryBackoffWaitsInsteadOfFailingFast(t *testing.T) {
	dialer := &tamizdatProxyDialer{
		dialRecoveryThreshold: 1,
		dialRecoveryBackoff:   time.Second,
	}
	dialer.recordDialAdmission(false)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := dialer.waitRecoveryWindow(ctx)
	if !errors.Is(err, errRecoveryBackoff) {
		t.Fatalf("recovery wait error = %v, want errRecoveryBackoff", err)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("recovery returned too quickly after %s", elapsed)
	}
}

// drainOpenPaceBurst consumes the full initial token-bucket burst so a
// subsequent acquire exercises the throttle path.
func drainOpenPaceBurst(t *testing.T, d *tamizdatProxyDialer) {
	t.Helper()
	for i := 0; i < openPaceBurst; i++ {
		if err := d.acquireOpenPace(context.Background()); err != nil {
			t.Fatalf("burst acquire %d: %v", i, err)
		}
	}
}

// TestDialerOpenPaceBurstAdmitsInstantly: the open-pacer is a token bucket that
// starts full, so a page-load burst of up to openPaceBurst new flows is
// admitted with no per-flow interval wait.
func TestDialerOpenPaceBurstAdmitsInstantly(t *testing.T) {
	d := &tamizdatProxyDialer{dialOpenInterval: 50 * time.Millisecond}
	start := time.Now()
	for i := 0; i < openPaceBurst; i++ {
		if err := d.acquireOpenPace(context.Background()); err != nil {
			t.Fatalf("burst acquire %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed >= d.dialOpenInterval {
		t.Fatalf("draining a full burst of %d took %s, want < one interval (%s) — burst not absorbed",
			openPaceBurst, elapsed, d.dialOpenInterval)
	}
}

// TestDialerOpenPaceThrottlesAfterBurst: once the burst is spent, the next
// acquire is throttled to roughly one refill interval.
func TestDialerOpenPaceThrottlesAfterBurst(t *testing.T) {
	d := &tamizdatProxyDialer{dialOpenInterval: 100 * time.Millisecond}
	drainOpenPaceBurst(t, d)
	start := time.Now()
	if err := d.acquireOpenPace(context.Background()); err != nil {
		t.Fatalf("post-burst acquire: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 70*time.Millisecond {
		t.Fatalf("post-burst acquire returned in %s, want ~one interval (%s) — throttle not applied",
			elapsed, d.dialOpenInterval)
	}
}

// TestDialerOpenPaceRefillsWhileIdle: tokens accrue over time, so flows that
// arrive after an idle gap are admitted without waiting.
func TestDialerOpenPaceRefillsWhileIdle(t *testing.T) {
	d := &tamizdatProxyDialer{dialOpenInterval: 40 * time.Millisecond}
	drainOpenPaceBurst(t, d)
	// Idle long enough for at least two tokens to refill.
	time.Sleep(2*d.dialOpenInterval + d.dialOpenInterval/2)
	start := time.Now()
	for i := 0; i < 2; i++ {
		if err := d.acquireOpenPace(context.Background()); err != nil {
			t.Fatalf("post-idle acquire %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed >= d.dialOpenInterval {
		t.Fatalf("2 acquires after idle refill took %s, want < one interval (%s) — tokens did not refill",
			elapsed, d.dialOpenInterval)
	}
}

// TestDialerOpenPaceHonorsContextDeadline: when the bucket is empty the wait
// for the next token must abort on context cancellation.
func TestDialerOpenPaceHonorsContextDeadline(t *testing.T) {
	d := &tamizdatProxyDialer{dialOpenInterval: time.Second}
	drainOpenPaceBurst(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := d.acquireOpenPace(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drained-bucket acquire error = %v, want context.DeadlineExceeded", err)
	}
}

// TestDialerOpenPaceDisabledWhenIntervalZero: a zero dialOpenInterval disables
// the pacer entirely — every acquire returns immediately.
func TestDialerOpenPaceDisabledWhenIntervalZero(t *testing.T) {
	d := &tamizdatProxyDialer{dialOpenInterval: 0}
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := d.acquireOpenPace(context.Background()); err != nil {
			t.Fatalf("disabled-pacer acquire %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
		t.Fatalf("100 acquires with the pacer disabled took %s, want near-instant", elapsed)
	}
}

func TestDialerDispatchesTCPThroughNodeDispatcher(t *testing.T) {
	tunnel := &recordingOutbound{tag: "tunnel-finland"}
	direct := &recordingOutbound{tag: "direct"}
	rules, err := node.CompileRules([]*node.Rule{
		{GeoIP: []string{"telegram"}, Outbound: "tunnel-finland"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	dispatcher, err := node.NewDispatcher(map[string]node.Outbound{
		"direct":         direct,
		"tunnel-finland": tunnel,
	}, rules, "direct", "direct", "AsIs")
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	dialer := &tamizdatProxyDialer{dispatcher: dispatcher}
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("10.255.0.2"),
		SrcPort: 45555,
		DstIP:   netip.MustParseAddr("149.154.166.1"),
		DstPort: 443,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, metadata)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	_ = tunnel.Close()
	_ = direct.Close()

	if len(tunnel.requests) != 1 {
		t.Fatalf("tunnel-finland dial count = %d, want 1", len(tunnel.requests))
	}
	if len(direct.requests) != 0 {
		t.Fatalf("direct dial count = %d, want 0", len(direct.requests))
	}
	req := tunnel.requests[0]
	if req.Network != node.NetworkTCP {
		t.Fatalf("request network = %q, want tcp", req.Network)
	}
	if req.TargetHost != "149.154.166.1" || req.TargetPort != 443 {
		t.Fatalf("request target = %s:%d, want 149.154.166.1:443", req.TargetHost, req.TargetPort)
	}
	if got := req.SourceIP.String(); got != "10.255.0.2" {
		t.Fatalf("request source IP = %s, want 10.255.0.2", got)
	}
}
