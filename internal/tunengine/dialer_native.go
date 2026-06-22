package tunengine

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/node"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

var currentDialer atomic.Pointer[tamizdatProxyDialer]

func init() {
	expvar.Publish("tamizdat_tun_dialer", expvar.Func(func() interface{} {
		d := currentDialer.Load()
		if d == nil {
			return map[string]any{"active": false}
		}
		return d.snapshot()
	}))
}

// errJunkDestination is returned when the destination IP is link-local,
// multicast, or a broadcast address — these are unroutable on the public
// internet and would just waste a CONNECT round-trip + log noise.
var errJunkDestination = errors.New("destination is link-local/multicast/broadcast — not tunnelable")

// errPrivateDestination is used in emergency/full-tunnel modes where RFC1918
// LAN probes would otherwise waste scarce outer transport attempts.
var errPrivateDestination = errors.New("destination is private/local — not tunnelable in emergency mode")

// errBlockedEndpoint protects the client from routing its own outer transport
// endpoint back into the TUN interface if Windows routing briefly misbehaves.
var errBlockedEndpoint = errors.New("destination is protected endpoint — not tunnelable")

// errNonDNSUDP is used by emergency transports to keep QUIC/NTP/background UDP
// from consuming scarce short-TCP operations. DNS can still be allowed.
var errNonDNSUDP = errors.New("non-DNS UDP disabled in emergency mode")

// errTargetAdmission is returned when a duplicate target waits behind an
// in-flight/cooling-down open until the caller's TCP connect deadline expires.
var errTargetAdmission = errors.New("target admission deadline exceeded")

var errAttemptBudget = errors.New("insufficient dial attempt budget")

// errRecoveryBackoff is returned when emergency transport is deliberately
// pausing new TCP opens so the short-TCP worker pool can drain after a storm.
var errRecoveryBackoff = errors.New("emergency recovery backoff active")

// errUDPDialFailed wraps a UDP-tunnel open failure (was: stub returning
// "does not transport UDP" prior to wiring up H2-CONNECT UDP/1 protocol).
var errUDPDialFailed = errors.New("tamizdat UDP relay failed")

// isJunkDestination filters out destinations that won't survive an internet
// round-trip: link-local (169.254/16), multicast (224.0.0.0/4), limited
// broadcast (255.255.255.255), zero (0.0.0.0). These come from Windows
// auto-IP (NetBIOS broadcasts), mDNS, LLMNR, etc — silent local-drop is
// correct.
func isJunkDestination(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	if addr.Is4() {
		v4 := addr.As4()
		// 255.255.255.255 limited broadcast
		if v4[0] == 0xff && v4[1] == 0xff && v4[2] == 0xff && v4[3] == 0xff {
			return true
		}
		// 169.254/16 link-local (already covered by IsLinkLocalUnicast but
		// belt-and-braces in case the netip detection is conservative)
		if v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}

func isPrivateDestination(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	return addr.Unmap().IsPrivate()
}

type tamizdatProxyDialer struct {
	client                  ProxyClient
	dispatcher              *node.Dispatcher
	debug                   bool
	dialAttemptTimeout      time.Duration
	openSlots               chan struct{}
	activeSlots             chan struct{}
	dialOpenInterval        time.Duration
	openPaceMu              sync.Mutex
	openTokens              float64
	openTokensAt            time.Time
	dialTargetCooldown      time.Duration
	dialTargetCooldownMax   time.Duration
	dialMinAttemptBudget    time.Duration
	dialRecoveryThreshold   int
	dialRecoveryBackoff     time.Duration
	recoveryMu              sync.Mutex
	recoveryFailures        int
	recoveryUntil           time.Time
	targetMu                sync.Mutex
	targetGates             map[string]*targetGate
	activeMu                sync.Mutex
	activeConns             map[*activeSlotConn]struct{}
	dropPrivateDestinations bool
	dropAllUDP              bool
	dropNonDNSUDP           bool
	blockedEndpoints        map[netip.AddrPort]struct{}
	// silent UDP counters: log a summary once per logEvery interval instead of per-flow spam
	udpDropped      atomic.Uint64
	ipv6Drops       atomic.Uint64
	dialRetries     atomic.Uint64
	activeEvictions atomic.Uint64
	noisyThrottles  atomic.Uint64
	stopOnce        atomic.Bool
}

type targetGate struct {
	inFlight      int
	cooldownUntil time.Time
	failures      int
	changed       chan struct{}
	// recentOpens / windowStart track this target's short-TCP open rate so a
	// destination that keeps re-opening can be paced down as background noise.
	recentOpens int
	windowStart time.Time
}

// dialerMetricsInterval is how often the dialer logs slot/gate occupancy and
// any aggregated UDP/junk drop counts. PoC anti-stick diagnostic cadence.
const dialerMetricsInterval = 10 * time.Second
const defaultDialAttemptTimeout = 3 * time.Second
const openPaceBurst = 24

// Noisy-target suppression: a destination granted more than
// noisyTargetThreshold short-TCP opens within noisyTargetWindow is paced with
// noisyTargetCooldown between further opens — even when those opens succeed —
// so background chatter to a handful of IPs cannot starve a foreground
// page-load of the scarce short-TCP budget. Active only when per-target
// cooldowns are enabled (positive dialTargetCooldown).
const noisyTargetWindow = 10 * time.Second
const noisyTargetThreshold = 10
const noisyTargetCooldown = 750 * time.Millisecond

// maxConcurrentPerTarget caps simultaneous logical-stream OPENs to one
// destination. A strict limit of 1 serialized a page's parallel connections
// to a single CDN IP into single-file, which on a slow restricted path hung
// the page; a small cap lets a page parallelize while still stopping one
// target from stampeding the whole short-TCP budget.
const maxConcurrentPerTarget = 6

// targetFailuresBeforeCooldown is how many consecutive failed OPENs (with no
// success in between) a target accumulates before it is cooled down. A single
// transient OPEN failure is normal on the restricted path and must not block
// new opens to the destination of the page being loaded.
const targetFailuresBeforeCooldown = 3

// activeSlotIdleTimeout bounds how long a tunnelled flow may hold a tunengine
// active slot with zero bytes moving in either direction. Past this the flow
// is treated as abandoned (gVisor/tun2socks never tore it down — e.g. a
// browser killed mid-storm) and is force-closed so the slot returns to the
// pool. Backstop to the fragpoc DOWN-scheduler stuck killer.
const activeSlotIdleTimeout = 120 * time.Second
const activeSlotEvictWait = 300 * time.Millisecond
const activeSlotSoftEvictIdle = 15 * time.Second

func newTamizdatProxyDialer(client ProxyClient, debug bool, dispatcher *node.Dispatcher, dialAttemptTimeout time.Duration, dialConcurrency int, dialActiveConcurrency int, dialOpenInterval time.Duration, dialTargetCooldown time.Duration, dialTargetCooldownMax time.Duration, dialMinAttemptBudget time.Duration, dialRecoveryThreshold int, dialRecoveryBackoff time.Duration, dropPrivateDestinations bool, dropAllUDP bool, dropNonDNSUDP bool, blockedEndpoints []netip.AddrPort) *tamizdatProxyDialer {
	if dialAttemptTimeout <= 0 {
		dialAttemptTimeout = defaultDialAttemptTimeout
	}
	var openSlots chan struct{}
	if dialConcurrency > 0 {
		openSlots = make(chan struct{}, dialConcurrency)
	}
	var activeSlots chan struct{}
	if dialActiveConcurrency > 0 {
		activeSlots = make(chan struct{}, dialActiveConcurrency)
	}
	blocked := make(map[netip.AddrPort]struct{}, len(blockedEndpoints))
	for _, ep := range blockedEndpoints {
		if ep.IsValid() {
			blocked[ep] = struct{}{}
		}
	}
	d := &tamizdatProxyDialer{
		client:                  client,
		dispatcher:              dispatcher,
		debug:                   debug,
		dialAttemptTimeout:      dialAttemptTimeout,
		openSlots:               openSlots,
		activeSlots:             activeSlots,
		dialOpenInterval:        dialOpenInterval,
		dialTargetCooldown:      dialTargetCooldown,
		dialTargetCooldownMax:   dialTargetCooldownMax,
		dialMinAttemptBudget:    dialMinAttemptBudget,
		dialRecoveryThreshold:   dialRecoveryThreshold,
		dialRecoveryBackoff:     dialRecoveryBackoff,
		targetGates:             make(map[string]*targetGate),
		activeConns:             make(map[*activeSlotConn]struct{}),
		dropPrivateDestinations: dropPrivateDestinations,
		dropAllUDP:              dropAllUDP,
		dropNonDNSUDP:           dropNonDNSUDP,
		blockedEndpoints:        blocked,
	}
	currentDialer.Store(d)
	go d.summaryLoop()
	return d
}

func (d *tamizdatProxyDialer) snapshot() map[string]any {
	d.targetMu.Lock()
	gates := len(d.targetGates)
	d.targetMu.Unlock()

	d.recoveryMu.Lock()
	recFailures := d.recoveryFailures
	recRemaining := time.Until(d.recoveryUntil)
	d.recoveryMu.Unlock()
	if recRemaining < 0 {
		recRemaining = 0
	}

	d.activeMu.Lock()
	activeConns := len(d.activeConns)
	d.activeMu.Unlock()

	out := map[string]any{
		"active":                 true,
		"debug":                  d.debug,
		"active_conns":           activeConns,
		"target_gates":           gates,
		"recovery_failures":      recFailures,
		"recovery_active":        recRemaining > 0,
		"recovery_remaining_ms":  recRemaining.Milliseconds(),
		"udp_dropped_total":      d.udpDropped.Load(),
		"ipv6_dropped_total":     d.ipv6Drops.Load(),
		"dial_retries_total":     d.dialRetries.Load(),
		"active_evictions_total": d.activeEvictions.Load(),
		"noisy_throttles_total":  d.noisyThrottles.Load(),
	}
	if d.openSlots != nil {
		out["open_slots_enabled"] = true
		out["open_slots_in_use"] = len(d.openSlots)
		out["open_slots_capacity"] = cap(d.openSlots)
	} else {
		out["open_slots_enabled"] = false
		out["open_slots_in_use"] = 0
		out["open_slots_capacity"] = 0
	}
	if d.activeSlots != nil {
		out["active_slots_enabled"] = true
		out["active_slots_in_use"] = len(d.activeSlots)
		out["active_slots_capacity"] = cap(d.activeSlots)
	} else {
		out["active_slots_enabled"] = false
		out["active_slots_in_use"] = 0
		out["active_slots_capacity"] = 0
	}
	return out
}

func (d *tamizdatProxyDialer) summaryLoop() {
	t := time.NewTicker(dialerMetricsInterval)
	defer t.Stop()
	var lastUDPDropped, lastIPv6Drops, lastDialRetries uint64
	var lastActiveEvictions, lastNoisyThrottles uint64
	for range t.C {
		if d.stopOnce.Load() {
			return
		}
		// Anti-stick backstop: reclaim active slots pinned by abandoned flows
		// whose gVisor side was never torn down.
		d.reapIdleActiveConns()
		// GC idle per-target gates so fail-once / contacted-once destinations
		// do not accumulate for the lifetime of the process.
		d.reapStaleTargetGates()
		// Slot/gate occupancy. In H2 mode this is useful only when debug is on;
		// in emergency mode it also shows whether admission gates are saturated.
		if d.debug || d.activeSlots != nil || d.openSlots != nil {
			d.targetMu.Lock()
			gates := len(d.targetGates)
			d.targetMu.Unlock()
			d.recoveryMu.Lock()
			recFailures := d.recoveryFailures
			recActive := time.Now().Before(d.recoveryUntil)
			d.recoveryMu.Unlock()
			d.activeMu.Lock()
			activeConns := len(d.activeConns)
			d.activeMu.Unlock()
			evictionsTotal := d.activeEvictions.Load()
			noisyTotal := d.noisyThrottles.Load()
			evictionsDelta := evictionsTotal - lastActiveEvictions
			noisyDelta := noisyTotal - lastNoisyThrottles
			lastActiveEvictions = evictionsTotal
			lastNoisyThrottles = noisyTotal
			log.Printf("[DIALER-METRICS] active_conns=%d active_slots=%d/%d open_slots=%d/%d target_gates=%d recovery_failures=%d recovery_active=%t active_evictions=%d noisy_throttles=%d",
				activeConns,
				len(d.activeSlots), cap(d.activeSlots),
				len(d.openSlots), cap(d.openSlots),
				gates, recFailures, recActive, evictionsDelta, noisyDelta)
		}

		// UDP/junk drop summary — only when something was dropped.
		udpTotal := d.udpDropped.Load()
		v6Total := d.ipv6Drops.Load()
		retryTotal := d.dialRetries.Load()
		udp := udpTotal - lastUDPDropped
		v6 := v6Total - lastIPv6Drops
		bp := retryTotal - lastDialRetries
		lastUDPDropped = udpTotal
		lastIPv6Drops = v6Total
		lastDialRetries = retryTotal
		if udp == 0 && v6 == 0 && bp == 0 {
			continue
		}
		log.Printf("dropped %d UDP/junk %d IPv6 flows; %d dials retried after transient transport failure (last %s)", udp, v6, bp, dialerMetricsInterval)
	}
}

func (d *tamizdatProxyDialer) Stop() {
	d.stopOnce.Store(true)
	currentDialer.CompareAndSwap(d, nil)
}

func (d *tamizdatProxyDialer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	if metadata == nil {
		return nil, errors.New("nil metadata")
	}
	if metadata.Network != M.TCP {
		// Should not happen — UDP goes via DialUDP — but guard anyway.
		d.udpDropped.Add(1)
		return nil, fmt.Errorf("unsupported network %s", metadata.Network)
	}
	if !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid destination IP")
	}
	if isJunkDestination(metadata.DstIP) {
		// Silent local-drop. Aggregate counter via udpDropped (technically TCP
		// here but sharing the bucket avoids splitting the summary log).
		d.udpDropped.Add(1)
		return nil, errJunkDestination
	}
	if d.isBlockedEndpoint(metadata.DstIP, uint16(metadata.DstPort)) {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[endpoint drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errBlockedEndpoint
	}
	if d.dropPrivateDestinations && isPrivateDestination(metadata.DstIP) {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[private drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errPrivateDestination
	}
	if !metadata.DstIP.Is4() {
		d.ipv6Drops.Add(1)
		if d.debug {
			log.Printf("[ipv6 drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, fmt.Errorf("IPv6 destination %s disabled in v1", metadata.DestinationAddress())
	}

	dest := metadata.DestinationAddress()
	src := metadata.SourceAddress()
	startedAt := time.Now()
	if d.debug {
		log.Printf("[TCP-START] %s -> %s", src, dest)
	}
	if err := d.waitRecoveryWindow(ctx); err != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (recovery wait: %v)", src, dest, time.Since(startedAt).Milliseconds(), err)
		return nil, err
	}
	releaseTarget, targetErr := d.acquireTargetGate(ctx, dest)
	if targetErr != nil {
		d.recordDialAdmission(false)
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (target admission ctx done)", src, dest, time.Since(startedAt).Milliseconds())
		return nil, targetErr
	}
	targetOK := false
	defer func() {
		releaseTarget(targetOK)
		d.recordDialAdmission(targetOK)
	}()
	if err := d.requireAttemptBudget(ctx); err != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (%v)", src, dest, time.Since(startedAt).Milliseconds(), err)
		return nil, err
	}
	releaseActiveSlot, activeSlotErr := d.acquireActiveSlot(ctx)
	if activeSlotErr != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (active admission ctx done)", src, dest, time.Since(startedAt).Milliseconds())
		return nil, activeSlotErr
	}
	activeSlotHeld := true
	defer func() {
		if activeSlotHeld {
			releaseActiveSlot()
		}
	}()

	if err := d.acquireOpenPace(ctx); err != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (open pace ctx done)", src, dest, time.Since(startedAt).Milliseconds())
		return nil, err
	}
	if err := d.requireAttemptBudget(ctx); err != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (%v)", src, dest, time.Since(startedAt).Milliseconds(), err)
		return nil, err
	}

	releaseOpenSlot, slotErr := d.acquireOpenSlot(ctx)
	if slotErr != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (open admission ctx done)", src, dest, time.Since(startedAt).Milliseconds())
		return nil, slotErr
	}
	defer releaseOpenSlot()
	if err := d.requireAttemptBudget(ctx); err != nil {
		log.Printf("[TCP-CANCEL] %s -> %s before attempt in %dms (%v)", src, dest, time.Since(startedAt).Milliseconds(), err)
		return nil, err
	}

	// Retry on scheduler backpressure (no outer transport with budget yet, prewarm in flight).
	// Browsers pump dozens of parallel TCP dials; first attempts may race ahead of prewarm.
	var (
		conn net.Conn
		err  error
	)
	for attempt := 0; attempt < 6; attempt++ {
		if err := d.requireAttemptBudget(ctx); err != nil {
			log.Printf("[TCP-CANCEL] %s -> %s before attempt %d in %dms (%v)", src, dest, attempt+1, time.Since(startedAt).Milliseconds(), err)
			return nil, err
		}
		attemptStart := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, d.dialAttemptTimeout)
		conn, err = d.dialTCP(dialCtx, metadata, dest)
		cancel()
		if err == nil {
			targetOK = true
			if d.debug {
				log.Printf("[TCP-OK]    %s -> %s after %d attempt(s) in %dms", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			}
			activeSlotHeld = false
			asc := &activeSlotConn{Conn: conn, release: releaseActiveSlot, dialer: d}
			asc.touch()
			if d.activeSlots != nil || d.debug {
				d.registerActiveConn(asc)
			}
			return asc, nil
		}
		if !isRetryableDialError(err) {
			// Hard failure — not transient. Operator wants to see exactly where it fell apart.
			log.Printf("[TCP-FAIL]  %s -> %s after %d attempt(s) in %dms: %v",
				src, dest, attempt+1, time.Since(startedAt).Milliseconds(), err)
			return nil, err
		}
		d.dialRetries.Add(1)
		log.Printf("[TCP-WAIT]  %s -> %s attempt %d transient (%dms): %v",
			src, dest, attempt+1, time.Since(attemptStart).Milliseconds(), err)
		select {
		case <-ctx.Done():
			log.Printf("[TCP-CANCEL] %s -> %s after %d attempt(s) in %dms (ctx done)", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			return nil, ctx.Err()
		case <-time.After(time.Duration(50<<attempt) * time.Millisecond):
			// 50ms, 100ms, 200ms, 400ms, 800ms, 1600ms = ~3.15s total worst case
		}
	}
	log.Printf("[TCP-EXHAUSTED] %s -> %s all 6 attempts hit transient transport failures (%dms total): %v",
		src, dest, time.Since(startedAt).Milliseconds(), err)
	return nil, err
}

func (d *tamizdatProxyDialer) requireAttemptBudget(ctx context.Context) error {
	if d.dialMinAttemptBudget <= 0 {
		return nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	remaining := time.Until(deadline)
	if remaining >= d.dialMinAttemptBudget {
		return nil
	}
	if remaining <= 0 {
		return ctx.Err()
	}
	return fmt.Errorf("%w: remaining %s < %s", errAttemptBudget, remaining.Round(time.Millisecond), d.dialMinAttemptBudget)
}

func (d *tamizdatProxyDialer) waitRecoveryWindow(ctx context.Context) error {
	if d.dialRecoveryThreshold <= 0 || d.dialRecoveryBackoff <= 0 {
		return nil
	}
	for {
		d.recoveryMu.Lock()
		now := time.Now()
		wait := time.Duration(0)
		if now.Before(d.recoveryUntil) {
			wait = time.Until(d.recoveryUntil)
		}
		d.recoveryMu.Unlock()
		if wait <= 0 {
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return fmt.Errorf("%w: %w", errRecoveryBackoff, ctx.Err())
		case <-timer.C:
		}
	}
}

func (d *tamizdatProxyDialer) recordDialAdmission(success bool) {
	if d.dialRecoveryThreshold <= 0 || d.dialRecoveryBackoff <= 0 {
		return
	}
	d.recoveryMu.Lock()
	defer d.recoveryMu.Unlock()
	if success {
		d.recoveryFailures = 0
		return
	}
	now := time.Now()
	if now.Before(d.recoveryUntil) {
		return
	}
	d.recoveryFailures++
	if d.recoveryFailures < d.dialRecoveryThreshold {
		return
	}
	d.recoveryFailures = 0
	d.recoveryUntil = now.Add(d.dialRecoveryBackoff)
	log.Printf("[TCP-RECOVERY] pausing new TCP opens for %s after %d failed admissions", d.dialRecoveryBackoff, d.dialRecoveryThreshold)
}

func (d *tamizdatProxyDialer) dialTCP(ctx context.Context, metadata *M.Metadata, dest string) (net.Conn, error) {
	if d.dispatcher != nil {
		conn, _, err := d.dispatcher.Dispatch(ctx, requestFromMetadata(metadata))
		return conn, err
	}
	if d.client == nil {
		return nil, errors.New("nil tamizdat client")
	}
	return d.client.DialContext(ctx, "tcp", dest)
}

func (d *tamizdatProxyDialer) acquireOpenSlot(ctx context.Context) (func(), error) {
	if d.openSlots == nil {
		return func() {}, nil
	}
	select {
	case d.openSlots <- struct{}{}:
		return func() { <-d.openSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *tamizdatProxyDialer) acquireActiveSlot(ctx context.Context) (func(), error) {
	if d.activeSlots == nil {
		return func() {}, nil
	}
	for {
		select {
		case d.activeSlots <- struct{}{}:
			var once sync.Once
			return func() { once.Do(func() { <-d.activeSlots }) }, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(activeSlotEvictWait):
			d.evictOneIdleActiveConn()
		}
	}
}

type activeSlotConn struct {
	net.Conn
	release      func()
	once         sync.Once
	dialer       *tamizdatProxyDialer
	lastActivity atomic.Int64 // unix nanos of last non-empty Read/Write
}

func (c *activeSlotConn) touch() {
	c.lastActivity.Store(time.Now().UnixNano())
}

func (c *activeSlotConn) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, c.lastActivity.Load()))
}

func (c *activeSlotConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *activeSlotConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *activeSlotConn) Close() error {
	c.once.Do(func() {
		c.release()
		if c.dialer != nil {
			c.dialer.unregisterActiveConn(c)
		}
	})
	return c.Conn.Close()
}

func (d *tamizdatProxyDialer) registerActiveConn(c *activeSlotConn) {
	d.activeMu.Lock()
	if d.activeConns == nil {
		d.activeConns = make(map[*activeSlotConn]struct{})
	}
	d.activeConns[c] = struct{}{}
	d.activeMu.Unlock()
}

func (d *tamizdatProxyDialer) unregisterActiveConn(c *activeSlotConn) {
	d.activeMu.Lock()
	delete(d.activeConns, c)
	d.activeMu.Unlock()
}

func (d *tamizdatProxyDialer) evictOneIdleActiveConn() {
	now := time.Now()
	var victim *activeSlotConn
	var idle time.Duration
	d.activeMu.Lock()
	for c := range d.activeConns {
		if cur := c.idleFor(now); victim == nil || cur > idle {
			victim = c
			idle = cur
		}
	}
	d.activeMu.Unlock()
	if victim == nil || idle < activeSlotSoftEvictIdle {
		return
	}
	_ = victim.Close()
	d.activeEvictions.Add(1)
	log.Printf("[ACTIVE-EVICT] reclaimed slot from %s (idle %s)",
		victim.RemoteAddr(), idle.Round(time.Second))
}

// reapIdleActiveConns force-closes flows that have held an active slot with no
// bytes moving in either direction for activeSlotIdleTimeout. This is the
// anti-stick backstop: if gVisor/tun2socks never tears a dead flow down, its
// slot would otherwise stay pinned forever and the emergency transport wedges
// once every slot fills. Closing the conn releases the slot, unblocks any
// gVisor Read/Write, and closes the underlying fragpoc stream.
func (d *tamizdatProxyDialer) reapIdleActiveConns() {
	if d.activeSlots == nil || activeSlotIdleTimeout <= 0 {
		return
	}
	now := time.Now()
	var victims []*activeSlotConn
	d.activeMu.Lock()
	for c := range d.activeConns {
		if c.idleFor(now) >= activeSlotIdleTimeout {
			victims = append(victims, c)
		}
	}
	d.activeMu.Unlock()
	for _, c := range victims {
		log.Printf("[ACTIVE-REAP] force-closing idle flow %s (no I/O for %s)",
			c.RemoteAddr(), c.idleFor(now).Round(time.Second))
		_ = c.Close()
	}
}

func (d *tamizdatProxyDialer) acquireOpenPace(ctx context.Context) error {
	if d.dialOpenInterval <= 0 {
		return nil
	}
	for {
		d.openPaceMu.Lock()
		now := time.Now()

		if d.openTokensAt.IsZero() {
			d.openTokens = openPaceBurst
			d.openTokensAt = now
		}

		d.openTokens += float64(now.Sub(d.openTokensAt)) / float64(d.dialOpenInterval)
		if d.openTokens > openPaceBurst {
			d.openTokens = openPaceBurst
		}
		d.openTokensAt = now

		if d.openTokens >= 1 {
			d.openTokens -= 1
			d.openPaceMu.Unlock()
			return nil
		}

		wait := time.Duration((1 - d.openTokens) * float64(d.dialOpenInterval))
		d.openPaceMu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *tamizdatProxyDialer) acquireTargetGate(ctx context.Context, target string) (func(success bool), error) {
	if !d.targetGateEnabled() {
		return func(bool) {}, nil
	}
	for {
		d.targetMu.Lock()
		g := d.targetGates[target]
		if g == nil {
			g = &targetGate{changed: make(chan struct{})}
			d.targetGates[target] = g
		}
		now := time.Now()
		if g.inFlight < maxConcurrentPerTarget && !now.Before(g.cooldownUntil) {
			g.inFlight++
			g.noteOpen(now)
			d.targetMu.Unlock()
			return func(success bool) {
				d.releaseTargetGate(target, success)
			}, nil
		}
		changed := g.changed
		cooldownUntil := g.cooldownUntil
		d.targetMu.Unlock()

		var timer *time.Timer
		var timerC <-chan time.Time
		if now.Before(cooldownUntil) {
			timer = time.NewTimer(time.Until(cooldownUntil))
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return nil, fmt.Errorf("%w: %w", errTargetAdmission, ctx.Err())
		case <-changed:
			stopTimer(timer)
		case <-timerC:
		}
	}
}

func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func (d *tamizdatProxyDialer) releaseTargetGate(target string, success bool) {
	if !d.targetGateEnabled() {
		return
	}
	d.targetMu.Lock()
	defer d.targetMu.Unlock()
	g := d.targetGates[target]
	if g == nil {
		return
	}
	now := time.Now()
	if g.inFlight > 0 {
		g.inFlight--
	}
	if success {
		g.failures = 0
		// A target that keeps re-opening at a high rate — even when every
		// open succeeds — is background chatter; pace it down so it cannot
		// monopolise the short-TCP budget against a foreground page-load.
		if d.dialTargetCooldown > 0 && g.isNoisy(now) {
			g.cooldownUntil = now.Add(noisyTargetCooldown)
			d.noisyThrottles.Add(1)
		} else {
			g.cooldownUntil = time.Time{}
		}
	} else {
		g.failures++
		// Only cool a target down once it has failed consistently. A single
		// transient OPEN failure is normal on the restricted path and must
		// not block new opens to the destination of the page being loaded.
		if g.failures >= targetFailuresBeforeCooldown {
			if cooldown := d.targetCooldownDuration(); cooldown > 0 {
				g.cooldownUntil = now.Add(cooldown)
			} else {
				g.cooldownUntil = time.Time{}
			}
		}
	}
	close(g.changed)
	g.changed = make(chan struct{})
	// Keep the gate while its rate window is live so per-target open counts
	// accumulate across consecutive opens; a later release or
	// reapStaleTargetGates drops it once the window goes stale.
	if g.inFlight == 0 && g.cooldownUntil.IsZero() && g.rateWindowStale(now) {
		delete(d.targetGates, target)
	}
}

// noteOpen records that one short-TCP open was granted for this target,
// rolling the rate window if the previous one has elapsed.
func (g *targetGate) noteOpen(now time.Time) {
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= noisyTargetWindow {
		g.windowStart = now
		g.recentOpens = 0
	}
	g.recentOpens++
}

// isNoisy reports whether this target exceeded noisyTargetThreshold opens
// within the current, still-live rate window.
func (g *targetGate) isNoisy(now time.Time) bool {
	return !g.windowStart.IsZero() &&
		now.Sub(g.windowStart) < noisyTargetWindow &&
		g.recentOpens > noisyTargetThreshold
}

// rateWindowStale reports whether the rate window has elapsed, meaning the
// gate carries no live open-rate state worth preserving.
func (g *targetGate) rateWindowStale(now time.Time) bool {
	return g.windowStart.IsZero() || now.Sub(g.windowStart) >= noisyTargetWindow
}

// reapStaleTargetGates drops gates that are idle: not in-flight, past any
// cooldown, and with an elapsed rate window. Without this, gates for targets
// that fail once or are contacted once and never retried would accumulate for
// the lifetime of the process.
func (d *tamizdatProxyDialer) reapStaleTargetGates() {
	if !d.targetGateEnabled() {
		return
	}
	now := time.Now()
	d.targetMu.Lock()
	for target, g := range d.targetGates {
		if g.inFlight == 0 && now.After(g.cooldownUntil) && g.rateWindowStale(now) {
			delete(d.targetGates, target)
		}
	}
	d.targetMu.Unlock()
}

func (d *tamizdatProxyDialer) targetGateEnabled() bool {
	return d.dialTargetCooldown != 0
}

// targetCooldownDuration is the flat cooldown applied to a target after it
// fails targetFailuresBeforeCooldown times in a row. It deliberately does NOT
// escalate: an escalating per-target cooldown turned transient restricted-
// network failures into multi-second blocks on the destination of the active
// page. dialTargetCooldownMax only clamps an over-large configured base.
func (d *tamizdatProxyDialer) targetCooldownDuration() time.Duration {
	if d.dialTargetCooldown <= 0 {
		return 0
	}
	cooldown := d.dialTargetCooldown
	if d.dialTargetCooldownMax > 0 && cooldown > d.dialTargetCooldownMax {
		cooldown = d.dialTargetCooldownMax
	}
	return cooldown
}

func (d *tamizdatProxyDialer) isBlockedEndpoint(addr netip.Addr, port uint16) bool {
	if len(d.blockedEndpoints) == 0 || !addr.IsValid() || port == 0 {
		return false
	}
	_, ok := d.blockedEndpoints[netip.AddrPortFrom(addr.Unmap(), port)]
	return ok
}

func requestFromMetadata(metadata *M.Metadata) *node.Request {
	return &node.Request{
		Network:    node.NetworkTCP,
		TargetHost: metadata.DstIP.String(),
		TargetPort: int(metadata.DstPort),
		SourceIP:   netIPFromAddr(metadata.SrcIP),
		InboundTag: "tun",
	}
}

func netIPFromAddr(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	if addr.Is4() {
		v4 := addr.As4()
		return net.IPv4(v4[0], v4[1], v4[2], v4[3])
	}
	v6 := addr.As16()
	ip := make(net.IP, net.IPv6len)
	copy(ip, v6[:])
	return ip
}

func isRetryableDialError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := err.Error()
	// All of these are transient scheduler / outer-transport states during
	// logical stream OPEN. Retrying here hides short-lived carrier/NAT loss from
	// the gVisor TCP layer without duplicating application payload.
	return strings.Contains(s, "scheduler backpressure") ||
		strings.Contains(s, "ErrSchedulerBackpressure") ||
		strings.Contains(s, "transport is not active") ||
		strings.Contains(s, "no active transport") ||
		strings.Contains(s, "OPEN_STREAM") ||
		strings.Contains(s, "use of closed network connection") || // outer TCP died — pool will create fresh transport on retry
		strings.Contains(s, "transport closed") || // pool member self-marked dead
		strings.Contains(s, "transport draining") || // mid-rotation; next attempt picks the new one
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connection timed out") ||
		strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "forcibly closed by the remote host") ||
		strings.Contains(s, "wsarecv") ||
		s == "EOF" ||
		strings.Contains(s, "GOAWAY")
}

func (d *tamizdatProxyDialer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	if metadata == nil {
		return nil, errors.New("nil metadata")
	}
	if !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid destination IP")
	}
	if isJunkDestination(metadata.DstIP) {
		d.udpDropped.Add(1)
		// No log per-packet — summary every 30s shows count.
		return nil, errJunkDestination
	}
	if d.isBlockedEndpoint(metadata.DstIP, uint16(metadata.DstPort)) {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[endpoint udp drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errBlockedEndpoint
	}
	if d.dropPrivateDestinations && isPrivateDestination(metadata.DstIP) {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[private udp drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errPrivateDestination
	}
	if d.dropAllUDP {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[udp policy drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errNonDNSUDP
	}
	if d.dropNonDNSUDP && metadata.DstPort != 53 {
		d.udpDropped.Add(1)
		if d.debug {
			log.Printf("[udp policy drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, errNonDNSUDP
	}
	if !metadata.DstIP.Is4() {
		d.ipv6Drops.Add(1)
		if d.debug {
			log.Printf("[ipv6 udp drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, fmt.Errorf("IPv6 UDP destination %s disabled in v1", metadata.DestinationAddress())
	}
	dest := metadata.DestinationAddress()
	src := metadata.SourceAddress()
	startedAt := time.Now()
	if d.debug {
		log.Printf("[UDP-START] %s -> %s", src, dest)
	}
	admissionCtx, admissionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	releaseOpenSlot, slotErr := d.acquireOpenSlot(admissionCtx)
	admissionCancel()
	if slotErr != nil {
		log.Printf("[UDP-CANCEL] %s -> %s before attempt in %dms (open admission ctx done)", src, dest, time.Since(startedAt).Milliseconds())
		d.udpDropped.Add(1)
		return nil, fmt.Errorf("%w: %s", errUDPDialFailed, slotErr.Error())
	}
	defer releaseOpenSlot()

	// Retry on transient backpressure (transport scheduler, prewarm in flight).
	var (
		pc  net.PacketConn
		err error
	)
	for attempt := 0; attempt < 4; attempt++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), d.dialAttemptTimeout)
		pc, err = d.client.DialUDP(dialCtx, dest)
		cancel()
		if err == nil {
			if d.debug {
				log.Printf("[UDP-OK]    %s -> %s after %d attempt(s) in %dms", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			}
			return pc, nil
		}
		if !isRetryableDialError(err) {
			log.Printf("[UDP-FAIL]  %s -> %s after %d attempt(s) in %dms: %v",
				src, dest, attempt+1, time.Since(startedAt).Milliseconds(), err)
			d.udpDropped.Add(1)
			return nil, fmt.Errorf("%w: %s", errUDPDialFailed, err.Error())
		}
		d.dialRetries.Add(1)
		log.Printf("[UDP-WAIT]  %s -> %s attempt %d transient: %v", src, dest, attempt+1, err)
		time.Sleep(time.Duration(50<<attempt) * time.Millisecond)
	}
	log.Printf("[UDP-EXHAUSTED] %s -> %s 4 attempts in %dms: %v", src, dest, time.Since(startedAt).Milliseconds(), err)
	d.udpDropped.Add(1)
	return nil, fmt.Errorf("%w: %s", errUDPDialFailed, err.Error())
}
