package tamizdat

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Per-source-IP rate-limit on masquerade forward (compass v2 §3.11):
// without this, an attacker without PSK can flood the server with
// random ClientHellos -- each one ECDH+HKDF+HMAC-checked, fails auth,
// then the server opens a fresh TCP+TLS forward to ok.ru. Amplification
// factor: 1 attacker ClientHello -> 1 outbound TLS to cover origin.
// At 10 Gbps the attacker easily exhausts the server's upstream-bandwidth
// to ok.ru, AND can produce IP-reputation problems for the origin.
//
// review-A P2 redesign: replace the original step-function token bucket
// with a sliding-window probabilistic limiter. The hard-cap step function
// gives an active scanner a clean, stable signal: "the 11th probe in 60s
// always closes instantly". A real overloaded backend doesn't behave that
// way -- it degrades probabilistically and slows down. The new behaviour:
//
//   - <= soft  : always Forward
//   - (soft, hard] : Forward with probability (hard - n) / (hard - soft);
//                    otherwise DropAfterJitter
//   - > hard   : DropAfterJitter (mimics overloaded backend response)
//
// Soft = 5, Hard = 10, Window = 60s. Burst is implicit in the
// soft-threshold and the window length.

const (
	masqueradeWindowDuration = 60 * time.Second
	masqueradeSoftThreshold  = 5
	masqueradeHardCap        = 10
	masqueradeJitterMin      = 200 * time.Millisecond
	masqueradeJitterMax      = 800 * time.Millisecond
	masqueradeBucketTTL      = 5 * time.Minute
	masqueradeReapInterval   = 60 * time.Second

	// masqueradeMaxProbes caps the per-source slidingWindow.probes slice
	// so a flood from a single IP (e.g. 100k probes/s on a hot path
	// before the kernel rate-limits the SYNs) cannot grow the slice
	// without bound. The cap is set to 2*hardCap because anything beyond
	// hardCap inside the window is already an unconditional jitter-drop
	// — we only need enough headroom to remember the window edge, not
	// every probe. The oldest entries are dropped when the cap fires.
	// A-RR-3.
	masqueradeMaxProbes = 2 * masqueradeHardCap
)

// RateLimitDecision is the outcome of a masquerade-forward gate check.
// Forward = let the probe through (open the TCP forward to the cover
// origin). DropAfterJitter = hold the connection for
// masqueradeJitterMin..Max then close, mimicking the timing of an
// overloaded real backend (so the cliff isn't a clean signal to a
// scanner).
//
// A-RR-3 dropped the historical RateLimitDropSilent value: the limiter
// never returned it (silent drops give a scanner a clean timing signal
// the jitter-drop is meant to hide) and dead enum values invite future
// regressions where a caller adds a `case DropSilent` that quietly
// undoes the jitter pacing.
type RateLimitDecision int

const (
	RateLimitForward RateLimitDecision = iota
	RateLimitDropAfterJitter
)

type masqueradeRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*slidingWindow
	stop    chan struct{}
}

// slidingWindow tracks recent probe timestamps per source IP. The window
// is `masqueradeWindowDuration`; on each decide() we evict timestamps
// older than now-window then count the remainder.
type slidingWindow struct {
	probes []time.Time
}

func newMasqueradeRateLimiter() *masqueradeRateLimiter {
	rl := &masqueradeRateLimiter{
		buckets: make(map[string]*slidingWindow),
		stop:    make(chan struct{}),
	}
	go rl.reaper()
	return rl
}

// decide returns the rate-limit decision for a probe from `ip`. The probe
// timestamp is recorded regardless of the decision so that a sustained
// attack continues to count toward the window. This is consistent with
// "real backend overload" behaviour: an overloaded server still pays
// CPU on the connection even if it ultimately drops the work.
func (rl *masqueradeRateLimiter) decide(ip string) RateLimitDecision {
	if rl == nil {
		return RateLimitForward
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-masqueradeWindowDuration)

	w, ok := rl.buckets[ip]
	if !ok {
		w = &slidingWindow{}
		rl.buckets[ip] = w
	}

	// Evict expired timestamps. The slice is ordered (probes append in
	// time order), so a simple prefix-trim suffices.
	keep := 0
	for keep < len(w.probes) && w.probes[keep].Before(cutoff) {
		keep++
	}
	if keep > 0 {
		w.probes = append(w.probes[:0], w.probes[keep:]...)
	}

	// A-RR-3: bound the slice to masqueradeMaxProbes. Without this an
	// attacker flooding a single IP can grow w.probes without limit
	// inside one window (entries only age out after window-duration).
	// Drop the oldest entries when at capacity. All entries above
	// hardCap are jitter-drops anyway, so the eviction is semantically
	// safe — losing the exact ordering of historical-but-doomed probes
	// doesn't change the decision for the current probe.
	if len(w.probes) >= masqueradeMaxProbes {
		drop := len(w.probes) - masqueradeMaxProbes + 1
		w.probes = append(w.probes[:0], w.probes[drop:]...)
	}

	w.probes = append(w.probes, now)
	count := len(w.probes)

	switch {
	case count <= masqueradeSoftThreshold:
		return RateLimitForward
	case count <= masqueradeHardCap:
		// Probability of DROP scales linearly from 0 at soft+1 to 1 at hard.
		// At count = soft+1 (e.g. 6 with soft=5, hard=10), p_drop = 1/5 = 20%.
		// At count = hard (10), p_drop = 5/5 = 100%.
		num := uint64(count - masqueradeSoftThreshold)
		den := uint64(masqueradeHardCap - masqueradeSoftThreshold)
		if dropDraw(num, den) {
			return RateLimitDropAfterJitter
		}
		return RateLimitForward
	default:
		// count > hard: always drop with jitter.
		return RateLimitDropAfterJitter
	}
}

// allow keeps the legacy boolean API for any embedded caller that still
// wants a yes/no decision (forward vs not). Use decide() in new code.
func (rl *masqueradeRateLimiter) allow(ip string) bool {
	return rl.decide(ip) == RateLimitForward
}

// dropDraw returns true with probability num/den. Uses crypto/rand so the
// random source is unbiased and not predictable to an attacker who could
// otherwise time-correlate a deterministic PRNG seed.
func dropDraw(num, den uint64) bool {
	if den == 0 {
		return false
	}
	if num == 0 {
		return false
	}
	if num >= den {
		return true
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fail-open on the rare crypto/rand error: prefer letting the
		// probe through to risking a deterministic side-channel from
		// always-drop fallback.
		return false
	}
	r := binary.BigEndian.Uint64(b[:])
	// Threshold = floor((num/den) * 2^64).
	// To avoid overflow, compute via float for simplicity given small num/den.
	threshold := uint64(float64(num) / float64(den) * float64(^uint64(0)))
	return r < threshold
}

// jitterDelay returns a random delay in [masqueradeJitterMin, masqueradeJitterMax].
// Used by the server to hold a DropAfterJitter decision before closing.
func jitterDelay() time.Duration {
	span := uint64(masqueradeJitterMax - masqueradeJitterMin)
	if span == 0 {
		return masqueradeJitterMin
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return masqueradeJitterMin + time.Duration(span)/2
	}
	r := binary.BigEndian.Uint64(b[:]) % span
	return masqueradeJitterMin + time.Duration(r)
}

// reaper periodically deletes idle windows so the map doesn't grow without
// bound (probes from rotating bots).
func (rl *masqueradeRateLimiter) reaper() {
	t := time.NewTicker(masqueradeReapInterval)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-t.C:
			rl.reapExpiredBuckets(time.Now())
		}
	}
}

func (rl *masqueradeRateLimiter) reapExpiredBuckets(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-masqueradeBucketTTL)
	for ip, w := range rl.buckets {
		// Drop windows whose newest probe is older than the bucket TTL.
		// Empty windows are also dropped (never observed in practice but
		// cheap to handle).
		if len(w.probes) == 0 {
			delete(rl.buckets, ip)
			continue
		}
		newest := w.probes[len(w.probes)-1]
		if newest.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

func (rl *masqueradeRateLimiter) close() {
	close(rl.stop)
}

// extractRemoteIP pulls the IP portion of a net.Conn RemoteAddr() result.
// Falls back to the full string if SplitHostPort fails. IPv6 addresses are
// normalized to /64 prefixes so a single client allocation cannot create a fresh
// rate-limit bucket per 128-bit address; IPv4 remains per-host.
func extractRemoteIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if parsed.Is6() && !parsed.Is4In6() {
		if pfx, perr := parsed.Prefix(64); perr == nil {
			return pfx.Masked().String()
		}
	}
	return parsed.String()
}
