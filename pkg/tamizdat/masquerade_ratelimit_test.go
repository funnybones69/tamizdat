package tamizdat

import (
	"net"
	"testing"
	"time"
)

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

// review-A P2: the first masqueradeSoftThreshold probes from a single IP
// always Forward — no probabilistic drop in the soft band.
func TestMasqueradeRateLimiterSoftBandAlwaysForwards(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.10"
	for i := 0; i < masqueradeSoftThreshold; i++ {
		if d := rl.decide(ip); d != RateLimitForward {
			t.Fatalf("probe %d in soft band returned %v, want Forward", i+1, d)
		}
	}
}

// review-A P2: in the (soft, hard] band, drops scale linearly with count.
// At count = soft+1, p_drop ≈ 1/(hard-soft) = 20% with the 5/10 defaults.
// Over 1000 trials we expect ~200 drops; allow a generous tolerance to
// keep the test deterministic-flake-free under crypto/rand jitter.
func TestMasqueradeRateLimiterProbabilisticBand(t *testing.T) {
	const trials = 1000
	drops := 0
	for trial := 0; trial < trials; trial++ {
		rl := newMasqueradeRateLimiter()
		// Distinct IP per trial so each trial is independent.
		ip := makeIPv4(trial)
		// Burn the soft band (these never drop).
		for i := 0; i < masqueradeSoftThreshold; i++ {
			rl.decide(ip)
		}
		// The (soft+1)-th probe is the one with p_drop = 1/(hard-soft).
		// A-RR-3: the limiter only ever returns DropAfterJitter (the
		// historical RateLimitDropSilent value was removed as dead).
		if rl.decide(ip) == RateLimitDropAfterJitter {
			drops++
		}
		rl.close()
	}
	expected := trials / (masqueradeHardCap - masqueradeSoftThreshold)
	// ±5σ tolerance: σ ≈ √(n*p*(1-p)). For p=0.2, n=1000: σ ≈ 12.6, so 5σ ≈ 63.
	tolerance := 80
	if drops < expected-tolerance || drops > expected+tolerance {
		t.Fatalf("(soft+1)-th probe drops = %d/%d, expected ≈ %d ± %d", drops, trials, expected, tolerance)
	}
}

// review-A P2: above the hard cap, every additional probe is a
// jitter-drop. The very first probe in the over-cap band must be
// DropAfterJitter (never Forward, never Silent).
func TestMasqueradeRateLimiterOverHardCapAlwaysJitterDrops(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.20"
	// Drive count to hard+1 (probe 11 with hard=10).
	for i := 0; i < masqueradeHardCap; i++ {
		rl.decide(ip)
	}
	for i := 0; i < 5; i++ {
		if d := rl.decide(ip); d != RateLimitDropAfterJitter {
			t.Fatalf("over-cap probe returned %v, want DropAfterJitter", d)
		}
	}
}

// review-A P2: jitterDelay sits in the [min, max] interval. Sample many
// times to catch a broken mod / off-by-one quickly.
func TestJitterDelayWithinAdvertisedRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		d := jitterDelay()
		if d < masqueradeJitterMin || d > masqueradeJitterMax {
			t.Fatalf("jitterDelay sample %d = %v, outside [%v, %v]", i, d, masqueradeJitterMin, masqueradeJitterMax)
		}
	}
}

// IPv6 /64 collapse still works under the new sliding-window limiter:
// two distinct /128 addresses inside the same /64 share a single bucket
// so a client can't paper around the rate limit by hopping its EUI-64
// suffix. Probes 1..soft from one address + probes from the second
// address within the same /64 are counted together.
func TestMasqueradeRateLimiterIPv6Same64SharesBucket(t *testing.T) {
	addr1 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:12:1111::1"), Port: 443}
	addr2 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:12:2222::2"), Port: 443}
	key1 := extractRemoteIP(remoteAddrConn{remote: addr1})
	key2 := extractRemoteIP(remoteAddrConn{remote: addr2})

	if key1 != "2001:db8:abcd:12::/64" {
		t.Fatalf("IPv6 bucket key = %q, want /64 prefix", key1)
	}
	if key1 != key2 {
		t.Fatalf("same /64 produced different bucket keys: %q vs %q", key1, key2)
	}

	rl := newMasqueradeRateLimiter()
	defer rl.close()

	// Burn the soft band on key1.
	for i := 0; i < masqueradeSoftThreshold; i++ {
		if d := rl.decide(key1); d != RateLimitForward {
			t.Fatalf("soft-band probe %d on key1 returned %v, want Forward", i+1, d)
		}
	}
	// Drive past hard on key2 (shared window). After enough probes we
	// must see DropAfterJitter — proving the buckets are shared. We
	// don't assert the exact transition because the in-between band is
	// probabilistic; instead we assert that at least once in the
	// over-cap band we see a jitter drop.
	hits := 0
	for i := 0; i < masqueradeHardCap+10; i++ {
		if rl.decide(key2) == RateLimitDropAfterJitter {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("no DropAfterJitter observed on shared /64 — buckets aren't shared")
	}
}

// review-A P2: window TTL eviction. After more than masqueradeBucketTTL
// of inactivity, an idle bucket is reaped so the map can't grow forever
// against a rotating-source attacker.
func TestMasqueradeRateLimiterReapsIdleBucket(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.55"
	// Burn the soft band so the window has timestamps in it.
	for i := 0; i < masqueradeSoftThreshold; i++ {
		rl.decide(ip)
	}

	// Age the timestamps past the bucket TTL.
	rl.mu.Lock()
	w := rl.buckets[ip]
	old := time.Now().Add(-masqueradeBucketTTL - time.Second)
	for i := range w.probes {
		w.probes[i] = old
	}
	rl.mu.Unlock()

	rl.reapExpiredBuckets(time.Now())

	rl.mu.Lock()
	_, ok := rl.buckets[ip]
	rl.mu.Unlock()
	if ok {
		t.Fatal("idle bucket not reaped past masqueradeBucketTTL")
	}
}

// review-A A-RR-3: under a sustained flood from a single source IP the
// per-bucket slidingWindow.probes slice must stay bounded by
// masqueradeMaxProbes. Without this cap a hot probe path (the kernel
// can deliver thousands of SYNs/sec faster than the window-duration
// can age them out) grows the slice without limit and turns into a
// memory-exhaustion DoS amplifier — the very thing the rate-limiter
// was added to prevent.
//
// Flood the limiter with 100k probes from one IP and assert the slice
// stays at or below masqueradeMaxProbes throughout.
func TestMasqueradeRateLimiterSlidingWindowBounded(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.99"
	const flood = 100_000

	maxObserved := 0
	for i := 0; i < flood; i++ {
		rl.decide(ip)
		// Sample the slice length without taking the lock for every
		// call (overkill); peek every 1000 iterations is plenty to
		// catch unbounded growth.
		if i%1000 == 0 {
			rl.mu.Lock()
			n := len(rl.buckets[ip].probes)
			rl.mu.Unlock()
			if n > maxObserved {
				maxObserved = n
			}
		}
	}

	rl.mu.Lock()
	final := len(rl.buckets[ip].probes)
	rl.mu.Unlock()

	if final > masqueradeMaxProbes {
		t.Fatalf("after %d probes slice = %d, want ≤ %d", flood, final, masqueradeMaxProbes)
	}
	if maxObserved > masqueradeMaxProbes {
		t.Fatalf("peak slice during flood = %d, want ≤ %d", maxObserved, masqueradeMaxProbes)
	}
}

// A-RR-3: even when the bucket is at the cap, the limiter must keep
// returning DropAfterJitter (not silently fail-open). The semantic
// invariant: a flooded source IP NEVER gets Forward.
func TestMasqueradeRateLimiterStillDropsAtCap(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.100"
	// Fill past hardCap so we're firmly in the always-drop band.
	for i := 0; i < masqueradeMaxProbes*2; i++ {
		rl.decide(ip)
	}
	// Take a few more samples; all should be DropAfterJitter.
	for i := 0; i < 50; i++ {
		if d := rl.decide(ip); d != RateLimitDropAfterJitter {
			t.Fatalf("at-cap sample %d returned %v, want DropAfterJitter", i, d)
		}
	}
}

// makeIPv4 fabricates a unique IPv4 string from an integer. Used by the
// probabilistic-band test where each trial needs a fresh bucket.
func makeIPv4(i int) string {
	a := (i >> 16) & 0xff
	b := (i >> 8) & 0xff
	c := i & 0xff
	return netIPV4(byte(a), byte(b), byte(c)).String()
}

func netIPV4(a, b, c byte) net.IP {
	return net.IPv4(10, a, b, c)
}
