package tamizdat

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"

	utls "github.com/refraction-networking/utls"
)

// fingerprintRotator selects the uTLS ClientHelloID for new TCP
// connections. Historically (P1.3 of the Samizdat audit roadmap) it
// did a uniform-random pick per dial, but that's the loudest JA4 tell
// — one IP rotating Chrome → Firefox → Safari → Edge in minutes.
//
// Review-B B-1 (2026-05-09): switched to per-install pinning. The
// rotator deterministically selects ONE fingerprint at construction
// time, seeded from MasterShortID, and returns the same fingerprint
// for every dial. One client = one fingerprint for life of the
// install. mode argument still picks which family pool we choose
// from ("chrome" / "firefox" / "safari" / "edge" / "ios" / "mix").
//
// Review-B B-2 (2026-05-09): per-OS gating. Safari and iOS
// fingerprints are only included on darwin/ios (Apple TCP stack);
// shipping a Safari ClientHello from a Linux/Windows TCP stack
// produces a JA4/p0f collision a censor can flag.
type fingerprintRotator struct {
	pool   []utls.ClientHelloID
	pinned utls.ClientHelloID
}

// isApplePlatform reports whether the current runtime targets an
// Apple TCP stack — the only platforms where shipping a Safari /
// iOS ClientHello won't collide with a passive p0f-class fingerprinter.
func isApplePlatform() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "ios"
}

// newFingerprintRotator builds the family pool for `mode` and pins
// one fingerprint deterministically based on `seed`. If seed is empty
// (or shorter than 4 bytes), we fall back to a random pin (rare; only
// happens if MasterShortID is zero, which the client constructor
// rejects anyway).
func newFingerprintRotator(mode string, seed []byte) *fingerprintRotator {
	var pool []utls.ClientHelloID
	switch mode {
	case "", "mix", "auto", "rotate":
		// Weighted (by internet share). 2026-04-30 refresh: Chrome_Auto (=133)
		// includes X25519MLKEM768 in supported_groups -- matches real Chrome
		// 131+ post-quantum hybrid handshakes that Cloudflare/Google have
		// rolled out. Dropped Chrome 100/106 (would emit a "stale browser"
		// signature). Pool intentionally biased toward 2024-2025 versions
		// since real fleet of clients is heavily on the latest channels.
		//
		// B-2 (2026-05-09): Safari only on darwin/ios. Shipping a Safari
		// ClientHello from Linux/Windows = JA4 + p0f TCP-stack collision.
		//
		// B-3 (2026-05-09): HelloEdge_106 dropped. utls@v1.8.2
		// u_common.go:656 explicitly comments "HelloEdge_106 seems to
		// be incompatible with this library" — shipping it produces a
		// malformed Edge ClientHello (signature anomaly on the wire,
		// which is the opposite of what the parrot is meant to do).
		// Chrome family covers Edge users for now (Edge derives from
		// Chromium so the JA4 is broadly similar). A future utls bump
		// (B-4) may add a working modern Edge parrot.
		//
		// B-4 (2026-05-09): library version check. utls latest tag is
		// v1.8.2 (matches refraction-networking/utls master HEAD).
		// HelloChrome_Auto = HelloChrome_133 — already the newest
		// Chrome parrot available. No HelloChrome_134+ exists; no
		// working HelloEdge_>106 exists. NOT bumping go.mod (already
		// at v1.8.2). Operator said NO to hand-written
		// ClientHelloSpec, so we stay at Chrome 133 until upstream
		// publishes a newer parrot.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto, // = Chrome 133, ML-KEM-768 in supported_groups
			utls.HelloChrome_131,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_120,
			utls.HelloFirefox_120,
		}
		if isApplePlatform() {
			pool = append(pool, utls.HelloSafari_16_0)
		}
	case "firefox":
		pool = []utls.ClientHelloID{
			utls.HelloFirefox_120, utls.HelloFirefox_105, utls.HelloFirefox_102,
		}
	case "safari":
		// B-2: Safari only makes sense on Apple TCP stacks. On other
		// OSes, fall back to Chrome family — explicit "safari" mode
		// would otherwise produce a JA4/p0f collision.
		if isApplePlatform() {
			pool = []utls.ClientHelloID{
				utls.HelloSafari_16_0, utls.HelloIOS_14, utls.HelloIOS_13,
			}
		} else {
			pool = []utls.ClientHelloID{
				utls.HelloChrome_Auto, utls.HelloChrome_131,
				utls.HelloChrome_120_PQ, utls.HelloChrome_120,
			}
		}
	case "edge":
		// B-3: HelloEdge_106 dropped (utls@v1.8.2 marks it
		// incompatible). HelloEdge_85 is the only remaining Edge
		// parrot in this utls version and is fairly stale. We keep
		// it so callers who explicitly request mode="edge" still get
		// an Edge-family fingerprint, but the auto pool no longer
		// includes Edge at all (Chrome covers it via JA4 similarity).
		pool = []utls.ClientHelloID{utls.HelloEdge_85}
	case "ios":
		// B-2: iOS fingerprints only on iOS/darwin. Linux/Windows
		// senders fall back to Chrome.
		if isApplePlatform() {
			pool = []utls.ClientHelloID{utls.HelloIOS_14, utls.HelloIOS_13, utls.HelloIOS_12_1}
		} else {
			pool = []utls.ClientHelloID{
				utls.HelloChrome_Auto, utls.HelloChrome_131,
				utls.HelloChrome_120_PQ, utls.HelloChrome_120,
			}
		}
	default: // "chrome" and any unrecognised value: default to modern Chrome family
		// 2026-05-09 cleanup: dropped HelloChrome_100 + HelloChrome_106_Shuffle
		// (2022-era, would emit a "stale browser" signature). Aligns this branch
		// with the modern subset in "mix" / "auto" above. Production hits this
		// only when operator explicitly sets Fingerprint="" or an unknown value
		// (applyDefaults normalises the empty string to "mix"); kept to avoid
		// silently downgrading to outdated fingerprints.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto,
			utls.HelloChrome_131,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_120,
		}
	}
	r := &fingerprintRotator{pool: pool}
	if len(pool) == 0 {
		r.pinned = utls.HelloChrome_Auto
		return r
	}
	if len(seed) >= 4 {
		h := sha256.Sum256(seed)
		idx := int(binary.LittleEndian.Uint32(h[:4])) % len(pool)
		if idx < 0 {
			idx = -idx
		}
		if idx >= len(pool) {
			idx = idx % len(pool)
		}
		r.pinned = pool[idx]
	} else {
		idx := randomInt(0, len(pool))
		if idx >= len(pool) {
			idx = len(pool) - 1
		}
		r.pinned = pool[idx]
	}
	return r
}

// pick returns the pinned fingerprint. Per B-1 (2026-05-09) this is
// deterministic across the lifetime of the rotator — same value every
// call. Kept as a method (not a field read) so call-sites don't need
// to change.
func (r *fingerprintRotator) pick() utls.ClientHelloID {
	if r == nil {
		return utls.HelloChrome_Auto
	}
	return r.pinned
}

// fingerprintIDLookup resolves a server-pushed fingerprint_pool ID
// (e.g. "chrome_auto", "chrome_131") to the corresponding uTLS ClientHelloID.
// Unknown IDs return (zero, false) so the caller skips them silently —
// a server can advertise a fingerprint that this client binary does not
// know yet without breaking the entire pool.
func fingerprintIDLookup(id string) (utls.ClientHelloID, bool) {
	switch id {
	case "chrome_auto":
		return utls.HelloChrome_Auto, true
	case "chrome_131":
		return utls.HelloChrome_131, true
	case "chrome_120_pq":
		return utls.HelloChrome_120_PQ, true
	case "chrome_120":
		return utls.HelloChrome_120, true
	case "chrome_115_pq":
		return utls.HelloChrome_115_PQ, true
	case "chrome_106_shuffle":
		return utls.HelloChrome_106_Shuffle, true
	case "chrome_100":
		return utls.HelloChrome_100, true
	case "firefox_120":
		return utls.HelloFirefox_120, true
	case "firefox_105":
		return utls.HelloFirefox_105, true
	case "firefox_102":
		return utls.HelloFirefox_102, true
	case "safari_16_0":
		return utls.HelloSafari_16_0, true
	case "ios_14":
		return utls.HelloIOS_14, true
	case "ios_13":
		return utls.HelloIOS_13, true
	case "ios_12_1":
		return utls.HelloIOS_12_1, true
	case "edge_106":
		return utls.HelloEdge_106, true
	case "edge_85":
		return utls.HelloEdge_85, true
	}
	return utls.ClientHelloID{}, false
}
