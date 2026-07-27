package tamizdat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// startCoverTraffic spawns a goroutine that periodically opens H2 CONNECT
// streams to cover-site URLs through the samizdat tunnel. The goal: make
// per-IP H2-stream-distribution look like "real browser to ok.ru with side
// streams" instead of "every stream is user-driven samizdat traffic".
//
// Compass v2 §5.6 + USENIX Sec 2024 (Xue et al.): random fragmentation
// alone doesn't fully defeat encapsulated-TLS-handshake fingerprinting;
// mixing real cover requests on the same H2 session is the actually-effective
// counter.
//
// Each cover request opens a CONNECT to one of the cover targets (ok.ru:443,
// vk.com:443, mail.ru:443 -- all in RKN whitelist), reads a small amount,
// closes. Frequency: random 30-90s gap. Cover targets cycle so distribution
// matches the SNI rotation pool.
//
// Stops when ctx is cancelled (Client.Close).

const (
	coverGapMin       = 30 * time.Second
	coverGapMax       = 90 * time.Second
	coverReadBudget   = 4096
	coverReadDeadline = 3 * time.Second
)

type coverDriver struct {
	c       *Client
	targets atomic.Pointer[[]string]
	gapMin  atomic.Int64
	gapMax  atomic.Int64
	stop    chan struct{}
	once    sync.Once
}

// defaultCoverTargets returns a diversified set of cover destinations that
// mimics the background traffic mix a real RU browser produces while a user
// is on a homepage: small-flow analytics beacons, medium-flow ad and CDN
// fetches, short API calls. Compared to a homogeneous list of homepages
// (compass v2 §5.6), this gives the H2 stream-size distribution a believable
// shape and breaks the "5 identical hits to ok.ru/vk.com/mail.ru/..." pattern
// that a passive collector could otherwise pin. All targets are RKN-whitelist
// RU CDN/analytics endpoints that are never blocked.
func defaultCoverTargets() []string {
	return []string{
		"mc.yandex.ru:443",       // analytics beacon (~1-2 KB)
		"an.yandex.ru:443",       // ad network (~5-15 KB)
		"yastatic.net:443",       // CDN: fonts, scripts (~10-50 KB)
		"top-fwz1.mail.ru:443",   // tracking pixel (~tiny)
		"clck.yandex.ru:443",     // click counter (~tiny)
		"sun9-1.userapi.com:443", // VK content CDN (~medium)
		"api-maps.yandex.ru:443", // API endpoint (~small)
		"id.vk.com:443",          // VK SSO (~small)
	}
}

func (c *Client) startCoverTraffic(ctx context.Context, targets []string) *coverDriver {
	if len(targets) == 0 {
		targets = defaultCoverTargets()
	}
	targetCopy := append([]string(nil), targets...)
	d := &coverDriver{
		c:    c,
		stop: make(chan struct{}),
	}
	d.targets.Store(&targetCopy)
	d.gapMin.Store(int64(coverGapMin))
	d.gapMax.Store(int64(coverGapMax))
	go d.run(ctx)
	return d
}

func (d *coverDriver) run(ctx context.Context) {
	for {
		minGap := time.Duration(d.gapMin.Load())
		maxGap := time.Duration(d.gapMax.Load())
		if minGap <= 0 {
			minGap = coverGapMin
		}
		if maxGap < minGap {
			maxGap = minGap
		}
		gap := minGap
		if maxGap > minGap {
			gap += time.Duration(coverRandUint64n(uint64(maxGap - minGap)))
		}
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case <-time.After(gap):
		}
		// Pick a target at random. The slice pointer can be atomically replaced
		// by a server-pushed bundle; existing iterations keep their snapshot.
		targetsPtr := d.targets.Load()
		if targetsPtr == nil || len(*targetsPtr) == 0 {
			continue
		}
		targets := *targetsPtr
		idx := int(coverRandUint64n(uint64(len(targets))))
		target := targets[idx]
		d.coverOnce(ctx, target)
	}
}

// coverOnce opens a single H2 CONNECT to `target` via the tunnel and reads
// up to coverReadBudget bytes. Errors are swallowed; cover is best-effort.
func (d *coverDriver) coverOnce(parent context.Context, target string) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	conn, err := d.c.dialBulk(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer conn.Close()

	// Small "browser-like" TLS-ClientHello-shaped opening write so the H2
	// stream sees activity. We don't actually negotiate inner TLS; just the
	// first record-shaped 5-byte header + a few random bytes (enough that
	// the encapsulated-TLS-handshake classifier sees a "TLS-init"-like
	// pattern matching real cover traffic to ok.ru).
	hdr := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	binary.BigEndian.PutUint16(hdr[3:5], 32) // record body length 32
	body := make([]byte, 32)
	_, _ = rand.Read(body)
	_, _ = conn.Write(append(hdr, body...))

	// Read up to budget bytes, then close.
	_ = conn.SetReadDeadline(time.Now().Add(coverReadDeadline))
	io.CopyN(io.Discard, conn, coverReadBudget)
}

func (d *coverDriver) replaceTargets(newTargets []string) {
	if len(newTargets) == 0 {
		return
	}
	copyTargets := append([]string(nil), newTargets...)
	d.targets.Store(&copyTargets)
}

func (d *coverDriver) replaceGap(min, max time.Duration) {
	if min <= 0 || max <= 0 || min > max {
		return
	}
	d.gapMin.Store(int64(min))
	d.gapMax.Store(int64(max))
}

func (d *coverDriver) close() {
	d.once.Do(func() {
		close(d.stop)
	})
}

// coverRandUint64n returns a uniform random number in [0, n).
func coverRandUint64n(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	x := uint64(0)
	for i := 0; i < 8; i++ {
		x = (x << 8) | uint64(b[i])
	}
	return x % n
}

// Make sure the wider package imports satisfy: net is used elsewhere
// implicitly through Conn typing.
var _ = net.Conn(nil)
