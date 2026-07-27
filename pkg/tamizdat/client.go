package tamizdat

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/internal/bundlecache"
	utls "github.com/refraction-networking/utls"
)

// pickServerNameExcluding returns a random SNI from the pool, biased away
// from any SNI in `exclude`. Used to guarantee that a freshly-spawned lite
// transport picks a different cover SNI than the active bulk transport so
// the TSPU #546 counter (src_IP, SNI, JA3) for any single SNI stays at 1.
//
// If filtering yields an empty candidate set (pool exhausted by excludes),
// falls back to the unfiltered weighted pick — the safety property is
// best-effort, not absolute.
func (c *Client) pickServerNameExcluding(exclude []string) string {
	if len(exclude) == 0 {
		return c.pickServerName()
	}
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, e := range exclude {
		if e != "" {
			excludeSet[e] = struct{}{}
		}
	}
	if pushed := c.serverPushedSNIPool.Load(); pushed != nil && len(*pushed) > 0 {
		primary := c.config.PrimarySNI
		if primary == "" {
			primary = c.config.ServerName
		}
		entries := []SNIEntry{}
		if _, skip := excludeSet[primary]; !skip {
			entries = append(entries, SNIEntry{SNI: primary, Weight: 100})
		}
		for _, e := range *pushed {
			if e.SNI == "" {
				continue
			}
			if _, skip := excludeSet[e.SNI]; skip {
				continue
			}
			if len(entries) > 0 && entries[0].SNI == primary && e.SNI == primary {
				if e.Weight > entries[0].Weight {
					entries[0].Weight = e.Weight
				}
				continue
			}
			entries = append(entries, e)
		}
		if len(entries) > 0 {
			if picked := pickWeightedSNI(entries); picked != "" {
				return picked
			}
		}
	}
	pool := c.config.ServerNames
	if len(pool) == 0 {
		return c.pickServerName()
	}
	filtered := pool[:0:0]
	for _, s := range pool {
		if _, skip := excludeSet[s]; skip {
			continue
		}
		filtered = append(filtered, s)
	}
	if len(filtered) == 0 {
		return c.pickServerName()
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % len(filtered)
	return filtered[i]
}

// pickServerName returns a randomly-chosen SNI from the configured pool.
// Falls back to legacy single ServerName when no pool is configured.
// Per-transport rotation breaks the "all clients of one IP share one SNI"
// behavioural correlation flagged by compass P1.1.
func (c *Client) pickServerName() string {
	if pushed := c.serverPushedSNIPool.Load(); pushed != nil && len(*pushed) > 0 {
		primary := c.config.PrimarySNI
		if primary == "" {
			primary = c.config.ServerName
		}
		// Per spec §3.B (clarified 2026-05-01): if bundle has primary's sni, use max(its weight, 100); else insert primary at weight 100; append other bundle entries unchanged.
		entries := []SNIEntry{{SNI: primary, Weight: 100}}
		for _, e := range *pushed {
			if e.SNI == "" {
				continue
			}
			if e.SNI == primary {
				if e.Weight > entries[0].Weight {
					entries[0].Weight = e.Weight
				}
				continue
			}
			entries = append(entries, e)
		}
		if picked := pickWeightedSNI(entries); picked != "" {
			return picked
		}
	}
	pool := c.config.ServerNames
	if len(pool) == 0 {
		if c.config.PrimarySNI != "" {
			return c.config.PrimarySNI
		}
		return c.config.ServerName
	}
	if len(pool) == 1 {
		return pool[0]
	}
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % len(pool)
	return pool[i]
}

// pickShortID returns the master shortID. Shortid full-B simplification
// (2026-05-09): HKDF derivation pool removed; each user has 1 master_shortid.
// Per operator decision after Opus DPI-rotation analysis — rotation defended a
// theoretical RU TSPU 2026 threat (per-shortid blocklist accumulation) that
// has no public corpus evidence, and the cover-config epoch_key channel was
// never exercised in production. See C:\var-tmp\shortid-rotation-analysis-opus.md.
func (c *Client) pickShortID() [8]byte {
	return c.config.MasterShortID
}

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config                      ClientConfig
	pool                        *connPool
	shaper                      *Shaper
	fragmenter                  *RecordFragmenter
	fingerprintChooser          *fingerprintRotator
	cover                       *coverDriver
	handshakeLimiter            *handshakeLimiter
	serverPushedSNIPool         atomic.Pointer[[]SNIEntry]
	serverPushedFingerprintPool atomic.Pointer[[]FingerprintEntry]
	serverPushedTURNCreds       atomic.Pointer[TURNCredsEntry]
	bundleCache                 *bundlecache.Cache
	bundleETag                  atomic.Pointer[string]
	// bundleFetchInFlight (SPP-FU-2) dedupes concurrent bundle fetches:
	// when N transports finish dialing in parallel, only the first
	// CompareAndSwap-winner runs fetchAndApplyBundle; the rest exit early.
	// Avoids hammering the magic-CONNECT bundle endpoint and stomping on
	// each other's atomic pool pointers. Picked atomic.Bool over
	// singleflight to avoid the new x/sync external dep.
	bundleFetchInFlight atomic.Bool
	bootstrapSNI        string
	coverCtx            context.Context
	coverCancel         context.CancelFunc
	bundleCtx           context.Context
	bundleCancel        context.CancelFunc
	rttProbe            *rttProbe
	// sessionIDCache backs the v2 wire-format: per-(server_addr, shortID)
	// 6-byte stable random + 2-byte counter so the SessionID prefix stays
	// stable across reconnects within a session-ticket-lifetime window
	// (review-C tell #12 / Wu+Xue 2024). nil when WireVersion=1 (legacy
	// fresh-random-per-dial path).
	sessionIDCache *sessionIDCache

	mu     sync.Mutex
	closed bool
}

// NewClient creates a new Samizdat client.
func NewClient(config ClientConfig) (*Client, error) {
	config.applyDefaults()

	if len(config.PublicKey) != 32 {
		return nil, fmt.Errorf("PublicKey must be exactly 32 bytes, got %d", len(config.PublicKey))
	}
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("ServerAddr is required")
	}
	if config.PrimarySNI == "" {
		return nil, fmt.Errorf("PrimarySNI/ServerName is required")
	}
	var zeroShortID [8]byte
	if config.MasterShortID == zeroShortID {
		return nil, fmt.Errorf("MasterShortID/ShortID is required")
	}

	c := &Client{
		config:           config,
		handshakeLimiter: newHandshakeLimiter(),
		bootstrapSNI:     config.BootstrapSNI,
	}
	// SessionID cache is allocated only when emitting v2 wire format. v1
	// callers (test pinning, legacy operator override) bypass the cache and
	// land on the fresh-random nonce path inside BuildSessionIDv1.
	if config.WireVersion >= 2 {
		c.sessionIDCache = newSessionIDCache()
	}
	c.bundleCtx, c.bundleCancel = context.WithCancel(context.Background())
	if config.BundleEnabled {
		c.bundleCache = bundlecache.New(config.BundleCacheDir)
	} else {
		c.bundleCache = bundlecache.New("")
	}

	c.shaper = NewShaper(false, 0)
	c.fragmenter = NewRecordFragmenter(config.RecordFragmentation)
	c.fingerprintChooser = newFingerprintRotator(config.Fingerprint, config.MasterShortID[:])
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, config.MinTransports, config.MaxTransports, config.BytesPerTransportSoftCap, config.RotationOverlapAllowance, func(ctx context.Context) (*h2Transport, error) {
		return c.createTransport(ctx)
	})

	if config.CoverTrafficEnabled {
		c.coverCtx, c.coverCancel = context.WithCancel(context.Background())
		c.cover = c.startCoverTraffic(c.coverCtx, config.CoverTrafficTargets)
	}

	// Replay last server-pushed bundle from disk so the very first dial
	// already has a populated SNI / fingerprint pool. The disk copy may be
	// stale; the asynchronous fetchAndApplyBundle on the first transport
	// will refresh it via ETag conditional GET.
	c.replayCachedBundle()
	if c.config.BundleEnabled && c.bundleCtx != nil {
		go c.bundleRefreshLoop()
	}

	c.rttProbe = newRTTProbe(c)
	c.rttProbe.start()
	return c, nil
}

// replayCachedBundle parses the bundle persisted on disk (if any) and
// applies it to in-memory pools, so the first dial benefits from the
// previous run's pool data without waiting for the asynchronous fetch.
func (c *Client) replayCachedBundle() {
	if c == nil || c.bundleCache == nil || !c.bundleCache.Enabled() {
		return
	}
	body, etag, err := c.bundleCache.Load(bundlecache.Key{
		Host:    bundleCacheHostKey(c.config.ServerAddr),
		ShortID: c.config.MasterShortID,
	})
	if err != nil || len(body) == 0 {
		return
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return
	}
	if err := bundle.Validate(nil, false); err != nil {
		return
	}
	if bundle.ExpiresAt > 0 && bundle.ExpiresAt < time.Now().Unix() {
		// Expired entry — keep the body for ETag-driven refresh but do
		// NOT seed pools from a stale snapshot.
		if etag != "" {
			c.bundleETag.Store(&etag)
		}
		return
	}
	c.applyCoverConfigBundle(&bundle)
	if etag != "" {
		c.bundleETag.Store(&etag)
	}
}

func (c *Client) bundleRefreshLoop() {
	if c == nil || c.bundleCtx == nil || !c.config.BundleEnabled || c.pool == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.bundleCtx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(c.bundleCtx, 10*time.Second)
		transport, err := c.pool.getTransport(ctx)
		cancel()
		if err != nil || transport == nil {
			continue
		}
		_ = c.fetchAndApplyBundle(c.bundleCtx, transport)
	}
}

// bundleCacheHostKey strips the port from a host:port server address so
// "ya.ru:443" and "ya.ru:778" share the same cache slot for the same
// authority.
func bundleCacheHostKey(serverAddr string) string {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return serverAddr
	}
	return host
}

// DialContext opens a proxied connection to the destination through the server.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	transport, err := c.pool.getTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	conn, err := transport.openTunnel(ctx, address)
	if err != nil {
		transport.releaseStreamSlot()
		return nil, fmt.Errorf("opening tunnel to %s: %w", address, err)
	}

	return conn, nil
}

// dialBulk is preserved for the cover-traffic driver. With the realtime
// classifier removed, it is a thin wrapper around DialContext (kept distinct
// for callsite clarity / future divergence).
func (c *Client) dialBulk(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("dialBulk supports tcp only, got %q", network)
	}
	return c.DialContext(ctx, network, address)
}

// DialUDP opens a UDP-tunneling stream to the destination through the server.
// Returns a net.PacketConn that frames inner UDP datagrams as length-prefixed
// records over the H2 stream. Single-target: WriteTo addresses other than the
// CONNECT authority are rejected; ReadFrom always returns address as Addr.
func (c *Client) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	transport, err := c.pool.getTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	rwc, err := transport.openUDPTunnel(ctx, address)
	if err != nil {
		transport.releaseStreamSlot()
		return nil, fmt.Errorf("opening UDP tunnel to %s: %w", address, err)
	}

	target := &streamAddr{network: "udp", address: address}
	return newUDPFramedPacketConn(rwc, target), nil
}

// Close shuts down all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.rttProbe != nil {
		c.rttProbe.stop()
	}
	if c.bundleCancel != nil {
		c.bundleCancel()
	}
	if c.coverCancel != nil {
		c.coverCancel()
	}
	if c.cover != nil {
		c.cover.close()
	}
	return c.pool.close()
}

// createTransport creates a new TLS+H2 connection to the server with
// Reality-style auth embedded in the ClientHello.
func (c *Client) createTransport(ctx context.Context) (*h2Transport, error) {
	if c.handshakeLimiter != nil {
		if err := c.handshakeLimiter.Wait(ctx, c.config.ServerAddr); err != nil {
			return nil, err
		}
	}

	var tcpConn net.Conn
	var err error

	if c.config.Dialer != nil {
		tcpConn, err = c.config.Dialer(ctx, "tcp", c.config.ServerAddr)
	} else {
		dialer := &net.Dialer{Timeout: c.config.ConnectTimeout}
		tcpConn, err = dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("TCP dial to %s: %w", c.config.ServerAddr, err)
	}

	var conn net.Conn = tcpConn
	var fragmenter *Fragmenter
	if c.config.TCPFragmentation {
		// #7 adaptive Geneva: bandit picks strategy per server (host:port).
		// Outcome reported below after handshake completes.
		fragmenter = NewFragmenterWithStrategy(tcpConn, true, c.config.ServerAddr, "")
		conn = fragmenter
	}

	// Per-transport SNI rotation across active transports avoids "all
	// transports of one IP share one SNI" correlation flagged by compass
	// P1.1.
	sni := c.pickServerNameExcluding(c.pool.activeSNIs())
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	helloID := c.pickFingerprint()
	uConn := utls.UClient(conn, tlsConfig, helloID)

	// compass v2 §5.1 Approach A (Reality-style): instead of generating a
	// separate ephemeral X25519 keypair and stuffing the pub into a private
	// extension 0xFE0C, we piggy-back on the X25519 keypair uTLS ALREADY
	// generates for the standard TLS-1.3 key_share extension. Result: zero
	// JA4-fingerprintable extensions appear in our ClientHello.
	if err := uConn.BuildHandshakeState(); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("building uTLS handshake state: %w", err)
	}
	ksk := uConn.HandshakeState.State13.KeyShareKeys
	if ksk == nil || ksk.Ecdhe == nil {
		uConn.Close()
		return nil, fmt.Errorf("uTLS did not allocate X25519 KeyShareKeys (need standalone X25519 in client_shares)")
	}
	ephPub := ksk.Ecdhe.PublicKey().Bytes()
	if len(ephPub) != x25519KeyLen {
		uConn.Close()
		return nil, fmt.Errorf("uTLS Ecdhe pubkey length %d, want %d", len(ephPub), x25519KeyLen)
	}
	shortID := c.pickShortID()

	// Compute samizdat ECDH using uTLS's Ecdhe priv against the server's static pub.
	serverStaticPub, err := ecdh.X25519().NewPublicKey(c.config.PublicKey)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("parsing server static pub: %w", err)
	}
	shared, err := ksk.Ecdhe.ECDH(serverStaticPub)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("ECDH(uTLS Ecdhe priv, server static pub): %w", err)
	}
	psk, err := DerivePSKFromSharedSecret(shared, shortID)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("deriving samizdat PSK from shared secret: %w", err)
	}
	// SessionID build:
	//   - v2 (default): cache hands out 8-byte nonce as
	//     stable_random_6 || counter_uint16_be, keyed by (server_addr,
	//     shortID). Same client+shortID reuses the 6-byte prefix across
	//     reconnects within TTL [30 min, 120 min]; counter ensures the
	//     replay key (SHA-256(SessionID || eph_pub)[:16]) stays unique.
	//   - v1 (legacy / test-pinned): nil nonce → BuildSessionIDv1
	//     internally generates a fresh random 8-byte nonce per dial.
	var sessionID [sessionIDLen]byte
	if c.config.WireVersion >= 2 && c.sessionIDCache != nil {
		nonce, cerr := c.sessionIDCache.Acquire(c.config.ServerAddr, shortID)
		if cerr != nil {
			uConn.Close()
			return nil, fmt.Errorf("acquiring SessionID nonce from cache: %w", cerr)
		}
		sessionID, err = BuildSessionIDv2(psk, shortID, ephPub, nonce[:])
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("building session ID v2: %w", err)
		}
	} else {
		sessionID, err = BuildSessionIDv1(psk, shortID, ephPub, nil)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("building session ID v1: %w", err)
		}
	}

	// Inject SessionID into the (already-built) handshake state and re-marshal.
	// No 0xFE0C extension is added -- server reads the pubkey from the standard
	// key_share extension instead.
	uConn.HandshakeState.Hello.SessionId = make([]byte, len(sessionID))
	copy(uConn.HandshakeState.Hello.SessionId, sessionID[:])
	if err := uConn.MarshalClientHello(); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("re-marshaling ClientHello after SessionID inject: %w", err)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		if fragmenter != nil {
			fragmenter.ReportOutcome(false)
		}
		uConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		if fragmenter != nil {
			fragmenter.ReportOutcome(false)
		}
		uConn.Close()
		return nil, fmt.Errorf("expected h2, got %q", state.NegotiatedProtocol)
	}
	if fragmenter != nil {
		fragmenter.ReportOutcome(true)
	}

	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper, c.fragmenter, c.config.DrainTimeout, sni)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}
	if c.bundleCtx != nil {
		// SPP-FU-2: dedupe concurrent bundle fetches. The first transport to
		// arrive after a cold start (or after a previous fetch finished)
		// wins the CAS and runs the fetch; concurrent dialers exit early
		// rather than racing each other on the magic-CONNECT endpoint.
		if c.bundleFetchInFlight.CompareAndSwap(false, true) {
			go func() {
				defer c.bundleFetchInFlight.Store(false)
				_ = c.fetchAndApplyBundle(c.bundleCtx, transport)
			}()
		}
	}

	return transport, nil
}

func (c *Client) fetchAndApplyBundle(parent context.Context, transport *h2Transport) (err error) {
	if parent == nil || transport == nil || transport.h2Roundtrip == nil {
		return nil
	}
	if c.config.BundleEnabledSet && !c.config.BundleEnabled {
		return nil
	}
	defer func() {
		if err != nil {
			safeIntAdd(bundleFetchErrorsTotal, 1)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+transport.serverAddr, nil)
	if err != nil {
		return err
	}
	req.Host = configAuthority
	req.Header.Set(SamizdatProtocolHeader, SamizdatProtocolConfig)
	if etagPtr := c.bundleETag.Load(); etagPtr != nil && *etagPtr != "" {
		req.Header.Set("If-None-Match", *etagPtr)
	}
	resp, err := transport.h2Roundtrip.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		// Disk-cached bundle still authoritative; the in-memory pools were
		// already seeded by replayCachedBundle on startup.
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config bundle status %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, MaxCoverConfigBundleBytes+1))
	if err != nil {
		return err
	}
	if len(buf) == 0 {
		return nil
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return fmt.Errorf("config bundle too large: %d > %d", len(buf), MaxCoverConfigBundleBytes)
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(buf, &bundle); err != nil {
		return err
	}
	if err := bundle.Validate(nil, false); err != nil {
		return err
	}
	safeIntAdd(bundleReceivedTotal, 1)
	c.applyCoverConfigBundle(&bundle)
	safeIntAdd(bundleAppliedTotal, 1)
	if etag := resp.Header.Get("ETag"); etag != "" {
		c.bundleETag.Store(&etag)
	}
	if c.bundleCache != nil && c.bundleCache.Enabled() {
		_ = c.bundleCache.Save(bundlecache.Key{
			Host:    bundleCacheHostKey(c.config.ServerAddr),
			ShortID: c.config.MasterShortID,
		}, buf, resp.Header.Get("ETag"))
	}
	return nil
}

func (c *Client) applyCoverConfigBundle(bundle *CoverConfigBundle) {
	if bundle == nil {
		return
	}
	// Server-authoritative pool bounds (2026-05-18). The server may push an
	// exact transport count via min/max, or fall back to the legacy
	// v1/v2/v3 pool-variant seam for old bundles.
	if c.pool != nil {
		switch {
		case bundle.MinTransports > 0 || bundle.MaxTransports > 0:
			minT := bundle.MinTransports
			if minT < 1 {
				minT = 1
			}
			maxT := bundle.MaxTransports
			if maxT == 0 || maxT < minT {
				maxT = minT
			}
			c.pool.resize(minT, maxT)
		case bundle.PoolVariant != "":
			switch bundle.PoolVariant {
			case "v1":
				c.pool.resize(1, 1)
			case "v2":
				c.pool.resize(1, 2)
			case "v3":
				c.pool.resize(2, 4)
			}
		}
	}
	// Shortid full-B simplification (2026-05-09): bundle's epoch_key /
	// shortid_pool_size fields are tolerated for backward-compat with old
	// server bundles but ignored — the client always uses MasterShortID.
	if len(bundle.SNIPool) > 0 {
		sniCopy := append([]SNIEntry(nil), bundle.SNIPool...)
		c.serverPushedSNIPool.Store(&sniCopy)
	} else {
		empty := []SNIEntry{}
		c.serverPushedSNIPool.Store(&empty)
	}
	if len(bundle.FingerprintPool) > 0 {
		// Filter out unknown IDs server-side so pickFingerprint only sees
		// entries this binary can dial. Empty result falls back to
		// fingerprintChooser (URI-supplied fp= or default).
		filtered := make([]FingerprintEntry, 0, len(bundle.FingerprintPool))
		for _, e := range bundle.FingerprintPool {
			if _, ok := fingerprintIDLookup(e.ID); ok {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) > 0 {
			c.serverPushedFingerprintPool.Store(&filtered)
		} else {
			empty := []FingerprintEntry{}
			c.serverPushedFingerprintPool.Store(&empty)
		}
	} else {
		empty := []FingerprintEntry{}
		c.serverPushedFingerprintPool.Store(&empty)
	}
	if c.cover != nil {
		if len(bundle.CoverTargets) > 0 {
			c.cover.replaceTargets(bundle.CoverTargets)
		}
		if bundle.CoverGapMinMS > 0 || bundle.CoverGapMaxMS > 0 {
			c.cover.replaceGap(time.Duration(bundle.CoverGapMinMS)*time.Millisecond, time.Duration(bundle.CoverGapMaxMS)*time.Millisecond)
		}
	}
	// VK TURN credentials: store for future TURN transport implementation.
	// Currently a forward-compatible placeholder; the client-side TURN
	// dialer will read these when implemented.
	if bundle.TURNCreds != nil {
		entry := *bundle.TURNCreds
		c.serverPushedTURNCreds.Store(&entry)
	}
	// Phase C iOS-notify: forward a one-shot user-facing notification to any
	// registered consumer (iOS NE bridges this to a local notification).
	// Fire on a goroutine to keep the bundle-apply path non-blocking; the
	// callback may do I/O (UserDefaults write, sendProviderMessage) we don't
	// want to serialize against transport rotation. Copy the entry by value
	// before launching — the caller may reuse the bundle.
	if bundle.Notification != nil && c.config.OnNotification != nil {
		entry := *bundle.Notification
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Don't propagate consumer panics into the client pool.
					_ = r
				}
			}()
			c.config.OnNotification(entry)
		}()
	}
}

// pickFingerprint selects the next uTLS ClientHelloID. When a server-pushed
// fingerprint_pool is in effect, pick weighted-random across recognised IDs;
// otherwise fall back to the local rotator (URI-supplied fp= or the default
// chrome/mix family pool).
func (c *Client) pickFingerprint() utls.ClientHelloID {
	if pushed := c.serverPushedFingerprintPool.Load(); pushed != nil && len(*pushed) > 0 {
		// Weighted pick across entries; fingerprintIDLookup may still
		// reject ID at dial-time if the binary was downgraded between
		// bundle apply and dial. Fall through to rotator on miss.
		total := 0
		for _, e := range *pushed {
			if e.Weight < 0 {
				continue
			}
			total += e.Weight
		}
		if total > 0 {
			r := int(coverRandUint64n(uint64(total)))
			cum := 0
			for _, e := range *pushed {
				if e.Weight <= 0 {
					continue
				}
				cum += e.Weight
				if r < cum {
					if id, ok := fingerprintIDLookup(e.ID); ok {
						return id
					}
				}
			}
		}
	}
	return c.fingerprintChooser.pick()
}

type tlsConnWrapper struct {
	*utls.UConn
}

func (w *tlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := w.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            state.Version,
		HandshakeComplete:  state.HandshakeComplete,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
	}
}

// RTTProbeSnapshot returns the current RTT probe stats — last p50 in ms,
// sample count, and the most-recent measurement. Returns -1 fields if the
// probe has not collected samples yet.
func (c *Client) RTTProbeSnapshot() RTTProbeStats {
	if c == nil || c.rttProbe == nil {
		return RTTProbeStats{P50Ms: -1, LastMs: -1}
	}
	return c.rttProbe.Snapshot()
}

// ServerPushedTURNCreds returns the most recently received VK TURN
// credentials from the server's CoverConfigBundle. Returns nil if the
// server has not pushed any credentials yet (e.g. turncreds manager
// disabled or credentials not yet fetched).
func (c *Client) ServerPushedTURNCreds() *TURNCredsEntry {
	if c == nil {
		return nil
	}
	return c.serverPushedTURNCreds.Load()
}
