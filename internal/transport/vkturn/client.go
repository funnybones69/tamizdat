package vkturn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/vkcreds"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	kcp "github.com/xtaci/kcp-go/v5"
)

type ClientConfig struct {
	ServerAddr      string
	ShortID         [ShortIDLen]byte
	VKHashes        []string
	VKAppID         string
	VKAppSecret     string
	UserAgent       string
	DeviceID        string
	SNI             string
	Workers         int
	UseUDP          bool
	TURNHost        string
	TURNPort        string
	Direct          bool
	Dialer          DialFunc
	Credentials     *Credentials
	MaxFramePayload int
	ConnectTimeout  time.Duration
	SessionTimeout  time.Duration

	// CredCachePath, when non-empty, persists acquired VK TURN credentials
	// to disk (mode 0600) so they survive process restarts and can bootstrap
	// the relay after a network whitelist cuts off everything except VK —
	// without re-solving a captcha. The same file can be seeded out-of-band
	// (e.g. by a panel break-glass captcha solved in a real browser); the
	// client adopts a newer valid file on the next acquisition.
	CredCachePath string

	// CaptchaDir, when non-empty, routes VK captchas to a filesystem
	// human-in-the-loop solver (vkcreds.FileCaptchaSolver) instead of the
	// automated reverse-JS solver: a challenge.json is written here and the
	// client waits (up to credentialAcquireTimeout) for a result file with the
	// success_token, produced by a real browser on the LAN (router panel).
	// This is the break-glass path under a whitelist that leaves only VK + LAN
	// reachable. Empty keeps the default automated solver.
	CaptchaDir string
}

type Client struct {
	config          ClientConfig
	workers         int
	maxFramePayload int
	connectTimeout  time.Duration
	sessionTimeout  time.Duration

	cachePath string
	// acquire fetches fresh credentials from VK. It is a field so tests can
	// inject a fake without hitting the network; NewClient sets the default
	// (the full vkcreds 5-step flow over all configured hashes).
	acquire func(ctx context.Context) (*Credentials, error)

	mu          sync.Mutex
	sessions    []*muxSession
	rr          int
	closed      bool
	creds       *Credentials
	credsExpiry time.Time

	// Credential acquisition control (storm prevention).
	credInflight *credFuture // non-nil while a single acquisition is in flight
	credBackoff  time.Time   // do not attempt VK acquisition before this instant
	credFails    int         // consecutive acquisition failures, drives backoff
	lastCredErr  error       // most recent acquisition error, surfaced during backoff
}

// credFuture lets concurrent dials share a single in-flight credential
// acquisition (singleflight) instead of each launching its own VK captcha flow.
type credFuture struct {
	done  chan struct{}
	creds *Credentials
	err   error
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, errors.New("vkturn: ServerAddr is required")
	}
	var zero [ShortIDLen]byte
	if config.ShortID == zero {
		return nil, errors.New("vkturn: ShortID is required")
	}
	if config.SNI == "" {
		config.SNI = "calls.okcdn.ru"
	}
	c := &Client{
		config:          config,
		cachePath:       config.CredCachePath,
		workers:         workerCount(config.Workers),
		maxFramePayload: maxFramePayload(config.MaxFramePayload),
		connectTimeout:  durationDefault(config.ConnectTimeout, DefaultConnectTimeout),
		sessionTimeout:  durationDefault(config.SessionTimeout, DefaultSessionTimeout),
	}
	c.acquire = c.acquireFromVK
	c.loadCachedCreds()
	return c, nil
}

// loadCachedCreds primes the in-memory cache from disk at startup so the first
// dial after a restart (or after a whitelist activation) can use the relay
// immediately instead of triggering a VK captcha. An expired file is still
// adopted as a last-resort fallback: credExpiry's lapse only means we *prefer*
// to refresh, and a stale credential served during backoff beats hammering VK.
func (c *Client) loadCachedCreds() {
	if c.cachePath == "" {
		return
	}
	pc, err := loadPersistentCreds(c.cachePath)
	if err != nil {
		return
	}
	c.creds = pc.toCredentials()
	c.credsExpiry = pc.ExpiresAt
	if time.Now().Before(pc.ExpiresAt) {
		log.Printf("[vkturn] loaded cached credentials, valid for %s", time.Until(pc.ExpiresAt).Round(time.Second))
	} else {
		log.Printf("[vkturn] loaded expired cached credentials as fallback (will try to refresh)")
	}
}

// acquireFromVK runs the full vkcreds flow across all configured hashes. It is
// the default Client.acquire. MaxRetries is pinned to 1: the client-level
// backoff (credBackoffDuration) governs spacing between attempts, so the
// vkcreds layer must not run its own multi-attempt retry loop — that would
// multiply captcha requests per acquisition and re-create the storm.
func (c *Client) acquireFromVK(ctx context.Context) (*Credentials, error) {
	if len(c.config.VKHashes) == 0 {
		return nil, errors.New("vkturn: VKHashes is required when Direct=false")
	}
	cfg := &vkcreds.Config{
		AppID:      c.config.VKAppID,
		AppSecret:  c.config.VKAppSecret,
		UserAgent:  c.config.UserAgent,
		DeviceID:   c.config.DeviceID,
		MaxRetries: 1,
	}
	if len(c.config.VKHashes) > 1 {
		cfg.SecondaryHash = c.config.VKHashes[1]
	}
	// With a captcha dir configured, hand captchas to the human-in-the-loop
	// file solver (break-glass) rather than the automated reverse-JS solver,
	// which VK now rejects as BOT. The 15m acquisition budget is the solve
	// window for a real browser on the LAN.
	if c.config.CaptchaDir != "" {
		cfg.CaptchaSolver = &vkcreds.FileCaptchaSolver{Dir: c.config.CaptchaDir}
	}
	var lastErr error
	for _, hash := range c.config.VKHashes {
		log.Printf("[vkturn] acquiring TURN credentials for hash %s...", hash[:min(8, len(hash))])
		vc, err := vkcreds.GetCredentials(ctx, cfg, hash)
		if err == nil {
			return &Credentials{
				User:     vc.User,
				Pass:     vc.Pass,
				TurnURLs: vc.TurnURLs,
				Lifetime: vc.Lifetime,
				Fetched:  time.Now(),
			}, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedNetwork, network)
	}
	if address == "" {
		return nil, errors.New("vkturn: empty destination")
	}
	sess, err := c.pickSession(ctx)
	if err != nil {
		return nil, err
	}
	st, err := sess.newClientStream(address)
	if err != nil {
		return nil, err
	}
	select {
	case err := <-st.openCh:
		if err != nil {
			_ = st.Close()
			return nil, err
		}
		return st, nil
	case <-ctx.Done():
		_ = st.Close()
		return nil, ctx.Err()
	case <-time.After(c.connectTimeout):
		_ = st.Close()
		return nil, context.DeadlineExceeded
	}
}

func (c *Client) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	if address == "" {
		return nil, errors.New("vkturn: empty UDP destination")
	}
	conn, err := c.DialContext(ctx, "tcp", UDPDestinationPrefix+address)
	if err != nil {
		return nil, err
	}
	return newUDPFramedPacketConn(conn, streamAddr{network: "udp", address: address}), nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := append([]*muxSession(nil), c.sessions...)
	c.sessions = nil
	c.mu.Unlock()
	for _, sess := range sessions {
		_ = sess.Close()
	}
	return nil
}

func (c *Client) pickSession(ctx context.Context) (*muxSession, error) {
	if err := c.ensureSessions(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	live := c.sessions[:0]
	for _, sess := range c.sessions {
		select {
		case <-sess.done:
		default:
			live = append(live, sess)
		}
	}
	c.sessions = live
	if len(c.sessions) == 0 {
		return nil, ErrNoSession
	}
	sess := c.sessions[c.rr%len(c.sessions)]
	c.rr++
	return sess, nil
}

func (c *Client) ensureSessions(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	live := c.sessions[:0]
	for _, sess := range c.sessions {
		select {
		case <-sess.done:
		default:
			live = append(live, sess)
		}
	}
	c.sessions = live
	need := c.workers - len(c.sessions)
	c.mu.Unlock()
	if need <= 0 {
		return nil
	}
	var lastErr error
	for i := 0; i < need; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		sess, err := c.connectSession(ctx, i)
		if err != nil {
			lastErr = err
			if len(c.activeSessions()) > 0 {
				return nil
			}
			continue
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = sess.Close()
			return net.ErrClosed
		}
		c.sessions = append(c.sessions, sess)
		c.mu.Unlock()
	}
	if len(c.activeSessions()) == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

func (c *Client) activeSessions() []*muxSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.sessions[:0]
	for _, sess := range c.sessions {
		select {
		case <-sess.done:
		default:
			live = append(live, sess)
		}
	}
	c.sessions = live
	return append([]*muxSession(nil), live...)
}

func (c *Client) connectSession(ctx context.Context, idx int) (*muxSession, error) {
	ctx, cancel := context.WithTimeout(ctx, c.connectTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if c.config.Direct || len(c.config.VKHashes) == 0 && c.config.Credentials == nil {
		conn, err = c.directKCP(ctx)
	} else {
		conn, err = c.turnKCP(ctx, idx)
	}
	if err != nil {
		return nil, err
	}
	if err := writeRawFrame(conn, frameHello, 0, c.config.ShortID[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(c.connectTimeout))
	fr, err := readRawFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if fr.typ != frameHelloOK {
		_ = conn.Close()
		return nil, ErrAuthFailed
	}
	return newMuxSession(conn, c.maxFramePayload, false, c.config.ShortID, nil), nil
}

func (c *Client) directKCP(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn *kcp.UDPSession
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := kcp.DialWithOptions(c.config.ServerAddr, nil, 0, 0)
		if err == nil {
			configureKCPConn(conn)
		}
		ch <- result{conn: conn, err: err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) turnKCP(ctx context.Context, idx int) (net.Conn, error) {
	creds, err := c.getCredentials(ctx)
	if err != nil {
		return nil, err
	}
	if len(creds.TurnURLs) == 0 {
		return nil, errors.New("vkturn: no TURN urls")
	}
	turnAddr := creds.TurnURLs[idx%len(creds.TurnURLs)]
	host, port, err := net.SplitHostPort(turnAddr)
	if err == nil {
		if c.config.TURNHost != "" {
			host = c.config.TURNHost
		}
		if c.config.TURNPort != "" {
			port = c.config.TURNPort
		}
		turnAddr = net.JoinHostPort(host, port)
	}
	var pc net.PacketConn
	var raw net.Conn
	if c.config.UseUDP {
		var uc *net.UDPConn
		if c.config.Dialer != nil {
			conn, err := c.config.Dialer(ctx, "udp", turnAddr)
			if err != nil {
				return nil, err
			}
			var ok bool
			uc, ok = conn.(*net.UDPConn)
			if !ok {
				_ = conn.Close()
				return nil, fmt.Errorf("vkturn: custom UDP dialer returned %T, want *net.UDPConn", conn)
			}
		} else {
			resolved, err := net.ResolveUDPAddr("udp", turnAddr)
			if err != nil {
				return nil, err
			}
			uc, err = net.DialUDP("udp", nil, resolved)
			if err != nil {
				return nil, err
			}
		}
		_ = uc.SetReadBuffer(625 * 1024)
		_ = uc.SetWriteBuffer(625 * 1024)
		pc = &connectedUDPConn{uc}
		raw = uc
	} else {
		var tcp net.Conn
		if c.config.Dialer != nil {
			tcp, err = c.config.Dialer(ctx, "tcp", turnAddr)
		} else {
			d := net.Dialer{Timeout: c.connectTimeout}
			tcp, err = d.DialContext(ctx, "tcp", turnAddr)
		}
		if err != nil {
			return nil, err
		}
		if tc, ok := tcp.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetReadBuffer(625 * 1024)
			_ = tc.SetWriteBuffer(625 * 1024)
		}
		pc = turn.NewSTUNConn(tcp)
		raw = tcp
	}
	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           pc,
		Username:       creds.User,
		Password:       creds.Pass,
		LoggerFactory:  &nullLoggerFactory{},
	})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := tc.Listen(); err != nil {
		tc.Close()
		_ = raw.Close()
		return nil, err
	}
	relay, err := tc.Allocate()
	if err != nil {
		tc.Close()
		_ = raw.Close()
		return nil, err
	}
	peer, err := net.ResolveUDPAddr("udp", c.config.ServerAddr)
	if err != nil {
		_ = relay.Close()
		tc.Close()
		_ = raw.Close()
		return nil, err
	}
	kcpConn, err := kcp.NewConn2(peer, nil, 0, 0, relay)
	if err != nil {
		_ = relay.Close()
		tc.Close()
		_ = raw.Close()
		return nil, err
	}
	configureKCPConn(kcpConn)
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_, _ = tc.SendBindingRequest()
			case <-done:
				return
			}
		}
	}()
	return &compoundConn{Conn: kcpConn, done: done, closers: []io.Closer{relay, closerFunc(tc.Close), raw}}, nil
}

func (c *Client) getCredentials(ctx context.Context) (*Credentials, error) {
	if c.config.Credentials != nil {
		return c.config.Credentials, nil
	}

	c.mu.Lock()

	// 1. Fresh in-memory cache hit — the common steady-state path, no VK contact.
	if c.creds != nil && time.Now().Before(c.credsExpiry) {
		creds := c.creds
		c.mu.Unlock()
		return creds, nil
	}

	// 2. Backoff window: a recent acquisition failed. Do NOT call VK — retrying
	//    from one IP is exactly what feeds the captcha storm. Serve stale creds
	//    if we have any (they may still satisfy the TURN server), else fail fast.
	if time.Now().Before(c.credBackoff) {
		if c.creds != nil {
			creds := c.creds
			c.mu.Unlock()
			return creds, nil
		}
		wait := time.Until(c.credBackoff).Round(time.Second)
		err := c.lastCredErr
		c.mu.Unlock()
		if err == nil {
			err = errors.New("acquisition failed")
		}
		return nil, fmt.Errorf("vkturn: credential acquisition backing off %s: %w", wait, err)
	}

	// 3. Join an in-flight acquisition rather than launching a parallel captcha.
	if c.credInflight != nil {
		fut := c.credInflight
		c.mu.Unlock()
		select {
		case <-fut.done:
			return fut.creds, fut.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 4. Re-read the on-disk cache before touching VK: an external seeder (a
	//    panel break-glass captcha solved in a real browser) may have written
	//    fresh creds since startup. Adopting them avoids a needless captcha.
	if c.cachePath != "" {
		if pc, err := loadPersistentCreds(c.cachePath); err == nil && time.Now().Before(pc.ExpiresAt) {
			creds := pc.toCredentials()
			c.creds = creds
			c.credsExpiry = pc.ExpiresAt
			c.credFails = 0
			c.credBackoff = time.Time{}
			c.lastCredErr = nil
			c.mu.Unlock()
			log.Printf("[vkturn] adopted seeded credentials from cache, valid for %s", time.Until(pc.ExpiresAt).Round(time.Second))
			return creds, nil
		}
	}

	// 5. Become the single acquisition leader. The acquisition itself runs under
	//    a long control-plane context, not the caller's short dial context: if a
	//    health probe times out after a few seconds, the captcha/credential flow
	//    must keep running so the next probe joins the same future instead of
	//    creating a new VK challenge.
	fut := &credFuture{done: make(chan struct{})}
	c.credInflight = fut
	c.mu.Unlock()
	go c.runCredentialAcquisition(fut)

	select {
	case <-fut.done:
		return fut.creds, fut.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) runCredentialAcquisition(fut *credFuture) {
	acqCtx, cancel := context.WithTimeout(context.Background(), credentialAcquireTimeout)
	defer cancel()
	creds, err := c.acquire(acqCtx)

	c.mu.Lock()
	if c.credInflight == fut {
		c.credInflight = nil
	}
	if err != nil {
		c.credFails++
		backoff := credBackoffDuration(c.credFails)
		c.lastCredErr = err
		c.credBackoff = time.Now().Add(backoff)
		log.Printf("[vkturn] credential acquisition failed (%d in a row), backing off %s: %v",
			c.credFails, backoff.Round(time.Second), err)
	} else {
		c.credFails = 0
		c.lastCredErr = nil
		c.credBackoff = time.Time{}
		c.creds = creds
		c.credsExpiry = credExpiry(creds, time.Now())
		c.persistLocked(creds)
	}
	c.mu.Unlock()

	fut.creds = creds
	fut.err = err
	close(fut.done)
}

// persistLocked write-throughs freshly acquired credentials to the disk cache.
// Best-effort: a persistence failure is logged, not propagated, so it never
// fails an otherwise-successful acquisition. Caller must hold c.mu.
func (c *Client) persistLocked(creds *Credentials) {
	if c.cachePath == "" || creds == nil {
		return
	}
	var digest string
	if len(c.config.VKHashes) > 0 {
		digest = hashDigest(c.config.VKHashes[0])
	}
	fetched := creds.Fetched
	if fetched.IsZero() {
		fetched = time.Now()
	}
	pc := &persistentCreds{
		User:       creds.User,
		Pass:       creds.Pass,
		TurnURLs:   creds.TurnURLs,
		Lifetime:   creds.Lifetime,
		HashDigest: digest,
		FetchedAt:  fetched,
		ExpiresAt:  c.credsExpiry,
	}
	if err := savePersistentCreds(c.cachePath, pc); err != nil {
		log.Printf("[vkturn] warning: could not persist credentials: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

type compoundConn struct {
	net.Conn
	done    chan struct{}
	once    sync.Once
	closers []io.Closer
}

func (c *compoundConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		err = c.Conn.Close()
		for _, cl := range c.closers {
			if cl == nil {
				continue
			}
			if e := cl.Close(); err == nil && e != nil {
				err = e
			}
		}
	})
	return err
}

type nullLoggerFactory struct{}

func (n *nullLoggerFactory) NewLogger(_ string) logging.LeveledLogger { return nullLogger{} }

type nullLogger struct{}

func (nullLogger) Trace(string)                  {}
func (nullLogger) Tracef(string, ...interface{}) {}
func (nullLogger) Debug(string)                  {}
func (nullLogger) Debugf(string, ...interface{}) {}
func (nullLogger) Info(string)                   {}
func (nullLogger) Infof(string, ...interface{})  {}
func (nullLogger) Warn(string)                   {}
func (nullLogger) Warnf(string, ...interface{})  {}
func (nullLogger) Error(string)                  {}
func (nullLogger) Errorf(string, ...interface{}) {}
