package tamizdat

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Masquerade implements a TCP-level transparent proxy to the real masquerade
// domain. When the server receives a connection that fails Samizdat auth
// verification, it enters masquerade mode: the buffered raw ClientHello is
// forwarded to the real domain, and bidirectional TCP proxying begins.
//
// This makes the server indistinguishable from the real domain to active
// probes — the probe completes a real TLS handshake with the real domain's
// certificate and receives real HTTP responses.
type Masquerade struct {
	OriginAddr   string        // IP:port of real domain (or resolved from domain)
	OriginDomain string        // domain name for DNS resolution
	IdleTimeout  time.Duration // close after no data (default: 5m)
	MaxDuration  time.Duration // absolute max proxy duration (default: 10m)
	DialTimeout  time.Duration // timeout connecting to origin (default: 10s)

	// DialOrigin, when non-nil, replaces the default net.DialTimeout the
	// proxy uses to connect to the origin. The Server installs a hook
	// here that pulls from the pre-warmed pool (review-A P3) so the
	// auth-fail path can skip the SYN RTT for the first few probes per
	// origin per minute. nil keeps legacy direct-dial behaviour for
	// embedded callers and the existing test suite.
	DialOrigin func(ctx context.Context, addr string) (net.Conn, error)
}

// NewMasquerade creates a new masquerade proxy with defaults.
func NewMasquerade(domain, addr string, idleTimeout, maxDuration time.Duration) *Masquerade {
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}
	if maxDuration == 0 {
		maxDuration = 10 * time.Minute
	}
	return &Masquerade{
		OriginAddr:   addr,
		OriginDomain: domain,
		IdleTimeout:  idleTimeout,
		MaxDuration:  maxDuration,
		DialTimeout:  10 * time.Second,
	}
}

type idleConn struct {
	net.Conn
	idle        time.Duration
	maxDeadline time.Time
}

func (c *idleConn) Read(p []byte) (int, error) {
	deadline := c.readDeadline()
	if !deadline.IsZero() {
		_ = c.Conn.SetReadDeadline(deadline)
	}
	return c.Conn.Read(p)
}

func (c *idleConn) readDeadline() time.Time {
	if c.idle <= 0 {
		return c.maxDeadline
	}
	deadline := time.Now().Add(c.idle)
	if !c.maxDeadline.IsZero() && c.maxDeadline.Before(deadline) {
		return c.maxDeadline
	}
	return deadline
}

// ProxyConnection forwards a non-authenticated connection to the real domain.
// clientHello contains the buffered raw ClientHello bytes that triggered the
// auth check failure. conn is the raw TCP connection from the probe (pre-TLS).
// ProxyConnectionWithOrigin is the SNI-aware variant. originDomain overrides
// m.OriginDomain when non-empty (cover-SNI rotation -- compass P1.1). If
// originDomain is empty, falls back to default m.OriginDomain. originAddr
// is recomputed from originDomain unless explicitly overridden.
//
// A-FU-1: pool entries may carry an explicit `host:port` (e.g. `mc.yandex.ru:8443`)
// for non-:443 origins. Pre-fix the code unconditionally re-wrapped with `:443`,
// producing `mc.yandex.ru:8443:443` and a guaranteed dial failure. Now we
// detect explicit ports via net.SplitHostPort and only append the default :443
// when the entry is bare-host.
func (m *Masquerade) ProxyConnectionWithOrigin(conn net.Conn, clientHello []byte, originDomain string) error {
	var addr string
	switch {
	case originDomain == "" || originDomain == m.OriginDomain:
		// Default origin — honour MasqueradeAddr override if set.
		addr = m.OriginAddr
		if addr == "" {
			addr = ensureHostPort(m.OriginDomain, "443")
		}
	default:
		// Pool entry — already host:port (canonical) or bare host.
		addr = ensureHostPort(originDomain, "443")
	}
	return m.proxyTo(conn, clientHello, addr)
}

func (m *Masquerade) ProxyConnection(conn net.Conn, clientHello []byte) error {
	addr := m.OriginAddr
	if addr == "" {
		addr = ensureHostPort(m.OriginDomain, "443")
	}
	return m.proxyTo(conn, clientHello, addr)
}

// ensureHostPort returns h unchanged when it already parses as host:port,
// otherwise appends the default port. Handles the IPv6 [::1] form by
// detecting the enclosing brackets via SplitHostPort first.
func ensureHostPort(h, defaultPort string) string {
	if h == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(h); err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(h, defaultPort)
}

// proxyTo carries the actual TCP-level forward to a resolved address.
// Shared between ProxyConnection (default) and ProxyConnectionWithOrigin
// (SNI-routed pool).
func (m *Masquerade) proxyTo(conn net.Conn, clientHello []byte, addr string) error {
	// Connect to the real domain. If a DialOrigin hook is installed
	// (review-A P3 pre-warmed pool), use it; the hook is responsible for
	// honouring its own timeout via the supplied context. Otherwise fall
	// through to direct dial with m.DialTimeout.
	var (
		originConn net.Conn
		err        error
	)
	if m.DialOrigin != nil {
		dialCtx, cancel := context.WithTimeout(context.Background(), m.DialTimeout)
		originConn, err = m.DialOrigin(dialCtx, addr)
		cancel()
	} else {
		originConn, err = net.DialTimeout("tcp", addr, m.DialTimeout)
	}
	if err != nil {
		return fmt.Errorf("connecting to masquerade origin %s: %w", addr, err)
	}

	// Forward the buffered ClientHello that we already read
	if len(clientHello) > 0 {
		if _, err := originConn.Write(clientHello); err != nil {
			originConn.Close()
			return fmt.Errorf("forwarding ClientHello to origin: %w", err)
		}
	}

	// Set absolute max duration deadline, then wrap both read sides with a
	// shorter rolling idle deadline. The wrapper never extends reads past the
	// absolute max deadline.
	deadline := time.Now().Add(m.MaxDuration)
	conn.SetDeadline(deadline)
	originConn.SetDeadline(deadline)
	clientConn := &idleConn{Conn: conn, idle: m.IdleTimeout, maxDeadline: deadline}
	originIdleConn := &idleConn{Conn: originConn, idle: m.IdleTimeout, maxDeadline: deadline}

	// Bidirectional proxy: two goroutines running io.Copy
	var wg sync.WaitGroup
	var copyErr error
	var errOnce sync.Once

	wg.Add(2)

	// probe -> origin
	go func() {
		defer wg.Done()
		n, err := io.Copy(originIdleConn, clientConn)
		masqueradeBytesForwarded.Add(n)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := originConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// origin -> probe
	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, originIdleConn)
		masqueradeBytesForwarded.Add(n)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()

	originConn.Close()
	conn.Close()

	return copyErr
}
