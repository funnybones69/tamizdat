package tamizdat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// h2Transport manages a single TLS+HTTP/2 connection to the server and
// multiplexes CONNECT tunnels over it as separate H2 streams.
type h2Transport struct {
	tlsConn     net.Conn
	h2Roundtrip http.RoundTripper
	serverAddr  string
	localAddr   net.Addr
	remoteAddr  net.Addr
	shaper      *Shaper
	fragmenter  *RecordFragmenter

	// lastActiveUnixNano tracks the last time getTransport chose this
	// connection, so the connpool idle-reaper can honour IdleTimeout
	// instead of churning zero-stream transports every 30 s (the current
	// behaviour exactly matches what TSPU #546 polices).
	lastActiveUnixNano atomic.Int64

	// bytesSent is the cumulative outer-wire payload bytes written via this
	// transport. Used by P0.2 to decide when to migrate to a fresh TLS
	// connection before the #490 15-20 kB shaping threshold.
	bytesSent atomic.Int64

	// P0.2 adaptive chunking state. effectiveThreshold is randomized per
	// transport from BytesPerFlowThreshold ± BytesThresholdJitter. draining
	// makes connpool skip this flow for new streams; existing streams finish.
	effectiveThreshold int64
	// bytesSoftCap > 0: marks draining when bytesSent >= cap. Independent of
	// effectiveThreshold (which stays MaxInt64 in the post-BBCR design).
	// Set by connpool from ClientConfig.BytesPerTransportSoftCap.
	bytesSoftCap      int64
	drainTimeout      time.Duration
	draining          atomic.Bool
	drainCloseStarted atomic.Bool
	// sni is the SNI presented by THIS transport's TLS handshake. Connpool
	// reads it to feed pickServerNameExcluding() so freshly-spawned siblings
	// get a different SNI than the existing transports.
	// Empty string = unknown / not tracked.
	sni string

	mu            sync.Mutex
	activeStreams atomic.Int32
	maxStreams    int
	closed        bool
}

// newH2Transport creates an HTTP/2 transport over an existing TLS connection.
// sni is the SNI presented during the TLS handshake (used by connpool
// excludeSNIs accounting); empty string allowed for back-compat callers.
func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int, shaper *Shaper, fragmenter *RecordFragmenter, drainTimeout time.Duration, sni string) (*h2Transport, error) {
	t := &h2Transport{
		tlsConn:      tlsConn,
		serverAddr:   serverAddr,
		localAddr:    tlsConn.LocalAddr(),
		remoteAddr:   tlsConn.RemoteAddr(),
		maxStreams:   maxStreams,
		shaper:       shaper,
		fragmenter:   fragmenter,
		drainTimeout: drainTimeout,
		sni:          sni,
	}
	wrappedConn := t.wrapClientConn(tlsConn)
	h2t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return wrappedConn, nil
		},
		AllowHTTP:          false,
		DisableCompression: true,
		// OPT-2 + compass v2 §5.8 H2 SETTINGS Chrome-mimicry. Stock Go h2.Transport
		// can't control everything Chrome sends (initial-window-size in SETTINGS
		// frame is hard-coded; SETTINGS frame ordering can't be customized; full
		// Akamai/JA4H parity would require forking x/net/http2). Within stock Go
		// we tune what's exposed:
		//   - HEADER_TABLE_SIZE = 65536   (Chrome matches)
		//   - MAX_HEADER_LIST_SIZE = 262144 (Chrome matches)
		//   - ENABLE_PUSH = 0             (Go default, matches Chrome)
		//   - MAX_FRAME_SIZE = (default)  (Chrome client also doesn't set this)
		ReadIdleTimeout:           30 * time.Second,
		PingTimeout:               10 * time.Second,
		MaxDecoderHeaderTableSize: 1 << 16, // 65536, Chrome
		MaxHeaderListSize:         262144,  // Chrome
	}
	t.h2Roundtrip = h2t
	t.touch()

	return t, nil
}

// touch updates the last-active timestamp to now.
func (t *h2Transport) touch() { t.lastActiveUnixNano.Store(time.Now().UnixNano()) }

// lastActive returns the last time this transport handed out a stream.
func (t *h2Transport) lastActive() time.Time {
	ns := t.lastActiveUnixNano.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// totalBytesSent returns cumulative payload bytes emitted on this TLS flow.
func (t *h2Transport) totalBytesSent() int64 { return t.bytesSent.Load() }

// addBytesSent is invoked from the wire-facing writer to grow the counter.
func (t *h2Transport) addBytesSent(n int) {
	if n <= 0 {
		return
	}
	total := t.bytesSent.Add(estimatedOuterWireBytes(n))
	if t.effectiveThreshold > 0 && total >= t.effectiveThreshold {
		t.markDraining()
	}
	// #6 multi-conn fallback: per-transport soft cap. When set, drain this
	// transport so connpool round-robins to siblings; reaper spawns a fresh
	// replacement. Used to evict transports approaching #490 byte threshold.
	if t.bytesSoftCap > 0 && total >= t.bytesSoftCap {
		t.markDraining()
	}
}

// estimatedOuterWireBytes conservatively maps plaintext H2 frame bytes to the
// outer-wire budget used by TSPU #490. The pcap-visible budget includes TLS
// record overhead, TCP/IP overhead, ACKs, and handshake amortization; counting
// plaintext bytes 1:1 under-shoots and lets pcap flows exceed 15KB. A 6x
// multiplier is intentionally conservative: it triggers migration earlier
// while preserving the configured randomized threshold formula.
// TODO(pool-foundation): operator should recalibrate this multiplier from
// live pcaps before treating BytesPerTransportSoftCap as an outer-wire budget.
func estimatedOuterWireBytes(n int) int64 { return int64(n) * 6 }

// openTunnel issues an HTTP/2 CONNECT request to open a tunnel to the
// destination through the proxy server. Returns a net.Conn backed by the
// H2 stream.
func (t *h2Transport) openTunnel(ctx context.Context, destination string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("transport closed")
	}
	if t.isDraining() {
		t.mu.Unlock()
		return nil, errors.New("transport draining")
	}
	t.mu.Unlock()
	t.touch()

	pr, pw := io.Pipe()

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { tunnelCancel() })

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		return nil, fmt.Errorf("creating CONNECT request: %w", err)
	}
	req.Host = destination

	resp, err := t.h2Roundtrip.RoundTrip(req)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		// If the underlying TCP/TLS conn died, mark this transport closed so
		// future pool selections skip it and create a fresh one. Common
		// patterns: "use of closed network connection", "EOF", "stream error",
		// "broken pipe" — all indicate the outer pipe is gone, not just this
		// stream.
		if isOuterDeadErr(err) {
			t.closeFromError(err)
		}
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	// MED-2: if stop() returns false, the AfterFunc already fired (or is firing),
	// meaning ctx was cancelled before/during RoundTrip. The success-looking
	// resp is racy -- treat the dial as cancelled.
	if !stop() {
		resp.Body.Close()
		pw.Close()
		tunnelCancel()
		return nil, fmt.Errorf("CONNECT to %s: caller context cancelled mid-dial", destination)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		tunnelCancel()
		return nil, fmt.Errorf("CONNECT to %s returned status %d", destination, resp.StatusCode)
	}

	// activeStreams already incremented by reserveStreamSlot in connpool.getTransport.
	// (Belt-and-braces: if caller used the public API directly w/o reservation,
	// stream count drift is bounded by maxStreams+1 -- next reserveStreamSlot retries.)

	rwc := &h2StreamRWC{
		reader:       resp.Body,
		writer:       pw,
		transport:    t,
		tunnelCancel: tunnelCancel,
	}

	conn := newStreamConn(
		rwc,
		t.localAddr,
		&streamAddr{network: "tcp", address: destination},
		destination,
		t.shaper,
		t.fragmenter,
	)

	return conn, nil
}

// openUDPTunnel issues an HTTP/2 CONNECT request with the Samizdat-Protocol
// header set to udp/1. Server bridges this stream to a UDP socket targeting
// `destination`. The returned io.ReadWriteCloser carries length-prefixed UDP
// datagrams (uint16 BE length || payload, see udp_packetconn.go MaxUDPDatagram).
// Wrapped by Client.DialUDP into a net.PacketConn for callers.
func (t *h2Transport) openUDPTunnel(ctx context.Context, destination string) (io.ReadWriteCloser, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("transport closed")
	}
	if t.isDraining() {
		t.mu.Unlock()
		return nil, errors.New("transport draining")
	}
	t.mu.Unlock()
	t.touch()

	pr, pw := io.Pipe()

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { tunnelCancel() })

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		return nil, fmt.Errorf("creating UDP CONNECT request: %w", err)
	}
	req.Host = destination
	req.Header.Set(SamizdatProtocolHeader, SamizdatProtocolUDP)

	resp, err := t.h2Roundtrip.RoundTrip(req)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		if isOuterDeadErr(err) {
			t.closeFromError(err)
		}
		return nil, fmt.Errorf("UDP CONNECT to %s: %w", destination, err)
	}

	// MED-2: stop() race -- see openTunnel for the rationale.
	if !stop() {
		resp.Body.Close()
		pw.Close()
		tunnelCancel()
		return nil, fmt.Errorf("UDP CONNECT to %s: caller context cancelled mid-dial", destination)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		tunnelCancel()
		return nil, fmt.Errorf("UDP CONNECT to %s returned status %d", destination, resp.StatusCode)
	}

	// activeStreams already incremented by reserveStreamSlot in connpool.getTransport.
	// (Belt-and-braces: if caller used the public API directly w/o reservation,
	// stream count drift is bounded by maxStreams+1 -- next reserveStreamSlot retries.)

	return &h2StreamRWC{
		reader:       resp.Body,
		writer:       pw,
		transport:    t,
		tunnelCancel: tunnelCancel,
	}, nil
}

// hasCapacity returns true if the transport can accept more streams.
// Read-only -- racy by design. Use reserveStreamSlot for atomic claim.
func (t *h2Transport) hasCapacity() bool {
	if t.maxStreams <= 0 {
		return !t.isDraining()
	}
	return !t.isDraining() && int(t.activeStreams.Load()) < t.maxStreams
}

// reserveStreamSlot atomically increments activeStreams iff the transport
// is not draining/closed and is under maxStreams. Returns true on success.
// HIGH-4: prevents the TOCTOU oversubscription where two callers each pass
// hasCapacity() at activeStreams=99 and then both Add(1) -> 101 > 100.
func (t *h2Transport) reserveStreamSlot() bool {
	if t.maxStreams <= 0 {
		// No client-side cap configured: trust server's
		// SETTINGS_MAX_CONCURRENT_STREAMS handled by net/http2 internally.
		// Still increment activeStreams so observability + drain accounting work.
		if t.isDraining() || t.isClosed() {
			return false
		}
		t.activeStreams.Add(1)
		return true
	}

	for {
		if t.isClosed() || t.isDraining() {
			return false
		}
		cur := t.activeStreams.Load()
		if int(cur) >= t.maxStreams {
			return false
		}
		if t.activeStreams.CompareAndSwap(cur, cur+1) {
			return true
		}
		// CAS lost; retry
	}
}

// releaseStreamSlot decrements activeStreams. Pair with reserveStreamSlot
// when openTunnel fails after reservation succeeded.
func (t *h2Transport) releaseStreamSlot() {
	t.activeStreams.Add(-1)
}

// streamCount returns the number of active streams.
func (t *h2Transport) streamCount() int {
	return int(t.activeStreams.Load())
}

// close shuts down the H2 transport and underlying TLS connection.
func (t *h2Transport) close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	t.closeH2RoundTripper()
	return t.closeTLSConn()
}

// isClosed returns true if the transport has been closed.
func (t *h2Transport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// h2StreamRWC wraps a response body (reader) and pipe writer as an
// io.ReadWriteCloser for use as a bidirectional stream.
type h2StreamRWC struct {
	reader       io.ReadCloser
	writer       io.WriteCloser
	transport    *h2Transport
	tunnelCancel context.CancelFunc
	once         sync.Once
	writerOnce   sync.Once
}

func (s *h2StreamRWC) Read(b []byte) (int, error) {
	return s.reader.Read(b)
}

func (s *h2StreamRWC) Write(b []byte) (int, error) {
	n, err := s.writer.Write(b)
	if n > 0 && s.transport != nil {
		s.transport.addBytesSent(n)
	}
	return n, err
}

func (s *h2StreamRWC) Close() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.closeWriter()

		go func() {
			timer := time.AfterFunc(5*time.Second, func() {
				s.reader.Close()
			})
			io.Copy(io.Discard, s.reader)
			timer.Stop()
			s.reader.Close()
			if s.tunnelCancel != nil {
				s.tunnelCancel()
			}
			remaining := s.transport.activeStreams.Add(-1)
			if remaining == 0 && s.transport.isDraining() {
				_ = s.transport.close()
			}
		}()
	})
	return closeErr
}

func (s *h2StreamRWC) fastClose() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.closeWriter()
		_ = s.reader.Close()
		if s.tunnelCancel != nil {
			s.tunnelCancel()
		}
		if s.transport != nil {
			remaining := s.transport.activeStreams.Add(-1)
			if remaining == 0 && s.transport.isDraining() {
				_ = s.transport.close()
			}
		}
	})
	return closeErr
}

func (s *h2StreamRWC) closeWriter() error {
	var err error
	s.writerOnce.Do(func() {
		err = s.writer.Close()
	})
	return err
}

func (s *h2StreamRWC) CloseWrite() error {
	return s.closeWriter()
}

// randomizedBytesThreshold returns threshold randomized by ±jitter for one
// transport. randomInt is crypto/rand-backed (see fragmenter.go), avoiding a
// deterministic per-process fingerprint.
func randomizedBytesSoftCap(base int64) int64 {
	if base <= 0 {
		return 0
	}
	return base + int64(randomInt(0, 1537))
}

func randomizedBytesThreshold(threshold int, jitter float64) int64 {
	if threshold <= 0 {
		return 0
	}
	if jitter < 0 {
		jitter = -jitter
	}
	if jitter == 0 {
		return int64(threshold)
	}
	// r in [-1, +1], with six decimal digits of entropy.
	r := float64(randomInt(0, 2000001)-1000000) / 1000000.0
	effective := int64(float64(threshold) * (1 + r*jitter))
	if effective < 1 {
		return 1
	}
	return effective
}

func (t *h2Transport) markDraining() {
	if t == nil {
		return
	}
	if t.draining.CompareAndSwap(false, true) {
		t.startGracefulDrainClose()
	}
}

func (t *h2Transport) isDraining() bool {
	return t != nil && t.draining.Load()
}

func (t *h2Transport) startGracefulDrainClose() {
	if !t.drainCloseStarted.CompareAndSwap(false, true) {
		return
	}
	go t.gracefulDrainClose()
}

func (t *h2Transport) gracefulDrainClose() {
	// Ask the H2 stack to stop accepting/opening streams before touching the
	// TLS socket. This is the GOAWAY-equivalent ordering available through the
	// standard x/net/http2 Transport API.
	t.closeH2RoundTripper()

	wait := t.drainTimeout / 2
	if wait < 0 {
		wait = 0
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if t.activeStreams.Load() == 0 {
			_ = t.closeTLSConn()
			return
		}
		select {
		case <-deadline.C:
			_ = t.closeTLSConn()
			return
		case <-ticker.C:
		}
	}
}

func (t *h2Transport) closeH2RoundTripper() {
	if t == nil || t.h2Roundtrip == nil {
		return
	}
	if closer, ok := t.h2Roundtrip.(io.Closer); ok {
		_ = closer.Close()
		return
	}
	if closer, ok := t.h2Roundtrip.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *h2Transport) closeTLSConn() error {
	if t == nil || t.tlsConn == nil {
		return nil
	}
	return t.tlsConn.Close()
}

func (t *h2Transport) wrapClientConn(conn net.Conn) net.Conn {
	return &h2AdaptiveConn{Conn: conn, transport: t}
}

func (t *h2Transport) wrapServerConn(conn net.Conn) net.Conn {
	if t.effectiveThreshold <= 0 {
		return conn
	}
	return &h2AdaptiveConn{Conn: conn, transport: t, serverSide: true}
}

type h2AdaptiveConn struct {
	net.Conn
	transport  *h2Transport
	serverSide bool
	writeMu    sync.Mutex
	readMu     sync.Mutex
	readBuf    []byte
}

func (c *h2AdaptiveConn) Write(p []byte) (int, error) {
	if !c.serverSide || c.transport == nil || c.transport.effectiveThreshold <= 0 {
		return c.Conn.Write(p)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.Conn.Write(p)
	if n > 0 {
		total := c.transport.bytesSent.Add(estimatedOuterWireBytes(n))
		if total >= c.transport.effectiveThreshold {
			// Phase G removes raw GOAWAY from normal rotation. BBCR handles
			// make-before-break rotation with REBIND; legacy fallback only marks
			// this outer draining so connpool stops assigning new streams.
			c.transport.markDraining()
		}
	}
	return n, err
}

func (c *h2AdaptiveConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.serverSide && c.transport != nil {
		c.observeFrames(p[:n])
	}
	return n, err
}

func (c *h2AdaptiveConn) observeFrames(p []byte) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.readBuf = append(c.readBuf, p...)
	for len(c.readBuf) >= 9 {
		length := int(c.readBuf[0])<<16 | int(c.readBuf[1])<<8 | int(c.readBuf[2])
		frameLen := 9 + length
		if frameLen < 9 || length > 1<<20 {
			c.readBuf = c.readBuf[:0]
			return
		}
		if len(c.readBuf) < frameLen {
			return
		}
		frameType := c.readBuf[3]
		if frameType == 0x7 { // GOAWAY
			c.transport.markDraining()
		}
		copy(c.readBuf, c.readBuf[frameLen:])
		c.readBuf = c.readBuf[:len(c.readBuf)-frameLen]
	}
}

// isOuterDeadErr reports whether the error indicates the outer TCP/TLS pipe
// is dead (not just a per-stream issue). When true, the whole h2Transport
// must be discarded — no further streams will succeed on it.
func isOuterDeadErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "GOAWAY") ||
		strings.Contains(s, "ENOTCONN") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "no route to host")
}

// closeFromError marks this transport closed *because* of an outer-pipe
// failure detected from a RoundTrip. Idempotent — safe to call repeatedly.
// Goal is to flip the closed flag so the pool stops handing this transport
// to new dials. The actual H2/TLS teardown runs in a background goroutine.
func (t *h2Transport) closeFromError(err error) {
	t.mu.Lock()
	already := t.closed
	t.closed = true
	t.mu.Unlock()
	if already {
		return
	}
	go func() {
		t.closeH2RoundTripper()
		_ = t.closeTLSConn()
	}()
}
