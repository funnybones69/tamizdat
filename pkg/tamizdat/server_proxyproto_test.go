package tamizdat

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/proxyproto"
)

type proxyProtoTestConn struct {
	r      *bytes.Reader
	remote net.Addr
	local  net.Addr
	reads  atomic.Int32
	closed atomic.Bool
}

func newProxyProtoTestConn(payload []byte, remote string) *proxyProtoTestConn {
	return &proxyProtoTestConn{
		r:      bytes.NewReader(payload),
		remote: &net.TCPAddr{IP: net.ParseIP(remote), Port: 4242},
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}
}

func (c *proxyProtoTestConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.reads.Add(1)
	return c.r.Read(p)
}

func (c *proxyProtoTestConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *proxyProtoTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *proxyProtoTestConn) LocalAddr() net.Addr              { return c.local }
func (c *proxyProtoTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *proxyProtoTestConn) SetDeadline(time.Time) error      { return nil }
func (c *proxyProtoTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *proxyProtoTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *proxyProtoTestConn) readCount() int                   { return int(c.reads.Load()) }
func (c *proxyProtoTestConn) remaining() int                   { return c.r.Len() }
func (c *proxyProtoTestConn) isClosed() bool                   { return c.closed.Load() }

func proxyProtoTestServer(t *testing.T, trustedCIDRs, originAddr string) *Server {
	t.Helper()
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	trusted, err := proxyproto.ParseCIDRs(trustedCIDRs)
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	cfg := ServerConfig{
		PrivateKey:               privateKey,
		MasterShortID:            shortID,
		ProxyProtocol:            true,
		ProxyProtocolTrusted:     trusted,
		DisableMasqueradePrewarm: true, // origin listener accepts exactly 1 conn
		Handler: func(context.Context, net.Conn, string) {
		},
	}
	if originAddr != "" {
		cfg.MasqueradeDomain = "origin.test"
		cfg.MasqueradeAddr = originAddr
		cfg.MasqueradeIdleTimeout = time.Second
		cfg.MasqueradeMaxDuration = time.Second
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func startProxyProtoOrigin(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		defer close(got)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		got <- b
	}()
	return ln.Addr().String(), got
}

func runProxyProtoHandle(t *testing.T, s *Server, conn net.Conn) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.handleConnection(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("handleConnection did not return")
	}
}

func proxyProtoTLSRecord() []byte {
	payload := []byte{0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}
	return append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(payload))}, payload...)
}

func buildProxyProtoV2IPv4(src string, srcPort uint16, dst string, dstPort uint16) []byte {
	addr := make([]byte, 12)
	copy(addr[0:4], net.ParseIP(src).To4())
	copy(addr[4:8], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(addr[8:10], srcPort)
	binary.BigEndian.PutUint16(addr[10:12], dstPort)
	hdr := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	hdr = append(hdr, 0x21, 0x11, 0x00, byte(len(addr)))
	return append(hdr, addr...)
}

func assertMasqBucket(t *testing.T, s *Server, want string) {
	t.Helper()
	s.masqLimiter.mu.Lock()
	_, realOK := s.masqLimiter.buckets[want]
	_, proxyOK := s.masqLimiter.buckets["127.0.0.1"]
	s.masqLimiter.mu.Unlock()
	if !realOK {
		t.Fatalf("masquerade limiter bucket %q not found", want)
	}
	if proxyOK {
		t.Fatalf("masquerade limiter used proxy IP bucket 127.0.0.1 instead of %q", want)
	}
}

func waitProxyProtoOrigin(t *testing.T, got <-chan []byte, want []byte) {
	t.Helper()
	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Fatalf("origin received %x, want TLS record %x", b, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not receive forwarded TLS record")
	}
}

func TestProxyProtocol_TrustedV2_RealIPReachesLimiter(t *testing.T) {
	tlsRecord := proxyProtoTLSRecord()
	originAddr, originGot := startProxyProtoOrigin(t)
	s := proxyProtoTestServer(t, "127.0.0.1/32", originAddr)
	hdr := buildProxyProtoV2IPv4("203.0.113.42", 54321, "198.51.100.1", 443)
	conn := newProxyProtoTestConn(append(hdr, tlsRecord...), "127.0.0.1")

	runProxyProtoHandle(t, s, conn)
	waitProxyProtoOrigin(t, originGot, tlsRecord)
	assertMasqBucket(t, s, "203.0.113.42")
}

func TestProxyProtocol_TrustedV1_RealIPReachesLimiter(t *testing.T) {
	tlsRecord := proxyProtoTLSRecord()
	originAddr, originGot := startProxyProtoOrigin(t)
	s := proxyProtoTestServer(t, "127.0.0.1/32", originAddr)
	hdr := []byte("PROXY TCP4 203.0.113.42 198.51.100.1 54321 443\r\n")
	conn := newProxyProtoTestConn(append(hdr, tlsRecord...), "127.0.0.1")

	runProxyProtoHandle(t, s, conn)
	waitProxyProtoOrigin(t, originGot, tlsRecord)
	assertMasqBucket(t, s, "203.0.113.42")
}

func TestProxyProtocol_UntrustedDirect_Closes(t *testing.T) {
	s := proxyProtoTestServer(t, "", "")
	payload := append([]byte("PROXY TCP4 203.0.113.42 198.51.100.1 54321 443\r\n"), proxyProtoTLSRecord()...)
	conn := newProxyProtoTestConn(payload, "127.0.0.1")

	runProxyProtoHandle(t, s, conn)
	if !conn.isClosed() {
		t.Fatal("untrusted direct connection was not closed")
	}
	if got := conn.readCount(); got != 0 {
		t.Fatalf("untrusted direct connection read count = %d, want 0 before close", got)
	}
}

func TestProxyProtocol_TrustedRawTLS_Closes(t *testing.T) {
	s := proxyProtoTestServer(t, "127.0.0.1/32", "")
	conn := newProxyProtoTestConn(proxyProtoTLSRecord(), "127.0.0.1")

	runProxyProtoHandle(t, s, conn)
	if !conn.isClosed() {
		t.Fatal("trusted raw TLS connection was not closed")
	}
	s.masqLimiter.mu.Lock()
	buckets := len(s.masqLimiter.buckets)
	s.masqLimiter.mu.Unlock()
	if buckets != 0 {
		t.Fatalf("trusted raw TLS should close before masquerade limiter, got %d buckets", buckets)
	}
}

func TestProxyProtocol_V1OversizedLine_Rejected(t *testing.T) {
	s := proxyProtoTestServer(t, "127.0.0.1/32", "")
	payload := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 100 200" + string(bytes.Repeat([]byte{'x'}, 10000)))
	conn := newProxyProtoTestConn(payload, "127.0.0.1")

	runProxyProtoHandle(t, s, conn)
	if !conn.isClosed() {
		t.Fatal("oversized v1 connection was not closed")
	}
	if remaining := conn.remaining(); remaining == 0 {
		t.Fatal("oversized v1 line consumed the entire payload before rejection")
	}
}

func TestIsTrusted_IPv4Mapped(t *testing.T) {
	trusted, err := proxyproto.ParseCIDRs("127.0.0.1/32")
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1")}
	if !proxyproto.IsTrusted(remote, trusted) {
		t.Fatal("IPv4-mapped ::ffff:127.0.0.1 should match 127.0.0.1/32 with net.IPNet.Contains")
	}
}
