package tamizdat

import (
	"bytes"
	"context"
	"crypto/tls"
	"expvar"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type captureWriteConn struct {
	net.Conn
	mu       sync.Mutex
	captured []byte
}

func (c *captureWriteConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		c.mu.Lock()
		if c.captured == nil {
			c.captured = append([]byte(nil), p...)
		}
		c.mu.Unlock()
	}
	return c.Conn.Write(p)
}

func (c *captureWriteConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.captured...)
}

func startP03EchoServer(t *testing.T, enableBBCR bool) (net.Listener, []byte, [8]byte) {
	t.Helper()
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, _ string) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})
	return ln, serverPub, shortID
}

func TestP03ECDHSessionIDV1RoundTripBBCR1KiB(t *testing.T) {
	ln, serverPub, shortID := startP03EchoServer(t, true)
	client, err := NewClient(ClientConfig{
		ServerAddr:       ln.Addr().String(),
		ServerName:       "cover.example",
		PublicKey:        serverPub,
		ShortID:          shortID,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("x"), 1024)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echoed 1KiB: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload mismatch")
	}
}

func TestP03ReplayRejectionIncrementsExpvar(t *testing.T) {
	before := expvarIntValue("tamizdat.replay.hits")
	ln, serverPub, shortID := startP03EchoServer(t, false)
	var captured *captureWriteConn
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "cover.example",
		PublicKey:              serverPub,
		ShortID:                shortID,
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			captured = &captureWriteConn{Conn: conn}
			return captured, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := client.DialContext(ctx, "tcp", "example.org:443")
	cancel()
	if err != nil {
		t.Fatalf("initial DialContext: %v", err)
	}
	_ = conn.Close()
	clientHello := captured.Bytes()
	if len(clientHello) == 0 {
		t.Fatal("did not capture ClientHello")
	}

	replayConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial replay: %v", err)
	}
	defer replayConn.Close()
	if _, err := replayConn.Write(clientHello); err != nil {
		t.Fatalf("write replay ClientHello: %v", err)
	}
	_ = replayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = replayConn.Read(make([]byte, 1))

	if got := expvarIntValue("tamizdat.replay.hits"); got <= before {
		t.Fatalf("tamizdat.replay.hits = %d, want > %d", got, before)
	}
}

func TestP03DebugExpvarEndpointGated(t *testing.T) {
	serverPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	s, err := NewServer(ServerConfig{
		PrivateKey:             serverPriv,
		MasterShortID:          shortID,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		Debug:                  true,
		DebugListenAddr:        "127.0.0.1:0",
		DisableDefaultSecurity: true,
		Handler:                func(context.Context, net.Conn, string) {},
	})
	if err != nil {
		t.Fatalf("NewServer Debug=true: %v", err)
	}
	defer s.Close()
	if s.debugAddr() == nil {
		t.Fatal("Debug=true did not bind debug listener")
	}
	resp, err := http.Get("http://" + s.debugAddr().String() + "/debug/vars")
	if err != nil {
		t.Fatalf("GET /debug/vars: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/debug/vars status = %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("tamizdat.replay.hits")) {
		t.Fatalf("/debug/vars missing replay counters: %s", body)
	}

	s2, err := NewServer(ServerConfig{
		PrivateKey:             serverPriv,
		MasterShortID:          shortID,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		Debug:                  false,
		DebugListenAddr:        "127.0.0.1:0",
		DisableDefaultSecurity: true,
		Handler:                func(context.Context, net.Conn, string) {},
	})
	if err != nil {
		t.Fatalf("NewServer Debug=false: %v", err)
	}
	defer s2.Close()
	if s2.debugAddr() != nil {
		t.Fatalf("Debug=false unexpectedly bound %s", s2.debugAddr())
	}
}

func expvarIntValue(name string) int64 {
	if v := expvar.Get(name); v != nil {
		if i, ok := v.(*expvar.Int); ok {
			return i.Value()
		}
	}
	return 0
}

var _ = tls.VersionTLS13
