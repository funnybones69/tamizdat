package tamizdat

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type v1IntegrationRecorder struct {
	mu    sync.Mutex
	dests []string
}

func (r *v1IntegrationRecorder) add(dest string) {
	r.mu.Lock()
	r.dests = append(r.dests, dest)
	r.mu.Unlock()
}

func (r *v1IntegrationRecorder) count(dest string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, got := range r.dests {
		if got == dest {
			n++
		}
	}
	return n
}

type v1IntegrationOptions struct {
	bytesSoftCap int64
	dialer       DialFunc
}

func newV1IntegrationClient(t *testing.T, recorder *v1IntegrationRecorder) *Client {
	t.Helper()
	return newV1IntegrationClientWithOptions(t, recorder, v1IntegrationOptions{})
}

func newV1IntegrationClientWithOptions(t *testing.T, recorder *v1IntegrationRecorder, opts v1IntegrationOptions) *Client {
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
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			if recorder != nil {
				recorder.add(destination)
			}
			_, _ = conn.Write([]byte("ok"))
			_, _ = io.Copy(io.Discard, conn)
		},
	})
	client, err := NewClient(ClientConfig{
		ServerAddr:               ln.Addr().String(),
		ServerName:               "test.example.com",
		PublicKey:                serverPub,
		ShortID:                  shortID,
		Fingerprint:              "chrome",
		DisableDefaultSecurity:   true,
		PoolVariant:              "v1",
		MinTransports:            1,
		MaxTransports:            1,
		BytesPerTransportSoftCap: opts.bytesSoftCap,
		Dialer:                   opts.dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.handshakeLimiter = nil
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// poolCounts returns (total, draining) of transports currently in the pool.
// Replaces the old poolClassCounts helper that distinguished bulk vs lite.
func poolCounts(p *connPool) (total, draining int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tr := range p.transports {
		if tr == nil {
			continue
		}
		total++
		if tr.isDraining() {
			draining++
		}
	}
	return total, draining
}

// findFirstAliveTransport is a v1 helper for tests that previously called
// findClassTransport(pool, TrafficBulk).
func findFirstAliveTransport(p *connPool) *h2Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tr := range p.transports {
		if tr != nil && !tr.isClosed() {
			return tr
		}
	}
	return nil
}

func eventuallyV2(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not satisfied within %s", timeout)
	}
}

func TestV1_SteadyStateOneTransport(t *testing.T) {
	client := newV1IntegrationClient(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < 50; i++ {
		conn, err := client.DialContext(ctx, "tcp", fmt.Sprintf("bulk-%d.example:443", i))
		if err != nil {
			t.Fatalf("bulk DialContext %d: %v", i, err)
		}
		_ = conn.Close()
		if total, _ := poolCounts(client.pool); total != 1 {
			t.Fatalf("after sequential dial %d transports = %d, want 1", i, total)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 5)
	conns := make(chan net.Conn, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := client.DialContext(ctx, "tcp", fmt.Sprintf("parallel-%d.example:443", i))
			if err != nil {
				errCh <- err
				return
			}
			conns <- conn
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("parallel DialContext: %v", err)
		}
	}
	if total, _ := poolCounts(client.pool); total != 1 {
		t.Fatalf("parallel transports = %d, want 1", total)
	}
	close(conns)
	for conn := range conns {
		_ = conn.Close()
	}
}

func TestV1_RotationOnDoesNotExceedTwoTransports(t *testing.T) {
	var handshakes atomic.Int32
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		handshakes.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	client := newV1IntegrationClientWithOptions(t, nil, v1IntegrationOptions{bytesSoftCap: 4096, dialer: dialer})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", "upload.example:443")
	if err != nil {
		t.Fatalf("initial DialContext: %v", err)
	}
	if _, err := conn.Write(make([]byte, 50*1024)); err != nil {
		t.Fatalf("upload write: %v", err)
	}
	old := findFirstAliveTransport(client.pool)
	if old == nil {
		t.Fatal("missing initial transport")
	}
	eventuallyV2(t, 500*time.Millisecond, old.isDraining)

	freshConn, err := client.DialContext(ctx, "tcp", "after-rotation.example:443")
	if err != nil {
		t.Fatalf("fresh DialContext after cap: %v", err)
	}
	_ = freshConn.Close()
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("transport creates = %d, want 2 (initial + one replacement)", got)
	}
	if total, _ := poolCounts(client.pool); total > 2 {
		t.Fatalf("pool transports = %d, want <=2 during V1 rotation overlap", total)
	}
	_ = conn.Close()
	eventuallyV2(t, time.Second, func() bool {
		client.pool.cleanup()
		total, _ := poolCounts(client.pool)
		return total <= 1
	})
}
