package tamizdat

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
)

const testTamizdatOutboundURI = "tamizdat://example.com:443/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&fp=chrome"

type eofTestConn struct {
	closed atomic.Int32
}

func (c *eofTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *eofTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *eofTestConn) Close() error                     { c.closed.Add(1); return nil }
func (c *eofTestConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *eofTestConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *eofTestConn) SetDeadline(time.Time) error      { return nil }
func (c *eofTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eofTestConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

type recordingOutboundClient struct {
	mu      sync.Mutex
	targets []string
	closed  atomic.Int32
}

func (c *recordingOutboundClient) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	c.mu.Lock()
	c.targets = append(c.targets, network+" "+target)
	c.mu.Unlock()
	return &eofTestConn{}, nil
}

func (c *recordingOutboundClient) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	// Tests don't exercise UDP-over-CONNECT through a tamizdat outbound
	// (would need a full UDP framing harness). Returning an error is
	// fine — the routing dispatch never picks this client for UDP in
	// the current tests.
	return nil, fmt.Errorf("recordingOutboundClient: DialUDP not implemented")
}

func (c *recordingOutboundClient) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *recordingOutboundClient) snapshotTargets() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.targets...)
}

type stubIPResolver struct {
	ips   []net.IPAddr
	err   error
	calls atomic.Int32
}

func (r *stubIPResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	return append([]net.IPAddr(nil), r.ips...), nil
}

func setTestDestinationResolver(t *testing.T, resolver ipResolver) {
	t.Helper()
	destinationResolverMu.Lock()
	old := destinationResolver
	destinationResolver = resolver
	destinationResolverMu.Unlock()
	t.Cleanup(func() {
		destinationResolverMu.Lock()
		destinationResolver = old
		destinationResolverMu.Unlock()
	})
}

func newServerWithFakeTamizdatDefault(t *testing.T, client *recordingOutboundClient) (*Server, *sql.DB) {
	t.Helper()
	db, err := obreg.OpenSQLite(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := obreg.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`, "via", "tamizdat", testTamizdatOutboundURI, "test", now, now); err != nil {
		t.Fatalf("insert outbound: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES('default_outbound_tag', 'via') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatalf("set default outbound: %v", err)
	}
	registry := obreg.NewRegistry(func(configurl.Config) (obreg.Client, error) { return client, nil })
	if err := registry.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	t.Cleanup(func() {
		_ = registry.Close()
		_ = db.Close()
	})
	return &Server{outboundRegistry: registry}, db
}

func TestServerOutboundDispatchSSRFRejected(t *testing.T) {
	serverPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	var legacyHandlerCalls atomic.Int32
	defaultDirectServer, err := NewServer(ServerConfig{
		PrivateKey:    serverPriv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		ServerDBPath:  filepath.Join(t.TempDir(), "server.db"),
		Handler: func(context.Context, net.Conn, string) {
			legacyHandlerCalls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer defaultDirectServer.Close()

	rejectedBefore := ssrfRejectedTCP.Value()
	defaultDirectConn := &eofTestConn{}
	defaultDirectServer.handleTCPConnect(context.Background(), defaultDirectConn, "127.0.0.1:22", authIdentity{PoolIndex: -1})
	if legacyHandlerCalls.Load() != 0 {
		t.Fatalf("registry-enabled server unexpectedly used legacy handler")
	}
	if got := ssrfRejectedTCP.Value(); got != rejectedBefore+1 {
		t.Fatalf("default direct CONNECT did not record SSRF rejection: before=%d after=%d", rejectedBefore, got)
	}
	if got := defaultDirectConn.closed.Load(); got != 1 {
		t.Fatalf("default direct rejected CONNECT close count = %d, want 1", got)
	}

	client := &recordingOutboundClient{}
	server, _ := newServerWithFakeTamizdatDefault(t, client)

	unsafe := []string{"127.0.0.1:22", "169.254.169.254:80", "10.0.0.1:443"}
	for _, dst := range unsafe {
		beforeTargets := len(client.snapshotTargets())
		beforeRejected := ssrfRejectedTCP.Value()
		conn := &eofTestConn{}
		server.handleTCPConnect(context.Background(), conn, dst, authIdentity{PoolIndex: -1})
		if got := len(client.snapshotTargets()); got != beforeTargets {
			t.Fatalf("unsafe CONNECT %s reached outbound dialer: before=%d after=%d targets=%v", dst, beforeTargets, got, client.snapshotTargets())
		}
		if got := ssrfRejectedTCP.Value(); got != beforeRejected+1 {
			t.Fatalf("unsafe CONNECT %s did not increment SSRF rejection counter: before=%d after=%d", dst, beforeRejected, got)
		}
		if got := conn.closed.Load(); got != 1 {
			t.Fatalf("unsafe CONNECT %s close count = %d, want 1", dst, got)
		}
	}

	server.handleTCPConnect(context.Background(), &eofTestConn{}, "1.1.1.1:443", authIdentity{PoolIndex: -1})
	targets := client.snapshotTargets()
	if len(targets) != 1 || targets[0] != "tcp 1.1.1.1:443" {
		t.Fatalf("safe CONNECT targets = %v, want [tcp 1.1.1.1:443]", targets)
	}
}

func TestServerOutboundDispatch_HostnameRebinding(t *testing.T) {
	client := &recordingOutboundClient{}
	server, _ := newServerWithFakeTamizdatDefault(t, client)
	resolver := &stubIPResolver{ips: []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}}
	setTestDestinationResolver(t, resolver)

	rejectedBefore := ssrfRejectedTCP.Value()
	conn := &eofTestConn{}
	server.handleTCPConnect(context.Background(), conn, "public-looking.example:443", authIdentity{PoolIndex: -1})

	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want 1", got)
	}
	if got := len(client.snapshotTargets()); got != 0 {
		t.Fatalf("hostname rebinding CONNECT reached outbound dialer: targets=%v", client.snapshotTargets())
	}
	if got := ssrfRejectedTCP.Value(); got != rejectedBefore+1 {
		t.Fatalf("hostname rebinding CONNECT did not increment SSRF rejection counter: before=%d after=%d", rejectedBefore, got)
	}
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("hostname rebinding CONNECT close count = %d, want 1", got)
	}
}

type taggedTestEndpoint struct{ tag string }

func (e taggedTestEndpoint) OutboundTag() string { return e.tag }

func TestEffectiveOutboundTagPrefersSelectedEndpointTag(t *testing.T) {
	if got := effectiveOutboundTag("bal", taggedTestEndpoint{tag: "member-a"}); got != "member-a" {
		t.Fatalf("effectiveOutboundTag = %q, want member-a", got)
	}
	if got := effectiveOutboundTag("bal", taggedTestEndpoint{tag: "   "}); got != "bal" {
		t.Fatalf("blank selected tag fallback = %q, want bal", got)
	}
	if got := effectiveOutboundTag("bal", nil); got != "bal" {
		t.Fatalf("nil endpoint fallback = %q, want bal", got)
	}
}
