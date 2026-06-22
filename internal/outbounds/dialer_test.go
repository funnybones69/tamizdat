package outbounds

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

const goodURI = "tamizdat://example.com:443/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&fp=chrome"

func TestDirectDialerDialsTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		got <- string(b)
		_, _ = c.Write([]byte("pong"))
	}()

	d := DirectDialer{Timeout: time.Second}
	c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("ping"))
	b := make([]byte, 4)
	_, _ = io.ReadFull(c, b)
	if string(b) != "pong" {
		t.Fatalf("reply = %q", b)
	}
	if msg := <-got; msg != "ping" {
		t.Fatalf("server got %q", msg)
	}
}

type fakeClient struct {
	closed atomic.Int32
	dials  atomic.Int32
}

type fakeRTTClient struct {
	fakeClient
}

type fakeRootRTTStats struct {
	P50Ms  int64
	Count  int
	LastMs int64
}

func (f *fakeRTTClient) RTTProbeSnapshot() fakeRootRTTStats {
	return fakeRootRTTStats{P50Ms: 321, Count: 7, LastMs: 456}
}

func (f *fakeClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.dials.Add(1)
	a, b := net.Pipe()
	go func() {
		<-ctx.Done()
		_ = b.Close()
	}()
	return a, nil
}

// DialUDP satisfies the outbounds.Client interface for UDP routing
// (added 2026-05-11). Tests don't exercise tunnelled UDP yet, so a
// nil/error stub is fine — registry tests pass through Direct/
// Blackhole DialPacket paths.
func (f *fakeClient) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, errors.New("fakeClient: DialUDP not implemented")
}

func (f *fakeClient) Close() error { f.closed.Add(1); return nil }

func TestTamizdatDialerParsesURIAndIsLazy(t *testing.T) {
	var factoryCalls atomic.Int32
	cli := &fakeClient{}
	d, err := NewTamizdatDialer(goodURI, func(cfg configurl.Config) (Client, error) {
		factoryCalls.Add(1)
		if cfg.ServerAddr != "example.com:443" {
			t.Fatalf("ServerAddr = %q", cfg.ServerAddr)
		}
		if cfg.ServerName != "ok.ru" {
			t.Fatalf("ServerName = %q", cfg.ServerName)
		}
		return cli, nil
	})
	if err != nil {
		t.Fatalf("NewTamizdatDialer: %v", err)
	}
	if factoryCalls.Load() != 0 {
		t.Fatalf("factory called before first dial")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = c.Close()
	if factoryCalls.Load() != 1 {
		t.Fatalf("factory calls = %d", factoryCalls.Load())
	}
	if cli.dials.Load() != 1 {
		t.Fatalf("client dials = %d", cli.dials.Load())
	}
}

func TestTamizdatDialerRejectsBadURI(t *testing.T) {
	if _, err := NewTamizdatDialer("vless://example", func(configurl.Config) (Client, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("bad scheme err = %v", err)
	}
	if _, err := NewTamizdatDialer("tamizdat://example.com/?sni=ok.ru&pubkey=aa&shortid=bb", func(configurl.Config) (Client, error) { return nil, nil }); err == nil {
		t.Fatalf("missing port/bad keys unexpectedly accepted")
	}
}

func TestTamizdatDialerAdaptsClientRTTProbeSnapshot(t *testing.T) {
	cli := &fakeRTTClient{}
	d, err := NewTamizdatDialer(goodURI, func(configurl.Config) (Client, error) { return cli, nil })
	if err != nil {
		t.Fatalf("NewTamizdatDialer: %v", err)
	}
	if st := d.RTTProbeSnapshot(); st.P50Ms != -1 || st.LastMs != -1 {
		t.Fatalf("RTT before lazy client exists = %+v, want absent", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	st := d.RTTProbeSnapshot()
	if st.P50Ms != 321 || st.LastMs != 456 || st.Count != 7 {
		t.Fatalf("RTT snapshot = %+v, want P50=321 Last=456 Count=7", st)
	}
}
