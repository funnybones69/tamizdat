package localtun

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/rulesdb"
	"github.com/funnybones69/tamizdat/node"
)

type testAccounting struct {
	mu       sync.Mutex
	up, down int64
}

func (a *testAccounting) Add(_, _ string, up, down int64) {
	a.mu.Lock()
	a.up += up
	a.down += down
	a.mu.Unlock()
}

func (a *testAccounting) AddOutbound(_ string, _, _ int64) {}

func (a *testAccounting) bytes() (int64, int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.up, a.down
}

func TestClientTCPThroughDirectOutbound(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	accounting := &testAccounting{}
	client := NewClient(obreg.NewRegistry(nil), &rulesdb.Store{}, accounting, "local-1", "router-lan", "", false)
	conn, err := client.DialRequest(context.Background(), &node.Request{
		Network: node.NetworkTCP, TargetHost: "127.0.0.1", TargetPort: ln.Addr().(*net.TCPAddr).Port,
		SourceIP: net.ParseIP("192.168.1.105"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("reply = %q, want pong", buf)
	}
	_ = conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		up, down := accounting.bytes()
		if up >= 4 && down >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("accounting up/down = %d/%d, want at least 4/4", up, down)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientUDPThroughDirectOutbound(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		n, peer, err := server.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = server.WriteTo(append([]byte("echo:"), buf[:n]...), peer)
		serverErr <- err
	}()

	accounting := &testAccounting{}
	client := NewClient(obreg.NewRegistry(nil), &rulesdb.Store{}, accounting, "local-1", "router-lan", "", false)
	port := server.LocalAddr().(*net.UDPAddr).Port
	pc, err := client.DialPacketRequest(context.Background(), &node.Request{
		Network: node.NetworkUDP, TargetHost: "127.0.0.1", TargetPort: port,
		SourceIP: net.ParseIP("192.168.1.105"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pc.WriteTo([]byte("dns"), server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "echo:dns" {
		t.Fatalf("reply = %q, want echo:dns", got)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	up, down := accounting.bytes()
	if up < 3 || down < 8 {
		t.Fatalf("accounting up/down = %d/%d, want at least 3/8", up, down)
	}
}
