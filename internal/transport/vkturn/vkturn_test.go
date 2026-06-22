package vkturn

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

func TestDirectKCPEcho(t *testing.T) {
	ln, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	shortID := [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	srv, err := NewServer(ServerConfig{ShortID: shortID, Handler: func(ctx context.Context, conn net.Conn, destination string, shortID [ShortIDLen]byte) {
		if destination != "echo.test:443" {
			t.Errorf("destination = %q", destination)
		}
		_, _ = io.Copy(conn, conn)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	cli, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ShortID: shortID, Direct: true, Workers: 1, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	conn, err := cli.DialContext(ctx, "tcp", "echo.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", string(buf))
	}
}
