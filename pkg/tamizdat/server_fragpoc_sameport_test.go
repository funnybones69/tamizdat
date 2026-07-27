package tamizdat

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/transport/fragpoc"
)

func TestFragPoCSamePortEcho(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	server, err := NewServer(ServerConfig{
		PrivateKey:      priv,
		MasterShortID:   shortID,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		FragPoCSamePort: true,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			if destination != "example.com:80" {
				t.Errorf("destination = %q, want example.com:80", destination)
			}
			_, _ = io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		_ = server.Serve(ln)
	}()

	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure=%t", secure), func(t *testing.T) {
			client, err := fragpoc.NewClient(fragpoc.ClientConfig{
				ServerAddr:       ln.Addr().String(),
				ShortID:          shortID,
				Secure:           secure,
				Workers:          4,
				OperationTimeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("fragpoc.NewClient: %v", err)
			}
			defer client.Close()
			conn, err := client.DialContext(context.Background(), "tcp", "example.com:80")
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("ReadFull: %v", err)
			}
			if string(buf) != "hello" {
				t.Fatalf("echo = %q, want hello", buf)
			}
		})
	}
}

func TestFragPoCSamePortReplaysNonFragFirstByte(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0x16, 0x03})
	}()

	nextConn, handled := (&Server{}).demuxFragPoCSamePort(serverConn)
	if handled {
		t.Fatal("non-fragpoc first byte was handled as fragpoc")
	}
	var got [2]byte
	if _, err := io.ReadFull(nextConn, got[:]); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if got != [2]byte{0x16, 0x03} {
		t.Fatalf("replayed bytes = %x, want 1603", got)
	}
}
