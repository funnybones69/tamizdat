package sniff

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSClientHelloRealChrome(t *testing.T) {
	// Synthetic Chrome ClientHello — capture from a real TLS handshake to
	// example.com via openssl s_client -connect example.com:443 -servername
	// example.com 2>&1 | grep 16030 ... captured then hexified. Trimmed
	// version that retains record header + ClientHello + SNI extension.
	// We construct it programmatically to keep the test stable across Go
	// crypto/tls versions: stdlib's tls.Client writes a ClientHello to a
	// pipe and we extract bytes.
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}).Handshake()
	}()
	// Read what the client sent (ClientHello bytes).
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, MaxPeekBytes)
	n, _ := srv.Read(buf)
	if n == 0 {
		t.Fatal("empty ClientHello")
	}
	host, ok := TLSClientHello(buf[:n])
	if !ok {
		t.Fatalf("TLSClientHello returned !ok, bytes=%s", hex.EncodeToString(buf[:n]))
	}
	if host != "example.com" {
		t.Fatalf("host=%q want example.com", host)
	}
}

func TestTLSClientHelloLowercase(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: "API.GitHub.com", InsecureSkipVerify: true}).Handshake()
	}()
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, MaxPeekBytes)
	n, _ := srv.Read(buf)
	host, ok := TLSClientHello(buf[:n])
	if !ok || host != "api.github.com" {
		t.Fatalf("got host=%q ok=%v, want api.github.com true", host, ok)
	}
}

func TestTLSClientHelloRejectsNonTLS(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("GET / HTTP/1.1\r\n"),
		{0x00, 0x00, 0x00, 0x00, 0x00},
		{0x16, 0x99, 0x99, 0x00, 0x10}, // wrong version
	}
	for i, data := range cases {
		if _, ok := TLSClientHello(data); ok {
			t.Fatalf("case %d: accepted bogus data", i)
		}
	}
}

func TestHTTPHost(t *testing.T) {
	req := "GET /foo HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: x\r\n\r\n"
	host, ok := HTTPHost([]byte(req))
	if !ok || host != "example.com" {
		t.Fatalf("host=%q ok=%v, want example.com true", host, ok)
	}
}

func TestHTTPHostNoHostHeader(t *testing.T) {
	req := "GET /foo HTTP/1.1\r\nUser-Agent: x\r\n\r\n"
	if _, ok := HTTPHost([]byte(req)); ok {
		t.Fatal("returned ok with no Host header")
	}
}

func TestHTTPHostRejectsTLS(t *testing.T) {
	// TLS ClientHello first byte 0x16 — must not be misidentified as HTTP.
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x10}
	if _, ok := HTTPHost(data); ok {
		t.Fatal("HTTPHost matched TLS bytes")
	}
}

func TestPeekConnRoundTripsBytes(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	payload := []byte("GET / HTTP/1.1\r\nHost: peek-test.example\r\n\r\n")
	go func() {
		_, _ = cli.Write(payload)
		// Keep conn open so server can do additional reads after sniff.
	}()
	host, bc, err := PeekConn(srv, []Sniffer{TLSClientHello, HTTPHost})
	if err != nil {
		t.Logf("PeekConn err: %v (acceptable for short stream)", err)
	}
	if host != "peek-test.example" {
		t.Fatalf("host=%q want peek-test.example", host)
	}
	// BufferedConn must replay the peeked bytes verbatim.
	got := make([]byte, len(payload))
	if _, err := bytes.NewBuffer(nil).ReadFrom(strings.NewReader("")); err != nil {
		_ = err
	}
	if _, err := io_ReadFull(bc, got); err != nil {
		t.Fatalf("ReadFull from BufferedConn: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("BufferedConn replay mismatch:\ngot:  %q\nwant: %q", got, payload)
	}
}

// io_ReadFull wraps an io.Reader to read exactly len(p) bytes (or err).
// Stdlib io.ReadFull would do but the test file is small enough to inline.
func io_ReadFull(c interface{ Read([]byte) (int, error) }, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := c.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
