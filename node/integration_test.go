package node

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Spin up a tiny TCP echo server, point a SocksInbound + dispatcher with a
// freedom-like in-memory outbound at it, and verify a SOCKS5 client can
// reach the echo target through the routing layer.
//
// We can't use FreedomOutbound here because samizdat.ResolveAndValidateDestination
// rejects loopback. So we use a custom direct-dial outbound that skips SSRF
// checks for the test fixture (and only runs in tests).
type loopbackDialer struct{ tag string }

func (l *loopbackDialer) Tag() string { return l.tag }
func (l *loopbackDialer) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", req.Address())
}
func (l *loopbackDialer) Close() error { return nil }

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestSocksInboundRoutesThroughDispatcher(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	host, portStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(portStr)

	// Outbound that simply dials echoAddr (chosen because rule matches).
	loop := &loopbackDialer{tag: "loop"}
	black := NewBlackholeOutbound("block")

	rules, err := CompileRules([]*Rule{
		// route everything to the loopback dialer (catch-all)
		{Outbound: "loop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	disp, err := NewDispatcher(
		map[string]Outbound{"loop": loop, "block": black},
		rules, "", "loop", "AsIs",
	)
	if err != nil {
		t.Fatal(err)
	}

	// SOCKS inbound on a random port.
	inbound, err := NewSocksInbound("socks-in", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Manually start so we can grab the assigned port without ListenAndServe.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inbound.ln = ln
	socksAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Mimic the body of Start (which would re-Listen and overwrite ln).
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go inbound.handle(ctx, c, disp)
		}
	}()

	// Drive a SOCKS5 client that asks for echoAddr.
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: VER NMETHODS METHODS=NO_AUTH
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply: %v", resp)
	}

	// CONNECT to echo as domain (use 127.0.0.1 IPv4 to bypass DNS)
	hostBytes := []byte(host)
	addrLen := len(hostBytes)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(addrLen)}
	req = append(req, hostBytes...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(echoPort))
	req = append(req, pb...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("CONNECT reply: %v", rep)
	}

	// Echo round-trip.
	payload := []byte("samizdat-node ok\n")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestBlackholeOutboundReturnsError(t *testing.T) {
	black := NewBlackholeOutbound("block")
	_, err := black.Dial(context.Background(), &Request{TargetHost: "anywhere", TargetPort: 80})
	if !errors.Is(err, ErrBlackholed) {
		t.Errorf("expected ErrBlackholed, got %v", err)
	}
}

// Sanity: ensure outbound_socks.go encodeSocksAddr handles all 3 ATYPs.
func TestEncodeSocksAddr(t *testing.T) {
	cases := []struct {
		host string
		atyp byte
	}{
		{"1.2.3.4", 0x01},
		{"::1", 0x04},
		{"example.com", 0x03},
	}
	for _, tc := range cases {
		atyp, body, err := encodeSocksAddr(tc.host)
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		if atyp != tc.atyp {
			t.Errorf("%s: atyp=%d want %d", tc.host, atyp, tc.atyp)
		}
		if tc.atyp == 0x03 && !strings.Contains(string(body), strings.ToLower(tc.host)) {
			t.Errorf("%s: body did not contain hostname", tc.host)
		}
	}
	// Hostname > 255 must error.
	long := strings.Repeat("a", 256) + ".com"
	if _, _, err := encodeSocksAddr(long); err == nil {
		t.Errorf("long host must error")
	}
}

func init() {
	// Silence default logger noise in tests.
	_ = fmt.Sprint
}
