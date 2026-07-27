package wgturnclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSelectTurnEndpointFiltersV2ByRequestedUDPTransport(t *testing.T) {
	creds := &Credentials{
		TurnURLs: []string{"udp.example:3478", "tcp.example:3478"},
		TurnServers: []TurnServer{
			{Host: "udp.example", Port: 3478, Scheme: "turn", Transport: "udp"},
			{Host: "tcp.example", Port: 3478, Scheme: "turn", Transport: "tcp"},
		},
	}

	endpoint, err := selectTurnEndpoint(creds, 1, true)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "udp.example:3478" {
		t.Fatalf("selected addr = %q, want UDP endpoint", endpoint.Addr)
	}
	if !endpoint.UseUDP || endpoint.UseTLS || endpoint.Proto != "UDP" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want UDP/no-TLS", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestSelectTurnEndpointUsesTLSForTURNSOverTCP(t *testing.T) {
	creds := &Credentials{
		TurnURLs: []string{"secure.example:5349"},
		TurnServers: []TurnServer{
			{Host: "secure.example", Port: 5349, Scheme: "turns", Transport: "tcp"},
		},
	}

	endpoint, err := selectTurnEndpoint(creds, 0, false)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "secure.example:5349" {
		t.Fatalf("selected addr = %q", endpoint.Addr)
	}
	if endpoint.UseUDP || !endpoint.UseTLS || endpoint.Proto != "TLS" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want TLS over TCP", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestSelectTurnEndpointFallsBackToLegacyURLsWhenV2Absent(t *testing.T) {
	creds := &Credentials{TurnURLs: []string{"legacy-a.example:3478", "legacy-b.example:3478"}}

	endpoint, err := selectTurnEndpoint(creds, 1, false)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "legacy-b.example:3478" {
		t.Fatalf("selected addr = %q, want legacy-b.example:3478", endpoint.Addr)
	}
	if endpoint.UseUDP || endpoint.UseTLS || endpoint.Proto != "TCP" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want TCP/no-TLS", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestRunDTLSHandshakeWithThrottleReleasesSlotOnSuccessAndError(t *testing.T) {
	resetHandshakeSemForTest(t)

	if err := runDTLSHandshakeWithThrottle(context.Background(), 0, fakeDTLSHandshaker{}); err != nil {
		t.Fatalf("runDTLSHandshakeWithThrottle success: %v", err)
	}
	if got := len(handshakeSem); got != 0 {
		t.Fatalf("handshake semaphore leaked after success: len=%d", got)
	}

	boom := errors.New("boom")
	err := runDTLSHandshakeWithThrottle(context.Background(), 1, fakeDTLSHandshaker{err: boom})
	if err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("runDTLSHandshakeWithThrottle error = %v, want boom", err)
	}
	if got := len(handshakeSem); got != 0 {
		t.Fatalf("handshake semaphore leaked after error: len=%d", got)
	}
}

func TestRunDTLSHandshakeWithThrottleTimesOutWhenFull(t *testing.T) {
	resetHandshakeSemForTest(t)
	for i := 0; i < handshakeSemCap; i++ {
		handshakeSem <- struct{}{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := runDTLSHandshakeWithThrottle(ctx, 2, fakeDTLSHandshaker{})
	if err == nil || !strings.Contains(err.Error(), "DTLS handshake throttle") {
		t.Fatalf("runDTLSHandshakeWithThrottle full semaphore error = %v", err)
	}
}

type fakeDTLSHandshaker struct {
	err error
}

func (f fakeDTLSHandshaker) HandshakeContext(context.Context) error {
	return f.err
}

func resetHandshakeSemForTest(t *testing.T) {
	t.Helper()
	old := handshakeSem
	handshakeSem = make(chan struct{}, handshakeSemCap)
	t.Cleanup(func() { handshakeSem = old })
}
