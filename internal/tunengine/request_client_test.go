package tunengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/funnybones69/tamizdat/node"
)

type capturingRequestClient struct {
	packetRequest  *node.Request
	legacyUDPCalls int
}

func (c *capturingRequestClient) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("legacy TCP path called")
}

func (c *capturingRequestClient) DialUDP(context.Context, string) (net.PacketConn, error) {
	c.legacyUDPCalls++
	return nil, errors.New("legacy UDP path called")
}

func (c *capturingRequestClient) DialRequest(context.Context, *node.Request) (net.Conn, error) {
	return nil, errors.New("unexpected TCP request")
}

func (c *capturingRequestClient) DialPacketRequest(_ context.Context, req *node.Request) (net.PacketConn, error) {
	cp := *req
	c.packetRequest = &cp
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func (c *capturingRequestClient) Close() error { return nil }

func TestDialUDPUsesRequestAwareClient(t *testing.T) {
	client := &capturingRequestClient{}
	d := &samizdatProxyDialer{client: client}
	metadata := &M.Metadata{
		Network: M.UDP,
		SrcIP:   netip.MustParseAddr("192.168.1.105"), SrcPort: 53000,
		DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 53,
	}
	pc, err := d.dialUDP(context.Background(), metadata, metadata.DestinationAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if client.legacyUDPCalls != 0 {
		t.Fatalf("legacy UDP calls = %d, want 0", client.legacyUDPCalls)
	}
	req := client.packetRequest
	if req == nil {
		t.Fatal("request-aware UDP method was not called")
	}
	if req.Network != node.NetworkUDP || req.TargetHost != "1.1.1.1" || req.TargetPort != 53 {
		t.Fatalf("request = %+v", req)
	}
	if got := req.SourceIP.String(); got != "192.168.1.105" {
		t.Fatalf("source IP = %q, want 192.168.1.105", got)
	}
	if req.InboundTag != "tun" {
		t.Fatalf("inbound = %q, want tun", req.InboundTag)
	}
}

func TestDialUDPDropQUICBeforeOutbound(t *testing.T) {
	client := &capturingRequestClient{}
	d := &samizdatProxyDialer{client: client, dropQUIC: true}
	metadata := &M.Metadata{
		Network: M.UDP,
		SrcIP:   netip.MustParseAddr("192.168.1.105"), SrcPort: 53000,
		DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 443,
	}
	pc, err := d.DialUDP(metadata)
	if pc != nil {
		pc.Close()
		t.Fatal("QUIC unexpectedly returned a packet connection")
	}
	if !errors.Is(err, errNonDNSUDP) {
		t.Fatalf("error = %v, want QUIC policy drop", err)
	}
	if client.packetRequest != nil || client.legacyUDPCalls != 0 {
		t.Fatal("QUIC drop reached an outbound client")
	}
}
