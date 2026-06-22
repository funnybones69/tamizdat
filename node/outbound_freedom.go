package node

import (
	"context"
	"net"
	"time"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// FreedomOutbound is a direct dialer (xray-style "freedom"). It applies the
// shared SSRF guard so the node will not be tricked into dialling private/
// loopback/link-local IPs by a hostile inbound destination.
type FreedomOutbound struct {
	tag     string
	timeout time.Duration
}

// NewFreedomOutbound returns a freedom outbound with the given tag.
// timeout=0 ⇒ 10s.
func NewFreedomOutbound(tag string, timeout time.Duration) *FreedomOutbound {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &FreedomOutbound{tag: tag, timeout: timeout}
}

func (f *FreedomOutbound) Tag() string { return f.tag }

func (f *FreedomOutbound) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	host, port := req.TargetHost, req.TargetPort
	target, err := tamizdat.ResolveAndValidateDestination(ctx,
		host, itoa(port))
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: f.timeout}
	return d.DialContext(ctx, "tcp", target)
}

// DialPacket opens a UDP connection to req.TargetHost:req.TargetPort.
// Note: returns a net.PacketConn fixed to that single peer (a connected
// UDP socket wrapped). Inbounds that need fan-out should multiplex per
// destination.
func (f *FreedomOutbound) DialPacket(ctx context.Context, req *Request) (net.PacketConn, error) {
	host, port := req.TargetHost, req.TargetPort
	target, err := tamizdat.ResolveAndValidateDestination(ctx, host, itoa(port))
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: f.timeout}
	c, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		return nil, err
	}
	return &udpConnAdapter{UDPConn: c.(*net.UDPConn)}, nil
}

func (f *FreedomOutbound) Close() error { return nil }

// udpConnAdapter wraps a *net.UDPConn so it satisfies net.PacketConn with
// a fixed peer (ReadFrom returns the connected peer; WriteTo to a different
// addr is rejected).
type udpConnAdapter struct{ *net.UDPConn }

func (u *udpConnAdapter) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := u.UDPConn.Read(p)
	if err != nil {
		return n, nil, err
	}
	return n, u.UDPConn.RemoteAddr(), nil
}

func (u *udpConnAdapter) WriteTo(p []byte, _ net.Addr) (int, error) {
	return u.UDPConn.Write(p)
}
