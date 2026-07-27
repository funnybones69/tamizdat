package node

import (
	"context"
	"errors"
	"net"
)

// Outbound is the interface every outbound dialer implements.
//
// Tag returns the outbound's configured tag (used in routing rules).
// Dial opens a TCP-style stream to req.TargetHost:req.TargetPort.
// Close releases any persistent resources (transport pools, etc.).
type Outbound interface {
	Tag() string
	Dial(ctx context.Context, req *Request) (net.Conn, error)
	Close() error
}

// UDPDialer is the optional interface for outbounds that can carry UDP.
// freedom and samizdat implement it; blackhole does not (drops both).
type UDPDialer interface {
	DialPacket(ctx context.Context, req *Request) (net.PacketConn, error)
}

// ErrUDPUnsupported is returned by Dispatcher.DispatchPacket when the chosen
// outbound does not support UDP.
var ErrUDPUnsupported = errors.New("outbound does not support UDP")

// ErrBlackholed is returned by the blackhole outbound on every Dial.
var ErrBlackholed = errors.New("blackholed")
