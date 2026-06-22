package node

import (
	"context"
	"net"
)

// Inbound is the interface every inbound listener implements.
//
// Tag returns the configured tag (used as Request.InboundTag).
// Start begins accepting connections; it should return only on a fatal
// error (or after Close). The dispatcher is the seam Inbound calls into
// for each accepted client.
// Close stops the listener and releases resources.
type Inbound interface {
	Tag() string
	Start(ctx context.Context, dispatch InboundDispatcher) error
	Close() error
}

// InboundDispatcher is the subset of Dispatcher exposed to inbounds.
// (We define an interface so tests can supply a stub dispatcher.)
type InboundDispatcher interface {
	Dispatch(ctx context.Context, req *Request) (net.Conn, string, error)
	DispatchPacket(ctx context.Context, req *Request) (net.PacketConn, string, error)
}
