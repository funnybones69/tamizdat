//go:build linux

package main

import (
	"context"
	"net"
	"syscall"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// makeSOMarkDialer returns a tamizdat.DialFunc whose net.Dialer.Control sets
// SO_MARK on the outbound socket. The router gate installs an fwmark bypass so
// the client transport itself never recurses through its own TUN default route.
func makeSOMarkDialer(mark int) tamizdat.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var soerr error
				if cerr := c.Control(func(fd uintptr) {
					soerr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
				}); cerr != nil {
					return cerr
				}
				return soerr
			},
		}
		return d.DialContext(ctx, network, address)
	}
}
