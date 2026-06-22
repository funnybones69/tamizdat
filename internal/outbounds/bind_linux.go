//go:build linux

package outbounds

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToDeviceControl returns a net.Dialer.Control hook that pins the
// outgoing socket to the named network interface via SO_BINDTODEVICE.
// The kernel honors this even when the iface has multiple addresses or
// when the routing table prefers a different one, which is exactly what
// the operator wants for split-IP boxes (force outbound through back IP)
// and for forwarding through amnezia/wireguard tunnel devices.
//
// SO_BINDTODEVICE requires CAP_NET_RAW. tamizdat-server runs as root in
// the deployed systemd unit, so this is fine; if you ever drop privs you
// must add the capability via systemd's AmbientCapabilities=CAP_NET_RAW.
//
// Errors during SetsockoptString surface back through net.Dialer.Control
// → DialContext as a returned error, so the caller sees a fail-fast dial
// rather than a silent fallback to the default route.
func bindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockerr error
		err := c.Control(func(fd uintptr) {
			sockerr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return sockerr
	}
}
