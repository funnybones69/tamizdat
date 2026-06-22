//go:build !linux

package outbounds

import "syscall"

// Non-Linux stub: SO_BINDTODEVICE is Linux-only, so on Windows/macOS we
// silently fall through to the OS default route. The panel still allows
// setting bind_iface (panels run on the same Linux server in practice),
// but non-Linux servers would simply ignore the value rather than fail
// to compile.
func bindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	_ = iface
	return nil
}
