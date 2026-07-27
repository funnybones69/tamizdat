//go:build linux

package tamizdat

import (
	"net"

	"golang.org/x/sys/unix"
)

// setAcceptedConnDelayedAck enables TCP delayed ACK on server-side accepted
// client-facing TCP connections. TCP_QUICKACK=0 is the NDSS 2025 dMAP
// recommended mitigation: raise transport-layer RTT (TRTT) instead of adding
// userspace per-record jitter that inflates ARTT.
func setAcceptedConnDelayedAck(conn net.Conn) error {
	return setTCPQuickAck(conn, false)
}

// setTCPQuickAck sets TCP_QUICKACK on Linux TCP connections. quick=false
// preserves the delayed-ACK mitigation; quick=true is a generic toggle
// for callers that want low-latency behaviour on a specific connection.
func setTCPQuickAck(conn net.Conn, quick bool) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	value := 0
	if quick {
		value = 1
	}
	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, value)
	})
	if err != nil {
		return err
	}
	return setErr
}
