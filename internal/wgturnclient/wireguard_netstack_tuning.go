package wgturnclient

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	mobileTCPBufferMin     = 32 * 1024
	mobileTCPBufferDefault = 128 * 1024
	mobileTCPBufferMax     = 1 * 1024 * 1024
)

// tuneWireGuardNetstackTCPBuffers applies the same conservative mobile TCP
// buffer profile used by the H2 path. WireGuard's netstack.CreateNetTUN
// already enables SACK, but it leaves gVisor's TCP receive/send ranges at
// defaults; on the high-RTT VK TURN path that can cap single-flow throughput.
func tuneWireGuardNetstackTCPBuffers(tnet *netstack.Net) error {
	s, err := wireGuardNetstackStack(tnet)
	if err != nil {
		return err
	}
	return tuneMobileTCPBufferOptions(s)
}

func tuneMobileTCPBufferOptions(s *stack.Stack) error {
	if s == nil {
		return fmt.Errorf("nil gvisor stack")
	}
	recvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     mobileTCPBufferMin,
		Default: mobileTCPBufferDefault,
		Max:     mobileTCPBufferMax,
	}
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvOpt); tcpipErr != nil {
		return fmt.Errorf("set tcp receive buffer range: %v", tcpipErr)
	}
	sendOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     mobileTCPBufferMin,
		Default: mobileTCPBufferDefault,
		Max:     mobileTCPBufferMax,
	}
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendOpt); tcpipErr != nil {
		return fmt.Errorf("set tcp send buffer range: %v", tcpipErr)
	}
	// Keep this explicit next to the buffer tuning even though CreateNetTUN
	// currently enables SACK internally.
	sack := tcpip.TCPSACKEnabled(true)
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); tcpipErr != nil {
		return fmt.Errorf("enable tcp sack: %v", tcpipErr)
	}
	return nil
}

func wireGuardNetstackStack(tnet *netstack.Net) (*stack.Stack, error) {
	if tnet == nil {
		return nil, fmt.Errorf("nil wireguard netstack")
	}
	v := reflect.ValueOf(tnet)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, fmt.Errorf("unexpected wireguard netstack value %T", tnet)
	}
	elem := v.Elem()
	field := elem.FieldByName("stack")
	if !field.IsValid() || field.Kind() != reflect.Pointer || field.IsNil() {
		return nil, fmt.Errorf("wireguard netstack stack field unavailable")
	}
	return (*stack.Stack)(unsafe.Pointer(field.Pointer())), nil
}
