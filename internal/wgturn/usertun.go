//go:build linux

package wgturn

// userTun is a userspace TUN device backed by a gvisor netstack. It is
// a near-verbatim copy of golang.zx2c4.com/wireguard/tun/netstack's
// netTun, with two changes:
//
//   1. The internal *stack.Stack is exposed via Stack() so callers can
//      attach their own TCP/UDP forwarders. The upstream netstack.Net
//      keeps Stack() private and is only meant for Dial() use.
//   2. DNS-resolving Dial wrappers are dropped — wgturn's OutboundBridge
//      dials via outbounds.Dialer, which carries its own resolution.
//
// Keeping the copy short and reading like the original makes it easy to
// re-sync with upstream when wireguard-go publishes changes.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// userTun implements golang.zx2c4.com/wireguard/tun.Device and is
// addressable from gvisor netstack via Stack().
type userTun struct {
	stk            *stack.Stack
	ep             *channel.Endpoint
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	hasV4, hasV6   bool
	notifyHandle   *channel.NotificationHandle

	closeOnce   sync.Once
	closeMu     sync.RWMutex
	closeNotify chan struct{}
}

// createUserTUN mirrors netstack.CreateNetTUN. Returns the wireguard
// tun.Device plus the userTun so the bridge can call .Stack().
func createUserTUN(localAddresses []netip.Addr, mtu int) (*userTun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	}
	dev := &userTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stk:            stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
		closeNotify:    make(chan struct{}),
	}
	sack := tcpip.TCPSACKEnabled(true)
	if errStack := dev.stk.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); errStack != nil {
		return nil, fmt.Errorf("set SACK: %v", errStack)
	}
	dev.notifyHandle = dev.ep.AddNotify(dev)
	if errStack := dev.stk.CreateNIC(1, dev.ep); errStack != nil {
		return nil, fmt.Errorf("CreateNIC: %v", errStack)
	}
	// The wgturn bridge is a router: clients send packets whose destination is
	// an arbitrary Internet IP, not the server's own WireGuard address. gVisor
	// drops those routed packets unless the NIC is allowed to spoof source
	// addresses and receive packets for non-local destinations. This mirrors
	// tun2socks/sing-tun setups and is what lets TCP/UDP forwarders see flows
	// such as 10.66.66.2 -> 93.184.216.34:443.
	if errStack := dev.stk.SetSpoofing(1, true); errStack != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", errStack)
	}
	if errStack := dev.stk.SetPromiscuousMode(1, true); errStack != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", errStack)
	}
	for _, ip := range localAddresses {
		var proto tcpip.NetworkProtocolNumber
		switch {
		case ip.Is4():
			proto = ipv4.ProtocolNumber
			dev.hasV4 = true
		case ip.Is6():
			proto = ipv6.ProtocolNumber
			dev.hasV6 = true
		}
		pa := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if errStack := dev.stk.AddProtocolAddress(1, pa, stack.AddressProperties{}); errStack != nil {
			return nil, fmt.Errorf("AddProtocolAddress %v: %v", ip, errStack)
		}
	}
	if dev.hasV4 {
		dev.stk.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stk.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	dev.events <- tun.EventUp
	return dev, nil
}

// Stack exposes the gvisor stack so callers can attach TCP/UDP forwarders.
func (t *userTun) Stack() *stack.Stack { return t.stk }

// --- tun.Device implementation (copied verbatim from netstack/tun.go). ---

func (t *userTun) Name() (string, error)    { return "usertun", nil }
func (t *userTun) File() *os.File           { return nil }
func (t *userTun) Events() <-chan tun.Event { return t.events }
func (t *userTun) BatchSize() int           { return 1 }
func (t *userTun) MTU() (int, error)        { return t.mtu, nil }

func (t *userTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *userTun) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		switch packet[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, errInvalidIPVersion
		}
	}
	return len(buf), nil
}

func (t *userTun) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()

	t.closeMu.RLock()
	ch := t.incomingPacket
	closing := t.closeNotify
	if ch == nil {
		t.closeMu.RUnlock()
		return
	}
	if closing == nil {
		ch <- view
		t.closeMu.RUnlock()
		return
	}
	select {
	case ch <- view:
	case <-closing:
	}
	t.closeMu.RUnlock()
}

func (t *userTun) Close() error {
	t.closeOnce.Do(func() {
		// Remove notify FIRST so no new WriteNotify calls are scheduled while
		// shutdown closes the channels below.
		if t.notifyHandle != nil {
			t.ep.RemoveNotify(t.notifyHandle)
			t.notifyHandle = nil
		}
		// Unblock a WriteNotify that was already waiting to hand a packet to
		// incomingPacket; closeMu then waits for it to return before closing the
		// channel, preventing send-on-closed-channel panics.
		if t.closeNotify != nil {
			close(t.closeNotify)
		}

		t.closeMu.Lock()
		defer t.closeMu.Unlock()

		t.stk.RemoveNIC(1)
		if t.events != nil {
			close(t.events)
			t.events = nil
		}
		t.ep.Close()
		if t.incomingPacket != nil {
			close(t.incomingPacket)
			t.incomingPacket = nil
		}
		t.closeNotify = nil
		// NOTE: stk.Destroy() was here briefly (PR #3) but is suspected
		// of being the cause of the slow-shutdown
		// issue during integration testing. gvisor's Destroy can take many
		// seconds and run heavy global cleanup that interferes with
		// other goroutines on the same runtime. Leaking the stack on
		// shutdown is annoying but not fatal (whole process exits a
		// moment later under systemd). Re-enable only after a guarded
		// reproduction in a sandbox.
		// t.stk.Destroy()
	})
	return nil
}

var errInvalidIPVersion = errors.New("invalid IP version")

// ensure these symbols are referenced so go vet doesn't complain about
// unused imports if a future edit drops the only users.
var (
	_ = context.Background
	_ = io.EOF
)
