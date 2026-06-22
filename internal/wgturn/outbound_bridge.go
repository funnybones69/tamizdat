//go:build linux

package wgturn

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/internal/outbounds"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// OutboundResolver names whatever can hand us an outbounds.Dialer to route
// a single wgturn-decapsulated flow through. The full *outbounds.Registry
// satisfies this — but the wgturn package doesn't take a hard dep on the
// registry type so tests can pass a fake.
type OutboundResolver interface {
	Resolve(tag string) (outbounds.Dialer, string)
}

// createNetstackTUN builds a userspace WireGuard device whose TUN is
// our internal userTun (copy of wireguard-go's netstack.CreateNetTUN
// with public Stack() access). The returned device pipes plaintext IP
// packets out into the netstack — the bridge then ferries every
// TCP/UDP flow into the outbounds.Registry instead of the kernel
// routing table.
//
// No kernel TUN, no iptables. Canonical wireguard-go "userspace"
// pattern, used by Tailscale and wireguard-apple.
func createNetstackTUN(keys *wgKeys, wgPort int, serverIP string) (*device.Device, *userTun, error) {
	addr, err := netip.ParseAddr(serverIP)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server IP %q: %w", serverIP, err)
	}
	tunDev, err := createUserTUN([]netip.Addr{addr}, wgMTU)
	if err != nil {
		return nil, nil, fmt.Errorf("createUserTUN: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[wgturn-wg-netstack] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)
	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("device.Up: %w", err)
	}
	log.Printf("[wgturn] netstack WG device up on port %d, server IP %s", wgPort, serverIP)
	return dev, tunDev, nil
}

// ClientIdentityLookup maps a WireGuard source IP to the authenticated
// GETCONF identity that owns it.
type ClientIdentityLookup interface {
	IdentityForIP(ip string) (ClientIdentity, bool)
}

// OutboundBridge attaches TCP+UDP forwarders to a gvisor stack and
// ferries every accepted flow into an outbounds.Dialer.
//
// Concurrency: each accepted flow runs as its own goroutine; the bridge
// itself only owns the stack and the forwarders.
type OutboundBridge struct {
	stk      *stack.Stack
	resolver OutboundResolver
	tag      string
	router   FlowRouter
	identity ClientIdentityLookup
	account  Accounting
	tcpFwd   *tcp.Forwarder
	udpFwd   *udp.Forwarder

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	activeFlows atomic.Int64
	lastFlowLog atomic.Int64
	flowLogDrop atomic.Int64
	closeMu     sync.Mutex
	closed      bool
}

const (
	bridgeTCPRcvBuf    = 512 * 1024 // 512 KiB per stream window; avoids 1-2 Mbit/s BDP ceiling on high-RTT TURN paths
	bridgeUDPIdle      = 60 * time.Second
	bridgeFlowLogEvery = 5 * time.Second
)

func closeNetConn(c net.Conn) {
	_ = c.SetDeadline(time.Now())
	_ = c.Close()
}

func closePacketConn(c net.PacketConn) {
	_ = c.SetDeadline(time.Now())
	_ = c.Close()
}

func (b *OutboundBridge) logFlowOpen(network, dest, resolved string) {
	now := time.Now()
	nowNS := now.UnixNano()
	lastNS := b.lastFlowLog.Load()
	if lastNS != 0 && now.Sub(time.Unix(0, lastNS)) < bridgeFlowLogEvery {
		b.flowLogDrop.Add(1)
		return
	}
	if !b.lastFlowLog.CompareAndSwap(lastNS, nowNS) {
		b.flowLogDrop.Add(1)
		return
	}
	if suppressed := b.flowLogDrop.Swap(0); suppressed > 0 {
		log.Printf("[wgturn-bridge] %s %s via %s (suppressed %d flow-open logs)", network, dest, resolved, suppressed)
		return
	}
	log.Printf("[wgturn-bridge] %s %s via %s", network, dest, resolved)
}

// NewOutboundBridge attaches gvisor TCP/UDP forwarders to the netstack
// of the given userTun. Each accepted flow is dialed via resolver.Resolve(tag).
// FlowRouter may choose a per-flow tag; otherwise tag is the fixed fallback.
func NewOutboundBridge(tnet *userTun, resolver OutboundResolver, tag string, identity ClientIdentityLookup, router FlowRouter, account Accounting) *OutboundBridge {
	stk := tnet.Stack()
	ctx, cancel := context.WithCancel(context.Background())
	b := &OutboundBridge{
		stk:      stk,
		resolver: resolver,
		tag:      tag,
		identity: identity,
		router:   router,
		account:  account,
		ctx:      ctx,
		cancel:   cancel,
	}
	// gvisor's Forwarder API — we limit max in-flight requests aggressively
	// because each wgturn instance is for ONE user; even 256 simultaneous
	// streams are far more than a normal browser keeps open.
	b.tcpFwd = tcp.NewForwarder(stk, bridgeTCPRcvBuf, 256, b.handleTCP)
	b.udpFwd = udp.NewForwarder(stk, b.handleUDP)
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, b.tcpFwd.HandlePacket)
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, b.udpFwd.HandlePacket)
	return b
}

// Close cancels in-flight bridge flows and drops the registered handlers so a
// subsequent reattach can replace them cleanly. It waits briefly for active
// pumps to drain; misbehaving flows are reported but cannot block shutdown
// forever.
func (b *OutboundBridge) Close() {
	b.closeMu.Lock()
	b.closed = true
	b.closeMu.Unlock()

	if b.cancel != nil {
		b.cancel()
	}

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("[wgturn-bridge] Close: 5s timeout, %d flows leaked", b.activeFlows.Load())
	}

	// Reset to default no-op handlers.
	b.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, nil)
	b.stk.SetTransportProtocolHandler(udp.ProtocolNumber, nil)
}

func (b *OutboundBridge) isClosed() bool {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	return b.closed
}

func (b *OutboundBridge) handleTCP(req *tcp.ForwarderRequest) {
	if b.isClosed() {
		req.Complete(true)
		return
	}
	id := req.ID()
	dest := net.JoinHostPort(addrToString(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		log.Printf("[wgturn-bridge] tcp CreateEndpoint %s: %v", dest, terr)
		req.Complete(true)
		return
	}
	req.Complete(false)
	gconn := gonet.NewTCPConn(&wq, ep)

	sourceIP := addrToString(id.RemoteAddress)
	go b.pumpTCP(gconn, dest, sourceIP)
}

func (b *OutboundBridge) resolveFlow(network, sourceIP, dest string) (outbounds.Dialer, string, ClientIdentity, bool) {
	tag := b.tag
	var identity ClientIdentity
	if b.identity != nil && sourceIP != "" {
		if id, ok := b.identity.IdentityForIP(sourceIP); ok {
			identity = id
		}
	}
	if b.router != nil {
		host, portStr, err := net.SplitHostPort(dest)
		port := 0
		if err == nil {
			port, _ = strconv.Atoi(portStr)
		} else {
			host = dest
		}
		if pick := b.router(b.ctx, Flow{
			Network:  network,
			SourceIP: sourceIP,
			DestHost: host,
			DestPort: port,
			Identity: identity,
		}); pick != "" {
			tag = pick
		}
	}
	if tag == "block" {
		return nil, "block", identity, false
	}
	dialer, resolved := b.resolver.Resolve(tag)
	if dialer == nil {
		return nil, resolved, identity, false
	}
	return dialer, resolved, identity, true
}

func (b *OutboundBridge) accountFlow(outboundTag string, identity ClientIdentity, up, down int64) {
	if b == nil || b.account == nil || (up == 0 && down == 0) {
		return
	}
	if outboundTag != "" {
		b.account.AddOutbound(outboundTag, up, down)
	}
	if identity.UserID != "" {
		b.account.Add(identity.UserID, identity.SessionID, up, down)
	}
}

func (b *OutboundBridge) pumpTCP(gconn net.Conn, dest string, sourceIP string) {
	b.wg.Add(1)
	b.activeFlows.Add(1)
	defer closeNetConn(gconn)
	defer func() {
		b.activeFlows.Add(-1)
		b.wg.Done()
	}()

	dialer, resolved, identity, ok := b.resolveFlow("tcp", sourceIP, dest)
	if !ok {
		log.Printf("[wgturn-bridge] tcp %s blocked/unresolved via %s", dest, resolved)
		return
	}
	defer dialer.Close()
	var upBytes, downBytes int64
	defer func() { b.accountFlow(resolved, identity, upBytes, downBytes) }()

	baseCtx := b.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 15*time.Second)
	upConn, err := dialer.DialContext(ctx, "tcp", dest)
	cancel()
	if err != nil {
		log.Printf("[wgturn-bridge] tcp dial %s via %s: %v", dest, resolved, err)
		return
	}
	defer closeNetConn(upConn)
	b.logFlowOpen("tcp", dest, resolved)

	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-baseCtx.Done():
			closeNetConn(gconn)
			closeNetConn(upConn)
		case <-shutdownDone:
		}
	}()
	defer close(shutdownDone)

	// Two-way pipe. Closing either endpoint above unblocks both copies during
	// normal completion or bridge shutdown.
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upConn, gconn)
		upBytes = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(gconn, upConn)
		downBytes = n
		done <- struct{}{}
	}()
	<-done
	closeNetConn(gconn)
	closeNetConn(upConn)
	<-done
}

func (b *OutboundBridge) handleUDP(req *udp.ForwarderRequest) {
	if b.isClosed() {
		return
	}
	id := req.ID()
	dest := net.JoinHostPort(addrToString(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		log.Printf("[wgturn-bridge] udp CreateEndpoint %s: %v", dest, terr)
		return
	}
	gconn := gonet.NewUDPConn(&wq, ep)

	sourceIP := addrToString(id.RemoteAddress)
	go b.pumpUDP(gconn, dest, sourceIP)
}

func (b *OutboundBridge) pumpUDP(gconn net.PacketConn, dest string, sourceIP string) {
	b.wg.Add(1)
	b.activeFlows.Add(1)
	defer closePacketConn(gconn)
	defer func() {
		b.activeFlows.Add(-1)
		b.wg.Done()
	}()

	dialer, resolved, identity, ok := b.resolveFlow("udp", sourceIP, dest)
	if !ok {
		log.Printf("[wgturn-bridge] udp %s blocked/unresolved via %s", dest, resolved)
		return
	}
	defer dialer.Close()
	var upBytes, downBytes int64
	defer func() { b.accountFlow(resolved, identity, upBytes, downBytes) }()

	baseCtx := b.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, 15*time.Second)
	upConn, err := dialer.DialPacket(ctx, dest)
	cancel()
	if err != nil {
		log.Printf("[wgturn-bridge] udp dial %s via %s: %v", dest, resolved, err)
		return
	}
	defer closePacketConn(upConn)
	b.logFlowOpen("udp", dest, resolved)

	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-baseCtx.Done():
			closePacketConn(gconn)
			closePacketConn(upConn)
		case <-shutdownDone:
		}
	}()
	defer close(shutdownDone)

	// Per-flow idle timeout: any side silent for >bridgeUDPIdle closes.
	deadline := func() {
		_ = gconn.SetReadDeadline(time.Now().Add(bridgeUDPIdle))
		_ = upConn.SetReadDeadline(time.Now().Add(bridgeUDPIdle))
	}
	deadline()

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := gconn.ReadFrom(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, werr := upConn.WriteTo(buf[:n], targetAddr(dest)); werr != nil {
				done <- struct{}{}
				return
			}
			upBytes += int64(n)
			deadline()
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := upConn.ReadFrom(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, werr := gconn.WriteTo(buf[:n], nil); werr != nil {
				done <- struct{}{}
				return
			}
			downBytes += int64(n)
			deadline()
		}
	}()
	<-done
	closePacketConn(gconn)
	closePacketConn(upConn)
	<-done
}

// targetAddr produces a *net.UDPAddr from "host:port" — outbounds.Dialer
// implementations expect any net.Addr whose String() matches the dial
// target; *net.UDPAddr satisfies that. Hostname-based targets (where
// host is not an IP) are punted to net.ResolveUDPAddr.
func targetAddr(hostPort string) net.Addr {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return &resolvedHostAddr{s: hostPort}
	}
	p, _ := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if ip != nil {
		return &net.UDPAddr{IP: ip, Port: p}
	}
	if addr, err := net.ResolveUDPAddr("udp", hostPort); err == nil {
		return addr
	}
	return &resolvedHostAddr{s: hostPort}
}

// resolvedHostAddr is a fallback net.Addr when the destination is a
// hostname we couldn't resolve. The outbounds.Dialer's WriteTo must
// already have the destination baked in (DialPacket connects to a
// single target), so this is mostly cosmetic.
type resolvedHostAddr struct{ s string }

func (a *resolvedHostAddr) Network() string { return "udp" }
func (a *resolvedHostAddr) String() string  { return a.s }

// addrToString converts a tcpip.Address to a printable IP literal.
// IPv4 and IPv6 are both handled.
func addrToString(a tcpip.Address) string {
	b := a.AsSlice()
	if len(b) == 0 {
		return ""
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
