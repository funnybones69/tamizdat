//go:build linux

package wgturn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/outbounds"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type staticResolver struct {
	dialer outbounds.Dialer
}

func (r staticResolver) Resolve(tag string) (outbounds.Dialer, string) {
	return r.dialer, "test-outbound"
}

type tagRecordingResolver struct {
	dialer outbounds.Dialer
	tagCh  chan string
}

func (r tagRecordingResolver) Resolve(tag string) (outbounds.Dialer, string) {
	select {
	case r.tagCh <- tag:
	default:
	}
	return r.dialer, tag
}

type testIdentityLookup struct {
	byIP map[string]ClientIdentity
}

func (l testIdentityLookup) IdentityForIP(ip string) (ClientIdentity, bool) {
	id, ok := l.byIP[ip]
	return id, ok
}

type routerCapture struct {
	ch chan Flow
}

func (r routerCapture) route(ctx context.Context, flow Flow) string {
	select {
	case r.ch <- flow:
	case <-ctx.Done():
	}
	return "routed-tag"
}

type recordingAccounting struct {
	userID    string
	sessionID string
	userUp    int64
	userDown  int64
	outTag    string
	outUp     int64
	outDown   int64
}

func (a *recordingAccounting) Add(userID, sessionID string, up, down int64) {
	a.userID = userID
	a.sessionID = sessionID
	a.userUp += up
	a.userDown += down
}

func (a *recordingAccounting) AddOutbound(tag string, up, down int64) {
	a.outTag = tag
	a.outUp += up
	a.outDown += down
}

type recordingDialer struct {
	dialCh   chan string
	packetCh chan string
}

var errRecordedDial = errors.New("recorded dial")

func (d *recordingDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	select {
	case d.dialCh <- target:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, errRecordedDial
}

func (d *recordingDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	if d.packetCh != nil {
		select {
		case d.packetCh <- target:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errRecordedDial
}

func (d *recordingDialer) Close() error { return nil }

func TestUserTunForwardsRoutedTCPToOutboundBridge(t *testing.T) {
	d := &recordingDialer{dialCh: make(chan string, 1)}
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.66.66.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}
	defer tunDev.Close()

	b := NewOutboundBridge(tunDev, staticResolver{dialer: d}, "fallback-test", nil, nil, nil)
	defer b.Close()

	clientIP := netip.MustParseAddr("10.66.66.2")
	destIP := netip.MustParseAddr("93.184.216.34")
	const (
		clientPort = uint16(49152)
		destPort   = uint16(80)
		clientSeq  = uint32(1000)
	)

	syn := testIPv4TCPPacket(t, clientIP, destIP, clientPort, destPort, clientSeq, 0, header.TCPFlagSyn)
	if n, err := tunDev.Write([][]byte{syn}, 0); err != nil || n != 1 {
		t.Fatalf("Write SYN into userTun = %d, %v; want 1, nil", n, err)
	}

	synAck := readOneIPv4TCPPacket(t, tunDev)
	serverTCP := header.TCP(synAck[header.IPv4MinimumSize:])
	if !serverTCP.Flags().Contains(header.TCPFlagSyn) || !serverTCP.Flags().Contains(header.TCPFlagAck) {
		t.Fatalf("first response flags = %s, want SYN|ACK", serverTCP.Flags())
	}

	ack := testIPv4TCPPacket(
		t,
		clientIP,
		destIP,
		clientPort,
		destPort,
		clientSeq+1,
		serverTCP.SequenceNumber()+1,
		header.TCPFlagAck,
	)
	if n, err := tunDev.Write([][]byte{ack}, 0); err != nil || n != 1 {
		t.Fatalf("Write ACK into userTun = %d, %v; want 1, nil", n, err)
	}

	select {
	case target := <-d.dialCh:
		if target != "93.184.216.34:80" {
			t.Fatalf("bridge dialed %q, want 93.184.216.34:80", target)
		}
		rst := testIPv4TCPPacket(
			t,
			clientIP,
			destIP,
			clientPort,
			destPort,
			clientSeq+1,
			serverTCP.SequenceNumber()+1,
			header.TCPFlagRst|header.TCPFlagAck,
		)
		if n, err := tunDev.Write([][]byte{rst}, 0); err != nil || n != 1 {
			t.Fatalf("Write RST into userTun = %d, %v; want 1, nil", n, err)
		}
	case <-time.After(2 * time.Second):
		stats := tunDev.stk.Stats()
		t.Fatalf("completed routed TCP handshake was not delivered to outbound bridge (ip rx=%d valid=%d invalid_dst=%d malformed=%d delivered=%d; tcp valid=%d invalid=%d)",
			stats.IP.PacketsReceived.Value(),
			stats.IP.ValidPacketsReceived.Value(),
			stats.IP.InvalidDestinationAddressesReceived.Value(),
			stats.IP.MalformedPacketsReceived.Value(),
			stats.IP.PacketsDelivered.Value(),
			stats.TCP.ValidSegmentsReceived.Value(),
			stats.TCP.InvalidSegmentsReceived.Value(),
		)
	}
}

func TestOutboundBridgeUsesFlowRouterAndClientIdentity(t *testing.T) {
	d := &recordingDialer{dialCh: make(chan string, 1)}
	tagCh := make(chan string, 1)
	flowCh := make(chan Flow, 1)
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.66.66.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}
	defer tunDev.Close()

	identity := testIdentityLookup{byIP: map[string]ClientIdentity{
		"10.66.66.2": {ShortIDHex: "0011223344556677", UserID: "u1", UserName: "alice", SessionID: "s1"},
	}}
	capture := routerCapture{ch: flowCh}
	b := NewOutboundBridge(tunDev, tagRecordingResolver{dialer: d, tagCh: tagCh}, "fallback-tag", identity, capture.route, nil)
	defer b.Close()

	clientIP := netip.MustParseAddr("10.66.66.2")
	destIP := netip.MustParseAddr("93.184.216.34")
	const clientPort = uint16(49153)
	const destPort = uint16(443)
	const clientSeq = uint32(7000)

	syn := testIPv4TCPPacket(t, clientIP, destIP, clientPort, destPort, clientSeq, 0, header.TCPFlagSyn)
	if n, err := tunDev.Write([][]byte{syn}, 0); err != nil || n != 1 {
		t.Fatalf("Write SYN into userTun = %d, %v; want 1, nil", n, err)
	}
	synAck := readOneIPv4TCPPacket(t, tunDev)
	serverTCP := header.TCP(synAck[header.IPv4MinimumSize:])
	ack := testIPv4TCPPacket(t, clientIP, destIP, clientPort, destPort, clientSeq+1, serverTCP.SequenceNumber()+1, header.TCPFlagAck)
	if n, err := tunDev.Write([][]byte{ack}, 0); err != nil || n != 1 {
		t.Fatalf("Write ACK into userTun = %d, %v; want 1, nil", n, err)
	}

	select {
	case target := <-d.dialCh:
		if target != "93.184.216.34:443" {
			t.Fatalf("bridge dialed %q, want 93.184.216.34:443", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completed routed TCP handshake was not delivered to outbound bridge")
	}
	select {
	case tag := <-tagCh:
		if tag != "routed-tag" {
			t.Fatalf("resolver tag = %q, want routed-tag", tag)
		}
	case <-time.After(time.Second):
		t.Fatal("resolver was not called")
	}
	select {
	case flow := <-flowCh:
		if flow.Network != "tcp" || flow.SourceIP != "10.66.66.2" || flow.DestHost != "93.184.216.34" || flow.DestPort != 443 {
			t.Fatalf("flow = %#v, want tcp 10.66.66.2 -> 93.184.216.34:443", flow)
		}
		if flow.Identity.UserName != "alice" || flow.Identity.UserID != "u1" || flow.Identity.ShortIDHex != "0011223344556677" {
			t.Fatalf("identity = %#v, want alice/u1 shortid", flow.Identity)
		}
	case <-time.After(time.Second):
		t.Fatal("flow router was not called")
	}
}

func TestIdentityForIPPersistsAfterRegistration(t *testing.T) {
	s := &Server{identitiesByIP: make(map[string]ClientIdentity)}
	want := ClientIdentity{ShortIDHex: "0011223344556677", UserID: "u1", UserName: "alice", SessionID: "s1"}
	s.setIdentityForIP("10.66.66.2", want)

	got, ok := s.IdentityForIP("10.66.66.2")
	if !ok {
		t.Fatal("identity was not registered")
	}
	if got != want {
		t.Fatalf("identity = %#v, want %#v", got, want)
	}
}

func TestOutboundBridgeAccountsUserAndOutboundBytes(t *testing.T) {
	acc := &recordingAccounting{}
	b := &OutboundBridge{account: acc}
	id := ClientIdentity{UserID: "u1", SessionID: "s1"}

	b.accountFlow("direct", id, 123, 456)

	if acc.userID != "u1" || acc.sessionID != "s1" || acc.userUp != 123 || acc.userDown != 456 {
		t.Fatalf("user accounting = %#v, want u1/s1 123/456", acc)
	}
	if acc.outTag != "direct" || acc.outUp != 123 || acc.outDown != 456 {
		t.Fatalf("outbound accounting = %#v, want direct 123/456", acc)
	}
}

func TestUserTunForwardsRoutedUDPToOutboundBridge(t *testing.T) {
	d := &recordingDialer{packetCh: make(chan string, 1)}
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.66.66.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}
	defer tunDev.Close()

	b := NewOutboundBridge(tunDev, staticResolver{dialer: d}, "fallback-test", nil, nil, nil)
	defer b.Close()

	pkt := testIPv4UDPPacket(t,
		netip.MustParseAddr("10.66.66.2"),
		netip.MustParseAddr("1.1.1.1"),
		5353,
		53,
		[]byte{0, 1, 0, 0},
	)
	if n, err := tunDev.Write([][]byte{pkt}, 0); err != nil || n != 1 {
		t.Fatalf("Write UDP into userTun = %d, %v; want 1, nil", n, err)
	}

	select {
	case target := <-d.packetCh:
		if target != "1.1.1.1:53" {
			t.Fatalf("bridge dialed packet target %q, want 1.1.1.1:53", target)
		}
	case <-time.After(2 * time.Second):
		stats := tunDev.stk.Stats()
		t.Fatalf("routed UDP packet was not delivered to outbound bridge (ip rx=%d valid=%d invalid_dst=%d malformed=%d delivered=%d)",
			stats.IP.PacketsReceived.Value(),
			stats.IP.ValidPacketsReceived.Value(),
			stats.IP.InvalidDestinationAddressesReceived.Value(),
			stats.IP.MalformedPacketsReceived.Value(),
			stats.IP.PacketsDelivered.Value(),
		)
	}
}

func testIPv4UDPPacket(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	if !src.Is4() || !dst.Is4() {
		t.Fatalf("testIPv4UDPPacket requires IPv4 addresses, got %s -> %s", src, dst)
	}

	const (
		ipLen  = header.IPv4MinimumSize
		udpLen = header.UDPMinimumSize
	)
	pkt := make([]byte, ipLen+udpLen+len(payload))
	srcAddr := tcpip.AddrFromSlice(src.AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.AsSlice())

	ip := header.IPv4(pkt[:ipLen])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^checksum.Checksum(ip, 0))

	udp := header.UDP(pkt[ipLen : ipLen+udpLen])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen + len(payload)),
	})
	copy(pkt[ipLen+udpLen:], payload)
	if !ip.IsChecksumValid() {
		t.Fatalf("invalid IPv4 checksum")
	}
	return pkt
}

func readOneIPv4TCPPacket(t *testing.T, tunDev *userTun) []byte {
	t.Helper()
	type result struct {
		pkt []byte
		err error
		n   int
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		sizes := make([]int, 1)
		n, err := tunDev.Read([][]byte{buf}, sizes, 0)
		ch <- result{pkt: buf[:sizes[0]], err: err, n: n}
	}()
	select {
	case res := <-ch:
		if res.err != nil || res.n != 1 {
			t.Fatalf("Read response from userTun = %d, %v; want 1, nil", res.n, res.err)
		}
		if len(res.pkt) < header.IPv4MinimumSize+header.TCPMinimumSize {
			t.Fatalf("short IPv4/TCP response: %d bytes", len(res.pkt))
		}
		return append([]byte(nil), res.pkt...)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP SYN-ACK from userTun")
	}
	return nil
}

func testIPv4TCPPacket(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags header.TCPFlags) []byte {
	t.Helper()
	if !src.Is4() || !dst.Is4() {
		t.Fatalf("testIPv4TCPPacket requires IPv4 addresses, got %s -> %s", src, dst)
	}

	const (
		ipLen  = header.IPv4MinimumSize
		tcpLen = header.TCPMinimumSize
	)
	pkt := make([]byte, ipLen+tcpLen)
	srcAddr := tcpip.AddrFromSlice(src.AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.AsSlice())

	ip := header.IPv4(pkt[:ipLen])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^checksum.Checksum(ip, 0))

	tcp := header.TCP(pkt[ipLen:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: tcpLen,
		Flags:      flags,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, tcpLen)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	if !ip.IsChecksumValid() {
		t.Fatalf("invalid IPv4 checksum")
	}
	if !tcp.IsChecksumValid(srcAddr, dstAddr, 0, 0) {
		t.Fatalf("invalid TCP checksum")
	}
	return pkt
}
