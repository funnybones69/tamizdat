//go:build linux

package wgturn

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/outbounds"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type lifecycleResolver struct {
	dialer *lifecycleDialer
}

func (r lifecycleResolver) Resolve(tag string) (outbounds.Dialer, string) {
	return r.dialer, "test-outbound"
}

type lifecycleDialer struct {
	peerCh    chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newLifecycleDialer() *lifecycleDialer {
	return &lifecycleDialer{
		peerCh:  make(chan net.Conn, 1),
		closeCh: make(chan struct{}),
	}
}

func (d *lifecycleDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	upConn, peer := net.Pipe()
	select {
	case d.peerCh <- peer:
	case <-ctx.Done():
		_ = upConn.Close()
		_ = peer.Close()
		return nil, ctx.Err()
	}
	return upConn, nil
}

func (d *lifecycleDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	return nil, nil
}

func (d *lifecycleDialer) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	return nil
}

func newTestBridge(t *testing.T, d *lifecycleDialer) (*OutboundBridge, *userTun) {
	t.Helper()
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}
	return NewOutboundBridge(tunDev, lifecycleResolver{dialer: d}, "test", nil, nil, nil), tunDev
}

func TestPumpTCPReleasesOutboundLease(t *testing.T) {
	d := newLifecycleDialer()
	b, tunDev := newTestBridge(t, d)
	defer tunDev.Close()
	defer b.Close()

	client, bridgeSide := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		b.pumpTCP(bridgeSide, "192.0.2.1:443", "")
		close(done)
	}()

	var upstreamPeer net.Conn
	select {
	case upstreamPeer = <-d.peerCh:
		defer upstreamPeer.Close()
	case <-time.After(time.Second):
		t.Fatal("pumpTCP did not dial upstream")
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pumpTCP did not finish after client close")
	}

	select {
	case <-d.closeCh:
	case <-time.After(time.Second):
		t.Fatal("pumpTCP finished without closing outbound lease")
	}
}

func TestBridgeCloseStopsInFlightTCPFlow(t *testing.T) {
	d := newLifecycleDialer()
	b, tunDev := newTestBridge(t, d)
	defer tunDev.Close()

	client, bridgeSide := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		b.pumpTCP(bridgeSide, "192.0.2.1:443", "")
		close(done)
	}()

	var upstreamPeer net.Conn
	select {
	case upstreamPeer = <-d.peerCh:
		defer upstreamPeer.Close()
	case <-time.After(time.Second):
		t.Fatal("pumpTCP did not dial upstream")
	}

	closeDone := make(chan struct{})
	go func() {
		b.Close()
		close(closeDone)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge Close did not stop in-flight TCP flow")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("bridge Close did not return after flow stopped")
	}
}

func TestUserTunCloseIsIdempotent(t *testing.T) {
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}
	if err := tunDev.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tunDev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestUserTunCloseUnblocksInFlightWriteNotifyWithoutPanic(t *testing.T) {
	tunDev, err := createUserTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, 1500)
	if err != nil {
		t.Fatalf("createUserTUN: %v", err)
	}

	panicked := make(chan any, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked <- recover() }()
		var pkts stack.PacketBufferList
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0x00})})
		defer pkt.DecRef()
		pkts.PushBack(pkt)
		_, _ = tunDev.ep.WritePackets(pkts)
	}()

	select {
	case <-done:
		t.Fatal("WriteNotify returned before Close; test did not exercise blocked notification")
	case <-time.After(50 * time.Millisecond):
	}

	if err := tunDev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock WriteNotify")
	}
	if p := <-panicked; p != nil {
		t.Fatalf("WriteNotify panicked during Close: %v", p)
	}
}
