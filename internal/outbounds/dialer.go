// Package outbounds loads and resolves Phase 1 tamizdat outbound dialers.
package outbounds

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

// Dialer dials a target either directly or through an upstream tamizdat client.
// DialPacket is the UDP counterpart of DialContext: returns a net.PacketConn
// suitable for tunnelled UDP forwarding. Server's handleUDPCONNECT routes
// QUIC/UDP traffic through it, so routing rules apply to UDP just like TCP.
type Dialer interface {
	DialContext(ctx context.Context, network, target string) (net.Conn, error)
	DialPacket(ctx context.Context, target string) (net.PacketConn, error)
	Close() error
}

// Client is the subset of tamizdat.Client used by an outbound dialer.
type Client interface {
	DialContext(ctx context.Context, network, target string) (net.Conn, error)
	DialUDP(ctx context.Context, address string) (net.PacketConn, error)
	Close() error
}

// ClientFactory builds a lazy tamizdat client from a parsed tamizdat:// URL.
type ClientFactory func(configurl.Config) (Client, error)

// DirectDialer dials the requested target from the local server IP. When
// BindIface is non-empty the underlying socket is bound to that NIC via
// SO_BINDTODEVICE (Linux). Multi-IP boxes (split front/back IP) and
// amnezia/wireguard tunnel hosts use this to force the direct outbound
// to exit through a specific interface — the panel's Edit-direct modal
// writes the iface name into outbounds.bind_iface and the registry
// reload propagates it here.
type DirectDialer struct {
	Timeout   time.Duration
	BindIface string // optional Linux network interface name (eth0, wg-amnezia, …); empty = OS default route
}

func (d DirectDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	nd := &net.Dialer{Timeout: timeout}
	if d.BindIface != "" {
		nd.Control = bindToDeviceControl(d.BindIface)
	}
	return nd.DialContext(ctx, network, target)
}

// DialPacket opens a local UDP socket — returns a net.PacketConn the
// caller can WriteTo(target) on. We deliberately use ListenPacket
// (unconnected) instead of DialUDP so the same interface contract
// works for both Direct and Tamizdat outbounds — tamizdat's tunnelled
// PacketConn always requires WriteTo(addr) semantics, and a connected
// UDPConn would reject WriteTo with errWriteToConnected.
func (d DirectDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	_ = target // resolved by handleUDPCONNECT before this call; we just open the socket
	lc := &net.ListenConfig{}
	if d.BindIface != "" {
		lc.Control = bindToDeviceControl(d.BindIface)
	}
	return lc.ListenPacket(ctx, "udp", ":0")
}

func (d DirectDialer) Close() error { return nil }

// BlackholeDialer drops every connection without dialing anything. Routing
// rules pointing at a blackhole outbound effectively block matching traffic
// (Windows telemetry, ads, RKN-listed, ...). Returns ErrBlackholed so the
// upstream stream handler can surface a clean RST/connection-refused-style
// teardown to the client rather than a hang.
//
// Operator UX (2026-05-10): exposed as kind="blackhole" in the panel
// outbounds page; created without a URI; routing rules can target it like
// any other outbound tag.
type BlackholeDialer struct{}

// ErrBlackholed signals that a connection was intentionally dropped by a
// blackhole outbound. Callers can match on this to log "blocked" rather
// than "failed" in metrics.
var ErrBlackholed = fmt.Errorf("outbound: blackholed")

func (BlackholeDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	return nil, fmt.Errorf("blackhole outbound: udp blocked")
}

func (BlackholeDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return nil, ErrBlackholed
}

func (BlackholeDialer) Close() error { return nil }

// TamizdatDialer lazily constructs one upstream tamizdat client and delegates
// CONNECT dials through it. URI validation happens eagerly; network activity
// does not happen until the first DialContext call.
type TamizdatDialer struct {
	uri     string
	cfg     configurl.Config
	factory ClientFactory

	mu     sync.Mutex
	client Client
	closed bool
}

func NewTamizdatDialer(uri string, factory ClientFactory) (*TamizdatDialer, error) {
	cfg, err := configurl.Parse(uri)
	if err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, fmt.Errorf("tamizdat client factory is nil")
	}
	return &TamizdatDialer{uri: uri, cfg: cfg, factory: factory}, nil
}

func (d *TamizdatDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("tamizdat outbound supports tcp CONNECT only, got %q", network)
	}
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, network, target)
}

// DialPacket routes UDP through the tamizdat outbound's tunnel via
// the client's DialUDP path (Tamizdat-Protocol: udp/1). Without this,
// the server's handleUDPCONNECT path skipped routing entirely and
// dialed UDP from the local IP — breaking iPhone QUIC traffic that
// was supposed to exit via a remote outbound (e.g. default → mirror).
func (d *TamizdatDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	client, err := d.ensureClient()
	if err != nil {
		return nil, err
	}
	return client.DialUDP(ctx, target)
}

// ensureClient lazily creates the underlying tamizdat client on first
// dial. Shared by DialContext + DialPacket so a process can do either
// TCP or UDP first and the other works equally well.
func (d *TamizdatDialer) ensureClient() (Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fmt.Errorf("tamizdat outbound is closed")
	}
	if d.client != nil {
		return d.client, nil
	}
	client, err := d.factory(d.cfg)
	if err != nil {
		return nil, fmt.Errorf("create tamizdat client: %w", err)
	}
	d.client = client
	return client, nil
}

func (d *TamizdatDialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	client := d.client
	d.client = nil
	d.mu.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}

// RTTProbeSnapshot adapts the public tamizdat.Client RTT probe to the internal
// outbounds package without adding a direct dependency on pkg/tamizdat from this
// package boundary. If the lazy client has not been created yet, or the concrete
// client does not expose RTTProbeSnapshot, the snapshot is reported absent.
func (d *TamizdatDialer) RTTProbeSnapshot() RTTSnapshot {
	if d == nil {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	d.mu.Lock()
	client := d.client
	d.mu.Unlock()
	if client == nil {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	return reflectRTTProbeSnapshot(client)
}

func reflectRTTProbeSnapshot(v any) RTTSnapshot {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	m := rv.MethodByName("RTTProbeSnapshot")
	if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() != 1 {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	out := m.Call(nil)
	if len(out) != 1 {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	sv := out[0]
	if sv.Kind() == reflect.Pointer {
		if sv.IsNil() {
			return RTTSnapshot{P50Ms: -1, LastMs: -1}
		}
		sv = sv.Elem()
	}
	if sv.Kind() != reflect.Struct {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	return RTTSnapshot{
		P50Ms:  reflectedIntField(sv, "P50Ms", -1),
		Count:  int(reflectedIntField(sv, "Count", 0)),
		LastMs: reflectedIntField(sv, "LastMs", -1),
	}
}

func reflectedIntField(v reflect.Value, name string, fallback int64) int64 {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return fallback
	}
	switch f.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return f.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := f.Uint()
		if u > uint64(^uint64(0)>>1) {
			return fallback
		}
		return int64(u)
	default:
		return fallback
	}
}
