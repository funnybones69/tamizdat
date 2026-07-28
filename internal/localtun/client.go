package localtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/rulesdb"
	"github.com/funnybones69/tamizdat/internal/sniff"
	"github.com/funnybones69/tamizdat/node"
)

type Accounting interface {
	Add(userID, sessionID string, up, down int64)
	AddOutbound(tag string, up, down int64)
}

// Client adapts a panel-managed local TUN user to the server's existing
// outbound registry and routing rules. It deliberately owns no upstream
// transport: outbound leases remain the single source of truth.
type Client struct {
	registry   *obreg.Registry
	rules      *rulesdb.Store
	accounting Accounting
	userID     string
	userName   string
	sniff      bool
	closed     atomic.Bool
}

func NewClient(registry *obreg.Registry, rules *rulesdb.Store, accounting Accounting, userID, userName string, sniffEnabled bool) *Client {
	return &Client{registry: registry, rules: rules, accounting: accounting, userID: userID, userName: userName, sniff: sniffEnabled}
}

func (c *Client) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := parsePort(port)
	if err != nil {
		return nil, err
	}
	return c.DialRequest(ctx, &node.Request{Network: network, TargetHost: host, TargetPort: p})
}

func (c *Client) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := parsePort(port)
	if err != nil {
		return nil, err
	}
	return c.DialPacketRequest(ctx, &node.Request{Network: node.NetworkUDP, TargetHost: host, TargetPort: p})
}

func (c *Client) DialRequest(ctx context.Context, req *node.Request) (net.Conn, error) {
	if c == nil || c.closed.Load() {
		return nil, errors.New("local TUN client is closed")
	}
	if c.registry == nil || req == nil {
		return nil, errors.New("local TUN client is not configured")
	}
	if req.Network != "" && req.Network != node.NetworkTCP {
		return nil, fmt.Errorf("local TUN: unsupported TCP network %q", req.Network)
	}
	if req.TargetHost == "" || req.TargetPort < 1 || req.TargetPort > 65535 {
		return nil, errors.New("local TUN: invalid TCP destination")
	}

	clientConn, bridgeConn := net.Pipe()
	request := *req
	request.Network = node.NetworkTCP
	request.InboundTag = "local-tun"
	request.User = c.userName
	go c.serveTCP(bridgeConn, &request)
	return clientConn, nil
}

func (c *Client) serveTCP(conn net.Conn, req *node.Request) {
	defer conn.Close()
	routingConn := conn
	routingHost := req.TargetHost
	if c.sniff {
		host, buffered, err := sniff.PeekConn(conn, []sniff.Sniffer{sniff.TLSClientHello, sniff.HTTPHost})
		if buffered != nil {
			routingConn = buffered
		}
		if err == nil && strings.TrimSpace(host) != "" {
			routingHost = host
		}
	}
	routeReq := *req
	routeReq.TargetHost = routingHost
	tagPick := rulesdb.ResolveRequest(context.Background(), c.rules.Load(), &routeReq)
	if tagPick == "block" {
		return
	}
	dialer, resolvedTag := c.registry.Resolve(tagPick)
	defer dialer.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	upstream, err := dialer.DialContext(dialCtx, node.NetworkTCP, req.Address())
	cancel()
	if err != nil {
		return
	}
	defer upstream.Close()
	resolvedTag = effectiveTag(resolvedTag, upstream)
	up, down := proxyCounted(routingConn, upstream)
	c.record(resolvedTag, up, down)
}

func (c *Client) DialPacketRequest(ctx context.Context, req *node.Request) (net.PacketConn, error) {
	if c == nil || c.closed.Load() {
		return nil, errors.New("local TUN client is closed")
	}
	if c.registry == nil || req == nil {
		return nil, errors.New("local TUN client is not configured")
	}
	request := *req
	request.Network = node.NetworkUDP
	request.InboundTag = "local-tun"
	request.User = c.userName
	tagPick := rulesdb.ResolveRequest(ctx, c.rules.Load(), &request)
	if tagPick == "block" {
		return nil, errors.New("local TUN: UDP blocked by routing rule")
	}
	dialer, resolvedTag := c.registry.Resolve(tagPick)
	pc, err := dialer.DialPacket(ctx, request.Address())
	if err != nil {
		_ = dialer.Close()
		return nil, err
	}
	return &meteredPacketConn{PacketConn: pc, lease: dialer, accounting: c.accounting, userID: c.userID, tag: effectiveTag(resolvedTag, pc)}, nil
}

func (c *Client) record(tag string, up, down int64) {
	if c.accounting == nil || (up == 0 && down == 0) {
		return
	}
	c.accounting.Add(c.userID, "", up, down)
	c.accounting.AddOutbound(tag, up, down)
}

type outboundTagger interface{ OutboundTag() string }

func effectiveTag(fallback string, value any) string {
	if tagged, ok := value.(outboundTagger); ok {
		if tag := strings.TrimSpace(tagged.OutboundTag()); tag != "" {
			return tag
		}
	}
	return fallback
}

func proxyCounted(local, upstream net.Conn) (up, down int64) {
	type result struct {
		up bool
		n  int64
	}
	results := make(chan result, 2)
	go func() { n, _ := io.Copy(upstream, local); results <- result{up: true, n: n} }()
	go func() { n, _ := io.Copy(local, upstream); results <- result{n: n} }()
	first := <-results
	_ = local.Close()
	_ = upstream.Close()
	second := <-results
	for _, r := range []result{first, second} {
		if r.up {
			up += r.n
		} else {
			down += r.n
		}
	}
	return up, down
}

type meteredPacketConn struct {
	net.PacketConn
	lease      obreg.Dialer
	accounting Accounting
	userID     string
	tag        string
	up         atomic.Int64
	down       atomic.Int64
	once       sync.Once
}

func (m *meteredPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := m.PacketConn.WriteTo(p, addr)
	m.up.Add(int64(n))
	return n, err
}

func (m *meteredPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := m.PacketConn.ReadFrom(p)
	m.down.Add(int64(n))
	return n, addr, err
}

func (m *meteredPacketConn) Close() error {
	var err error
	m.once.Do(func() {
		err = m.PacketConn.Close()
		up, down := m.up.Load(), m.down.Load()
		if m.accounting != nil && (up != 0 || down != 0) {
			m.accounting.Add(m.userID, "", up, down)
			m.accounting.AddOutbound(m.tag, up, down)
		}
		if closeErr := m.lease.Close(); err == nil {
			err = closeErr
		}
	})
	return err
}

func parsePort(raw string) (int, error) {
	var port int
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, errors.New("invalid port")
		}
		port = port*10 + int(r-'0')
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}
