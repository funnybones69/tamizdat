package tunengine

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/funnybones69/tamizdat/node"
)

type ProxyClient interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	DialUDP(ctx context.Context, address string) (net.PacketConn, error)
	Close() error
}

type Options struct {
	Name                     string
	MTU                      int
	Debug                    bool
	TCPModerateReceiveBuffer bool
	TCPSendBufferSize        int
	TCPReceiveBufferSize     int
	TunIP                    string
	TunPrefix                int
	AutoRoute                bool
	DialAttemptTimeout       time.Duration
	DialConcurrency          int
	DialActiveConcurrency    int
	DialOpenInterval         time.Duration
	DialTargetCooldown       time.Duration
	DialTargetCooldownMax    time.Duration
	DialMinAttemptBudget     time.Duration
	DialRecoveryThreshold    int
	DialRecoveryBackoff      time.Duration
	DropPrivateDestinations  bool
	DropAllUDP               bool
	DropNonDNSUDP            bool
	BlockedEndpoints         []netip.AddrPort
	Dispatcher               *node.Dispatcher
	PostTunUp                func() error // optional callback fired once TUN device + stack are open
}
