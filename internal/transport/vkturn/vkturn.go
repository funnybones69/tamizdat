package vkturn

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	ShortIDLen = 8

	UDPDestinationPrefix = "udp:"

	DefaultWorkers         = 12
	MaxWorkers             = 48
	DefaultMaxFramePayload = 1150
	DefaultConnectTimeout  = 30 * time.Second
	DefaultSessionTimeout  = 90 * time.Second
)

var (
	ErrUnsupportedNetwork = errors.New("vkturn: unsupported network")
	ErrUnsupportedUDP     = errors.New("vkturn: UDP is not supported")
	ErrAuthFailed         = errors.New("vkturn: auth failed")
	ErrProtocol           = errors.New("vkturn: protocol error")
	ErrNoSession          = errors.New("vkturn: no active relay session")
)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Credentials struct {
	User     string
	Pass     string
	TurnURLs []string
	Lifetime int
	Fetched  time.Time
}

type streamAddr struct {
	network string
	address string
}

func (a streamAddr) Network() string { return a.network }
func (a streamAddr) String() string  { return a.address }

func workerCount(n int) int {
	if n <= 0 {
		return DefaultWorkers
	}
	if n > MaxWorkers {
		return MaxWorkers
	}
	return n
}

func maxFramePayload(n int) int {
	if n <= 0 || n > DefaultMaxFramePayload {
		return DefaultMaxFramePayload
	}
	if n < 256 {
		return 256
	}
	return n
}

func durationDefault(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}

func ParseHashes(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		h := strings.TrimSpace(part)
		if h == "" {
			continue
		}
		if i := strings.Index(h, "/call/join/"); i >= 0 {
			h = h[i+len("/call/join/"):]
		} else if i := strings.LastIndex(h, "/"); i >= 0 {
			h = h[i+1:]
		}
		if i := strings.IndexAny(h, "?#"); i >= 0 {
			h = h[:i]
		}
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func isDNSDestination(address string) bool {
	host, port, err := net.SplitHostPort(strings.TrimPrefix(address, UDPDestinationPrefix))
	if err != nil {
		return false
	}
	_ = host
	return port == "53"
}

func configureKCPConn(conn net.Conn) {
	ks, ok := conn.(*kcp.UDPSession)
	if !ok || ks == nil {
		return
	}
	ks.SetStreamMode(true)
	ks.SetWriteDelay(false)
	ks.SetACKNoDelay(true)
	ks.SetNoDelay(1, 10, 2, 1)
	ks.SetWindowSize(4096, 4096)
	ks.SetMtu(1350)
	_ = ks.SetReadBuffer(4 * 1024 * 1024)
	_ = ks.SetWriteBuffer(4 * 1024 * 1024)
}
