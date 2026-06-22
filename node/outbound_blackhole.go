package node

import (
	"context"
	"net"
)

// BlackholeOutbound silently rejects every Dial. It mirrors xray's
// "blackhole" outbound and is the canonical sink for ad/tracker/private
// rules.
type BlackholeOutbound struct{ tag string }

func NewBlackholeOutbound(tag string) *BlackholeOutbound { return &BlackholeOutbound{tag: tag} }

func (b *BlackholeOutbound) Tag() string { return b.tag }

func (b *BlackholeOutbound) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	return nil, ErrBlackholed
}

func (b *BlackholeOutbound) Close() error { return nil }
