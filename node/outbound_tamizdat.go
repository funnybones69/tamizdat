package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// TamizdatOutbound dials through a tamizdat tunnel. It owns a tamizdat.Client
// keyed by the configured server pubkey + shortid pool; one outbound entry
// → one client → one (or N) persistent TLS+H2 transports.
//
// To build a multi-hop chain, simply declare two tamizdat outbounds and
// route the first's traffic into the second via a SOCKS inbound on the
// intermediate hop. (Direct outbound→outbound chaining without an inbound
// in between is not supported in v1; the inbound seam keeps each hop's
// auth/routing self-contained.)
type TamizdatOutbound struct {
	tag    string
	client *tamizdat.Client
}

// NewTamizdatOutbound builds the outbound from JSON settings.
func NewTamizdatOutbound(tag string, raw json.RawMessage) (*TamizdatOutbound, error) {
	var s TamizdatClientSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("tamizdat outbound %q settings: %w", tag, err)
		}
	}
	if s.URI != "" {
		profile, err := ParseURI(s.URI)
		if err != nil {
			return nil, fmt.Errorf("tamizdat outbound %q uri: %w", tag, err)
		}
		// Pool-config is server-authoritative, but URI-provided bounds are now
		// threaded through so the first live client starts with the server's
		// exact transport count instead of a client-side default stub.
		cfg := tamizdat.ClientConfig{
			ServerAddr:               net.JoinHostPort(profile.Host, strconv.Itoa(profile.Port)),
			PrimarySNI:               profile.PrimarySNI,
			ServerName:               profile.PrimarySNI,
			PublicKey:                profile.Pubkey,
			MasterShortID:            profile.MasterShortID,
			Fingerprint:              s.Fingerprint,
			CoverTrafficEnabled:      s.CoverTrafficEnabled,
			CoverTrafficTargets:      profile.CoverTrafficTargets,
			PoolVariant:              profile.PoolVariant,
			MinTransports:            profile.MinTransports,
			MaxTransports:            profile.MaxTransports,
			RotationOverlapAllowance: profile.RotationOverlapAllowance,
			BytesPerTransportSoftCap: profile.BytesPerTransportSoftCap,
			IdleTimeout:              durationMs(s.IdleTimeoutMs),
			ConnectTimeout:           durationMs(s.ConnectTimeoutMs),
		}
		cli, err := tamizdat.NewClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("tamizdat outbound %q: build client: %w", tag, err)
		}
		return &TamizdatOutbound{tag: tag, client: cli}, nil
	}
	if s.ServerAddr == "" {
		return nil, fmt.Errorf("tamizdat outbound %q: server_addr required", tag)
	}
	if len(s.ServerNames) == 0 {
		return nil, fmt.Errorf("tamizdat outbound %q: server_names required", tag)
	}
	pub, err := hex.DecodeString(s.PublicKeyHex)
	if err != nil || len(pub) != 32 {
		return nil, fmt.Errorf("tamizdat outbound %q: public_key_hex must be 64 hex chars", tag)
	}
	if len(s.ShortIDsHex) == 0 {
		return nil, fmt.Errorf("tamizdat outbound %q: shortids_hex required", tag)
	}
	shortIDs := make([][8]byte, 0, len(s.ShortIDsHex))
	for _, h := range s.ShortIDsHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 8 {
			return nil, fmt.Errorf("tamizdat outbound %q: shortid %q must be 16 hex chars", tag, h)
		}
		var id [8]byte
		copy(id[:], b)
		shortIDs = append(shortIDs, id)
	}

	// Pool-config fields from JSON are threaded through directly. The server
	// still reasserts the authoritative bounds in the cover-config bundle, but
	// direct JSON deployments no longer lose explicit transport sizing.
	cfg := tamizdat.ClientConfig{
		ServerAddr:               s.ServerAddr,
		PrimarySNI:               s.ServerNames[0],
		ServerName:               s.ServerNames[0],
		ServerNames:              s.ServerNames,
		PublicKey:                pub,
		MasterShortID:            shortIDs[0],
		Fingerprint:              s.Fingerprint,
		CoverTrafficEnabled:      s.CoverTrafficEnabled,
		CoverTrafficTargets:      s.CoverTrafficTargets,
		PoolVariant:              s.PoolVariant,
		MinTransports:            s.MinTransports,
		MaxTransports:            s.MaxTransports,
		RotationOverlapAllowance: s.RotationOverlapAllowance,
		BytesPerTransportSoftCap: s.BytesPerTransportSoftCap,
		IdleTimeout:              durationMs(s.IdleTimeoutMs),
		ConnectTimeout:           durationMs(s.ConnectTimeoutMs),
	}
	cli, err := tamizdat.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("tamizdat outbound %q: build client: %w", tag, err)
	}
	return &TamizdatOutbound{tag: tag, client: cli}, nil
}

func (s *TamizdatOutbound) Tag() string { return s.tag }

func (s *TamizdatOutbound) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	return s.client.DialContext(ctx, "tcp", req.Address())
}

func (s *TamizdatOutbound) DialPacket(ctx context.Context, req *Request) (net.PacketConn, error) {
	return s.client.DialUDP(ctx, req.Address())
}

func (s *TamizdatOutbound) Close() error { return s.client.Close() }
