package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// TamizdatInbound is the wire-protocol server side of tamizdat (TLS+H2 with
// masquerade fallback). Decrypted streams go through the dispatcher exactly
// like SOCKS/HTTP inbounds — making the tamizdat server useful as one hop in
// a longer chain (e.g. TSPU → tamizdat-server → freedom OR tamizdat-out).
type TamizdatInbound struct {
	tag    string
	server *tamizdat.Server

	// Dispatcher reference set by Start; handler closure reads it via mu/atomic.
	mu       sync.Mutex
	dispatch InboundDispatcher
	ctx      context.Context
	closed   atomic.Bool
}

func NewTamizdatInbound(tag, listen string, raw json.RawMessage) (*TamizdatInbound, error) {
	var s TamizdatServerSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("tamizdat inbound %q settings: %w", tag, err)
		}
	}
	if listen == "" {
		return nil, fmt.Errorf("tamizdat inbound %q: listen required", tag)
	}
	if s.PrivateKeyHex == "" {
		return nil, fmt.Errorf("tamizdat inbound %q: private_key_hex required", tag)
	}
	priv, err := hex.DecodeString(s.PrivateKeyHex)
	if err != nil || len(priv) != 32 {
		return nil, fmt.Errorf("tamizdat inbound %q: private_key_hex must be 64 hex", tag)
	}
	if len(s.ShortIDsHex) == 0 {
		return nil, fmt.Errorf("tamizdat inbound %q: shortids_hex required", tag)
	}
	shortIDs := make([][8]byte, 0, len(s.ShortIDsHex))
	for _, h := range s.ShortIDsHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 8 {
			return nil, fmt.Errorf("tamizdat inbound %q: shortid %q must be 16 hex", tag, h)
		}
		var id [8]byte
		copy(id[:], b)
		shortIDs = append(shortIDs, id)
	}
	if s.CertPEMPath == "" || s.KeyPEMPath == "" {
		return nil, fmt.Errorf("tamizdat inbound %q: cert_pem_path and key_pem_path required", tag)
	}
	certPEM, err := os.ReadFile(s.CertPEMPath)
	if err != nil {
		return nil, fmt.Errorf("tamizdat inbound %q: read cert: %w", tag, err)
	}
	keyPEM, err := os.ReadFile(s.KeyPEMPath)
	if err != nil {
		return nil, fmt.Errorf("tamizdat inbound %q: read key: %w", tag, err)
	}

	in := &TamizdatInbound{tag: tag}
	cfg := tamizdat.ServerConfig{
		ListenAddr:       listen,
		PrivateKey:       priv,
		MasterShortID:    shortIDs[0],
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradeDomain: s.MasqueradeDomain,
		MasqueradeAddr:   s.MasqueradeAddr,
		MasqueradePool:   s.MasqueradePool,
		ReplayWindow:     durationMs(s.ReplayWindowMs),
		Debug:            s.Debug,
		DebugListenAddr:  s.DebugListenAddr,
		// HandlerWithIdentity carries the userdb-resolved user name so that
		// routing rules with a {"user": [...]} filter can match for the
		// tamizdat-protocol inbound (review-H finding H-1). Falls back to an
		// empty user when the lib's userRegistry is unconfigured (no
		// ServerDBPath set) or when the verified shortid is the embedded
		// master fallback — both cases preserve "no user" semantics.
		HandlerWithIdentity: in.connHandlerWithIdentity,
		// ServerDBPath threads through unchanged. Leaving it empty keeps the
		// legacy embedded mode (no userdb) working; setting it activates the
		// shortid → user.name lookup performed by tamizdat.Server.
		ServerDBPath: s.ServerDBPath,
		// The node owns outbound dispatch via its own InboundDispatcher; the
		// lib's outbound registry must stay disabled even when ServerDBPath
		// is set (otherwise the lib would try to route the connection itself
		// instead of handing it to HandlerWithIdentity).
		DisableOutboundRegistry: true,
	}
	srv, err := tamizdat.NewServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("tamizdat inbound %q: build server: %w", tag, err)
	}
	in.server = srv
	return in, nil
}

func (s *TamizdatInbound) Tag() string { return s.tag }

func (s *TamizdatInbound) Start(ctx context.Context, d InboundDispatcher) error {
	s.mu.Lock()
	s.dispatch = d
	s.ctx = ctx
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return s.server.ListenAndServe()
}

func (s *TamizdatInbound) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.server.Close()
}

// connHandlerWithIdentity is the tamizdat.ConnHandlerWithIdentity. It is
// invoked once per authenticated H2 CONNECT stream with the destination
// string and the resolved user identity. We synthesize a Request, attach the
// user (review-H H-1 fix), and hand it to the dispatcher.
//
// identity.UserName is empty when the lib's userRegistry is unconfigured
// (no ServerDBPath set) or when the verified shortid is the embedded master
// fallback. In both cases Request.User stays empty, which preserves prior
// behaviour: routing rules with a {"user": [...]} filter naturally don't
// match an empty user, and rules without that filter are unaffected.
func (s *TamizdatInbound) connHandlerWithIdentity(ctx context.Context, conn net.Conn, destination string, identity tamizdat.ConnIdentity) {
	defer conn.Close()

	s.mu.Lock()
	d := s.dispatch
	rootCtx := s.ctx
	s.mu.Unlock()
	if d == nil || rootCtx == nil {
		return
	}
	if rootCtx.Err() != nil {
		return
	}

	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return
	}

	req := &Request{
		Network:    NetworkTCP,
		TargetHost: host,
		TargetPort: port,
		InboundTag: s.tag,
		User:       identity.UserName,
	}
	// SourceIP is the client of the tamizdat tunnel.
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		req.SourceIP = tcpAddr.IP
	}

	dctx, cancel := context.WithTimeout(rootCtx, 20*time.Second)
	defer cancel()
	tunnel, _, err := d.Dispatch(dctx, req)
	if err != nil {
		return
	}
	defer tunnel.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(tunnel, conn)
		if cw, ok := tunnel.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, tunnel)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
