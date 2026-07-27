package tamizdat

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/proxyproto"
	"github.com/funnybones69/tamizdat/internal/sniff"
	"github.com/funnybones69/tamizdat/internal/transport/fragpoc"
	"github.com/funnybones69/tamizdat/internal/transport/vkturn"
	"github.com/funnybones69/tamizdat/internal/userdb"

	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

// ErrServerClosed is the cause set on the server's context when Close is called.
var ErrServerClosed = errors.New("server closed")

// Server accepts Samizdat connections, authenticates them via Reality-style
// auth in the TLS ClientHello, and proxies authenticated HTTP/2 CONNECT
// tunnels. Non-authenticated connections are transparently proxied to the
// masquerade domain at the TCP level.
type Server struct {
	config       ServerConfig
	serverPubKey []byte

	// Cached TLS certificate - loaded once at NewServer so the auth-success
	// handshake does not do a disk read on the hot path (timing distinguisher
	// fix per audit finding T5). nil on parse error (server refuses to boot).
	cachedCert *tls.Certificate

	// Shaper + fragmenter wire P0.1 record fragmentation into server-side
	// response writes. P0.4 removes per-record jitter from this path.
	shaper     *Shaper
	fragmenter *RecordFragmenter

	// Replay-protection: sliding window of recently-seen SessionID nonces
	// (auth T5 finding - captured ClientHellos could be replayed forever).
	replayGuard *replayGuard

	listenerMu sync.Mutex
	listener   net.Listener
	masquerade *Masquerade
	ctx        context.Context
	cancel     context.CancelCauseFunc
	wg         sync.WaitGroup

	debugMu       sync.Mutex
	debugListener net.Listener
	debugServer   *http.Server

	// Shape-event log: per-stream open/close events when configured.
	// The writer rotates by size so the file cannot grow unbounded.
	shapeEventMu  sync.Mutex
	shapeEventOut *rotatingWriter

	// MED-4: track in-flight TCP connections so Server.Close can actively
	// terminate them. Without this, h2Server.ServeConn parks on tlsConn.Read
	// and wg.Wait() blocks forever, breaking systemd graceful-shutdown.
	activeConns sync.Map // map[net.Conn]struct{}

	// Per-IP rate-limiter on masquerade forwards (compass v2 §3.11 DoS protection).
	masqLimiter *masqueradeRateLimiter
	// Pre-warmed TCP connection pool to masquerade origins (review-A P3).
	// nil when masquerade is disabled.
	masqPrewarm *prewarmedPool
	// review-D-2: per-shortid token-bucket limiter applied AFTER the
	// 8-byte SessionID prefix is parsed but BEFORE PSK derivation, so
	// flooders cannot drive the curve25519 budget with random shortids.
	// See handshake_limiter_server.go for rate / burst / capacity defaults.
	shortIDLimiter *shortIDLimiter

	// Server-pushed config bundle. coverConfigJSON is the precomputed wire
	// form for the no-TTL case. When BundleTTL > 0, the handler re-marshals
	// coverConfigBundle on each request with a fresh expires_at so clients
	// can disk-cache for the advertised lifetime; the ETag is computed over
	// the static portion (excluding expires_at) and stays stable across
	// requests.
	coverConfigJSON   []byte
	coverConfigBundle *CoverConfigBundle
	coverConfigETag   string

	// VK TURN credential provider (nil when disabled). Injected via
	// ServerConfig.TURNCredsProvider; called on every bundle request
	// to include fresh TURN credentials in the response.
	turnCredsProvider TURNCredsProvider

	outboundDB       *sql.DB
	outboundRegistry *obreg.Registry
	outboundReloads  atomic.Uint64

	// Phase 2 multi-user identity. ServerDBPath enables loading users from
	// SQLite; the registry maps shortid → user, the accounting layer buffers
	// per-stream byte counters and flushes them to SQLite every few seconds,
	// and userdbCancel stops the background flush goroutine on Close.
	userRegistry  *userdb.UserRegistry
	accounting    *userdb.Accounting
	userdbCancel  context.CancelFunc
	userdbReloads atomic.Uint64

	// Per-user connection tracker for server-side immediate-block on
	// quota overrun (2026-05-10 evening). On auth-success we register
	// each authenticated TCP+TLS conn here keyed by user_id; on Flush
	// the OnFlushUser hook re-checks IsOverQuota and, when the user just
	// crossed the BandwidthCap, calls KillUser to close every tracked
	// conn. Without this, only NEW handshakes were rejected — existing
	// long-lived H2 sessions could keep streaming past cap indefinitely.
	connTracker *userConnTracker

	// Per-user bandwidth-rate limiter (Mbits/sec). Populated/updated on
	// every userdb reload (boot + SIGHUP) from users.rate_limit_mbps. nil
	// limiter map entry = unlimited; handleTCPConnect / handleUDPCONNECT
	// hands the limiter to proxyBidirectionalCounted which throttles both
	// directions of every flow owned by that user.
	rateLimits *userRateLimiters

	// H2-only per-user peak tracker. This is diagnostic state, separate from
	// admission control, so FragPoC and future transports do not pollute the
	// "streams inside H2" panel signal.
	h2StreamTracker *userH2StreamTracker
	h2PeakUpdates   chan userH2PeakUpdate

	userRelayStreamTracker *userH2StreamTracker

	// Per-outbound relay pressure tracker. Unlike h2StreamTracker, this is
	// keyed by outbound tag and answers "how many streams this server is
	// pushing toward the next hop".
	outboundStreamTracker *outboundStreamTracker

	fragPoCOnce        sync.Once
	fragPoCServer      *fragpoc.Server
	fragPoCErr         error
	fragPoCPortManager *FragPoCPortManager

	vkTurnOnce   sync.Once
	vkTurnServer *vkturn.Server
	vkTurnErr    error
}

// userConnTracker maps userID → set of close functions for all currently
// authenticated connections of that user. Operations are O(1) under a
// single mutex; the bookkeeping cost is negligible vs. the per-stream
// I/O it protects.
type userConnTracker struct {
	mu     sync.Mutex
	nextID uint64
	byUser map[string]map[uint64]func()
}

func newUserConnTracker() *userConnTracker {
	return &userConnTracker{byUser: make(map[string]map[uint64]func())}
}

// Track registers a close func for userID and returns an untrack func the
// caller MUST defer. Panics on empty userID (programmer error: never
// register an unauthenticated conn).
func (t *userConnTracker) Track(userID string, closeFn func()) func() {
	if t == nil || userID == "" || closeFn == nil {
		return func() {}
	}
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	if t.byUser[userID] == nil {
		t.byUser[userID] = make(map[uint64]func())
	}
	t.byUser[userID][id] = closeFn
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		if m, ok := t.byUser[userID]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(t.byUser, userID)
			}
		}
		t.mu.Unlock()
	}
}

// KillUser closes every tracked conn for userID and clears the slot.
// Returns the number of conns that were closed (for logging). The actual
// close is invoked synchronously; callers in goroutine-sensitive paths
// should themselves spawn a goroutine if blocking is undesirable.
func (t *userConnTracker) KillUser(userID string) int {
	if t == nil || userID == "" {
		return 0
	}
	t.mu.Lock()
	closes := t.byUser[userID]
	delete(t.byUser, userID)
	t.mu.Unlock()
	n := 0
	for _, c := range closes {
		c()
		n++
	}
	return n
}

// authIdentity carries everything the post-auth handler needs to know about
// the connecting user: the 8-byte shortid (for shape-event logs and fallback
// behaviour) plus the resolved user_id, session_id, and pool_index. When the
// userdb registry is disabled or the connection authenticated via the legacy
// master_shortid direct check, UserID stays empty and the accounting
// integration is a no-op.
type authIdentity struct {
	ShortID   [8]byte
	UserID    string
	UserName  string // populated when userRegistry hit; empty otherwise
	SessionID string
	PoolIndex int
	// DataPlaneBlocked = true when the user holds valid creds but is in a
	// state that blocks tunneling (over-quota or expired). Phase C iOS-notify
	// pipeline (2026-05-10): instead of dropping such users into masquerade
	// (which leaves them with a silent black-hole and no error message), we
	// complete the TLS+H2 handshake so they CAN fetch the config bundle
	// (which carries a NotificationEntry explaining the situation). The H2
	// handler then refuses CONNECT with HTTP 402 — opaque to passive
	// observers since it lives inside the encrypted H2 stream.
	DataPlaneBlocked bool
}

// NewServer creates a new Samizdat server.
func NewServer(config ServerConfig) (*Server, error) {
	config.applyDefaults()

	if len(config.PrivateKey) != 32 {
		return nil, fmt.Errorf("PrivateKey must be exactly 32 bytes, got %d", len(config.PrivateKey))
	}
	// MasterShortID is required ONLY for embedded callers without a userdb
	// (ServerDBPath==""). Production servers run with the panel's userdb
	// and accept any user.master_shortid; the legacy global MasterShortID
	// is irrelevant. Multi-user-cleanup operator policy: shortIDs ONLY in
	// the users table; NO global master_shortid identity field.
	var zeroShortID [8]byte
	if config.MasterShortID == zeroShortID && config.ServerDBPath == "" {
		return nil, fmt.Errorf("MasterShortID is required when ServerDBPath is empty")
	}
	if config.Handler == nil && config.HandlerWithIdentity == nil {
		return nil, fmt.Errorf("Handler or HandlerWithIdentity is required")
	}

	_, serverPubKey, err := derivePublicKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("deriving server public key: %w", err)
	}

	// Pre-load cert so auth-success path does not pay a disk read.
	var cached *tls.Certificate
	if len(config.CertPEM) > 0 && len(config.KeyPEM) > 0 {
		cert, cerr := tls.X509KeyPair(config.CertPEM, config.KeyPEM)
		if cerr != nil {
			return nil, fmt.Errorf("loading TLS certificate: %w", cerr)
		}
		cached = &cert
	}

	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		config:                 config,
		serverPubKey:           serverPubKey,
		cachedCert:             cached,
		shaper:                 NewShaper(false, 0),
		fragmenter:             NewRecordFragmenter(config.RecordFragmentation),
		replayGuard:            newReplayGuard(config.ReplayWindow),
		shortIDLimiter:         newShortIDLimiter(),
		h2StreamTracker:        newUserH2StreamTracker(),
		userRelayStreamTracker: newUserH2StreamTracker(),
		outboundStreamTracker:  newOutboundStreamTracker(),
		turnCredsProvider:      config.TURNCredsProvider,
		ctx:                    ctx,
		cancel:                 cancel,
	}

	// Optional shape-event-log: per-stream open/close events with the
	// authenticated client identity. Off by default (empty path). The writer
	// rotates by size (rotatingWriter) so the file cannot grow unbounded.
	if config.ShapeEventLogPath != "" {
		w, ferr := openRotatingWriter(config.ShapeEventLogPath, config.ShapeEventLogMaxBytes, config.ShapeEventLogMaxBackups)
		if ferr != nil {
			return nil, fmt.Errorf("open shape-event-log %q: %w", config.ShapeEventLogPath, ferr)
		}
		s.shapeEventOut = w
	}

	// Aparecium audit fix: pad cert chain to ~3.5 KB extra so encrypted
	// Certificate flight in TLS 1.3 handshake matches the size of a real
	// CDN cert chain (e.g. ok.ru â GlobalSign chain ~4 KB DER). Without
	// padding our self-signed single cert (~1 KB) gives a passive size-based
	// detector signal even though TLS 1.3 encrypts cert content.
	//
	// F-RR-2 / F-RR-3 / F-RR-4: skip padding when the operator has explicitly
	// opted out (DisableCertPadding) or when the natural chain already
	// meets/exceeds the target size. Real LE / commercial CA chains often
	// ship a leaf+intermediate that already crosses 4 KB, in which case
	// adding our dummy CA-style padding would produce a Frankenstein chain
	// (mixed real + synthetic certs). A 256-byte safety margin keeps a
	// marginally-sized natural chain on the padding side. Surface the
	// decision via expvar tamizdat.cert_padding.{applied,skipped_*} and
	// an INFO log when Debug=true.
	if cached != nil && len(cached.Certificate) > 0 {
		const targetExtraBytes = 4200
		const naturalChainSkipMargin = 256
		naturalSize := 0
		for _, der := range cached.Certificate {
			naturalSize += len(der)
		}
		switch {
		case config.DisableCertPadding:
			certPaddingSkippedDisabled.Add(1)
			s.logf("tamizdat: cert padding skipped (DisableCertPadding=true; natural chain %d bytes)", naturalSize)
		case naturalSize >= targetExtraBytes+naturalChainSkipMargin:
			certPaddingSkippedNatural.Add(1)
			s.logf("tamizdat: cert padding skipped (natural chain %d bytes >= %d target+margin)", naturalSize, targetExtraBytes+naturalChainSkipMargin)
		default:
			padded, perr := padCertChain(cached.Certificate, targetExtraBytes, 3)
			if perr == nil {
				cached.Certificate = padded
				certPaddingApplied.Add(1)
				paddedSize := 0
				for _, der := range padded {
					paddedSize += len(der)
				}
				s.logf("tamizdat: cert padding applied (natural %d bytes -> padded %d bytes)", naturalSize, paddedSize)
			} else {
				certPaddingErrors.Add(1)
				s.logf("tamizdat: cert padding failed: %v (keeping natural %d-byte chain)", perr, naturalSize)
			}
			// On padding failure (rsa.GenerateKey error etc.) we silently keep
			// the un-padded chain rather than fail server startup. Detection
			// risk degrades gracefully.
		}
	}

	s.masqLimiter = newMasqueradeRateLimiter()

	if err := s.initCoverConfig(config); err != nil {
		return nil, err
	}

	if config.MasqueradeDomain != "" {
		s.masquerade = NewMasquerade(
			config.MasqueradeDomain,
			config.MasqueradeAddr,
			config.MasqueradeIdleTimeout,
			config.MasqueradeMaxDuration,
		)

		// review-A P3: pre-warm a small bank of TCP conns to each origin
		// in the masquerade pool so the auth-fail path can skip the SYN
		// RTT for the first few probes per minute. Skipped when the
		// operator (or test harness) explicitly disables prewarm via
		// DisableMasqueradePrewarm.
		if !config.DisableMasqueradePrewarm {
			s.masqPrewarm = newPrewarmedPool(3, 30*time.Second, nil)
			registered := make(map[string]struct{})
			registerOrigin := func(target string) {
				if target == "" {
					return
				}
				if _, _, err := net.SplitHostPort(target); err != nil {
					target = net.JoinHostPort(target, "443")
				}
				if _, dup := registered[target]; dup {
					return
				}
				registered[target] = struct{}{}
				s.masqPrewarm.Register(target)
			}
			// Default origin: prefer explicit MasqueradeAddr, else MasqueradeDomain:443.
			if config.MasqueradeAddr != "" {
				registerOrigin(config.MasqueradeAddr)
			} else {
				registerOrigin(config.MasqueradeDomain)
			}
			for _, origin := range config.MasqueradePool {
				registerOrigin(origin)
			}
			s.masquerade.DialOrigin = func(ctx context.Context, addr string) (net.Conn, error) {
				return s.masqPrewarm.Take(ctx, addr)
			}
		}
	}

	if config.ServerDBPath != "" {
		db, derr := obreg.OpenSQLite(config.ServerDBPath)
		if derr != nil {
			return nil, fmt.Errorf("open server outbound db %q: %w", config.ServerDBPath, derr)
		}
		s.outboundDB = db

		if !config.DisableOutboundRegistry {
			registry := obreg.NewRegistry(newOutboundClientFromConfig)
			if derr := registry.Reload(db); derr != nil {
				_ = db.Close()
				return nil, fmt.Errorf("load server outbounds from %q: %w", config.ServerDBPath, derr)
			}
			s.outboundRegistry = registry
		}

		// Phase 2: bring up the userdb schema, run the legacy shortid.hex
		// migration if applicable, build the in-memory user registry, and
		// start the per-user accounting flush goroutine. All steps are
		// idempotent + survive empty databases.
		if err := userdb.EnsureSchema(db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("ensure userdb schema: %w", err)
		}
		s.startH2PeakPersister()
		legacyPath := config.LegacyShortIDPath
		if legacyPath == "" {
			legacyPath = userdb.DefaultLegacyShortIDPath
		}
		if _, err := userdb.BootstrapLegacyShortID(db, legacyPath); err != nil {
			log.Printf("WARN userdb legacy bootstrap from %q: %v", legacyPath, err)
		}
		userReg := userdb.NewRegistry(0)
		if err := userReg.Reload(db); err != nil {
			log.Printf("WARN userdb registry reload: %v", err)
		}
		acc := userdb.NewAccounting(db)
		s.userRegistry = userReg
		s.accounting = acc
		s.connTracker = newUserConnTracker()
		s.rateLimits = newUserRateLimiters()
		// Seed the per-user rate-limit map from the freshly-loaded users so
		// boot-time clients are throttled from their first byte.
		for _, u := range userReg.Snapshot() {
			s.rateLimits.setMbps(u.ID, u.RateLimitMbps)
		}

		// Wire per-outbound byte accounting into the registry so every
		// dialed conn flowing through a leased dialer is counted under
		// its resolved tag. The Accounting satisfies obreg.Recorder via
		// AddOutbound(tag, up, down). Tests that don't set up a Registry
		// silently skip this (Recorder nil = no accounting).
		if s.outboundRegistry != nil {
			s.outboundRegistry.SetRecorder(acc)
		}

		// Helper: refresh the "bytes left before cap" budget for one user.
		// Called at boot (for every user with cap), after each Flush, and
		// after a SIGHUP userdb reload (Reset Quota changes baseline).
		refreshRemaining := func(userID string) {
			var bUp, bDown, baseline, cap0 int64
			err := db.QueryRow(
				`SELECT bytes_up, bytes_down, COALESCE(quota_baseline, 0), COALESCE(bandwidth_cap, 0) FROM users WHERE id=?`,
				userID,
			).Scan(&bUp, &bDown, &baseline, &cap0)
			if err != nil {
				return
			}
			if cap0 <= 0 {
				acc.SetUserRemaining(userID, -1) // unlimited
				return
			}
			used := bUp + bDown - baseline
			if used < 0 {
				used = 0
			}
			remaining := cap0 - used
			if remaining < 0 {
				remaining = 0
			}
			acc.SetUserRemaining(userID, remaining)
		}

		// Fast-path overrun hook (fires inside Accounting.Add the moment a
		// byte delta drives the user's remaining-budget to <=0). At
		// speedtest speeds the 1s flush window would otherwise leak
		// 50+ MB past cap; this hook fires within microseconds. The work
		// is delegated to a goroutine so Add stays cheap.
		acc.SetOnOverrun(func(userID string) {
			go func() {
				n := s.connTracker.KillUser(userID)
				if n > 0 {
					log.Printf("[tamizdat] quota: user %s over cap (in-Add fast path) — killed %d active connection(s)", userID, n)
					_, _ = db.Exec(`UPDATE users SET notification_pending=1, updated_at=? WHERE id=?`, time.Now().Unix(), userID)
				}
			}()
		})

		// Slow-path flush hook (post-commit DB ground truth). Catches any
		// overrun the in-Add path missed during a brief race (e.g. user
		// with cap=0→cap=N transition mid-Flush) and refreshes the
		// remaining-budget cache so the next window is correctly seeded.
		acc.SetOnFlushUser(func(userID string, _, _ int64) {
			if userID == "" {
				return
			}
			refreshRemaining(userID)
			var bUp, bDown, baseline, cap0 int64
			err := db.QueryRow(
				`SELECT bytes_up, bytes_down, COALESCE(quota_baseline, 0), COALESCE(bandwidth_cap, 0) FROM users WHERE id=?`,
				userID,
			).Scan(&bUp, &bDown, &baseline, &cap0)
			if err != nil || cap0 <= 0 {
				return
			}
			used := bUp + bDown - baseline
			if used < 0 {
				used = 0
			}
			if used < cap0 {
				return
			}
			n := s.connTracker.KillUser(userID)
			if n > 0 {
				log.Printf("[tamizdat] quota: user %s over cap (post-flush) — used=%d cap=%d baseline=%d — killed %d active connection(s)", userID, used, cap0, baseline, n)
				_, _ = db.Exec(`UPDATE users SET notification_pending=1, updated_at=? WHERE id=?`, time.Now().Unix(), userID)
			}
		})

		// Seed the remaining-budget cache at boot for every user with
		// BandwidthCap>0. Users without cap get -1 (unlimited) so the
		// Add-time check skips them.
		for _, u := range userReg.Snapshot() {
			refreshRemaining(u.ID)
		}

		// 1s flush interval. The DB write is a single batched
		// transaction per window — for a small handful of active users
		// this is well within SQLite's headroom. The tighter cadence
		// also makes the panel "burned" tag and the post-flush hook
		// react within ~1s of the in-Add fast path missing anything.
		userdbCtx, userdbCancel := context.WithCancel(context.Background())
		acc.Start(userdbCtx, 1*time.Second)
		s.userdbCancel = userdbCancel
		s.startUserRegistryReloader(1 * time.Second)
	}

	if config.Debug {
		if err := s.startDebugExpvar(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func newOutboundClientFromConfig(cfg configurl.Config) (obreg.Client, error) {
	client, err := NewClient(ClientConfig{
		ServerAddr:     cfg.ServerAddr,
		PrimarySNI:     cfg.ServerName,
		ServerName:     cfg.ServerName,
		ServerNames:    cfg.ServerNames,
		PublicKey:      cfg.PublicKey,
		MasterShortID:  cfg.MasterShortID,
		Fingerprint:    cfg.Fingerprint,
		BootstrapSNI:   cfg.BootstrapSNI,
		ConnectTimeout: 10 * time.Second,
		IdleTimeout:    5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Server) initCoverConfig(config ServerConfig) error {
	poolVariant := normalizePoolVariant(config.InboundPoolVariant)
	if config.CoverConfigPath == "" {
		bundle := &CoverConfigBundle{Version: 1, PoolVariant: poolVariant}
		if minT, maxT := poolBoundsForVariant(poolVariant); minT > 0 || maxT > 0 {
			bundle.MinTransports = minT
			bundle.MaxTransports = maxT
		}
		wire, err := bundle.MarshalForWire()
		if err != nil {
			s.coverConfigJSON = []byte(`{"version":1}`)
		} else {
			s.coverConfigJSON = wire
		}
		s.coverConfigBundle = bundle
		s.coverConfigETag = bundle.ETag()
		return nil
	}
	// Shortid full-B simplification (2026-05-09): epoch_key + shortid_pool_size
	// fields are deprecated in cover_config bundle (no rotation; each user has
	// 1 master_shortid). LoadCoverConfigWithMasquerade still parses the legacy
	// fields tolerantly for backward-compat with existing on-disk bundles, but
	// the server no longer uses them. Only sni_pool / cover_targets / gaps are
	// active. CoverConfigPreviousPath has been dropped from ServerConfig.
	bundle, err := LoadCoverConfigWithMasquerade(config.CoverConfigPath, config.MasqueradePool)
	if err != nil {
		return fmt.Errorf("load cover config: %w", err)
	}
	// Server-pushes-pool (2026-05-09): when an operator hasn't set
	// ttl_seconds in the on-disk bundle, default it from ServerConfig.BundleTTL
	// so a fresh tamizdat-server (without bundle JSON edits) still advertises
	// a sensible cache lifetime. Operator-supplied ttl_seconds wins.
	if config.BundleTTL > 0 && bundle.TTLSeconds == 0 {
		bundle.TTLSeconds = int(config.BundleTTL.Seconds())
	}
	// Pool variant from server settings (2026-05-11). On-disk bundle JSON
	// can also carry pool_variant; ServerConfig.InboundPoolVariant wins
	// when non-empty so the panel toggle is the source of truth.
	if poolVariant != "" {
		bundle.PoolVariant = poolVariant
		if minT, maxT := poolBoundsForVariant(poolVariant); minT > 0 || maxT > 0 {
			bundle.MinTransports = minT
			bundle.MaxTransports = maxT
		}
	}
	wire, err := bundle.MarshalForWire()
	if err != nil {
		return err
	}
	s.coverConfigBundle = bundle
	s.coverConfigJSON = wire
	s.coverConfigETag = bundle.ETag()
	return nil
}

// normalizePoolVariant returns "v1"/"v2"/"v3" for any recognised value,
// "v1" for empty input, "" for anything else (treated as no-op).
func normalizePoolVariant(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "v1", "":
		return "v1"
	case "v2":
		return "v2"
	case "v3":
		return "v3"
	}
	return ""
}

// poolBoundsForVariant maps the legacy pool-variant knob to exact H2 transport
// bounds. The user-specific transport dropdown uses exact min=max counts, but
// the old global variant seam still needs to produce a concrete pool size.
func poolBoundsForVariant(v string) (int, int) {
	switch normalizePoolVariant(v) {
	case "v1", "":
		return 1, 1
	case "v2":
		return 1, 2
	case "v3":
		return 2, 4
	default:
		return 1, 1
	}
}

// serveConfigBundle serves the server-pushed config bundle at the magic
// CONNECT authority `tamizdat-config.invalid:443`. It accepts CONNECT (full
// body) and HEAD (ETag-only) so a long-lived client can cheaply check
// whether its on-disk bundle is still fresh without re-fetching the body.
// The handler is gated by ServerConfig.BundleEnabled; when disabled the
// server returns the static `{"version":1}` body so clients fall back to
// URI-supplied sni/fp.
//
// Stage 3 (2026-05-10): when the authenticated user has
// users.notification_pending=1, a per-user CoverConfigBundle.Notification
// is injected and the pending flag is cleared after the body is written.
// Users without a pending notification get the cached body (no per-request
// marshal cost). The notification path deliberately bypasses ETag/304 so a
// notification waiting for one fetch lands the next time the client polls
// (even if its cached ETag matches the static body).
func (s *Server) serveConfigBundle(w http.ResponseWriter, r *http.Request, identity authIdentity) {
	switch r.Method {
	case http.MethodConnect, http.MethodHead, http.MethodGet:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := s.coverConfigJSON
	etag := s.coverConfigETag
	hasNotification := false
	hasTURNProfile := false

	// Fetch current VK TURN credentials (nil when disabled or not
	// yet available). When present we must always take the dynamic
	// marshal path because the credentials change independently of
	// the static bundle ETag.
	var turnCreds *TURNCredsEntry
	if s.turnCredsProvider != nil {
		turnCreds = s.turnCredsProvider.CurrentTURNCreds()
	}

	if s.config.BundleEnabled && s.coverConfigBundle != nil && (s.coverConfigBundle.TTLSeconds > 0 || turnCreds != nil) {
		// Re-marshal to inject a fresh expires_at and/or TURN creds.
		// Static fields (ETag input) stay unchanged so the cached
		// ETag is still valid for non-TURN-aware clients.
		clone := *s.coverConfigBundle
		clone.TURNCreds = turnCreds
		if dynamic, err := clone.MarshalForWireWithExpiry(time.Now()); err == nil {
			body = dynamic
		}
		// When TURN creds are present, suppress ETag so the client
		// always gets fresh credentials on each fetch.
		if turnCreds != nil {
			etag = ""
		}
	}
	if !s.config.BundleEnabled {
		body = []byte(`{"version":1}`)
		etag = `"disabled"`
	}
	// Per-user bundle fields, such as exact H2 transport count, must be
	// present on every authenticated bundle fetch. Notification is a separate
	// optional overlay; tying transport sizing to notification_pending would
	// leave normal users stuck on the global default.
	if s.config.BundleEnabled && identity.UserID != "" {
		perUser := s.buildPerUserBundle(identity, time.Now())
		if s.outboundDB != nil {
			// Phase C (2026-05-10): DataPlaneBlocked users (over_quota/expired
			// who reach the bundle endpoint via the new no-masquerade path)
			// ALWAYS get a notification on every fetch, regardless of the
			// pending flag. Pending=1 fires for manual operator-pushed
			// notifications too.
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			pending, err := userdb.GetNotificationPending(ctx, s.outboundDB, identity.UserID)
			cancel()
			if identity.DataPlaneBlocked || (err == nil && pending) {
				s.attachNotification(perUser, identity, time.Now())
				hasNotification = true
			}
		}
		if s.attachTURNProfile(perUser, identity) {
			hasTURNProfile = true
		}
		if wire, err := perUser.MarshalForWire(); err == nil {
			body = wire
			etag = perUser.ETag()
			if hasNotification || hasTURNProfile {
				// Do not let clients cache a one-shot dynamic body; the next
				// poll should get the normal per-user bundle again.
				etag = ""
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if s.config.BundleEnabled && s.coverConfigBundle != nil && s.coverConfigBundle.TTLSeconds > 0 && !hasNotification && !hasTURNProfile {
		// SPP-FU-4: gate Cache-Control on BundleEnabled for consistency with
		// the body emission. When the bundle is disabled the body is the
		// static `{"version":1}` placeholder; advertising a TTL for that
		// would just confuse caching middlemen. Also suppress max-age when a
		// notification is in flight so the client re-polls promptly.
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", s.coverConfigBundle.TTLSeconds))
	}
	if !hasNotification && !hasTURNProfile && s.config.BundleEnabled && r.Header.Get("If-None-Match") != "" && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	// Clear the pending flag AFTER the body is written so a write failure
	// keeps the notification queued for the next fetch. The clear runs even
	// on HEAD-with-notification because HEAD signals the client has at
	// least observed-the-server-wants-to-tell-me-something semantics; the
	// next CONNECT will still see body=cached (no notification re-send).
	// Use a fresh context so a HUP-cancellation doesn't strand the flag set.
	if hasNotification {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if cerr := userdb.ClearNotificationPending(ctx, s.outboundDB, identity.UserID, time.Now().Unix()); cerr != nil {
			s.logf("[tamizdat] bundle: clear notification_pending for user=%s: %v", identity.UserID, cerr)
		}
		cancel()
	}
	if hasTURNProfile {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if cerr := userdb.ClearTurnProfilePending(ctx, s.outboundDB, identity.UserID, time.Now().Unix()); cerr != nil {
			s.logf("[tamizdat] bundle: clear turn_profile_pending for user=%s: %v", identity.UserID, cerr)
		}
		cancel()
	}
}

// buildPerUserBundle returns a copy of the global cover-config bundle with
// per-user transport sizing overlaid.
func (s *Server) buildPerUserBundle(identity authIdentity, now time.Time) *CoverConfigBundle {
	var base CoverConfigBundle
	if s.coverConfigBundle != nil {
		base = *s.coverConfigBundle
	} else {
		base.Version = 1
	}
	if base.TTLSeconds > 0 {
		base.ExpiresAt = now.Add(time.Duration(base.TTLSeconds) * time.Second).Unix()
	}
	if s.userRegistry != nil {
		if user, ok := s.userRegistry.User(identity.UserID); ok {
			if pool := user.PoolSize; pool > 0 {
				base.MinTransports = pool
				base.MaxTransports = pool
			} else if minT, maxT := poolBoundsForVariant(base.PoolVariant); minT > 0 || maxT > 0 {
				base.MinTransports = minT
				base.MaxTransports = maxT
			}
		}
	}
	return &base
}

// attachTURNProfile mutates bundle to include a panel-staged per-user TURN
// profile update. It returns true when a pending profile was attached.
func (s *Server) attachTURNProfile(bundle *CoverConfigBundle, identity authIdentity) bool {
	if bundle == nil || s.userRegistry == nil || identity.UserID == "" {
		return false
	}
	user, ok := s.userRegistry.User(identity.UserID)
	if !ok || user == nil || !user.TurnProfilePending {
		return false
	}
	roomLink := strings.TrimSpace(user.TurnRoomLink)
	roomHash := strings.TrimSpace(user.TurnRoomHash)
	if roomLink == "" && roomHash == "" {
		return false
	}
	bundle.TURNProfile = &TURNProfileEntry{
		Version:    user.TurnProfileVersion,
		Provider:   "vk",
		RoomLink:   roomLink,
		RoomHash:   roomHash,
		WGTurnPort: s.wgturnPublicPort(),
	}
	return true
}

func (s *Server) wgturnPublicPort() int {
	if s == nil || s.outboundDB == nil {
		return 0
	}
	listen := strings.TrimSpace(userdb.GetSetting(s.outboundDB, "wgturn_listen", ""))
	if listen == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Accept the common shorthand ":5000" / "5000".
		port = strings.TrimPrefix(listen, ":")
		if i := strings.LastIndex(port, ":"); i >= 0 {
			port = port[i+1:]
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// attachNotification mutates bundle to include a per-user Notification entry
// for notification_pending / data-plane-blocked callers.
//
// Body resolution priority (Phase C iOS-notify pipeline, 2026-05-10):
//  1. user.NotificationText is non-empty → operator-supplied message wins.
//     Code is "admin_broadcast" when prefixed with "BROADCAST: ", else
//     "admin_message".
//  2. Server-detected cause (expired / quota_exhausted) → localized RU body.
//  3. Generic "notification_pending" fallback.
//
// Code is stable across versions so iOS-side rendering can localize or
// branch per cause.
func (s *Server) attachNotification(bundle *CoverConfigBundle, identity authIdentity, now time.Time) {
	if bundle == nil {
		return
	}
	code := "notification_pending"
	title := "Уведомление"
	body := "Сервер запросил отображение системного уведомления."
	if s.userRegistry != nil {
		if user, ok := s.userRegistry.User(identity.UserID); ok {
			// (1) Operator-supplied text wins when set.
			if txt := strings.TrimSpace(user.NotificationText); txt != "" {
				const broadcastPrefix = "BROADCAST: "
				if strings.HasPrefix(txt, broadcastPrefix) {
					code = "admin_broadcast"
					title = "Сообщение администратора"
					body = strings.TrimPrefix(txt, broadcastPrefix)
				} else {
					code = "admin_message"
					title = "Сообщение администратора"
					body = txt
				}
			} else {
				// (2) Server-detected cause.
				switch {
				case user.ExpiresAt > 0 && user.ExpiresAt < now.Unix():
					code = "expired"
					title = "Срок действия истёк"
					body = "Срок действия вашей учётной записи истёк. Обратитесь к администратору."
				case s.userRegistry.IsOverQuota(user):
					code = "quota_exhausted"
					title = "Квота исчерпана"
					body = "Лимит трафика исчерпан. Обратитесь к администратору для сброса."
				}
			}
		}
	}
	bundle.Notification = &NotificationEntry{
		Code:   code,
		Title:  title,
		Body:   body,
		Locale: "ru",
	}
	// Inject TURN credentials into per-user bundles too.
	if s.turnCredsProvider != nil {
		bundle.TURNCreds = s.turnCredsProvider.CurrentTURNCreds()
	}
}

// logf is a debug-gated wrapper around log.Printf. Production servers run
// with Debug=false so that CONNECT destinations, drain transitions, and
// recovered-panic traces never make it to disk - those logs are a forensic
// goldmine and a side channel that differentiates the authenticated path
// from the masquerade path.
func (s *Server) logf(format string, args ...any) {
	if s.config.Debug {
		log.Printf(format, args...)
	}
}

func (s *Server) startDebugExpvar() error {
	initTelemetry()
	initReplayExpvars()
	s.publishUserExpvars()
	s.publishOutboundExpvars()
	addr := s.config.DebugListenAddr
	if addr == "" {
		addr = "127.0.0.1:6060"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("debug expvar listen on %s: %w", addr, err)
	}
	srv := &http.Server{Handler: http.DefaultServeMux}
	s.debugMu.Lock()
	s.debugListener = ln
	s.debugServer = srv
	s.debugMu.Unlock()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logf("[tamizdat] debug expvar server: %v", err)
		}
	}()
	return nil
}

func (s *Server) debugAddr() net.Addr {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	if s.debugListener == nil {
		return nil
	}
	return s.debugListener.Addr()
}

// ListenAndServe creates a TCP listener on the configured ListenAddr.
func (s *Server) ListenAndServe() error {
	if s.config.ListenAddr == "" {
		return fmt.Errorf("ListenAddr is required")
	}
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.config.ListenAddr, err)
	}
	return s.Serve(ln)
}

// Serve accepts connections on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				return fmt.Errorf("accepting connection: %w", err)
			}
		}

		if err := setAcceptedConnDelayedAck(conn); err != nil {
			s.logf("setting TCP delayed ACK on accepted connection: %v", err)
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// Close shuts down the server.
func (s *Server) Close() error {
	s.cancel(ErrServerClosed)
	s.shapeEventMu.Lock()
	if s.shapeEventOut != nil {
		_ = s.shapeEventOut.Close()
		s.shapeEventOut = nil
	}
	s.shapeEventMu.Unlock()
	s.listenerMu.Lock()
	ln := s.listener
	s.listenerMu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.debugMu.Lock()
	debugServer := s.debugServer
	s.debugMu.Unlock()
	if debugServer != nil {
		if derr := debugServer.Close(); err == nil && derr != nil && !errors.Is(derr, http.ErrServerClosed) {
			err = derr
		}
	}
	// MED-4: actively terminate in-flight TCP connections so handleConnection
	// goroutines unblock from Read and wg.Wait() can return. Without this,
	// SIGINT-driven shutdown hangs until every TCP peer FINs (or never).
	s.activeConns.Range(func(k, _ any) bool {
		if c, ok := k.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
	if s.masqLimiter != nil {
		s.masqLimiter.close()
	}
	if s.masqPrewarm != nil {
		_ = s.masqPrewarm.Close()
	}
	if s.vkTurnServer != nil {
		_ = s.vkTurnServer.Close()
	}
	s.wg.Wait()
	if s.userdbCancel != nil {
		s.userdbCancel()
	}
	if s.accounting != nil {
		if ferr := s.accounting.Flush(); err == nil && ferr != nil {
			err = ferr
		}
	}
	if s.outboundRegistry != nil {
		if cerr := s.outboundRegistry.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}
	if s.outboundDB != nil {
		if derr := s.outboundDB.Close(); err == nil && derr != nil {
			err = derr
		}
	}
	return err
}

// Addr returns the server's listen address.
func (s *Server) Addr() net.Addr {
	s.listenerMu.Lock()
	ln := s.listener
	s.listenerMu.Unlock()
	if ln != nil {
		return ln.Addr()
	}
	return nil
}

func (s *Server) fragPoCTransport() (*fragpoc.Server, error) {
	s.fragPoCOnce.Do(func() {
		downReadTimeout := s.config.FragPoCDownReadTimeout
		if downReadTimeout <= 0 {
			downReadTimeout = 500 * time.Millisecond
		}
		s.fragPoCServer, s.fragPoCErr = fragpoc.NewServer(fragpoc.ServerConfig{
			ShortID:    s.config.MasterShortID,
			MaxPayload: s.config.FragPoCMaxPayload,
			Authorize: func(shortID [fragpoc.ShortIDLen]byte) bool {
				return s.fragPoCAuthorize(shortID)
			},
			Handler: func(ctx context.Context, conn net.Conn, destination string, shortID [fragpoc.ShortIDLen]byte) {
				defer conn.Close()
				identity, ok := s.fragPoCIdentity(shortID)
				if !ok {
					return
				}
				var untrackConn func()
				if identity.UserID != "" && s.connTracker != nil {
					untrackConn = s.connTracker.Track(identity.UserID, func() {
						_ = conn.Close()
					})
				}
				if identity.UserID != "" && identity.SessionID != "" && s.outboundDB != nil {
					defer func() {
						if err := userdb.EndSession(s.outboundDB, identity.UserID, identity.SessionID); err != nil {
							s.logf("[tamizdat] fragpoc EndSession failed: %v", err)
						}
					}()
				}
				if untrackConn != nil {
					defer untrackConn()
				}
				if strings.HasPrefix(destination, fragpoc.UDPDestinationPrefix) {
					udpDestination := strings.TrimPrefix(destination, fragpoc.UDPDestinationPrefix)
					s.logShapeEvent(fmt.Sprintf("stream_open client=%s shortid=%x user=%s session=%s dst=%s proto=fragpoc-udp",
						conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, udpDestination))
					defer s.logShapeEvent(fmt.Sprintf("stream_close client=%s shortid=%x user=%s session=%s dst=%s proto=fragpoc-udp",
						conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, udpDestination))
					s.handleFragPoCUDP(ctx, conn, udpDestination, identity)
					return
				}
				s.logShapeEvent(fmt.Sprintf("stream_open client=%s shortid=%x user=%s session=%s dst=%s proto=fragpoc",
					conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, destination))
				defer s.logShapeEvent(fmt.Sprintf("stream_close client=%s shortid=%x user=%s session=%s dst=%s proto=fragpoc",
					conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, destination))
				s.handleTCPConnect(ctx, conn, destination, identity)
			},
			DownReadTimeout:     downReadTimeout,
			OperationTimeout:    10 * time.Second,
			SessionTTL:          90 * time.Second,
			SessionReapInterval: 10 * time.Second,
			PortHintHandler: func(shortID [fragpoc.ShortIDLen]byte, requestedPorts []int) []int {
				if s.fragPoCPortManager == nil {
					return nil
				}
				return s.fragPoCPortManager.RequestPorts(requestedPorts)
			},
		})
	})
	return s.fragPoCServer, s.fragPoCErr
}

// SetFragPoCPortManager attaches the dynamic port manager so the FragPoC
// server can handle OpPortHint requests from clients. Must be called before
// any ServeFragPoC if port-hint support is desired.
func (s *Server) SetFragPoCPortManager(mgr *FragPoCPortManager) {
	s.fragPoCPortManager = mgr
}

// ServeFragPoC serves the plain fragmented TCP proof-of-concept transport on
// ln. This is intentionally separate from the production H2/TLS listener: it
// exists to validate the short-TCP transport shape before enabling same-port
// demux on the primary listener.
func (s *Server) ServeFragPoC(ln net.Listener) error {
	fp, err := s.fragPoCTransport()
	if err != nil {
		return err
	}
	return fp.Serve(s.ctx, ln)
}

// FragPoCSessionCount returns the live FragPoC session count, or 0 when the
// FragPoC transport has not been initialised. It feeds the dynamic
// port-manager's load signal.
func (s *Server) FragPoCSessionCount() int {
	fp, err := s.fragPoCTransport()
	if err != nil || fp == nil {
		return 0
	}
	return fp.SessionCount()
}

func (s *Server) fragPoCAuthorize(shortID [fragpoc.ShortIDLen]byte) bool {
	if s.userRegistry != nil {
		_, user, ok := s.userRegistry.LookupBytes(shortID)
		if !ok {
			return false
		}
		now := time.Now().Unix()
		if user.ExpiresAt > 0 && now > user.ExpiresAt {
			return false
		}
		return !s.userRegistry.IsOverQuota(user)
	}
	return shortID == s.config.MasterShortID
}

func (s *Server) fragPoCIdentity(shortID [fragpoc.ShortIDLen]byte) (authIdentity, bool) {
	identity := authIdentity{ShortID: shortID, PoolIndex: -1}
	if s.userRegistry != nil {
		lk, user, ok := s.userRegistry.LookupBytes(shortID)
		if !ok {
			return identity, false
		}
		now := time.Now().Unix()
		if user.ExpiresAt > 0 && now > user.ExpiresAt {
			return identity, false
		}
		if s.userRegistry.IsOverQuota(user) {
			return identity, false
		}
		identity.UserID = lk.UserID
		identity.UserName = user.Name
		identity.PoolIndex = lk.PoolIndex
		if s.outboundDB != nil {
			if sid, err := userdb.GenerateHex(8); err == nil {
				identity.SessionID = sid
				if err := userdb.StartSession(s.outboundDB, identity.UserID, sid, identity.PoolIndex); err != nil {
					s.logf("[tamizdat] fragpoc StartSession failed: %v", err)
				}
			}
		}
		return identity, true
	}
	if shortID == s.config.MasterShortID {
		return identity, true
	}
	return identity, false
}

func (s *Server) vkTurnTransport() (*vkturn.Server, error) {
	s.vkTurnOnce.Do(func() {
		s.vkTurnServer, s.vkTurnErr = vkturn.NewServer(vkturn.ServerConfig{
			ShortID:         s.config.MasterShortID,
			MaxFramePayload: 1150,
			Authorize: func(shortID [vkturn.ShortIDLen]byte) bool {
				var sid [fragpoc.ShortIDLen]byte
				copy(sid[:], shortID[:])
				return s.fragPoCAuthorize(sid)
			},
			Handler: func(ctx context.Context, conn net.Conn, destination string, shortID [vkturn.ShortIDLen]byte) {
				defer conn.Close()
				var sid [fragpoc.ShortIDLen]byte
				copy(sid[:], shortID[:])
				identity, ok := s.fragPoCIdentity(sid)
				if !ok {
					return
				}
				var untrackConn func()
				if identity.UserID != "" && s.connTracker != nil {
					untrackConn = s.connTracker.Track(identity.UserID, func() { _ = conn.Close() })
				}
				if identity.UserID != "" && identity.SessionID != "" && s.outboundDB != nil {
					defer func() {
						if err := userdb.EndSession(s.outboundDB, identity.UserID, identity.SessionID); err != nil {
							s.logf("[tamizdat] vkturn EndSession failed: %v", err)
						}
					}()
				}
				if untrackConn != nil {
					defer untrackConn()
				}
				if strings.HasPrefix(destination, vkturn.UDPDestinationPrefix) {
					udpDestination := strings.TrimPrefix(destination, vkturn.UDPDestinationPrefix)
					s.logShapeEvent(fmt.Sprintf("stream_open client=%s shortid=%x user=%s session=%s dst=%s proto=vkturn-udp",
						conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, udpDestination))
					defer s.logShapeEvent(fmt.Sprintf("stream_close client=%s shortid=%x user=%s session=%s dst=%s proto=vkturn-udp",
						conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, udpDestination))
					s.handleFragPoCUDP(ctx, conn, udpDestination, identity)
					return
				}
				s.logShapeEvent(fmt.Sprintf("stream_open client=%s shortid=%x user=%s session=%s dst=%s proto=vkturn",
					conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, destination))
				defer s.logShapeEvent(fmt.Sprintf("stream_close client=%s shortid=%x user=%s session=%s dst=%s proto=vkturn",
					conn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, destination))
				s.handleTCPConnect(ctx, conn, destination, identity)
			},
		})
	})
	return s.vkTurnServer, s.vkTurnErr
}

// ServeVKTurn serves the VK-call TURN/DTLS relay transport on a UDP listen addr.
// The primary TLS/H2 listener remains unchanged; this is the FragPoC replacement
// for hostile networks where the client can only look like VK media traffic.
func (s *Server) ServeVKTurn(listenAddr string) error {
	vt, err := s.vkTurnTransport()
	if err != nil {
		return err
	}
	return vt.ListenAndServe(s.ctx, listenAddr)
}

func (s *Server) VKTurnSessionCount() int {
	vt, err := s.vkTurnTransport()
	if err != nil || vt == nil {
		return 0
	}
	return vt.SessionCount()
}

// handleConnection processes a new TCP connection:
// 1. Read the ClientHello (buffer raw bytes)
// 2. Attempt Samizdat auth verification
// 3. If auth passes: complete TLS handshake, enter H2 proxy mode
// 4. If auth fails or replayed: masquerade (forward to real domain)
func (s *Server) handleConnection(conn net.Conn) {
	// MED-4: register this conn so Close() can terminate it. Keep the
	// original TCP conn as the activeConns key even if PROXY protocol wrapping
	// replaces the local conn variable below.
	origConn := conn
	s.activeConns.Store(origConn, struct{}{})
	defer s.activeConns.Delete(origConn)
	safeIntAdd(connectTotal, 1)
	defer conn.Close()

	// PROXY protocol header strip. When the server is fronted by nginx
	// (`proxy_protocol on`) or haproxy (`send-proxy-v2`), each accepted TCP
	// connection is prefixed with a header carrying the real client IP/port.
	// We only honour the header when the upstream IP is in the trusted
	// whitelist; otherwise an attacker on a non-whitelisted path could spoof
	// their source IP and bypass per-IP rate limits.
	if s.config.ProxyProtocol {
		if !proxyproto.IsTrusted(conn.RemoteAddr(), s.config.ProxyProtocolTrusted) {
			log.Printf("INFO proxy-proto: untrusted upstream %s - closing", conn.RemoteAddr())
			return
		}
		real, reader, err := proxyproto.ReadHeader(conn, 5*time.Second)
		if err != nil {
			switch {
			case errors.Is(err, proxyproto.ErrNotPROXY):
				log.Printf("INFO proxy-proto: trusted upstream %s sent non-PROXY/raw TLS header - closing", conn.RemoteAddr())
			case errors.Is(err, proxyproto.ErrMalformed):
				log.Printf("WARN proxy-proto: malformed header from trusted upstream %s: %v", conn.RemoteAddr(), err)
			default:
				log.Printf("WARN proxy-proto: read header from trusted upstream %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		conn = proxyproto.Wrap(conn, real, reader)
	}

	if s.config.FragPoCSamePort {
		nextConn, handled := s.demuxFragPoCSamePort(conn)
		if handled {
			return
		}
		conn = nextConn
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientHelloRecord, handshakeMsg, err := readClientHelloRecord(conn)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	sessionID, err := ExtractSessionID(handshakeMsg)
	if err != nil {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	// Standard TLS-1.3 key_share auth (compass v2 §5.1 fully migrated; legacy
	// 0xFE0C extension path removed in compass v3 cleanup -- 24h+ soak passed).
	ephPub, err := ExtractX25519FromKeyShare(handshakeMsg)
	if err != nil {
		s.logf("[tamizdat] ephemeral pubkey extraction failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	if len(sessionID) != sessionIDLen {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	var shortID [shortIDLen]byte
	copy(shortID[:], sessionID[:shortIDLen])

	// review-D-2: per-shortid token-bucket rate limiter. Applied AFTER
	// the 8-byte SessionID prefix is parsed but BEFORE PSK derivation,
	// so a flooder spamming a single known shortID hits the bucket cap
	// before paying curve25519 cost. Random-shortID flooders pay one
	// bucket entry each, capped by the LRU at 65k entries (same memory
	// bound as replay_guard). Concurrent legitimate users on the same
	// upstream haproxy IP have distinct shortids -> distinct buckets,
	// so per-IP confusion (which a per-IP limiter would suffer because
	// PROXY-protocol passthrough is not configured) is avoided.
	//
	// On reject we route through handleReplayRejected (D-1) rather
	// than doMasquerade so the wire shape on rate-limit reject is
	// identical to the wire shape on replay reject -- a uniform "we
	// did the server-cert handshake, then closed" pattern regardless
	// of which auth-path branch tripped.
	if !s.shortIDLimiter.Allow(shortID) {
		safeIntAdd(connectShortIDLimited, 1)
		s.handleReplayRejected(conn, clientHelloRecord)
		return
	}

	// Timing-oracle hardening: derive and HMAC-check using the candidate
	// shortID unconditionally. Unknown-shortID probes and known-shortID/bad-tag
	// probes both pay the same expensive auth path.
	psk, err := DeriveServerPSK(s.config.PrivateKey, ephPub[:], shortID)
	if err != nil {
		s.logf("[tamizdat] deriving PSK failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	// C-2: drop the tautological allowlist (slice was always
	// [{shortID}] — first 8 bytes of sessionID are the only candidate).
	// C-1 phase 1: accept both v1 and v2 wire formats during the rollout
	// window gated by ServerConfig.{Min,Max}AcceptedWireVersion. The
	// returned matchedVersion is logged for migration observability;
	// upstream replay-key calculation is unchanged.
	matchedVersion, authenticated, err := VerifySessionIDAny(
		sessionID,
		psk,
		ephPub[:],
		shortID,
		s.config.MinAcceptedWireVersion,
		s.config.MaxAcceptedWireVersion,
	)
	if err != nil || !authenticated {
		s.logf("[tamizdat] SessionID verification failed: matched_version=%d err=%v", matchedVersion, err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	verifiedShortID := shortID
	_ = matchedVersion // observability hook; reserved for per-version expvar in a follow-up

	// Phase 2 multi-user identity: if the userdb registry is configured,
	// it owns the source-of-truth shortid → user mapping. Otherwise (embedded
	// callers without ServerDBPath) accept only the configured master shortid.
	//
	// Shortid full-B simplification (2026-05-09): HKDF derivation pool +
	// cover-config epoch_key rotation removed (~700 LoC dropped). Each user
	// has exactly one master_shortid; server checks value-equality. Operator
	// rotates by editing the DB row + restart/SIGHUP. Defense-in-depth claim
	// of the prior pool was theoretical against RU TSPU 2026 corpus and the
	// rotation channel was never exercised in production. See operator
	// decision in C:\var-tmp\spec-shortid-full-B-impl-opus.md.
	identity := authIdentity{ShortID: verifiedShortID, PoolIndex: -1}
	accepted := false
	if s.userRegistry != nil {
		if lk, user, ok := s.userRegistry.LookupBytes(verifiedShortID); ok {
			now := time.Now().Unix()
			expired := user.ExpiresAt > 0 && now > user.ExpiresAt
			overQuota := !expired && s.userRegistry.IsOverQuota(user)
			// Phase C iOS-notify pipeline (2026-05-10): when the bundle is
			// enabled, expired/over-quota users complete TLS+H2 so they can
			// fetch /tamizdat-config.invalid and receive a NotificationEntry
			// explaining why their app stopped working. The H2 handler then
			// refuses CONNECT with HTTP 402 (encrypted, opaque to passive
			// observers). When bundle disabled, fall back to the legacy
			// masquerade for wire-shape parity with "unknown shortid" probes.
			if expired {
				s.logf("[tamizdat] auth: user %q expired_at=%d now=%d", user.Name, user.ExpiresAt, now)
				if s.outboundDB != nil {
					if _, derr := s.outboundDB.Exec(`UPDATE users SET notification_pending=1, updated_at=? WHERE id=?`, now, user.ID); derr != nil {
						s.logf("[tamizdat] auth: notification_pending update failed: %v", derr)
					}
				}
				if !s.config.BundleEnabled {
					s.doMasquerade(conn, clientHelloRecord)
					return
				}
				identity.DataPlaneBlocked = true
			}
			if overQuota {
				s.logf("[tamizdat] auth: user %q over BandwidthCap=%d (used %d)", user.Name, user.BandwidthCap, user.BytesUp+user.BytesDown)
				if s.outboundDB != nil {
					if _, derr := s.outboundDB.Exec(`UPDATE users SET notification_pending=1, updated_at=? WHERE id=?`, now, user.ID); derr != nil {
						s.logf("[tamizdat] auth: notification_pending update failed: %v", derr)
					}
				}
				if !s.config.BundleEnabled {
					s.doMasquerade(conn, clientHelloRecord)
					return
				}
				identity.DataPlaneBlocked = true
			}
			identity.UserID = lk.UserID
			identity.UserName = user.Name
			identity.PoolIndex = lk.PoolIndex
			accepted = true
		}
	}
	// DEPRECATED master-shortid direct check (multi-user-cleanup, 2026-05-10):
	// fires ONLY when the userdb registry is unconfigured. Production (panel
	// + userdb wired) NEVER hits this branch because s.userRegistry is set
	// the moment ServerDBPath is non-empty. Kept here only so embedded
	// callers (in-process tests, library users without a SQLite path) can
	// still authenticate against ServerConfig.MasterShortID without setting
	// up a full userdb. Operator policy is "shortIDs ONLY in users table" —
	// honoured for every panel-managed deployment.
	if !accepted && s.userRegistry == nil && verifiedShortID == s.config.MasterShortID {
		accepted = true
	}
	if !accepted {
		s.logf("[tamizdat] auth: shortid %x not in user registry and != master", verifiedShortID[:])
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	// Replay check: reject duplicate SessionID+ephemeral-public-key tuples within the replay window.
	if s.replayGuard != nil {
		digest := sha256.New()
		digest.Write(sessionID)
		digest.Write(ephPub[:])
		var replayKey [replayKeyLen]byte
		copy(replayKey[:], digest.Sum(nil)[:replayKeyLen])
		if !s.replayGuard.checkV1(replayKey) {
			safeIntAdd(connectReplay, 1)
			// D-1: server-cert TLS handshake then abort, mirroring the
			// post-window path (where replay-guard accepts the captured
			// nonce because it has aged out of the window, then auth-OK
			// drops into handleAuthenticated whose tls.Server handshake
			// fails because the attacker has no matching ephemeral
			// private key). Splicing into doMasquerade here would emit
			// a different wire shape than the post-window path; an
			// adversary capturing one ClientHello and replaying it
			// twice (once <5min, once >5min) would observe two
			// distinct response shapes -- a state-leak side-channel.
			s.handleReplayRejected(conn, clientHelloRecord)
			return
		}
	}

	// Allocate a session id when we have a userdb-identified user. The
	// session_id is a per-handshake random nonce (not the TLS SessionID, to
	// avoid leaking auth state across the userdb→panel boundary).
	if identity.UserID != "" {
		sid, ferr := userdb.GenerateHex(8)
		if ferr == nil {
			identity.SessionID = sid
			if serr := userdb.StartSession(s.outboundDB, identity.UserID, sid, identity.PoolIndex); serr != nil {
				s.logf("[tamizdat] userdb StartSession failed: %v", serr)
			}
		}
	}

	safeIntAdd(connectAuthOK, 1)
	s.handleAuthenticated(conn, clientHelloRecord, identity)
}

func (s *Server) demuxFragPoCSamePort(conn net.Conn) (net.Conn, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return conn, true
	}
	_ = conn.SetReadDeadline(time.Time{})

	if (first[0] < fragpoc.OpOpen || first[0] > fragpoc.OpClose) &&
		(first[0] < fragpoc.OpOpenSecure || first[0] > fragpoc.OpCloseSecure) {
		return newReplayConn(conn, first[:]), false
	}

	fp, err := s.fragPoCTransport()
	if err != nil {
		s.logf("[tamizdat] fragpoc same-port init failed: %v", err)
		return conn, true
	}
	fp.ServeConn(s.ctx, newReplayConn(conn, first[:]))
	return conn, true
}

// doMasquerade forwards the connection to the real masquerade domain.
func (s *Server) doMasquerade(conn net.Conn, clientHelloRecord []byte) {
	if s.masquerade == nil {
		return
	}
	// compass v2 §3.11 + review-A P2: probabilistic per-IP rate-limit. The
	// limiter returns Forward / DropAfterJitter; jitter-drops hold the
	// connection ~200-800ms before closing so the timing of a rate-limited
	// drop matches an overloaded real backend rather than being a clean
	// cliff signal to a scanner. (A-RR-3 dropped the unused
	// RateLimitDropSilent enum value.)
	switch s.masqLimiter.decide(extractRemoteIP(conn)) {
	case RateLimitForward:
		// fall through to the masquerade forward below
	case RateLimitDropAfterJitter:
		safeIntAdd(masqRateLimited, 1)
		// Hold the connection so close timing isn't deterministic. The
		// caller's defer will then close conn.
		select {
		case <-time.After(jitterDelay()):
		case <-s.ctx.Done():
		}
		return
	}
	safeIntAdd(connectMasquerade, 1)
	// Cover-SNI rotation (compass P1.1, review-A P5): parse SNI from
	// buffered ClientHello, look up matching origin in MasqueradePool with
	// normalization (exact, www-stripped, suffix wildcard). Unknown SNI
	// falls back to the default origin.
	originDomain := ""
	if len(s.config.MasqueradePool) > 0 && len(clientHelloRecord) > 5 {
		// clientHelloRecord includes 5-byte TLS record header; strip it for handshake parser.
		if sni, err := parseSNIFromClientHello(clientHelloRecord[5:]); err == nil && sni != "" {
			if origin, ok := lookupMasqueradeOrigin(s.config.MasqueradePool, sni); ok {
				originDomain = origin
			}
		}
	}
	s.masquerade.ProxyConnectionWithOrigin(conn, clientHelloRecord, originDomain)
}

// handleReplayRejected handles a replay-rejected ClientHello with the same
// wire shape the post-window path naturally produces: server-cert TLS
// handshake driven from the buffered ClientHello, then abort. The
// attacker -- who replayed a captured ClientHello -- does not own the
// matching ephemeral private key, so HandshakeContext fails on
// ClientFinished decryption (or the server emits a TLS Alert and closes).
// The post-window path falls through to handleAuthenticated, which calls
// tls.Server.HandshakeContext on the same buffered ClientHello and ends
// up in the same state. Symmetric wire shape closes the review-D
// side-channel where in-window vs post-window replays diverged.
func (s *Server) handleReplayRejected(conn net.Conn, clientHelloRecord []byte) {
	if s.cachedCert == nil {
		return
	}
	// D-1 follow-up: mirror handleAuthenticated's shadow dial so the
	// wall-clock time-to-first-server-byte is symmetric across auth-OK
	// and replay-rejected paths. Without this, an attacker replaying a
	// captured ClientHello in-window vs replaying a fresh ClientHello
	// (auth-OK) could distinguish the two on RTT-to-first-record alone:
	// auth-OK would absorb the masquerade origin dial RTT but the
	// replay-rejected path would skip it and emit ServerHello sooner.
	if s.masquerade != nil {
		// Parse SNI from buffered ClientHello so the shadow dial hits the
		// same pool-mapped origin handleAuthenticated would have used
		// (review-A A-RR-2 parity).
		shadowSNI := ""
		if len(clientHelloRecord) > 5 {
			if sni, err := parseSNIFromClientHello(clientHelloRecord[5:]); err == nil {
				shadowSNI = sni
			}
		}
		s.shadowDialOrigin(s.ctx, shadowSNI)
	}
	replayConn := newReplayConn(conn, clientHelloRecord)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*s.cachedCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
		// Match handleAuthenticated's TLS config so the visible
		// post-handshake bytes (NewSessionTicket count etc.) are
		// identical to the post-window path.
		SessionTicketsDisabled: false,
	}
	tlsConn := tls.Server(replayConn, tlsConfig)
	// Bound the handshake; handleAuthenticated also relies on s.ctx
	// timing out for slow handshakes. Either ClientFinished decryption
	// fails (most common) or the attacker abandons -- either way we
	// close cleanly, mirroring post-window behaviour.
	_ = tlsConn.HandshakeContext(s.ctx)
	tlsConn.Close()
}

// shadowDialOrigin absorbs the masquerade origin TCP dial RTT on the
// authenticated path so active probes cannot distinguish auth-success from
// auth-fail purely by first-response timing. Dial failures are intentionally
// ignored: legitimate users must still proceed to the server TLS handshake
// when the cover origin is transiently unreachable, so the shadow dial is
// capped even if the masquerade dial timeout is larger.
//
// A-RR-2: when the buffered ClientHello carried an SNI that matches a
// MasqueradePool entry, the shadow dial targets THAT pool origin (not
// the default OriginAddr). Otherwise an authenticated probe with
// SNI=ya.ru would shadow-dial the default origin (e.g. ok.ru) while the
// failure path forwards to ya.ru — the resulting RTT divergence between
// success and failure paths is exactly Tell #1 (timing oracle) and
// undoes the value of the shadow dial. The pool lookup honours all the
// normalization rules in lookupMasqueradeOrigin (case-fold, www-strip,
// suffix wildcard).
func (s *Server) shadowDialOrigin(ctx context.Context, sni string) {
	m := s.masquerade
	if m == nil {
		return
	}
	addr := m.OriginAddr
	// A-RR-2: prefer pool-mapped origin for the probe SNI when known.
	if sni != "" && len(s.config.MasqueradePool) > 0 {
		if origin, ok := lookupMasqueradeOrigin(s.config.MasqueradePool, sni); ok {
			// Pool entries are typically bare hostnames; ProxyConnection
			// resolves origin == sni to host:443 via DNS so the shadow
			// dial uses the same JoinHostPort form for parity.
			if _, _, splitErr := net.SplitHostPort(origin); splitErr != nil {
				addr = net.JoinHostPort(origin, "443")
			} else {
				addr = origin
			}
		}
	}
	if addr == "" {
		if m.OriginDomain == "" {
			return
		}
		addr = ensureHostPort(m.OriginDomain, "443")
	}
	if addr == "" {
		return
	}
	timeout := m.DialTimeout
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	_ = conn.Close()
}

// handleAuthenticated completes the TLS handshake with the authenticated
// client and serves HTTP/2 CONNECT requests.
func (s *Server) handleAuthenticated(conn net.Conn, clientHelloRecord []byte, identity authIdentity) {
	// Register the conn with the per-user tracker so the post-flush quota
	// hook can force-close it when the user crosses BandwidthCap mid-
	// session. The tracker stores a closure that calls conn.Close(); the
	// underlying TCP teardown propagates as a stream RST through the
	// HTTP/2 server below, ending all active CONNECT streams for this
	// user. Untrack on return so the slot doesn't leak.
	var untrackConn func()
	if identity.UserID != "" && s.connTracker != nil {
		untrackConn = s.connTracker.Track(identity.UserID, func() {
			_ = conn.Close()
		})
	}
	defer func() {
		if untrackConn != nil {
			untrackConn()
		}
		// Tear down the userdb session row when the H2 connection ends so
		// "online" counters drop the moment a client disconnects.
		if identity.UserID != "" && identity.SessionID != "" && s.outboundDB != nil {
			if err := userdb.EndSession(s.outboundDB, identity.UserID, identity.SessionID); err != nil {
				s.logf("[tamizdat] userdb EndSession failed: %v", err)
			}
		}
	}()
	replayConn := newReplayConn(conn, clientHelloRecord)

	if s.cachedCert == nil {
		return
	}
	if s.masquerade != nil {
		// A-RR-2: parse SNI from the buffered ClientHello so the shadow
		// dial hits the same origin that the masquerade-forward path
		// would have used. Parse failures fall through to default origin.
		shadowSNI := ""
		if len(clientHelloRecord) > 5 {
			if sni, err := parseSNIFromClientHello(clientHelloRecord[5:]); err == nil {
				shadowSNI = sni
			}
		}
		s.shadowDialOrigin(s.ctx, shadowSNI)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*s.cachedCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
		// Aparecium NST mitigation v2 (compass deep-research v2 finding):
		// Earlier probe with OpenSSL ClientHello to ok.ru returned 0 NST, but
		// re-probe with real Chrome ClientHello (utls.HelloChrome_Auto) returns
		// ~40 bytes post-handshake = 1 small NST. Since samizdat uses utls
		// Chrome by default, the matching origin-pattern is Go's default 1 NST,
		// not zero. Leave SessionTicketsDisabled=false (default) so Go emits 1
		// NewSessionTicket after ClientFinished -- closes the Aparecium PoC's
		// "no NST after ClientFinished" detector.
		SessionTicketsDisabled: false,
	}

	tlsConn := tls.Server(replayConn, tlsConfig)
	hsStart := time.Now()
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		tlsConn.Close()
		return
	}

	handshakeDurationNanosSum.Add(int64(time.Since(hsStart)))
	handshakeDurationNanosCount.Add(1)
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return
	}

	s.serveH2(tlsConn, identity)
}

const serverH2MaxReadFrameSize = 64 << 10

func newServerH2(maxConcurrentStreams int) *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams: uint32(maxConcurrentStreams),
		// OPT-2: server-side H2 PING keepalive. golang.org/x/net/http2 server
		// sends PING after IdleTimeout of inactivity; if no PONG within
		// PingTimeout, server tears down the connection. Defends symmetrically
		// against NAT-table eviction and detects half-open connections.
		IdleTimeout:     60 * time.Second,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     10 * time.Second,
		// OPT-1: per-stream initial upload window so client uploads aren't
		// capped at default 64 KB. Also bump connection-level via
		// MaxUploadBufferPerConnection. Matches NaiveProxy/Hysteria tuning.
		MaxUploadBufferPerConnection: 16 << 20, // 16 MiB
		MaxUploadBufferPerStream:     4 << 20,  //  4 MiB
		// x/net/http2 clients reserve min(peer frame size, 512 KiB) for each
		// live request-body writer. Advertising 1 MiB therefore retained
		// roughly 512 KiB per proxied stream on upstream Tamizdat servers.
		// A 64 KiB frame keeps the generous flow-control windows above while
		// reducing that per-stream scratch allocation eightfold.
		MaxReadFrameSize: serverH2MaxReadFrameSize,
	}
}

// serveH2 serves HTTP/2 over the authenticated TLS connection.
func (s *Server) serveH2(tlsConn net.Conn, identity authIdentity) {
	h2Server := newServerH2(s.config.MaxConcurrentStreams)
	flow := &h2Transport{
		tlsConn:      tlsConn,
		maxStreams:   s.config.MaxConcurrentStreams,
		drainTimeout: s.config.DrainTimeout,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == configAuthority {
			s.serveConfigBundle(w, r, identity)
			return
		}
		// Phase C iOS-notify pipeline (2026-05-10): valid creds + over-quota
		// or expired => DataPlaneBlocked. Refuse CONNECT with HTTP 402 so
		// the client gets an explicit error (and can surface the bundle
		// notification fetched on the same connection above) instead of a
		// silent black-hole. The 402 lives inside the encrypted H2 stream
		// so it's opaque to passive observers; an active probe with valid
		// stolen creds can already self-test their access, so this leaks
		// nothing new.
		if identity.DataPlaneBlocked {
			http.Error(w, "service suspended for this account", http.StatusPaymentRequired)
			return
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		destination := r.Host
		if destination == "" {
			http.Error(w, "No destination", http.StatusBadRequest)
			return
		}

		// Branch on Samizdat-Protocol header to route UDP-over-CONNECT through
		// the dedicated handler (udp_server.go). Empty / "tcp/1" is the default
		// TCP CONNECT path.
		proto := r.Header.Get(SamizdatProtocolHeader)
		network := "tcp"
		if proto == SamizdatProtocolUDP {
			network = "udp"
		}
		switch proto {
		case "", "tcp/1", SamizdatProtocolUDP:
			// supported below
		default:
			http.Error(w, "unsupported tamizdat-protocol", http.StatusBadRequest)
			return
		}

		releaseH2Track := s.trackUserH2Stream(identity, network)
		defer releaseH2Track()

		s.logShapeEvent(fmt.Sprintf("stream_open client=%s shortid=%x user=%s session=%s dst=%s proto=%s",
			tlsConn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, destination, network))

		switch proto {
		case SamizdatProtocolUDP:
			s.handleUDPCONNECT(w, r, destination, identity)
			return
		}

		s.logf("[tamizdat] legacy CONNECT: handler started")

		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}

		body := r.Body
		sr := &syncReader{r: body}

		streamConn := &serverStreamConn{
			reader:     io.NopCloser(sr),
			writer:     flushWriter{w: w, flusher: flusher},
			shaper:     s.shaper,
			fragmenter: s.fragmenter,
			debug:      s.config.Debug,
		}
		// Phase 2 per-user/per-session accounting: when the connection was
		// authenticated against a userdb-known user, hook the streamConn so
		// each successful Read/Write boundary buffers a byte delta to the
		// in-memory atomic counter. Background goroutine flushes to SQLite
		// every 5s; ServerClose flushes on shutdown.
		if s.accounting != nil && identity.UserID != "" {
			streamConn.acc = s.accounting
			streamConn.accUserID = identity.UserID
			streamConn.accSessionID = identity.SessionID
		}

		defer streamConn.shutdown()
		closedDst := destination
		closedNet := network
		defer func() {
			s.logShapeEvent(fmt.Sprintf("stream_close client=%s shortid=%x user=%s session=%s dst=%s proto=%s",
				tlsConn.RemoteAddr().String(), identity.ShortID[:], identity.UserID, identity.SessionID, closedDst, closedNet))
		}()

		s.handleTCPConnect(r.Context(), streamConn, destination, identity)

		s.logf("[tamizdat] legacy CONNECT: handler returned, starting drain")

		drainDone := make(chan struct{})
		go func() {
			n, err := io.Copy(io.Discard, sr)
			s.logf("[tamizdat] legacy CONNECT: drain finished, n=%d, err=%v", n, err)
			close(drainDone)
		}()
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-drainDone:
			timer.Stop()
			s.logf("[tamizdat] legacy CONNECT: drain completed, handler returning cleanly")
		case <-timer.C:
			s.logf("[tamizdat] legacy CONNECT: drain timeout, closing body")
			body.Close()
			<-drainDone
		}
	})

	s.logf("[tamizdat] serveH2: starting ServeConn")
	h2Server.ServeConn(flow.wrapServerConn(tlsConn), &http2.ServeConnOpts{
		Handler: handler,
	})
	s.logf("[tamizdat] serveH2: ServeConn returned")
}

// OutboundTags returns the current set of outbound tags known to the
// server's registry. Used by the cmd/tamizdat-server SIGHUP loop to seed
// the routing dispatcher's placeholder Outbound map; safe to call even
// when the registry is disabled (returns nil).
func (s *Server) OutboundTags() []string {
	if s == nil || s.outboundRegistry == nil {
		return nil
	}
	return s.outboundRegistry.Tags()
}

// OutboundRegistry exposes the live outbounds.Registry so subsystems
// outside the core server (e.g. internal/wgturn's outbound bridge)
// can resolve a tag to a Dialer. Returns nil when the registry is
// disabled (DisableOutboundRegistry=true).
func (s *Server) OutboundRegistry() *obreg.Registry {
	if s == nil {
		return nil
	}
	return s.outboundRegistry
}

// UserTrafficAccounting exposes the live per-user/outbound accounting sink to
// helper inbounds such as wgturn's userspace bridge. It deliberately returns a
// tiny interface so callers can record traffic without depending on userdb's
// concrete type.
type UserTrafficAccounting interface {
	Add(userID, sessionID string, up, down int64)
	AddOutbound(tag string, up, down int64)
}

func (s *Server) UserTrafficAccounting() UserTrafficAccounting {
	if s == nil {
		return nil
	}
	return s.accounting
}

// AuthenticateUserShortIDHex validates a panel user's master_shortid for
// non-H2 transports (wgturn/FragPoC-style fallbacks). It mirrors the normal
// handshake policy: unknown, expired, or over-quota users are rejected. When
// accepted, a user session row is opened if the DB is available; callers must
// later invoke EndUserSession with the returned IDs.
func (s *Server) AuthenticateUserShortIDHex(shortIDHex string) (userID, userName, sessionID string, ok bool) {
	if s == nil || s.userRegistry == nil {
		return "", "", "", false
	}
	lk, user, found := s.userRegistry.LookupHex(shortIDHex)
	if !found || user == nil {
		return "", "", "", false
	}
	now := time.Now().Unix()
	if user.ExpiresAt > 0 && now > user.ExpiresAt {
		return "", "", "", false
	}
	if s.userRegistry.IsOverQuota(user) {
		return "", "", "", false
	}
	userID = lk.UserID
	userName = user.Name
	if s.outboundDB != nil {
		if sid, err := userdb.GenerateHex(8); err == nil {
			sessionID = sid
			if err := userdb.StartSessionWithTransport(s.outboundDB, userID, sid, lk.PoolIndex, "turn"); err != nil {
				s.logf("[tamizdat] wgturn StartSession failed: %v", err)
				sessionID = ""
			}
		}
	}
	return userID, userName, sessionID, true
}

// EndUserSession closes a session opened by AuthenticateUserShortIDHex.
func (s *Server) EndUserSession(userID, sessionID string) {
	if s == nil || s.outboundDB == nil || userID == "" || sessionID == "" {
		return
	}
	if err := userdb.EndSession(s.outboundDB, userID, sessionID); err != nil {
		s.logf("[tamizdat] wgturn EndSession failed: %v", err)
	}
}

// ReloadOutbounds re-reads the SQLite outbound registry after a SIGHUP.
func (s *Server) ReloadOutbounds() (uint64, string, error) {
	if s.outboundRegistry == nil || s.outboundDB == nil {
		return s.outboundReloads.Load(), "direct", fmt.Errorf("server outbound registry is disabled")
	}
	if err := s.outboundRegistry.Reload(s.outboundDB); err != nil {
		return s.outboundReloads.Load(), s.outboundRegistry.DefaultTag(), err
	}
	count := s.outboundReloads.Add(1)
	return count, s.outboundRegistry.DefaultTag(), nil
}

// ReloadUsers re-reads the userdb registry after a SIGHUP. Existing live
// connections keep their cached identity; only new handshakes consult the
// refreshed registry. After reload we also refresh the in-Accounting
// remaining-budget cache for every user, so a panel-side "Reset Quota"
// click (which writes a new baseline into the DB and SIGHUPs us) takes
// effect on the next byte through the fast path, not at the end of the
// next flush window.
func (s *Server) ReloadUsers() (uint64, int, error) {
	if s.userRegistry == nil || s.outboundDB == nil {
		return s.userdbReloads.Load(), 0, fmt.Errorf("userdb registry is disabled")
	}
	if err := s.userRegistry.Reload(s.outboundDB); err != nil {
		return s.userdbReloads.Load(), s.userRegistry.Count(), err
	}
	// Re-publish per-user rate-limit caps (new users, edited Mbps values,
	// deleted users) into the in-memory limiter map. setMbps with the
	// previous value is a no-op so token-bucket state is preserved across
	// reloads where the cap didn't actually change.
	if s.rateLimits != nil {
		for _, u := range s.userRegistry.Snapshot() {
			s.rateLimits.setMbps(u.ID, u.RateLimitMbps)
		}
	}
	if s.accounting != nil {
		for _, u := range s.userRegistry.Snapshot() {
			var bUp, bDown, baseline, cap0 int64
			if err := s.outboundDB.QueryRow(
				`SELECT bytes_up, bytes_down, COALESCE(quota_baseline, 0), COALESCE(bandwidth_cap, 0) FROM users WHERE id=?`,
				u.ID,
			).Scan(&bUp, &bDown, &baseline, &cap0); err != nil {
				continue
			}
			if cap0 <= 0 {
				s.accounting.SetUserRemaining(u.ID, -1)
				continue
			}
			used := bUp + bDown - baseline
			if used < 0 {
				used = 0
			}
			remaining := cap0 - used
			if remaining < 0 {
				remaining = 0
			}
			s.accounting.SetUserRemaining(u.ID, remaining)
		}
	}
	count := s.userdbReloads.Add(1)
	return count, s.userRegistry.Count(), nil
}

func (s *Server) startUserRegistryReloader(interval time.Duration) {
	if s.userRegistry == nil || s.outboundDB == nil || interval <= 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if _, _, err := s.ReloadUsers(); err != nil && context.Cause(s.ctx) == nil {
					s.logf("[tamizdat] userdb live reload: %v", err)
				}
			}
		}
	}()
}

type selectedOutboundTagger interface {
	OutboundTag() string
}

type selectedOutboundRecorder interface {
	Recorder() obreg.Recorder
}

func effectiveOutboundTag(fallback string, endpoint any) string {
	if tagged, ok := endpoint.(selectedOutboundTagger); ok {
		if tag := strings.TrimSpace(tagged.OutboundTag()); tag != "" {
			return tag
		}
	}
	return fallback
}

func effectiveOutboundRecorder(endpoint any) obreg.Recorder {
	if recorded, ok := endpoint.(selectedOutboundRecorder); ok {
		return recorded.Recorder()
	}
	return nil
}

func (s *Server) handleTCPConnect(ctx context.Context, conn net.Conn, destination string, identity authIdentity) {
	if s.outboundRegistry == nil {
		if s.config.HandlerWithIdentity != nil {
			s.config.HandlerWithIdentity(ctx, conn, destination, ConnIdentity{
				ShortID:  identity.ShortID,
				UserID:   identity.UserID,
				UserName: identity.UserName,
			})
			return
		}
		s.config.Handler(ctx, conn, destination)
		return
	}
	defer conn.Close()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}
	resolvedTarget, err := ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		safeIntAdd(ssrfRejectedTCP, 1)
		s.logf("[tamizdat] outbound CONNECT rejected unsafe dst=%s err=%v", destination, err)
		return
	}

	// SNI / HTTP-Host sniff (2026-05-11): IP-mode clients (sing-tun
	// on iOS, full-tunnel VPNs) resolve DNS on-device and send the
	// resolved IP through the tunnel — so domain: routing rules never
	// fire. Peek the first bytes of the client→destination payload,
	// extract SNI or Host, and OVERRIDE the routing host for rule
	// evaluation only. The actual dial target (resolvedTarget) stays
	// what the client picked. Disabled by default; flip via panel
	// setting inbound_sniff_enabled.
	routingHost := host
	if s.config.SniffEnabled {
		sniffed, bufConn, perr := sniff.PeekConn(conn, []sniff.Sniffer{
			sniff.TLSClientHello,
			sniff.HTTPHost,
		})
		// Whatever Peek returned, swap conn for the buffered wrapper
		// so the bytes flow downstream untouched.
		if bufConn != nil {
			conn = bufConn
		}
		if perr == nil && sniffed != "" {
			routingHost = sniffed
			s.logf("[tamizdat] sniff: dst=%s sniffed=%s (routing host overridden)", destination, sniffed)
		}
	}

	// Panel v5: when a routing resolver is installed, evaluate the rule
	// list to pick the outbound tag (geoip/geosite/IP/domain/port/network/
	// inbound/source/user). The resolver is rule-evaluation-only —
	// outboundRegistry still owns the actual dialer.
	tagPick := s.resolveRoutingTag(ctx, routingHost, port, identity)
	if tagPick == "block" {
		// Structured route event (always emitted, debug-flag independent) so
		// the e2e routing test agent can verify rule decisions even when the
		// downstream dial gets blackholed. 2026-05-11.
		s.logShapeEvent(fmt.Sprintf("stream_route user=%s session=%s dst=%s outbound=block pick=%q",
			identity.UserID, identity.SessionID, destination, "block"))
		s.logf("[tamizdat] outbound CONNECT blocked by rule: dst=%s user=%s", destination, identity.UserID)
		return
	}
	dialer, outboundTag := s.outboundRegistry.Resolve(tagPick)
	defer dialer.Close()
	// Structured route event (see above). pick is the raw routing tag the
	// resolver returned ("" when no rule matched, falling back to default
	// outbound — outboundTag is the post-Resolve canonical answer).
	s.logShapeEvent(fmt.Sprintf("stream_route user=%s session=%s dst=%s outbound=%s pick=%q",
		identity.UserID, identity.SessionID, destination, outboundTag, tagPick))
	s.logf("[tamizdat] outbound CONNECT: dst=%s resolved=%s outbound=%s pick=%q", destination, resolvedTarget, outboundTag, tagPick)

	upstream, err := dialer.DialContext(ctx, "tcp", resolvedTarget)
	if err != nil {
		s.recordOutboundDialFailure(outboundTag, "tcp", err)
		s.logf("[tamizdat] outbound CONNECT dial failed: dst=%s resolved=%s outbound=%s err=%v", destination, resolvedTarget, outboundTag, err)
		return
	}
	defer upstream.Close()
	meterTag := effectiveOutboundTag(outboundTag, upstream)
	releaseUserRelayTrack := s.trackUserRelayStream(identity, "tcp")
	releaseOutboundTrack := s.trackOutboundStream(meterTag, "tcp")
	var releaseRelayOnce sync.Once
	releaseRelayTrack := func() {
		releaseRelayOnce.Do(func() {
			releaseUserRelayTrack()
			releaseOutboundTrack()
		})
	}
	defer releaseRelayTrack()

	// Per-outbound + per-user accounting at the io.Copy boundary. We do NOT
	// wrap conn (the previous countingConn approach hid the underlying
	// *net.TCPConn, breaking downstream type-asserts and killing iPhone
	// connectivity — see revert commit 04d3c94). Hooks fire once per
	// goroutine after the copy completes, so the cumulative byte counts
	// land in the recorder without per-syscall overhead.
	up, down := proxyBidirectionalCounted(conn, upstream, s.userRateLimiter(identity.UserID), releaseRelayTrack)
	if meterTag != "" {
		// up   = bytes WE WROTE to upstream (target ← server)
		// down = bytes WE READ from upstream (target → server)
		if rec := effectiveOutboundRecorder(upstream); rec != nil {
			rec.AddOutbound(meterTag, up, down)
		} else if s.accounting != nil {
			s.accounting.AddOutbound(meterTag, up, down)
		}
	}
}

// proxyIdleTimeout bounds how long proxyBidirectionalCounted will let a
// proxied connection move zero bytes in BOTH directions before presuming a
// copy goroutine is wedged and force-closing both ends. It is an *idle*
// window — it resets on any activity — so it never interrupts a long but
// live download, only a genuinely stalled connection. proxyCopyBufSize
// matches io.Copy's default buffer.
const (
	proxyIdleTimeout = 30 * time.Second
	proxyCopyBufSize = 32 * 1024
)

// proxyBidirectionalCounted is a counting + optional rate-limiting variant
// of proxyBidirectional. Returns (clientToTarget, targetToClient) byte
// totals after both directions drain. When limiter != nil, both halves are
// throttled to the user's configured Mbits/sec budget — the limiter is
// shared so write-direction-only saturation can't blow the budget.
//
// onUpstreamReadDone fires when the upstream->client half finishes. TCP
// half-close can leave the client->upstream half parked until the idle
// watchdog fires; relay observability should track next-hop occupancy, not
// that downstream linger.
//
// Idle-timeout backstop: when one direction finishes it half-closes (sends
// FIN via CloseWrite) and we wg.Wait() for the other. A peer that ignores
// the FIN — keep-alive web servers, or a restricted-network FragPoC client
// that vanished — leaves the surviving copy goroutine blocked in Read()
// forever, so wg.Wait() never returns, the caller never runs its defer
// Close(), and the upstream FD + goroutine leak permanently. The watchdog
// force-closes both conns once neither direction has moved a byte for
// proxyIdleTimeout, which unblocks the stuck Read().
func proxyBidirectionalCounted(client, upstream net.Conn, limiter *rate.Limiter, onUpstreamReadDone func()) (clientToUpstream, upstreamToClient int64) {
	lastActivity := new(atomic.Int64)
	lastActivity.Store(time.Now().UnixNano())

	done := make(chan struct{})
	go func() {
		for {
			idle := time.Duration(time.Now().UnixNano() - lastActivity.Load())
			wait := proxyIdleTimeout - idle
			if wait <= 0 {
				// Stuck: a copy goroutine is parked in Read() on a peer
				// that will neither send nor close. Closing both conns
				// makes that Read() return so wg.Wait() can complete.
				_ = client.Close()
				_ = upstream.Close()
				return
			}
			timer := time.NewTimer(wait)
			select {
			case <-done:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var src io.Reader = client
		if limiter != nil {
			src = newRateLimitedReader(client, limiter)
		}
		n := copyTrackingActivity(upstream, src, lastActivity)
		atomic.AddInt64(&clientToUpstream, n)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		var src io.Reader = upstream
		if limiter != nil {
			src = newRateLimitedReader(upstream, limiter)
		}
		n := copyTrackingActivity(client, src, lastActivity)
		atomic.AddInt64(&upstreamToClient, n)
		if onUpstreamReadDone != nil {
			onUpstreamReadDone()
		}
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	close(done)
	return clientToUpstream, upstreamToClient
}

// copyTrackingActivity copies src into dst like io.Copy, but stamps
// lastActivity with the current time on every non-empty read. That lets the
// idle-timeout watchdog in proxyBidirectionalCounted tell a stalled
// connection apart from a slow-but-live one — io.Copy itself reports no
// incremental progress. Returns the number of bytes written to dst.
func copyTrackingActivity(dst io.Writer, src io.Reader, lastActivity *atomic.Int64) int64 {
	buf := make([]byte, proxyCopyBufSize)
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil || nw < nr {
				return written
			}
		}
		if rerr != nil {
			return written
		}
	}
}

// dialUDPViaRouting picks an outbound for a UDP CONNECT and asks the
// resolved dialer to open a PacketConn. Mirrors handleTCPConnect's
// rule-evaluation path so UDP flows obey the same routing rules
// (user/domain/geosite/ip_cidr) — without this UDP always exited the
// local server IP regardless of rules, breaking chained scenarios
// like iPhone (anarki) → ru2 → mirror for QUIC traffic. Returns the
// PacketConn, the canonical outbound tag for logging, and an error.
func (s *Server) dialUDPViaRouting(ctx context.Context, host, port, resolvedTarget string, identity authIdentity) (net.PacketConn, string, error) {
	if s.outboundRegistry == nil {
		// Pre-Phase-1 deployment: no outbound registry, fall through to
		// a direct local UDP socket. Caller passes resolvedTarget as the
		// destination for WriteTo.
		lc := &net.ListenConfig{}
		pc, err := lc.ListenPacket(ctx, "udp", ":0")
		return pc, "direct", err
	}
	tagPick := s.resolveRoutingTag(ctx, host, port, identity)
	if tagPick == "block" {
		return nil, "block", fmt.Errorf("blocked by routing rule")
	}
	dialer, outboundTag := s.outboundRegistry.Resolve(tagPick)
	pc, err := dialer.DialPacket(ctx, resolvedTarget)
	if err != nil {
		_ = dialer.Close()
		return nil, outboundTag, err
	}
	meterTag := effectiveOutboundTag(outboundTag, pc)
	// Wrap so dialer.Close fires when PacketConn closes (outbound lease release).
	return &leasedPacketConn{PacketConn: pc, releaser: dialer}, meterTag, nil
}

// leasedPacketConn pairs a net.PacketConn with the outbound dialer
// lease that produced it, releasing the lease when Close fires. Mirrors
// what the TCP path does with `defer dialer.Close()` in handleTCPConnect.
type leasedPacketConn struct {
	net.PacketConn
	releaser interface{ Close() error }
	once     sync.Once
}

func (l *leasedPacketConn) Close() error {
	err := l.PacketConn.Close()
	l.once.Do(func() {
		if l.releaser != nil {
			_ = l.releaser.Close()
		}
	})
	return err
}

// resolveRoutingTag asks the panel-installed routing resolver (if any)
// which outbound tag should serve this CONNECT. Returns "" when no
// resolver is configured so the caller falls back to the registry default.
// "block" is a sentinel the resolver may emit to drop the connection.
func (s *Server) resolveRoutingTag(ctx context.Context, host, port string, identity authIdentity) string {
	if s.config.RoutingResolver == nil {
		return ""
	}
	portNum := 0
	if p, perr := atoiPort(port); perr == nil {
		portNum = p
	}
	userName := ""
	if identity.UserID != "" && s.userRegistry != nil {
		if u, ok := s.userRegistry.User(identity.UserID); ok {
			userName = u.Name
		}
	}
	return s.config.RoutingResolver(ctx, host, portNum, "tamizdat-in", userName)
}

// atoiPort is a tiny wrapper that returns 0 on bad input. Kept here to
// avoid importing strconv at the top of server.go solely for this one site.
func atoiPort(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad digit")
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

func proxyBidirectional(left net.Conn, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
		if cw, ok := right.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
		if cw, ok := left.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// readClientHelloRecord reads a complete TLS record from the connection.
func readClientHelloRecord(conn net.Conn) ([]byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record header: %w", err)
	}

	if header[0] != 22 {
		return nil, nil, fmt.Errorf("expected handshake record (type 22), got type %d", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return nil, nil, fmt.Errorf("TLS record too large: %d", recordLen)
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record payload: %w", err)
	}

	record := make([]byte, 5+recordLen)
	copy(record[:5], header)
	copy(record[5:], payload)

	return record, payload, nil
}

// replayConn wraps a net.Conn and prepends buffered data before reading
// from the real connection.
type replayConn struct {
	net.Conn
	buf    []byte
	offset int
}

func newReplayConn(conn net.Conn, data []byte) *replayConn {
	return &replayConn{
		Conn: conn,
		buf:  data,
	}
}

func (rc *replayConn) Read(b []byte) (int, error) {
	if rc.offset < len(rc.buf) {
		n := copy(b, rc.buf[rc.offset:])
		rc.offset += n
		return n, nil
	}
	return rc.Conn.Read(b)
}

// serverStreamConn wraps an HTTP/2 stream as a net.Conn for the ConnHandler.
// Writes go through the shaper+fragmenter so server-side responses are
// subject to the same record fragmentation (P0.1) and no per-record jitter (P0.4) as
// the client side.
type serverStreamConn struct {
	reader     io.ReadCloser
	writer     flushWriter
	shaper     *Shaper
	fragmenter *RecordFragmenter
	debug      bool
	closed     atomic.Bool
	mu         sync.Mutex

	// Phase 2 per-user accounting hooks. acc may be nil when running as an
	// embedded callable without ServerDBPath; in that case Read/Write don't
	// touch the counter at all (no atomic operation).
	acc          *userdb.Accounting
	accUserID    string
	accSessionID string

	// HIGH-2: deadline enforcement to satisfy net.Conn contract.
	// rd / wd store the deadline as Unix nanos (0 = no deadline). Read/Write
	// check before blocking; rdTimer/wdTimer fire reader.Close() when the
	// deadline elapses while a Read is parked, which propagates io.EOF to
	// the blocked goroutine.
	rd      atomic.Int64
	wd      atomic.Int64
	dlMu    sync.Mutex
	rdTimer *time.Timer
	wdTimer *time.Timer
}

func (sc *serverStreamConn) Read(b []byte) (int, error) {
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	if t := sc.rd.Load(); t != 0 && t <= time.Now().UnixNano() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := sc.reader.Read(b)
	// Phase 2 accounting: bytes Read here came from the client → counted
	// as "upload" (bytes_up) for the user. Counter is buffered + flushed.
	if n > 0 && sc.acc != nil && sc.accUserID != "" {
		sc.acc.Add(sc.accUserID, sc.accSessionID, int64(n), 0)
	}
	return n, err
}

func (sc *serverStreamConn) Write(b []byte) (n int, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if ok && msg == "Write called after Handler finished" {
				if sc.debug {
					log.Printf("[tamizdat] recovered expected panic in Write: %v", r)
				}
				sc.closed.Store(true)
				n = 0
				err = net.ErrClosed
				return
			}
			if sc.debug {
				log.Printf("[tamizdat] unexpected panic in Write: %v", r)
			}
			panic(r)
		}
	}()

	// Route through shaper+fragmenter so outer TLS records stay small and
	// fragmented without per-record jitter - P0.1 and P0.4 wired on the server side.
	if sc.shaper != nil {
		n, err = sc.shaper.FragmentWrite(&flushWriterWrapper{fw: sc.writer}, sc.fragmenter, b)
	} else {
		n, err = sc.writer.Write(b)
		if err == nil {
			sc.writer.Flush()
		}
	}
	// Phase 2 accounting: bytes Written here are travelling to the client →
	// counted as "download" (bytes_down) for the user.
	if n > 0 && sc.acc != nil && sc.accUserID != "" {
		sc.acc.Add(sc.accUserID, sc.accSessionID, 0, int64(n))
	}
	return n, err
}

// flushWriterWrapper ensures each fragment is flushed to the H2 framer as
// its own DATA frame.
type flushWriterWrapper struct {
	fw flushWriter
}

func (w *flushWriterWrapper) Write(p []byte) (int, error) {
	n, err := w.fw.Write(p)
	if err == nil {
		w.fw.Flush()
	}
	return n, err
}

func (sc *serverStreamConn) Close() error {
	sc.closed.Store(true)
	return nil
}

func (sc *serverStreamConn) shutdown() {
	sc.mu.Lock()
	sc.closed.Store(true)
	sc.mu.Unlock()
}

func (sc *serverStreamConn) CloseWrite() error {
	return nil
}

func (sc *serverStreamConn) LocalAddr() net.Addr  { return &streamAddr{"tcp", "server"} }
func (sc *serverStreamConn) RemoteAddr() net.Addr { return &streamAddr{"tcp", "client"} }

// SetDeadline sets both read and write deadlines. Implements net.Conn contract:
// blocked Read/Write returns os.ErrDeadlineExceeded after t; t.IsZero() clears.
func (sc *serverStreamConn) SetDeadline(t time.Time) error {
	_ = sc.SetReadDeadline(t)
	_ = sc.SetWriteDeadline(t)
	return nil
}

func (sc *serverStreamConn) SetReadDeadline(t time.Time) error {
	sc.dlMu.Lock()
	defer sc.dlMu.Unlock()
	if sc.rdTimer != nil {
		sc.rdTimer.Stop()
		sc.rdTimer = nil
	}
	if t.IsZero() {
		sc.rd.Store(0)
		return nil
	}
	sc.rd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		// Already past: close reader so any in-flight Read returns immediately.
		_ = sc.reader.Close()
		return nil
	}
	sc.rdTimer = time.AfterFunc(d, func() {
		// Re-check the stored deadline in case it was reset to a later time
		// before the timer fired. If it was, do nothing.
		now := time.Now().UnixNano()
		if cur := sc.rd.Load(); cur != 0 && cur <= now {
			_ = sc.reader.Close()
		}
	})
	return nil
}

func (sc *serverStreamConn) SetWriteDeadline(t time.Time) error {
	sc.dlMu.Lock()
	defer sc.dlMu.Unlock()
	if sc.wdTimer != nil {
		sc.wdTimer.Stop()
		sc.wdTimer = nil
	}
	if t.IsZero() {
		sc.wd.Store(0)
		return nil
	}
	sc.wd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		// Already past: shut down the write side so in-flight Writes fail fast.
		_ = sc.shutdownWriteSide()
		return nil
	}
	sc.wdTimer = time.AfterFunc(d, func() {
		now := time.Now().UnixNano()
		if cur := sc.wd.Load(); cur != 0 && cur <= now {
			_ = sc.shutdownWriteSide()
		}
	})
	return nil
}

// shutdownWriteSide is a best-effort: closes the underlying reader (which
// drives the H2 stream lifecycle); the H2 framer will propagate RST_STREAM,
// failing any subsequent Write.
func (sc *serverStreamConn) shutdownWriteSide() error {
	if sc.closed.Swap(true) {
		return nil
	}
	return sc.reader.Close()
}

// syncReader serializes concurrent reads with a mutex.
type syncReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (sr *syncReader) Read(b []byte) (int, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.r.Read(b)
}

// flushWriter wraps an http.ResponseWriter with a Flusher.
type flushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw flushWriter) Write(b []byte) (int, error) {
	return fw.w.Write(b)
}

func (fw flushWriter) Flush() {
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
}

// defaultConnHandler is a simple handler that dials the destination and
// proxies data bidirectionally.

// logShapeEvent writes one line to the configured ShapeEventLogPath, if any.
// Off (no-op) when ShapeEventLogPath is empty. Format: ISO8601-time + msg + \n.
// Caller passes the message body without timestamp or trailing newline.
// Thread-safe via shapeEventMu.
func (s *Server) logShapeEvent(msg string) {
	if s == nil {
		return
	}
	s.shapeEventMu.Lock()
	defer s.shapeEventMu.Unlock()
	if s.shapeEventOut == nil {
		return
	}
	line := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + msg + "\n"
	_, _ = s.shapeEventOut.WriteString(line)
}

func defaultConnHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()
	safeIntAdd(tunnelsTCPOpened, 1)
	defer safeIntAdd(tunnelsTCPClosed, 1)
	var flowBytes int64
	defer func() { observeFlowBytes(flowBytes) }()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}

	// CRIT-0: validate destination and dial the resolved IP directly. Defeats
	// SSRF (RFC1918/loopback/cloud-metadata/CGNAT) and the DNS-rebinding TOCTOU
	// window between validation and net.Dial's own resolver.
	target, err := ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		safeIntAdd(ssrfRejectedTCP, 1)
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, conn)
		atomic.AddInt64(&flowBytes, n)
		bytesClientToTarget.Add(n)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		atomic.AddInt64(&flowBytes, n)
		bytesTargetToClient.Add(n)
		// HIGH-6: when target sends EOF, propagate write-close to the H2 stream
		// so the client's blocking Read(s) on its side can wake up cleanly.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

var (
	_ net.Conn = (*serverStreamConn)(nil)
	_ net.Conn = (*replayConn)(nil)
)
