// Package samizdat implements a censorship circumvention protocol that makes
// proxy traffic indistinguishable from a browser visiting a real website over
// HTTP/2. It uses a single TLS layer with Reality-style authentication,
// HTTP/2 CONNECT tunneling, multiplexed streams, Geneva-inspired TCP
// fragmentation, and traffic shaping with record fragmentation and delayed ACK defense.
//
// The server acts as a real web server to unauthorized connections by
// transparently proxying them to the masquerade domain at the TCP level.
package tamizdat

import (
	"context"
	"net"
	"time"
)

// DialFunc allows injecting a custom TCP dialer for the underlying connection.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ConnHandler is called for each proxied connection with destination info.
type ConnHandler func(ctx context.Context, conn net.Conn, destination string)

// ConnIdentity describes the authenticated client behind a CONNECT stream.
// It is supplied to ConnHandlerWithIdentity so that an embedded caller (e.g.
// node.SamizdatInbound) can populate Request.User for routing-rule evaluation.
//
// UserName is the userdb-resolved display name (users.name column). Empty
// when the connection authenticated against the embedded master shortid
// fallback (no userRegistry configured) or when the registry lookup did not
// find a matching user — both cases preserve "no user" semantics so that
// routing rules with a {"user": [...]} filter naturally don't match.
type ConnIdentity struct {
	ShortID  [8]byte
	UserID   string // empty when no userdb-resolved user
	UserName string // empty when no userdb-resolved user
}

// ConnHandlerWithIdentity is the identity-aware variant of ConnHandler. When
// ServerConfig.HandlerWithIdentity is non-nil, the server invokes it instead
// of the legacy Handler so the embedded caller can attach the authenticated
// user to its routing decision. The legacy Handler stays the supported path
// for callers that do not need user-level routing.
type ConnHandlerWithIdentity func(ctx context.Context, conn net.Conn, destination string, identity ConnIdentity)

// ClientConfig configures the Samizdat client.
type ClientConfig struct {
	// Server connection
	ServerAddr  string
	PrimarySNI  string   // canonical URI primary SNI; normalized from ServerName
	ServerName  string   // legacy single SNI; if ServerNames empty this is used
	ServerNames []string // legacy pool of SNIs; client picks random before bundle

	// Authentication. MasterShortID is the single URI shortID used as the
	// authentication root. ShortID is kept for backward-compatible in-process
	// callers and is normalized into MasterShortID by applyDefaults.
	PublicKey     []byte
	MasterShortID [8]byte
	ShortID       [8]byte // legacy single ID; normalized to MasterShortID

	// TLS fingerprint
	Fingerprint string

	// TCP fragmentation (Geneva-inspired)
	TCPFragmentation    bool
	RecordFragmentation bool

	// DisableDefaultSecurity, when true, suppresses the automatic-true defaults
	// for TCPFragmentation / RecordFragmentation. Tests flip this on when they
	// need deterministic no-shaping behaviour.
	DisableDefaultSecurity bool

	// Connection management
	MaxStreamsPerConn int
	IdleTimeout       time.Duration
	ConnectTimeout    time.Duration
	DrainTimeout      time.Duration

	// Cover/decoy traffic (compass v2 §5.6): periodic background CONNECTs
	// through the tunnel to cover sites. Defeats encapsulated-TLS-handshake
	// fingerprinting by mixing "browser-like" side streams with user traffic
	// on the same H2 session. Default disabled.
	CoverTrafficEnabled bool
	CoverTrafficTargets []string // empty = defaults

	// PoolVariant selects an operator-controlled transport-pool strategy.
	// Empty keeps the foundation/V3-shaped defaults; "v1" pins to a single
	// transport, "v2" pre-warms one transport with up to two under load,
	// "v3" pre-warms two with up to four under load. Realtime classifier
	// has been removed; all transports carry every flow.
	PoolVariant string

	// Multi-conn fallback against #490 (compass deep-research P1.2):
	// MinTransports pre-warms N parallel TLS+H2 transports up-front; new
	// streams round-robin across them so no single transport carries the
	// whole user traffic. If TSPU shapes one TCP after ~15 KB, the others
	// stay healthy and traffic continues. Default 1 = legacy behaviour
	// (single lazy transport).
	MinTransports int

	// MaxTransports caps the number of simultaneous TLS+H2 transports in the
	// pool. 0 means applyDefaults pins it to MinTransports; values below
	// MinTransports are raised to MinTransports.
	MaxTransports int

	// RotationOverlapAllowance permits this many extra transient bulk
	// transports while an old bulk transport is draining after a byte-cap
	// rotation. V1 defaults this to 1 so a single steady transport can be
	// gracefully replaced when rotation is explicitly enabled.
	RotationOverlapAllowance int

	// BytesPerTransportSoftCap, if >0, marks a transport draining once its
	// cumulative outbound bytes cross the cap (typical 12-15 KB to trigger
	// just before TSPU detector #490 fires). New streams flow to other
	// transports; pool reaper spawns a replacement. 0 = disabled.
	BytesPerTransportSoftCap int64

	// BootstrapSNI is the SNI used for the very first transport when no
	// bundle is yet cached on disk. Populated from the URI `bootstrap=`
	// query parameter, or — when absent — from the URI host (which lets a
	// bare-IP URI use the IP literal as bootstrap SNI). Empty string means
	// "fall back to PrimarySNI/ServerName".
	BootstrapSNI string

	// BundleDisabled, when true, opts out of the magic-CONNECT bundle
	// fetch on every fresh transport. Default false (i.e. fetch enabled).
	// SPP-FU-6: replaces the legacy BundleEnabled+BundleEnabledSet
	// two-flag dance whose silent-overwrite of an explicit false was a
	// footgun. After applyDefaults, BundleEnabled is derived from
	// !BundleDisabled and is the runtime-effective flag the rest of the
	// pipeline reads.
	BundleDisabled bool

	// BundleEnabled is the runtime-effective gating bit, derived from
	// !BundleDisabled by applyDefaults. Read-only for callers; writes
	// without also setting BundleEnabledSet (legacy path) are honoured
	// via the deprecated BundleEnabledSet seam below.
	BundleEnabled bool

	// BundleEnabledSet is the legacy "I really mean BundleEnabled=false"
	// flag. Deprecated: use BundleDisabled instead. Kept for back-compat
	// with callers that already adopted the two-flag pattern; if
	// BundleDisabled is unset and BundleEnabledSet is true, applyDefaults
	// honours the explicit BundleEnabled value verbatim.
	//
	// Deprecated: set BundleDisabled = true to opt out.
	BundleEnabledSet bool

	// BundleCacheDir, when non-empty, points at a directory where the
	// client persists the most-recent server-pushed bundle keyed by
	// (host, master_shortid). Empty leaves the bundle in-memory only and
	// the next process start fetches a fresh copy.
	BundleCacheDir string

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc

	// OnNotification is invoked once per applied bundle when the server
	// piggy-backed a NotificationEntry. Fires on a fresh Go goroutine so the
	// bundle-apply path stays non-blocking; consumer MUST be thread-safe and
	// MUST NOT panic (panics are recovered). Phase C iOS-notify pipeline —
	// iOS NE bridges this to a local UNNotification; future Windows/CLI
	// consumers can hook the same seam.
	OnNotification func(NotificationEntry)

	// WireVersion picks the SessionID HMAC tag-prefix the client emits on
	// new dials. Default 2 (cached 6-byte stable random + 2-byte counter,
	// matching real-Chrome SessionID-stable-across-reconnects behaviour;
	// review-C tell #12 / Wu+Xue 2024). Set to 1 to fall back to the legacy
	// fresh-random-per-dial wire form (used by some integration tests that
	// pin the older format). Values outside [1,2] are clamped to 2 by
	// applyDefaults.
	WireVersion int
}

func (c *ClientConfig) applyDefaults() {
	// Server-pushes-pool (2026-05-09): when the caller passed only
	// BootstrapSNI (clean URI form, sni= absent), seed the legacy
	// PrimarySNI/ServerName/ServerNames from it so the rest of the
	// pipeline has a name to dial before the server-pushed bundle
	// rewrites the pool.
	if c.PrimarySNI == "" && c.ServerName == "" && len(c.ServerNames) == 0 && c.BootstrapSNI != "" {
		c.PrimarySNI = c.BootstrapSNI
		c.ServerName = c.BootstrapSNI
		c.ServerNames = []string{c.BootstrapSNI}
	}
	if c.PrimarySNI == "" {
		if c.ServerName != "" {
			c.PrimarySNI = c.ServerName
		} else if len(c.ServerNames) > 0 {
			c.PrimarySNI = c.ServerNames[0]
		}
	}
	if c.ServerName == "" {
		c.ServerName = c.PrimarySNI
	}
	if c.BootstrapSNI == "" {
		c.BootstrapSNI = c.PrimarySNI
	}
	var zeroShortID [8]byte
	if c.MasterShortID == zeroShortID && c.ShortID != zeroShortID {
		c.MasterShortID = c.ShortID
	}
	if c.ShortID == zeroShortID {
		c.ShortID = c.MasterShortID
	}
	if c.Fingerprint == "" {
		c.Fingerprint = "mix"
	}
	// SPP-FU-6: BundleDisabled is the canonical opt-out switch; legacy
	// BundleEnabledSet remains honoured to avoid breaking callers that
	// already migrated to the two-flag pattern.
	switch {
	case c.BundleDisabled:
		c.BundleEnabled = false
	case c.BundleEnabledSet:
		// preserve explicit BundleEnabled supplied by legacy caller
	default:
		c.BundleEnabled = true
	}
	// MaxStreamsPerConn = 0 (default) means "no client-side cap; rely on
	// the server's SETTINGS_MAX_CONCURRENT_STREAMS announced via h2 SETTINGS
	// frame". Set to a positive value only as a per-platform safety floor
	// (e.g. iOS PacketTunnelProvider memory-budget protection).
	if c.MaxStreamsPerConn < 0 {
		c.MaxStreamsPerConn = 0
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	// WireVersion: 0 means "not set, use default"; clamp anything outside
	// [1,2] to the current default (2). Phase 1 of the v1->v2 rollout: new
	// clients emit v2 SessionIDs by default but operators can pin to 1 for
	// staged migration.
	if c.WireVersion <= 0 || c.WireVersion > 2 {
		c.WireVersion = 2
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	// Security defaults are ON by default (compass v2/v3): callers must opt
	// out via DisableDefaultSecurity (e.g. tests). The block below makes the
	// URI form minimal -- a tamizdat:// URI does not need to carry mintr/cap/
	// cover/tcpfrag/recfrag fields; library forces the safe values.
	if !c.DisableDefaultSecurity {
		c.TCPFragmentation = true
		c.RecordFragmentation = true
		c.CoverTrafficEnabled = true
	}
	// Explicit transport bounds from the server/URI win over the legacy
	// pool-variant mapping. This is the exact-count path the panel now uses.
	if c.MinTransports > 0 || c.MaxTransports > 0 {
		if c.MinTransports < 1 {
			c.MinTransports = 1
		}
		if c.MaxTransports == 0 || c.MaxTransports < c.MinTransports {
			c.MaxTransports = c.MinTransports
		}
		return
	}
	if !c.DisableDefaultSecurity {
		// Pool variant is legacy-compatible fallback only. Empty/unrecognized
		// means a single H2 transport.
		if c.PoolVariant != "v1" && c.PoolVariant != "v2" && c.PoolVariant != "v3" {
			c.PoolVariant = "v1"
		}
	} else if c.MinTransports < 1 {
		// even with security disabled, MinTransports must be >=1
		c.MinTransports = 1
	}
	switch c.PoolVariant {
	case "v1":
		c.MinTransports = 1
		c.MaxTransports = 1
		if c.RotationOverlapAllowance == 0 {
			c.RotationOverlapAllowance = 1
		}
	case "v2":
		c.MinTransports = 1
		c.MaxTransports = 2
	case "v3":
		// Opus pool sizing (compass review): two prewarmed transports for
		// throughput parallelism, up to four under load. Trades a slightly
		// taller TLS-conn-count fingerprint vs #546 threshold (~12) for
		// significantly better tail latency and per-flow throughput.
		c.MinTransports = 2
		c.MaxTransports = 4
	default:
		if c.MinTransports < 1 {
			c.MinTransports = 1
		}
		if c.MaxTransports == 0 {
			c.MaxTransports = c.MinTransports
		}
		if c.MaxTransports < c.MinTransports {
			c.MaxTransports = c.MinTransports
		}
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	ListenAddr string

	PrivateKey    []byte
	MasterShortID [8]byte

	CoverConfigPath string

	// BundleTTL controls the advertised expires_at lifetime in the
	// server-pushed config bundle (§9). Default 1h. Set to 0 to omit
	// expires_at and ttl_seconds entirely (legacy v1 wire format).
	BundleTTL time.Duration

	// BundleDisabled, when true, opts out of the server-pushed bundle
	// endpoint. Default false (i.e. endpoint enabled). SPP-FU-6: replaces
	// the legacy BundleEnabled+BundleEnabledSet pair whose silent default
	// of an explicit BundleEnabled=false was a footgun.
	BundleDisabled bool

	// BundleEnabled is the runtime-effective gating bit, derived from
	// !BundleDisabled by applyDefaults. Read-only for callers; writes
	// without also setting BundleEnabledSet are honoured via the
	// deprecated BundleEnabledSet seam below.
	BundleEnabled bool

	// BundleEnabledSet is the legacy "I really mean BundleEnabled=false"
	// flag. Deprecated: use BundleDisabled instead.
	//
	// Deprecated: set BundleDisabled = true to opt out.
	BundleEnabledSet bool

	// BootstrapSNI, when set, is included in the URI as &bootstrap=<sni>
	// by external URI generators (panel). The library itself does not emit
	// URIs; it carries the field so config tooling can surface the value
	// next to the rest of ServerConfig in tests and golden fixtures.
	BootstrapSNI string

	CertPEM []byte
	KeyPEM  []byte

	// MasqueradeDomain is the default upstream the server forwards
	// unauthenticated probes to (Reality fail-fast). When this is "" the
	// connections that fail authentication get a graceful FIN close (NOT
	// a TCP RST). For Reality-classic RST-on-unknown-SNI behaviour, see
	// MasqueradeFailMode (TODO: not yet implemented; tracked as P0 in
	// review-A; currently the only options are Forward and FIN-close).
	//
	// Auto-fill (review-A P1): if MasqueradeDomain is set but
	// MasqueradePool is empty, applyDefaults populates the pool from
	// DefaultRussianCoverMasqueradePool() so probes spread across many
	// real RU origins instead of all funneling to one.
	MasqueradeDomain string
	// MasqueradeAddr is an explicit IP:port override for the default
	// origin. When set it bypasses DNS resolution of MasqueradeDomain.
	MasqueradeAddr string
	// MasqueradePool maps client-presented SNI -> origin host:port. Allows
	// cover-SNI rotation (compass P1.1): client picks a random SNI from a
	// pool, server forwards auth-failed probes to the matching real origin
	// so the cert/handshake behaviour matches the SNI claim. Empty string
	// value means "use MasqueradeDomain". Unknown SNI falls back to default.
	MasqueradePool        map[string]string
	MasqueradeIdleTimeout time.Duration
	MasqueradeMaxDuration time.Duration

	RecordFragmentation bool
	DrainTimeout        time.Duration

	// ReplayWindow defines the server-side replay-guard retention duration.
	// Each accepted handshake's replay key — SHA-256(SessionID || eph_pub)[:16] —
	// is held in the guard for this long; a second handshake re-using the same
	// 16-byte tuple while the entry is still resident is rejected.
	ReplayWindow time.Duration

	// Debug gates verbose log.Printf output and the localhost expvar endpoint.
	Debug           bool
	DebugListenAddr string

	// ShapeEventLogPath, when non-empty, opens a SEPARATE log file (NOT
	// stderr/journalctl) and records per-stream open/close events with the
	// authenticated client identity. Operator-only debug aid, off by default.
	ShapeEventLogPath string

	// ShapeEventLogMaxBytes / ShapeEventLogMaxBackups bound the shape-event
	// log's on-disk footprint via in-process size rotation (see
	// rotatingWriter). Only consulted when ShapeEventLogPath is set. Zero
	// values are filled with defaults by applyDefaults, so enabling the log
	// always yields a bounded file even if these are never tuned. MaxBytes
	// <= 0 disables rotation entirely (unbounded — not recommended).
	ShapeEventLogMaxBytes   int64
	ShapeEventLogMaxBackups int

	// ServerDBPath enables the Phase 1 outbound SQLite registry. Empty keeps
	// legacy Handler-only direct proxying for embedded callers. Setting it
	// also activates Phase 2 multi-user identity (users + sessions tables).
	ServerDBPath string

	// LegacyShortIDPath is the bootstrap-migration source for Phase 2: when
	// the users table is empty and this file holds a 16-hex master shortid,
	// the server creates a single "anarki" user with that master and a fresh
	// epoch_key, marking schema_meta('migrated_from_v1'). Empty defaults to
	// "/etc/tamizdat/shortid.hex".
	LegacyShortIDPath string

	// DisableOutboundRegistry, when true, keeps userdb (Phase 2) wired up
	// from ServerDBPath but skips the outbound chain: handleTCPConnect
	// falls back to the supplied Handler. Used by tests that need user
	// identification + accounting without the SSRF guard or the
	// registry-direct dialer eating the test echo destination.
	DisableOutboundRegistry bool

	// DisableMasqueradePrewarm, when true, skips the review-A P3 pre-warmed
	// TCP pool to masquerade origins. Each masquerade-forward then pays the
	// full TCP-SYN RTT instead of pulling a ready conn from the pool.
	// Embedded callers and tests that count exact origin dials should set
	// this; production deployments should leave it false.
	DisableMasqueradePrewarm bool

	DisableDefaultSecurity bool

	// DisableCertPadding, when true, skips the cert-chain padding pass in
	// NewServer. Operators with real LE / commercial CA chains whose natural
	// chain already meets or exceeds the target size can opt out to avoid the
	// extra dummy CA-style certs (Frankenstein-chain). Recommended ON for
	// deployments serving a real LE / commercial cert where the natural chain
	// size already matches the masquerade target's JA4-S byte distribution.
	// When unset, padding applies only if the natural chain falls below the
	// target size threshold.
	DisableCertPadding bool

	MaxConcurrentStreams int

	// InboundPoolVariant is the server-authoritative transport pool
	// strategy pushed to every connecting client via cover-config bundle
	// (2026-05-11). Values: "v1" (single H2, default), "v2", "v3".
	// Empty = "v1". Operators flip via panel setting inbound_pool_variant.
	InboundPoolVariant string

	// SniffEnabled controls TLS SNI / HTTP Host extraction on each
	// inbound stream's first bytes (2026-05-11). When true, the server
	// peeks the first ~4KB of the client→destination payload before
	// dispatching to the routing resolver. Extracted hostname overrides
	// the destination IP for routing decisions only — the actual dial
	// target remains the client-supplied address. Default OFF when zero
	// (set by applyDefaults from the inbound_sniff_enabled DB setting).
	SniffEnabled bool

	// FragPoCSamePort enables the plain fragmented TCP PoC transport on the
	// primary listener by demuxing the first byte before the TLS/H2 path. It is
	// off by default so existing deployments keep their exact wire behavior
	// until the operator explicitly enables the PoC fallback.
	FragPoCSamePort bool

	// FragPoCDownReadTimeout bounds how long one short-TCP DOWN poll may wait
	// for destination data before returning an empty response. Lower values
	// keep full-tunnel background flows from monopolizing the per-client
	// short-TCP budget; zero uses the server default.
	FragPoCDownReadTimeout time.Duration

	// FragPoCMaxPayload caps one server-to-client DOWN data chunk for the
	// short-TCP fallback. Zero keeps the transport default. Restricted
	// iPhone/LTE hotspot profiles may require a much smaller cap (for example
	// 220 bytes) because larger first replies on a fresh TCP connection can be
	// blackholed by the carrier path.
	FragPoCMaxPayload int

	Handler ConnHandler

	// HandlerWithIdentity, when non-nil, is preferred over Handler. It carries
	// the authenticated client identity (resolved via userRegistry when one is
	// configured, empty otherwise) so embedded callers can plumb the user
	// through their own routing rule evaluation. Defaults to nil; callers that
	// do not need identity continue to use the legacy Handler unchanged.
	HandlerWithIdentity ConnHandlerWithIdentity

	// RoutingResolver, when non-nil, is consulted for every authenticated
	// CONNECT to pick the outbound tag handed to the internal outbound
	// registry. Returning "" means "use the registry default tag". The
	// special return value "block" tells the server to drop the
	// connection (panel UX convention). The resolver is installed by the
	// tamizdat-server binary (cmd/tamizdat-server/main.go); embedded
	// callers leave it nil and routing rules then have no effect.
	//
	// inboundTag is informational ("tamizdat-in"); user is the
	// authenticated user's display name (empty when no userdb).
	RoutingResolver func(ctx context.Context, host string, port int, inboundTag, user string) string

	// ProxyProtocol enables PROXY protocol v1/v2 header parsing on incoming
	// connections. When the server is fronted by nginx (`proxy_protocol on`)
	// or haproxy (`send-proxy(-v2)`), each accepted TCP connection is
	// prefixed with a header carrying the real client IP/port. tamizdat
	// reads and strips the header, then exposes the real address via
	// conn.RemoteAddr() to downstream code (rate limiter, logs, etc.).
	ProxyProtocol bool

	// ProxyProtocolTrusted is the whitelist of upstream proxy IPs allowed to
	// inject PROXY headers. Connections from any other IP are rejected before
	// header parsing. CRITICAL: leaving this empty when ProxyProtocol=true
	// fails closed (every connection rejected) — operator MUST configure the
	// upstream IP/CIDR (typically 127.0.0.1/32 for local nginx, or the edge
	// haproxy IP for direct edge routing).
	ProxyProtocolTrusted []*net.IPNet

	// MinAcceptedWireVersion / MaxAcceptedWireVersion gate the SessionID HMAC
	// tag-prefix range the server accepts during the v1->v2 rollout. Defaults
	// (applied by applyDefaults) are MIN=1 / MAX=2 — both legacy v1 and the
	// new cached-SessionID v2 are accepted. Phase 2 (later sprint) bumps MIN
	// to 2 to drop v1.
	//
	// Replay-window protection is unchanged: the replay key is
	// SHA-256(SessionID || eph_pub)[:16]; v2's per-dial counter in the
	// nonce field provides the across-dial uniqueness that legacy v1 got
	// from a fresh-random nonce.
	//
	// Values <=0 are normalised by applyDefaults to MIN=1 / MAX=2.
	MinAcceptedWireVersion int
	MaxAcceptedWireVersion int

	// TURNCredsProvider, when non-nil, supplies VK TURN relay
	// credentials for injection into the server-pushed config bundle.
	// The server calls CurrentTURNCreds on every bundle request; a nil
	// return means no credentials are available (disabled or not yet
	// fetched). Implemented by internal/turncreds.Manager.
	TURNCredsProvider TURNCredsProvider
}

// TURNCredsProvider is the interface the server uses to obtain cached
// TURN credentials. Defined here (not in internal/turncreds) to avoid
// an import cycle between the root tamizdat package and internal
// packages.
type TURNCredsProvider interface {
	// CurrentTURNCreds returns the latest cached TURN credentials, or
	// nil when none are available.
	CurrentTURNCreds() *TURNCredsEntry
}

func (c *ServerConfig) applyDefaults() {
	if c.MasqueradeIdleTimeout == 0 {
		c.MasqueradeIdleTimeout = 5 * time.Minute
	}
	if c.MasqueradeMaxDuration == 0 {
		c.MasqueradeMaxDuration = 10 * time.Minute
	}
	// Auto-populate the masquerade pool with a default Russian-cover set if
	// the operator enabled masquerade but didn't set a pool. Without this,
	// every probe forwards to the same MasqueradeDomain — that's the literal
	// SNI-IP-mismatch tell #2 the censor analyst flagged in review-A.
	if c.MasqueradeDomain != "" && len(c.MasqueradePool) == 0 {
		c.MasqueradePool = DefaultRussianCoverMasqueradePool()
	}
	if c.MaxConcurrentStreams == 0 {
		c.MaxConcurrentStreams = 1000
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = defaultReplayWindow
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	// Shape-event log size rotation: keep the file plus its backups from
	// growing unbounded once the operator turns the log on. Only meaningful
	// when ShapeEventLogPath is set; a zero MaxBytes/MaxBackups falls back to
	// the default policy (see rotating_writer.go).
	if c.ShapeEventLogPath != "" {
		if c.ShapeEventLogMaxBytes == 0 {
			c.ShapeEventLogMaxBytes = defaultShapeEventLogMaxBytes
		}
		if c.ShapeEventLogMaxBackups == 0 {
			c.ShapeEventLogMaxBackups = defaultShapeEventLogMaxBackups
		}
	}
	if !c.DisableDefaultSecurity {
		c.RecordFragmentation = c.RecordFragmentation || true
	}
	// SessionID wire-version acceptance window. Default to [1, 2]: legacy v1
	// stays accepted during Phase 1 of the rollout so existing clients keep
	// working while new clients start emitting v2. Phase 2 bumps Min to 2
	// (operator runbook task).
	if c.MinAcceptedWireVersion <= 0 {
		c.MinAcceptedWireVersion = 1
	}
	if c.MaxAcceptedWireVersion <= 0 {
		c.MaxAcceptedWireVersion = 2
	}
	// Clamp the upper bound to the highest version this build understands
	// (v2). Forward-compat: a future v3 bump must also bump this clamp.
	if c.MaxAcceptedWireVersion > 2 {
		c.MaxAcceptedWireVersion = 2
	}
	if c.MinAcceptedWireVersion > c.MaxAcceptedWireVersion {
		c.MinAcceptedWireVersion = c.MaxAcceptedWireVersion
	}
	if c.BundleTTL == 0 {
		c.BundleTTL = time.Hour
	}
	// SPP-FU-6: same precedence as ClientConfig — BundleDisabled is the
	// canonical opt-out; legacy BundleEnabledSet remains honoured.
	switch {
	case c.BundleDisabled:
		c.BundleEnabled = false
	case c.BundleEnabledSet:
		// preserve explicit BundleEnabled supplied by legacy caller
	default:
		c.BundleEnabled = true
	}
}
