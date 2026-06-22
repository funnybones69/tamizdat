// Package configurl parses tamizdat:// client configuration URLs.
package configurl

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Config is the transport-neutral representation of a tamizdat:// URL.
type Config struct {
	ServerAddr    string
	ServerName    string   // legacy single SNI; first pool entry
	ServerNames   []string // pool of SNIs from comma-separated sni query param
	PublicKey     []byte
	MasterShortID [8]byte
	Fingerprint   string
	MinTransports int
	MaxTransports int
	// BootstrapSNI is the SNI used for the very first transport when no
	// server-pushed bundle is yet cached on disk. Populated from the
	// optional `?bootstrap=<sni>` query parameter; when absent we fall
	// back to the URI host (allowing bare-IP URIs to use the IP literal
	// as bootstrap SNI). The library client uses this only on the very
	// first dial; subsequent dials pick from the bundle's sni_pool.
	BootstrapSNI string
}

// Parse converts a tamizdat:// URL into a validated Config.
//
// Accepted forms (any of these works):
//
//	tamizdat://<host>:<port>/?sni=<hostname>&pubkey=<64hex>&shortid=<16hex>&fp=chrome   (legacy v2, full; optional min_transports/max_transports)
//	tamizdat://<host>:<port>/?pubkey=<64hex>&shortid=<16hex>                            (server-pushes-pool, clean)
//	tamizdat://<host>:<port>/?pubkey=<64hex>&shortid=<16hex>&bootstrap=<sni>           (server-pushes-pool, explicit bootstrap)
//	tamizdat://<shortid>@<host>:<port>?sni=<hostname>&pbk=<64hex>&fp=chrome             (legacy tamizdat form)
//	tamizdat://<shortid>@<host>:<port>?sni=<hostname>&pbk=<64hex>&fp=chrome             (tamizdat scheme alias)
//
// Aliases: "pbk" == "pubkey", "sid" == "shortid", userinfo == "shortid".
//
// Server-pushes-pool (2026-05-09): `?sni=` and `?fp=` are now both optional.
// When absent, the client uses BootstrapSNI (from `?bootstrap=<sni>` or, when
// that is also absent, the URI host literal) for the very first transport
// and applies "mix" as default fingerprint mode. After the first transport
// is up, the server-pushed config bundle replaces both pools.
func Parse(raw string) (Config, error) {
	var cfg Config

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, fmt.Errorf("empty config URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return cfg, fmt.Errorf("parse config URL: %w", err)
	}
	if u.Scheme != "tamizdat" {
		return cfg, fmt.Errorf("unsupported config URL scheme %q (want tamizdat://)", u.Scheme)
	}
	if u.Host == "" {
		return cfg, fmt.Errorf("config URL must include server host:port")
	}
	if u.Path != "" && u.Path != "/" {
		return cfg, fmt.Errorf("config URL path must be empty or '/', got %q", u.Path)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return cfg, fmt.Errorf("server address must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return cfg, fmt.Errorf("server address must include non-empty host and port")
	}
	cfg.ServerAddr = net.JoinHostPort(host, port)

	q := u.Query()
	sniRaw := strings.TrimSpace(q.Get("sni"))
	for _, p := range strings.Split(sniRaw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			cfg.ServerNames = append(cfg.ServerNames, p)
		}
	}
	bootstrap := strings.TrimSpace(q.Get("bootstrap"))
	if bootstrap == "" {
		// fall back to URI host literal — works for both DNS names and bare
		// IPs (TLS handshake against an IP literal is uncommon but valid
		// and is what censors see as a direct-IP first-time connect anyway).
		bootstrap = host
	}
	cfg.BootstrapSNI = bootstrap
	if len(cfg.ServerNames) == 0 {
		// New (clean) URI without sni= : seed ServerNames with the bootstrap
		// SNI so the legacy single-SNI path still has a name to dial. The
		// server-pushed bundle replaces the pool on the very first transport.
		cfg.ServerNames = []string{bootstrap}
	}
	cfg.ServerName = cfg.ServerNames[0] // legacy field

	// Accept "pubkey" (canonical tamizdat) or "pbk" (legacy tamizdat) — both mean the same.
	pubRaw := q.Get("pubkey")
	if strings.TrimSpace(pubRaw) == "" {
		pubRaw = q.Get("pbk")
	}
	pub, err := decodeFixedHex(pubRaw, 32, "pubkey/pbk")
	if err != nil {
		return cfg, err
	}
	cfg.PublicKey = pub

	// Accept shortid from "?shortid=" (canonical), "?sid=" (alias),
	// or from URL userinfo (legacy tamizdat form: tamizdat://SHORTID@host:port?...).
	shortIDStr := strings.TrimSpace(q.Get("shortid"))
	if shortIDStr == "" {
		shortIDStr = strings.TrimSpace(q.Get("sid"))
	}
	if shortIDStr == "" && u.User != nil {
		shortIDStr = strings.TrimSpace(u.User.Username())
	}
	if shortIDStr == "" {
		return cfg, fmt.Errorf("missing required shortid (provide as ?shortid=, ?sid= or in URL userinfo)")
	}
	b, err := decodeFixedHex(shortIDStr, 8, "shortid")
	if err != nil {
		return cfg, err
	}
	copy(cfg.MasterShortID[:], b)

	cfg.Fingerprint = strings.TrimSpace(q.Get("fp"))
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "mix"
	}
	if cfg.MinTransports, err = parseOptionalNonNegativeInt(q.Get("min_transports"), "min_transports"); err != nil {
		return cfg, err
	}
	if cfg.MaxTransports, err = parseOptionalNonNegativeInt(q.Get("max_transports"), "max_transports"); err != nil {
		return cfg, err
	}
	if cfg.MinTransports > 0 && cfg.MaxTransports > 0 && cfg.MaxTransports < cfg.MinTransports {
		return cfg, fmt.Errorf("max_transports below min_transports")
	}

	return cfg, nil
}

func parseOptionalNonNegativeInt(s, name string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s must be non-negative, got %d", name, v)
	}
	return v, nil
}

func decodeFixedHex(s string, wantLen int, name string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("missing required %s query parameter", name)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must decode to %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}
