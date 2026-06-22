// Package node implements a config-driven multi-protocol proxy node with
// xray-style inbounds, outbounds, and rule-based routing.
//
// A Node owns:
//   - a set of named Inbound listeners (each accepts user/peer traffic and
//     yields connections with a destination + Request metadata),
//   - a set of named Outbound dialers (each can establish a connection toward
//     the destination — direct, blackholed, or via a Tamizdat tunnel, etc.),
//   - a Dispatcher with ordered routing Rules that map Request → outbound tag.
//
// Wire compatibility for the tamizdat inbound/outbound is provided by
// reusing the existing tamizdat.Server and tamizdat.Client implementations.
package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the top-level node configuration parsed from JSON.
//
// Example minimal config:
//
//	{
//	  "log": {"level": "info"},
//	  "inbounds": [
//	    {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1:1080"}
//	  ],
//	  "outbounds": [
//	    {"tag": "direct", "protocol": "freedom"},
//	    {"tag": "block",  "protocol": "blackhole"}
//	  ],
//	  "routing": {
//	    "default_outbound": "direct",
//	    "rules": [
//	      {"domain": ["geosite:ads"],   "outbound": "block"},
//	      {"ip":     ["10.0.0.0/8"],    "outbound": "block"},
//	      {"network":"udp", "port":"53", "outbound": "direct"}
//	    ]
//	  }
//	}
type Config struct {
	Log            LogConfig        `json:"log,omitempty"`
	Inbounds       []InboundConfig  `json:"inbounds"`
	Outbounds      []OutboundConfig `json:"outbounds"`
	Routing        RoutingConfig    `json:"routing"`
	GeoIPDatPath   string           `json:"geoip_dat_path,omitempty"`
	GeositeDatPath string           `json:"geosite_dat_path,omitempty"`

	baseDir string
}

// LogConfig controls log verbosity. Level is one of "debug","info","warn","error".
type LogConfig struct {
	Level string `json:"level,omitempty"`
}

// InboundConfig describes a single inbound listener.
//
// Protocols (string):
//   - "socks":    plain SOCKS5 server (CONNECT only). Settings: SocksSettings.
//   - "http":     HTTP/1.1 CONNECT proxy. Settings: HTTPSettings.
//   - "tamizdat": tamizdat-protocol server (TLS+H2 CONNECT, masquerade fallback).
//     Settings: TamizdatServerSettings.
//
// Tag must be unique within the config and is used in routing rules
// (rule.inbound_tag) and as the source identifier in dispatcher requests.
type InboundConfig struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Listen   string          `json:"listen,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// OutboundConfig describes a single outbound dialer.
//
// Protocols (string):
//   - "freedom":   direct net.Dial via the OS resolver (with SSRF guard).
//   - "blackhole": drops connections immediately.
//   - "tamizdat":  dial through a tamizdat tunnel. Settings: TamizdatClientSettings.
//   - "socks":     forward to an upstream SOCKS5 proxy. Settings: SocksOutSettings.
//
// Tag must be unique. The first outbound (or the one matched by
// default_outbound) is used when no rule matches.
type OutboundConfig struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// RoutingConfig defines the dispatch policy.
//
// DomainStrategy controls how host strings are interpreted before matching:
//   - "AsIs"        (default): match domain rules against the literal host.
//   - "IPIfNonMatch": if no domain rule matches, resolve the host and try
//     IP rules. (Resolution uses the system resolver.)
//   - "IPOnDemand": resolve the host whenever any rule needs an IP.
//
// Rules are evaluated in order; the first match wins. If no rule matches,
// DefaultOutbound is used; if that is empty, the first outbound is used.
type RoutingConfig struct {
	DomainStrategy  string  `json:"domain_strategy,omitempty"`
	DefaultOutbound string  `json:"default_outbound,omitempty"`
	Rules           []*Rule `json:"rules,omitempty"`
}

// Rule is one entry in the routing table. All non-empty fields must match
// (logical AND across fields, OR within each list).
//
// Field semantics:
//   - Domain: list of domain matchers; each entry is one of:
//     "example.com"           plain (exact match)
//     "domain:example.com"    suffix (matches example.com and *.example.com)
//     "full:foo.example.com"  full (exact host)
//     "regexp:^api[0-9]+\\.x" regex (Go syntax, anchored is caller's job)
//     "keyword:tracking"      substring match
//   - IP:  list of CIDR strings (e.g. "10.0.0.0/8", "192.168.1.1/32",
//     "::1/128"). For non-IP host (a domain) the IP rule may still
//     match if DomainStrategy resolves it.
//   - Port: range expression "80", "1000-2000", or comma list "80,443,8080-8090".
//   - Network: "tcp" | "udp" | "tcp,udp". Empty matches both.
//   - InboundTag: list of inbound tags; rule applies only when the request
//     came from one of these inbounds.
//   - Source: list of source-IP CIDRs (the client peer of the inbound).
//
// Outbound is the tag of the outbound to route to when the rule matches.
type Rule struct {
	Domain     []string `json:"domain,omitempty"`
	IP         []string `json:"ip,omitempty"`
	GeoIP      []string `json:"geoip,omitempty"`
	Geosite    []string `json:"geosite,omitempty"`
	Port       string   `json:"port,omitempty"`
	Network    string   `json:"network,omitempty"`
	InboundTag []string `json:"inbound_tag,omitempty"`
	Source     []string `json:"source,omitempty"`
	User       []string `json:"user,omitempty"`

	// IncludeDomainFile lists xray flat-text domain files to append to Domain.
	// Relative paths are resolved against the JSON config's directory by Node.New.
	IncludeDomainFile []string `json:"include_domain_file,omitempty"`

	// IncludeIPFile lists flat-text CIDR/IP files to append to IP. Bare IPs are
	// accepted by the normal CIDR parser as /32 or /128.
	IncludeIPFile []string `json:"include_ip_file,omitempty"`

	Outbound string `json:"outbound"`
}

// SocksSettings configures a "socks" inbound.
//
// Auth: empty Username/Password = NO AUTH (RFC 1928). Otherwise USER/PASS
// (RFC 1929) is required and other methods are rejected.
//
// UDP: when true, the inbound advertises UDP-ASSOCIATE. (Currently inbound
// SOCKS UDP is not implemented; the field is reserved for forward-compat.)
type SocksAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SocksSettings struct {
	// Username/Password are the legacy single-user shortcut. Accounts enables
	// multi-user USER/PASS auth; routing rules may match the authenticated user.
	Username string         `json:"username,omitempty"`
	Password string         `json:"password,omitempty"`
	Accounts []SocksAccount `json:"accounts,omitempty"`
	UDP      bool           `json:"udp,omitempty"`
}

// HTTPSettings configures an "http" inbound (HTTP/1.1 CONNECT).
type HTTPSettings struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// TamizdatServerSettings configures a "tamizdat" inbound. All fields mirror
// tamizdat.ServerConfig; see that type for full documentation.
type TamizdatServerSettings struct {
	PrivateKeyHex    string            `json:"private_key_hex"`
	ShortIDsHex      []string          `json:"shortids_hex"`
	CertPEMPath      string            `json:"cert_pem_path"`
	KeyPEMPath       string            `json:"key_pem_path"`
	MasqueradeDomain string            `json:"masquerade_domain,omitempty"`
	MasqueradeAddr   string            `json:"masquerade_addr,omitempty"`
	MasqueradePool   map[string]string `json:"masquerade_pool,omitempty"`
	ReplayWindowMs   int               `json:"replay_window_ms,omitempty"`
	Debug            bool              `json:"debug,omitempty"`
	DebugListenAddr  string            `json:"debug_listen_addr,omitempty"`

	// ServerDBPath, when non-empty, points at the SQLite users database that
	// the underlying tamizdat.Server uses to map verified shortids → users
	// (Phase 2 multi-user identity). Setting it activates Request.User
	// population for routing rules with a {"user": [...]} filter; leaving it
	// empty keeps legacy embedded behaviour where Request.User stays "".
	// DisableOutboundRegistry is forced true here: the node owns its outbound
	// chain via the dispatcher, so the lib must not try to attach its own.
	ServerDBPath string `json:"server_db_path,omitempty"`
}

// TamizdatClientSettings configures a "tamizdat" outbound.
type TamizdatClientSettings struct {
	URI           string   `json:"uri,omitempty"`
	ServerAddr    string   `json:"server_addr"`
	ServerNames   []string `json:"server_names"`
	PublicKeyHex  string   `json:"public_key_hex"`
	ShortIDsHex   []string `json:"shortids_hex"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	PoolVariant   string   `json:"pool_variant,omitempty"`
	MinTransports int      `json:"min_transports,omitempty"`
	// MaxTransports caps simultaneous TLS+H2 transports. 0 = applyDefaults
	// pins it to MinTransports. Required for #490 byte-rotation profile
	// because that profile permits one transient overlap.
	MaxTransports int `json:"max_transports,omitempty"`
	// RotationOverlapAllowance permits N transient extra bulk transports
	// during rotation drain. V1 defaults to 1 when BytesPerTransportSoftCap>0.
	RotationOverlapAllowance int      `json:"rotation_overlap_allowance,omitempty"`
	BytesPerTransportSoftCap int64    `json:"bytes_per_transport_soft_cap,omitempty"`
	CoverTrafficEnabled      bool     `json:"cover_traffic_enabled,omitempty"`
	CoverTrafficTargets      []string `json:"cover_traffic_targets,omitempty"`
	IdleTimeoutMs            int      `json:"idle_timeout_ms,omitempty"`
	ConnectTimeoutMs         int      `json:"connect_timeout_ms,omitempty"`
}

// SocksOutSettings configures a "socks" outbound.
type SocksOutSettings struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// LoadConfig reads JSON from the given path and validates it.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.baseDir = filepath.Dir(path)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &cfg, nil
}

// Validate checks structural invariants of the config (unique tags, known
// protocols, every rule references an existing outbound, etc.).
func (c *Config) Validate() error {
	if len(c.Inbounds) == 0 {
		return fmt.Errorf("at least one inbound is required")
	}
	if len(c.Outbounds) == 0 {
		return fmt.Errorf("at least one outbound is required")
	}

	inTags := make(map[string]struct{}, len(c.Inbounds))
	for i, in := range c.Inbounds {
		if in.Tag == "" {
			return fmt.Errorf("inbounds[%d]: tag required", i)
		}
		if _, dup := inTags[in.Tag]; dup {
			return fmt.Errorf("inbounds[%d]: duplicate tag %q", i, in.Tag)
		}
		inTags[in.Tag] = struct{}{}
		switch in.Protocol {
		case "socks", "http", "tamizdat":
		default:
			return fmt.Errorf("inbounds[%d] %q: unknown protocol %q", i, in.Tag, in.Protocol)
		}
		if in.Listen == "" && in.Protocol != "tamizdat" {
			// tamizdat uses Settings.ListenAddr via its own JSON; others need top-level listen
			// (kept loose so future protocols may not require Listen at top level)
		}
	}

	outTags := make(map[string]struct{}, len(c.Outbounds))
	for i, ob := range c.Outbounds {
		if ob.Tag == "" {
			return fmt.Errorf("outbounds[%d]: tag required", i)
		}
		if _, dup := outTags[ob.Tag]; dup {
			return fmt.Errorf("outbounds[%d]: duplicate tag %q", i, ob.Tag)
		}
		outTags[ob.Tag] = struct{}{}
		switch ob.Protocol {
		case "freedom", "blackhole", "tamizdat", "socks":
		default:
			return fmt.Errorf("outbounds[%d] %q: unknown protocol %q", i, ob.Tag, ob.Protocol)
		}
	}

	if c.Routing.DefaultOutbound != "" {
		if _, ok := outTags[c.Routing.DefaultOutbound]; !ok {
			return fmt.Errorf("routing.default_outbound %q: no such outbound", c.Routing.DefaultOutbound)
		}
	}
	for i, r := range c.Routing.Rules {
		if r.Outbound == "" {
			return fmt.Errorf("routing.rules[%d]: outbound required", i)
		}
		if _, ok := outTags[r.Outbound]; !ok {
			return fmt.Errorf("routing.rules[%d]: outbound %q not defined", i, r.Outbound)
		}
		for _, t := range r.InboundTag {
			if _, ok := inTags[t]; !ok {
				return fmt.Errorf("routing.rules[%d]: inbound_tag %q not defined", i, t)
			}
		}
	}
	return nil
}

// durationMs converts an int milliseconds field to time.Duration; 0 ⇒ 0.
func durationMs(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }
