//go:build windows

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

const configFileName = "config.uri"

// Config is loaded from a single tamizdat:// URI. Core connection settings
// stay in the URI that is passed to the embedded TUN engine unchanged; optional
// tray/TUN tuning knobs are accepted as extra query parameters.
type Config struct {
	URI                        string
	Server                     string // host:port
	Transport                  string // h2 (default) or fragpoc
	Debug                      bool   // optional; verbose TUN flow diagnostics
	DebugListen                string // optional; 127.0.0.1:port for child /debug/vars
	FragPoCWorkers             int    // optional; default 64, max 120
	FragPoCDownWindow          int    // optional; experimental per-stream DOWN fan-out, 0/1 = legacy
	FragPoCSecure              bool   // optional; secure-v1 AEAD framing for fragpoc
	FragPoCDialConcurrency     int    // optional; TUN logical OPEN gate
	FragPoCActiveConcurrency   int    // optional; active TCP session gate
	FragPoCDialTimeoutMS       int    // optional; TUN logical OPEN attempt timeout
	FragPoCOpenIntervalMS      int    // optional; minimum spacing between outer OPEN attempts
	FragPoCTargetCooldownMS    int    // optional; same ip:port retry cooldown
	FragPoCTargetCooldownMaxMS int    // optional; repeated failure cooldown cap
	FragPoCMinAttemptMS        int    // optional; minimum deadline left before outer dial
	FragPoCRecoveryThreshold   int    // optional; failed opens before global recovery pause
	FragPoCRecoveryBackoffMS   int    // optional; global recovery pause duration
	FragPoCUDPPolicy           string // dns-only (default), all, or off
	MinTransports              int
	MaxTransports              int
	SNI                        string   // TLS ClientHello SNI
	PubKey                     string   // tamizdat server X25519 pubkey, 64 hex
	ShortID                    string   // 16-hex master shortid
	FP                         string   // uTLS fingerprint: chrome / firefox / mix / ...
	BypassRoutes               []string // optional hostnames/IPs that must stay on the physical gateway
	TUN                        struct {
		Name   string // Wintun adapter name (default "TUN")
		MTU    int    // TUN MTU (default 1500)
		IP     string // TUN IPv4 address (default 10.255.0.2)
		Prefix int    // TUN IPv4 prefix length (default 24)
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rawURI := strings.TrimSpace(string(raw))
	if rawURI == "" {
		return nil, errors.New("config: empty URI")
	}

	parsed, err := configurl.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("config URI: %w", err)
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("parse config URI: %w", err)
	}
	q := u.Query()

	c := Config{
		URI:           rawURI,
		Server:        parsed.ServerAddr,
		MinTransports: parsed.MinTransports,
		MaxTransports: parsed.MaxTransports,
		SNI:           parsed.ServerName,
		PubKey:        hex.EncodeToString(parsed.PublicKey),
		ShortID:       hex.EncodeToString(parsed.MasterShortID[:]),
		FP:            parsed.Fingerprint,
	}

	c.Transport = strings.ToLower(strings.TrimSpace(q.Get("transport")))
	if c.Transport == "" {
		c.Transport = "h2"
	}
	if c.Transport != "h2" && c.Transport != "fragpoc" {
		return nil, errors.New("config: 'transport' must be 'h2' or 'fragpoc'")
	}

	if c.Debug, err = optionalBool(q, "debug"); err != nil {
		return nil, err
	}
	c.DebugListen = strings.TrimSpace(q.Get("debug_listen"))
	if c.FragPoCWorkers, err = optionalInt(q, "fragpoc_workers"); err != nil {
		return nil, err
	}
	if c.FragPoCWorkers <= 0 {
		c.FragPoCWorkers = 64
	}
	if c.FragPoCWorkers > 120 {
		c.FragPoCWorkers = 120
	}
	if c.FragPoCDownWindow, err = optionalInt(q, "fragpoc_down_window"); err != nil {
		return nil, err
	}
	if c.FragPoCDownWindow < 0 {
		return nil, errors.New("config: 'fragpoc_down_window' must be >= 0")
	}
	if c.FragPoCDownWindow > 16 {
		c.FragPoCDownWindow = 16
	}
	if c.FragPoCSecure, err = optionalBool(q, "fragpoc_secure"); err != nil {
		return nil, err
	}
	if c.FragPoCDialConcurrency, err = optionalInt(q, "fragpoc_dial_concurrency"); err != nil {
		return nil, err
	}
	if c.FragPoCActiveConcurrency, err = optionalInt(q, "fragpoc_active_concurrency"); err != nil {
		return nil, err
	}
	if c.FragPoCDialTimeoutMS, err = optionalInt(q, "fragpoc_dial_timeout_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCOpenIntervalMS, err = optionalInt(q, "fragpoc_open_interval_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCTargetCooldownMS, err = optionalInt(q, "fragpoc_target_cooldown_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCTargetCooldownMaxMS, err = optionalInt(q, "fragpoc_target_cooldown_max_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCMinAttemptMS, err = optionalInt(q, "fragpoc_min_attempt_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCRecoveryThreshold, err = optionalInt(q, "fragpoc_recovery_threshold"); err != nil {
		return nil, err
	}
	if c.FragPoCRecoveryBackoffMS, err = optionalInt(q, "fragpoc_recovery_backoff_ms"); err != nil {
		return nil, err
	}
	if c.FragPoCDialConcurrency < 0 {
		return nil, errors.New("config: 'fragpoc_dial_concurrency' must be >= 0")
	}
	if c.FragPoCActiveConcurrency < 0 {
		return nil, errors.New("config: 'fragpoc_active_concurrency' must be >= 0")
	}
	if c.FragPoCDialTimeoutMS < 0 {
		return nil, errors.New("config: 'fragpoc_dial_timeout_ms' must be >= 0")
	}
	if c.FragPoCOpenIntervalMS < 0 {
		return nil, errors.New("config: 'fragpoc_open_interval_ms' must be >= 0")
	}
	if c.FragPoCTargetCooldownMS < -1 {
		return nil, errors.New("config: 'fragpoc_target_cooldown_ms' must be >= -1")
	}
	if c.FragPoCTargetCooldownMaxMS < -1 {
		return nil, errors.New("config: 'fragpoc_target_cooldown_max_ms' must be >= -1")
	}
	if c.FragPoCMinAttemptMS < 0 {
		return nil, errors.New("config: 'fragpoc_min_attempt_ms' must be >= 0")
	}
	if c.FragPoCRecoveryThreshold < -1 {
		return nil, errors.New("config: 'fragpoc_recovery_threshold' must be >= -1")
	}
	if c.FragPoCRecoveryBackoffMS < -1 {
		return nil, errors.New("config: 'fragpoc_recovery_backoff_ms' must be >= -1")
	}
	c.FragPoCUDPPolicy = strings.ToLower(strings.TrimSpace(q.Get("fragpoc_udp_policy")))
	if c.FragPoCUDPPolicy == "" {
		c.FragPoCUDPPolicy = "dns-only"
	}
	if c.FragPoCUDPPolicy != "dns-only" && c.FragPoCUDPPolicy != "all" && c.FragPoCUDPPolicy != "off" {
		return nil, errors.New("config: 'fragpoc_udp_policy' must be 'dns-only', 'all', or 'off'")
	}

	c.BypassRoutes = queryList(q, "bypass_routes")
	c.TUN.Name = strings.TrimSpace(q.Get("tun_name"))
	if c.TUN.Name == "" {
		c.TUN.Name = "TUN"
	}
	c.TUN.IP = strings.TrimSpace(q.Get("tun_ip"))
	if c.TUN.IP == "" {
		c.TUN.IP = "10.255.0.2"
	}
	if c.TUN.Prefix, err = optionalInt(q, "tun_prefix"); err != nil {
		return nil, err
	}
	if c.TUN.Prefix <= 0 {
		c.TUN.Prefix = 24
	}
	if c.TUN.MTU, err = optionalIntAny(q, "tun_mtu", "mtu"); err != nil {
		return nil, err
	}
	if c.TUN.MTU <= 0 {
		c.TUN.MTU = 1500
	}
	return &c, nil
}

func optionalBool(q url.Values, name string) (bool, error) {
	raw := strings.TrimSpace(q.Get(name))
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: '%s' must be bool", name)
	}
	return v, nil
}

func optionalInt(q url.Values, name string) (int, error) {
	return optionalIntAny(q, name)
}

func optionalIntAny(q url.Values, names ...string) (int, error) {
	for _, name := range names {
		raw := strings.TrimSpace(q.Get(name))
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("config: '%s' must be an integer", name)
		}
		return v, nil
	}
	return 0, nil
}

func queryList(q url.Values, name string) []string {
	var out []string
	for _, raw := range q[name] {
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// buildURI returns the original tamizdat:// URL that the TUN engine accepts
// via its --config flag. Keep it unmodified so extra URI parameters and the
// human-readable fragment survive the tray wrapper.
func (c *Config) buildURI() string {
	return c.URI
}

// String returns a one-line description for the log + tray tooltip,
// with the pubkey/shortid abbreviated so the line fits on screen.
func (c *Config) String() string {
	abbr := func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	}
	return fmt.Sprintf("%s transport=%s debug=%t debug_listen=%s min_transports=%d max_transports=%d fragpoc_workers=%d fragpoc_down_window=%d fragpoc_secure=%t fragpoc_dial_concurrency=%d fragpoc_active_concurrency=%d fragpoc_dial_timeout_ms=%d fragpoc_open_interval_ms=%d fragpoc_target_cooldown_ms=%d fragpoc_target_cooldown_max_ms=%d fragpoc_min_attempt_ms=%d fragpoc_recovery_threshold=%d fragpoc_recovery_backoff_ms=%d fragpoc_udp_policy=%s sni=%s pubkey=%s shortid=%s fp=%s",
		c.Server, c.Transport, c.Debug, c.DebugListen, c.MinTransports, c.MaxTransports, c.FragPoCWorkers, c.FragPoCDownWindow, c.FragPoCSecure, c.FragPoCDialConcurrency, c.FragPoCActiveConcurrency, c.FragPoCDialTimeoutMS, c.FragPoCOpenIntervalMS, c.FragPoCTargetCooldownMS, c.FragPoCTargetCooldownMaxMS, c.FragPoCMinAttemptMS, c.FragPoCRecoveryThreshold, c.FragPoCRecoveryBackoffMS, c.FragPoCUDPPolicy, c.SNI, abbr(c.PubKey, 8), abbr(c.ShortID, 8), c.FP)
}
