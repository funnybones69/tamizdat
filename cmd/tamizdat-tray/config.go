//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

const configFileName = "config.uri"
const stateFileName = "tamizdat-tray.state"

type ServerProfile struct {
	Label  string // host:port shown in the tray Servers submenu
	Config *Config
}

// Config is loaded from one tamizdat:// URI. config.uri may contain several
// non-empty URI lines; each line becomes a ServerProfile, and the first URI is
// used on launch. Core connection settings stay in the URI that is passed to
// the embedded TUN engine unchanged; optional tray/TUN tuning knobs are
// accepted as extra query parameters.
type Config struct {
	URI                        string
	Server                     string // host:port
	StatePath                  string // local state file that remembers the last selected profile
	Profiles                   []ServerProfile
	ProfileIndex               int
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
	uris := configURIs(string(raw))
	if len(uris) == 0 {
		return nil, errors.New("config: empty URI")
	}

	configs := make([]*Config, 0, len(uris))
	for i, rawURI := range uris {
		cfg, err := parseConfigURI(rawURI)
		if err != nil {
			return nil, fmt.Errorf("config URI #%d: %w", i+1, err)
		}
		configs = append(configs, cfg)
	}
	labels := uniqueServerLabels(configs)
	profiles := make([]ServerProfile, 0, len(configs))
	for i, cfg := range configs {
		profiles = append(profiles, ServerProfile{Label: labels[i], Config: cfg})
	}
	statePath := filepath.Join(filepath.Dir(path), stateFileName)
	for i, cfg := range configs {
		cfg.Profiles = profiles
		cfg.ProfileIndex = i
		cfg.StatePath = statePath
	}
	return configs[loadActiveProfileIndex(statePath, configs)], nil
}

func profileStateKey(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(cfg.URI))
	return hex.EncodeToString(sum[:])
}

func loadActiveProfileIndex(path string, configs []*Config) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var key string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "active_uri_sha256="); ok {
			key = strings.TrimSpace(v)
			break
		}
		// Backward-compatible fallback for an older ad-hoc state file that
		// contained only the hash on the first line.
		key = line
		break
	}
	if key == "" {
		return 0
	}
	for i, cfg := range configs {
		if profileStateKey(cfg) == key {
			return i
		}
	}
	return 0
}

func saveActiveProfile(path string, cfg *Config) error {
	if path == "" || cfg == nil {
		return nil
	}
	content := fmt.Sprintf("active_uri_sha256=%s\n", profileStateKey(cfg))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func configURIs(raw string) []string {
	var uris []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		uris = append(uris, line)
	}
	return uris
}

func uniqueServerLabels(configs []*Config) []string {
	labels := make([]string, len(configs))
	seen := map[string]int{}
	for i, cfg := range configs {
		label := cfg.Server
		if label == "" {
			label = fmt.Sprintf("server-%d", i+1)
		}
		seen[label]++
		if seen[label] > 1 {
			labels[i] = fmt.Sprintf("%s (%d)", label, seen[label])
		} else {
			labels[i] = label
		}
	}
	return labels
}

func parseConfigURI(rawURI string) (*Config, error) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return nil, errors.New("empty URI")
	}

	parsed, err := configurl.Parse(rawURI)
	if err != nil {
		return nil, err
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
