package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

const defaultWGTurnStatePath = "/tmp/tamizdat-wgturn-state.json"

type wgturnProxyConfig struct {
	Listen         string
	PeerAddr       string
	Workers        int
	WorkersPerRoom int
	BondV2         bool
	UseUDP         bool
	VKHashes       []string
	DeviceID       string
	ConnPassword   string
	VKAppID        string
	VKAppSecret    string
	UserAgent      string
	CaptchaMode    string
	CaptchaDir     string
	CaptchaWait    time.Duration
	CredentialMode string
	TurnHost       string
	TurnPort       string
	SNI            string
	CredCache      string
	StatePath      string
	TURNUser       string
	TURNPass       string
	TURNURLs       []string
	Dialer         func(context.Context, string, string) (net.Conn, error)
	StartupWait    time.Duration
}

type wgturnProxyClient struct {
	runner *wgturnclient.Runner
	cancel context.CancelFunc
	done   chan error

	attach *wgturnclient.AttachResult

	cachePath     string
	cacheMu       sync.Mutex
	cacheSig      string
	roomCacheSigs map[string]string
}

func newWGTurnProxyClient(parent context.Context, cfg wgturnProxyConfig) (*wgturnProxyClient, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = "127.0.0.1:19000"
	}
	if cfg.StartupWait <= 0 {
		// VK TURN allocation quota can take a few minutes to clear after a bad
		// worker fanout. Keep the process alive long enough for the runner's
		// quota backoff instead of letting gate restart it in a tight loop.
		cfg.StartupWait = 7 * time.Minute
	}
	if cfg.CaptchaDir != "" && cfg.CaptchaWait > 0 && cfg.StartupWait < cfg.CaptchaWait+2*time.Minute {
		cfg.StartupWait = cfg.CaptchaWait + 2*time.Minute
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 12
	}
	if strings.TrimSpace(cfg.StatePath) == "" {
		cfg.StatePath = defaultWGTurnStatePath
	}
	writeWGTurnState(cfg.StatePath, map[string]interface{}{
		"state":      "starting",
		"updated_at": time.Now().UTC().Format(time.RFC3339),
		"workers":    cfg.Workers,
		"use_udp":    cfg.UseUDP,
	})
	var (
		creds           *wgturnclient.Credentials
		sig             string
		preloadedByHash map[string]*wgturnclient.Credentials
		roomCacheSigs   map[string]string
		err             error
	)
	if cfg.WorkersPerRoom > 0 {
		if strings.TrimSpace(cfg.TURNUser) != "" || strings.TrimSpace(cfg.TURNPass) != "" || len(cfg.TURNURLs) > 0 {
			return nil, errors.New("multi-room mode requires independent room credentials; single pre-shared TURN credentials are not valid")
		}
		preloadedByHash, roomCacheSigs = loadWGTurnRoomCreds(cfg)
		if len(preloadedByHash) > 0 {
			log.Printf("wgturn loaded room-scoped credential caches: %d/%d", len(preloadedByHash), len(cfg.VKHashes))
		}
	} else {
		creds, sig, err = loadWGTurnCreds(cfg)
		if err != nil {
			writeWGTurnCredsErrorState(cfg.StatePath, err, cfg)
			if len(cfg.VKHashes) == 0 {
				return nil, err
			}
			// Missing, expired, or corrupt cache is not fatal when a VK room is
			// configured: the runner must recover autonomously through VKCalls.
			log.Printf("wgturn credential cache unavailable; acquiring anonymously: %v", err)
			creds, sig = nil, ""
		}
	}

	if creds != nil {
		source := "cache"
		if strings.TrimSpace(cfg.TURNUser) != "" {
			source = "pre-shared"
		}
		writeWGTurnCredentialStatus(cfg.StatePath, source, creds)
	}

	configCh := make(chan string, 1)
	statePath := strings.TrimSpace(cfg.StatePath)
	runner, err := wgturnclient.New(wgturnclient.Config{
		Listen:               cfg.Listen,
		PeerAddr:             strings.TrimSpace(cfg.PeerAddr),
		Workers:              cfg.Workers,
		WorkersPerRoom:       cfg.WorkersPerRoom,
		BondV2:               cfg.BondV2,
		UseUDP:               cfg.UseUDP,
		UseTCP:               !cfg.UseUDP,
		VKHashes:             cfg.VKHashes,
		DeviceID:             firstNonEmpty(cfg.DeviceID, defaultVKDeviceID),
		ConnPassword:         cfg.ConnPassword,
		VKAppID:              strings.TrimSpace(cfg.VKAppID),
		VKAppSecret:          strings.TrimSpace(cfg.VKAppSecret),
		UserAgent:            firstNonEmpty(cfg.UserAgent, defaultVKUserAgent),
		CaptchaMode:          firstNonEmpty(cfg.CaptchaMode, "rjs"),
		CaptchaDir:           strings.TrimSpace(cfg.CaptchaDir),
		CaptchaWait:          cfg.CaptchaWait,
		CredentialMode:       firstNonEmpty(cfg.CredentialMode, "auto"),
		PreloadedCreds:       creds,
		PreloadedCredsByHash: preloadedByHash,
		OnConfig: func(conf string) {
			select {
			case configCh <- conf:
			default:
			}
		},
		OnCredentials: func(fresh *wgturnclient.Credentials) {
			if fresh == nil || strings.TrimSpace(cfg.CredCache) == "" {
				return
			}
			if err := saveWGTurnCreds(cfg.CredCache, cfg.VKHashes, fresh); err != nil {
				log.Printf("wgturn credential cache save failed: %v", err)
				return
			}
			source := strings.TrimSpace(fresh.Source)
			if source == "" {
				source = "credential-refresh"
			}
			writeWGTurnCredentialStatus(cfg.StatePath, source, fresh)
			log.Printf("wgturn credential cache refreshed: urls=%d lifetime=%ds", len(fresh.TurnURLs), fresh.Lifetime)
		},
		OnRoomCredentials: func(hash string, fresh *wgturnclient.Credentials) {
			path := roomCredentialCachePath(cfg.CredCache, hash)
			if fresh == nil || path == "" {
				return
			}
			if err := saveWGTurnCreds(path, []string{hash}, fresh); err != nil {
				log.Printf("wgturn room credential cache save failed: %v", err)
				return
			}
			log.Printf("wgturn room credential cache refreshed: urls=%d lifetime=%ds", len(fresh.TurnURLs), fresh.Lifetime)
		},
		OnQuota: func(reason string) {
			if statePath != "" && wgturnStateIsAttached(statePath) {
				writeWGTurnState(statePath, map[string]interface{}{
					"state":      "degraded",
					"last_error": "quota",
					"reason":     truncateForState(reason, 220),
					"updated_at": time.Now().UTC().Format(time.RFC3339),
					"workers":    cfg.Workers,
					"use_udp":    cfg.UseUDP,
				})
				return
			}
			writeWGTurnState(statePath, map[string]interface{}{
				"state":      "retrying",
				"last_error": "quota",
				"reason":     truncateForState(reason, 220),
				"updated_at": time.Now().UTC().Format(time.RFC3339),
				"workers":    cfg.Workers,
				"use_udp":    cfg.UseUDP,
			})
		},
		TurnHost: cfg.TurnHost,
		TurnPort: cfg.TurnPort,
		SNI:      cfg.SNI,
		Dialer:   cfg.Dialer,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	if roomCacheSigs == nil {
		roomCacheSigs = make(map[string]string)
	}
	c := &wgturnProxyClient{
		runner: runner, cancel: cancel, done: make(chan error, 1),
		cachePath: strings.TrimSpace(cfg.CredCache), cacheSig: sig, roomCacheSigs: roomCacheSigs,
	}
	go func() {
		c.done <- runner.Start(ctx)
	}()
	if cfg.WorkersPerRoom > 0 {
		go c.watchRoomCredCaches(ctx, cfg)
	} else {
		go c.watchCredCache(ctx, cfg)
	}

	startup := time.NewTimer(cfg.StartupWait)
	defer startup.Stop()
	var wgConf string
	select {
	case wgConf = <-configCh:
		if strings.TrimSpace(wgConf) == "" {
			_ = c.Close()
			return nil, errors.New("wgturn returned empty WireGuard config")
		}
	case err := <-c.done:
		_ = c.Close()
		return nil, fmt.Errorf("wgturn runner stopped before GETCONF: %w", err)
	case <-startup.C:
		_ = c.Close()
		return nil, fmt.Errorf("wgturn GETCONF timeout after %s", cfg.StartupWait)
	case <-parent.Done():
		_ = c.Close()
		return nil, parent.Err()
	}

	attach, err := runner.AttachWireGuardUserspace(wgConf)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.attach = attach
	writeWGTurnState(statePath, map[string]interface{}{
		"state":      "attached",
		"updated_at": time.Now().UTC().Format(time.RFC3339),
		"workers":    cfg.Workers,
		"use_udp":    cfg.UseUDP,
	})
	log.Printf("wgturn upstream attached: peer=%s listen=%s workers=%d transport=%s cache=%s", redactHostPort(cfg.PeerAddr), cfg.Listen, cfg.Workers, ternary(cfg.UseUDP, "udp", "tcp"), ternary(creds != nil, "preloaded", "vk-api"))
	return c, nil
}

func (c *wgturnProxyClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c == nil || c.attach == nil || c.attach.Net == nil {
		return nil, errors.New("wgturn netstack is not attached")
	}
	return c.attach.Net.DialContext(ctx, network, address)
}

func (c *wgturnProxyClient) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	if c == nil || c.attach == nil || c.attach.Net == nil {
		return nil, errors.New("wgturn netstack is not attached")
	}
	conn, err := c.attach.Net.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	return &connectedPacketConn{Conn: conn, raddr: conn.RemoteAddr()}, nil
}

func (c *wgturnProxyClient) Close() error {
	if c == nil {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.runner != nil {
		c.runner.Shutdown()
	}
	if c.attach != nil && c.attach.Stop != nil {
		c.attach.Stop()
	}
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

func (c *wgturnProxyClient) watchCredCache(ctx context.Context, cfg wgturnProxyConfig) {
	if strings.TrimSpace(cfg.CredCache) == "" {
		return
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			creds, sig, err := loadWGTurnCreds(cfg)
			if err != nil {
				log.Printf("wgturn cache refresh skipped: %v", err)
				continue
			}
			if creds == nil || sig == "" {
				continue
			}
			c.cacheMu.Lock()
			changed := sig != c.cacheSig
			if changed {
				c.cacheSig = sig
			}
			c.cacheMu.Unlock()
			if changed {
				c.runner.UpdatePreloadedCreds(creds)
				log.Printf("wgturn cache refresh loaded: urls=%d lifetime=%ds", len(creds.TurnURLs), creds.Lifetime)
			}
		}
	}
}

func (c *wgturnProxyClient) watchRoomCredCaches(ctx context.Context, cfg wgturnProxyConfig) {
	if strings.TrimSpace(cfg.CredCache) == "" {
		return
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, hash := range cfg.VKHashes {
				path := roomCredentialCachePath(cfg.CredCache, hash)
				creds, sig, err := loadWGTurnCreds(wgturnProxyConfig{CredCache: path})
				if err != nil || creds == nil || sig == "" {
					continue
				}
				c.cacheMu.Lock()
				changed := sig != c.roomCacheSigs[hash]
				if changed {
					c.roomCacheSigs[hash] = sig
				}
				c.cacheMu.Unlock()
				if changed {
					if err := c.runner.UpdatePreloadedCredsByHash(map[string]*wgturnclient.Credentials{hash: creds}); err != nil {
						log.Printf("wgturn room cache refresh rejected: %v", err)
						continue
					}
					log.Printf("wgturn room cache refresh loaded: urls=%d lifetime=%ds", len(creds.TurnURLs), creds.Lifetime)
				}
			}
		}
	}
}

type connectedPacketConn struct {
	net.Conn
	raddr net.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.raddr, err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func loadWGTurnCreds(cfg wgturnProxyConfig) (*wgturnclient.Credentials, string, error) {
	if strings.TrimSpace(cfg.TURNUser) != "" || strings.TrimSpace(cfg.TURNPass) != "" || len(cfg.TURNURLs) > 0 {
		if strings.TrimSpace(cfg.TURNUser) == "" || strings.TrimSpace(cfg.TURNPass) == "" || len(cfg.TURNURLs) == 0 {
			return nil, "", errors.New("pre-shared TURN creds require user, pass, and urls")
		}
		urls := compactStrings(cfg.TURNURLs)
		turnServers := make([]wgturnclient.TurnServer, 0, len(urls))
		for _, rawURL := range urls {
			if server, _, ok := parseTurnURLMetadata(rawURL); ok {
				turnServers = append(turnServers, server)
			}
		}
		creds := &wgturnclient.Credentials{User: strings.TrimSpace(cfg.TURNUser), Pass: strings.TrimSpace(cfg.TURNPass), TurnURLs: urls, TurnServers: turnServers, Lifetime: 1800}
		return creds, "flags", nil
	}
	path := strings.TrimSpace(cfg.CredCache)
	if path == "" {
		return nil, "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read TURN cache: %w", err)
	}
	st, _ := os.Stat(path)
	creds, expiresAt, err := parseWGTurnCredsJSON(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse TURN cache: %w", err)
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt.Add(-30*time.Second)) {
		return nil, "", fmt.Errorf("TURN cache expired/near-expiry at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	if !expiresAt.IsZero() {
		remaining := int(time.Until(expiresAt).Seconds())
		if remaining > 0 && (creds.Lifetime <= 0 || remaining < creds.Lifetime) {
			creds.Lifetime = remaining
		}
	}
	if st != nil {
		return creds, fmt.Sprintf("%d:%d:%d", st.ModTime().UnixNano(), st.Size(), len(raw)), nil
	}
	return creds, fmt.Sprintf("raw:%d", len(raw)), nil
}

func roomCredentialCachePath(basePath, hash string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(hash)))
	suffix := hex.EncodeToString(sum[:8])
	ext := filepath.Ext(basePath)
	stem := strings.TrimSuffix(basePath, ext)
	return stem + ".room-" + suffix + ext
}

func loadWGTurnRoomCreds(cfg wgturnProxyConfig) (map[string]*wgturnclient.Credentials, map[string]string) {
	credsByHash := make(map[string]*wgturnclient.Credentials)
	sigs := make(map[string]string)
	for _, hash := range compactStrings(cfg.VKHashes) {
		path := roomCredentialCachePath(cfg.CredCache, hash)
		if path == "" {
			continue
		}
		creds, sig, err := loadWGTurnCreds(wgturnProxyConfig{CredCache: path})
		if err != nil || creds == nil {
			continue
		}
		credsByHash[hash] = creds
		sigs[hash] = sig
	}
	return credsByHash, sigs
}

func parseWGTurnCredsJSON(raw []byte) (*wgturnclient.Credentials, time.Time, error) {
	var w struct {
		Username      string   `json:"username"`
		Password      string   `json:"password"`
		TurnServers   []string `json:"turn_servers"`
		TurnServersV2 []struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Scheme    string `json:"scheme"`
			Transport string `json:"transport"`
		} `json:"turn_servers_v2"`
		LifetimeSec int `json:"lifetime_sec"`

		TurnUser string   `json:"turn_user"`
		TurnPass string   `json:"turn_pass"`
		TurnURLs []string `json:"turn_urls"`
		Lifetime int      `json:"lifetime"`
		Expires  string   `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, time.Time{}, err
	}
	user := firstNonEmpty(w.Username, w.TurnUser)
	pass := firstNonEmpty(w.Password, w.TurnPass)
	urls := compactStrings(firstNonEmptySlice(w.TurnServers, w.TurnURLs))
	turnServers := make([]wgturnclient.TurnServer, 0, len(w.TurnServersV2)+len(urls))
	if len(w.TurnServersV2) > 0 {
		urls = urls[:0]
		for _, s := range w.TurnServersV2 {
			server, addr, ok := normalizeTurnServer(s.Host, s.Port, s.Scheme, s.Transport)
			if !ok {
				continue
			}
			turnServers = append(turnServers, server)
			urls = append(urls, addr)
		}
	} else {
		for _, rawURL := range urls {
			if server, _, ok := parseTurnURLMetadata(rawURL); ok {
				turnServers = append(turnServers, server)
			}
		}
	}
	lifetime := w.LifetimeSec
	if lifetime <= 0 {
		lifetime = w.Lifetime
	}
	if lifetime <= 0 {
		lifetime = 1800
	}
	if user == "" || pass == "" || len(urls) == 0 {
		return nil, time.Time{}, errors.New("missing user/pass/urls")
	}
	var expires time.Time
	if strings.TrimSpace(w.Expires) != "" {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(w.Expires)); err == nil {
			expires = t
		}
	}
	return &wgturnclient.Credentials{User: user, Pass: pass, TurnURLs: urls, TurnServers: turnServers, Lifetime: lifetime}, expires, nil
}

func saveWGTurnCreds(path string, hashes []string, creds *wgturnclient.Credentials) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if creds == nil || strings.TrimSpace(creds.User) == "" || strings.TrimSpace(creds.Pass) == "" || len(creds.TurnURLs) == 0 {
		return errors.New("refusing to persist incomplete TURN credentials")
	}
	lifetime := creds.Lifetime
	if lifetime <= 0 {
		lifetime = 600
	}
	type turnServerWire struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Scheme    string `json:"scheme"`
		Transport string `json:"transport"`
	}
	wire := struct {
		Version       int              `json:"version"`
		HashDigest    string           `json:"hash_digest,omitempty"`
		Username      string           `json:"username"`
		Password      string           `json:"password"`
		TurnServers   []string         `json:"turn_servers"`
		TurnServersV2 []turnServerWire `json:"turn_servers_v2,omitempty"`
		LifetimeSec   int              `json:"lifetime_sec"`
		FetchedAt     string           `json:"fetched_at"`
		ExpiresAt     string           `json:"expires_at"`
	}{
		Version:     2,
		HashDigest:  credentialHashDigest(hashes),
		Username:    creds.User,
		Password:    creds.Pass,
		TurnServers: append([]string(nil), creds.TurnURLs...),
		LifetimeSec: lifetime,
		FetchedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt:   time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339Nano),
	}
	for _, server := range creds.TurnServers {
		wire.TurnServersV2 = append(wire.TurnServersV2, turnServerWire{
			Host: server.Host, Port: server.Port, Scheme: server.Scheme, Transport: server.Transport,
		})
	}
	raw, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal TURN cache: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir TURN cache: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tamizdat-turn-*.tmp")
	if err != nil {
		return fmt.Errorf("create TURN cache temp: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("chmod TURN cache temp: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return fmt.Errorf("write TURN cache temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync TURN cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close TURN cache temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename TURN cache: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("chmod TURN cache: %w", err)
	}
	ok = true
	return nil
}

func credentialHashDigest(hashes []string) string {
	parts := compactStrings(hashes)
	if len(parts) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func normalizeTurnServer(host string, port int, scheme, transport string) (wgturnclient.TurnServer, string, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return wgturnclient.TurnServer{}, "", false
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "turn"
	}
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport == "" {
		if scheme == "turns" {
			transport = "tcp"
		} else {
			transport = "udp"
		}
	}
	if transport != "udp" && transport != "tcp" {
		transport = "udp"
	}
	if scheme == "turns" {
		transport = "tcp"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return wgturnclient.TurnServer{Host: host, Port: port, Scheme: scheme, Transport: transport}, addr, true
}

func parseTurnURLMetadata(raw string) (wgturnclient.TurnServer, string, bool) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "turn:") && !strings.HasPrefix(lower, "turns:") {
		return wgturnclient.TurnServer{}, raw, false
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return wgturnclient.TurnServer{}, raw, false
	}
	scheme := strings.ToLower(u.Scheme)
	rest := strings.TrimPrefix(raw, u.Scheme+":")
	if strings.HasPrefix(rest, "//") {
		rest = strings.TrimPrefix(rest, "//")
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		return wgturnclient.TurnServer{}, raw, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return wgturnclient.TurnServer{}, raw, false
	}
	server, addr, ok := normalizeTurnServer(host, port, scheme, u.Query().Get("transport"))
	return server, addr, ok
}

func writeWGTurnCredsErrorState(path string, err error, cfg wgturnProxyConfig) {
	if err == nil {
		return
	}
	reason := err.Error()
	state := "creds-error"
	last := "creds"
	switch {
	case strings.Contains(reason, "expired/near-expiry"):
		state = "expired"
		last = "creds-expired"
	case strings.Contains(reason, "read TURN cache"):
		state = "missing"
		last = "creds-missing"
	case strings.Contains(reason, "parse TURN cache") || strings.Contains(reason, "missing user/pass/urls"):
		state = "invalid"
		last = "creds-invalid"
	}
	writeWGTurnState(path, map[string]interface{}{
		"state":      state,
		"last_error": last,
		"reason":     truncateForState(reason, 220),
		"updated_at": time.Now().UTC().Format(time.RFC3339),
		"workers":    cfg.Workers,
		"use_udp":    cfg.UseUDP,
	})
}

func writeWGTurnCredentialStatus(statePath, source string, creds *wgturnclient.Credentials) {
	if creds == nil {
		return
	}
	lifetime := creds.Lifetime
	if lifetime <= 0 {
		lifetime = 600
	}
	path := strings.TrimSpace(statePath)
	if path == "" {
		path = defaultWGTurnStatePath
	}
	path = strings.TrimSuffix(path, ".json") + "-credentials.json"
	writeWGTurnState(path, map[string]interface{}{
		"state":        "ready",
		"source":       source,
		"urls":         len(creds.TurnURLs),
		"refreshed_at": time.Now().UTC().Format(time.RFC3339),
		"expires_at":   time.Now().Add(time.Duration(lifetime) * time.Second).UTC().Format(time.RFC3339),
	})
}

func writeWGTurnState(path string, state map[string]interface{}) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if _, ok := state["updated_at"]; !ok {
		state["updated_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	if i := strings.LastIndex(path, "/"); i > 0 {
		_ = os.MkdirAll(path[:i], 0755)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0600)
	_ = os.Rename(tmp, path)
}

func wgturnStateIsAttached(path string) bool {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return false
	}
	var w struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(w.State))
	return s == "attached" || s == "degraded"
}

func truncateForState(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmptySlice(a, b []string) []string {
	if len(compactStrings(a)) > 0 {
		return a
	}
	return b
}

func redactHostPort(s string) string {
	h, p, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return "[set]"
	}
	if h == "" {
		h = "[host]"
	}
	return net.JoinHostPort(h, p)
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
