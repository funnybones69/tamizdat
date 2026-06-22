// Command tamizdat-server runs a standalone Tamizdat protocol server.
//
// Inbound configuration (cert/key paths, masquerade domain+pool, listen-addr,
// listen-port, max_streams, proxy-protocol setup) is read from SQLite settings
// rows under -server-db. CLI flags act as bootstrap-time overrides: any flag
// that is explicitly passed on the command line takes precedence over the
// matching settings row. Operators normally manage these via the panel UI;
// the systemd unit's ExecStart only carries -listen, -server-db, -pidfile,
// and (optionally) -shape-event-log + -debug. The shape-event log self-rotates
// by size; -shape-event-log-max-mb / -shape-event-log-backups tune the policy.
//
// Note: a few inbound_* settings are panel-only and intentionally NOT consumed
// here — see the comment block in main() for inbound_public_port,
// inbound_fingerprint, and inbound_jitter_ms.
//
// Bootstrap: an empty users table on first start is migrated from the legacy
// /etc/tamizdat/shortid.hex file into a single user "default".
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	_ "net/http/pprof" // pprof routes attach to http.DefaultServeMux, exposed via -debug + -debug-listen
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/proxyproto"
	"github.com/funnybones69/tamizdat/internal/rulesdb"
	"github.com/funnybones69/tamizdat/internal/turncreds"
	"github.com/funnybones69/tamizdat/internal/userdb"
	"github.com/funnybones69/tamizdat/internal/vkcreds"
	"github.com/funnybones69/tamizdat/internal/wgturn"
	"github.com/funnybones69/tamizdat/node"
	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

func main() {
	var (
		listenAddr           = flag.String("listen", "", "Listen address (overrides settings.inbound_listen_addr+inbound_listen_port)")
		masqueradeDomain     = flag.String("domain", "", "Masquerade domain (overrides settings.inbound_masquerade_domain)")
		masqueradeAddr       = flag.String("domain-addr", "", "Masquerade domain IP:port override")
		masqPool             = flag.String("masq-pool", "", "Cover-SNI rotation pool (overrides settings.inbound_masquerade_pool)")
		certFile             = flag.String("cert", "", "TLS certificate PEM file (overrides settings.inbound_cert_path)")
		keyFile              = flag.String("key", "", "TLS key PEM file (overrides settings.inbound_key_path)")
		privKeyHex           = flag.String("privkey", "", "Server X25519 private key (hex; deprecated, visible in process list)")
		privKeyFile          = flag.String("privkey-file", "", "Path to file containing server X25519 private key hex (overrides settings.inbound_priv_key_path)")
		shortIDHex           = flag.String("shortid", "", "Master short ID (hex, 16 chars; deprecated, visible in process list)")
		shortIDFile          = flag.String("shortid-file", "", "Path to file containing master short ID hex (defaults to settings.inbound_shortid_path or /etc/tamizdat/shortid.hex)")
		coverConfig          = flag.String("cover-config", "", "Path to server-pushed cover config bundle JSON")
		genKeys              = flag.Bool("genkeys", false, "Generate new server keypair and short ID")
		debug                = flag.Bool("debug", false, "Enable debug logs and localhost expvar /debug/vars")
		debugListen          = flag.String("debug-listen", "127.0.0.1:6060", "Debug expvar listen addr (Debug=true only)")
		shapeEventLog        = flag.String("shape-event-log", "", "Optional path to a separate log file for per-stream open/close events. Empty = disabled.")
		shapeEventLogMaxMB   = flag.Int("shape-event-log-max-mb", 2, "Shape-event log rotation: max file size in MB before rotating (default 2).")
		shapeEventLogBackups = flag.Int("shape-event-log-backups", 4, "Shape-event log rotation: rotated backups to keep (default 4; total ≤10 MB).")
		serverDB             = flag.String("server-db", "/etc/tamizdat/data.db", "SQLite shared tamizdat data DB path. Set empty to disable Phase 1 outbound registry.")
		pidFile              = flag.String("pidfile", "", "Optional path to write this process PID for panel-triggered SIGHUP reloads")
		proxyProtocol        = flag.Bool("proxy-protocol", false, "Accept PROXY protocol v1/v2 header on inbound connections (overrides settings.inbound_proxy_protocol)")
		proxyProtocolFrom    = flag.String("proxy-protocol-from", "", "Comma-separated CIDRs of trusted upstream proxies (overrides settings.inbound_proxy_protocol_from)")
		maxStreams           = flag.Int("max-streams", 0, "SETTINGS_MAX_CONCURRENT_STREAMS announced by the H2 server (0 = use settings.inbound_max_streams or default 1000)")
		fragPoCListen        = flag.String("fragpoc-listen", "", "Optional plain fragmented TCP PoC listener addr. Empty disables FragPoC.")
		fragPoCDynamic       = flag.Bool("fragpoc-dynamic", false, "Enable the FragPoC dynamic listener-port pool — opens extra listener ports under load and closes them when idle. Requires -fragpoc-listen. Default off.")
		fragPoCMaxPorts      = flag.Int("fragpoc-max-ports", 0, "Max ADDITIONAL FragPoC listener ports the dynamic pool may open (0 disables opening).")
		fragPoCPortMode      = flag.String("fragpoc-port-mode", "random", "FragPoC dynamic-port selection mode: \"random\" or \"list\".")
		fragPoCPortPool      = flag.String("fragpoc-port-pool", "", "Candidate ports for the FragPoC dynamic pool: comma-separated ports and/or \"lo-hi\" ranges, e.g. \"31510-31560\". In list mode this is the explicit required set; in random mode an empty value falls back to a built-in range.")
		fragPoCSamePort      = flag.Bool("fragpoc-same-port", false, "Enable FragPoC demux on the primary listener. PoC only; H2/TLS remains primary.")
		fragPoCDownTO        = flag.Duration("fragpoc-down-timeout", 500*time.Millisecond, "FragPoC server DOWN long-poll timeout before an empty response. Lower values reduce full-tunnel idle-flow slot monopolization.")
		fragPoCMaxPayload    = flag.Int("fragpoc-max-payload", 0, "FragPoC server DOWN data chunk cap in bytes. 0 = transport default; use ~220 for restricted iPhone/LTE hotspot paths that blackhole larger first replies.")
		geoDataDir           = flag.String("geodata-dir", node.DefaultGeoDataDir, "Directory holding geoip.dat / geosite.dat (xray format). Auto-downloaded from Loyalsoldier/v2ray-rules-dat unless --no-geodata-update is set.")
		geoIPURL             = flag.String("geoip-url", node.DefaultGeoIPURL, "Override URL for geoip.dat (default: Loyalsoldier/v2ray-rules-dat latest release)")
		geoSiteURL           = flag.String("geosite-url", node.DefaultGeoSiteURL, "Override URL for geosite.dat (default: Loyalsoldier/v2ray-rules-dat latest release)")
		geoDataInterval      = flag.Duration("geodata-interval", node.DefaultGeoDataInterval, "Periodic re-check interval for geoip/geosite. 0 disables periodic refresh (still does the startup pass).")
		noGeoDataUpdate      = flag.Bool("no-geodata-update", false, "Disable network downloads of geoip.dat / geosite.dat. Server uses whatever is already on disk in --geodata-dir, or falls back to curated in-tree shortlist.")
		replayWindow         = flag.Duration("replay-window", 5*time.Minute, "Server-side replay-guard retention window. Each accepted handshake's replay key (SHA-256(SessionID||eph_pub)[:16]) is held for this duration; second handshake reusing the tuple within the window is rejected.")
		disableCertPad       = flag.Bool("disable-cert-padding", false, "Skip the dummy CA-style cert-chain padding pass. Useful when the inbound cert is a real LE / commercial CA chain that already exceeds the ~4 KB target; padding would produce a Frankenstein chain. Default false.")
	)
	flag.Parse()

	if *genKeys {
		generateKeys()
		return
	}

	// Pre-load inbound settings from SQLite so unset CLI flags can fall back
	// to the panel-managed values. The DB is opened twice (here, then again
	// inside NewServer) which is fine — both share the same SQLite file with
	// busy_timeout/WAL.
	settings := loadInboundSettings(*serverDB)
	flagSet := flagsExplicitlySet()
	configureWGTurnFromSettings(settings, flagSet)

	resolveStr := func(flagName, cliValue, dbKey, builtinDefault string) string {
		if flagSet[flagName] {
			return cliValue
		}
		if v, ok := settings[dbKey]; ok && v != "" {
			return v
		}
		if cliValue != "" {
			return cliValue
		}
		return builtinDefault
	}
	resolveBool := func(flagName string, cliValue bool, dbKey string) bool {
		if flagSet[flagName] {
			return cliValue
		}
		if v, ok := settings[dbKey]; ok && v != "" {
			return v == "1" || strings.EqualFold(v, "true")
		}
		return cliValue
	}
	resolveInt := func(flagName string, cliValue int, dbKey string, builtinDefault int) int {
		if flagSet[flagName] {
			return cliValue
		}
		if v, ok := settings[dbKey]; ok && strings.TrimSpace(v) != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
		if cliValue != 0 {
			return cliValue
		}
		return builtinDefault
	}

	listenResolved := resolveStr("listen", *listenAddr, "", "")
	if listenResolved == "" {
		// Combine inbound_listen_addr + inbound_listen_port from settings.
		addr := settings["inbound_listen_addr"]
		port := settings["inbound_listen_port"]
		if addr == "" {
			addr = "127.0.0.1"
		}
		if port == "" {
			port = "7780"
		}
		listenResolved = addr + ":" + port
	}
	domainResolved := resolveStr("domain", *masqueradeDomain, "inbound_masquerade_domain", "")
	masqPoolResolved := resolveStr("masq-pool", *masqPool, "inbound_masquerade_pool", "")
	certFileResolved := resolveStr("cert", *certFile, "inbound_cert_path", "")
	keyFileResolved := resolveStr("key", *keyFile, "inbound_key_path", "")
	privKeyFileResolved := resolveStr("privkey-file", *privKeyFile, "inbound_priv_key_path", "")
	shortIDFileResolved := resolveStr("shortid-file", *shortIDFile, "inbound_shortid_path", userdb.DefaultLegacyShortIDPath)
	proxyProtocolResolved := resolveBool("proxy-protocol", *proxyProtocol, "inbound_proxy_protocol")
	proxyProtocolFromResolved := resolveStr("proxy-protocol-from", *proxyProtocolFrom, "inbound_proxy_protocol_from", "127.0.0.1/32")
	maxStreamsResolved := resolveInt("max-streams", *maxStreams, "inbound_max_streams", 0)
	fragPoCDynamicResolved := resolveBool("fragpoc-dynamic", *fragPoCDynamic, "fragpoc_dynamic_enabled")
	fragPoCMaxPortsResolved := resolveInt("fragpoc-max-ports", *fragPoCMaxPorts, "fragpoc_dynamic_max_ports", 0)
	fragPoCPortModeResolved := resolveStr("fragpoc-port-mode", *fragPoCPortMode, "fragpoc_dynamic_mode", "random")
	fragPoCPortPoolResolved := resolveStr("fragpoc-port-pool", *fragPoCPortPool, "fragpoc_dynamic_pool", "")

	// Panel-only settings the server does NOT consume (informational / URI-render hints):
	//   inbound_public_port  — client-facing TCP port rendered into tamizdat:// URIs by
	//                          the panel; server binds inbound_listen_addr:inbound_listen_port,
	//                          public_port is the externally-visible 443/etc that nginx maps to.
	//   inbound_fingerprint  — uTLS fingerprint name (e.g. "chrome", "mix"); a CLIENT concept
	//                          for browser mimicry. Server-side TLS uses crypto/tls.Server,
	//                          there is no ServerConfig.Fingerprint to wire it to. Panel
	//                          renders this into the URI's ?fp= for client uTLS selection.
	//   inbound_jitter_ms    — historic per-record send-jitter knob; data-path jitter was
	//                          removed (P0.4, see shaper.go) per NDSS 2025 dMAP analysis.
	//                          Setting is preserved for backward compat with old panels but
	//                          has no effect.

	var proxyTrusted []*net.IPNet
	if proxyProtocolResolved {
		pt, err := proxyproto.ParseCIDRs(proxyProtocolFromResolved)
		if err != nil {
			log.Fatalf("proxy-protocol-from: %v", err)
		}
		if len(pt) == 0 {
			log.Fatalf("proxy-protocol-from: must list at least one trusted CIDR when proxy-protocol is set (got empty)")
		}
		proxyTrusted = pt
	}

	if certFileResolved == "" || keyFileResolved == "" {
		log.Fatal("--cert and --key are required (or set inbound_cert_path/inbound_key_path in settings)")
	}
	privKey, err := readHexFlagOrFile("privkey", *privKeyHex, "privkey-file", privKeyFileResolved, 32, "use --genkeys to generate")
	if err != nil {
		log.Fatal(err)
	}
	// shortid is optional when --server-db is set: identity is sourced from
	// the userdb users table. Multi-user-cleanup operator policy: shortIDs
	// ONLY in users table; NO global master_shortid identity field.
	var masterShortID [8]byte
	shortIDBytes, sidErr := readHexFlagOrFile("shortid", *shortIDHex, "shortid-file", shortIDFileResolved, 8, "use --genkeys to generate")
	if sidErr != nil {
		if *serverDB == "" {
			log.Fatal(sidErr)
		}
		// soft-fail: panel-managed deployments DO NOT need shortid.hex
		log.Printf("INFO --shortid/-shortid-file unset; relying on userdb (--server-db=%q) for identity", *serverDB)
	} else {
		copy(masterShortID[:], shortIDBytes)
	}

	certPEM, err := os.ReadFile(certFileResolved)
	if err != nil {
		log.Fatalf("reading cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFileResolved)
	if err != nil {
		log.Fatalf("reading key: %v", err)
	}

	// Panel v5: routing dispatcher store. Owned by main.go so the
	// `node ⇄ tamizdat` import edge stays one-way (server.go cannot
	// import internal/rulesdb without a cycle).
	routingStore := &rulesdb.Store{}

	// VK TURN credential manager. Always created (even when disabled)
	// so SIGHUP can hot-enable it without a server restart.
	turnMgr := turncreds.NewManager(
		buildVKCredsConfig(settings),
		settings["turn_vk_call_hash"],
		settings["turn_vk_enabled"] == "1",
	)
	turnCtx, turnCancel := context.WithCancel(context.Background())
	defer turnCancel()
	turnMgr.Start(turnCtx)
	if settings["turn_vk_enabled"] == "1" {
		log.Printf("[turncreds] VK TURN credential manager started (hash=%s)", truncateStr(settings["turn_vk_call_hash"], 12))
	} else {
		log.Printf("[turncreds] VK TURN credential manager disabled")
	}

	config := tamizdat.ServerConfig{
		ListenAddr:              listenResolved,
		PrivateKey:              privKey,
		MasterShortID:           masterShortID,
		CoverConfigPath:         *coverConfig,
		MaxConcurrentStreams:    maxStreamsResolved,
		InboundPoolVariant:      settings["inbound_pool_variant"],
		SniffEnabled:            settings["inbound_sniff_enabled"] == "1" || settings["inbound_sniff_enabled"] == "true",
		CertPEM:                 certPEM,
		KeyPEM:                  keyPEM,
		MasqueradeDomain:        domainResolved,
		MasqueradePool:          parseMasqPool(masqPoolResolved),
		MasqueradeAddr:          *masqueradeAddr,
		Debug:                   *debug,
		DebugListenAddr:         *debugListen,
		ShapeEventLogPath:       *shapeEventLog,
		ShapeEventLogMaxBytes:   int64(*shapeEventLogMaxMB) << 20,
		ShapeEventLogMaxBackups: *shapeEventLogBackups,
		ServerDBPath:            *serverDB,
		LegacyShortIDPath:       shortIDFileResolved,
		ReplayWindow:            *replayWindow,
		DisableCertPadding:      *disableCertPad,
		ProxyProtocol:           proxyProtocolResolved,
		ProxyProtocolTrusted:    proxyTrusted,
		FragPoCSamePort:         *fragPoCSamePort,
		FragPoCDownReadTimeout:  *fragPoCDownTO,
		FragPoCMaxPayload:       *fragPoCMaxPayload,
		TURNCredsProvider:       turnMgr,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			proxyHandler(ctx, conn, destination, *debug)
		},
		RoutingResolver: func(ctx context.Context, host string, port int, inboundTag, user string) string {
			return rulesdb.ResolveTCP(ctx, routingStore.Load(), host, port, inboundTag, user)
		},
	}

	server, err := tamizdat.NewServer(config)
	if err != nil {
		log.Fatalf("creating server: %v", err)
	}
	cleanupPID, err := writePIDFile(*pidFile)
	if err != nil {
		log.Fatalf("pidfile: %v", err)
	}
	defer cleanupPID()

	// Panel v5: load routing_rules now that the server has its outbound
	// registry initialised. Errors are non-fatal — bad rule rows shouldn't
	// stop the server from booting; the resolver will simply return ""
	// (registry default) until the next SIGHUP reload fixes them.
	if total, err := publishRouting(*serverDB, *geoDataDir, routingStore, server.OutboundTags()); err != nil {
		log.Printf("WARN routing_rules initial load: %v", err)
	} else if total > 0 {
		log.Printf("routing: %d enabled rules loaded from %s", total, *serverDB)
	}

	// Geodata auto-updater (3x-ui style). Runs in the background, refreshes
	// geoip.dat / geosite.dat from Loyalsoldier/v2ray-rules-dat, and on each
	// successful refresh re-publishes the routing dispatcher so geoip:/geosite:
	// rules immediately see the new dataset without an operator SIGHUP.
	//
	// Safety: download failure NEVER aborts boot — Start() logs warnings and
	// returns nil. Server keeps serving with whatever .dat is on disk (or the
	// curated in-tree fallback if nothing is there yet).
	geoCtx, geoCancel := context.WithCancel(context.Background())
	defer geoCancel()
	var geoUpdater *node.GeoDataUpdater
	if !*noGeoDataUpdate {
		// Phase 4 (2026-05-10): panel's inbound_geoip_url / inbound_geosite_url
		// settings may carry a newline-separated list of URLs. Each non-empty
		// trimmed line is one source; the updater downloads them to
		// geoip-<idx>.dat / geosite-<idx>.dat (index 0 keeps the legacy
		// flat filename), and node.LoadGeoDBMulti merges entries at load
		// time. Single-URL operators see no behavioural change.
		geoIPMulti := splitGeoURLs(resolveStr("geoip-url", *geoIPURL, "inbound_geoip_url", ""))
		geoSiteMulti := splitGeoURLs(resolveStr("geosite-url", *geoSiteURL, "inbound_geosite_url", ""))
		geoUpdater = &node.GeoDataUpdater{
			Dir:            *geoDataDir,
			GeoIPURL:       *geoIPURL,
			GeoSiteURL:     *geoSiteURL,
			GeoIPURLs:      geoIPMulti,
			GeoSiteURLs:    geoSiteMulti,
			UpdateInterval: *geoDataInterval,
			OnRefresh: func(path string) {
				if total, err := publishRouting(*serverDB, *geoDataDir, routingStore, server.OutboundTags()); err != nil {
					log.Printf("geodata: post-refresh routing republish skipped: %v", err)
				} else {
					log.Printf("geodata: %s refreshed → routing republished (%d rules)", path, total)
				}
			},
		}
		if err := geoUpdater.Start(geoCtx); err != nil {
			log.Printf("WARN geodata updater start: %v (continuing without auto-update)", err)
		}
		if n := len(geoIPMulti) + len(geoSiteMulti); n > 0 {
			log.Printf("geodata: multi-source enabled (%d geoip + %d geosite URLs)", len(geoIPMulti), len(geoSiteMulti))
		}
	} else {
		log.Printf("geodata: auto-update disabled (--no-geodata-update); using whatever is in %s", *geoDataDir)
	}

	// Start the optional DTLS+WireGuard-over-TURN inbound if configured.
	// Pass the server's outbound registry so the wgturn bridge can route
	// decapsulated flows through Phase-2G outbound tags/rules.
	wgturnCtx, wgturnCancel := context.WithCancel(context.Background())
	defer wgturnCancel()
	wgturnAuth := func(ctx context.Context, deviceID, password string) (wgturn.ClientIdentity, string) {
		shortID := strings.ToLower(strings.TrimSpace(password))
		if len(shortID) != 16 {
			return wgturn.ClientIdentity{}, "wrong_password"
		}
		if _, err := hex.DecodeString(shortID); err != nil {
			return wgturn.ClientIdentity{}, "wrong_password"
		}
		userID, userName, sessionID, ok := server.AuthenticateUserShortIDHex(shortID)
		if !ok {
			return wgturn.ClientIdentity{}, "wrong_password"
		}
		return wgturn.ClientIdentity{ShortIDHex: shortID, UserID: userID, UserName: userName, SessionID: sessionID}, ""
	}
	wgturnIdentityDone := func(id wgturn.ClientIdentity) {
		server.EndUserSession(id.UserID, id.SessionID)
	}
	wgturnFlowRouter := func(ctx context.Context, flow wgturn.Flow) string {
		return rulesdb.Resolve(ctx, routingStore.Load(), flow.Network, flow.DestHost, flow.DestPort, "wgturn-in", flow.Identity.UserName)
	}
	wgturnShutdown := startWGTurn(wgturnCtx, server.OutboundRegistry(), wgturnAuth, wgturnIdentityDone, wgturnFlowRouter, server.UserTrafficAccounting())

	// Handle shutdown and outbound-registry reload signals.
	var fragPoCLn net.Listener
	fragPoCMgrCancel := func() {}
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		log.Println("Shutting down...")
		turnCancel()
		turnMgr.Stop()
		wgturnCancel()
		wgturnShutdown()
		geoCancel()
		fragPoCMgrCancel()
		if fragPoCLn != nil {
			_ = fragPoCLn.Close()
		}
		server.Close()
	}()

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	go func() {
		for range reloadCh {
			if count, defaultTag, err := server.ReloadOutbounds(); err != nil {
				log.Printf("SIGHUP outbound reload failed: %v", err)
			} else {
				log.Printf("SIGHUP outbound reload #%d complete (default=%s)", count, defaultTag)
			}
			if count, total, err := server.ReloadUsers(); err != nil {
				log.Printf("SIGHUP userdb reload skipped: %v", err)
			} else {
				log.Printf("SIGHUP userdb reload #%d complete (%d users)", count, total)
			}
			// Trigger a fresh geodata pull on SIGHUP so the operator can
			// force-refresh out of band (e.g. after editing /etc/tamizdat/
			// directly or rotating to a different upstream URL).
			if geoUpdater != nil {
				go func() {
					_ = geoUpdater.RefreshNow(geoCtx)
				}()
			}
			if total, err := publishRouting(*serverDB, *geoDataDir, routingStore, server.OutboundTags()); err != nil {
				log.Printf("SIGHUP routing reload skipped: %v", err)
			} else {
				log.Printf("SIGHUP routing reload complete (%d rules)", total)
			}
			// Reload VK TURN credential settings.
			reloadedSettings := loadInboundSettings(*serverDB)
			turnMgr.Reload(
				buildVKCredsConfig(reloadedSettings),
				reloadedSettings["turn_vk_call_hash"],
				reloadedSettings["turn_vk_enabled"] == "1",
			)
			log.Printf("SIGHUP turn creds reload (enabled=%v)", reloadedSettings["turn_vk_enabled"] == "1")
		}
	}()

	if addr := strings.TrimSpace(*fragPoCListen); addr != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			log.Fatalf("fragpoc listen on %s: %v", addr, lerr)
		}
		fragPoCLn = ln
		go func() {
			log.Printf("tamizdat fragpoc listening on %s", ln.Addr())
			if err := server.ServeFragPoC(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("fragpoc server error: %v", err)
			}
		}()
	}
	if fragPoCLn != nil && fragPoCDynamicResolved {
		host, portStr, splitErr := net.SplitHostPort(fragPoCLn.Addr().String())
		if splitErr != nil {
			log.Printf("fragpoc dynamic ports disabled: cannot parse base listener addr %q: %v", fragPoCLn.Addr().String(), splitErr)
		} else {
			basePort, _ := strconv.Atoi(portStr)
			pool, perr := tamizdat.ParseFragPoCPortPool(fragPoCPortPoolResolved)
			if perr != nil {
				log.Fatalf("fragpoc-port-pool: %v", perr)
			}
			fragMgrCtx, cancel := context.WithCancel(context.Background())
			fragPoCMgrCancel = cancel
			serveFunc := func(l net.Listener) {
				if err := server.ServeFragPoC(l); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("fragpoc dynamic listener error: %v", err)
				}
			}
			mgr := tamizdat.NewFragPoCPortManager(tamizdat.FragPoCPortConfig{
				Enabled:  true,
				MaxPorts: fragPoCMaxPortsResolved,
				Mode:     fragPoCPortModeResolved,
				Pool:     pool,
				BindHost: host,
				BasePort: basePort,
			}, serveFunc, server.FragPoCSessionCount, log.Printf)
			mgr.Start(fragMgrCtx)
			server.SetFragPoCPortManager(mgr)
			log.Printf("tamizdat fragpoc dynamic ports enabled (mode=%s max=%d base=%d)", fragPoCPortModeResolved, fragPoCMaxPortsResolved, basePort)
		}
	}
	if *fragPoCSamePort {
		log.Printf("tamizdat fragpoc same-port demux enabled on %s", listenResolved)
	}

	log.Printf("tamizdat server listening on %s (masquerade: %s)", listenResolved, domainResolved)
	if err := server.ListenAndServe(); err != nil {
		cleanupPID()
		log.Fatalf("server error: %v", err)
	}
}

func writePIDFile(path string) (func(), error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create pidfile dir %s: %w", dir, err)
		}
	}
	pid := fmt.Sprintf("%d\n", os.Getpid())
	if err := os.WriteFile(path, []byte(pid), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return func() {
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) != strings.TrimSpace(pid) {
			return
		}
		_ = os.Remove(path)
	}, nil
}

func readHexFlagOrFile(flagName, flagValue, fileFlagName, filePath string, wantBytes int, missingHint string) ([]byte, error) {
	flagValue = strings.TrimSpace(flagValue)
	filePath = strings.TrimSpace(filePath)
	if flagValue != "" && filePath != "" {
		return nil, fmt.Errorf("use one of -%s or -%s, not both", flagName, fileFlagName)
	}

	var hexValue string
	switch {
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading -%s: %w", fileFlagName, err)
		}
		hexValue = strings.TrimSpace(string(data))
	case flagValue != "":
		log.Printf("DEPRECATED: -%s on cmdline is visible in /proc/<pid>/cmdline; use -%s", flagName, fileFlagName)
		hexValue = flagValue
	default:
		return nil, fmt.Errorf("--%s is required (%s)", flagName, missingHint)
	}

	decoded, err := hex.DecodeString(hexValue)
	if err != nil || len(decoded) != wantBytes {
		return nil, fmt.Errorf("--%s must be %d hex characters (%d bytes)", flagName, wantBytes*2, wantBytes)
	}
	return decoded, nil
}

func generateKeys() {
	privKey, pubKey, err := tamizdat.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generating keypair: %v", err)
	}
	shortID, err := tamizdat.GenerateShortID()
	if err != nil {
		log.Fatalf("generating short ID: %v", err)
	}

	fmt.Printf("Private key: %s\n", hex.EncodeToString(privKey))
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Short ID:    %s\n", hex.EncodeToString(shortID[:]))
}

// proxyHandler is the default handler that dials the destination and proxies
// data bidirectionally.
func proxyHandler(ctx context.Context, conn net.Conn, destination string, debug bool) {
	defer conn.Close()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}

	// CRIT-0: validate destination + dial resolved IP (defeats SSRF and
	// DNS-rebinding TOCTOU). CRIT-4: log destination only behind debug gate.
	target, err := tamizdat.ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		if debug {
			log.Printf("rejected destination %s: %v", destination, err)
		}
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if debug {
			log.Printf("Failed to dial %s: %v", destination, err)
		}
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
		// HIGH-6: when target sends EOF, propagate write-close to the H2
		// stream so the client's blocking Read(s) wake up cleanly.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

// parseMasqPool turns "sni1=origin1,sni2=origin2" into a map for ServerConfig.
// Empty input returns nil (no pool, default-only behaviour).
func parseMasqPool(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 1 {
			log.Fatalf("--masq-pool: bad pair %q (want sni=origin)", pair)
		}
		sni := strings.TrimSpace(pair[:eq])
		origin := strings.TrimSpace(pair[eq+1:])
		if sni == "" || origin == "" {
			log.Fatalf("--masq-pool: empty sni or origin in %q", pair)
		}
		out[sni] = origin
	}
	return out
}

// flagsExplicitlySet returns the set of flag names that were passed on the
// command line. Used so a caller-supplied -listen :8443 takes precedence
// over a panel-managed inbound_listen_port row, even if the values match.
func flagsExplicitlySet() map[string]bool {
	out := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { out[f.Name] = true })
	return out
}

// publishRouting reads routing_rules from SQLite, builds a fresh
// node.Dispatcher (rule-evaluation only — no real outbound dialers), and
// publishes it on routingStore. Returns the count of enabled rules now
// active. Empty/missing-table cases publish a nil-dispatcher snapshot so
// the resolver short-circuits to "" (registry default tag).
//
// geoDataDir, when non-empty, points at the directory holding xray-format
// geoip.dat / geosite.dat files (auto-downloaded by node.GeoDataUpdater
// when --no-geodata-update is not set). Both files are optional; missing
// files cause node.LoadGeoDB to return (nil, nil) and rule compilation
// then falls back to the curated in-tree shortlist.
//
// 2026-05-13: GeoDB load is now mtime-cached. Parsing the protobuf for a
// big multi-source set (geoip.dat + geosite.dat + geosite-1.dat ≈ 96 MB)
// takes 20-40s on a 1 vCPU VPS, and that ran on EVERY SIGHUP — every
// routing/user/outbound tweak through the panel UI froze for half a
// minute before the new rule actually took effect. Now we re-parse only
// when one of the geo file mtimes has changed.
func publishRouting(serverDB, geoDataDir string, store *rulesdb.Store, knownTags []string) (int, error) {
	if strings.TrimSpace(serverDB) == "" {
		store.Store(&rulesdb.Snapshot{})
		return 0, nil
	}
	db, err := obreg.OpenSQLite(serverDB)
	if err != nil {
		return 0, fmt.Errorf("open routing DB: %w", err)
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		return 0, fmt.Errorf("ensure schema: %w", err)
	}
	rules, err := rulesdb.Load(db)
	if err != nil {
		return 0, err
	}
	defaultTag := userdb.GetSetting(db, "default_outbound_tag", "direct")

	var geoDB *node.GeoDB
	if strings.TrimSpace(geoDataDir) != "" {
		// Phase 4 (2026-05-10): glob for geoip-<n>.dat / geosite-<n>.dat
		// alongside the legacy geoip.dat / geosite.dat so multi-source
		// downloads contribute to the merged GeoDB. Missing files are
		// silently skipped (LoadGeoDBMulti tolerates ENOENT).
		geoIPPaths := collectGeoDatPaths(geoDataDir, "geoip")
		geoSitePaths := collectGeoDatPaths(geoDataDir, "geosite")
		geoDB = loadGeoDBCached(geoIPPaths, geoSitePaths)
	}

	disp, err := rulesdb.BuildWithGeoDB(rules, knownTags, defaultTag, geoDB)
	if err != nil {
		return 0, err
	}
	store.Store(&rulesdb.Snapshot{Dispatcher: disp, DefaultTag: defaultTag})
	return len(rules), nil
}

// geoDBCache holds the last-parsed GeoDB keyed by file mtimes. A successful
// LoadGeoDBMulti is reused as-is until any of the source files change on
// disk (xray-format geodata is immutable post-write, so mtime is a safe
// invalidation signal). Concurrent SIGHUPs serialize on cacheMu — the
// expensive path runs once per file change, every other call returns the
// cached pointer immediately.
var (
	geoDBCacheMu     sync.Mutex
	geoDBCachedFP    string      // hash of (paths + mtimes), "" before first load
	geoDBCachedDB    *node.GeoDB // nil if load returned error or no files
	geoDBCachedErrAt time.Time   // throttle WARN log spam on persistent load errors
)

func geoCacheFingerprint(paths ...[]string) string {
	var b strings.Builder
	for _, set := range paths {
		for _, p := range set {
			st, err := os.Stat(p)
			if err != nil {
				// missing file is a stable signal too — record as "MISS"
				b.WriteString(p)
				b.WriteString("|MISS\n")
				continue
			}
			fmt.Fprintf(&b, "%s|%d|%d\n", p, st.Size(), st.ModTime().UnixNano())
		}
	}
	return b.String()
}

func loadGeoDBCached(geoIPPaths, geoSitePaths []string) *node.GeoDB {
	fp := geoCacheFingerprint(geoIPPaths, geoSitePaths)
	geoDBCacheMu.Lock()
	defer geoDBCacheMu.Unlock()
	if fp == geoDBCachedFP {
		return geoDBCachedDB
	}
	db, err := node.LoadGeoDBMulti(geoIPPaths, geoSitePaths)
	if err != nil {
		// Throttle the WARN to once per minute so a persistently broken
		// geo file doesn't spam the journal every SIGHUP.
		if time.Since(geoDBCachedErrAt) > time.Minute {
			log.Printf("WARN load geo DB (cached): %v (using curated fallback)", err)
			geoDBCachedErrAt = time.Now()
		}
		geoDBCachedFP = fp
		geoDBCachedDB = nil
		return nil
	}
	geoDBCachedFP = fp
	geoDBCachedDB = db
	return db
}

// loadInboundSettings reads the inbound_* settings rows from SQLite and
// returns them as a string→string map. On any error (DB missing, schema not
// yet applied, sqlite open error) the returned map is empty so the caller
// falls back to CLI flags + builtin defaults.
func loadInboundSettings(serverDB string) map[string]string {
	out := make(map[string]string)
	if strings.TrimSpace(serverDB) == "" {
		return out
	}
	db, err := obreg.OpenSQLite(serverDB)
	if err != nil {
		log.Printf("WARN open settings DB: %v", err)
		return out
	}
	defer db.Close()
	if err := userdb.EnsureSchema(db); err != nil {
		log.Printf("WARN ensure userdb schema for settings load: %v", err)
		return out
	}
	settings, err := userdb.LoadSettings(db)
	if err != nil {
		log.Printf("WARN load settings: %v", err)
		return out
	}
	for k, v := range settings {
		out[k] = v
	}
	return out
}

// splitGeoURLs parses a newline-separated multi-URL string from the panel
// (inbound_geoip_url / inbound_geosite_url settings). Empty + whitespace-
// only lines are filtered out. Returns nil when no URLs are present (so
// the updater falls back to the singular field / default URL).
//
// Backward compat: a single URL on a single line yields a 1-element slice;
// the updater treats len==1 identically to the legacy single-source path
// and the on-disk filename stays as the legacy geoip.dat / geosite.dat.
func splitGeoURLs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			// Skip blanks and panel-style "# comment" lines so operators can
			// annotate URLs without breaking the parser.
			continue
		}
		out = append(out, ln)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectGeoDatPaths returns the on-disk paths to merge for one side
// (base = "geoip" or "geosite"). Always includes the legacy <dir>/<base>.dat
// path first (matching the index-0 download target). Then walks
// <dir>/<base>-1.dat .. <base>-N.dat for N up to maxGeoMultiSources (32)
// and includes each one that exists. Missing files are not an error here
// — LoadGeoDBMulti likewise tolerates ENOENT.
func collectGeoDatPaths(dir, base string) []string {
	out := []string{filepath.Join(dir, base+".dat")}
	for i := 1; i <= maxGeoMultiSources; i++ {
		p := filepath.Join(dir, fmt.Sprintf("%s-%d.dat", base, i))
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// maxGeoMultiSources is the panel-side soft cap on how many geo URLs an
// operator can configure per side. 32 is more than anyone should ever
// need; the panel UI can advertise a smaller comfortable limit.
const maxGeoMultiSources = 32

// buildVKCredsConfig constructs a vkcreds.Config from the settings map.
func buildVKCredsConfig(settings map[string]string) *vkcreds.Config {
	maxRetries := 5
	if v, err := strconv.Atoi(settings["turn_vk_max_retries"]); err == nil && v > 0 {
		maxRetries = v
	}
	concurrency := 2
	if v, err := strconv.Atoi(settings["turn_vk_concurrency"]); err == nil && v > 0 {
		concurrency = v
	}
	return &vkcreds.Config{
		AppID:         settings["turn_vk_app_id"],
		AppSecret:     settings["turn_vk_app_secret"],
		DeviceID:      settings["turn_vk_device_id"],
		SecondaryHash: settings["turn_vk_secondary_hash"],
		MaxRetries:    maxRetries,
		Concurrency:   concurrency,
	}
}

// truncateStr returns the first n bytes of s, appending "..." if truncated.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
