// Command tamizdat-tun-windows exposes a Windows Wintun TUN interface and
// forwards IPv4 TCP flows through the existing Tamizdat Client API.
package main

import (
	"context"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	"github.com/funnybones69/tamizdat/internal/routing"
	"github.com/funnybones69/tamizdat/internal/transport/fragpoc"
	"github.com/funnybones69/tamizdat/internal/tunengine"
	"github.com/funnybones69/tamizdat/node"
	tamizdat "github.com/funnybones69/tamizdat/pkg/tamizdat"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tamizdat-tun-windows", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configURL := fs.String("config", "", "tamizdat:// URL with server, sni, pubkey, shortid and fp")
	transport := fs.String("transport", "h2", "Transport mode: h2 or fragpoc")
	fragPoCWorkers := fs.Int("fragpoc-workers", fragpoc.DefaultWorkers, "FragPoC short-TCP operation budget per client (1-120)")
	fragPoCDownWindow := fs.Int("fragpoc-down-window", 0, "FragPoC concurrent DOWN polls per logical stream. 0 = legacy window 1; experimental.")
	fragPoCSecure := fs.Bool("fragpoc-secure", false, "Enable FragPoC secure-v1 AEAD framing")
	fragPoCUDPPolicy := fs.String("fragpoc-udp-policy", "", "FragPoC UDP policy: dns-only, all, or off. Empty defaults to dns-only in fragpoc mode.")
	tunName := fs.String("tun-name", "Tamizdat", "Windows TUN interface name")
	mtu := fs.Int("mtu", 1500, "TUN MTU")
	debug := fs.Bool("debug", false, "Enable verbose flow logs")
	tcpFrag := fs.Bool("tcpfrag", true, "Enable Tamizdat TCP ClientHello fragmentation")
	debugListen := fs.String("debug-listen", "", "Listen addr (e.g. 127.0.0.1:16062) for /debug/vars expvar HTTP. Empty = off.")
	tcpModerateReceiveBuffer := fs.Bool("tcp-moderate-receive-buffer", true, "Enable gVisor TCP receive-buffer auto-tuning")
	tcpSendBufferSize := fs.Int("tcp-send-buffer-size", 0, "Optional gVisor TCP send buffer size in bytes (0 = default)")
	tcpReceiveBufferSize := fs.Int("tcp-receive-buffer-size", 0, "Optional gVisor TCP receive buffer size in bytes (0 = default)")
	dialAttemptTimeout := fs.Duration("dial-attempt-timeout", 0, "Per-attempt timeout for opening a proxied TCP/UDP flow. 0 = transport default.")
	dialConcurrency := fs.Int("dial-concurrency", 0, "Maximum concurrent proxied TCP/UDP opens from TUN. 0 = transport default/unlimited.")
	dialActiveConcurrency := fs.Int("dial-active-concurrency", 0, "Maximum active proxied TCP sessions from TUN. 0 = transport default/unlimited.")
	dialOpenInterval := fs.Duration("dial-open-interval", 0, "Minimum interval between starting outer TCP OPEN attempts. 0 = transport default/off.")
	dialTargetCooldown := fs.Duration("dial-target-cooldown", 0, "Cooldown after a failed proxied TCP open to the same ip:port. 0 = transport default, negative disables.")
	dialTargetCooldownMax := fs.Duration("dial-target-cooldown-max", 0, "Maximum adaptive cooldown after repeated failed opens to the same ip:port. 0 = transport default, negative disables.")
	dialMinAttemptBudget := fs.Duration("dial-min-attempt-budget", 0, "Minimum caller deadline remaining before starting an outer transport dial. 0 = transport default/off.")
	dialRecoveryThreshold := fs.Int("dial-recovery-threshold", 0, "Consecutive failed TCP open admissions before pausing new opens. 0 = transport default, negative disables.")
	dialRecoveryBackoff := fs.Duration("dial-recovery-backoff", 0, "Global pause after --dial-recovery-threshold failures. 0 = transport default, negative disables.")
	tunIP := fs.String("tun-ip", "10.255.0.2", "IPv4 address to assign to the TUN interface")
	tunPrefix := fs.Int("tun-prefix", 24, "IPv4 prefix length for the TUN interface")
	autoRoute := fs.Bool("auto-route", true, "Automatically configure host-route to server + RFC1918 LAN bypass + default-route via TUN; cleaned up on exit")
	selectiveRoutes := fs.String("selective-routes", "", "Comma-separated host names or IPv4 literals. When set: TUN comes up but default route is NOT installed; instead /32 host-routes for each resolved IP point into the TUN. Use this to route only specific test sites through tamizdat alongside an existing default-route owner (e.g. another VPN).")
	bypassRoutes := fs.String("bypass-routes", "", "Comma-separated host names or IPv4 literals that MUST go through the physical gateway (bypass the tunnel). Default route still goes via TUN. Use this for AI provider APIs / control plane that must remain reachable when the tunnel is congested or geo-blocked from the exit point.")
	selectiveRefresh := fs.Duration("selective-refresh", 5*time.Minute, "How often to re-resolve --selective-routes / --bypass-routes hostnames and update host-routes. 0 = disable.")
	routingConfig := fs.String("routing-config", "", "Path to JSON node config (xray-style inbounds/outbounds/rules). When set, the TUN routes flows via the node Dispatcher (geoip:telegram, geosite:openai, IncludeFile, etc. are honoured). Empty = legacy mode: all TUN flows go through the single tamizdat client built from --config.")
	routeHelp := fs.Bool("route-help", false, "Print manual Windows route setup notes and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s --config 'tamizdat://host:port/?sni=...&pubkey=...&shortid=...&fp=chrome' [flags]\n\n", fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *routeHelp {
		printRouteHelp(stdout, *tunName, *configURL)
		return 0
	}
	if strings.TrimSpace(*configURL) == "" {
		fs.Usage()
		return 2
	}

	// Parse --selective-routes into a slice.
	var selectiveHosts []string
	for _, h := range strings.Split(*selectiveRoutes, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			selectiveHosts = append(selectiveHosts, h)
		}
	}
	if len(selectiveHosts) > 0 && !*autoRoute {
		log.Printf("--selective-routes requires --auto-route=true (it controls how routes are installed)")
		return 2
	}
	// Parse --bypass-routes into a slice.
	var bypassHosts []string
	for _, h := range strings.Split(*bypassRoutes, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			bypassHosts = append(bypassHosts, h)
		}
	}
	if len(bypassHosts) > 0 && !*autoRoute {
		log.Printf("--bypass-routes requires --auto-route=true")
		return 2
	}
	if len(bypassHosts) > 0 && len(selectiveHosts) > 0 {
		log.Printf("--bypass-routes and --selective-routes are mutually exclusive (bypass needs default-via-TUN, selective leaves default alone)")
		return 2
	}

	parsed, err := configurl.Parse(*configURL)
	if err != nil {
		log.Printf("config URL: %v", err)
		return 2
	}

	mode := strings.ToLower(strings.TrimSpace(*transport))
	if mode == "" {
		mode = "h2"
	}
	if mode != "h2" && mode != "fragpoc" {
		log.Printf("--transport must be h2 or fragpoc")
		return 2
	}
	udpPolicy := strings.ToLower(strings.TrimSpace(*fragPoCUDPPolicy))
	if udpPolicy == "" {
		if mode == "fragpoc" {
			udpPolicy = "dns-only"
		} else {
			udpPolicy = "all"
		}
	}
	if udpPolicy != "dns-only" && udpPolicy != "all" && udpPolicy != "off" {
		log.Printf("--fragpoc-udp-policy must be dns-only, all, or off")
		return 2
	}

	var proxyClient tunengine.ProxyClient
	var h2Client *tamizdat.Client
	switch mode {
	case "h2":
		h2Client, err = tamizdat.NewClient(tamizdat.ClientConfig{
			ServerAddr:       parsed.ServerAddr,
			ServerName:       parsed.ServerName,
			ServerNames:      parsed.ServerNames,
			PublicKey:        parsed.PublicKey,
			MasterShortID:    parsed.MasterShortID,
			Fingerprint:      parsed.Fingerprint,
			MinTransports:    parsed.MinTransports,
			MaxTransports:    parsed.MaxTransports,
			TCPFragmentation: *tcpFrag,
		})
		if err != nil {
			log.Printf("client init: %v", err)
			return 1
		}
		proxyClient = h2Client
	case "fragpoc":
		proxyClient, err = fragpoc.NewClient(fragpoc.ClientConfig{
			ServerAddr:       parsed.ServerAddr,
			ShortID:          parsed.MasterShortID,
			Secure:           *fragPoCSecure,
			Workers:          *fragPoCWorkers,
			DownWindow:       *fragPoCDownWindow,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 5 * time.Second,
		})
		if err != nil {
			log.Printf("fragpoc client init: %v", err)
			return 1
		}
	}
	defer proxyClient.Close()

	// Publish RTT probe stats for the Windows tray/status UI.
	expvar.Publish("tamizdat_rtt_probe", expvar.Func(func() interface{} {
		if h2Client != nil {
			return h2Client.RTTProbeSnapshot()
		}
		return map[string]any{"p50_ms": -1, "last_ms": -1, "samples": 0}
	}))

	if addr := strings.TrimSpace(*debugListen); addr != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			log.Printf("debug-listen: %v", lerr)
			return 1
		}
		log.Printf("expvar /debug/vars listening on %s", ln.Addr())
		go func() {
			// expvar registers itself on http.DefaultServeMux at init time
			// (via the blank import above). Use a fresh server so we control
			// shutdown semantics if needed later.
			srv := &http.Server{Handler: http.DefaultServeMux}
			_ = srv.Serve(ln)
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Optional: build a routing-rule dispatcher from a node JSON config. When
	// set, tunengine routes each TCP flow via the dispatcher (geoip:telegram,
	// geosite:openai, IncludeFile rules, etc.) instead of the legacy "all
	// traffic through one tamizdat client" path. The legacy --config tamizdat
	// client built above stays alive: it powers the expvar lamp/stats and is
	// the dialer's fallback if the dispatcher is somehow nil.
	var routingNode *node.Node
	var dispatcher *node.Dispatcher
	if path := strings.TrimSpace(*routingConfig); path != "" {
		nodeCfg, lerr := node.LoadConfig(path)
		if lerr != nil {
			log.Printf("routing-config %q: %v", path, lerr)
			return 2
		}
		n, nerr := node.New(nodeCfg)
		if nerr != nil {
			log.Printf("routing-config %q build node: %v", path, nerr)
			return 1
		}
		routingNode = n
		dispatcher = n.Dispatcher()
		defer routingNode.Close()
		log.Printf("routing-config: %d inbounds, %d outbounds, %d rules loaded from %s",
			len(nodeCfg.Inbounds), len(nodeCfg.Outbounds), len(nodeCfg.Routing.Rules), path)
	}

	attemptTimeout := *dialAttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = 3 * time.Second
		if mode == "fragpoc" {
			attemptTimeout = 4500 * time.Millisecond
		}
	}
	openConcurrency := *dialConcurrency
	if openConcurrency <= 0 && mode == "fragpoc" {
		openConcurrency = 6
	}
	activeConcurrency := *dialActiveConcurrency
	if activeConcurrency <= 0 && mode == "fragpoc" {
		activeConcurrency = 48
	}
	openInterval := *dialOpenInterval
	if openInterval <= 0 && mode == "fragpoc" {
		openInterval = 750 * time.Millisecond
	}
	targetCooldown := *dialTargetCooldown
	if targetCooldown == 0 && mode == "fragpoc" {
		targetCooldown = 3 * time.Second
	}
	targetCooldownMax := *dialTargetCooldownMax
	if targetCooldownMax == 0 && mode == "fragpoc" {
		targetCooldownMax = 30 * time.Second
	}
	minAttemptBudget := *dialMinAttemptBudget
	if minAttemptBudget <= 0 && mode == "fragpoc" {
		minAttemptBudget = 1500 * time.Millisecond
	}
	recoveryThreshold := *dialRecoveryThreshold
	if recoveryThreshold == 0 && mode == "fragpoc" {
		recoveryThreshold = 12
	}
	recoveryBackoff := *dialRecoveryBackoff
	if recoveryBackoff == 0 && mode == "fragpoc" {
		recoveryBackoff = 15 * time.Second
	}
	blockedEndpoints := protectedServerEndpoints(ctx, parsed.ServerAddr)

	opts := tunengine.Options{
		Name:                     *tunName,
		MTU:                      *mtu,
		Debug:                    *debug,
		TCPModerateReceiveBuffer: *tcpModerateReceiveBuffer,
		TCPSendBufferSize:        *tcpSendBufferSize,
		TCPReceiveBufferSize:     *tcpReceiveBufferSize,
		DialAttemptTimeout:       attemptTimeout,
		DialConcurrency:          openConcurrency,
		DialActiveConcurrency:    activeConcurrency,
		DialOpenInterval:         openInterval,
		DialTargetCooldown:       targetCooldown,
		DialTargetCooldownMax:    targetCooldownMax,
		DialMinAttemptBudget:     minAttemptBudget,
		DialRecoveryThreshold:    recoveryThreshold,
		DialRecoveryBackoff:      recoveryBackoff,
		DropPrivateDestinations:  mode == "fragpoc",
		DropAllUDP:               mode == "fragpoc" && udpPolicy == "off",
		DropNonDNSUDP:            mode == "fragpoc" && udpPolicy == "dns-only",
		BlockedEndpoints:         blockedEndpoints,
		Dispatcher:               dispatcher,
	}

	log.Printf("tamizdat TUN starting: server=%s transport=%s sni=%s fp=%s tun=%s mtu=%d dial_attempt_timeout=%s dial_concurrency=%d dial_active_concurrency=%d dial_open_interval=%s dial_target_cooldown=%s dial_target_cooldown_max=%s dial_min_attempt_budget=%s dial_recovery_threshold=%d dial_recovery_backoff=%s drop_private=%t udp_policy=%s blocked_endpoints=%v", parsed.ServerAddr, mode, parsed.ServerName, parsed.Fingerprint, opts.Name, opts.MTU, opts.DialAttemptTimeout, opts.DialConcurrency, opts.DialActiveConcurrency, opts.DialOpenInterval, opts.DialTargetCooldown, opts.DialTargetCooldownMax, opts.DialMinAttemptBudget, opts.DialRecoveryThreshold, opts.DialRecoveryBackoff, opts.DropPrivateDestinations, udpPolicy, opts.BlockedEndpoints)

	// Auto-routing: snapshot original gateway, pin host-route to server, install
	// default route via TUN OR /32 selective routes via TUN. Cleanup on shutdown.
	var routingCleanup func()
	opts.TunIP = *tunIP
	opts.TunPrefix = *tunPrefix
	opts.AutoRoute = *autoRoute
	if *autoRoute {
		defer func() {
			if routingCleanup != nil {
				routingCleanup()
			}
		}()
		opts.PostTunUp = func() error {
			cleanup, e := routing.ConfigureAutoRouting(ctx, parsed.ServerAddr, opts.Name, *tunIP, *tunPrefix, selectiveHosts, bypassHosts, *selectiveRefresh)
			if e != nil {
				return e
			}
			routingCleanup = cleanup
			return nil
		}
	}

	if err := requireWintunDLL(); err != nil {
		log.Printf("wintun: %v", err)
		return 1
	}
	if err := tunengine.Run(ctx, opts, proxyClient); err != nil && ctx.Err() == nil {
		log.Printf("tun: %v", err)
		return 1
	}
	log.Printf("shutdown complete")
	return 0
}

func protectedServerEndpoints(ctx context.Context, serverAddr string) []netip.AddrPort {
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port64 == 0 {
		return nil
	}
	port := uint16(port64)
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), port)}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		log.Printf("protected endpoint resolve %q failed: %v", host, err)
		return nil
	}
	out := make([]netip.AddrPort, 0, len(ips))
	seen := map[netip.AddrPort]struct{}{}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		ep := netip.AddrPortFrom(addr, port)
		if _, exists := seen[ep]; exists {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
	}
	return out
}

func printRouteHelp(w io.Writer, tunName, rawConfig string) {
	server := "<tamizdat-server-ip>"
	if cfg, err := configurl.Parse(rawConfig); err == nil {
		if host, _, splitErr := net.SplitHostPort(cfg.ServerAddr); splitErr == nil {
			server = host
		}
	}

	fmt.Fprintf(w, `Manual Windows routing notes (run PowerShell as Administrator; this program never changes routes automatically):

1. Start the client first:
   .\tamizdat-tun-windows.exe --config "tamizdat://..."

2. Find the TUN interface index:
   Get-NetIPInterface -InterfaceAlias %q

3. Assign an IPv4 address to the TUN if Windows did not assign one:
   New-NetIPAddress -InterfaceAlias %q -IPAddress 10.255.0.2 -PrefixLength 24

4. Add a host route for the Tamizdat server (%s) via your normal physical gateway BEFORE default-routing traffic into the TUN. This prevents Tamizdat outer dials from recursively entering the TUN.

5. Add the default IPv4 route only when ready to test:
   New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias %q -NextHop "0.0.0.0" -RouteMetric 1

6. Remove test route when done:
   Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias %q -Confirm:$false

UDP is intentionally not relayed by Tamizdat v1; UDP flows are dropped so applications can retry over TCP.
`, tunName, tunName, server, tunName, tunName)
}
