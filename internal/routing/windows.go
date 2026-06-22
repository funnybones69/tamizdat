//go:build windows

package routing

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// routingState records what we changed so we can undo it on shutdown.
type routingState struct {
	mu                sync.Mutex
	serverIP          string // host-route destination (server we tunnel to)
	origGateway       string // original physical default gateway
	origIfaceAlias    string // original physical interface alias
	origMetric        string // original physical default route metric
	tunAlias          string // TUN interface alias
	tunIP             string // IP we assigned to TUN
	tunGateway        string // on-link gw for TUN (e.g. 10.255.0.1)
	tunPrefix         int    // /24 etc.
	tunIfaceIdx       int    // ifIndex of TUN
	addedHostRoute    bool
	assignedTunIP     bool
	addedDefaultRoute bool

	// selective-routes mode
	selectiveHosts   []string
	selectiveRefresh time.Duration
	selectiveRoutes  map[string]struct{} // currently installed /32 routes (key = "ip-string")
	selectiveStop    chan struct{}
	selectiveDone    chan struct{}
	// bypass-routes mode: default goes via TUN, but listed hosts are pinned
	// through the physical gateway (so they bypass the tunnel). Use case:
	// keep selected management/control APIs reachable when the tunnel might be
	// down or geo-blocked from the exit point.
	bypassHosts  []string
	bypassRoutes map[string]struct{} // currently installed /32 routes via origGateway
	serverIPs    map[string]struct{} // skip routing tamizdat-server IP through tamizdat TUN
}

// configureAutoRouting snapshots the current default gateway, pins a host-route
// to the tamizdat server through it, assigns an IP to the TUN, and either:
//   - installs a default route via TUN (default-route mode), OR
//   - installs /32 host-routes for each --selective-routes hostname (selective mode).
//
// All operations run as separate `route.exe` / `netsh.exe` subprocesses so we
// don't need any extra Go dependencies.
func ConfigureAutoRouting(ctx context.Context, serverHost, tunAlias, tunIP string, tunPrefix int, selectiveHosts []string, bypassHosts []string, selectiveRefresh time.Duration) (cleanup func(), err error) {
	state := &routingState{
		serverIP:         serverHost,
		tunAlias:         tunAlias,
		tunIP:            tunIP,
		tunPrefix:        tunPrefix,
		selectiveHosts:   selectiveHosts,
		bypassHosts:      bypassHosts,
		selectiveRefresh: selectiveRefresh,
		serverIPs:        map[string]struct{}{},
	}

	// 0. Sweep orphan routes from a previous run that crashed without cleanup.
	// Specifically:
	//   - any default 0.0.0.0/0 routes via this run's TUN gateway
	//   - any /32 routes via this run's TUN gateway
	// /32 bypass routes via the physical gateway are left alone — they can't
	// hurt (Windows would route those IPs the same way anyway via default).
	CleanupOrphanTUNRoutes(ctx, nextHopFromTunIP(tunIP), tunIP)

	// 1. Resolve serverHost to an IPv4 address.
	serverIP, err := resolveIPv4(ctx, serverHost)
	if err != nil {
		return nil, fmt.Errorf("resolve server IP: %w", err)
	}
	state.serverIP = serverIP
	state.serverIPs[serverIP] = struct{}{}
	// Also collect any other A-records for serverHost so we never accidentally
	// route the tamizdat server itself through the tamizdat TUN.
	if hostOnly := stripPort(serverHost); hostOnly != "" && net.ParseIP(hostOnly) == nil {
		if all, e := resolveAllIPv4(ctx, hostOnly); e == nil {
			for _, ip := range all {
				state.serverIPs[ip] = struct{}{}
			}
		}
	}

	// 2. Snapshot the current default IPv4 gateway BEFORE we add any routes.
	gw, ifaceAlias, metric, err := snapshotDefaultRoute(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot default route: %w", err)
	}
	if gw == "" || gw == "0.0.0.0" {
		return nil, fmt.Errorf("no usable default gateway found (got %q); run with --auto-route=false and configure routing manually", gw)
	}
	state.origGateway = gw
	state.origIfaceAlias = ifaceAlias
	state.origMetric = metric

	log.Printf("auto-route: snapshot default gateway %s on interface %q metric=%s", gw, ifaceAlias, metric)
	log.Printf("auto-route: pinning host-route %s -> %s via %q", serverIP, gw, ifaceAlias)

	// 3. Pin host-route: server IP via original gateway. METRIC 1 wins over default.
	// If another already-running tunnel owns the same server host-route, reuse
	// it and do not remove it on cleanup.
	if hostRouteExists(ctx, serverIP, gw) {
		log.Printf("auto-route: host-route %s via %s already exists; leaving ownership external", serverIP, gw)
	} else if out, err := runCmd(ctx, "route.exe", "ADD", serverIP, "MASK", "255.255.255.255", gw, "METRIC", "1"); err != nil {
		return nil, fmt.Errorf("add host-route %s via %s: %w (output: %s)", serverIP, gw, err, out)
	} else {
		state.addedHostRoute = true
	}

	// 4. Wait briefly for TUN interface to be ready.
	if err := waitForInterface(ctx, tunAlias, 5*time.Second); err != nil {
		state.cleanup()
		return nil, fmt.Errorf("wait for tun interface %q: %w", tunAlias, err)
	}

	// 5. Assign IP to TUN.
	mask := prefixToMask(tunPrefix)
	if out, err := runCmd(ctx, "netsh.exe", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", tunAlias), "static", tunIP, mask); err != nil {
		if !strings.Contains(strings.ToLower(out), "already exists") {
			state.cleanup()
			return nil, fmt.Errorf("assign tun IP: %w (output: %s)", err, out)
		}
	}
	state.assignedTunIP = true
	log.Printf("auto-route: assigned %s/%d to %q", tunIP, tunPrefix, tunAlias)

	tunGateway := nextHopFromTunIP(tunIP)
	state.tunGateway = tunGateway
	tunIfaceIdx, err := interfaceIndex(ctx, tunAlias)
	if err != nil {
		state.cleanup()
		return nil, fmt.Errorf("get tun interface index: %w", err)
	}
	state.tunIfaceIdx = tunIfaceIdx

	// 6. Branch: default-route mode vs selective-routes mode.
	if len(selectiveHosts) == 0 {
		// Bypass /32 routes MUST be installed BEFORE the default route flips
		// to TUN. Once 0.0.0.0/0 points at TUN, DNS UDP traffic to bypass
		// resolvers (1.1.1.1, 8.8.8.8, …) sinks into TUN — which doesn't
		// transit UDP — so name lookups for bypassed hosts may fail.
		// Resolve them now while the system DNS still works through the
		// physical gateway, then pin the resulting IPs.
		if len(bypassHosts) > 0 {
			state.bypassRoutes = map[string]struct{}{}
			added, _ := state.refreshBypassRoutes(ctx)
			log.Printf("bypass-routes: pre-install — %d IPs across %d hostnames", added, len(bypassHosts))
		}

		// Default-route mode: install 0.0.0.0/0 via TUN with metric 1.
		if out, err := runCmd(ctx, "route.exe", "ADD", "0.0.0.0", "MASK", "0.0.0.0", tunGateway,
			"METRIC", "1", "IF", fmt.Sprintf("%d", tunIfaceIdx)); err != nil {
			state.cleanup()
			return nil, fmt.Errorf("add default route via TUN: %w (output: %s)", err, out)
		}
		state.addedDefaultRoute = true
		log.Printf("auto-route: default 0.0.0.0/0 via TUN ifIndex=%d gw=%s", tunIfaceIdx, tunGateway)

		// Start periodic re-resolve of bypass hosts. New A-records (DNS load
		// balancing, CDN failover) get pinned; stale ones get removed.
		if len(bypassHosts) > 0 && selectiveRefresh > 0 && state.selectiveStop == nil {
			state.selectiveStop = make(chan struct{})
			state.selectiveDone = make(chan struct{})
			go state.runBypassOnlyRefresh(selectiveRefresh)
		}
	} else {
		// Selective-routes mode: leave default route alone, install /32 host-routes.
		log.Printf("auto-route: selective mode — default route untouched, %d hostnames in scope", len(selectiveHosts))
		state.selectiveRoutes = map[string]struct{}{}
		state.selectiveStop = make(chan struct{})
		state.selectiveDone = make(chan struct{})

		added, _ := state.refreshSelectiveRoutes(ctx)
		log.Printf("selective-routes: initial install — %d IPs across %d hostnames", added, len(selectiveHosts))

		if selectiveRefresh > 0 {
			go state.runSelectiveRefresh(selectiveRefresh)
		} else {
			close(state.selectiveDone)
		}
	}

	cleanup = func() { state.cleanup() }
	return cleanup, nil
}

// refreshSelectiveRoutes re-resolves all selectiveHosts and reconciles installed
// /32 routes. Returns (added, removed) counts.
func (s *routingState) refreshSelectiveRoutes(ctx context.Context) (int, int) {
	desired := map[string]string{} // ip -> originating host (for log)
	for _, h := range s.selectiveHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				desired[ip4.String()] = h
			}
			continue
		}
		ips, err := resolveAllIPv4(ctx, h)
		if err != nil {
			log.Printf("selective-routes: resolve %q failed: %v", h, err)
			continue
		}
		for _, ip := range ips {
			if _, srv := s.serverIPs[ip]; srv {
				log.Printf("selective-routes: skipping %s (tamizdat server IP)", ip)
				continue
			}
			if _, exists := desired[ip]; !exists {
				desired[ip] = h
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var addedIPs, removedIPs []string
	for ip := range desired {
		if _, ok := s.selectiveRoutes[ip]; !ok {
			if out, err := runCmd(ctx, "route.exe", "ADD", ip, "MASK", "255.255.255.255", s.tunGateway,
				"METRIC", "1", "IF", fmt.Sprintf("%d", s.tunIfaceIdx)); err != nil {
				log.Printf("selective-routes: add /32 %s failed: %v (%s)", ip, err, strings.TrimSpace(out))
				continue
			}
			s.selectiveRoutes[ip] = struct{}{}
			addedIPs = append(addedIPs, fmt.Sprintf("%s=%s", desired[ip], ip))
		}
	}
	for ip := range s.selectiveRoutes {
		if _, keep := desired[ip]; !keep {
			if out, err := runCmd(ctx, "route.exe", "DELETE", ip); err != nil {
				log.Printf("selective-routes: del /32 %s failed: %v (%s)", ip, err, strings.TrimSpace(out))
				continue
			}
			delete(s.selectiveRoutes, ip)
			removedIPs = append(removedIPs, ip)
		}
	}

	if len(addedIPs)+len(removedIPs) > 0 {
		sort.Strings(addedIPs)
		sort.Strings(removedIPs)
		log.Printf("selective-routes: refreshed; +%d -%d (added %s; removed %s)",
			len(addedIPs), len(removedIPs),
			strings.Join(addedIPs, ", "), strings.Join(removedIPs, ", "))
	}

	return len(addedIPs), len(removedIPs)
}

func (s *routingState) runSelectiveRefresh(interval time.Duration) {
	defer close(s.selectiveDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.selectiveStop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			s.refreshSelectiveRoutes(ctx)
			cancel()
		}
	}
}

// refreshBypassRoutes resolves bypassHosts and reconciles installed /32 routes
// going via the original physical gateway (so listed hosts bypass the tunnel).
func (s *routingState) refreshBypassRoutes(ctx context.Context) (int, int) {
	if len(s.bypassHosts) == 0 || s.origGateway == "" {
		return 0, 0
	}
	desired := map[string]string{}
	for _, h := range s.bypassHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				desired[ip4.String()] = h
			}
			continue
		}
		ips, err := resolveAllIPv4(ctx, h)
		if err != nil {
			log.Printf("bypass-routes: resolve %q failed: %v", h, err)
			continue
		}
		for _, ip := range ips {
			if _, srv := s.serverIPs[ip]; srv {
				continue // server IP — already bypasses TUN via host-route
			}
			if _, ok := desired[ip]; !ok {
				desired[ip] = h
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var added, removed []string
	for ip := range desired {
		if _, ok := s.bypassRoutes[ip]; !ok {
			if out, err := runCmd(ctx, "route.exe", "ADD", ip, "MASK", "255.255.255.255",
				s.origGateway, "METRIC", "1"); err != nil {
				log.Printf("bypass-routes: add /32 %s via %s failed: %v (%s)", ip, s.origGateway, err, strings.TrimSpace(out))
				continue
			}
			s.bypassRoutes[ip] = struct{}{}
			added = append(added, fmt.Sprintf("%s=%s", desired[ip], ip))
		}
	}
	for ip := range s.bypassRoutes {
		if _, keep := desired[ip]; !keep {
			if out, err := runCmd(ctx, "route.exe", "DELETE", ip); err != nil {
				log.Printf("bypass-routes: del /32 %s failed: %v (%s)", ip, err, strings.TrimSpace(out))
				continue
			}
			delete(s.bypassRoutes, ip)
			removed = append(removed, ip)
		}
	}

	if len(added)+len(removed) > 0 {
		sort.Strings(added)
		sort.Strings(removed)
		log.Printf("bypass-routes: refreshed; +%d -%d (added %s; removed %s)",
			len(added), len(removed),
			strings.Join(added, ", "), strings.Join(removed, ", "))
	}
	return len(added), len(removed)
}

// runBypassOnlyRefresh periodically re-resolves bypassHosts and updates routes.
// Used in default-route mode (selective mode has its own goroutine that
// subsumes bypass refresh implicitly). Stops when selectiveStop is closed.
func (s *routingState) runBypassOnlyRefresh(interval time.Duration) {
	defer close(s.selectiveDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.selectiveStop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			s.refreshBypassRoutes(ctx)
			cancel()
		}
	}
}

func (s *routingState) cleanup() {
	// Stop refresh goroutine BEFORE we tear down state.
	if s.selectiveStop != nil {
		select {
		case <-s.selectiveStop:
		default:
			close(s.selectiveStop)
		}
		if s.selectiveDone != nil {
			select {
			case <-s.selectiveDone:
			case <-time.After(2 * time.Second):
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Remove selective /32 routes.
	if len(s.selectiveRoutes) > 0 {
		n := 0
		for ip := range s.selectiveRoutes {
			if out, err := runCmd(ctx, "route.exe", "DELETE", ip); err != nil {
				log.Printf("auto-route cleanup: del selective /32 %s failed: %v (%s)", ip, err, strings.TrimSpace(out))
				continue
			}
			n++
		}
		log.Printf("auto-route cleanup: deleted %d selective host-routes", n)
		s.selectiveRoutes = nil
	}

	// Remove bypass /32 routes.
	if len(s.bypassRoutes) > 0 {
		n := 0
		for ip := range s.bypassRoutes {
			if out, err := runCmd(ctx, "route.exe", "DELETE", ip); err != nil {
				log.Printf("auto-route cleanup: del bypass /32 %s failed: %v (%s)", ip, err, strings.TrimSpace(out))
				continue
			}
			n++
		}
		log.Printf("auto-route cleanup: deleted %d bypass host-routes", n)
		s.bypassRoutes = nil
	}

	if s.addedDefaultRoute {
		// Targeted delete: only OUR TUN-default (specifying our tunGateway).
		target := "0.0.0.0"
		if s.tunGateway != "" {
			if out, err := runCmd(ctx, "route.exe", "DELETE", target, "MASK", "0.0.0.0", s.tunGateway); err != nil {
				log.Printf("auto-route cleanup: del default route via %s failed: %v (%s)", s.tunGateway, err, out)
			} else {
				log.Printf("auto-route cleanup: deleted default route via TUN (%s)", s.tunGateway)
			}
		}
		// Safety net: verify the original physical default route is still there;
		// if not, re-add it.
		if s.origGateway != "" {
			if !defaultRouteExists(ctx, s.origGateway) {
				metric := s.origMetric
				if metric == "" {
					metric = "25"
				}
				if out, err := runCmd(ctx, "route.exe", "ADD", "0.0.0.0", "MASK", "0.0.0.0", s.origGateway, "METRIC", metric); err != nil {
					log.Printf("auto-route cleanup: re-add original default %s METRIC %s failed: %v (%s)", s.origGateway, metric, err, out)
				} else {
					log.Printf("auto-route cleanup: re-added original default 0.0.0.0/0 -> %s metric=%s", s.origGateway, metric)
				}
			}
		}
		s.addedDefaultRoute = false
	}

	if s.addedHostRoute && s.serverIP != "" {
		if out, err := runCmd(ctx, "route.exe", "DELETE", s.serverIP); err != nil {
			log.Printf("auto-route cleanup: del host-route %s failed: %v (%s)", s.serverIP, err, out)
		} else {
			log.Printf("auto-route cleanup: deleted host-route %s", s.serverIP)
		}
		s.addedHostRoute = false
	}

	if s.assignedTunIP && s.tunAlias != "" && s.tunIP != "" {
		if _, err := runCmd(ctx, "netsh.exe", "interface", "ipv4", "delete", "address",
			fmt.Sprintf("name=%s", s.tunAlias), s.tunIP); err != nil {
			log.Printf("auto-route cleanup: del TUN address ignored: %v", err)
		}
		s.assignedTunIP = false
	}
}

// resolveIPv4 returns the first IPv4 A-record for host. Accepts host or host:port
// or just an IP literal.
func resolveIPv4(ctx context.Context, hostOrAddr string) (string, error) {
	host := stripPort(hostOrAddr)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", fmt.Errorf("server is IPv6 literal %q; tamizdat is IPv4-only", host)
	}
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ip4 := a.IP.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", host)
}

// resolveAllIPv4 returns every A-record for host.
func resolveAllIPv4(ctx context.Context, host string) ([]string, error) {
	host = stripPort(host)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return []string{ip4.String()}, nil
		}
		return nil, fmt.Errorf("not IPv4: %s", host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]struct{}{}
	for _, a := range addrs {
		if ip4 := a.IP.To4(); ip4 != nil {
			s := ip4.String()
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	return out, nil
}

func stripPort(hostOrAddr string) string {
	if h, _, err := net.SplitHostPort(hostOrAddr); err == nil {
		return h
	}
	return hostOrAddr
}

// snapshotDefaultRoute returns the current default-IPv4 gateway IP and the
// interface alias it points to.
//
// On-link defaults (NextHop=0.0.0.0, owned by VPN/TUN adapters) are skipped:
// tamizdat needs a concrete gateway IP to pin its outer dials away from any TUN.
func snapshotDefaultRoute(ctx context.Context) (gateway, ifaceAlias, metric string, err error) {
	psCmd := `Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1 -Property NextHop,InterfaceAlias,RouteMetric | Format-List`
	if out, e := runCmd(ctx, "powershell.exe", "-NoProfile", "-Command", psCmd); e == nil {
		gw := extractFL(out, "NextHop")
		alias := extractFL(out, "InterfaceAlias")
		m := extractFL(out, "RouteMetric")
		if gw != "" && gw != "0.0.0.0" && alias != "" {
			return gw, alias, m, nil
		}
	}
	out, err := runCmd(ctx, "route.exe", "print", "-4", "0.0.0.0")
	if err != nil {
		return "", "", "", err
	}
	re := regexp.MustCompile(`(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		gw := m[1]
		if gw == "On-link" || gw == "0.0.0.0" {
			continue
		}
		return gw, "", m[3], nil
	}
	return "", "", "", fmt.Errorf("no default route with concrete gateway in route print output")
}

func extractFL(formatListOut, key string) string {
	for _, line := range strings.Split(formatListOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+" :") || strings.HasPrefix(line, key+":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func interfaceIndex(ctx context.Context, alias string) (int, error) {
	psCmd := fmt.Sprintf(`(Get-NetAdapter -Name '%s').ifIndex`, alias)
	out, err := runCmd(ctx, "powershell.exe", "-NoProfile", "-Command", psCmd)
	if err != nil {
		return 0, fmt.Errorf("query ifIndex: %w (%s)", err, out)
	}
	out = strings.TrimSpace(out)
	var idx int
	if _, err := fmt.Sscanf(out, "%d", &idx); err != nil {
		return 0, fmt.Errorf("parse ifIndex %q: %w", out, err)
	}
	return idx, nil
}

func waitForInterface(ctx context.Context, alias string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := interfaceIndex(ctx, alias); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("interface %q did not appear within %s", alias, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Suppress the console window each CLI subprocess (route, netsh, ...)
	// would otherwise pop on top of the operator's screen. When the parent
	// is linked with -H windowsgui it has no console, so every CLI child
	// creates its own — a dozen flash during auto-route setup.
	// CREATE_NO_WINDOW (0x08000000) keeps the subprocess windowless.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func prefixToMask(prefix int) string {
	if prefix < 0 || prefix > 32 {
		prefix = 24
	}
	mask := uint32(0xffffffff) << uint(32-prefix)
	return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}

// nextHopFromTunIP picks an on-link "gateway" address for the TUN. For
// /24 like 10.255.0.2/24 we use 10.255.0.1 (first usable).
func nextHopFromTunIP(tunIP string) string {
	ip := net.ParseIP(tunIP).To4()
	if ip == nil {
		return tunIP
	}
	gw := make(net.IP, 4)
	copy(gw, ip)
	gw[3] = 1
	return gw.String()
}

// defaultRouteExists reports whether a default IPv4 route via the given gateway
// is currently present.
func defaultRouteExists(ctx context.Context, gateway string) bool {
	out, err := runCmd(ctx, "route.exe", "print", "-4", "0.0.0.0")
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+\S+\s+\d+`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		if m[1] == gateway {
			return true
		}
	}
	return false
}

func hostRouteExists(ctx context.Context, ip string, gateway string) bool {
	out, err := runCmd(ctx, "route.exe", "print", "-4", ip)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] == ip && fields[1] == "255.255.255.255" && fields[2] == gateway {
			return true
		}
	}
	return false
}

// cleanupOrphanTUNRoutes removes leftover routes from a previous instance that
// died without running its deferred cleanup (engine crash, taskkill, OS hang).
// We identify orphans by next-hop matching the current run's TUN gateway.
// This runs at startup BEFORE we install our own routes, so it's safe.
func CleanupOrphanTUNRoutes(ctx context.Context, tunGateway string, tunIP string) {
	out, err := runCmd(ctx, "route.exe", "PRINT", "-4")
	if err != nil {
		log.Printf("orphan-sweep: route PRINT failed: %v", err)
		return
	}
	if tunGateway == "" || tunIP == "" {
		return
	}
	removed := 0
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// route PRINT format: "Network Destination, Netmask, Gateway, Interface, Metric"
		if len(fields) < 5 {
			continue
		}
		dest, mask, gw := fields[0], fields[1], fields[2]
		// Skip entries that are not our orphans:
		// match if next-hop is the TUN gateway, OR interface IP is the TUN side.
		if !strings.Contains(line, tunGateway) && !strings.Contains(line, tunIP) {
			continue
		}
		// Filter to:
		//   1. Default route 0.0.0.0/0 via TUN gw
		//   2. /32 routes via TUN gw (selective-routes leftovers)
		isDefault := dest == "0.0.0.0" && mask == "0.0.0.0" && gw == tunGateway
		is32 := mask == "255.255.255.255" && gw == tunGateway
		if !isDefault && !is32 {
			continue
		}
		// Skip the TUN subnet on-link entries — those auto-go-away when the TUN
		// interface is destroyed. Don't try to remove them via route DELETE.
		if gw == "On-link" {
			continue
		}
		log.Printf("orphan-sweep: removing %s mask %s via %s", dest, mask, gw)
		if delOut, delErr := runCmd(ctx, "route.exe", "DELETE", dest, "MASK", mask, gw); delErr != nil {
			log.Printf("orphan-sweep: del %s/%s failed: %v (%s)", dest, mask, delErr, strings.TrimSpace(delOut))
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Printf("orphan-sweep: removed %d orphan TUN routes from previous run", removed)
	}
}
