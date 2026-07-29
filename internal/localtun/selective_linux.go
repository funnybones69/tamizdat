//go:build linux

package localtun

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	localDNSDir       = "/tmp/tamizdat-local-dns"
	localDNSConfig    = localDNSDir + "/chinadns.conf"
	localDNSPID       = localDNSDir + "/chinadns.pid"
	localDNSState     = localDNSDir + "/dnsmasq-state.json"
	localDNSLog       = localDNSDir + "/chinadns.log"
	localDNSPort      = 65353
	localChinaDNSPath = "/usr/bin/chinadns-ng"
)

// selectiveRouteController installs only the policy-selected destinations in
// the local TUN. Direct remains the default. Domain/geosite rules are resolved
// by ChinaDNS-NG into small nft sets, so dnsmasq never parses the large lists.
type selectiveRouteController struct {
	cfg     Config
	dnsCmd  *exec.Cmd
	dnsDone chan error
}

type dnsmasqSnapshot struct {
	Servers        []string `json:"servers"`
	StrictOrder    string   `json:"strict_order,omitempty"`
	StrictOrderSet bool     `json:"strict_order_set"`
}

func (r *selectiveRouteController) Setup(ctx context.Context) error {
	if err := runCommand(ctx, nil, "ip", "addr", "replace", r.cfg.TunAddress, "dev", r.cfg.TunName); err != nil {
		return err
	}
	if err := runCommand(ctx, nil, "ip", "link", "set", "dev", r.cfg.TunName, "mtu", fmt.Sprint(r.cfg.MTU), "up"); err != nil {
		return err
	}
	if !r.cfg.AutoRoute {
		return nil
	}
	if _, err := net.InterfaceByName(r.cfg.Interface); err != nil {
		return fmt.Errorf("local source interface %q is unavailable: %w", r.cfg.Interface, err)
	}

	policy, err := buildIngressPolicy(r.cfg.Policy, r.cfg.UserName)
	if err != nil {
		return err
	}
	if len(policy.rules) == 0 {
		return errors.New("local TUN has no applicable routing rules")
	}
	ifaces, err := localSourceInterfaces(r.cfg.Interface)
	if err != nil {
		return err
	}

	// Build the classifier first. Until the fwmark rule is installed at the
	// end of Setup, matching packets still fail open through the normal WAN.
	_ = runCommand(ctx, nil, "nft", "delete", "table", "inet", localNFTTable)
	if err := runCommand(ctx, []byte(r.nftConfig(policy, ifaces)), "nft", "-f", "-"); err != nil {
		return err
	}
	if policy.dynamicGroups > 0 {
		if err := r.startManagedDNS(ctx, policy); err != nil {
			_ = runCommand(context.Background(), nil, "nft", "delete", "table", "inet", localNFTTable)
			return err
		}
	}

	if err := runCommand(ctx, nil, "ip", "route", "replace", "table", localTableID, "default", "dev", r.cfg.TunName); err != nil {
		return err
	}
	if err := runCommand(ctx, nil, "ip", "-6", "route", "replace", "table", localTableID, "default", "dev", r.cfg.TunName); err != nil {
		_ = runCommand(context.Background(), nil, "ip", "route", "flush", "table", localTableID)
		return err
	}
	_ = runCommand(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
	if err := runCommand(ctx, nil, "ip", "rule", "add", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID); err != nil {
		_ = runCommand(context.Background(), nil, "ip", "-6", "route", "flush", "table", localTableID)
		_ = runCommand(context.Background(), nil, "ip", "route", "flush", "table", localTableID)
		return err
	}
	_ = runCommand(ctx, nil, "ip", "-6", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
	if err := runCommand(ctx, nil, "ip", "-6", "rule", "add", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID); err != nil {
		_ = runCommand(context.Background(), nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
		_ = runCommand(context.Background(), nil, "ip", "-6", "route", "flush", "table", localTableID)
		_ = runCommand(context.Background(), nil, "ip", "route", "flush", "table", localTableID)
		return err
	}
	return nil
}

func (r *selectiveRouteController) Cleanup(ctx context.Context) error {
	// Fail open in this order: stop marking, remove the policy route, restore
	// the original DNS upstreams, then terminate our private ChinaDNS process.
	_ = runCommand(ctx, nil, "nft", "delete", "table", "inet", localNFTTable)
	_ = runCommand(ctx, nil, "ip", "-6", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
	_ = runCommand(ctx, nil, "ip", "-6", "route", "flush", "table", localTableID)
	_ = runCommand(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
	_ = runCommand(ctx, nil, "ip", "route", "flush", "table", localTableID)
	return r.cleanupManagedDNS(ctx)
}

func localSourceInterfaces(primary string) ([]string, error) {
	out := []string{primary}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", primary, "brif"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read bridge members for %q: %w", primary, err)
	}
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if safeInterfaceName.MatchString(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	uniq := out[:0]
	for _, name := range out {
		if len(uniq) == 0 || uniq[len(uniq)-1] != name {
			uniq = append(uniq, name)
		}
	}
	return uniq, nil
}

func (r *selectiveRouteController) nftConfig(policy ingressPolicy, ifaces []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", localNFTTable)
	bypass4 := []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"}
	if r.cfg.BypassPrivate {
		bypass4 = append(bypass4, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
	}
	fmt.Fprintf(&b, "  set bypass_v4 { type ipv4_addr; flags interval; elements = { %s }; }\n", strings.Join(bypass4, ", "))
	b.WriteString("  set bypass_v6 { type ipv6_addr; flags interval; elements = { ::/128, ::1/128, fe80::/10, fc00::/7, ff00::/8 }; }\n")

	for _, rule := range policy.rules {
		if len(rule.domains) > 0 {
			fmt.Fprintf(&b, "  set r%d4 { type ipv4_addr; flags interval; }\n", rule.index)
			fmt.Fprintf(&b, "  set r%d6 { type ipv6_addr; flags interval; }\n", rule.index)
			continue
		}
		if len(rule.ipv4) > 0 {
			fmt.Fprintf(&b, "  set r%d4 { type ipv4_addr; flags interval; elements = { %s }; }\n",
				rule.index, joinPrefixes(rule.ipv4))
		}
		if len(rule.ipv6) > 0 {
			fmt.Fprintf(&b, "  set r%d6 { type ipv6_addr; flags interval; elements = { %s }; }\n",
				rule.index, joinPrefixes(rule.ipv6))
		}
	}

	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	iif := nftInterfaceExpr(ifaces)
	fmt.Fprintf(&b, "    %s ip daddr @bypass_v4 return\n", iif)
	fmt.Fprintf(&b, "    %s ip6 daddr @bypass_v6 return\n", iif)
	for _, rule := range policy.rules {
		for _, line := range nftRuleLines(rule, iif) {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func nftRuleLines(rule ingressRule, iif string) []string {
	base := []string{iif, nftNetworkExpr(rule.network)}
	if len(rule.ports) > 0 {
		base = append(base, "th dport { "+joinPorts(rule.ports)+" }")
	}
	action := "return"
	switch rule.action {
	case ingressTunnel:
		action = "meta mark set 0x9d return"
	case ingressBlock:
		action = "drop"
	}

	hasDestination := len(rule.domains)+len(rule.ipv4)+len(rule.ipv6) > 0
	if !hasDestination {
		lines := make([]string, 0, 2)
		if len(rule.source4) == 0 && len(rule.source6) == 0 {
			return []string{strings.Join(append(base, action), " ")}
		}
		if len(rule.source4) > 0 {
			lines = append(lines, strings.Join(append(append([]string{}, base...), "ip saddr { "+joinPrefixes(rule.source4)+" }", action), " "))
		}
		if len(rule.source6) > 0 {
			lines = append(lines, strings.Join(append(append([]string{}, base...), "ip6 saddr { "+joinPrefixes(rule.source6)+" }", action), " "))
		}
		return lines
	}

	var lines []string
	if len(rule.domains) > 0 || len(rule.ipv4) > 0 {
		if len(rule.source6) == 0 {
			parts := append([]string{}, base...)
			if len(rule.source4) > 0 {
				parts = append(parts, "ip saddr { "+joinPrefixes(rule.source4)+" }")
			}
			parts = append(parts, fmt.Sprintf("ip daddr @r%d4", rule.index), action)
			lines = append(lines, strings.Join(parts, " "))
		}
	}
	if len(rule.domains) > 0 || len(rule.ipv6) > 0 {
		if len(rule.source4) == 0 {
			parts := append([]string{}, base...)
			if len(rule.source6) > 0 {
				parts = append(parts, "ip6 saddr { "+joinPrefixes(rule.source6)+" }")
			}
			parts = append(parts, fmt.Sprintf("ip6 daddr @r%d6", rule.index), action)
			lines = append(lines, strings.Join(parts, " "))
		}
	}
	return lines
}

func nftNetworkExpr(network string) string {
	switch network {
	case "tcp":
		return "meta l4proto tcp"
	case "udp":
		return "meta l4proto udp"
	default:
		return "meta l4proto { tcp, udp }"
	}
}

func nftInterfaceExpr(ifaces []string) string {
	quoted := make([]string, 0, len(ifaces))
	for _, name := range ifaces {
		quoted = append(quoted, strconv.Quote(name))
	}
	if len(quoted) == 1 {
		return "iifname " + quoted[0]
	}
	return "iifname { " + strings.Join(quoted, ", ") + " }"
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.Masked().String())
	}
	return strings.Join(values, ", ")
}

func joinPorts(ports []ingressPortRange) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.lo == port.hi {
			values = append(values, strconv.Itoa(port.lo))
		} else {
			values = append(values, fmt.Sprintf("%d-%d", port.lo, port.hi))
		}
	}
	return strings.Join(values, ", ")
}

func (r *selectiveRouteController) startManagedDNS(ctx context.Context, policy ingressPolicy) error {
	if _, err := os.Stat(localChinaDNSPath); err != nil {
		return fmt.Errorf("ChinaDNS-NG is required for domain routing: %w", err)
	}
	if err := os.MkdirAll(localDNSDir, 0o700); err != nil {
		return err
	}

	var groups []string
	for _, rule := range policy.rules {
		if len(rule.domains) == 0 {
			continue
		}
		listPath := filepath.Join(localDNSDir, fmt.Sprintf("r%d.txt", rule.index))
		if err := writeAtomic(listPath, []byte(strings.Join(rule.domains, "\n")+"\n"), 0o600); err != nil {
			return err
		}
		groups = append(groups, fmt.Sprintf(
			"group tam_r%d\ngroup-dnl %s\ngroup-upstream 127.0.0.1#5053,127.0.0.1#5054\ngroup-ipset inet@%s@r%d4,inet@%s@r%d6\n",
			rule.index, listPath, localNFTTable, rule.index, localNFTTable, rule.index,
		))
	}
	// ChinaDNS gives later groups higher priority. Reverse declarations to
	// preserve the panel's top-to-bottom, first-match-wins ordering.
	for i, j := 0, len(groups)-1; i < j; i, j = i+1, j-1 {
		groups[i], groups[j] = groups[j], groups[i]
	}
	config := fmt.Sprintf(`bind-addr 127.0.0.1
bind-port %d
china-dns 127.0.0.1#5053
trust-dns 127.0.0.1#5054
default-tag chn
cache 10000
cache-stale 86400
cache-refresh 20
cache-db %s/cache.db

%s`, localDNSPort, localDNSDir, strings.Join(groups, "\n"))
	if err := writeAtomic(localDNSConfig, []byte(config), 0o600); err != nil {
		return err
	}

	logFile, err := os.OpenFile(localDNSLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(localChinaDNSPath, "-C", localDNSConfig)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start ChinaDNS-NG: %w", err)
	}
	_ = logFile.Close()
	r.dnsCmd = cmd
	r.dnsDone = make(chan error, 1)
	go func() { r.dnsDone <- cmd.Wait() }()
	if err := writeAtomic(localDNSPID, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return err
	}

	if err := waitDNS(ctx, localDNSPort, r.dnsDone); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("ChinaDNS-NG readiness: %w", err)
	}
	if err := r.installDNSMasqFrontend(ctx); err != nil {
		return fmt.Errorf("configure dnsmasq frontend: %w", err)
	}
	if err := waitDNS(ctx, 53, nil); err != nil {
		return fmt.Errorf("dnsmasq through ChinaDNS-NG readiness: %w", err)
	}
	return nil
}

func (r *selectiveRouteController) installDNSMasqFrontend(ctx context.Context) error {
	serversRaw, _ := optionalCommandOutput(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0].server")
	strictRaw, strictErr := optionalCommandOutput(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0].strictorder")
	snapshot := dnsmasqSnapshot{
		Servers:        strings.Fields(serversRaw),
		StrictOrder:    strings.TrimSpace(strictRaw),
		StrictOrderSet: strictErr == nil,
	}
	if len(snapshot.Servers) == 0 {
		snapshot.Servers = []string{"127.0.0.1#5053", "127.0.0.1#5054"}
	}
	state, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := writeAtomic(localDNSState, state, 0o600); err != nil {
		return err
	}
	_, _ = optionalCommandOutput(ctx, "uci", "-q", "delete", "dhcp.@dnsmasq[0].server")
	servers := append([]string{fmt.Sprintf("127.0.0.1#%d", localDNSPort)}, snapshot.Servers...)
	for _, server := range uniqueStrings(servers) {
		if err := runCommand(ctx, nil, "uci", "add_list", "dhcp.@dnsmasq[0].server="+server); err != nil {
			return err
		}
	}
	if err := runCommand(ctx, nil, "uci", "set", "dhcp.@dnsmasq[0].strictorder=1"); err != nil {
		return err
	}
	if err := runCommand(ctx, nil, "uci", "commit", "dhcp"); err != nil {
		return err
	}
	return runCommandWithTimeout(ctx, 12*time.Second, nil, "/etc/init.d/dnsmasq", "restart")
}

func (r *selectiveRouteController) cleanupManagedDNS(ctx context.Context) error {
	var firstErr error
	state, err := os.ReadFile(localDNSState)
	if err == nil {
		var snapshot dnsmasqSnapshot
		if json.Unmarshal(state, &snapshot) != nil || len(snapshot.Servers) == 0 {
			snapshot.Servers = []string{"127.0.0.1#5053", "127.0.0.1#5054"}
		}
		_, _ = optionalCommandOutput(ctx, "uci", "-q", "delete", "dhcp.@dnsmasq[0].server")
		for _, server := range uniqueStrings(snapshot.Servers) {
			if cmdErr := runCommand(ctx, nil, "uci", "add_list", "dhcp.@dnsmasq[0].server="+server); cmdErr != nil && firstErr == nil {
				firstErr = cmdErr
			}
		}
		if snapshot.StrictOrderSet {
			if cmdErr := runCommand(ctx, nil, "uci", "set", "dhcp.@dnsmasq[0].strictorder="+snapshot.StrictOrder); cmdErr != nil && firstErr == nil {
				firstErr = cmdErr
			}
		} else {
			_, _ = optionalCommandOutput(ctx, "uci", "-q", "delete", "dhcp.@dnsmasq[0].strictorder")
		}
		if cmdErr := runCommand(ctx, nil, "uci", "commit", "dhcp"); cmdErr != nil && firstErr == nil {
			firstErr = cmdErr
		}
		if cmdErr := runCommandWithTimeout(ctx, 12*time.Second, nil, "/etc/init.d/dnsmasq", "restart"); cmdErr != nil && firstErr == nil {
			firstErr = cmdErr
		}
		_ = os.Remove(localDNSState)
	}

	if r.dnsCmd != nil && r.dnsCmd.Process != nil {
		_ = r.dnsCmd.Process.Signal(syscall.SIGTERM)
		if r.dnsDone != nil {
			select {
			case <-r.dnsDone:
			case <-time.After(2 * time.Second):
				_ = r.dnsCmd.Process.Kill()
			}
		}
	} else {
		_ = stopStaleChinaDNS()
	}
	r.dnsCmd, r.dnsDone = nil, nil
	_ = os.Remove(localDNSPID)
	return firstErr
}

func stopStaleChinaDNS() error {
	raw, err := os.ReadFile(localDNSPID)
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 {
		return nil
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || !bytes.Contains(cmdline, []byte(localDNSConfig)) {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = process.Signal(syscall.SIGTERM)
	for i := 0; i < 20; i++ {
		if process.Signal(syscall.Signal(0)) != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return process.Kill()
}

func waitDNS(ctx context.Context, port int, done <-chan error) error {
	// Loading the RU-blocked domain list and restarting dnsmasq can take more
	// than a single upstream DNS timeout on small OpenWrt devices. The forwarding
	// mark is installed only after this succeeds, so the wait remains fail-open.
	const readinessTimeout = 30 * time.Second
	deadline := time.Now().Add(readinessTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("process exited")
			}
			return err
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := dnsProbe(ctx, port); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(150 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("DNS query timed out after %s: %w", readinessTimeout, lastErr)
	}
	return errors.New("DNS query timed out")
}

func dnsProbe(parent context.Context, port int) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	id := uint16(time.Now().UnixNano())
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split("example.com", ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	if _, err := conn.Write(packet); err != nil {
		return err
	}
	reply := make([]byte, 1500)
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(reply[0:2]) != id || reply[3]&0x0f != 0 {
		return errors.New("invalid DNS response")
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func optionalCommandOutput(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCommandWithTimeout(parent context.Context, timeout time.Duration, stdin []byte, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(out))
	if message == "" {
		message = err.Error()
	}
	if len(message) > 300 {
		message = message[:300]
	}
	return fmt.Errorf("%s: %s", name, message)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

var _ io.Closer = (*os.File)(nil)
