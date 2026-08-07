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
	"sync"
	"syscall"
	"time"
)

const (
	localDNSDir       = "/tmp/tamizdat-local-dns"
	localDNSConfig    = localDNSDir + "/chinadns.conf"
	localDNSPID       = localDNSDir + "/chinadns.pid"
	localDNSState     = localDNSDir + "/dnsmasq-state.json"
	localDNSLog       = localDNSDir + "/chinadns.log"
	localDNSPort      = 5335
	localChinaDNSPath = "/usr/bin/chinadns-ng"
)

// selectiveRouteController installs only the policy-selected destinations in
// the local TUN. Direct remains the default. Domain/geosite rules are resolved
// by ChinaDNS-NG into small nft sets, so dnsmasq never parses the large lists.
type selectiveRouteController struct {
	cfg     Config
	dnsCmd  *exec.Cmd
	dnsDone chan error
	dnsMu   sync.Mutex
	dnsErr  error
	policy  ingressPolicy
	ifaces  []string
	run     func(context.Context, []byte, string, ...string) error
	output  func(context.Context, string, ...string) (string, error)
}

type dnsmasqSnapshot struct {
	Servers        []string `json:"servers"`
	StrictOrder    string   `json:"strict_order,omitempty"`
	StrictOrderSet bool     `json:"strict_order_set"`
}

func (r *selectiveRouteController) command(ctx context.Context, stdin []byte, name string, args ...string) error {
	if r.run != nil {
		return r.run(ctx, stdin, name, args...)
	}
	return runCommand(ctx, stdin, name, args...)
}

func (r *selectiveRouteController) commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	if r.output != nil {
		return r.output(ctx, name, args...)
	}
	return commandOutput(ctx, name, args...)
}

func (r *selectiveRouteController) Setup(ctx context.Context) error {
	if err := r.command(ctx, nil, "ip", "addr", "replace", r.cfg.TunAddress, "dev", r.cfg.TunName); err != nil {
		return err
	}
	if err := r.command(ctx, nil, "ip", "link", "set", "dev", r.cfg.TunName, "mtu", fmt.Sprint(r.cfg.MTU), "up"); err != nil {
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

	r.policy, r.ifaces = policy, ifaces

	// Phase 1: replace only staged sets + regular chains. In compatibility
	// mode they have no hooks and therefore cannot classify traffic yet. The
	// opt-in fail-closed mode keeps a staged public-WAN drop hook while the new
	// generation is prepared.
	stage := r.nftConfig(policy, ifaces)
	if _, err := r.commandOutput(ctx, "nft", "list", "table", "inet", localNFTTable); err == nil {
		stage = "delete table inet " + localNFTTable + "\n" + stage
	} else if !isCommandNotFound(err) {
		return r.rollbackSetup(fmt.Errorf("inspect old nft table: %w", err))
	}
	if err := r.command(ctx, []byte(stage), "nft", "-f", "-"); err != nil {
		return r.rollbackSetup(err)
	}

	if err := r.command(ctx, nil, "ip", "route", "replace", "table", localTableID, "default", "dev", r.cfg.TunName); err != nil {
		return r.rollbackSetup(err)
	}
	// The v1 local TUN data plane is IPv4-only. Older builds installed an
	// IPv6 default route to the TUN anyway, which black-holed IPv6-preferred
	// clients such as iOS. Remove any stale IPv6 policy state; nft rejects
	// only tunnel-selected IPv6 destinations so clients immediately retry A.
	if err := errors.Join(
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "route", "del", "table", localTableID, "default", "dev", r.cfg.TunName),
		r.commandIgnoreNotFound(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
	); err != nil {
		return r.rollbackSetup(err)
	}
	if err := r.command(ctx, nil, "ip", "rule", "add", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID); err != nil {
		return r.rollbackSetup(err)
	}
	if policy.dynamicGroups > 0 {
		if err := r.startManagedDNS(ctx, policy); err != nil {
			return r.rollbackSetup(err)
		}
	}

	// Phase 2 (last operation): atomically publish both the mangle classifier
	// and DNS redirect hook. At this point the TUN, route, RPDB rule, nft sets,
	// dnsmasq and ChinaDNS are all ready.
	if err := r.activateHooks(ctx, false); err != nil {
		return r.rollbackSetup(err)
	}
	return nil
}

func (r *selectiveRouteController) Cleanup(ctx context.Context) error {
	// Reverse setup order. Refuse to remove the RPDB route if hooks could not
	// be detached: marked traffic must never fall through to the normal WAN.
	if err := r.deactivateHooks(ctx); err != nil {
		return err
	}
	err := errors.Join(
		r.cleanupManagedDNS(ctx),
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "route", "del", "table", localTableID, "default", "dev", r.cfg.TunName),
		r.commandIgnoreNotFound(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		r.commandIgnoreNotFound(ctx, nil, "ip", "route", "flush", "table", localTableID),
	)
	// Hooks are already detached, so continue all remaining reverse-order
	// cleanup even when one command fails. Returning the joined command and
	// invariant errors lets the manager refuse an overlapping generation.
	tableErr := r.commandIgnoreNotFound(ctx, nil, "nft", "delete", "table", "inet", localNFTTable)
	verifyErr := r.verifyCleanup(ctx)
	return errors.Join(err, tableErr, verifyErr)
}

func (r *selectiveRouteController) commandIgnoreNotFound(ctx context.Context, stdin []byte, name string, args ...string) error {
	err := r.command(ctx, stdin, name, args...)
	if isCommandNotFound(err) {
		return nil
	}
	return err
}

func (r *selectiveRouteController) rollbackSetup(setupErr error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var cleanupErr error
	if r.cfg.FailClosed {
		cleanupErr = r.EnterFailClosed(cleanupCtx)
	} else {
		cleanupErr = r.Cleanup(cleanupCtx)
	}
	return errors.Join(setupErr, cleanupErr)
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
			fmt.Fprintf(&b, "  set r%d4 { type ipv4_addr; flags interval; auto-merge; elements = { %s }; }\n",
				rule.index, joinPrefixes(rule.ipv4))
		}
		if len(rule.ipv6) > 0 {
			fmt.Fprintf(&b, "  set r%d6 { type ipv6_addr; flags interval; auto-merge; elements = { %s }; }\n",
				rule.index, joinPrefixes(rule.ipv6))
		}
	}

	b.WriteString("  chain classify {\n")
	iif := nftInterfaceExpr(ifaces)
	// fw4 DNAT runs after this mangle chain. A local FIB destination includes
	// the router's own WAN address, so hairpin/port-forward and router-local
	// services stay on the normal fw4 path before any policy restriction.
	fmt.Fprintf(&b, "    %s fib daddr type local return\n", iif)
	// DNS-over-TLS/QUIC must not bypass ChinaDNS. DoH is indistinguishable
	// from ordinary HTTPS and is documented as an explicit limitation.
	fmt.Fprintf(&b, "    %s meta l4proto { tcp, udp } th dport 853 drop\n", iif)
	fmt.Fprintf(&b, "    %s ip daddr @bypass_v4 return\n", iif)
	fmt.Fprintf(&b, "    %s ip6 daddr @bypass_v6 return\n", iif)
	for _, rule := range policy.rules {
		for _, line := range nftRuleLines(rule, iif) {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	b.WriteString("  }\n")
	b.WriteString("  chain killswitch {\n")
	fmt.Fprintf(&b, "    %s fib daddr type local return\n", iif)
	fmt.Fprintf(&b, "    %s meta l4proto { tcp, udp } th dport 853 drop\n", iif)
	fmt.Fprintf(&b, "    %s ip daddr @bypass_v4 return\n", iif)
	fmt.Fprintf(&b, "    %s ip6 daddr @bypass_v6 return\n", iif)
	fmt.Fprintf(&b, "    %s meta l4proto { tcp, udp } drop\n", iif)
	b.WriteString("  }\n")
	if r.cfg.FailClosed {
		b.WriteString("  chain prerouting { type filter hook prerouting priority mangle; policy accept; jump killswitch; }\n")
		writeDNSHook(&b, iif, "  ")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeDNSHook(b *strings.Builder, iif, indent string) {
	fmt.Fprintf(b, "%schain dns_prerouting {\n", indent)
	fmt.Fprintf(b, "%s  type nat hook prerouting priority -105; policy accept;\n", indent)
	fmt.Fprintf(b, "%s  %s udp dport 53 redirect to :53\n", indent, iif)
	fmt.Fprintf(b, "%s  %s tcp dport 53 redirect to :53\n", indent, iif)
	fmt.Fprintf(b, "%s}\n", indent)
}

func (r *selectiveRouteController) chainExists(ctx context.Context, chain string) (bool, error) {
	_, err := r.commandOutput(ctx, "nft", "list", "chain", "inet", localNFTTable, chain)
	if err == nil {
		return true, nil
	}
	if isCommandNotFound(err) {
		return false, nil
	}
	return false, err
}

func (r *selectiveRouteController) activateHooks(ctx context.Context, killswitch bool) error {
	target := "classify"
	if killswitch {
		target = "killswitch"
	}
	iif := nftInterfaceExpr(r.ifaces)
	preExists, err := r.chainExists(ctx, "prerouting")
	if err != nil {
		return err
	}
	dnsExists, err := r.chainExists(ctx, "dns_prerouting")
	if err != nil {
		return err
	}
	var b strings.Builder
	if preExists {
		b.WriteString("flush chain inet " + localNFTTable + " prerouting\n")
	} else {
		fmt.Fprintf(&b, "add chain inet %s prerouting { type filter hook prerouting priority mangle; policy accept; }\n", localNFTTable)
	}
	fmt.Fprintf(&b, "add rule inet %s prerouting jump %s\n", localNFTTable, target)
	if dnsExists {
		b.WriteString("flush chain inet " + localNFTTable + " dns_prerouting\n")
	} else {
		fmt.Fprintf(&b, "add chain inet %s dns_prerouting { type nat hook prerouting priority -105; policy accept; }\n", localNFTTable)
	}
	fmt.Fprintf(&b, "add rule inet %s dns_prerouting %s udp dport 53 redirect to :53\n", localNFTTable, iif)
	fmt.Fprintf(&b, "add rule inet %s dns_prerouting %s tcp dport 53 redirect to :53\n", localNFTTable, iif)
	return r.command(ctx, []byte(b.String()), "nft", "-f", "-")
}

func (r *selectiveRouteController) deactivateHooks(ctx context.Context) error {
	if _, err := r.commandOutput(ctx, "nft", "list", "table", "inet", localNFTTable); err != nil {
		if isCommandNotFound(err) {
			return nil
		}
		return err
	}
	var b strings.Builder
	for _, chain := range []string{"prerouting", "dns_prerouting"} {
		exists, err := r.chainExists(ctx, chain)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		fmt.Fprintf(&b, "flush chain inet %s %s\ndelete chain inet %s %s\n", localNFTTable, chain, localNFTTable, chain)
	}
	if b.Len() == 0 {
		return nil
	}
	return r.command(ctx, []byte(b.String()), "nft", "-f", "-")
}

func (r *selectiveRouteController) verifyCleanup(ctx context.Context) error {
	var errs []error
	if _, err := r.commandOutput(ctx, "nft", "list", "table", "inet", localNFTTable); err == nil {
		errs = append(errs, fmt.Errorf("nft table inet %s still exists after cleanup", localNFTTable))
	} else if !isCommandNotFound(err) {
		errs = append(errs, err)
	}
	if out, err := r.commandOutput(ctx, "ip", "rule", "show", "priority", localPriority); err != nil {
		errs = append(errs, err)
	} else if strings.TrimSpace(out) != "" {
		errs = append(errs, fmt.Errorf("ip rule priority %s still exists: %s", localPriority, out))
	}
	errs = append(errs,
		r.verifyRouteTableEmpty(ctx, false),
		r.verifyRouteTableEmpty(ctx, true),
	)
	return errors.Join(errs...)
}

func (r *selectiveRouteController) verifyRouteTableEmpty(ctx context.Context, ipv6 bool) error {
	args := []string{"route", "show", "table", localTableID}
	family := "ip"
	if ipv6 {
		args = append([]string{"-6"}, args...)
		family = "ip -6"
	}
	out, err := r.commandOutput(ctx, "ip", args...)
	if err != nil {
		// iproute2 exits 2 on a pristine system when the policy table has never
		// existed: "FIB table does not exist. Dump terminated". That is the
		// desired cleanup postcondition, not a reason to block TUN startup.
		if isRouteTableNotFound(err) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("%s route table %s still exists: %s", family, localTableID, out)
	}
	return nil
}

func isRouteTableNotFound(err error) bool {
	var commandErr *commandError
	if !errors.As(err, &commandErr) || errors.Is(commandErr.cause, os.ErrNotExist) {
		return false
	}
	return strings.Contains(strings.ToLower(commandErr.output), "does not exist")
}

func (r *selectiveRouteController) EnterFailClosed(ctx context.Context) error {
	if !r.cfg.AutoRoute || !r.cfg.FailClosed {
		return r.Cleanup(ctx)
	}
	if len(r.ifaces) == 0 {
		r.ifaces = []string{r.cfg.Interface}
	}
	stage := r.nftConfig(ingressPolicy{}, r.ifaces)
	if _, err := r.commandOutput(ctx, "nft", "list", "table", "inet", localNFTTable); err == nil {
		// Rebuild instead of assuming an old/legacy table already contains the
		// killswitch chain. nft -f commits delete+create atomically.
		stage = "delete table inet " + localNFTTable + "\n" + stage
	} else if !isCommandNotFound(err) {
		return err
	}
	if err := r.command(ctx, []byte(stage), "nft", "-f", "-"); err != nil {
		return err
	}
	// Once the public-WAN drop hook is committed it is safe to tear down the
	// unusable dataplane while the supervisor waits before retrying.
	return errors.Join(
		r.cleanupManagedDNS(ctx),
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		r.commandIgnoreNotFound(ctx, nil, "ip", "-6", "route", "del", "table", localTableID, "default", "dev", r.cfg.TunName),
		r.commandIgnoreNotFound(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		r.commandIgnoreNotFound(ctx, nil, "ip", "route", "flush", "table", localTableID),
	)
}

func (r *selectiveRouteController) DNSDone() <-chan error { return r.dnsDone }

func (r *selectiveRouteController) DNSError() error {
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	return r.dnsErr
}

func (r *selectiveRouteController) Health(ctx context.Context) error {
	link, err := r.commandOutput(ctx, "ip", "-o", "link", "show", "dev", r.cfg.TunName)
	if err != nil {
		return fmt.Errorf("TUN link invariant: %w", err)
	}
	if !strings.Contains(link, "<") || !strings.Contains(link, "UP") {
		return fmt.Errorf("TUN link %s is not UP: %s", r.cfg.TunName, link)
	}
	if !r.cfg.AutoRoute {
		return nil
	}
	route, err := r.commandOutput(ctx, "ip", "route", "show", "table", localTableID)
	if err != nil || !strings.Contains(route, "default dev "+r.cfg.TunName) {
		return fmt.Errorf("route table %s invariant failed: %s: %w", localTableID, route, err)
	}
	rule, err := r.commandOutput(ctx, "ip", "rule", "show", "priority", localPriority)
	if err != nil || !strings.Contains(rule, "fwmark 0x9d/0xff") || !strings.Contains(rule, "lookup "+localTableID) {
		return fmt.Errorf("RPDB rule invariant failed: %s: %w", rule, err)
	}
	chain, err := r.commandOutput(ctx, "nft", "list", "chain", "inet", localNFTTable, "prerouting")
	if err != nil || !strings.Contains(chain, "jump classify") {
		return fmt.Errorf("nft classifier invariant failed: %s: %w", chain, err)
	}
	dnsChain, err := r.commandOutput(ctx, "nft", "list", "chain", "inet", localNFTTable, "dns_prerouting")
	if err != nil || !strings.Contains(dnsChain, "udp dport 53 redirect") || !strings.Contains(dnsChain, "tcp dport 53 redirect") {
		return fmt.Errorf("nft DNS redirect invariant failed: %s: %w", dnsChain, err)
	}
	if r.policy.dynamicGroups > 0 {
		if err := dnsProbe(ctx, localDNSPort); err != nil {
			return fmt.Errorf("ChinaDNS health: %w", err)
		}
		if err := dnsProbe(ctx, 53); err != nil {
			return fmt.Errorf("dnsmasq frontend health: %w", err)
		}
	}
	return nil
}

func nftRuleLines(rule ingressRule, iif string) []string {
	base := []string{iif, nftNetworkExpr(rule.network)}
	if len(rule.ports) > 0 {
		base = append(base, "th dport { "+joinPorts(rule.ports)+" }")
	}
	action4, action6 := "return", "return"
	switch rule.action {
	case ingressTunnel:
		action4 = "meta mark set (meta mark & 0xffffff00) | 0x9d return"
		action6 = "reject with icmpv6 addr-unreachable"
	case ingressBlock:
		action4, action6 = "drop", "drop"
	}

	hasDestination := len(rule.domains)+len(rule.ipv4)+len(rule.ipv6) > 0
	if !hasDestination {
		lines := make([]string, 0, 2)
		if len(rule.source4) == 0 && len(rule.source6) == 0 {
			if action4 == action6 {
				return []string{strings.Join(append(base, action4), " ")}
			}
			return []string{
				strings.Join(append(append([]string{}, base...), "meta nfproto ipv4", action4), " "),
				strings.Join(append(append([]string{}, base...), "meta nfproto ipv6", action6), " "),
			}
		}
		if len(rule.source4) > 0 {
			lines = append(lines, strings.Join(append(append([]string{}, base...), "ip saddr { "+joinPrefixes(rule.source4)+" }", action4), " "))
		}
		if len(rule.source6) > 0 {
			lines = append(lines, strings.Join(append(append([]string{}, base...), "ip6 saddr { "+joinPrefixes(rule.source6)+" }", action6), " "))
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
			parts = append(parts, fmt.Sprintf("ip daddr @r%d4", rule.index), action4)
			lines = append(lines, strings.Join(parts, " "))
		}
	}
	if len(rule.domains) > 0 || len(rule.ipv6) > 0 {
		if len(rule.source4) == 0 {
			parts := append([]string{}, base...)
			if len(rule.source6) > 0 {
				parts = append(parts, "ip6 saddr { "+joinPrefixes(rule.source6)+" }")
			}
			parts = append(parts, fmt.Sprintf("ip6 daddr @r%d6", rule.index), action6)
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
	r.dnsDone = make(chan error)
	r.dnsMu.Lock()
	r.dnsErr = nil
	r.dnsMu.Unlock()
	go func() {
		err := cmd.Wait()
		r.dnsMu.Lock()
		r.dnsErr = err
		r.dnsMu.Unlock()
		close(r.dnsDone)
	}()
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
	if err := restoreDNSMasqFrontend(ctx); err != nil {
		// Keep ChinaDNS alive while dnsmasq may still point at it. The saved
		// state and PID intentionally remain for the manager's cleanup retry.
		return err
	}

	var stopErr error
	if r.dnsCmd != nil && r.dnsCmd.Process != nil {
		stopErr = stopManagedChinaDNS(r.dnsCmd, r.dnsDone)
	} else {
		stopErr = stopStaleChinaDNS()
	}
	if stopErr != nil {
		return stopErr
	}
	r.dnsCmd, r.dnsDone = nil, nil
	if err := os.Remove(localDNSPID); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove ChinaDNS PID file: %w", err)
	}
	return nil
}

func restoreDNSMasqFrontend(ctx context.Context) error {
	state, err := os.ReadFile(localDNSState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read dnsmasq state: %w", err)
	}
	var snapshot dnsmasqSnapshot
	if err := json.Unmarshal(state, &snapshot); err != nil {
		return fmt.Errorf("decode dnsmasq state: %w", err)
	}
	if len(snapshot.Servers) == 0 {
		return errors.New("dnsmasq state has no upstream servers")
	}

	// Deleting an already-absent optional UCI value is idempotent. All writes,
	// commit and restart errors are retained instead of being silently ignored.
	_, _ = optionalCommandOutput(ctx, "uci", "-q", "delete", "dhcp.@dnsmasq[0].server")
	var errs []error
	for _, server := range uniqueStrings(snapshot.Servers) {
		errs = append(errs, runCommand(ctx, nil, "uci", "add_list", "dhcp.@dnsmasq[0].server="+server))
	}
	if snapshot.StrictOrderSet {
		errs = append(errs, runCommand(ctx, nil, "uci", "set", "dhcp.@dnsmasq[0].strictorder="+snapshot.StrictOrder))
	} else {
		_, _ = optionalCommandOutput(ctx, "uci", "-q", "delete", "dhcp.@dnsmasq[0].strictorder")
	}
	errs = append(errs,
		runCommand(ctx, nil, "uci", "commit", "dhcp"),
		runCommandWithTimeout(ctx, 12*time.Second, nil, "/etc/init.d/dnsmasq", "restart"),
	)
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.Remove(localDNSState); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove dnsmasq state: %w", err)
	}
	return nil
}

func stopManagedChinaDNS(cmd *exec.Cmd, done <-chan error) error {
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !processGone(err) {
		return fmt.Errorf("signal ChinaDNS: %w", err)
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
	}
	if err := cmd.Process.Kill(); err != nil && !processGone(err) {
		return fmt.Errorf("kill ChinaDNS: %w", err)
	}
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("ChinaDNS did not exit after SIGKILL")
	}
}

func stopStaleChinaDNS() error {
	raw, err := os.ReadFile(localDNSPID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read stale ChinaDNS PID: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 {
		return fmt.Errorf("invalid stale ChinaDNS PID %q", strings.TrimSpace(string(raw)))
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stale ChinaDNS process %d: %w", pid, err)
	}
	if !bytes.Contains(cmdline, []byte(localDNSConfig)) {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !processGone(err) {
		return fmt.Errorf("signal stale ChinaDNS: %w", err)
	}
	for i := 0; i < 20; i++ {
		if err := process.Signal(syscall.Signal(0)); processGone(err) {
			return nil
		} else if err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := process.Kill(); err != nil && !processGone(err) {
		return fmt.Errorf("kill stale ChinaDNS: %w", err)
	}
	return nil
}

func processGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH)
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
