package localtun

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/funnybones69/tamizdat/internal/rulesdb"
	"github.com/funnybones69/tamizdat/node"
)

const (
	maxChinaDNSGroups = 6
	// Large static interval batches make nft itself consume more than 100 MiB
	// on small OpenWrt targets. Domain-heavy lists must use ChinaDNS instead.
	maxStaticPrefixesPerRule = 4096
)

type ingressAction string

const (
	ingressDirect ingressAction = "direct"
	ingressTunnel ingressAction = "tunnel"
	ingressBlock  ingressAction = "block"
)

type ingressPortRange struct{ lo, hi int }

type ingressRule struct {
	index   int
	action  ingressAction
	ipv4    []netip.Prefix
	ipv6    []netip.Prefix
	domains []string
	source4 []netip.Prefix
	source6 []netip.Prefix
	network string
	ports   []ingressPortRange
}

type ingressPolicy struct {
	rules         []ingressRule
	dynamicGroups int
	tunnelTag     string
}

func localTunnelOutbound(snap *rulesdb.Snapshot, userName string) (string, error) {
	if snap == nil {
		return "", nil
	}
	userName = strings.TrimSpace(userName)
	selected := ""
	for _, loaded := range snap.Rules {
		m := loaded.Match
		if !listAllows(m.User, userName) || !listAllows(m.InboundTag, "local-tun") {
			continue
		}
		tag := strings.TrimSpace(loaded.OutboundTag)
		if tag == "" {
			return "", fmt.Errorf("local rule priority %d has no outbound", loaded.Priority)
		}
		if tag == "direct" || tag == "block" {
			continue
		}
		if selected == "" {
			selected = tag
			continue
		}
		if selected != tag {
			return "", fmt.Errorf(
				"local routing selects multiple tunnel outbounds %q and %q; use one tunnel outbound for router-lan",
				selected, tag,
			)
		}
	}
	return selected, nil
}

func buildIngressPolicy(snap *rulesdb.Snapshot, userName string) (ingressPolicy, error) {
	var out ingressPolicy
	userName = strings.TrimSpace(userName)
	if snap == nil || len(snap.Rules) == 0 {
		return out, nil
	}
	var err error
	if out.tunnelTag, err = localTunnelOutbound(snap, userName); err != nil {
		return out, err
	}

	for _, loaded := range snap.Rules {
		m := loaded.Match
		if !listAllows(m.User, userName) || !listAllows(m.InboundTag, "local-tun") {
			continue
		}
		rule := ingressRule{index: len(out.rules)}
		tag := strings.TrimSpace(loaded.OutboundTag)
		switch tag {
		case "direct":
			rule.action = ingressDirect
		case "block":
			rule.action = ingressBlock
		case "":
			return out, fmt.Errorf("local rule priority %d has no outbound", loaded.Priority)
		default:
			if tag != out.tunnelTag {
				return out, fmt.Errorf("local rule priority %d targets unexpected outbound %q", loaded.Priority, tag)
			}
			rule.action = ingressTunnel
		}

		rule.network = strings.ToLower(strings.TrimSpace(m.Network))
		switch rule.network {
		case "", "tcp", "udp", "tcp,udp", "udp,tcp":
		default:
			return out, fmt.Errorf("local rule priority %d: invalid network %q", loaded.Priority, m.Network)
		}
		var err error
		if rule.ports, err = parseIngressPorts(m.Port); err != nil {
			return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
		}
		for _, raw := range m.Source {
			p, parseErr := parseIngressPrefix(raw)
			if parseErr != nil {
				return out, fmt.Errorf("local rule priority %d source %q: %w", loaded.Priority, raw, parseErr)
			}
			if p.Addr().Is4() {
				rule.source4 = append(rule.source4, p)
			} else {
				rule.source6 = append(rule.source6, p)
			}
		}

		for _, name := range m.GeoIP {
			if err := appendGeoPrefixes(&rule, snap.GeoDB, name); err != nil {
				return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
			}
		}
		for _, raw := range m.IP {
			if name, ok := geoToken(raw, "geoip"); ok {
				if err := appendGeoPrefixes(&rule, snap.GeoDB, name); err != nil {
					return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
				}
				continue
			}
			p, parseErr := parseIngressPrefix(raw)
			if parseErr != nil {
				return out, fmt.Errorf("local rule priority %d ip %q: %w", loaded.Priority, raw, parseErr)
			}
			if p.Addr().Is4() {
				rule.ipv4 = append(rule.ipv4, p)
			} else {
				rule.ipv6 = append(rule.ipv6, p)
			}
		}

		domainSeen := make(map[string]struct{})
		for _, name := range m.Geosite {
			if err := appendGeoDomains(&rule, snap.GeoDB, name, domainSeen); err != nil {
				return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
			}
		}
		for _, raw := range m.Domain {
			if name, ok := geoToken(raw, "geosite"); ok {
				if err := appendGeoDomains(&rule, snap.GeoDB, name, domainSeen); err != nil {
					return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
				}
				continue
			}
			if name, ok := geoToken(raw, "geoip"); ok {
				if err := appendGeoPrefixes(&rule, snap.GeoDB, name); err != nil {
					return out, fmt.Errorf("local rule priority %d: %w", loaded.Priority, err)
				}
				continue
			}
			domain, parseErr := ingressDomain(raw)
			if parseErr != nil {
				return out, fmt.Errorf("local rule priority %d domain %q: %w", loaded.Priority, raw, parseErr)
			}
			if _, exists := domainSeen[domain]; !exists {
				domainSeen[domain] = struct{}{}
				rule.domains = append(rule.domains, domain)
			}
		}
		rule.ipv4 = normalizeIngressPrefixes(rule.ipv4)
		rule.ipv6 = normalizeIngressPrefixes(rule.ipv6)
		rule.source4 = normalizeIngressPrefixes(rule.source4)
		rule.source6 = normalizeIngressPrefixes(rule.source6)

		if len(rule.domains) > 0 && len(rule.ipv4)+len(rule.ipv6) > 0 {
			return out, fmt.Errorf(
				"local rule priority %d combines domain and IP categories; split it into two ordered rules",
				loaded.Priority,
			)
		}
		if n := len(rule.ipv4) + len(rule.ipv6); n > maxStaticPrefixesPerRule {
			return out, fmt.Errorf(
				"local rule priority %d has %d static prefixes (safe limit %d); use geosite/ChinaDNS",
				loaded.Priority, n, maxStaticPrefixesPerRule,
			)
		}
		if len(rule.domains) > 0 {
			out.dynamicGroups++
			if out.dynamicGroups > maxChinaDNSGroups {
				return out, fmt.Errorf("local routing needs %d ChinaDNS groups; maximum is %d", out.dynamicGroups, maxChinaDNSGroups)
			}
		}
		out.rules = append(out.rules, rule)
	}
	return out, nil
}

func listAllows(values []string, wanted string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func geoToken(raw, kind string) (string, bool) {
	left, right, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(left), kind) {
		return "", false
	}
	right = strings.TrimSpace(right)
	return right, right != ""
}

func appendGeoPrefixes(rule *ingressRule, db *node.GeoDB, name string) error {
	if db == nil {
		return fmt.Errorf("geoip %q requires loaded geodata", name)
	}
	prefixes := db.GeoIPCIDRs(name)
	if len(prefixes) == 0 {
		return fmt.Errorf("geoip %q not found", name)
	}
	for _, p := range prefixes {
		if p.Addr().Is4() {
			rule.ipv4 = append(rule.ipv4, p.Masked())
		} else {
			rule.ipv6 = append(rule.ipv6, p.Masked())
		}
	}
	return nil
}

func appendGeoDomains(rule *ingressRule, db *node.GeoDB, name string, seen map[string]struct{}) error {
	if db == nil {
		return fmt.Errorf("geosite %q requires loaded geodata", name)
	}
	rawRules := db.GeoSiteDomainRules(name)
	if len(rawRules) == 0 {
		return fmt.Errorf("geosite %q not found", name)
	}
	before := len(rule.domains)
	for _, raw := range rawRules {
		typ := strings.ToLower(strings.TrimSpace(raw.Type))
		if typ == "regex" || typ == "regexp" {
			continue
		}
		value := normalizeIngressDomain(raw.Value)
		if value == "" {
			continue
		}
		if typ == "plain" && !strings.Contains(value, ".") {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		rule.domains = append(rule.domains, value)
	}
	if len(rule.domains) == before {
		return fmt.Errorf("geosite %q has no ChinaDNS-compatible domains", name)
	}
	return nil
}

func ingressDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if left, right, ok := strings.Cut(raw, ":"); ok {
		switch strings.ToLower(strings.TrimSpace(left)) {
		case "domain", "full":
			raw = right
		case "regexp", "regex", "keyword":
			return "", fmt.Errorf("%s match cannot be represented by ChinaDNS", left)
		}
	}
	value := normalizeIngressDomain(raw)
	if value == "" {
		return "", fmt.Errorf("invalid domain suffix")
	}
	return value, nil
}

func normalizeIngressDomain(raw string) string {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, " \t\r\n/\\[]()^$*+?{}|") {
		return ""
	}
	return raw
}

func parseIngressPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "/") {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(addr, bits), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func parseIngressPorts(raw string) ([]ingressPortRange, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []ingressPortRange
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := 0, 0
		var err error
		if left, right, ok := strings.Cut(part, "-"); ok {
			lo, err = strconv.Atoi(strings.TrimSpace(left))
			if err == nil {
				hi, err = strconv.Atoi(strings.TrimSpace(right))
			}
		} else {
			lo, err = strconv.Atoi(part)
			hi = lo
		}
		if err != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		out = append(out, ingressPortRange{lo: lo, hi: hi})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port specification")
	}
	return out, nil
}

// normalizeIngressPrefixes removes duplicate and already-covered CIDRs before
// they are handed to nft. That keeps interval sets valid without auto-merge,
// whose incremental rebuild cost is unsafe on small OpenWrt targets.
func normalizeIngressPrefixes(values []netip.Prefix) []netip.Prefix {
	if len(values) < 2 {
		return values
	}
	values = append([]netip.Prefix(nil), values...)
	for i := range values {
		values[i] = values[i].Masked()
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.Addr().BitLen() != right.Addr().BitLen() {
			return left.Addr().BitLen() < right.Addr().BitLen()
		}
		if cmp := left.Addr().Compare(right.Addr()); cmp != 0 {
			return cmp < 0
		}
		return left.Bits() < right.Bits()
	})
	out := values[:0]
	for _, candidate := range values {
		covered := false
		for i := len(out) - 1; i >= 0; i-- {
			prior := out[i]
			if prior.Addr().BitLen() != candidate.Addr().BitLen() {
				continue
			}
			if prior.Bits() <= candidate.Bits() && prior.Contains(candidate.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, candidate)
		}
	}
	return out
}
