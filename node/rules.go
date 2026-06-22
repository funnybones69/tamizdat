package node

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Network constants.
const (
	NetworkTCP = "tcp"
	NetworkUDP = "udp"
)

// Request describes a routing decision input. It is filled by an Inbound
// before handing the connection to the Dispatcher.
type Request struct {
	// Network is "tcp" or "udp".
	Network string
	// TargetHost is the destination host as supplied by the client (may be
	// a domain or a literal IP).
	TargetHost string
	// TargetPort is the destination port (1-65535).
	TargetPort int
	// SourceIP is the peer IP that connected to the inbound (may be nil).
	SourceIP net.IP
	// InboundTag is the tag of the inbound that produced this request.
	InboundTag string
	// User is the authenticated user identifier from the inbound (for example,
	// a SOCKS5 USER/PASS username). Empty when no auth was used.
	User string
}

// Address returns "host:port" suitable for a Dial call.
func (r *Request) Address() string {
	return net.JoinHostPort(r.TargetHost, strconv.Itoa(r.TargetPort))
}

// CompiledRule is a Rule with its matchers pre-built.
type CompiledRule struct {
	tag         string
	domains     []domainMatcher
	cidrs       []netip.Prefix
	srcCIDRs    []netip.Prefix
	portRanges  []portRange
	network     string
	inboundTags map[string]struct{}
	users       map[string]struct{}
}

// CompileRules turns a slice of *Rule into matcher form using only the curated
// in-tree geo fallback. Errors out on the first invalid pattern/CIDR/port spec.
func CompileRules(rs []*Rule) ([]*CompiledRule, error) {
	return CompileRulesWithGeoDB(rs, nil)
}

// CompileRulesWithGeoDB turns a slice of *Rule into matcher form using an
// optional parsed xray .dat database plus curated fallback for common lists.
func CompileRulesWithGeoDB(rs []*Rule, geoDB *GeoDB) ([]*CompiledRule, error) {
	out := make([]*CompiledRule, 0, len(rs))
	for i, r := range rs {
		cr, err := compileRule(r, geoDB)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out = append(out, cr)
	}
	return out, nil
}

func compileRule(r *Rule, geoDB *GeoDB) (*CompiledRule, error) {
	if r == nil {
		return nil, fmt.Errorf("nil rule")
	}
	cr := &CompiledRule{tag: r.Outbound}

	for _, name := range r.GeoIP {
		if err := appendGeoIPCIDRs(cr, geoDB, name); err != nil {
			return nil, err
		}
	}
	for _, name := range r.Geosite {
		if err := appendGeositeMatchers(cr, geoDB, name); err != nil {
			return nil, err
		}
	}

	for _, d := range r.Domain {
		if name, ok := geoPrefixValue(d, "geosite"); ok {
			if err := appendGeositeMatchers(cr, geoDB, name); err != nil {
				return nil, err
			}
			continue
		}
		if name, ok := geoPrefixValue(d, "geoip"); ok {
			if err := appendGeoIPCIDRs(cr, geoDB, name); err != nil {
				return nil, err
			}
			continue
		}
		m, err := parseDomainMatcher(d)
		if err != nil {
			return nil, fmt.Errorf("domain %q: %w", d, err)
		}
		cr.domains = append(cr.domains, m)
	}

	for _, c := range r.IP {
		if name, ok := geoPrefixValue(c, "geoip"); ok {
			if err := appendGeoIPCIDRs(cr, geoDB, name); err != nil {
				return nil, err
			}
			continue
		}
		p, err := parseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("ip %q: %w", c, err)
		}
		cr.cidrs = append(cr.cidrs, p)
	}
	for _, c := range r.Source {
		p, err := parseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", c, err)
		}
		cr.srcCIDRs = append(cr.srcCIDRs, p)
	}

	if r.Port != "" {
		ranges, err := parsePortSpec(r.Port)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", r.Port, err)
		}
		cr.portRanges = ranges
	}

	if r.Network != "" {
		nw := strings.ToLower(strings.TrimSpace(r.Network))
		switch nw {
		case "tcp", "udp", "tcp,udp", "udp,tcp":
		default:
			return nil, fmt.Errorf("network %q: must be tcp|udp|tcp,udp", r.Network)
		}
		cr.network = nw
	}

	if len(r.InboundTag) > 0 {
		cr.inboundTags = make(map[string]struct{}, len(r.InboundTag))
		for _, t := range r.InboundTag {
			cr.inboundTags[t] = struct{}{}
		}
	}
	if len(r.User) > 0 {
		cr.users = make(map[string]struct{}, len(r.User))
		for _, u := range r.User {
			cr.users[u] = struct{}{}
		}
	}

	return cr, nil
}

// Match reports whether the rule applies to the given Request.
//
// AND across categories (domain AND IP AND port AND ...); OR within each.
// An empty category is treated as "match anything" — i.e. it does not
// constrain the decision.
//
// IP matching: if TargetHost parses as a valid net.IP, that IP is checked
// against the CIDR list. Otherwise IP rules are skipped — call sites that
// want IP-after-resolve behaviour must resolve before invoking Match.
func (cr *CompiledRule) Match(req *Request) bool {
	if cr.network != "" && !networkMatches(cr.network, req.Network) {
		return false
	}
	if len(cr.inboundTags) > 0 {
		if _, ok := cr.inboundTags[req.InboundTag]; !ok {
			return false
		}
	}
	if len(cr.users) > 0 {
		if _, ok := cr.users[req.User]; !ok {
			return false
		}
	}
	if len(cr.portRanges) > 0 && !portInRanges(req.TargetPort, cr.portRanges) {
		return false
	}
	if len(cr.srcCIDRs) > 0 {
		if req.SourceIP == nil || !cidrsContain(cr.srcCIDRs, req.SourceIP) {
			return false
		}
	}

	domainOK := len(cr.domains) == 0
	if !domainOK {
		host := strings.TrimSuffix(strings.ToLower(req.TargetHost), ".")
		for _, m := range cr.domains {
			if m.match(host) {
				domainOK = true
				break
			}
		}
		if !domainOK {
			return false
		}
	}

	ipOK := len(cr.cidrs) == 0
	if !ipOK {
		if ip := net.ParseIP(req.TargetHost); ip != nil {
			ipOK = cidrsContain(cr.cidrs, ip)
		}
		if !ipOK {
			return false
		}
	}

	return true
}

func networkMatches(spec, nw string) bool {
	if spec == "" {
		return true
	}
	if spec == nw {
		return true
	}
	// "tcp,udp" / "udp,tcp" matches both.
	return strings.Contains(spec, ",") && strings.Contains(spec, nw)
}

// ---- Domain matchers --------------------------------------------------

type domainMatcher interface{ match(host string) bool }

type fullMatch struct{ s string }
type plainMatch struct{ s string } // alias for full
type suffixMatch struct{ s string }
type keywordMatch struct{ s string }
type regexMatch struct{ re *regexp.Regexp }

func (m fullMatch) match(h string) bool  { return h == m.s }
func (m plainMatch) match(h string) bool { return h == m.s }

// suffixMatch matches the host either as the exact suffix-string, or as
// `<prefix>.<suffix>` for any prefix. The naïve formulation
//
//	return h == m.s || strings.HasSuffix(h, "."+m.s)
//
// allocated a fresh string on every call via "."+m.s. With geosite
// expanded into hundreds of thousands of suffix matchers and each
// inbound stream walking every rule, that allocation chain dominated
// CPU under load (pprof: 93% of total in concatstring2/memmove from
// here, single client could peg a 1 vCPU VPS). The non-allocating form
// below checks the trailing-byte boundary and the slice equality
// directly — same semantics, zero allocations.
func (m suffixMatch) match(h string) bool {
	if h == m.s {
		return true
	}
	// h must be at least len("<X>." + m.s) chars to host a "*." + m.s match.
	if len(h) < len(m.s)+1 {
		return false
	}
	// The byte immediately before the suffix span must be the label sep.
	if h[len(h)-len(m.s)-1] != '.' {
		return false
	}
	return h[len(h)-len(m.s):] == m.s
}
func (m keywordMatch) match(h string) bool { return strings.Contains(h, m.s) }
func (m regexMatch) match(h string) bool   { return m.re.MatchString(h) }

// parseDomainMatcher parses "type:value" or a bare value (treated as full).
//
// Recognised types: domain (suffix), full, regexp, keyword.
// "geosite:*" and "geoip:*" are reserved; they are accepted at parse time but
// match nothing (warn at config-validate stage). This avoids requiring a
// geosite database for v1 while keeping config compatibility with xray.
func parseDomainMatcher(s string) (domainMatcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty domain pattern")
	}
	if i := strings.IndexByte(s, ':'); i > 0 {
		typ := strings.ToLower(s[:i])
		val := strings.ToLower(strings.TrimSpace(s[i+1:]))
		switch typ {
		case "domain":
			return suffixMatch{s: val}, nil
		case "full":
			return fullMatch{s: val}, nil
		case "keyword":
			return keywordMatch{s: val}, nil
		case "regexp", "regex":
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, fmt.Errorf("regex compile: %w", err)
			}
			return regexMatch{re: re}, nil
		case "geosite", "geoip":
			// Accepted but disabled in v1 (no geo db). Match nothing.
			return regexMatch{re: regexp.MustCompile(`^\x00$`)}, nil
		}
	}
	return fullMatch{s: strings.ToLower(s)}, nil
}

func appendGeoIPCIDRs(cr *CompiledRule, geoDB *GeoDB, name string) error {
	cidrs := geoDB.GeoIPCIDRs(name)
	if len(cidrs) == 0 {
		return fmt.Errorf("geoip %q: not found in .dat files or curated fallback", normalizeGeoName(name))
	}
	cr.cidrs = append(cr.cidrs, cidrs...)
	return nil
}

func appendGeositeMatchers(cr *CompiledRule, geoDB *GeoDB, name string) error {
	matchers, ok, err := geositeMatchersFor(geoDB, name)
	if err != nil {
		return fmt.Errorf("geosite %q: %w", normalizeGeoName(name), err)
	}
	if !ok || len(matchers) == 0 {
		return fmt.Errorf("geosite %q: not found in .dat files or curated fallback", normalizeGeoName(name))
	}
	cr.domains = append(cr.domains, matchers...)
	return nil
}

func geoPrefixValue(s, prefix string) (string, bool) {
	left, right, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || !strings.EqualFold(left, prefix) {
		return "", false
	}
	right = normalizeGeoName(right)
	return right, right != ""
}

// ---- IP/CIDR ---------------------------------------------------------

func parseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	// allow bare IP -> /32 or /128
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		bits := 32
		if addr.Is6() && !addr.Is4In6() {
			bits = 128
		}
		return netip.PrefixFrom(addr, bits), nil
	}
	return netip.ParsePrefix(s)
}

func cidrsContain(cidrs []netip.Prefix, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ---- Ports -----------------------------------------------------------

type portRange struct{ lo, hi int }

func parsePortSpec(s string) ([]portRange, error) {
	var out []portRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(part[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("bad range %q", part)
			}
			out = append(out, portRange{lo, hi})
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("bad port %q", part)
			}
			out = append(out, portRange{p, p})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port spec")
	}
	return out, nil
}

func portInRanges(p int, rs []portRange) bool {
	for _, r := range rs {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

// ExpandRuleIncludes mutates r by appending xray flat-text include files into
// its inline Domain and IP rule lists. baseDir resolves relative include paths;
// pass an empty baseDir to resolve relative paths from the current process cwd.
func ExpandRuleIncludes(r *Rule, baseDir string) error {
	if r == nil {
		return nil
	}
	for _, raw := range r.IncludeDomainFile {
		path := resolveIncludePath(raw, baseDir)
		lines, err := readNonCommentLines(path)
		if err != nil {
			return fmt.Errorf("include_domain_file %q: %w", raw, err)
		}
		r.Domain = append(r.Domain, lines...)
	}
	for _, raw := range r.IncludeIPFile {
		path := resolveIncludePath(raw, baseDir)
		lines, err := readNonCommentLines(path)
		if err != nil {
			return fmt.Errorf("include_ip_file %q: %w", raw, err)
		}
		r.IP = append(r.IP, lines...)
	}
	return nil
}

func resolveIncludePath(raw, baseDir string) string {
	if raw == "" || filepath.IsAbs(raw) || baseDir == "" {
		return raw
	}
	return filepath.Join(baseDir, raw)
}

func readNonCommentLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
