package node

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDomainMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false}, // bare = full match
		{"full:example.com", "example.com", true},
		{"full:example.com", "example.com", true}, // matcher contract: caller pre-lowercases
		{"domain:example.com", "example.com", true},
		{"domain:example.com", "www.example.com", true},
		{"domain:example.com", "evil-example.com", false},
		{"domain:example.com", "com", false},
		{"keyword:track", "ads.tracker.com", true},
		{"keyword:track", "example.com", false},
		{"regexp:^api[0-9]+$", "api42", true},
		{"regexp:^api[0-9]+$", "api", false},
		// geosite/geoip stubbed → never match
		{"geosite:ads", "ads.example.com", false},
		{"geoip:cn", "8.8.8.8", false},
	}
	for _, tc := range cases {
		m, err := parseDomainMatcher(tc.pattern)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.pattern, err)
		}
		got := m.match(tc.host)
		if got != tc.want {
			t.Errorf("%q match %q = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		bits int
	}{
		{"10.0.0.0/8", true, 8},
		{"192.168.1.1", true, 32}, // bare → /32
		{"::1", true, 128},
		{"fe80::/10", true, 10},
		{"not-an-ip", false, 0},
		{"10.0.0.0/40", false, 0},
	}
	for _, tc := range cases {
		p, err := parseCIDR(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseCIDR(%q) ok=%v err=%v", tc.in, tc.ok, err)
			continue
		}
		if tc.ok && p.Bits() != tc.bits {
			t.Errorf("parseCIDR(%q) bits=%d want %d", tc.in, p.Bits(), tc.bits)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		in    string
		port  int
		match bool
	}{
		{"80", 80, true},
		{"80", 81, false},
		{"1000-2000", 1500, true},
		{"1000-2000", 999, false},
		{"80,443,8080-8090", 443, true},
		{"80,443,8080-8090", 8085, true},
		{"80,443,8080-8090", 8091, false},
	}
	for _, tc := range cases {
		rs, err := parsePortSpec(tc.in)
		if err != nil {
			t.Fatalf("parsePortSpec(%q): %v", tc.in, err)
		}
		got := portInRanges(tc.port, rs)
		if got != tc.match {
			t.Errorf("portInRanges(%d in %q) = %v, want %v", tc.port, tc.in, got, tc.match)
		}
	}

	for _, bad := range []string{"", "70000", "0", "abc", "10-5"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Errorf("parsePortSpec(%q) should fail", bad)
		}
	}
}

func TestRuleMatchAndCategories(t *testing.T) {
	rules := []*Rule{
		{Domain: []string{"domain:example.com"}, Outbound: "ob1"},
		{IP: []string{"10.0.0.0/8"}, Outbound: "ob2"},
		{Network: "udp", Port: "53", Outbound: "ob3"},
		{InboundTag: []string{"sock-a"}, Source: []string{"127.0.0.1/32"}, Outbound: "ob4"},
		{User: []string{"alice", "carol"}, Outbound: "ob5"},
	}
	cr, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// rule[0]: domain
	if !cr[0].Match(&Request{Network: "tcp", TargetHost: "www.example.com", TargetPort: 443}) {
		t.Error("domain suffix should match www.example.com")
	}
	if cr[0].Match(&Request{Network: "tcp", TargetHost: "evil.com", TargetPort: 443}) {
		t.Error("domain rule must not match evil.com")
	}

	// rule[1]: IP CIDR — only matches when host is literal IP
	if !cr[1].Match(&Request{Network: "tcp", TargetHost: "10.0.0.5", TargetPort: 80}) {
		t.Error("CIDR should match 10.0.0.5")
	}
	if cr[1].Match(&Request{Network: "tcp", TargetHost: "8.8.8.8", TargetPort: 80}) {
		t.Error("CIDR must not match 8.8.8.8")
	}
	if cr[1].Match(&Request{Network: "tcp", TargetHost: "example.com", TargetPort: 80}) {
		t.Error("CIDR must not match a domain")
	}

	// rule[2]: udp + port 53 (AND)
	if !cr[2].Match(&Request{Network: "udp", TargetHost: "1.1.1.1", TargetPort: 53}) {
		t.Error("udp:53 should match")
	}
	if cr[2].Match(&Request{Network: "tcp", TargetHost: "1.1.1.1", TargetPort: 53}) {
		t.Error("network constraint must filter tcp")
	}
	if cr[2].Match(&Request{Network: "udp", TargetHost: "1.1.1.1", TargetPort: 1053}) {
		t.Error("port constraint must filter wrong port")
	}

	// rule[3]: inbound_tag + source AND
	rq := &Request{
		Network: "tcp", TargetHost: "anywhere", TargetPort: 80,
		SourceIP: net.ParseIP("127.0.0.1"), InboundTag: "sock-a",
	}
	if !cr[3].Match(rq) {
		t.Error("inbound_tag+source AND should match")
	}
	rq.InboundTag = "other"
	if cr[3].Match(rq) {
		t.Error("inbound_tag mismatch must reject")
	}
	rq.InboundTag = "sock-a"
	rq.SourceIP = net.ParseIP("10.1.2.3")
	if cr[3].Match(rq) {
		t.Error("source CIDR mismatch must reject")
	}

	// rule[4]: authenticated user OR-list
	if !cr[4].Match(&Request{Network: "tcp", TargetHost: "x", TargetPort: 443, User: "alice"}) {
		t.Error("user rule should match listed authenticated user")
	}
	if cr[4].Match(&Request{Network: "tcp", TargetHost: "x", TargetPort: 443, User: "bob"}) {
		t.Error("user rule must reject non-listed user")
	}
	if cr[4].Match(&Request{Network: "tcp", TargetHost: "x", TargetPort: 443}) {
		t.Error("user rule must reject anonymous request")
	}
}

func TestExpandRuleIncludesAddsDomainAndIPRules(t *testing.T) {
	dir := t.TempDir()
	domainFile := filepath.Join(dir, "domains.txt")
	ipFile := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(domainFile, []byte("# comments are ignored\n\ndomain:example.org\nfull:api.example.net\nkeyword:tracker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipFile, []byte("# CIDRs and bare IPs\n10.0.0.0/8\n192.0.2.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	domainRule := &Rule{IncludeDomainFile: []string{filepath.Base(domainFile)}, Outbound: "domain-ob"}
	ipRule := &Rule{IncludeIPFile: []string{filepath.Base(ipFile)}, Outbound: "ip-ob"}
	if err := ExpandRuleIncludes(domainRule, dir); err != nil {
		t.Fatalf("ExpandRuleIncludes domain: %v", err)
	}
	if err := ExpandRuleIncludes(ipRule, dir); err != nil {
		t.Fatalf("ExpandRuleIncludes ip: %v", err)
	}
	if len(domainRule.Domain) != 3 {
		t.Fatalf("expanded domains=%v, want 3", domainRule.Domain)
	}
	if len(ipRule.IP) != 2 {
		t.Fatalf("expanded IPs=%v, want 2", ipRule.IP)
	}

	compiled, err := CompileRules([]*Rule{domainRule, ipRule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	if !compiled[0].Match(&Request{Network: "tcp", TargetHost: "www.example.org", TargetPort: 443}) {
		t.Error("included domain suffix should match")
	}
	if !compiled[1].Match(&Request{Network: "tcp", TargetHost: "192.0.2.9", TargetPort: 443}) {
		t.Error("included bare IP should match as /32")
	}
}
