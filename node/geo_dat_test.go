package node

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGeoDBParsesSyntheticDatFiles(t *testing.T) {
	dir := t.TempDir()
	geoipPath := filepath.Join(dir, "geoip.dat")
	geositePath := filepath.Join(dir, "geosite.dat")

	writeTestDat(t, geoipPath, testGeoIPList(
		testGeoIP("telegram", testCIDR("149.154.160.0", 20)),
		testGeoIP("private", testCIDR("10.0.0.0", 8)),
	))
	writeTestDat(t, geositePath, testGeoSiteList(
		testGeoSite("openai",
			testDomainRule(2, "openai.com"),
			testDomainRule(3, "api.openai.com"),
		),
		testGeoSite("telegram", testDomainRule(2, "telegram.org")),
	))

	db, err := LoadGeoDB(geoipPath, geositePath)
	if err != nil {
		t.Fatalf("LoadGeoDB: %v", err)
	}
	if db == nil {
		t.Fatal("LoadGeoDB returned nil for existing dat files")
	}
	if !prefixesContainAddr(db.GeoIPCIDRs("telegram"), netip.MustParseAddr("149.154.166.1")) {
		t.Fatal("telegram geoip from dat should contain 149.154.166.1")
	}
	if prefixesContainAddr(db.GeoIPCIDRs("private"), netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("private geoip from dat must not contain 8.8.8.8")
	}

	matchers := db.GeositeMatchers("openai")
	if len(matchers) != 2 {
		t.Fatalf("openai matchers len=%d, want 2", len(matchers))
	}
	if !anyDomainMatcherMatches(matchers, "chat.openai.com") {
		t.Fatal("openai root-domain geosite matcher should match chat.openai.com")
	}
	if !anyDomainMatcherMatches(matchers, "api.openai.com") {
		t.Fatal("openai full geosite matcher should match api.openai.com")
	}
}

func TestLoadGeoDBLogsWarningWhenConfiguredDatMissing(t *testing.T) {
	// Capture geoDatLogger output. The package-level seam is set in geo_dat.go
	// to log.Printf by default; we swap it for the duration of the test so
	// we can assert the warning fires for explicitly-configured-but-missing paths.
	var captured []string
	origLogger := geoDatLogger
	geoDatLogger = func(format string, args ...interface{}) {
		captured = append(captured, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { geoDatLogger = origLogger })

	missingGeoIP := filepath.Join(t.TempDir(), "absent-geoip.dat")
	missingGeosite := filepath.Join(t.TempDir(), "absent-geosite.dat")

	db, err := LoadGeoDB(missingGeoIP, missingGeosite)
	if err != nil {
		t.Fatalf("LoadGeoDB: %v", err)
	}
	if db != nil {
		t.Fatalf("LoadGeoDB with no existing dat should return nil, got %#v", db)
	}

	if len(captured) != 2 {
		t.Fatalf("expected 2 warning lines (geoip + geosite), got %d: %v", len(captured), captured)
	}
	if !strings.Contains(captured[0], "geoip.dat") || !strings.Contains(captured[0], missingGeoIP) {
		t.Fatalf("geoip warning missing path or label: %q", captured[0])
	}
	if !strings.Contains(captured[1], "geosite.dat") || !strings.Contains(captured[1], missingGeosite) {
		t.Fatalf("geosite warning missing path or label: %q", captured[1])
	}

	// Empty path → operator did NOT configure → no warning, no surprise.
	captured = nil
	if _, err := LoadGeoDB("", ""); err != nil {
		t.Fatalf("LoadGeoDB empty paths: %v", err)
	}
	if len(captured) != 0 {
		t.Fatalf("empty paths should not log warnings, got %d: %v", len(captured), captured)
	}
}

func TestCuratedGeoIPFallbackWorksWithoutDat(t *testing.T) {
	db, err := LoadGeoDB(filepath.Join(t.TempDir(), "missing-geoip.dat"), "")
	if err != nil {
		t.Fatalf("LoadGeoDB missing file: %v", err)
	}
	if db != nil {
		t.Fatalf("LoadGeoDB with no existing dat should return nil, got %#v", db)
	}
	if !prefixesContainAddr(db.GeoIPCIDRs("telegram"), netip.MustParseAddr("149.154.166.1")) {
		t.Fatal("curated telegram geoip should contain 149.154.166.1")
	}
	if !prefixesContainAddr(db.GeoIPCIDRs("private"), netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("curated private geoip should contain RFC1918 addresses")
	}
}

func TestCuratedGeoIPTelegramCoversUpstreamCIDRs(t *testing.T) {
	// Sample one address from each upstream CIDR (core.telegram.org/resources/cidr.txt)
	// added in the 2026-05-09 expansion. Pre-expansion the curated list
	// only had 91.108.4-20/22, 91.108.56/22, 149.154.160/20 — these new
	// addresses would have fallen through to "no match".
	wantMatches := []string{
		"91.105.192.5",  // 91.105.192.0/23
		"91.108.4.5",    // 91.108.4.0/22 (was already covered, sanity)
		"95.161.64.5",   // 95.161.64.0/20
		"149.154.164.5", // 149.154.164.0/22 (subsumed by /20 but listed for parity)
		"185.76.151.5",  // 185.76.151.0/24
	}
	wantMatchesV6 := []string{
		"2001:67c:4e8::1",  // 2001:67c:4e8::/48
		"2001:b28:f23c::1", // 2001:b28:f23c::/47
		"2001:b28:f23f::1", // 2001:b28:f23f::/48
		"2a0a:f280:200::1", // 2a0a:f280:200::/40
	}

	// Empty paths → curated fallback only (no .dat overrides).
	prefixes := (*GeoDB)(nil).GeoIPCIDRs("telegram")
	if len(prefixes) == 0 {
		t.Fatal("curated telegram CIDR list is empty")
	}

	for _, addrStr := range wantMatches {
		addr := netip.MustParseAddr(addrStr)
		if !prefixesContainAddr(prefixes, addr) {
			t.Errorf("curated telegram should contain IPv4 %s but did not", addrStr)
		}
	}
	for _, addrStr := range wantMatchesV6 {
		addr := netip.MustParseAddr(addrStr)
		if !prefixesContainAddr(prefixes, addr) {
			t.Errorf("curated telegram should contain IPv6 %s but did not", addrStr)
		}
	}
}

func TestGeoIPRuleRoutesThroughDispatcher(t *testing.T) {
	finland := &stubOutbound{tag: "tunnel-finland"}
	direct := &stubOutbound{tag: "direct"}
	rules, err := CompileRules([]*Rule{
		{GeoIP: []string{"telegram"}, Outbound: "tunnel-finland"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	disp, err := NewDispatcher(map[string]Outbound{
		"tunnel-finland": finland,
		"direct":         direct,
	}, rules, "direct", "direct", "AsIs")
	if err != nil {
		t.Fatal(err)
	}

	got, _ := disp.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "149.154.166.1", TargetPort: 443})
	if got != "tunnel-finland" {
		t.Fatalf("telegram IP routed to %q, want tunnel-finland", got)
	}
	got, _ = disp.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "8.8.8.8", TargetPort: 443})
	if got != "direct" {
		t.Fatalf("non-telegram IP routed to %q, want direct", got)
	}
}

func TestGeoPrefixesInRuleFields(t *testing.T) {
	rules, err := CompileRules([]*Rule{
		{IP: []string{"geoip:private"}, Outbound: "block"},
		{Domain: []string{"geosite:openai"}, Outbound: "tunnel-finland"},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	if !rules[0].Match(&Request{Network: "tcp", TargetHost: "10.0.0.1", TargetPort: 443}) {
		t.Fatal("ip geoip:private should match RFC1918 target")
	}
	if !rules[1].Match(&Request{Network: "tcp", TargetHost: "chat.openai.com", TargetPort: 443}) {
		t.Fatal("domain geosite:openai should match chat.openai.com via curated fallback")
	}
}

func writeTestDat(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func prefixesContainAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func anyDomainMatcherMatches(matchers []domainMatcher, host string) bool {
	for _, m := range matchers {
		if m.match(host) {
			return true
		}
	}
	return false
}

func testGeoIPList(entries ...[]byte) []byte {
	var out []byte
	for _, entry := range entries {
		out = append(out, testLenField(1, entry)...)
	}
	return out
}

func testGeoIP(country string, cidrs ...[]byte) []byte {
	out := testLenField(1, []byte(country))
	for _, cidr := range cidrs {
		out = append(out, testLenField(2, cidr)...)
	}
	return out
}

func testCIDR(ip string, bits int) []byte {
	addr := netip.MustParseAddr(ip)
	var ipBytes []byte
	if addr.Is4() {
		b := addr.As4()
		ipBytes = b[:]
	} else {
		b := addr.As16()
		ipBytes = b[:]
	}
	out := testLenField(1, ipBytes)
	out = append(out, testVarintField(2, uint64(bits))...)
	return out
}

func testGeoSiteList(entries ...[]byte) []byte {
	var out []byte
	for _, entry := range entries {
		out = append(out, testLenField(1, entry)...)
	}
	return out
}

func testGeoSite(country string, domains ...[]byte) []byte {
	out := testLenField(1, []byte(country))
	for _, d := range domains {
		out = append(out, testLenField(2, d)...)
	}
	return out
}

func testDomainRule(typeNumber int, value string) []byte {
	out := testVarintField(1, uint64(typeNumber))
	out = append(out, testLenField(2, []byte(value))...)
	return out
}

func testLenField(field int, payload []byte) []byte {
	out := testUvarint(uint64(field<<3 | 2))
	out = append(out, testUvarint(uint64(len(payload)))...)
	out = append(out, payload...)
	return out
}

func testVarintField(field int, value uint64) []byte {
	out := testUvarint(uint64(field<<3 | 0))
	out = append(out, testUvarint(value)...)
	return out
}

func testUvarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	out = append(out, byte(v))
	return out
}
