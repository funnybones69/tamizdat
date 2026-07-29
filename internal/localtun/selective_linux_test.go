//go:build linux

package localtun

import (
	"bytes"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func TestSelectiveNFTConfigIsValidAndNeverMarksAllLAN(t *testing.T) {
	policy := ingressPolicy{dynamicGroups: 1, rules: []ingressRule{
		{index: 0, action: ingressDirect, domains: []string{"sync.example"}},
		{index: 1, action: ingressTunnel, domains: []string{"blocked.example"}},
		{index: 2, action: ingressTunnel, ipv4: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{index: 3, action: ingressDirect},
	}}
	r := &selectiveRouteController{cfg: Config{Interface: "br-lan", BypassPrivate: true}}
	got := r.nftConfig(policy, []string{"br-lan", "phy0-ap0"})
	for _, want := range []string{
		`iifname { "br-lan", "phy0-ap0" }`,
		`ip daddr @r14 meta mark set 0x9d return`,
		`ip6 daddr @r16 reject with icmpv6 addr-unreachable`,
		`ip daddr @r24 meta mark set 0x9d return`,
		`set r14 { type ipv4_addr; flags interval; }`,
		`set r24 { type ipv4_addr; flags interval; auto-merge;`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("nft config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `iifname "br-lan" meta l4proto { tcp, udp } meta mark set`) {
		t.Fatalf("selective config contains blanket LAN marking:\n%s", got)
	}
	if strings.Contains(got, `ip6 daddr @r16 meta mark set`) {
		t.Fatalf("IPv6-only destinations must not be sent to the IPv4-only TUN:\n%s", got)
	}
	if _, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(got)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -c failed: %v: %s\n%s", err, out, got)
		}
	}
}
