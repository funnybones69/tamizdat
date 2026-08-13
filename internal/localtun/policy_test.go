package localtun

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/funnybones69/tamizdat/internal/rulesdb"
)

func TestBuildIngressPolicyKeepsDirectDefaultAndDomainTunnel(t *testing.T) {
	snap := &rulesdb.Snapshot{Rules: []rulesdb.Loaded{
		{Priority: 10, OutboundTag: "sync", Match: rulesdb.Match{
			Domain: []string{"example.com"}, User: []string{"router-lan"},
		}},
		{Priority: 20, OutboundTag: "direct"},
	}}
	policy, err := buildIngressPolicy(snap, "router-lan")
	if err != nil {
		t.Fatal(err)
	}
	if policy.tunnelTag != "sync" {
		t.Fatalf("tunnel tag = %q, want sync", policy.tunnelTag)
	}
	if len(policy.rules) != 2 || policy.dynamicGroups != 1 {
		t.Fatalf("rules/groups = %d/%d, want 2/1", len(policy.rules), policy.dynamicGroups)
	}
	if policy.rules[0].action != ingressTunnel || len(policy.rules[0].domains) != 1 {
		t.Fatalf("first rule = %#v, want one tunnel domain", policy.rules[0])
	}
	if policy.rules[1].action != ingressDirect {
		t.Fatalf("last action = %q, want direct", policy.rules[1].action)
	}
}

func TestBuildIngressPolicyRejectsMultipleTunnelOutbounds(t *testing.T) {
	snap := &rulesdb.Snapshot{Rules: []rulesdb.Loaded{
		{
			Priority: 1, OutboundTag: "sync", Match: rulesdb.Match{IP: []string{"203.0.113.1"}},
		},
		{
			Priority: 2, OutboundTag: "other", Match: rulesdb.Match{IP: []string{"198.51.100.1"}},
		},
	}}
	_, err := buildIngressPolicy(snap, "router-lan")
	if err == nil || !strings.Contains(err.Error(), "multiple tunnel outbounds") {
		t.Fatalf("error = %v, want multiple-outbound rejection", err)
	}
}

func TestBuildIngressPolicyAcceptsSevenDomainGroups(t *testing.T) {
	rules := make([]rulesdb.Loaded, 0, 7)
	for i := 0; i < 7; i++ {
		rules = append(rules, rulesdb.Loaded{
			Priority:    i + 1,
			OutboundTag: "balancer",
			Match: rulesdb.Match{
				Domain: []string{fmt.Sprintf("rule-%d.example", i)},
				User:   []string{"router-lan"},
			},
		})
	}
	policy, err := buildIngressPolicy(&rulesdb.Snapshot{Rules: rules}, "router-lan")
	if err != nil {
		t.Fatalf("buildIngressPolicy: %v", err)
	}
	if policy.dynamicGroups != 1 {
		t.Fatalf("dynamic groups = %d, want 1 after coalescing", policy.dynamicGroups)
	}
	if policy.tunnelTag != "balancer" {
		t.Fatalf("tunnel tag = %q, want balancer", policy.tunnelTag)
	}
}

func TestBuildIngressPolicyDoesNotMergeAcrossDifferentAction(t *testing.T) {
	snap := &rulesdb.Snapshot{Rules: []rulesdb.Loaded{
		{Priority: 1, OutboundTag: "balancer", Match: rulesdb.Match{Domain: []string{"tunnel.example"}, User: []string{"router-lan"}}},
		{Priority: 2, OutboundTag: "direct", Match: rulesdb.Match{Domain: []string{"direct.example"}, User: []string{"router-lan"}}},
	}}
	policy, err := buildIngressPolicy(snap, "router-lan")
	if err != nil {
		t.Fatalf("buildIngressPolicy: %v", err)
	}
	if policy.dynamicGroups != 2 || len(policy.rules) != 2 {
		t.Fatalf("rules/groups = %d/%d, want 2/2", len(policy.rules), policy.dynamicGroups)
	}
}

func TestBuildIngressPolicySkipsRulesForAnotherUser(t *testing.T) {
	snap := &rulesdb.Snapshot{Rules: []rulesdb.Loaded{
		{Priority: 1, OutboundTag: "sync", Match: rulesdb.Match{
			Domain: []string{"private.example"}, User: []string{"someone-else"},
		}},
		{Priority: 2, OutboundTag: "direct"},
	}}
	policy, err := buildIngressPolicy(snap, "router-lan")
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.rules) != 1 || policy.rules[0].action != ingressDirect {
		t.Fatalf("policy = %#v, want only direct fallback", policy)
	}
}

func TestNormalizeIngressPrefixesRemovesCoveredCIDRs(t *testing.T) {
	values := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.9/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	got := normalizeIngressPrefixes(values)
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(got) != len(want) {
		t.Fatalf("prefix count = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}
}
