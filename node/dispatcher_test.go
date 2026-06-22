package node

import (
	"context"
	"errors"
	"net"
	"testing"
)

// stubOutbound records every Dial. Tag is its identity.
type stubOutbound struct {
	tag      string
	dialed   []*Request
	dialErr  error
	dialConn net.Conn
}

func (s *stubOutbound) Tag() string { return s.tag }
func (s *stubOutbound) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	s.dialed = append(s.dialed, req)
	return s.dialConn, s.dialErr
}
func (s *stubOutbound) Close() error { return nil }

func TestDispatcherFirstMatchWins(t *testing.T) {
	a := &stubOutbound{tag: "a", dialErr: errors.New("a-no-dial")}
	b := &stubOutbound{tag: "b", dialErr: errors.New("b-no-dial")}
	c := &stubOutbound{tag: "c", dialErr: errors.New("c-no-dial")}
	outbounds := map[string]Outbound{"a": a, "b": b, "c": c}

	rules, err := CompileRules([]*Rule{
		{Domain: []string{"domain:cdn.example.com"}, Outbound: "a"},
		{IP: []string{"10.0.0.0/8"}, Outbound: "b"},
		{Outbound: "c"}, // catch-all (empty rule = match anything)
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDispatcher(outbounds, rules, "", "a", "AsIs")
	if err != nil {
		t.Fatal(err)
	}

	got, ob := d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "img.cdn.example.com", TargetPort: 443})
	if got != "a" || ob.Tag() != "a" {
		t.Errorf("expected a, got %s", got)
	}
	got, _ = d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "10.5.5.5", TargetPort: 80})
	if got != "b" {
		t.Errorf("expected b, got %s", got)
	}
	got, _ = d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "8.8.8.8", TargetPort: 80})
	if got != "c" {
		t.Errorf("catch-all should fire, got %s", got)
	}
}

func TestDispatcherDefaultOutboundWhenNoRulesMatch(t *testing.T) {
	a := &stubOutbound{tag: "a"}
	b := &stubOutbound{tag: "b"}
	d, err := NewDispatcher(map[string]Outbound{"a": a, "b": b},
		nil, "b", "a", "AsIs")
	if err != nil {
		t.Fatal(err)
	}
	got, ob := d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "anything", TargetPort: 1})
	if got != "b" || ob != b {
		t.Errorf("default should be b, got %s", got)
	}
}

func TestDispatcherFallbackToFirstWhenDefaultEmpty(t *testing.T) {
	a := &stubOutbound{tag: "a"}
	d, err := NewDispatcher(map[string]Outbound{"a": a},
		nil, "", "a", "AsIs")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "anything", TargetPort: 1})
	if got != "a" {
		t.Errorf("fallback should be a, got %s", got)
	}
}

func TestDispatcherInboundTagAffectsRouting(t *testing.T) {
	priv := &stubOutbound{tag: "priv"}
	pub := &stubOutbound{tag: "pub"}
	rules, err := CompileRules([]*Rule{
		{InboundTag: []string{"trusted"}, Outbound: "priv"},
		{Outbound: "pub"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := NewDispatcher(map[string]Outbound{"priv": priv, "pub": pub},
		rules, "", "pub", "AsIs")

	got, _ := d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "x", TargetPort: 1, InboundTag: "trusted"})
	if got != "priv" {
		t.Errorf("trusted inbound should route to priv, got %s", got)
	}
	got, _ = d.Resolve(context.Background(), &Request{Network: "tcp", TargetHost: "x", TargetPort: 1, InboundTag: "anon"})
	if got != "pub" {
		t.Errorf("untrusted inbound should fall through to pub, got %s", got)
	}
}

func TestConfigValidateRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no inbounds", Config{Outbounds: []OutboundConfig{{Tag: "a", Protocol: "freedom"}}}},
		{"no outbounds", Config{Inbounds: []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}}}},
		{"dup outbound tag", Config{
			Inbounds:  []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}},
			Outbounds: []OutboundConfig{{Tag: "a", Protocol: "freedom"}, {Tag: "a", Protocol: "blackhole"}},
		}},
		{"unknown outbound protocol", Config{
			Inbounds:  []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}},
			Outbounds: []OutboundConfig{{Tag: "a", Protocol: "wormhole"}},
		}},
		{"rule outbound missing", Config{
			Inbounds:  []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}},
			Outbounds: []OutboundConfig{{Tag: "a", Protocol: "freedom"}},
			Routing:   RoutingConfig{Rules: []*Rule{{Outbound: "ghost"}}},
		}},
		{"default_outbound missing", Config{
			Inbounds:  []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}},
			Outbounds: []OutboundConfig{{Tag: "a", Protocol: "freedom"}},
			Routing:   RoutingConfig{DefaultOutbound: "ghost"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}

	// Valid baseline.
	good := Config{
		Inbounds:  []InboundConfig{{Tag: "i", Protocol: "socks", Listen: "127.0.0.1:1"}},
		Outbounds: []OutboundConfig{{Tag: "a", Protocol: "freedom"}, {Tag: "b", Protocol: "blackhole"}},
		Routing: RoutingConfig{
			DefaultOutbound: "a",
			Rules: []*Rule{
				{Domain: []string{"domain:ads.example.com"}, Outbound: "b"},
			},
		},
	}
	if err := good.Validate(); err != nil {
		t.Errorf("good config rejected: %v", err)
	}
}

// TestIPOnDemandIteratesAllARecords is the H-RR-2 regression guard: when a
// host resolves to multiple A records and at least one matches a CIDR rule
// (e.g. geoip:cn block list), the dispatcher must honour the matching rule
// regardless of which IP came back first from the resolver. Pre-fix, only
// addrs[0] was checked, so a CDN that returned [a-cdn-clean, b-cn-bad] in
// random order would slip through whenever a-cdn-clean came first.
func TestIPOnDemandIteratesAllARecords(t *testing.T) {
	cleanOut := &stubOutbound{tag: "clean", dialErr: errors.New("clean-no-dial")}
	blockOut := &stubOutbound{tag: "block", dialErr: errors.New("block-no-dial")}
	defaultOut := &stubOutbound{tag: "default", dialErr: errors.New("default-no-dial")}
	outbounds := map[string]Outbound{"clean": cleanOut, "block": blockOut, "default": defaultOut}

	// "block" rule matches a /24 representing the bad-region. The
	// dispatcher's defaultOutbound covers everything else (we deliberately
	// do NOT add an empty catch-all rule, because an empty Match would
	// pre-empt the IP-resolve branch by accepting the un-resolved request).
	rules, err := CompileRules([]*Rule{
		{IP: []string{"203.0.113.0/24"}, Outbound: "block"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDispatcher(outbounds, rules, "default", "default", "IPOnDemand")
	if err != nil {
		t.Fatal(err)
	}

	// Stub the resolver so the test is hermetic. The host returns two A
	// records: one outside the block CIDR (would slip through under the
	// pre-fix first-only behaviour) and one inside it. Order matches the
	// real-world scenario where the "good" IP comes first.
	prev := tryResolveAllFunc
	tryResolveAllFunc = func(_ context.Context, host string) []net.IP {
		if host != "multi.example.com" {
			return nil
		}
		return []net.IP{
			net.ParseIP("198.51.100.10"), // not in any block CIDR
			net.ParseIP("203.0.113.42"),  // matches /24 block CIDR
		}
	}
	t.Cleanup(func() { tryResolveAllFunc = prev })

	req := &Request{
		Network:    "tcp",
		TargetHost: "multi.example.com",
		TargetPort: 443,
	}
	tag, _ := d.Resolve(context.Background(), req)
	if tag != "block" {
		t.Fatalf("Resolve tag = %q, want block (the second A record matches the block CIDR)", tag)
	}

	// Sanity: when no answer matches, default still wins.
	tryResolveAllFunc = func(_ context.Context, host string) []net.IP {
		if host != "clean.example.com" {
			return nil
		}
		return []net.IP{
			net.ParseIP("198.51.100.10"),
			net.ParseIP("198.51.100.11"),
		}
	}
	req2 := &Request{Network: "tcp", TargetHost: "clean.example.com", TargetPort: 443}
	tag2, _ := d.Resolve(context.Background(), req2)
	if tag2 != "default" {
		t.Fatalf("Resolve tag = %q, want default", tag2)
	}
}
