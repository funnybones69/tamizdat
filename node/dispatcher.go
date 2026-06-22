package node

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// Dispatcher routes a Request to the configured Outbound based on
// CompiledRule order. It is the integration seam between Inbound and
// Outbound: an Inbound calls Dispatch with a Request, the Dispatcher
// chooses an Outbound and delegates the dial.
type Dispatcher struct {
	mu               sync.RWMutex
	rules            []*CompiledRule
	defaultOutbound  string
	firstOutboundTag string
	outbounds        map[string]Outbound
	domainStrategy   string
}

// NewDispatcher constructs a Dispatcher.
//
// outbounds: map of tag → Outbound. Must contain at least one entry.
// rules:     compiled in order; first match wins.
// defaultOutbound: fallback when no rule matches. If empty, the dispatcher
//
//	falls back to firstOutboundTag (typically the first declared outbound,
//	which mirrors xray's "outbound[0] is default" rule).
//
// domainStrategy: AsIs|IPIfNonMatch|IPOnDemand. AsIs is the default.
func NewDispatcher(outbounds map[string]Outbound, rules []*CompiledRule,
	defaultOutbound, firstOutboundTag, domainStrategy string) (*Dispatcher, error) {

	if len(outbounds) == 0 {
		return nil, fmt.Errorf("no outbounds")
	}
	if defaultOutbound != "" {
		if _, ok := outbounds[defaultOutbound]; !ok {
			return nil, fmt.Errorf("default_outbound %q not in outbounds", defaultOutbound)
		}
	}
	if firstOutboundTag == "" {
		// pick any tag; iteration order is undefined, callers should pass it.
		for t := range outbounds {
			firstOutboundTag = t
			break
		}
	}
	if domainStrategy == "" {
		domainStrategy = "AsIs"
	}
	return &Dispatcher{
		rules:            rules,
		defaultOutbound:  defaultOutbound,
		firstOutboundTag: firstOutboundTag,
		outbounds:        outbounds,
		domainStrategy:   domainStrategy,
	}, nil
}

// Resolve returns the Outbound that handles req. It does NOT dial; it only
// applies routing logic. Used by tests and by Dispatch itself.
//
// IPIfNonMatch: if no rule matched on domain, the host is resolved (best
// IP) and the rules are re-tried with the resolved IP literal in TargetHost.
// On resolve failure, the request proceeds with the original host.
func (d *Dispatcher) Resolve(ctx context.Context, req *Request) (string, Outbound) {
	d.mu.RLock()
	rules := d.rules
	d.mu.RUnlock()

	for _, r := range rules {
		if r.Match(req) {
			return r.tag, d.outbounds[r.tag]
		}
	}

	if d.domainStrategy == "IPIfNonMatch" || d.domainStrategy == "IPOnDemand" {
		// H-RR-2: iterate every resolved IP, not just the first. DNS round-
		// robins answer order, so a host that resolves to e.g. [a-cdn-clean,
		// b-cn-bad] would slip past a geoip:cn block rule whenever the DNS
		// happened to return a-cdn-clean first. Walk rules in priority
		// order (outer) and IPs in answer order (inner); the first rule
		// that matches ANY of the answer IPs wins. This preserves rule
		// priority (a generic catch-all does not pre-empt a specific block
		// CIDR just because the generic rule trivially matches the first
		// IP).
		ips := tryResolveAll(ctx, req.TargetHost)
		if len(ips) > 0 {
			for _, r := range rules {
				for _, ip := range ips {
					alt := *req
					alt.TargetHost = ip.String()
					if r.Match(&alt) {
						return r.tag, d.outbounds[r.tag]
					}
				}
			}
		}
	}

	tag := d.defaultOutbound
	if tag == "" {
		tag = d.firstOutboundTag
	}
	return tag, d.outbounds[tag]
}

// Dispatch applies routing then asks the chosen Outbound to dial.
// Returns the resolved outbound tag for logging.
func (d *Dispatcher) Dispatch(ctx context.Context, req *Request) (net.Conn, string, error) {
	tag, ob := d.Resolve(ctx, req)
	if ob == nil {
		return nil, tag, fmt.Errorf("no outbound %q", tag)
	}
	conn, err := ob.Dial(ctx, req)
	return conn, tag, err
}

// DispatchPacket applies routing then opens a UDP outbound.
// Outbounds that do not implement UDPDialer return ErrUDPUnsupported.
func (d *Dispatcher) DispatchPacket(ctx context.Context, req *Request) (net.PacketConn, string, error) {
	tag, ob := d.Resolve(ctx, req)
	if ob == nil {
		return nil, tag, fmt.Errorf("no outbound %q", tag)
	}
	udp, ok := ob.(UDPDialer)
	if !ok {
		return nil, tag, ErrUDPUnsupported
	}
	pc, err := udp.DialPacket(ctx, req)
	return pc, tag, err
}

// tryResolve does a best-effort lookup with a default resolver. Returns the
// first IP, or nil on failure. ctx deadline (if any) is honoured.
//
// Retained for callers (incl. tests) that want only the first IP. The
// IPIfNonMatch / IPOnDemand path uses tryResolveAll; see H-RR-2.
func tryResolve(ctx context.Context, host string) net.IP {
	if ips := tryResolveAll(ctx, host); len(ips) > 0 {
		return ips[0]
	}
	return nil
}

// tryResolveAll does a best-effort lookup and returns ALL resolved IPs
// in answer-set order, or nil on failure / empty answer. ctx deadline (if
// any) is honoured. resolveAll is overridable in tests via the package-
// private hook tryResolveAllFunc.
func tryResolveAll(ctx context.Context, host string) []net.IP {
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	if tryResolveAllFunc != nil {
		return tryResolveAllFunc(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out
}

// tryResolveAllFunc, when set, replaces the default DNS resolver in
// tryResolveAll. Test hook. nil = use net.DefaultResolver.
var tryResolveAllFunc func(ctx context.Context, host string) []net.IP
