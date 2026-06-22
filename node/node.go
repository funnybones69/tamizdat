package node

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Node owns the live inbounds, outbounds, and dispatcher for one config.
// It is the top-level handle the cmd binary uses to start/stop the proxy.
type Node struct {
	cfg        *Config
	dispatcher *Dispatcher
	inbounds   []Inbound
	outbounds  map[string]Outbound

	mu     sync.Mutex
	closed bool

	logger *log.Logger
}

// New builds a Node from cfg. It does NOT start listeners — call Start.
//
// Build order:
//  1. outbounds (so they can be referenced by routing rules)
//  2. compile rules → dispatcher
//  3. inbounds (each holds a reference to the dispatcher)
//
// On any failure mid-build, already-built outbounds are Close()d.
func New(cfg *Config) (*Node, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	logger := log.Default()

	outbounds := make(map[string]Outbound, len(cfg.Outbounds))
	cleanup := func() {
		for _, ob := range outbounds {
			_ = ob.Close()
		}
	}

	var firstTag string
	for i, oc := range cfg.Outbounds {
		ob, err := buildOutbound(oc)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("outbounds[%d] %q: %w", i, oc.Tag, err)
		}
		outbounds[oc.Tag] = ob
		if i == 0 {
			firstTag = oc.Tag
		}
	}

	rulesForCompile, err := expandedRoutingRules(cfg.Routing.Rules, cfg.baseDir)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("expand rule includes: %w", err)
	}
	geoDB, err := LoadGeoDB(
		resolveIncludePath(cfg.GeoIPDatPath, cfg.baseDir),
		resolveIncludePath(cfg.GeositeDatPath, cfg.baseDir),
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("load geo db: %w", err)
	}
	rules, err := CompileRulesWithGeoDB(rulesForCompile, geoDB)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	disp, err := NewDispatcher(outbounds, rules,
		cfg.Routing.DefaultOutbound, firstTag, cfg.Routing.DomainStrategy)
	if err != nil {
		cleanup()
		return nil, err
	}

	inbounds := make([]Inbound, 0, len(cfg.Inbounds))
	for i, ic := range cfg.Inbounds {
		in, err := buildInbound(ic)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("inbounds[%d] %q: %w", i, ic.Tag, err)
		}
		inbounds = append(inbounds, in)
	}

	return &Node{
		cfg:        cfg,
		dispatcher: disp,
		inbounds:   inbounds,
		outbounds:  outbounds,
		logger:     logger,
	}, nil
}

// Dispatcher returns the underlying dispatcher (used by tests).
func (n *Node) Dispatcher() *Dispatcher { return n.dispatcher }

// Start launches every inbound in its own goroutine. The first inbound that
// returns an error cancels ctx and triggers Close on the rest. Start returns
// when ctx is done or all inbounds have stopped.
func (n *Node) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(n.inbounds))
	var wg sync.WaitGroup
	for _, in := range n.inbounds {
		wg.Add(1)
		go func(in Inbound) {
			defer wg.Done()
			if err := in.Start(ctx, n.dispatcher); err != nil {
				n.logger.Printf("[node] inbound %q stopped: %v", in.Tag(), err)
				errCh <- fmt.Errorf("inbound %q: %w", in.Tag(), err)
				cancel()
			}
		}(in)
	}

	<-ctx.Done()
	for _, in := range n.inbounds {
		_ = in.Close()
	}
	wg.Wait()
	close(errCh)

	// Collect all inbound errors, return the first if any.
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Close stops all listeners and releases outbounds.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.mu.Unlock()

	for _, in := range n.inbounds {
		_ = in.Close()
	}
	for _, ob := range n.outbounds {
		_ = ob.Close()
	}
	return nil
}

func buildOutbound(oc OutboundConfig) (Outbound, error) {
	switch oc.Protocol {
	case "freedom":
		return NewFreedomOutbound(oc.Tag, 0), nil
	case "blackhole":
		return NewBlackholeOutbound(oc.Tag), nil
	case "tamizdat":
		return NewTamizdatOutbound(oc.Tag, oc.Settings)
	case "socks":
		return NewSocksOutbound(oc.Tag, oc.Settings)
	default:
		return nil, fmt.Errorf("unknown outbound protocol %q", oc.Protocol)
	}
}

func buildInbound(ic InboundConfig) (Inbound, error) {
	switch ic.Protocol {
	case "socks":
		return NewSocksInbound(ic.Tag, ic.Listen, ic.Settings)
	case "http":
		return NewHTTPInbound(ic.Tag, ic.Listen, ic.Settings)
	case "tamizdat":
		return NewTamizdatInbound(ic.Tag, ic.Listen, ic.Settings)
	default:
		return nil, fmt.Errorf("unknown inbound protocol %q", ic.Protocol)
	}
}

func expandedRoutingRules(rules []*Rule, baseDir string) ([]*Rule, error) {
	out := make([]*Rule, 0, len(rules))
	for i, r := range rules {
		if r == nil {
			out = append(out, nil)
			continue
		}
		clone := cloneRule(r)
		if err := ExpandRuleIncludes(clone, baseDir); err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out = append(out, clone)
	}
	return out, nil
}

func cloneRule(r *Rule) *Rule {
	clone := *r
	clone.Domain = append([]string(nil), r.Domain...)
	clone.IP = append([]string(nil), r.IP...)
	clone.GeoIP = append([]string(nil), r.GeoIP...)
	clone.Geosite = append([]string(nil), r.Geosite...)
	clone.InboundTag = append([]string(nil), r.InboundTag...)
	clone.Source = append([]string(nil), r.Source...)
	clone.User = append([]string(nil), r.User...)
	clone.IncludeDomainFile = append([]string(nil), r.IncludeDomainFile...)
	clone.IncludeIPFile = append([]string(nil), r.IncludeIPFile...)
	return &clone
}
