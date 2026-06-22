package node

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// captureDispatcher is a stub InboundDispatcher that records the Request
// handed to Dispatch and returns a configurable error so the caller exits
// the proxy loop immediately. Used to drive connHandlerWithIdentity in
// table-driven tests for review-H H-1 (Request.User population).
type captureDispatcher struct {
	mu        sync.Mutex
	got       *Request
	dispatchN int
	err       error
}

func (c *captureDispatcher) Dispatch(ctx context.Context, req *Request) (net.Conn, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dispatchN++
	// Snapshot so the caller can mutate req later without races on read.
	clone := *req
	c.got = &clone
	if c.err == nil {
		return nil, "", errors.New("captureDispatcher: synthetic dispatch failure")
	}
	return nil, "", c.err
}

func (c *captureDispatcher) DispatchPacket(ctx context.Context, req *Request) (net.PacketConn, string, error) {
	return nil, "", errors.New("captureDispatcher: udp not used")
}

func (c *captureDispatcher) snapshot() (*Request, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.got == nil {
		return nil, c.dispatchN
	}
	clone := *c.got
	return &clone, c.dispatchN
}

// runConnHandler drives a single connHandlerWithIdentity invocation with a
// pipe-backed conn so the handler can defer-close it without touching real
// network state. Returns the captured Request (or nil).
func runConnHandler(t *testing.T, identity tamizdat.ConnIdentity, destination string) *Request {
	t.Helper()

	in := &TamizdatInbound{tag: "tamizdat-in"}
	disp := &captureDispatcher{}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	in.mu.Lock()
	in.dispatch = disp
	in.ctx = rootCtx
	in.mu.Unlock()

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		in.connHandlerWithIdentity(rootCtx, server, destination, identity)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("connHandlerWithIdentity did not return within 2s")
	}

	got, n := disp.snapshot()
	if n != 1 {
		t.Fatalf("dispatcher Dispatch called %d times, want 1", n)
	}
	return got
}

// TestTamizdatConnHandlerPopulatesUserName is the headline review-H H-1
// regression test: when the lib resolves a userdb-backed user name, the
// node-level Request handed to the dispatcher carries it as Request.User
// so that routing rules with {"user": ["default"]} can match.
func TestTamizdatConnHandlerPopulatesUserName(t *testing.T) {
	identity := tamizdat.ConnIdentity{
		ShortID:  [8]byte{0x1a, 0xca, 0xd6, 0xad, 0xdd, 0x6e, 0xab, 0x4a},
		UserID:   "user-default-id",
		UserName: "default",
	}
	got := runConnHandler(t, identity, "example.com:443")
	if got == nil {
		t.Fatalf("dispatcher saw no request")
	}
	if got.User != "default" {
		t.Errorf("Request.User = %q, want %q", got.User, "default")
	}
	if got.TargetHost != "example.com" || got.TargetPort != 443 {
		t.Errorf("destination plumbed wrong: host=%q port=%d", got.TargetHost, got.TargetPort)
	}
	if got.InboundTag != "tamizdat-in" {
		t.Errorf("InboundTag = %q, want tamizdat-in", got.InboundTag)
	}
	if got.Network != NetworkTCP {
		t.Errorf("Network = %q, want tcp", got.Network)
	}
}

// TestTamizdatConnHandlerEmptyUserWhenNoRegistry covers the embedded /
// master-shortid fallback: when the lib's userRegistry is unconfigured (or
// the registry lookup missed and the master shortid was accepted), the lib
// hands an identity with empty UserName. Request.User must then stay empty
// so existing legacy callers see no behaviour change.
func TestTamizdatConnHandlerEmptyUserWhenNoRegistry(t *testing.T) {
	identity := tamizdat.ConnIdentity{
		ShortID: [8]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
		// UserID + UserName intentionally empty — embedded master fallback.
	}
	got := runConnHandler(t, identity, "example.com:443")
	if got == nil {
		t.Fatalf("dispatcher saw no request")
	}
	if got.User != "" {
		t.Errorf("Request.User = %q, want empty (no userdb identity)", got.User)
	}
}

// TestRoutingRuleMatchesNamedUser asserts the end-to-end routing decision:
// a CompiledRule with {"user": ["default"]} must match when the inbound has
// populated Request.User to "default", and must miss when the user is "bob"
// or empty. Combined with the above tests this proves H-1 closes the gap.
func TestRoutingRuleMatchesNamedUser(t *testing.T) {
	rules, err := CompileRules([]*Rule{{
		Outbound: "tunnel",
		User:     []string{"default"},
	}})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rule := rules[0]

	cases := []struct {
		name string
		user string
		want bool
	}{
		{"matches-named-user", "default", true},
		{"misses-other-user", "bob", false},
		{"misses-empty-user", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &Request{
				Network:    NetworkTCP,
				TargetHost: "example.com",
				TargetPort: 443,
				InboundTag: "tamizdat-in",
				User:       tc.user,
			}
			got := rule.Match(req)
			if got != tc.want {
				t.Errorf("rule.Match(user=%q) = %v, want %v", tc.user, got, tc.want)
			}
		})
	}
}
