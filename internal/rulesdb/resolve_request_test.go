package rulesdb

import (
	"context"
	"net"
	"testing"

	"github.com/funnybones69/tamizdat/node"
)

func TestResolveRequestPreservesLocalUDPMetadata(t *testing.T) {
	rules, err := node.CompileRules([]*node.Rule{{
		Network:    node.NetworkUDP,
		Source:     []string{"192.168.1.0/24"},
		InboundTag: []string{"local-tun"},
		User:       []string{"router-lan"},
		Outbound:   "via-h2",
	}})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := node.NewDispatcher(map[string]node.Outbound{
		"direct": nil, "via-h2": nil,
	}, rules, "direct", "direct", "AsIs")
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Dispatcher: dispatcher, DefaultTag: "direct"}
	req := &node.Request{
		Network: node.NetworkUDP, TargetHost: "1.1.1.1", TargetPort: 53,
		SourceIP: net.ParseIP("192.168.1.105"), InboundTag: "local-tun", User: "router-lan",
	}
	if got := ResolveRequest(context.Background(), snap, req); got != "via-h2" {
		t.Fatalf("matched tag = %q, want via-h2", got)
	}
	miss := *req
	miss.SourceIP = net.ParseIP("192.168.2.105")
	if got := ResolveRequest(context.Background(), snap, &miss); got != "direct" {
		t.Fatalf("non-matching source tag = %q, want direct", got)
	}
}
