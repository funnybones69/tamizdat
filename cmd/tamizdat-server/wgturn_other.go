//go:build !linux

package main

import (
	"context"

	"github.com/funnybones69/tamizdat/internal/wgturn"
)

// startWGTurn is a no-op stub on non-Linux platforms. The wgturn package
// requires Linux TUN and iptables/nftables.
func configureWGTurnFromSettings(_ map[string]string, _ map[string]bool) {}

func startWGTurn(_ context.Context, _ wgturn.OutboundResolver, _ wgturn.Authenticator, _ func(wgturn.ClientIdentity), _ wgturn.FlowRouter, _ wgturn.Accounting) func() {
	return func() {}
}
