//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/funnybones69/tamizdat/internal/wgturn"
)

var (
	wgturnListen      = flag.String("wgturn-listen", "", "DTLS listen address for WireGuard-over-TURN inbound (empty = disabled)")
	wgturnPassword    = flag.String("wgturn-password", "", "Password for WireGuard-over-TURN client auth")
	wgturnWGPort      = flag.Int("wgturn-wg-port", 56001, "Internal WireGuard UDP port for wgturn")
	wgturnConfigDir   = flag.String("wgturn-config-dir", "/etc/tamizdat/wgturn", "WireGuard key storage directory for wgturn")
	wgturnSubnet      = flag.String("wgturn-subnet", "10.66.66.0/24", "WireGuard tunnel subnet for wgturn")
	wgturnServerIP    = flag.String("wgturn-server-ip", "10.66.66.1", "WireGuard tunnel server IP for wgturn")
	wgturnOutboundTag = flag.String("wgturn-outbound-tag", "", "When set, wgturn uses this outbound as fixed fallback; empty keeps bridge mode on registry/routing default.")
)

func wgturnFlagExplicit(flagSet map[string]bool, name string) bool {
	if flagSet != nil && flagSet[name] {
		return true
	}
	long := "-" + name
	for _, arg := range os.Args[1:] {
		if arg == long || strings.HasPrefix(arg, long+"=") {
			return true
		}
	}
	return false
}

func configureWGTurnFromSettings(settings map[string]string, flagSet map[string]bool) {
	if settings == nil {
		return
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-listen") {
		if enabled := settings["wgturn_enabled"]; enabled == "0" || enabled == "false" {
			*wgturnListen = ""
		} else if v := settings["wgturn_listen"]; v != "" {
			*wgturnListen = v
		}
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-password") {
		*wgturnPassword = settings["wgturn_password"]
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-config-dir") && settings["wgturn_config_dir"] != "" {
		*wgturnConfigDir = settings["wgturn_config_dir"]
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-subnet") && settings["wgturn_subnet"] != "" {
		*wgturnSubnet = settings["wgturn_subnet"]
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-server-ip") && settings["wgturn_server_ip"] != "" {
		*wgturnServerIP = settings["wgturn_server_ip"]
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-outbound-tag") {
		*wgturnOutboundTag = settings["wgturn_outbound_tag"]
	}
	if !wgturnFlagExplicit(flagSet, "wgturn-wg-port") {
		if v := settings["wgturn_wg_port"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				*wgturnWGPort = n
			}
		}
	}
}

// startWGTurn starts the wgturn DTLS+WireGuard listener if -wgturn-listen is
// set. Returns a shutdown function (no-op if wgturn is disabled).
//
// resolver may be nil when the outbound registry is disabled — in that case
// the legacy NAT path is used regardless of the -wgturn-outbound-tag flag.
func startWGTurn(ctx context.Context, resolver wgturn.OutboundResolver, authenticator wgturn.Authenticator, onIdentityDone func(wgturn.ClientIdentity), flowRouter wgturn.FlowRouter, accounting wgturn.Accounting) func() {
	addr := *wgturnListen
	if addr == "" {
		return func() {}
	}

	if *wgturnPassword == "" && authenticator == nil {
		log.Fatal("-wgturn-password is required when -wgturn-listen is set unless panel shortid auth is available")
	}

	cfg := wgturn.Config{
		ListenAddr:     addr,
		WGPort:         *wgturnWGPort,
		Password:       *wgturnPassword,
		ConfigDir:      *wgturnConfigDir,
		WGSubnet:       *wgturnSubnet,
		WGServerIP:     *wgturnServerIP,
		Authenticate:   authenticator,
		OnIdentityDone: onIdentityDone,
		FlowRouter:     flowRouter,
		Accounting:     accounting,
	}

	if resolver != nil && (*wgturnOutboundTag != "" || flowRouter != nil) {
		cfg.Outbounds = resolver
		cfg.OutboundTag = *wgturnOutboundTag
		if *wgturnOutboundTag != "" {
			log.Printf("wgturn: bridge mode enabled, fallback outbound %q", *wgturnOutboundTag)
		} else {
			log.Printf("wgturn: bridge mode enabled, fallback outbound = registry default")
		}
	} else if tag := *wgturnOutboundTag; tag != "" {
		log.Printf("wgturn: -wgturn-outbound-tag=%q ignored (no outbound registry available)", tag)
	}

	srv, err := wgturn.NewServer(cfg)
	if err != nil {
		log.Fatalf("wgturn: %v", err)
	}

	go func() {
		if err := srv.Start(ctx); err != nil {
			log.Fatalf("wgturn: %v", err)
		}
	}()

	return func() {
		srv.Shutdown()
	}
}
