//go:build linux

package wgturnclient

import (
	"fmt"
	"log"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// KernelAttachResult owns a userspace WireGuard device backed by a Linux
// kernel TUN interface. The OpenWrt routing lifecycle owns the address and
// policy routes; this object owns only the TUN fd and WireGuard device.
type KernelAttachResult struct {
	Device    tun.Device
	Addresses []netip.Addr
	Stop      func()
}

// AttachWireGuardKernel parses the broker-delivered wg-quick config and
// attaches userspace WireGuard to an existing/new Linux TUN interface.
func (r *Runner) AttachWireGuardKernel(wgConfig, tunName string, mtu int) (*KernelAttachResult, error) {
	cfg, err := parseWGQuick(wgConfig)
	if err != nil {
		return nil, fmt.Errorf("wgquick parse: %w", err)
	}
	if ep := localRelayEndpoint(r.cfg.Listen); ep != "" {
		cfg.Endpoint = ep
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("wgquick config: %w", err)
	}
	// Addresses and AllowedIPs are non-secret routing metadata and are useful
	// when validating an OpenWrt kernel-TUN attachment. Keys and the original
	// configuration are deliberately never logged.
	log.Printf("[wg] routing config: addresses=%v allowed_ips=%v", cfg.Addresses, cfg.AllowedIPs)
	if tunName == "" {
		tunName = "tamtun0"
	}
	if mtu <= 0 {
		mtu = 1280
	}

	tunDev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create kernel tun %s: %w", tunName, err)
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { log.Printf("[wg] "+format, args...) },
		Errorf:   func(format string, args ...any) { log.Printf("[wg ERR] "+format, args...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapiSetString(cfg)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg up: %w", err)
	}

	stop := func() {
		dev.Down()
		dev.Close()
	}
	return &KernelAttachResult{Device: tunDev, Addresses: append([]netip.Addr(nil), cfg.Addresses...), Stop: stop}, nil
}
