package wgturnclient

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// AttachResult is what the runner hands back to the caller after the
// WG userspace is alive and reachable through the configured 127.0.0.1
// relay.
type AttachResult struct {
	Net  *netstack.Net // dial through here
	Stop func()        // tears down device + netstack
}

// AttachWireGuardUserspace parses a wg-quick style config text, brings
// up a userspace WireGuard device whose UDP endpoint is the local
// 127.0.0.1:<wgturnclient relay port>, and returns a netstack ready
// for dial.
func (r *Runner) AttachWireGuardUserspace(wgConfig string) (*AttachResult, error) {
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

	// CreateNetTUN gives socksstub a dialable gVisor stack without a
	// kernel utun/fd handoff; the WG device itself consumes the TUN packets.
	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, 1280)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}
	if err := tuneWireGuardNetstackTCPBuffers(tnet); err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("tune netstack tcp buffers: %w", err)
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
	return &AttachResult{Net: tnet, Stop: stop}, nil
}

type wgQuickConfig struct {
	Addresses               []netip.Addr
	DNS                     []netip.Addr
	PrivateKey              []byte
	PeerPublicKey           []byte
	AllowedIPs              []netip.Prefix
	Endpoint                string
	PersistentKeepaliveSecs int
}

func parseWGQuick(text string) (*wgQuickConfig, error) {
	cfg := &wgQuickConfig{}
	section := ""
	peerSeen := false

	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		line := stripWGComment(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				if peerSeen {
					return nil, fmt.Errorf("line %d: multiple [Peer] sections are unsupported", lineNo)
				}
				peerSeen = true
			default:
				return nil, fmt.Errorf("line %d: unsupported section %q", lineNo, section)
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if section == "" {
			return nil, fmt.Errorf("line %d: key outside a section", lineNo)
		}

		switch section {
		case "interface":
			switch key {
			case "address":
				addrs, err := parseAddressList(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: Address: %w", lineNo, err)
				}
				cfg.Addresses = append(cfg.Addresses, addrs...)
			case "dns":
				dns, err := parseAddrList(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: DNS: %w", lineNo, err)
				}
				cfg.DNS = append(cfg.DNS, dns...)
			case "privatekey":
				keyBytes, err := decodeWGKey(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: PrivateKey: %w", lineNo, err)
				}
				cfg.PrivateKey = keyBytes
			case "mtu", "table", "preup", "postup", "predown", "postdown", "saveconfig":
				// wg-quick-only knobs do not apply to the in-process netstack.
			default:
				return nil, fmt.Errorf("line %d: unsupported [Interface] key %q", lineNo, key)
			}
		case "peer":
			switch key {
			case "publickey":
				keyBytes, err := decodeWGKey(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: PublicKey: %w", lineNo, err)
				}
				cfg.PeerPublicKey = keyBytes
			case "allowedips":
				prefixes, err := parsePrefixList(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: AllowedIPs: %w", lineNo, err)
				}
				cfg.AllowedIPs = append(cfg.AllowedIPs, prefixes...)
			case "endpoint":
				ep, err := normalizeEndpoint(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: Endpoint: %w", lineNo, err)
				}
				cfg.Endpoint = ep
			case "persistentkeepalive":
				keepalive, err := parseKeepalive(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: PersistentKeepalive: %w", lineNo, err)
				}
				cfg.PersistentKeepaliveSecs = keepalive
			default:
				return nil, fmt.Errorf("line %d: unsupported [Peer] key %q", lineNo, key)
			}
		}
	}
	return cfg, nil
}

func (c *wgQuickConfig) validate() error {
	if len(c.Addresses) == 0 {
		return fmt.Errorf("missing Interface.Address")
	}
	if len(c.PrivateKey) != 32 {
		return fmt.Errorf("missing or invalid Interface.PrivateKey")
	}
	if len(c.PeerPublicKey) != 32 {
		return fmt.Errorf("missing or invalid Peer.PublicKey")
	}
	if len(c.AllowedIPs) == 0 {
		return fmt.Errorf("missing Peer.AllowedIPs")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("missing Peer.Endpoint/local relay endpoint")
	}
	if len(c.DNS) == 0 {
		c.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return nil
}

func uapiSetString(c *wgQuickConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%x\n", c.PrivateKey)
	b.WriteString("listen_port=0\n")
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%x\n", c.PeerPublicKey)
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.PersistentKeepaliveSecs)
	return b.String()
}

func stripWGComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func decodeWGKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("decoded key is %d bytes, want 32", len(b))
	}
	return b, nil
}

func parseAddressList(s string) ([]netip.Addr, error) {
	prefixes, err := parsePrefixList(s)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(prefixes))
	for _, p := range prefixes {
		addrs = append(addrs, p.Addr())
	}
	return addrs, nil
}

func parseAddrList(s string) ([]netip.Addr, error) {
	parts := splitCSV(s)
	addrs := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", part)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func parsePrefixList(s string) ([]netip.Prefix, error) {
	parts := splitCSV(s)
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := parsePrefixOrAddr(part)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP prefix", s)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

func splitCSV(s string) []string {
	raw := strings.Split(s, ",")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func normalizeEndpoint(s string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("host and port are required")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

func localRelayEndpoint(listen string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func parseKeepalive(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "off" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0")
	}
	return n, nil
}
