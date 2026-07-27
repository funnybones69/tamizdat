package tamizdat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// ErrUnsafeDestination is returned when a client-requested destination resolves
// to a private, loopback, link-local, or otherwise reserved address. This
// prevents authenticated clients from using the server as a confused-deputy to
// reach internal services or cloud-metadata endpoints.
var ErrUnsafeDestination = errors.New("destination resolves to unsafe address")

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

var (
	destinationResolverMu sync.RWMutex
	destinationResolver   ipResolver = net.DefaultResolver
)

func lookupDestinationIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	destinationResolverMu.RLock()
	resolver := destinationResolver
	destinationResolverMu.RUnlock()
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIPAddr(ctx, host)
}

// ResolveAndValidateDestination resolves host to one or more IP addresses and
// returns "ip:port" for the first non-reserved IP. If host is already a
// literal IP it is validated in-place. Returns ErrUnsafeDestination wrapped
// with detail if all resolved IPs are private/loopback/link-local/multicast/etc.
//
// Returning the resolved IP (rather than re-dialing the hostname) eliminates
// a DNS-rebinding TOCTOU window: net.DialTimeout would re-resolve and could
// be fooled into picking a private IP that the validator never saw.
func ResolveAndValidateDestination(ctx context.Context, host, port string) (string, error) {
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return "", fmt.Errorf("%w: invalid port %q", ErrUnsafeDestination, port)
	}

	// Literal IP fast-path: validate directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if isUnsafeIP(ip) {
			return "", fmt.Errorf("%w: literal IP %s in reserved range", ErrUnsafeDestination, ip)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	// Hostname path: resolve, pick first non-unsafe IP, return literal.
	ips, err := lookupDestinationIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("dns lookup %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("dns lookup %q: no records", host)
	}
	for _, ipa := range ips {
		if !isUnsafeIP(ipa.IP) {
			return net.JoinHostPort(ipa.IP.String(), port), nil
		}
	}
	return "", fmt.Errorf("%w: all resolved IPs for %q are private/reserved", ErrUnsafeDestination, host)
}

// isUnsafeIP reports whether the IP belongs to a range the proxy refuses to
// forward to. Covers RFC 1918 private (10/8, 172.16/12, 192.168/16),
// loopback (127/8), link-local incl. cloud-metadata (169.254/16, fe80::/10),
// multicast, unspecified (0.0.0.0, ::), broadcast/reserved (240/4),
// CGNAT (100.64/10), and IPv6 ULA (fc00::/7).
func isUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8 -- current network
		if ip4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 -- RFC 6598 CGNAT
		if ip4[0] == 100 && (ip4[1]&0xC0) == 0x40 {
			return true
		}
		// 240.0.0.0/4 -- reserved (incl. 255.255.255.255 broadcast)
		if ip4[0] >= 240 {
			return true
		}
	}
	return false
}
