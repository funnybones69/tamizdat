package tamizdat

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestIsUnsafeIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
		why  string
	}{
		// Unsafe
		{"127.0.0.1", true, "loopback v4"},
		{"127.255.255.254", true, "loopback v4 high"},
		{"10.0.0.1", true, "RFC1918 10/8"},
		{"172.16.0.1", true, "RFC1918 172.16/12"},
		{"172.31.255.254", true, "RFC1918 172.16/12 boundary"},
		{"192.168.1.1", true, "RFC1918 192.168/16"},
		{"169.254.169.254", true, "AWS/GCP/Azure cloud metadata"},
		{"169.254.0.1", true, "link-local v4"},
		{"224.0.0.1", true, "multicast v4"},
		{"239.255.255.255", true, "multicast v4 high"},
		{"255.255.255.255", true, "broadcast"},
		{"0.0.0.0", true, "unspecified v4"},
		{"0.1.2.3", true, "0/8 current network"},
		{"100.64.0.1", true, "CGNAT RFC6598"},
		{"100.127.255.254", true, "CGNAT high"},
		{"240.0.0.1", true, "reserved 240/4"},
		{"::1", true, "loopback v6"},
		{"::", true, "unspecified v6"},
		{"fe80::1", true, "link-local v6"},
		{"fc00::1", true, "ULA fc00::/7"},
		{"fd12::1", true, "ULA fd00::/8"},
		{"ff00::1", true, "multicast v6"},
		// Safe
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"8.8.8.8", false, "Google DNS"},
		{"100.63.255.255", false, "just below CGNAT"},
		{"100.128.0.0", false, "just above CGNAT"},
		{"172.15.255.255", false, "just below RFC1918 172.16"},
		{"172.32.0.0", false, "just above RFC1918 172.16"},
		{"2001:4860:4860::8888", false, "Google public IPv6"},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Errorf("parse %q failed", tc.ip)
			continue
		}
		got := isUnsafeIP(ip)
		if got != tc.want {
			t.Errorf("isUnsafeIP(%s) = %v, want %v (%s)", tc.ip, got, tc.want, tc.why)
		}
	}
}

func TestResolveAndValidateLiteral(t *testing.T) {
	ctx := context.Background()

	// Public literal IP should pass.
	got, err := ResolveAndValidateDestination(ctx, "1.1.1.1", "443")
	if err != nil {
		t.Fatalf("public literal IP rejected: %v", err)
	}
	if got != "1.1.1.1:443" {
		t.Errorf("got %q, want %q", got, "1.1.1.1:443")
	}

	// Private literal IPs should fail with ErrUnsafeDestination.
	for _, badIP := range []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1",
	} {
		_, err := ResolveAndValidateDestination(ctx, badIP, "443")
		if err == nil {
			t.Errorf("private literal IP %s NOT rejected", badIP)
			continue
		}
		if !errors.Is(err, ErrUnsafeDestination) {
			t.Errorf("private literal IP %s: err = %v, want ErrUnsafeDestination", badIP, err)
		}
	}

	// Bad port.
	for _, badPort := range []string{"0", "65536", "abc", "-1"} {
		_, err := ResolveAndValidateDestination(ctx, "1.1.1.1", badPort)
		if err == nil {
			t.Errorf("bad port %q NOT rejected", badPort)
		}
	}
}
