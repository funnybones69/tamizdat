package node

import "net/netip"

// curatedGeoIP is the in-tree fallback used when no .dat is loaded (or when a
// dat file lacks a given country code). It is intentionally tiny — for prod
// use prefer the runetfreedom .dat (refreshed every ~6h) via geoip_dat_path
// in the node JSON config; that gets you the full xray-format dataset
// instead of this hand-curated shortlist.
//
// telegram entries updated 2026-05-09 from core.telegram.org/resources/cidr.txt
// (mirrored at runetfreedom russia-blocked-geoip text/telegram.txt).
var curatedGeoIP = map[string][]netip.Prefix{
	"private": mustPrefixes(
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	),
	"telegram": mustPrefixes(
		"91.105.192.0/23",
		"91.108.4.0/22",
		"91.108.8.0/22",
		"91.108.12.0/22",
		"91.108.16.0/22",
		"91.108.20.0/22",
		"91.108.56.0/22",
		"95.161.64.0/20",
		"149.154.160.0/20",
		"149.154.164.0/22",
		"149.154.168.0/22",
		"149.154.172.0/22",
		"185.76.151.0/24",
		"2001:67c:4e8::/48",
		"2001:b28:f23c::/47",
		"2001:b28:f23f::/48",
		"2a0a:f280:200::/40",
	),
	"cloudflare": mustPrefixes(
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	),
	"google": mustPrefixes(
		"8.8.8.0/24",
		"8.8.4.0/24",
		"34.0.0.0/8",
		"35.0.0.0/8",
		"64.233.160.0/19",
		"66.102.0.0/20",
		"66.249.80.0/20",
		"72.14.192.0/18",
		"74.125.0.0/16",
		"108.177.8.0/21",
		"142.250.0.0/15",
		"172.217.0.0/16",
		"216.58.192.0/19",
		"2001:4860::/32",
	),
}

var curatedGeosite = map[string][]DomainRule{
	"openai": {
		{Type: "RootDomain", Value: "openai.com"},
		{Type: "RootDomain", Value: "chatgpt.com"},
		{Type: "RootDomain", Value: "oaistatic.com"},
		{Type: "RootDomain", Value: "oaiusercontent.com"},
		{Type: "RootDomain", Value: "openaiapi-site.azureedge.net"},
	},
	"telegram": {
		{Type: "RootDomain", Value: "telegram.org"},
		{Type: "RootDomain", Value: "t.me"},
		{Type: "RootDomain", Value: "tdesktop.com"},
		{Type: "RootDomain", Value: "telegra.ph"},
	},
	"google": {
		{Type: "RootDomain", Value: "google.com"},
		{Type: "RootDomain", Value: "gstatic.com"},
		{Type: "RootDomain", Value: "googleapis.com"},
		{Type: "RootDomain", Value: "googleusercontent.com"},
		{Type: "RootDomain", Value: "youtube.com"},
		{Type: "RootDomain", Value: "gvt1.com"},
	},
	"cloudflare": {
		{Type: "RootDomain", Value: "cloudflare.com"},
		{Type: "RootDomain", Value: "cloudflare-dns.com"},
		{Type: "RootDomain", Value: "workers.dev"},
	},
}

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}
