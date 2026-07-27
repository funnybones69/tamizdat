package tamizdat

import "testing"

// TestEnsureHostPort_NoPort exercises the bare-host fallback path.
func TestEnsureHostPort_NoPort(t *testing.T) {
	cases := map[string]string{
		"example.com":   "example.com:443",
		"127.0.0.1":     "127.0.0.1:443",
		"localhost":     "localhost:443",
		"":              "",
		"sub.host.test": "sub.host.test:443",
	}
	for in, want := range cases {
		if got := ensureHostPort(in, "443"); got != want {
			t.Errorf("ensureHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestForwardPathRespectsExplicitPort is the A-FU-1 regression guard:
// when a masquerade pool entry carries an explicit port (e.g.
// `mc.yandex.ru:8443`), the forward dial must NOT re-wrap with the
// default :443. Pre-fix the address became `mc.yandex.ru:8443:443` and
// every forward dial failed.
func TestForwardPathRespectsExplicitPort(t *testing.T) {
	cases := map[string]string{
		"mc.yandex.ru:8443":  "mc.yandex.ru:8443",
		"example.com:80":     "example.com:80",
		"127.0.0.1:31337":    "127.0.0.1:31337",
		"[2001:db8::1]:443":  "[2001:db8::1]:443",
		"[2001:db8::2]:8080": "[2001:db8::2]:8080",
	}
	for in, want := range cases {
		if got := ensureHostPort(in, "443"); got != want {
			t.Errorf("ensureHostPort(%q) = %q, want %q (explicit port should NOT be re-wrapped with :443)", in, got, want)
		}
	}
}
