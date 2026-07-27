package tamizdat

import "testing"

// review-A P5: lookupMasqueradeOrigin matches an exact SNI key.
func TestLookupMasqueradeOriginExactMatch(t *testing.T) {
	pool := map[string]string{
		"ok.ru":  "ok.ru:443",
		"vk.com": "vk.com:443",
	}
	got, ok := lookupMasqueradeOrigin(pool, "ok.ru")
	if !ok || got != "ok.ru:443" {
		t.Errorf("exact match: got (%q, %v), want (%q, true)", got, ok, "ok.ru:443")
	}
}

// review-A P5: lookupMasqueradeOrigin strips a leading "www." and
// retries the lookup. Real browsers send www.ok.ru while operators
// usually configure the pool with the bare domain.
func TestLookupMasqueradeOriginWwwStripped(t *testing.T) {
	pool := map[string]string{
		"ok.ru": "ok.ru:443",
	}
	got, ok := lookupMasqueradeOrigin(pool, "www.ok.ru")
	if !ok || got != "ok.ru:443" {
		t.Errorf("www-stripped: got (%q, %v), want (%q, true)", got, ok, "ok.ru:443")
	}
}

// review-A P5: a bare domain that has no "www." prefix should NOT match
// a "www.foo" key (we only strip, not add).
func TestLookupMasqueradeOriginWwwNotAdded(t *testing.T) {
	pool := map[string]string{
		"www.example.com": "example-cdn:443",
	}
	if got, ok := lookupMasqueradeOrigin(pool, "example.com"); ok {
		t.Errorf("bare-domain lookup unexpectedly matched www-key: got (%q, true)", got)
	}
}

// review-A P5: suffix-wildcard "*.cdn.example.com" matches any subdomain
// of cdn.example.com but NOT the bare domain or a co-prefix.
func TestLookupMasqueradeOriginWildcardMatch(t *testing.T) {
	pool := map[string]string{
		"*.cdn.example.com": "shared-cdn:443",
	}

	cases := []struct {
		sni    string
		want   string
		wantOK bool
	}{
		{"static.cdn.example.com", "shared-cdn:443", true},
		{"a.b.cdn.example.com", "shared-cdn:443", true},
		{"cdn.example.com", "", false},     // bare domain — wildcard requires extra label
		{"evilcdn.example.com", "", false}, // co-prefix without dot boundary
		{"static.cdn.evil.com", "", false}, // different parent
	}
	for _, tc := range cases {
		got, ok := lookupMasqueradeOrigin(pool, tc.sni)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("sni %q: got (%q, %v), want (%q, %v)", tc.sni, got, ok, tc.want, tc.wantOK)
		}
	}
}

// review-A P5: when nothing matches, return ("", false) so the caller
// falls through to the default MasqueradeDomain origin.
func TestLookupMasqueradeOriginNoMatchFallsThrough(t *testing.T) {
	pool := map[string]string{"ok.ru": "ok.ru:443"}
	got, ok := lookupMasqueradeOrigin(pool, "completely-unknown.invalid")
	if ok || got != "" {
		t.Errorf("no-match: got (%q, %v), want (\"\", false)", got, ok)
	}
}

// review-A P5: empty pool or empty SNI returns ("", false) without
// crashing on nil-map access.
func TestLookupMasqueradeOriginEmptyInputs(t *testing.T) {
	if _, ok := lookupMasqueradeOrigin(nil, "ok.ru"); ok {
		t.Error("nil pool unexpectedly matched")
	}
	if _, ok := lookupMasqueradeOrigin(map[string]string{}, "ok.ru"); ok {
		t.Error("empty pool unexpectedly matched")
	}
	if _, ok := lookupMasqueradeOrigin(map[string]string{"ok.ru": "ok.ru:443"}, ""); ok {
		t.Error("empty SNI unexpectedly matched")
	}
}

// review-A P5: empty origin value in the pool is treated as "no entry".
// Lets operators conditionally disable a pool key without deleting it.
func TestLookupMasqueradeOriginEmptyOriginIgnored(t *testing.T) {
	pool := map[string]string{
		"ok.ru":             "",
		"*.cdn.example.com": "",
	}
	if _, ok := lookupMasqueradeOrigin(pool, "ok.ru"); ok {
		t.Error("empty origin value matched on exact lookup")
	}
	if _, ok := lookupMasqueradeOrigin(pool, "www.ok.ru"); ok {
		t.Error("empty origin value matched on www-stripped lookup")
	}
	if _, ok := lookupMasqueradeOrigin(pool, "static.cdn.example.com"); ok {
		t.Error("empty origin value matched on wildcard lookup")
	}
}

// review-A A-RR-1: SNI is case-insensitive per RFC 6066 §3. A probe
// arriving with SNI YANDEX.RU / Yandex.Ru / yandex.RU must match a
// pool keyed yandex.ru. Without case-folding the lookup falls through
// to the default origin = exactly Tell #2 (success-path / failure-path
// origin mismatch) the SNI pool is meant to fix.
func TestLookupMasqueradeOriginCaseInsensitive(t *testing.T) {
	pool := map[string]string{
		"yandex.ru":         "yandex.ru:443",
		"*.cdn.example.com": "shared-cdn:443",
	}
	cases := []struct {
		name string
		sni  string
		want string
	}{
		{"all-uppercase", "YANDEX.RU", "yandex.ru:443"},
		{"mixed-case", "Yandex.Ru", "yandex.ru:443"},
		{"trailing-uppercase-tld", "yandex.RU", "yandex.ru:443"},
		{"www-stripped-uppercase", "WWW.YANDEX.RU", "yandex.ru:443"},
		{"wildcard-uppercase", "STATIC.CDN.EXAMPLE.COM", "shared-cdn:443"},
		{"wildcard-mixed-case", "Static.Cdn.Example.Com", "shared-cdn:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := lookupMasqueradeOrigin(pool, tc.sni)
			if !ok || got != tc.want {
				t.Errorf("sni %q: got (%q, %v), want (%q, true)", tc.sni, got, ok, tc.want)
			}
		})
	}
}
