package node

import (
	"fmt"
	"strings"
	"testing"
)

const testPubKeyHex = "1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363"

func TestParseURIMinimal(t *testing.T) {
	p, err := ParseURI("tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru#primary")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if p.Host != "example.com" || p.Port != 443 {
		t.Fatalf("host/port = %s/%d", p.Host, p.Port)
	}
	if p.PrimarySNI != "ok.ru" {
		t.Fatalf("PrimarySNI = %q", p.PrimarySNI)
	}
	if p.MasterShortID != [8]byte{0xd1, 0xb1, 0x22, 0x78, 0x22, 0x19, 0x75, 0x9f} {
		t.Fatalf("MasterShortID = %x", p.MasterShortID)
	}
	if len(p.Pubkey) != 32 {
		t.Fatalf("Pubkey len = %d", len(p.Pubkey))
	}
	if p.Label != "primary" {
		t.Fatalf("Label = %q", p.Label)
	}
	if len(p.CoverTrafficTargets) != 0 {
		t.Fatalf("CoverTrafficTargets = %v", p.CoverTrafficTargets)
	}
}

func TestParseURIWithCpool(t *testing.T) {
	raw := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru&cpool=mc.yandex.ru:443,an.yandex.ru:443,yastatic.net:443"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	want := []string{"mc.yandex.ru:443", "an.yandex.ru:443", "yastatic.net:443"}
	if strings.Join(p.CoverTrafficTargets, "|") != strings.Join(want, "|") {
		t.Fatalf("cpool = %v, want %v", p.CoverTrafficTargets, want)
	}
}

func TestParseURICpoolDuplicatesVerbatim(t *testing.T) {
	raw := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru&cpool=mc.yandex.ru:443,mc.yandex.ru:443,vk.com:443"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	want := []string{"mc.yandex.ru:443", "mc.yandex.ru:443", "vk.com:443"}
	if strings.Join(p.CoverTrafficTargets, "|") != strings.Join(want, "|") {
		t.Fatalf("cpool = %v, want %v", p.CoverTrafficTargets, want)
	}
}

func TestParseURIWithCpoolEncoded(t *testing.T) {
	raw := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru&cpool=mc.yandex.ru%3A443%2Can.yandex.ru%3A443#label%2Cwith%2Ccomma"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	want := []string{"mc.yandex.ru:443", "an.yandex.ru:443"}
	if strings.Join(p.CoverTrafficTargets, "|") != strings.Join(want, "|") {
		t.Fatalf("cpool = %v, want %v", p.CoverTrafficTargets, want)
	}
	if p.Label != "label,with,comma" {
		t.Fatalf("Label = %q", p.Label)
	}
}

func TestParseURIErrorCases(t *testing.T) {
	base := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru"
	cases := map[string]string{
		"bad scheme":        "https://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"missing master":    "tamizdat://example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"master length":     "tamizdat://abcd@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"missing pbk":       "tamizdat://d1b122782219759f@example.com:443?sni=ok.ru",
		"bad pbk hex":       "tamizdat://d1b122782219759f@example.com:443?pbk=zz&sni=ok.ru",
		"missing sni":       "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex,
		"bad hostport":      "tamizdat://d1b122782219759f@example.com?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"port out of range": "tamizdat://d1b122782219759f@example.com:70000?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"bad master hex":    "tamizdat://zzzzzzzzzzzzzzzz@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru",
		"control":           base,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseURI(raw)
			if name == "control" {
				if err != nil {
					t.Fatalf("control parse failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseURI succeeded for %s", name)
			}
		})
	}
}

func TestParseURICpoolErrors(t *testing.T) {
	prefix := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru"
	entries := make([]string, 33)
	for i := range entries {
		entries[i] = fmt.Sprintf("h%d.example:443", i)
	}
	cases := map[string]string{
		"duplicate-key":      prefix + "&cpool=mc.yandex.ru:443&cpool=an.yandex.ru:443",
		"empty-value":        prefix + "&cpool=",
		"empty-entry":        prefix + "&cpool=mc.yandex.ru:443,,an.yandex.ru:443",
		"malformed-hostport": prefix + "&cpool=mc.yandex.ru",
		"port-out-of-range":  prefix + "&cpool=mc.yandex.ru:70000",
		"non-ascii-byte":     prefix + "&cpool=%D1%8F.ru:443",
		"33-entries-cap":     prefix + "&cpool=" + strings.Join(entries, ","),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseURI(raw); err == nil {
				t.Fatalf("ParseURI succeeded for %s", name)
			}
		})
	}

	p, err := ParseURI(prefix + "&cpool=%20mc.yandex.ru:443%20")
	if err != nil {
		t.Fatalf("single-entry trim whitespace rejected: %v", err)
	}
	if got := strings.Join(p.CoverTrafficTargets, ","); got != "mc.yandex.ru:443" {
		t.Fatalf("trimmed cpool = %q", got)
	}
}

// TestURIImportPreservesPoolConfig is the H-RR-1 regression guard: the
// pool-config knobs (`pool_variant`, `min_transports`, `max_transports`,
// `rotation_overlap`, `bytes_per_transport`) carried in the URI's query
// must round-trip through ParseURI into Profile and out to the resulting
// TamizdatOutbound's tamizdat.ClientConfig — pre-fix the URI-import branch
// of NewTamizdatOutbound silently dropped them.
func TestURIImportPreservesPoolConfig(t *testing.T) {
	raw := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex +
		"&sni=ok.ru" +
		"&pool_variant=v2" +
		"&min_transports=1" +
		"&max_transports=2" +
		"&rotation_overlap=1" +
		"&bytes_per_transport=13312"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if p.PoolVariant != "v2" {
		t.Errorf("PoolVariant = %q, want v2", p.PoolVariant)
	}
	if p.MinTransports != 1 {
		t.Errorf("MinTransports = %d, want 1", p.MinTransports)
	}
	if p.MaxTransports != 2 {
		t.Errorf("MaxTransports = %d, want 2", p.MaxTransports)
	}
	if p.RotationOverlapAllowance != 1 {
		t.Errorf("RotationOverlapAllowance = %d, want 1", p.RotationOverlapAllowance)
	}
	if p.BytesPerTransportSoftCap != 13312 {
		t.Errorf("BytesPerTransportSoftCap = %d, want 13312", p.BytesPerTransportSoftCap)
	}
}

func TestURIImportRejectsInvalidPoolFields(t *testing.T) {
	prefix := "tamizdat://d1b122782219759f@example.com:443?pbk=" + testPubKeyHex + "&sni=ok.ru"
	cases := map[string]string{
		"bad pool_variant":       prefix + "&pool_variant=v9",
		"negative min":           prefix + "&min_transports=-1",
		"non-numeric max":        prefix + "&max_transports=abc",
		"max below min":          prefix + "&min_transports=4&max_transports=2",
		"non-int bytes_per_xpt":  prefix + "&bytes_per_transport=oops",
		"negative bytes_per_xpt": prefix + "&bytes_per_transport=-5",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseURI(raw); err == nil {
				t.Fatalf("ParseURI accepted bad URI: %s", name)
			}
		})
	}
}
