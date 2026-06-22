package configurl

import "testing"

const testURL = "tamizdat://server.example.com:8443/?sni=cover.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&fp=chrome"

func TestParse(t *testing.T) {
	cfg, err := Parse(testURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ServerAddr != "server.example.com:8443" {
		t.Fatalf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.ServerName != "cover.example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.PublicKey) != 32 {
		t.Fatalf("PublicKey len = %d", len(cfg.PublicKey))
	}
	if cfg.MasterShortID != [8]byte{0xd1, 0xb1, 0x22, 0x78, 0x22, 0x19, 0x75, 0x9f} {
		t.Fatalf("MasterShortID = %x", cfg.MasterShortID)
	}
	if cfg.Fingerprint != "chrome" {
		t.Fatalf("Fingerprint = %q", cfg.Fingerprint)
	}
}

func TestParseDefaultsFingerprint(t *testing.T) {
	cfg, err := Parse("tamizdat://example.com:443/?sni=cover.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Fingerprint != "mix" {
		t.Fatalf("Fingerprint = %q", cfg.Fingerprint)
	}
}

func TestParseRejectsMissingPort(t *testing.T) {
	if _, err := Parse("tamizdat://example.com/?sni=cover.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f"); err == nil {
		t.Fatal("Parse succeeded without host:port")
	}
}

func TestParseCleanURICopiesHostToBootstrap(t *testing.T) {
	// Server-pushes-pool (2026-05-09): URI without sni= must parse OK and
	// carry BootstrapSNI = host so the very first transport has a name.
	cfg, err := Parse("tamizdat://example.com:443/?pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.BootstrapSNI != "example.com" {
		t.Fatalf("BootstrapSNI = %q, want %q", cfg.BootstrapSNI, "example.com")
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName = %q, want fallback to host", cfg.ServerName)
	}
	if cfg.Fingerprint != "mix" {
		t.Fatalf("Fingerprint default mismatch: %q", cfg.Fingerprint)
	}
}

func TestParseExplicitBootstrap(t *testing.T) {
	cfg, err := Parse("tamizdat://203.0.113.10:443/?bootstrap=bootstrap.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.BootstrapSNI != "bootstrap.example.com" {
		t.Fatalf("BootstrapSNI = %q, want bootstrap.example.com", cfg.BootstrapSNI)
	}
	if cfg.ServerName != "bootstrap.example.com" {
		t.Fatalf("ServerName fallback wrong: %q", cfg.ServerName)
	}
}

func TestParseBareIPWithoutBootstrap(t *testing.T) {
	cfg, err := Parse("tamizdat://203.0.113.10:443/?pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.BootstrapSNI != "203.0.113.10" {
		t.Fatalf("BootstrapSNI = %q, want IP literal", cfg.BootstrapSNI)
	}
	if cfg.ServerName != "203.0.113.10" {
		t.Fatalf("ServerName = %q, want IP fallback", cfg.ServerName)
	}
}

func TestParseLegacyURIBackwardCompat(t *testing.T) {
	// Old URI with sni= and fp= must continue to parse and produce the
	// same Config it always did. The only addition is BootstrapSNI = host
	// (used only when no bundle is cached).
	cfg, err := Parse(testURL)
	if err != nil {
		t.Fatalf("Parse legacy URI: %v", err)
	}
	if cfg.ServerName != "cover.example.com" || cfg.Fingerprint != "chrome" {
		t.Fatalf("legacy fields lost: name=%q fp=%q", cfg.ServerName, cfg.Fingerprint)
	}
	if cfg.BootstrapSNI != "server.example.com" {
		t.Fatalf("legacy URI bootstrap fallback = %q, want host", cfg.BootstrapSNI)
	}
}

func TestParseExplicitBootstrapOverridesHost(t *testing.T) {
	// Mixed URI: legacy sni= still present plus new bootstrap= override.
	cfg, err := Parse("tamizdat://example.com:443/?sni=cover.example.com&bootstrap=bootstrap.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.BootstrapSNI != "bootstrap.example.com" {
		t.Fatalf("BootstrapSNI = %q, want explicit bootstrap.example.com", cfg.BootstrapSNI)
	}
	if cfg.ServerName != "cover.example.com" {
		t.Fatalf("ServerName = %q, want sni= cover.example.com", cfg.ServerName)
	}
}

func TestParseTransportBounds(t *testing.T) {
	cfg, err := Parse("tamizdat://example.com:443/?sni=cover.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&min_transports=4&max_transports=4#PC")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.MinTransports != 4 || cfg.MaxTransports != 4 {
		t.Fatalf("transport bounds = %d/%d, want 4/4", cfg.MinTransports, cfg.MaxTransports)
	}
}

func TestParseRejectsInvalidTransportBounds(t *testing.T) {
	if _, err := Parse("tamizdat://example.com:443/?sni=cover.example.com&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&min_transports=4&max_transports=2"); err == nil {
		t.Fatal("Parse succeeded with max_transports below min_transports")
	}
}
