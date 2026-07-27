package tamizdat

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewServerReplayWindowDefaultIsFiveMinutes(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	s, err := NewServer(ServerConfig{
		PrivateKey:    priv,
		MasterShortID: shortID,
		Handler: func(context.Context, net.Conn, string) {
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.replayGuard == nil {
		t.Fatal("replayGuard is nil")
	}
	if s.replayGuard.window != 5*time.Minute {
		t.Fatalf("replay window = %s, want 5m", s.replayGuard.window)
	}
}

func TestClientDefaultFingerprintModeIsMix(t *testing.T) {
	cfg := ClientConfig{DisableDefaultSecurity: true}
	cfg.applyDefaults()
	if cfg.Fingerprint != "mix" {
		t.Fatalf("Fingerprint = %q, want mix", cfg.Fingerprint)
	}
}

func TestClientPoolVariantV2Defaults(t *testing.T) {
	cfg := ClientConfig{PoolVariant: "v2"}
	cfg.applyDefaults()
	if cfg.MinTransports != 1 || cfg.MaxTransports != 2 {
		t.Fatalf("v2 Min/MaxTransports = %d/%d, want 1/2", cfg.MinTransports, cfg.MaxTransports)
	}
}

// TestClientBundleDisabledOverridesDefault is the SPP-FU-6 regression
// guard: setting BundleDisabled=true must produce BundleEnabled=false
// after applyDefaults, replacing the legacy two-flag dance
// (BundleEnabled=false + BundleEnabledSet=true). Catches a regression
// where applyDefaults silently overwrites an explicit opt-out.
func TestClientBundleDisabledOverridesDefault(t *testing.T) {
	cfg := ClientConfig{BundleDisabled: true, DisableDefaultSecurity: true}
	cfg.applyDefaults()
	if cfg.BundleEnabled {
		t.Fatalf("BundleDisabled=true did not propagate; BundleEnabled = true")
	}
}

func TestClientBundleDefaultEnabled(t *testing.T) {
	cfg := ClientConfig{DisableDefaultSecurity: true}
	cfg.applyDefaults()
	if !cfg.BundleEnabled {
		t.Fatalf("BundleEnabled default = false, want true (zero-value caller wants opt-in)")
	}
}

func TestServerBundleDisabledOverridesDefault(t *testing.T) {
	cfg := ServerConfig{BundleDisabled: true}
	cfg.applyDefaults()
	if cfg.BundleEnabled {
		t.Fatalf("ServerConfig.BundleDisabled=true did not propagate; BundleEnabled = true")
	}
}

func TestServerBundleLegacyEnabledSetStillHonoured(t *testing.T) {
	// Backward compat: a legacy caller that sets BundleEnabled=false +
	// BundleEnabledSet=true must keep working until they migrate to
	// BundleDisabled=true.
	cfg := ServerConfig{BundleEnabled: false, BundleEnabledSet: true}
	cfg.applyDefaults()
	if cfg.BundleEnabled {
		t.Fatalf("legacy two-flag opt-out broken: BundleEnabled=true after applyDefaults")
	}
}

func TestClientPoolVariantV1Defaults(t *testing.T) {
	cfg := ClientConfig{PoolVariant: "v1"}
	cfg.applyDefaults()
	if cfg.MinTransports != 1 || cfg.MaxTransports != 1 {
		t.Fatalf("v1 Min/MaxTransports = %d/%d, want 1/1", cfg.MinTransports, cfg.MaxTransports)
	}
	if cfg.RotationOverlapAllowance != 1 {
		t.Fatalf("v1 RotationOverlapAllowance = %d, want 1", cfg.RotationOverlapAllowance)
	}
	if cfg.BytesPerTransportSoftCap != 0 {
		t.Fatalf("v1 BytesPerTransportSoftCap = %d, want 0 default", cfg.BytesPerTransportSoftCap)
	}
}
