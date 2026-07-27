package tamizdat

import (
	"context"
	"net"
	"path/filepath"
	"testing"
)

// TestNoServerConfigMasterShortIDRequiredWhenServerDBPathSet verifies the
// multi-user-cleanup operator policy: prod (ServerDBPath set) no longer
// requires the legacy global ServerConfig.MasterShortID field. NewServer
// should accept config.MasterShortID == zero when ServerDBPath != "".
func TestNoServerConfigMasterShortIDRequiredWhenServerDBPathSet(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	dbPath := filepath.Join(t.TempDir(), "users.db")

	cfg := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: priv,
		// MasterShortID intentionally left zero.
		CertPEM:                 certPEM,
		KeyPEM:                  keyPEM,
		MasqueradeDomain:        "",
		ServerDBPath:            dbPath,
		DisableOutboundRegistry: true,
		LegacyShortIDPath:       filepath.Join(t.TempDir(), "no-such-shortid.hex"),
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
		},
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer with ServerDBPath + zero MasterShortID failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("NewServer returned nil server")
	}
	defer srv.Close()
}

// TestServerConfigMasterShortIDRequiredWhenNoServerDBPath verifies the
// embedded-caller path still rejects a zero MasterShortID. Without a userdb,
// authentication has no source of truth for shortid → identity, so the
// configured master is the only key.
func TestServerConfigMasterShortIDRequiredWhenNoServerDBPath(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	cfg := ServerConfig{
		ListenAddr:              "127.0.0.1:0",
		PrivateKey:              priv,
		CertPEM:                 certPEM,
		KeyPEM:                  keyPEM,
		DisableOutboundRegistry: true,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
		},
	}
	if _, err := NewServer(cfg); err == nil {
		t.Fatalf("NewServer with no ServerDBPath + zero MasterShortID should error")
	}
}
