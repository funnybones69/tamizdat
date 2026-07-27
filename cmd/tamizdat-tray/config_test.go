//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigURI(t *testing.T) {
	rawURI := "tamizdat://sync.example.com:443/?sni=ya.ru&pubkey=0000000000000000000000000000000000000000000000000000000000000001&shortid=0000000000000001&fp=mix&min_transports=4&max_transports=4#PC"
	path := filepath.Join(t.TempDir(), configFileName)
	if err := os.WriteFile(path, []byte(rawURI+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.buildURI(); got != rawURI {
		t.Fatalf("buildURI = %q, want raw URI %q", got, rawURI)
	}
	if cfg.Server != "sync.example.com:443" {
		t.Fatalf("Server = %q", cfg.Server)
	}
	if cfg.MinTransports != 4 || cfg.MaxTransports != 4 {
		t.Fatalf("transport bounds = %d/%d, want 4/4", cfg.MinTransports, cfg.MaxTransports)
	}
}
