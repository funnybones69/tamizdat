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
	if len(cfg.Profiles) != 1 {
		t.Fatalf("Profiles = %d, want 1", len(cfg.Profiles))
	}
}

func TestLoadConfigMultipleURIs(t *testing.T) {
	uri1 := "tamizdat://sync.example.com:443/?sni=ya.ru&pubkey=0000000000000000000000000000000000000000000000000000000000000001&shortid=0000000000000001&fp=mix#PC"
	uri2 := "tamizdat://203.0.113.10:8443/?sni=vk.com&pubkey=0000000000000000000000000000000000000000000000000000000000000002&shortid=0000000000000002&fp=chrome#RU2"
	path := filepath.Join(t.TempDir(), configFileName)
	body := "# primary first\n" + uri1 + "\n\n" + uri2 + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.buildURI() != uri1 {
		t.Fatalf("active URI = %q, want first URI", cfg.buildURI())
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("Profiles = %d, want 2", len(cfg.Profiles))
	}
	if got := cfg.Profiles[0].Label; got != "sync.example.com:443" {
		t.Fatalf("profile[0].Label = %q", got)
	}
	if got := cfg.Profiles[1].Label; got != "203.0.113.10:8443" {
		t.Fatalf("profile[1].Label = %q", got)
	}
	if got := cfg.Profiles[1].Config.buildURI(); got != uri2 {
		t.Fatalf("profile[1] URI = %q, want %q", got, uri2)
	}
}

func TestLoadConfigRestoresLastServer(t *testing.T) {
	uri1 := "tamizdat://sync.example.com:443/?sni=ya.ru&pubkey=0000000000000000000000000000000000000000000000000000000000000001&shortid=0000000000000001&fp=mix#PC"
	uri2 := "tamizdat://203.0.113.10:8443/?sni=vk.com&pubkey=0000000000000000000000000000000000000000000000000000000000000002&shortid=0000000000000002&fp=chrome#RU2"
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, []byte(uri1+"\n"+uri2+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte("active_uri_sha256="+profileStateKey(&Config{URI: uri2})+"\n"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.buildURI(); got != uri2 {
		t.Fatalf("active URI = %q, want restored URI %q", got, uri2)
	}
	if cfg.ProfileIndex != 1 {
		t.Fatalf("ProfileIndex = %d, want 1", cfg.ProfileIndex)
	}
}
