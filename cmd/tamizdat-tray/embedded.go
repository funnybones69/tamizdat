//go:build windows

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Single-EXE distribution. The TUN engine binary and wintun.dll are
// embedded into the tray executable and extracted at first start to
// %LOCALAPPDATA%\Tamizdat-Tray\. SHA-256 of the on-disk copies is
// compared to the embedded blob — if they diverge (different release),
// the on-disk copies get refreshed.

//go:embed embed-tun.exe
var embeddedTunExe []byte

//go:embed embed-wintun.dll
var embeddedWintunDLL []byte

//go:embed icon-red.ico
var embeddedIconRed []byte

//go:embed icon-orange.ico
var embeddedIconOrange []byte

//go:embed icon-green.ico
var embeddedIconGreen []byte

func extractEmbeddedAssets() (tunExe, dir string, err error) {
	dir, err = assetDir()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tunExe = filepath.Join(dir, "tamizdat-tun-windows.exe")
	dllPath := filepath.Join(dir, "wintun.dll")
	if err := writeIfChanged(tunExe, embeddedTunExe); err != nil {
		return "", "", fmt.Errorf("write tun exe: %w", err)
	}
	if err := writeIfChanged(dllPath, embeddedWintunDLL); err != nil {
		return "", "", fmt.Errorf("write wintun.dll: %w", err)
	}
	return tunExe, dir, nil
}

func assetDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("TAMIZDAT_TRAY_ASSET_DIR")); override != "" {
		return override, nil
	}
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	if exe, err := os.Executable(); err == nil {
		name := strings.ToLower(filepath.Base(exe))
		if strings.Contains(name, "fragpoc") || strings.Contains(name, "test") {
			return filepath.Join(base, "Tamizdat-FragPoC-Test"), nil
		}
	}
	return filepath.Join(base, "Tamizdat-Tray"), nil
}

func writeIfChanged(path string, content []byte) error {
	want := sha256.Sum256(content)
	if existing, err := os.ReadFile(path); err == nil {
		have := sha256.Sum256(existing)
		if hex.EncodeToString(have[:]) == hex.EncodeToString(want[:]) {
			return nil
		}
	}
	return os.WriteFile(path, content, 0o755)
}
