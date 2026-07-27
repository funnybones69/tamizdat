package svcipc

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed assets/wintun.dll
var wintunDLLBytes []byte
var _ embed.FS

const WintunSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

func EmbeddedWintunSHA256() string {
	sum := sha256.Sum256(wintunDLLBytes)
	return hex.EncodeToString(sum[:])
}

// ExtractWintun extracts the pinned Wintun 0.14.1 amd64 DLL next to the
// running executable. The wintun-go loader searches only the application
// directory and System32, so %ProgramData% is intentionally not used here.
func ExtractWintun() (string, error) {
	if EmbeddedWintunSHA256() != WintunSHA256 {
		return "", fmt.Errorf("embedded wintun.dll sha256 mismatch: got %s want %s", EmbeddedWintunSHA256(), WintunSHA256)
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "."
	}
	target := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if b, err := os.ReadFile(target); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) == WintunSHA256 {
			return target, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(target, wintunDLLBytes, 0644); err != nil {
		return "", err
	}
	return target, nil
}
