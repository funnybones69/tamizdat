//go:build windows

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Single-exe distribution: the wintun driver DLL and the TUN-engine
// child binary are embedded into the GUI executable and extracted to
// %LOCALAPPDATA%\Tamizdat\ on first start. Extracted-file digests are
// checked against the embedded ones — if the embedded blob changed
// across releases (e.g. UPX repack), the on-disk copy gets refreshed.
//
// Trade-off vs a refactor that runs TUN in-process: this keeps the
// two-binary architecture (TUN spawned with --uac elevation via
// runas), no code-path merge between GUI + TUN. Cost = ~5 MB compressed
// TUN binary embedded into the GUI.

//go:embed embed-tun.exe
var embeddedTunExe []byte

//go:embed embed-wintun.dll
var embeddedWintunDLL []byte

// extractEmbeddedAssets writes the bundled TUN exe + wintun.dll to a
// per-user directory and returns the path to the TUN exe. Idempotent:
// on subsequent runs the files are re-written only if their sha256
// digests no longer match the embedded ones (cheap to compute).
func extractEmbeddedAssets() (string, error) {
	dir, err := assetDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tunExePath := filepath.Join(dir, "tamizdat-tun-windows.exe")
	dllPath := filepath.Join(dir, "wintun.dll")
	if err := writeIfChanged(tunExePath, embeddedTunExe); err != nil {
		return "", fmt.Errorf("write tun exe: %w", err)
	}
	if err := writeIfChanged(dllPath, embeddedWintunDLL); err != nil {
		return "", fmt.Errorf("write wintun.dll: %w", err)
	}
	return tunExePath, nil
}

// assetDir resolves %LOCALAPPDATA%\Tamizdat (falls back to %TEMP%).
// We deliberately use LocalAppData rather than ProgramData: this dir
// is writable without admin, and the TUN child re-elevates separately
// via ShellExecute("runas") so the path being non-system-protected is
// fine.
func assetDir() (string, error) {
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "Tamizdat"), nil
}

// writeIfChanged updates a file in place only if its content sha256
// differs from the embedded one. Avoids rewriting megabytes on every
// start. Also lets the user replace the on-disk file manually for
// debugging — the next start with the same GUI version restores the
// original.
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
