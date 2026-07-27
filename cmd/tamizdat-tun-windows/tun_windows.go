//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func requireWintunDLL() error {
	candidates := []string{"wintun.dll"}
	if exe, err := os.Executable(); err == nil {
		candidates = append([]string{filepath.Join(filepath.Dir(exe), "wintun.dll")}, candidates...)
	}
	for _, candidate := range candidates {
		st, err := os.Stat(candidate)
		if err == nil && !st.IsDir() {
			return nil
		}
	}
	return fmt.Errorf("wintun.dll not found next to executable or in working directory; copy the amd64 Wintun DLL beside samizdat-tun-windows.exe")
}
