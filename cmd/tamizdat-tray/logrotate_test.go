//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingLogWriterKeepsSingleFileWhenBackupsDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tamizdat-tray.log")

	w, err := openRotatingLogWriter(path, 32, 0)
	if err != nil {
		t.Fatalf("openRotatingLogWriter: %v", err)
	}
	if _, err := w.WriteString(strings.Repeat("a", 24)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := w.WriteString(strings.Repeat("b", 24)); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("backup log exists or unexpected stat error: %v", err)
	}
}
