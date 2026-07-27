package tamizdat

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotatingWriterRotatesAndRetains drives enough writes through a small
// rotatingWriter to trigger many rotations, then checks the size budget holds,
// exactly maxBackups backups survive, the oldest data was pruned, and the
// newest data is in the active file.
func TestRotatingWriterRotatesAndRetains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shape-events.log")

	const (
		maxBytes   = 1000
		maxBackups = 3
		lineLen    = 100
		lines      = 200 // 20000 bytes total, far past (maxBackups+1)*maxBytes
	)
	w, err := openRotatingWriter(path, maxBytes, maxBackups)
	if err != nil {
		t.Fatalf("openRotatingWriter: %v", err)
	}
	for i := 0; i < lines; i++ {
		// Each line is exactly lineLen bytes and carries a unique marker.
		marker := fmt.Sprintf("event-%05d-", i)
		line := marker + strings.Repeat("x", lineLen-len(marker)-1) + "\n"
		if len(line) != lineLen {
			t.Fatalf("test bug: line %d is %d bytes, want %d", i, len(line), lineLen)
		}
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The active file must exist and stay within budget. One line of overshoot
	// is allowed: rotation happens before a write that would exceed maxBytes,
	// never mid-line.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat active file: %v", err)
	}
	if st.Size() > maxBytes+lineLen {
		t.Errorf("active file is %d bytes, want <= %d", st.Size(), maxBytes+lineLen)
	}

	// Exactly maxBackups timestamped backups must remain.
	backups, err := filepath.Glob(filepath.Join(dir, "shape-events-*.log"))
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != maxBackups {
		t.Fatalf("got %d backups, want %d: %v", len(backups), maxBackups, backups)
	}
	for _, b := range backups {
		bst, err := os.Stat(b)
		if err != nil {
			t.Fatalf("stat backup %s: %v", b, err)
		}
		if bst.Size() > maxBytes+lineLen {
			t.Errorf("backup %s is %d bytes, want <= %d", b, bst.Size(), maxBytes+lineLen)
		}
	}

	// Retention dropped the oldest data: line 0 is gone from every file, while
	// the final line survives in the active file.
	everything := append([]string{path}, backups...)
	if logsContain(t, everything, "event-00000-") {
		t.Error("line 0 should have been pruned but is still on disk")
	}
	lastMarker := fmt.Sprintf("event-%05d-", lines-1)
	if !logsContain(t, []string{path}, lastMarker) {
		t.Errorf("most recent line %q missing from the active file", lastMarker)
	}
}

// TestRotatingWriterFirstWriteNeverRotates verifies the empty-file guard: the
// very first write is never preceded by a rotation, even when it is on its own
// larger than maxBytes, so a fresh log never starts with an empty backup.
func TestRotatingWriterFirstWriteNeverRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ev.log")
	w, err := openRotatingWriter(path, 10, 2)
	if err != nil {
		t.Fatalf("openRotatingWriter: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte(strings.Repeat("a", 500) + "\n")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if got, _ := filepath.Glob(filepath.Join(dir, "ev-*.log")); len(got) != 0 {
		t.Fatalf("first (oversized) write must not rotate, got backups: %v", got)
	}
	// The next write sees a non-empty over-budget file and rotates exactly once.
	if _, err := w.Write([]byte("b\n")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got, _ := filepath.Glob(filepath.Join(dir, "ev-*.log")); len(got) != 1 {
		t.Fatalf("second write should have rotated once, got %d backups", len(got))
	}
}

// TestRotatingWriterAdoptsExistingSize verifies a restart does not reset the
// size budget: an already-present file's length counts toward the next
// rotation rather than starting from zero.
func TestRotatingWriterAdoptsExistingSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ev.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 90)), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	w, err := openRotatingWriter(path, 100, 2)
	if err != nil {
		t.Fatalf("openRotatingWriter: %v", err)
	}
	defer w.Close()

	// 90 adopted bytes plus a 20-byte write crosses 100 and rotates.
	if _, err := w.Write([]byte(strings.Repeat("b", 20))); err != nil {
		t.Fatalf("write: %v", err)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "ev-*.log"))
	if len(backups) != 1 {
		t.Fatalf("write crossing the budget over an adopted file should rotate, got %d backups", len(backups))
	}
	if bst, err := os.Stat(backups[0]); err != nil {
		t.Fatalf("stat backup: %v", err)
	} else if bst.Size() != 90 {
		t.Errorf("rotated backup is %d bytes, want 90 (the adopted prefix)", bst.Size())
	}
}

// logsContain reports whether substr appears in any of the given files.
func logsContain(t *testing.T, paths []string, substr string) bool {
	t.Helper()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if strings.Contains(string(data), substr) {
			return true
		}
	}
	return false
}
