package tamizdat

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default rotation policy for the shape-event log, applied by
// ServerConfig.applyDefaults when the operator turns ShapeEventLogPath on
// without tuning rotation. Worst-case on-disk footprint is bounded by
// (defaultShapeEventLogMaxBackups + 1) * defaultShapeEventLogMaxBytes ≈ 10 MiB
// — chosen to stay comfortably inside a small RAM-backed /tmp on a router.
const (
	defaultShapeEventLogMaxBytes   = 2 << 20 // 2 MiB
	defaultShapeEventLogMaxBackups = 4
)

// backupTimeFormat stamps rotated files. It is intentionally lexically
// sortable — chronological order equals sort.Strings order — and free of ':'
// so the names are valid on every filesystem. Millisecond precision keeps two
// rotations apart even under a burst.
const backupTimeFormat = "2006-01-02T15-04-05.000"

// rotatingWriter is an append-only log file that rotates on size: once a write
// would push the active file past maxBytes, the file is closed, moved aside
// under a timestamped name, the oldest backups beyond maxBackups are deleted,
// and a fresh active file is opened.
//
// This is the in-application equivalent of an external logrotate/cron job: the
// process owns its log lifecycle, so there is no window in which an unmanaged
// file fills the disk. That window is exactly what bit us — the shape-event
// log grew to 206 MiB and exhausted the router's tmpfs, which silently broke
// DNS (netifd could no longer write resolv.conf).
//
// The shape mirrors cmd/tamizdat-svc's dailyLogWriter (mutex-guarded
// Write/Close/rotate, glob+sort backup retention) but the trigger is size
// rather than calendar day: the shape-event log grows at a steady byte rate,
// and a day-granular scheme cannot bound disk use between rotations.
//
// All methods are safe for concurrent use.
type rotatingWriter struct {
	mu         sync.Mutex
	path       string // active file path
	maxBytes   int64  // rotate before exceeding this; <= 0 disables rotation
	maxBackups int    // timestamped backups to retain
	file       *os.File
	size       int64 // bytes currently in the active file
}

// openRotatingWriter opens path for appending, creating it if necessary, and
// returns a rotatingWriter. An existing file is adopted in place: its current
// length counts toward the next rotation, so a process restart does not reset
// the size budget. maxBytes <= 0 disables rotation (the file grows unbounded).
func openRotatingWriter(path string, maxBytes int64, maxBackups int) (*rotatingWriter, error) {
	if maxBackups < 0 {
		maxBackups = 0
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	w := &rotatingWriter{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
		file:       f,
	}
	if st, serr := f.Stat(); serr == nil {
		w.size = st.Size()
	}
	return w, nil
}

// Write appends p to the active file, rotating beforehand if the write would
// push a non-empty file past maxBytes. A single write larger than maxBytes is
// still written in full — it just lands in a freshly rotated file — so a log
// line is never split or dropped.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.maxBytes > 0 && w.size > 0 && w.file != nil && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			// Best-effort: a failed rotation must not drop the event. rotate()
			// leaves a usable file open whenever it can; an oversized log beats
			// silent data loss. Surface the failure so an operator sees it.
			log.Printf("tamizdat: shape-event log rotation failed: %v", err)
		}
	}
	if w.file == nil {
		return 0, os.ErrClosed
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// WriteString is the string-input convenience wrapper around Write.
func (w *rotatingWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// Close closes the active file. The writer must not be used afterwards.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// rotate moves the active file aside under a timestamped name, prunes old
// backups, and opens a fresh active file. The caller must hold w.mu.
//
// On success w.file is the new empty file and w.size is 0. If the rename
// fails, the original file is reopened so logging survives. Only a reopen
// failure on an otherwise-writable directory leaves w.file nil — Write guards
// against that and returns os.ErrClosed rather than panicking.
func (w *rotatingWriter) rotate() error {
	_ = w.file.Close()
	w.file = nil

	backup := w.backupPath(time.Now())
	if err := os.Rename(w.path, backup); err != nil {
		// Could not move the file aside — reopen the original and keep going.
		f, oerr := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if oerr != nil {
			return fmt.Errorf("rotate %q: rename failed (%v) and reopen failed: %w", w.path, err, oerr)
		}
		w.file = f
		if st, serr := f.Stat(); serr == nil {
			w.size = st.Size()
		}
		return fmt.Errorf("rotate %q: rename to %q: %w", w.path, backup, err)
	}

	w.pruneBackups()

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("rotate %q: reopen after rename: %w", w.path, err)
	}
	w.file = f
	w.size = 0
	return nil
}

// backupPath is the timestamped name an about-to-rotate file is renamed to:
// "<stem>-<timestamp><ext>" next to the active file. A nanosecond suffix is
// appended only on the (practically impossible) chance the millisecond-stamped
// name is already taken, so a rotation never overwrites an existing backup.
func (w *rotatingWriter) backupPath(t time.Time) string {
	dir, stem, ext := splitLogName(w.path)
	cand := filepath.Join(dir, stem+"-"+t.Format(backupTimeFormat)+ext)
	if _, err := os.Stat(cand); err == nil {
		cand = filepath.Join(dir, fmt.Sprintf("%s-%s-%09d%s", stem, t.Format(backupTimeFormat), t.Nanosecond(), ext))
	}
	return cand
}

// pruneBackups deletes the oldest timestamped backups so at most maxBackups
// remain. Backups are found with the "<stem>-*<ext>" glob and sorted by name;
// because backupTimeFormat is lexically sortable, name order is age order. The
// active file ("<stem><ext>", no '-' before the extension) does not match the
// glob and is therefore never a prune candidate.
func (w *rotatingWriter) pruneBackups() {
	dir, stem, ext := splitLogName(w.path)
	matches, err := filepath.Glob(filepath.Join(dir, stem+"-*"+ext))
	if err != nil {
		return
	}
	sort.Strings(matches)
	for len(matches) > w.maxBackups {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
}

// splitLogName breaks a log path into its directory, extension-less stem, and
// extension, so backup names can be built as "<stem>-<stamp><ext>".
func splitLogName(path string) (dir, stem, ext string) {
	dir = filepath.Dir(path)
	base := filepath.Base(path)
	ext = filepath.Ext(base)
	stem = strings.TrimSuffix(base, ext)
	return dir, stem, ext
}
