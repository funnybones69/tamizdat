//go:build windows

package main

import (
	"fmt"
	"os"
)

const (
	trayLogMaxBytes   int64 = 5 * 1024 * 1024
	trayLogMaxBackups       = 0
)

type rotatingLogWriter struct {
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

func openRotatingLogWriter(path string, maxBytes int64, maxBackups int) (*rotatingLogWriter, error) {
	if maxBytes <= 0 {
		maxBytes = trayLogMaxBytes
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	w := &rotatingLogWriter{path: path, maxBytes: maxBytes, maxBackups: maxBackups}
	if err := w.openAppend(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingLogWriter) WriteString(s string) (int, error) {
	if w.file == nil {
		if err := w.openAppend(); err != nil {
			return 0, err
		}
	}
	if w.size+int64(len(s)) > w.maxBytes && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.WriteString(s)
	w.size += int64(n)
	return n, err
}

func (w *rotatingLogWriter) Close() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingLogWriter) openAppend() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file = f
	w.size = st.Size()
	if w.size > w.maxBytes {
		return w.rotate()
	}
	return nil
}

func (w *rotatingLogWriter) rotate() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if w.maxBackups > 0 {
		_ = os.Remove(w.backupPath(w.maxBackups))
		for i := w.maxBackups - 1; i >= 1; i-- {
			_ = os.Rename(w.backupPath(i), w.backupPath(i+1))
		}
		_ = os.Rename(w.path, w.backupPath(1))
	} else {
		_ = os.Remove(w.path)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *rotatingLogWriter) backupPath(n int) string {
	return fmt.Sprintf("%s.%d", w.path, n)
}
