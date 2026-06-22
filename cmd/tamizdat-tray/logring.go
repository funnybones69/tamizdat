//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type logFileWriter interface {
	WriteString(string) (int, error)
}

// logRing is a bounded in-memory log buffer. The log window pulls a full
// snapshot when it opens and gets per-line notifications afterwards via
// the channel returned by Subscribe.
type logRing struct {
	mu    sync.Mutex
	cap   int
	lines []string
	subs  []chan string
	file  logFileWriter
}

func newLogRing(capacity int) *logRing {
	if capacity <= 0 {
		capacity = 1000
	}
	return &logRing{cap: capacity, lines: make([]string, 0, capacity)}
}

func (r *logRing) SetFile(f logFileWriter) {
	r.mu.Lock()
	r.file = f
	r.mu.Unlock()
}

func (r *logRing) Log(format string, args ...any) {
	stamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := "[" + stamp + "] " + msg

	r.mu.Lock()
	if len(r.lines) >= r.cap {
		copy(r.lines, r.lines[1:])
		r.lines[len(r.lines)-1] = line
	} else {
		r.lines = append(r.lines, line)
	}
	if r.file != nil {
		_, _ = r.file.WriteString(line + "\r\n")
	}
	subs := make([]chan string, len(r.subs))
	copy(subs, r.subs)
	r.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- line:
		default:
		}
	}
}

func (r *logRing) Snapshot() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == 0 {
		return ""
	}
	return strings.Join(r.lines, "\r\n") + "\r\n"
}

func (r *logRing) Subscribe() chan string {
	ch := make(chan string, 256)
	r.mu.Lock()
	r.subs = append(r.subs, ch)
	r.mu.Unlock()
	return ch
}

func (r *logRing) Unsubscribe(ch chan string) {
	r.mu.Lock()
	for i, c := range r.subs {
		if c == ch {
			r.subs = append(r.subs[:i], r.subs[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	close(ch)
}
