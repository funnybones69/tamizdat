package main

import (
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/svcipc"
)

type logHub struct {
	mu   sync.Mutex
	next uint64
	ring []svcipc.LogLine
	subs map[chan svcipc.LogLine]struct{}
}

func newLogHub() *logHub { return &logHub{subs: map[chan svcipc.LogLine]struct{}{}} }

func (h *logHub) Write(p []byte) (int, error) {
	for _, b := range bytes.Split(p, []byte{'\n'}) {
		if s := strings.TrimSpace(string(b)); s != "" {
			h.Add("info", "svc", s)
		}
	}
	return len(p), nil
}

func (h *logHub) Add(level, source, msg string) svcipc.LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	l := svcipc.LogLine{ID: h.next, Time: time.Now(), Level: level, Source: source, Msg: msg}
	h.ring = append(h.ring, l)
	if len(h.ring) > 1000 {
		h.ring = h.ring[len(h.ring)-1000:]
	}
	for ch := range h.subs {
		select {
		case ch <- l:
		default:
		}
	}
	return l
}

func (h *logHub) Subscribe(from uint64, emit func([]svcipc.LogLine)) func() {
	ch := make(chan svcipc.LogLine, 256)
	h.mu.Lock()
	var tail []svcipc.LogLine
	for _, l := range h.ring {
		if l.ID >= from {
			tail = append(tail, l)
		}
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	if len(tail) > 0 {
		emit(tail)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		var b []svcipc.LogLine
		flush := func() {
			if len(b) > 0 {
				emit(b)
				b = nil
			}
		}
		for {
			select {
			case l, ok := <-ch:
				if !ok {
					flush()
					return
				}
				b = append(b, l)
			case <-t.C:
				flush()
			}
		}
	}()
	return func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
		<-done
	}
}
