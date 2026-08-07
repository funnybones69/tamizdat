//go:build linux

package tunengine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleStack struct {
	once sync.Once
	done chan struct{}
}

func newLifecycleStack() *lifecycleStack {
	return &lifecycleStack{done: make(chan struct{})}
}

func (s *lifecycleStack) Close() { s.once.Do(func() { close(s.done) }) }
func (s *lifecycleStack) Wait()  { <-s.done }
func (s *lifecycleStack) Exit()  { s.Close() }

type stubbornLifecycleStack struct{ done chan struct{} }

func (s *stubbornLifecycleStack) Close() {}
func (s *stubbornLifecycleStack) Wait()  { <-s.done }

type lifecycleHandler struct{ closes atomic.Int32 }

func (h *lifecycleHandler) Close() { h.closes.Add(1) }

func newLifecycleSession(stack interface {
	Close()
	Wait()
}, handler interface{ Close() }) *Session {
	s := &Session{
		stack:    stack,
		handler:  handler,
		done:     make(chan struct{}),
		stopDone: make(chan struct{}),
	}
	go s.waitStack()
	return s
}

func TestSessionReportsUnexpectedStackExitAndStopsResources(t *testing.T) {
	stack := newLifecycleStack()
	handler := &lifecycleHandler{}
	session := newLifecycleSession(stack, handler)
	stack.Exit()
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not publish stack exit")
	}
	if err := session.Err(); err == nil || err.Error() != "tun2socks netstack stopped unexpectedly" {
		t.Fatalf("Session.Err() = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if got := handler.closes.Load(); got != 1 {
		t.Fatalf("handler close count = %d, want 1", got)
	}
}

func TestSessionStopIsIdempotentAndCanBeReawaitedAfterTimeout(t *testing.T) {
	stack := &stubbornLifecycleStack{done: make(chan struct{})}
	handler := &lifecycleHandler{}
	session := newLifecycleSession(stack, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Stop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Stop error = %v, want context.Canceled", err)
	}
	close(stack.done)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := session.Stop(ctx); err != nil {
		t.Fatalf("second Stop error = %v", err)
	}
	if err := session.Stop(ctx); err != nil {
		t.Fatalf("third Stop error = %v", err)
	}
	if got := handler.closes.Load(); got != 1 {
		t.Fatalf("handler close count = %d, want 1", got)
	}
	if err := session.Err(); err != nil {
		t.Fatalf("intentional stop Session.Err() = %v", err)
	}
}
