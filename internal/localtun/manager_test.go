package localtun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWaitRuntimeSupervisesEverySignal(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitRuntime(ctx, nil, nil, nil, nil, nil, nil); err != nil {
			t.Fatalf("waitRuntime context error = %v", err)
		}
	})

	t.Run("dns", func(t *testing.T) {
		done := make(chan error)
		close(done)
		want := errors.New("chinadns crashed")
		err := waitRuntime(context.Background(), done, func() error { return want }, nil, nil, nil, nil)
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "ChinaDNS exited") {
			t.Fatalf("waitRuntime DNS error = %v", err)
		}
	})

	t.Run("session", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		want := errors.New("netstack crashed")
		err := waitRuntime(context.Background(), nil, nil, done, func() error { return want }, nil, nil)
		if !errors.Is(err, want) {
			t.Fatalf("waitRuntime session error = %v", err)
		}
	})

	t.Run("unexpected clean session exit", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		err := waitRuntime(context.Background(), nil, nil, done, func() error { return nil }, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "TUN session exited unexpectedly") {
			t.Fatalf("waitRuntime clean session error = %v", err)
		}
	})

	t.Run("health", func(t *testing.T) {
		tick := make(chan time.Time, 1)
		tick <- time.Now()
		want := errors.New("route disappeared")
		err := waitRuntime(context.Background(), nil, nil, nil, nil, tick, func(context.Context) error { return want })
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "invariant check") {
			t.Fatalf("waitRuntime health error = %v", err)
		}
	})
}
