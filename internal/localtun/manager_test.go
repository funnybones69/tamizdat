package localtun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPrepareEnabledConfigAcceptsFallbackOnly(t *testing.T) {
	cfg := Config{
		UserID: "local-1", UserName: "router-lan", Enabled: true,
		FallbackTag: "balancer", Interface: "br-lan", AutoRoute: true,
	}.normalized()
	if err := prepareEnabledConfig(&cfg); err != nil {
		t.Fatalf("fallback-only config rejected: %v", err)
	}
	if cfg.OutboundTag != "balancer" {
		t.Fatalf("effective tunnel outbound = %q, want fallback balancer", cfg.OutboundTag)
	}
}

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

	t.Run("three consecutive health failures", func(t *testing.T) {
		tick := make(chan time.Time, 3)
		for range 3 {
			tick <- time.Now()
		}
		want := errors.New("route disappeared")
		calls := 0
		err := waitRuntime(context.Background(), nil, nil, nil, nil, tick, func(context.Context) error {
			calls++
			return want
		})
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "invariant check") {
			t.Fatalf("waitRuntime health error = %v", err)
		}
		if calls != 3 {
			t.Fatalf("health checks = %d, want 3", calls)
		}
	})

	t.Run("successful health resets failure streak", func(t *testing.T) {
		tick := make(chan time.Time, 6)
		for range 6 {
			tick <- time.Now()
		}
		want := errors.New("transient health failure")
		calls := 0
		err := waitRuntime(context.Background(), nil, nil, nil, nil, tick, func(context.Context) error {
			calls++
			if calls == 3 {
				return nil
			}
			return want
		})
		if !errors.Is(err, want) {
			t.Fatalf("waitRuntime health reset error = %v", err)
		}
		if calls != 6 {
			t.Fatalf("health checks = %d, want 6 after streak reset", calls)
		}
	})

	t.Run("DNS death bypasses health debounce", func(t *testing.T) {
		tick := make(chan time.Time, 1)
		tick <- time.Now()
		done := make(chan error)
		wantDNS := errors.New("ChinaDNS died after transient health failure")
		healthCalls := 0
		err := waitRuntime(context.Background(), done, func() error { return wantDNS }, nil, nil, tick, func(context.Context) error {
			healthCalls++
			close(done)
			return errors.New("transient health failure")
		})
		if !errors.Is(err, wantDNS) || healthCalls != 1 {
			t.Fatalf("waitRuntime immediate DNS error = %v, health calls = %d", err, healthCalls)
		}
	})

	t.Run("session death bypasses health debounce", func(t *testing.T) {
		tick := make(chan time.Time, 1)
		tick <- time.Now()
		done := make(chan struct{})
		wantSession := errors.New("netstack died after transient health failure")
		healthCalls := 0
		err := waitRuntime(context.Background(), nil, nil, done, func() error { return wantSession }, tick, func(context.Context) error {
			healthCalls++
			close(done)
			return errors.New("transient health failure")
		})
		if !errors.Is(err, wantSession) || healthCalls != 1 {
			t.Fatalf("waitRuntime immediate session error = %v, health calls = %d", err, healthCalls)
		}
	})
}
