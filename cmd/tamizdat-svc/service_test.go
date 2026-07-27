package main

import (
	"context"
	"errors"
	"expvar"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/svcipc"
)

type fakeTunnelEngine struct {
	mu             sync.Mutex
	connects       int
	closeCalls     int
	connectStarted chan struct{}
	connectRelease chan struct{}
	connectSession tunnelSession
	closeErr       error
	startedOnce    sync.Once
}

type fakeTunnelSession struct {
	stopped  bool
	stopErr  error
	stopWait <-chan struct{}
	stats    svcipc.StatsResponse
}

func (e *fakeTunnelEngine) Connect(ctx context.Context, req svcipc.ConnectRequest) (tunnelSession, svcipc.ConnectResponse, error) {
	e.mu.Lock()
	e.connects++
	started := e.connectStarted
	release := e.connectRelease
	sess := e.connectSession
	e.mu.Unlock()
	if started != nil {
		e.startedOnce.Do(func() { close(started) })
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, svcipc.ConnectResponse{}, ctx.Err()
		}
	}
	if sess == nil {
		sess = &fakeTunnelSession{stats: svcipc.StatsResponse{TCPOpenTotal: 7}}
	}
	return sess, svcipc.ConnectResponse{ConnectionID: "test", ServerAddr: "unit:443", LocalTunIP: "10.255.0.2"}, nil
}
func (e *fakeTunnelEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeCalls++
	return e.closeErr
}
func (s *fakeTunnelSession) Stop(ctx context.Context) error {
	if s.stopWait != nil {
		select {
		case <-s.stopWait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.stopped = true
	return s.stopErr
}
func (s *fakeTunnelSession) Status() tunnelStatus {
	return tunnelStatus{ServerAddr: "unit:443"}
}
func (s *fakeTunnelSession) Stats() svcipc.StatsResponse { return s.stats }

func TestServiceStateMachineConnectDisconnect(t *testing.T) {
	engine := &fakeTunnelEngine{}
	rt := newServiceRuntime(engine)
	if got := rt.snapshot().State; got != svcipc.StateDisconnected {
		t.Fatalf("initial state=%s", got)
	}
	resp, err := rt.Connect(context.Background(), svcipc.ConnectRequest{ConfigURI: "tamizdat://unit"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if resp.ConnectionID == "" || rt.snapshot().State != svcipc.StateConnected {
		t.Fatalf("not connected: resp=%+v status=%+v", resp, rt.snapshot())
	}
	stats := rt.Stats()
	if stats.TCPOpenTotal != 7 {
		t.Fatalf("stats not delegated: %+v", stats)
	}
	if err := rt.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if got := rt.snapshot().State; got != svcipc.StateDisconnected {
		t.Fatalf("final state=%s", got)
	}
	if engine.closeCalls == 0 {
		t.Fatalf("Disconnect did not close engine")
	}
}

func TestServiceStateMachineRejectsConcurrentConnect(t *testing.T) {
	rt := newServiceRuntime(&fakeTunnelEngine{})
	if _, err := rt.Connect(context.Background(), svcipc.ConnectRequest{ConfigURI: "tamizdat://unit"}); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	if _, err := rt.Connect(context.Background(), svcipc.ConnectRequest{ConfigURI: "tamizdat://unit"}); err == nil {
		t.Fatalf("second Connect succeeded while connected")
	}
}

func TestServiceStateMachineDisconnectDuringConnectingCancelsGracefully(t *testing.T) {
	started := make(chan struct{})
	rt := newServiceRuntime(&fakeTunnelEngine{connectStarted: started, connectRelease: make(chan struct{})})
	done := make(chan error, 1)
	go func() {
		_, err := rt.Connect(context.Background(), svcipc.ConnectRequest{ConfigURI: "tamizdat://unit"})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not start")
	}
	if got := rt.snapshot().State; got != svcipc.StateConnecting {
		t.Fatalf("state before Disconnect=%s", got)
	}
	if err := rt.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect while Connecting: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect error=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not finish after Disconnect")
	}
	if got := rt.snapshot().State; got != svcipc.StateDisconnected {
		t.Fatalf("state after cancelling Connect=%s", got)
	}
}

func TestServiceStateMachineStopTimeoutTransitionsToFailed(t *testing.T) {
	sess := &fakeTunnelSession{stopWait: make(chan struct{})}
	rt := newServiceRuntime(&fakeTunnelEngine{connectSession: sess})
	if _, err := rt.Connect(context.Background(), svcipc.ConnectRequest{ConfigURI: "tamizdat://unit"}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := rt.Disconnect(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Disconnect error=%v, want deadline", err)
	}
	if got := rt.snapshot().State; got != svcipc.StateFailed {
		t.Fatalf("state after Stop timeout=%s", got)
	}
}

func TestStatsResponseUsesExpvarCountersAfterSyntheticTraffic(t *testing.T) {
	names := statsExpvarNames{
		"tamizdat.test.bytes.client_to_target",
		"tamizdat.test.bytes.target_to_client",
		"tamizdat.test.tunnels.tcp.opened",
		"tamizdat.test.tunnels.tcp.closed",
		"tamizdat.test.tunnels.udp.opened",
		"tamizdat.test.tunnels.udp.closed",
	}
	setExpvarInt(t, names[0], 1234)
	setExpvarInt(t, names[1], 5678)
	setExpvarInt(t, names[2], 9)
	setExpvarInt(t, names[3], 8)
	setExpvarInt(t, names[4], 7)
	setExpvarInt(t, names[5], 6)

	oldNames := defaultStatsExpvarNames
	defaultStatsExpvarNames = names
	defer func() { defaultStatsExpvarNames = oldNames }()

	got := statsFromExpvar(time.Now().Add(-2 * time.Second))
	if got.BytesUp != 1234 || got.BytesDown != 5678 || got.TCPOpenTotal != 9 || got.TCPCloseTotal != 8 || got.UDPOpenTotal != 7 || got.UDPCloseTotal != 6 {
		t.Fatalf("stats not populated from expvar: %+v", got)
	}
	if got.Uptime <= 0 {
		t.Fatalf("uptime not populated: %+v", got)
	}
}

func setExpvarInt(t *testing.T, name string, value int64) {
	t.Helper()
	if existing := expvar.Get(name); existing != nil {
		v, ok := existing.(*expvar.Int)
		if !ok {
			t.Fatalf("%s has unexpected expvar type %T", name, existing)
		}
		cur, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		v.Add(value - cur)
		return
	}
	v := new(expvar.Int)
	v.Set(value)
	expvar.Publish(name, v)
}
