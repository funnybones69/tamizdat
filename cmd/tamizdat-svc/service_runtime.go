package main

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/internal/svcipc"
)

type tunnelStatus struct {
	ServerAddr string
	RTT        int64
}

type tunnelSession interface {
	Stop(context.Context) error
	Status() tunnelStatus
	Stats() svcipc.StatsResponse
}

type tunnelEngine interface {
	Connect(context.Context, svcipc.ConnectRequest) (tunnelSession, svcipc.ConnectResponse, error)
	Close() error
}

type serviceRuntime struct {
	mu            sync.Mutex
	engine        tunnelEngine
	session       tunnelSession
	state         string
	startedAt     time.Time
	server        string
	connectCancel context.CancelFunc
	connectDone   chan struct{}
	subs          map[chan svcipc.Frame]struct{}
}

func newServiceRuntime(engine tunnelEngine) *serviceRuntime {
	return &serviceRuntime{engine: engine, state: svcipc.StateDisconnected, subs: map[chan svcipc.Frame]struct{}{}}
}

func (rt *serviceRuntime) Connect(ctx context.Context, req svcipc.ConnectRequest) (svcipc.ConnectResponse, error) {
	rt.mu.Lock()
	if rt.state != svcipc.StateDisconnected {
		state := rt.state
		rt.mu.Unlock()
		return svcipc.ConnectResponse{}, fmt.Errorf("cannot Connect while %s", state)
	}
	connectCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	rt.connectCancel = cancel
	rt.connectDone = done
	rt.setStateLocked(svcipc.StateConnecting, "connect requested")
	rt.mu.Unlock()

	sess, resp, err := rt.engine.Connect(connectCtx, req)

	rt.mu.Lock()
	if rt.connectDone == done {
		rt.connectCancel = nil
		rt.connectDone = nil
	}
	defer close(done)
	if err != nil {
		if rt.state == svcipc.StateConnecting {
			rt.clearSessionLocked()
			rt.setStateLocked(svcipc.StateDisconnected, err.Error())
		}
		rt.mu.Unlock()
		return svcipc.ConnectResponse{}, err
	}
	if rt.state != svcipc.StateConnecting {
		// Disconnect was requested while Connect was still in-flight. Hand the
		// newly-created session to Disconnect, but do not publish Connected.
		rt.session = sess
		rt.startedAt = time.Now()
		rt.server = resp.ServerAddr
		rt.mu.Unlock()
		if connectCtx.Err() != nil {
			return svcipc.ConnectResponse{}, connectCtx.Err()
		}
		return svcipc.ConnectResponse{}, errors.New("connect cancelled by disconnect")
	}
	rt.session = sess
	rt.startedAt = time.Now()
	rt.server = resp.ServerAddr
	rt.setStateLocked(svcipc.StateConnected, "")
	rt.mu.Unlock()
	return resp, nil
}

func (rt *serviceRuntime) Disconnect(ctx context.Context) error {
	rt.mu.Lock()
	switch rt.state {
	case svcipc.StateDisconnected:
		rt.mu.Unlock()
		return nil
	case svcipc.StateConnecting:
		cancel := rt.connectCancel
		done := rt.connectDone
		rt.setStateLocked(svcipc.StateDisconnecting, "disconnect requested during connect")
		rt.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if err := waitDone(ctx, done); err != nil {
			rt.finishDisconnect(err)
			return err
		}
		rt.mu.Lock()
		sess := rt.session
		rt.mu.Unlock()
		err := stopSession(ctx, sess)
		if closeErr := rt.closeEngine(ctx); err == nil {
			err = closeErr
		}
		rt.finishDisconnect(err)
		return err
	case svcipc.StateFailed:
		// Manual Failed -> Disconnected recovery: Disconnect retries bounded Stop + engine.Close; otherwise restart service.
	}
	sess := rt.session
	rt.setStateLocked(svcipc.StateDisconnecting, "disconnect requested")
	rt.mu.Unlock()

	err := stopSession(ctx, sess)
	if closeErr := rt.closeEngine(ctx); err == nil {
		err = closeErr
	}
	rt.finishDisconnect(err)
	return err
}

func (rt *serviceRuntime) Shutdown(ctx context.Context) error {
	if err := rt.Disconnect(ctx); err != nil {
		return err
	}
	return rt.closeEngine(ctx)
}

func (rt *serviceRuntime) snapshot() svcipc.StatusResponse {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	resp := svcipc.StatusResponse{State: rt.state, ServerAddr: rt.server, RTT: -1}
	if !rt.startedAt.IsZero() {
		resp.Uptime = int64(time.Since(rt.startedAt).Seconds())
	}
	if rt.session != nil {
		st := rt.session.Status()
		resp.ServerAddr = st.ServerAddr
		resp.RTT = st.RTT
	}
	return resp
}

func (rt *serviceRuntime) Stats() svcipc.StatsResponse {
	rt.mu.Lock()
	sess := rt.session
	rt.mu.Unlock()
	if sess == nil {
		return svcipc.StatsResponse{}
	}
	return sess.Stats()
}

type statsExpvarNames [6]string

var defaultStatsExpvarNames = statsExpvarNames{"tamizdat.bytes.client_to_target", "tamizdat.bytes.target_to_client", "tamizdat.tunnels.tcp.opened", "tamizdat.tunnels.tcp.closed", "tamizdat.tunnels.udp.opened", "tamizdat.tunnels.udp.closed"}

func statsFromExpvar(startedAt time.Time) svcipc.StatsResponse {
	n := defaultStatsExpvarNames
	resp := svcipc.StatsResponse{BytesUp: expvarInt64(n[0]), BytesDown: expvarInt64(n[1]), TCPOpenTotal: expvarInt64(n[2]), TCPCloseTotal: expvarInt64(n[3]), UDPOpenTotal: expvarInt64(n[4]), UDPCloseTotal: expvarInt64(n[5]), RTTMs: -1, LastRTTMs: -1}
	if !startedAt.IsZero() {
		resp.Uptime = int64(time.Since(startedAt).Seconds())
	}
	return resp
}

func expvarInt64(name string) int64 {
	if v := expvar.Get(name); v != nil {
		n, _ := strconv.ParseInt(strings.Trim(v.String(), `"`), 10, 64)
		return n
	}
	return 0
}

func (rt *serviceRuntime) subscribeEvents() (chan svcipc.Frame, func()) {
	ch := make(chan svcipc.Frame, 32)
	rt.mu.Lock()
	rt.subs[ch] = struct{}{}
	rt.mu.Unlock()
	cancel := func() {
		rt.mu.Lock()
		if _, ok := rt.subs[ch]; ok {
			delete(rt.subs, ch)
			close(ch)
		}
		rt.mu.Unlock()
	}
	return ch, cancel
}

func stopSession(ctx context.Context, sess tunnelSession) error {
	if sess == nil {
		return nil
	}
	return sess.Stop(ctx)
}

func (rt *serviceRuntime) closeEngine(ctx context.Context) error {
	if rt.engine == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- rt.engine.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitDone(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rt *serviceRuntime) finishDisconnect(err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.connectCancel = nil
	rt.connectDone = nil
	if err != nil {
		rt.setStateLocked(svcipc.StateFailed, err.Error())
		return
	}
	rt.clearSessionLocked()
	rt.setStateLocked(svcipc.StateDisconnected, "")
}

func (rt *serviceRuntime) clearSessionLocked() {
	rt.session = nil
	rt.startedAt = time.Time{}
	rt.server = ""
}

func (rt *serviceRuntime) setStateLocked(state, reason string) {
	rt.state = state
	rt.broadcastLocked(svcipc.Frame{Type: svcipc.TypeEvent, Method: svcipc.EventConnectionStateChanged, Payload: svcipc.MustJSON(svcipc.ConnectionStateChanged{NewState: state, Reason: reason})})
}

func (rt *serviceRuntime) broadcastLocked(frame svcipc.Frame) {
	for ch := range rt.subs {
		select {
		case ch <- frame:
		default:
		}
	}
}
