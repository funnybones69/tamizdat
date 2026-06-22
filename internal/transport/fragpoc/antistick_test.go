package fragpoc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// --- A2: DOWN scheduler stuck-stream killer ---------------------------------

// newStuckTestScheduler builds a downScheduler with no worker goroutines so
// finish() can be exercised deterministically and in isolation.
func newStuckTestScheduler() (*downScheduler, *Client) {
	client := &Client{downWindow: 1}
	s := &downScheduler{
		client: client,
		active: make(map[*Conn]struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	client.scheduler = s
	return s, client
}

func newStuckTestConn(client *Client, lastProgress time.Time) *Conn {
	return &Conn{
		client:            client,
		done:              make(chan struct{}),
		errCh:             make(chan error, 1),
		schedWindow:       1,
		schedLastProgress: lastProgress,
	}
}

func addStuckTestConn(s *downScheduler, conn *Conn) {
	s.mu.Lock()
	s.active[conn] = struct{}{}
	s.conns = append(s.conns, conn)
	s.mu.Unlock()
}

// TestSchedulerAbandonsStuckStream: a stream that has had nothing but transient
// DOWN failures for longer than schedulerStuckTimeout must be dropped from the
// scheduler with its done channel closed and errCh fed, so the gVisor Read()
// unblocks and the tunengine active slot it pins is released. Core anti-stick
// guarantee.
func TestSchedulerAbandonsStuckStream(t *testing.T) {
	s, client := newStuckTestScheduler()
	// schedLastProgress older than schedulerStuckTimeout — the path is dead.
	conn := newStuckTestConn(client, time.Now().Add(-schedulerStuckTimeout-time.Second))
	addStuckTestConn(s, conn)

	s.finish(conn, downPollTransient)

	s.mu.Lock()
	_, stillActive := s.active[conn]
	queued := len(s.conns)
	s.mu.Unlock()
	if stillActive {
		t.Fatal("stuck stream still in scheduler active set")
	}
	if queued != 0 {
		t.Fatalf("stuck stream still queued: len(conns)=%d, want 0", queued)
	}
	select {
	case <-conn.done:
	default:
		t.Fatal("stuck stream done not closed — gVisor Read() would hang forever")
	}
	select {
	case err := <-conn.errCh:
		if err != errSchedulerStuck {
			t.Fatalf("errCh = %v, want errSchedulerStuck", err)
		}
	default:
		t.Fatal("errSchedulerStuck not delivered to errCh")
	}
}

// TestSchedulerKeepsHealthyStreamOnTransient: a single transient failure well
// within schedulerStuckTimeout must NOT kill the stream — it just backs off.
func TestSchedulerKeepsHealthyStreamOnTransient(t *testing.T) {
	s, client := newStuckTestScheduler()
	conn := newStuckTestConn(client, time.Now())
	addStuckTestConn(s, conn)

	s.finish(conn, downPollTransient)

	s.mu.Lock()
	_, stillActive := s.active[conn]
	s.mu.Unlock()
	if !stillActive {
		t.Fatal("healthy stream removed after a single transient failure")
	}
	select {
	case <-conn.done:
		t.Fatal("healthy stream done closed after a single transient failure")
	default:
	}
}

// TestSchedulerProgressResetsStuckTimer: a successful poll (idle outcome — the
// server answered, just had no data) re-arms the stuck timer, so an immediately
// following transient failure does not count the pre-progress staleness.
func TestSchedulerProgressResetsStuckTimer(t *testing.T) {
	s, client := newStuckTestScheduler()
	// Stale anchor — would trip the killer if a successful poll did not reset it.
	conn := newStuckTestConn(client, time.Now().Add(-schedulerStuckTimeout-time.Second))
	addStuckTestConn(s, conn)

	s.finish(conn, downPollIdle)      // successful round-trip re-arms the timer
	s.finish(conn, downPollTransient) // immediate transient must not trip it

	s.mu.Lock()
	_, stillActive := s.active[conn]
	s.mu.Unlock()
	if !stillActive {
		t.Fatal("stream killed even though a successful poll reset the stuck timer")
	}
}

// TestSchedulerAbandonsIdleStuckStream: a stream that keeps getting idle DOWNs
// (transport succeeds, but no real payload) for longer than
// schedulerAppStuckTimeout must be reaped. This is the primary "намертво"
// scenario — upstream is dead, server returns empty frames, client blocks
// forever in Conn.Read() without this fix.
func TestSchedulerAbandonsIdleStuckStream(t *testing.T) {
	s, client := newStuckTestScheduler()
	// Fresh stream — schedLastPayload will be set to now on first idle.
	conn := newStuckTestConn(client, time.Now())
	// Manually backdate schedLastPayload to simulate 120+ seconds without payload.
	conn.schedLastPayload = time.Now().Add(-schedulerAppStuckTimeout - time.Second)
	addStuckTestConn(s, conn)

	// An idle poll — transport succeeded but no data. With stale schedLastPayload
	// this must trigger the app-stuck reaper.
	s.finish(conn, downPollIdle)

	s.mu.Lock()
	_, stillActive := s.active[conn]
	queued := len(s.conns)
	s.mu.Unlock()
	if stillActive {
		t.Fatal("idle-stuck stream still in scheduler active set")
	}
	if queued != 0 {
		t.Fatalf("idle-stuck stream still queued: len(conns)=%d, want 0", queued)
	}
	select {
	case <-conn.done:
	default:
		t.Fatal("idle-stuck stream done not closed — Conn.Read() would hang forever")
	}
	select {
	case err := <-conn.errCh:
		if err != errSchedulerStuck {
			t.Fatalf("errCh = %v, want errSchedulerStuck", err)
		}
	default:
		t.Fatal("errSchedulerStuck not delivered to errCh for idle-stuck stream")
	}
}

// TestSchedulerKeepsIdleStreamWithRecentPayload: an idle poll on a stream that
// received real payload recently must NOT trigger the app-stuck reaper.
func TestSchedulerKeepsIdleStreamWithRecentPayload(t *testing.T) {
	s, client := newStuckTestScheduler()
	conn := newStuckTestConn(client, time.Now())
	conn.schedLastPayload = time.Now() // fresh payload
	addStuckTestConn(s, conn)

	s.finish(conn, downPollIdle)

	s.mu.Lock()
	_, stillActive := s.active[conn]
	s.mu.Unlock()
	if !stillActive {
		t.Fatal("stream with recent payload removed after idle poll")
	}
}

// --- A3: server-side background session reaper ------------------------------

// TestServerBackgroundReaperSweepsExpiredSessions: the reaper goroutine started
// by NewServer must expire idle sessions on its own timer, without needing any
// other client traffic to drive cleanupExpiredLocked.
func TestServerBackgroundReaperSweepsExpiredSessions(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:             [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		SessionTTL:          10 * time.Millisecond,
		SessionReapInterval: 15 * time.Millisecond,
		Handler:             func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	clientConn, serverConn := newBufferedPipe()
	defer serverConn.Close()
	sess := &session{conn: clientConn}
	sess.sid[0] = 0xAB
	sess.touch()
	srv.addSession(sess)

	deadline := time.After(2 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.sessions)
		srv.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("background reaper did not sweep the expired session within 2s")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if !sess.closed.Load() {
		t.Fatal("background reaper removed the session but did not close it")
	}
}

// TestServerCloseStopsReaper: Close() must be idempotent and stop the reaper.
func TestServerCloseStopsReaper(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID: [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Handler: func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close must be a safe no-op: %v", err)
	}
}
