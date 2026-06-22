package fragpoc

import (
	"errors"
	"sync"
	"time"
)

const (
	schedulerIdleInitial  = 100 * time.Millisecond
	schedulerIdleMax      = 2 * time.Second
	schedulerErrorInitial = 100 * time.Millisecond
	schedulerErrorMax     = 2 * time.Second
)

// schedulerStuckTimeout bounds how long a logical stream may receive nothing
// but transient DOWN failures before the scheduler gives up on it. Past this
// the session path is treated as dead: the stream is failed so its gVisor
// Read() unblocks and the tunengine active slot it pins gets released. This is
// the primary anti-stick mechanism.
const schedulerStuckTimeout = 75 * time.Second

// schedulerAppStuckTimeout bounds how long a stream may succeed at the
// transport level (idle DOWNs return OK) without receiving any real payload
// before the scheduler treats the upstream as dead. Without this, a session
// that gets nothing but empty idle DOWNs forever keeps refreshing
// schedLastProgress and is never reaped by the transient-error reaper.
const schedulerAppStuckTimeout = 120 * time.Second

// errSchedulerStuck is delivered to a stream's errCh when schedulerStuckTimeout
// is exceeded, so the gVisor Read() returns an error instead of blocking
// forever.
var errSchedulerStuck = errors.New("fragpoc: DOWN scheduler abandoned stuck stream")

type downScheduler struct {
	client *Client

	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
	next   int
	conns  []*Conn
	active map[*Conn]struct{}
}

func newDownScheduler(client *Client) *downScheduler {
	s := &downScheduler{
		client: client,
		active: make(map[*Conn]struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	for i := 0; i < client.downWorkers; i++ {
		go s.worker()
	}
	return s
}

func (s *downScheduler) addConn(conn *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || conn.closed.Load() || conn.eof.Load() {
		return
	}
	if _, ok := s.active[conn]; ok {
		return
	}
	conn.schedIdleDelay = schedulerIdleInitial
	conn.schedErrorDelay = schedulerErrorInitial
	conn.schedNextPoll = time.Time{}
	conn.schedInFlight = 0
	conn.schedWindow = 1
	conn.schedLastProgress = time.Now()
	conn.schedLastPayload = time.Time{}
	s.active[conn] = struct{}{}
	s.conns = append(s.conns, conn)
	s.cond.Broadcast()
}

// stats returns a point-in-time snapshot of scheduler occupancy for the
// diagnostic metrics log. activeConns is the number of logical streams the
// scheduler is polling, queuedConns is the round-robin slice length (should
// track activeConns), and totalInFlight is the sum of per-stream in-flight
// DOWN polls — i.e. how many DOWN workers are currently committed.
func (s *downScheduler) stats() (activeConns, queuedConns, totalInFlight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	activeConns = len(s.active)
	queuedConns = len(s.conns)
	for c := range s.active {
		totalInFlight += c.schedInFlight
	}
	return activeConns, queuedConns, totalInFlight
}

func (s *downScheduler) removeConn(conn *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[conn]; !ok {
		return
	}
	delete(s.active, conn)
	for i, c := range s.conns {
		if c != conn {
			continue
		}
		s.removeAtLocked(i)
		break
	}
	s.cond.Broadcast()
}

func (s *downScheduler) close() {
	s.mu.Lock()
	s.closed = true
	s.active = make(map[*Conn]struct{})
	s.conns = nil
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *downScheduler) worker() {
	for {
		conn, ok := s.pick()
		if !ok {
			return
		}
		outcome := conn.runScheduledDownPoll()
		s.finish(conn, outcome)
	}
}

func (s *downScheduler) pick() (*Conn, bool) {
	for {
		s.mu.Lock()
		for !s.closed && len(s.conns) == 0 {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return nil, false
		}

		now := time.Now()
		var earliest time.Time
		n := len(s.conns)
		for scanned := 0; scanned < n && len(s.conns) > 0; scanned++ {
			idx := (s.next + scanned) % len(s.conns)
			conn := s.conns[idx]
			if _, ok := s.active[conn]; !ok || conn.closed.Load() || conn.eof.Load() {
				s.removeAtLocked(idx)
				scanned--
				n--
				continue
			}
			window := conn.schedWindow
			if window <= 0 {
				window = 1
				conn.schedWindow = window
			}
			if window > s.client.downWindow {
				window = s.client.downWindow
				conn.schedWindow = window
			}
			if conn.schedInFlight >= window {
				continue
			}
			if len(conn.downCh)+conn.schedInFlight >= cap(conn.downCh) {
				continue
			}
			if !conn.schedNextPoll.IsZero() && conn.schedNextPoll.After(now) {
				if earliest.IsZero() || conn.schedNextPoll.Before(earliest) {
					earliest = conn.schedNextPoll
				}
				continue
			}
			conn.schedInFlight++
			s.next = (idx + 1) % len(s.conns)
			s.mu.Unlock()
			return conn, true
		}
		if earliest.IsZero() {
			// No conn is schedulable and none has a future poll time.
			// Two sub-cases:
			//  (a) all conns have in-flight polls — finish() will Broadcast
			//      when one returns, so cond.Wait is correct.
			//  (b) all conns are backpressured (downCh full, zero in-flight) —
			//      no external signal will arrive; fall through to a short sleep
			//      so we re-check once the consumer drains the channel.
			anyInFlight := false
			for c := range s.active {
				if c.schedInFlight > 0 {
					anyInFlight = true
					break
				}
			}
			if anyInFlight {
				s.cond.Wait() // woken by Broadcast in finish/addConn
				s.mu.Unlock()
				continue
			}
			s.mu.Unlock()
			time.Sleep(schedulerIdleInitial)
			continue
		}
		s.mu.Unlock()
		if d := time.Until(earliest); d > 0 {
			time.Sleep(d)
		}
	}
}

func (s *downScheduler) finish(conn *Conn, outcome downPollOutcome) {
	s.mu.Lock()
	if conn.schedInFlight > 0 {
		conn.schedInFlight--
	}
	if _, ok := s.active[conn]; !ok {
		s.cond.Broadcast()
		s.mu.Unlock()
		return
	}

	now := time.Now()
	stuck := false
	switch outcome {
	case downPollData:
		if conn.schedWindow <= 0 {
			conn.schedWindow = 1
		}
		if conn.schedWindow < s.client.downWindow {
			conn.schedWindow++
		}
		conn.schedIdleDelay = schedulerIdleInitial
		conn.schedErrorDelay = schedulerErrorInitial
		conn.schedNextPoll = now
		conn.schedLastProgress = now
		conn.schedLastPayload = now
	case downPollIdle:
		conn.schedWindow = 1
		conn.schedErrorDelay = schedulerErrorInitial
		delay := conn.schedIdleDelay
		if delay <= 0 {
			delay = schedulerIdleInitial
		}
		conn.schedNextPoll = now.Add(delay)
		conn.schedIdleDelay = growDelay(delay, schedulerIdleMax)
		conn.schedLastProgress = now
		// App-level stuck detection: if the application hasn't received
		// any real payload for schedulerAppStuckTimeout, the upstream is
		// likely dead even though the transport round-trip succeeds.
		if conn.schedLastPayload.IsZero() {
			conn.schedLastPayload = now
		}
		if schedulerAppStuckTimeout > 0 && now.Sub(conn.schedLastPayload) >= schedulerAppStuckTimeout {
			stuck = true
			delete(s.active, conn)
			for i, c := range s.conns {
				if c == conn {
					s.removeAtLocked(i)
					break
				}
			}
		}
	case downPollTransient:
		// Transient is NOT progress: the DOWN round-trip itself failed. If a
		// stream sees nothing but transient failures for schedulerStuckTimeout
		// its path is dead — the gVisor Read() would block forever (no data,
		// no EOF, no error) and pin its tunengine active slot. Fail it.
		if conn.schedLastProgress.IsZero() {
			conn.schedLastProgress = now
		}
		if schedulerStuckTimeout > 0 && now.Sub(conn.schedLastProgress) >= schedulerStuckTimeout {
			stuck = true
			delete(s.active, conn)
			for i, c := range s.conns {
				if c == conn {
					s.removeAtLocked(i)
					break
				}
			}
		} else {
			conn.schedWindow = 1
			conn.schedIdleDelay = schedulerIdleInitial
			delay := conn.schedErrorDelay
			if delay <= 0 {
				delay = schedulerErrorInitial
			}
			conn.schedNextPoll = now.Add(delay)
			conn.schedErrorDelay = growDelay(delay, schedulerErrorMax)
		}
	case downPollEOF, downPollFatal, downPollClosed:
		delete(s.active, conn)
		for i, c := range s.conns {
			if c == conn {
				s.removeAtLocked(i)
				break
			}
		}
	}
	s.cond.Broadcast()
	s.mu.Unlock()

	if stuck {
		// closeDone() re-enters the scheduler via removeConn() which locks
		// s.mu — so this must run after Unlock to avoid self-deadlock.
		select {
		case conn.errCh <- errSchedulerStuck:
		default:
		}
		conn.closeDone()
	}
}

func (s *downScheduler) removeAtLocked(i int) {
	if i < 0 || i >= len(s.conns) {
		return
	}
	copy(s.conns[i:], s.conns[i+1:])
	s.conns[len(s.conns)-1] = nil
	s.conns = s.conns[:len(s.conns)-1]
	if len(s.conns) == 0 {
		s.next = 0
		return
	}
	if s.next > i {
		s.next--
	}
	if s.next >= len(s.conns) {
		s.next = 0
	}
}

func growDelay(current, max time.Duration) time.Duration {
	if current <= 0 {
		current = schedulerIdleInitial
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}
