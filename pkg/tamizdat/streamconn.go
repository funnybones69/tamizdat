package tamizdat

import (
	"io"
	"net"
	"sync"
	"time"
)

// streamConn wraps an io.ReadWriteCloser (typically an HTTP/2 stream body)
// as a net.Conn. It implements all required net.Conn methods, delegating
// Read/Write to the underlying stream and supporting deadline-based timeouts.
type streamConn struct {
	rwc         io.ReadWriteCloser
	localAddr   net.Addr
	remoteAddr  net.Addr
	shaper      *Shaper
	fragmenter  *RecordFragmenter
	destination string

	readDeadline  *deadlineTimer
	writeDeadline *deadlineTimer

	mu     sync.Mutex
	closed bool
}

// newStreamConn creates a net.Conn backed by the given ReadWriteCloser.
// The fragmenter (may be nil) is consulted on every Write to split the
// payload across multiple H2 DATA frames (P0.1 wiring).
func newStreamConn(rwc io.ReadWriteCloser, localAddr, remoteAddr net.Addr, destination string, shaper *Shaper, fragmenter *RecordFragmenter) *streamConn {
	return &streamConn{
		rwc:           rwc,
		localAddr:     localAddr,
		remoteAddr:    remoteAddr,
		destination:   destination,
		shaper:        shaper,
		fragmenter:    fragmenter,
		readDeadline:  newDeadlineTimer(rwc),
		writeDeadline: newDeadlineTimer(rwc),
	}
}

func (sc *streamConn) Read(b []byte) (int, error) {
	if err := sc.readDeadline.wait(); err != nil {
		return 0, err
	}
	return sc.rwc.Read(b)
}

func (sc *streamConn) Write(b []byte) (int, error) {
	if err := sc.writeDeadline.wait(); err != nil {
		return 0, err
	}
	if sc.shaper != nil {
		return sc.shaper.FragmentWrite(sc.rwc, sc.fragmenter, b)
	}
	return sc.rwc.Write(b)
}

func (sc *streamConn) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	sc.closed = true
	sc.readDeadline.stop()
	sc.writeDeadline.stop()
	return sc.rwc.Close()
}

func (sc *streamConn) LocalAddr() net.Addr  { return sc.localAddr }
func (sc *streamConn) RemoteAddr() net.Addr { return sc.remoteAddr }

func (sc *streamConn) SetDeadline(t time.Time) error {
	sc.readDeadline.set(t)
	sc.writeDeadline.set(t)
	return nil
}

func (sc *streamConn) SetReadDeadline(t time.Time) error {
	sc.readDeadline.set(t)
	return nil
}

func (sc *streamConn) SetWriteDeadline(t time.Time) error {
	sc.writeDeadline.set(t)
	return nil
}

// CloseWrite performs a half-close on the write side of the connection,
// signaling EOF to the remote peer while keeping the read side open.
// This is critical for protocols like TLS where the server sends remaining
// data after the client signals it's done writing.
func (sc *streamConn) CloseWrite() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	if cw, ok := sc.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// deadlineTimer supports net.Conn deadline semantics.
type deadlineTimer struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired bool
	rwc     io.Closer
	gen     uint64
}

func newDeadlineTimer(rwc io.Closer) *deadlineTimer {
	return &deadlineTimer{rwc: rwc}
}

// set configures the deadline. A zero time clears the deadline.
func (dt *deadlineTimer) set(t time.Time) {
	var closeNow io.Closer

	dt.mu.Lock()
	dt.gen++
	gen := dt.gen
	dt.expired = false
	if dt.timer != nil {
		dt.timer.Stop()
		dt.timer = nil
	}

	if t.IsZero() {
		dt.mu.Unlock()
		return
	}

	d := time.Until(t)
	if d <= 0 {
		dt.expired = true
		closeNow = dt.rwc
		dt.mu.Unlock()
		if closeNow != nil {
			_ = closeNow.Close()
		}
		return
	}

	dt.timer = time.AfterFunc(d, func() {
		dt.mu.Lock()
		if dt.gen != gen {
			dt.mu.Unlock()
			return
		}
		dt.expired = true
		rwc := dt.rwc
		dt.mu.Unlock()
		if rwc != nil {
			_ = rwc.Close()
		}
	})
	dt.mu.Unlock()
}

func (dt *deadlineTimer) stop() {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.gen++
	if dt.timer != nil {
		dt.timer.Stop()
		dt.timer = nil
	}
}

// wait returns a timeout error if the deadline has expired, nil otherwise.
func (dt *deadlineTimer) wait() error {
	dt.mu.Lock()
	expired := dt.expired
	dt.mu.Unlock()
	if expired {
		return &timeoutError{}
	}
	return nil
}

// timeoutError implements the net.Error interface for deadline timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// streamAddr implements net.Addr for H2 stream connections.
type streamAddr struct {
	network string
	address string
}

func (a *streamAddr) Network() string { return a.network }
func (a *streamAddr) String() string  { return a.address }
