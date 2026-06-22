package fragpoc

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const pipeBufferSlots = 256

type bufferedPipe struct {
	once sync.Once
	done chan struct{}
}

type bufferedPipeConn struct {
	pipe       *bufferedPipe
	in         chan []byte
	out        chan []byte
	localAddr  net.Addr
	remoteAddr net.Addr

	mu            sync.Mutex
	readBuf       []byte
	readDeadline  time.Time
	writeDeadline time.Time
}

func newBufferedPipe() (net.Conn, net.Conn) {
	p := &bufferedPipe{done: make(chan struct{})}
	aToB := make(chan []byte, pipeBufferSlots)
	bToA := make(chan []byte, pipeBufferSlots)
	a := &bufferedPipeConn{
		pipe:       p,
		in:         bToA,
		out:        aToB,
		localAddr:  streamAddr{network: "pipe", address: "fragpoc-client"},
		remoteAddr: streamAddr{network: "pipe", address: "fragpoc-server"},
	}
	b := &bufferedPipeConn{
		pipe:       p,
		in:         aToB,
		out:        bToA,
		localAddr:  streamAddr{network: "pipe", address: "fragpoc-server"},
		remoteAddr: streamAddr{network: "pipe", address: "fragpoc-client"},
	}
	return a, b
}

func (c *bufferedPipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}

	select {
	case <-c.pipe.done:
		return 0, io.EOF
	case b := <-c.in:
		if len(b) == 0 {
			return 0, nil
		}
		n := copy(p, b)
		if n < len(b) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf[:0], b[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *bufferedPipeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()

	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}

	buf := append([]byte(nil), p...)
	select {
	case <-c.pipe.done:
		return 0, net.ErrClosed
	case c.out <- buf:
		return len(p), nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *bufferedPipeConn) Close() error {
	c.pipe.once.Do(func() {
		close(c.pipe.done)
	})
	return nil
}

func (c *bufferedPipeConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *bufferedPipeConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *bufferedPipeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *bufferedPipeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *bufferedPipeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
