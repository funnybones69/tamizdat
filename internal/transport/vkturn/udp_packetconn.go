package vkturn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type udpFramedPacketConn struct {
	rwc       io.ReadWriteCloser
	target    net.Addr
	closeOnce sync.Once
	closed    atomic.Bool
	wmu       sync.Mutex
	rmu       sync.Mutex
	rd        atomic.Int64
	wd        atomic.Int64
}

func newUDPFramedPacketConn(rwc io.ReadWriteCloser, target net.Addr) *udpFramedPacketConn {
	return &udpFramedPacketConn{rwc: rwc, target: target}
}

func (c *udpFramedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if t := c.rd.Load(); t != 0 && t <= time.Now().UnixNano() {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: timeoutErr{}}
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(c.rwc, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(p) {
		copied := 0
		remaining := n
		scratch := make([]byte, 4096)
		for remaining > 0 {
			chunk := remaining
			if chunk > len(scratch) {
				chunk = len(scratch)
			}
			if _, err := io.ReadFull(c.rwc, scratch[:chunk]); err != nil {
				return 0, nil, err
			}
			if copied < len(p) {
				copied += copy(p[copied:], scratch[:chunk])
			}
			remaining -= chunk
		}
		return len(p), c.target, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(c.rwc, p[:n]); err != nil {
		return 0, nil, err
	}
	return n, c.target, nil
}

func (c *udpFramedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > 65000 {
		return 0, errors.New("vkturn: udp datagram too large (>65000)")
	}
	if addr != nil && c.target != nil && !strings.EqualFold(addr.String(), c.target.String()) {
		return 0, errors.New("vkturn: udp tunnel is bound to a single target")
	}
	if t := c.wd.Load(); t != 0 && t <= time.Now().UnixNano() {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: timeoutErr{}}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	if _, err := c.rwc.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpFramedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() { c.closed.Store(true); err = c.rwc.Close() })
	return err
}
func (c *udpFramedPacketConn) LocalAddr() net.Addr {
	return streamAddr{network: "udp", address: "vkturn-udp"}
}
func (c *udpFramedPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}
func (c *udpFramedPacketConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.rd.Store(0)
	} else {
		c.rd.Store(t.UnixNano())
	}
	return nil
}
func (c *udpFramedPacketConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wd.Store(0)
	} else {
		c.wd.Store(t.UnixNano())
	}
	return nil
}
