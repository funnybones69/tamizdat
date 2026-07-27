package tamizdat

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

// MaxUDPDatagram is the maximum payload size of a single tunneled UDP datagram.
const MaxUDPDatagram = 65535

// SamizdatProtocolHeader names the request/response header used to negotiate
// non-TCP transports inside the H2 CONNECT tunnel. Today only "udp/1" is defined.
const SamizdatProtocolHeader = "Samizdat-Protocol"

// SamizdatProtocolUDP is the value used for UDP-over-CONNECT.
const SamizdatProtocolUDP = "udp/1"

// udpFramedPacketConn implements net.PacketConn over a length-prefixed
// bidirectional stream (H2 stream body + ResponseWriter, or a server-side
// equivalent). All datagrams travel as `uint16 BE length || payload`.
//
// All reads return the originally negotiated remote address (the CONNECT
// target). Writes are silently restricted to that address -- packets directed
// elsewhere are rejected. tun2socks's `symmetricNATPacketConn`
// (tun2socks/v2/tunnel/udp.go) filters by source string, so we MUST return
// the same Addr.String() that DialUDP's metadata had.
//
// HIGH-1 caveat (known): SetDeadline only takes effect at the start of the
// next ReadFrom/WriteTo call -- it does not unblock a Read already parked
// inside io.ReadFull. Callers wanting prompt cancellation should Close().
//
// DEADLINE TRAP (2026-05-13): SetReadDeadline / SetWriteDeadline schedule a
// time.AfterFunc that calls rwc.Close() when the deadline elapses. This is
// correct for "I want to abort this op and tear down the stream", but it is
// **catastrophic** if used as a polling tick in a read loop: every short
// deadline that fires will destroy the underlying H2 stream and kill the
// entire UDP tunnel. udp_server.go used this pattern with a 2s poll, which
// silently murdered AnyDesk/RDP traffic that went idle for >2s through the
// chain-hop outbound path. The server now branches on conn type and only
// uses SetReadDeadline on real *net.UDPConn. If you must add a deadline
// here, only do so at the very end of a tunnel's life, never in a loop.
type udpFramedPacketConn struct {
	rwc       io.ReadWriteCloser // the stream (h2 RoundTrip body or server stream)
	target    net.Addr           // target the CONNECT was made for; ReadFrom returns this
	closeOnce sync.Once
	closed    atomic.Bool

	wmu sync.Mutex // serialize writes (one Write per datagram)
	rmu sync.Mutex // serialize reads (one ReadFull per datagram)

	// HIGH-1: deadline enforcement so SetDeadline satisfies net.Conn contract.
	// rd / wd store the deadline as Unix nanos (0 = no deadline). Read / Write
	// fast-path check this before blocking. rdTimer / wdTimer fire rwc.Close()
	// when the deadline elapses while a Read/Write is parked, which propagates
	// io.EOF to the blocked io.ReadFull.
	rd      atomic.Int64
	wd      atomic.Int64
	dlMu    sync.Mutex
	rdTimer *time.Timer
	wdTimer *time.Timer
}

func newUDPFramedPacketConn(rwc io.ReadWriteCloser, target net.Addr) *udpFramedPacketConn {
	return &udpFramedPacketConn{rwc: rwc, target: target}
}

// ReadFrom reads one UDP datagram. The address returned is always the
// original CONNECT target (so tun2socks's symmetric-NAT filter accepts it).
func (c *udpFramedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if t := c.rd.Load(); t != 0 {
		now := time.Now().UnixNano()
		if t <= now {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: timeoutErr{}}
		}
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(c.rwc, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(p) {
		// MED-7: drain via fixed 4 KiB scratch buffer in a loop instead of
		// allocating a 65 KiB attacker-controlled buffer per oversized datagram.
		copiedToCaller := copy(p, make([]byte, 0)) // initialize for clarity
		remaining := n
		var scratch [4096]byte
		for remaining > 0 {
			chunk := remaining
			if chunk > len(scratch) {
				chunk = len(scratch)
			}
			if _, err := io.ReadFull(c.rwc, scratch[:chunk]); err != nil {
				return 0, nil, err
			}
			if copiedToCaller < len(p) {
				copiedToCaller += copy(p[copiedToCaller:], scratch[:chunk])
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

// WriteTo writes one UDP datagram. The address must match the original
// CONNECT target (tun2socks always passes the same metadata.DestinationAddress).
func (c *udpFramedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	// MED-3: clamp at 65000 (well under IPv4 UDP max 65507 minus IP/UDP headers)
	// so we never accept a payload the OS will reject with EMSGSIZE on the
	// server side and tear down the tunnel asymmetrically.
	if len(p) > 65000 {
		return 0, errors.New("samizdat: udp datagram too large (>65000)")
	}
	// Defensive: tun2socks always uses the same target, but reject divergent
	// destinations so we don't silently swallow buggy callers.
	if addr != nil && c.target != nil &&
		!strings.EqualFold(addr.String(), c.target.String()) {
		return 0, errors.New("samizdat: udp tunnel is bound to a single target")
	}
	if t := c.wd.Load(); t != 0 {
		now := time.Now().UnixNano()
		if t <= now {
			return 0, &net.OpError{Op: "write", Net: "udp", Err: timeoutErr{}}
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// MED-1: single Write for header+body so RST_STREAM between two Writes
	// can never leave the framer in a length-without-payload state.
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(p)))
	copy(buf[2:], p)
	if _, err := c.rwc.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpFramedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.dlMu.Lock()
		if c.rdTimer != nil {
			c.rdTimer.Stop()
			c.rdTimer = nil
		}
		if c.wdTimer != nil {
			c.wdTimer.Stop()
			c.wdTimer = nil
		}
		c.dlMu.Unlock()
		err = c.rwc.Close()
	})
	return err
}

func (c *udpFramedPacketConn) LocalAddr() net.Addr { return localUDPAddr{} }

func (c *udpFramedPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *udpFramedPacketConn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.rdTimer != nil {
		c.rdTimer.Stop()
		c.rdTimer = nil
	}
	if t.IsZero() {
		c.rd.Store(0)
		return nil
	}
	c.rd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		// Past: close the underlying RWC so any blocked io.ReadFull returns.
		_ = c.rwc.Close()
		return nil
	}
	c.rdTimer = time.AfterFunc(d, func() {
		now := time.Now().UnixNano()
		if cur := c.rd.Load(); cur != 0 && cur <= now {
			_ = c.rwc.Close()
		}
	})
	return nil
}

func (c *udpFramedPacketConn) SetWriteDeadline(t time.Time) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.wdTimer != nil {
		c.wdTimer.Stop()
		c.wdTimer = nil
	}
	if t.IsZero() {
		c.wd.Store(0)
		return nil
	}
	c.wd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		_ = c.rwc.Close()
		return nil
	}
	c.wdTimer = time.AfterFunc(d, func() {
		now := time.Now().UnixNano()
		if cur := c.wd.Load(); cur != 0 && cur <= now {
			_ = c.rwc.Close()
		}
	})
	return nil
}

type localUDPAddr struct{}

func (localUDPAddr) Network() string { return "udp" }
func (localUDPAddr) String() string  { return "samizdat-udp-tunnel" }

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }
