// Package sniff provides protocol-level destination extraction from the
// first bytes of a forwarded TCP stream. The server uses it to override
// IP destinations with real hostnames (TLS SNI or HTTP Host) so domain-
// based routing rules work for IP-mode clients like sing-tun on iOS that
// resolve DNS locally and pass only the IP through the tunnel.
//
// Design copies the sing-box / xray pattern (Apache-2.0 prior art):
//  1. Wrap conn with a buffered reader that captures the first N bytes
//     without consuming them from the underlying stream.
//  2. Try each Sniffer in order; first to return (host, true) wins.
//  3. Return BufferedConn that replays the captured bytes on Read,
//     so downstream readers (the actual proxy forward) see the full
//     original stream including the peeked bytes.
//
// 2026-05-11 — operator request after iOS Shadowrocket sending
// dst=<IP> made all domain: routing rules dead.
package sniff

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxPeekBytes caps how many bytes we'll read for sniffing. TLS
// ClientHello + HTTP Host are well under this — large enough for any
// realistic SNI/Host payload, small enough that we don't blow memory
// on a malicious client that streams gigabytes.
const MaxPeekBytes = 4096

// PeekTimeout bounds how long we'll wait for the first peek bytes.
// Some clients trickle the first packet; cap so sniff doesn't stall
// connection setup. NOTE: this is sniff's *own* wait; we never touch
// the underlying conn's deadline, so missing this timeout simply
// means "no sniff override, route by IP" — the conn remains alive
// and proxy continues normally.
//
// Set to 1500ms (was 300ms): with chained scenarios (iPhone → ru2 →
// mirror), the inner ClientHello bytes have to traverse two TLS
// tunnels before arriving at mirror's handler. RTT alone can be
// 100-300ms; some LTE / jitter cases push above 500ms. 1500ms gives
// a generous window without making sniff-disabled paths feel slow.
const PeekTimeout = 1500 * time.Millisecond

// Sniffer is a function that examines the first bytes of a TCP stream
// and returns the extracted hostname if recognised. Implementations
// must NOT mutate the byte slice (it may be shared between sniffers).
type Sniffer func(data []byte) (host string, ok bool)

// Errors from PeekConn.
var (
	ErrNoData    = errors.New("sniff: no data within timeout")
	ErrNoSniffer = errors.New("sniff: no sniffer matched")
)

// BufferedConn wraps an underlying net.Conn. A single background
// goroutine performs the FIRST Read; the bytes go into an internal
// buffer that downstream readers drain before falling through to the
// raw conn. This avoids SetReadDeadline entirely — tamizdat's H2
// stream conn (serverStreamConn) closes its reader when a deadline
// elapses, which used to break slow-first-byte clients ("работает
// через раз" with iPhone over LTE).
//
// Forwards CloseWrite to the underlying conn if it implements it
// (proxyBidirectional half-close needs that).
type BufferedConn struct {
	net.Conn
	mu     sync.Mutex
	buf    []byte
	bgErr  error
	ready  chan struct{} // closed when bg fill completes (success or err)
	bgDone atomic.Bool   // mirrors ready being closed; avoid select-on-closed-chan in hot Read path
}

// newBufferedConn wraps a conn and starts a background goroutine to
// fill the buffer with up to MaxPeekBytes from the first Read.
func newBufferedConn(conn net.Conn) *BufferedConn {
	bc := &BufferedConn{Conn: conn, ready: make(chan struct{})}
	go bc.fill()
	return bc
}

// fill runs ONCE: reads up to MaxPeekBytes from the underlying conn
// and stores them in buf. After this the background reader exits;
// downstream Read calls drain buf then go straight to conn.Read.
func (b *BufferedConn) fill() {
	chunk := make([]byte, MaxPeekBytes)
	n, err := b.Conn.Read(chunk)
	b.mu.Lock()
	if n > 0 {
		b.buf = append(b.buf, chunk[:n]...)
	}
	b.bgErr = err
	b.mu.Unlock()
	b.bgDone.Store(true)
	close(b.ready)
}

// peekWait returns whatever bytes the background fill has produced
// within `timeout`. If the fill finished early (within timeout), bytes
// are returned immediately. If timeout fires first, returns nil but
// does NOT cancel the bg fill — it continues, and any subsequent
// BufferedConn.Read picks up the bytes in order. Crucially: NO
// SetReadDeadline is touched on the underlying conn, so we cannot
// kill its reader on a slow client.
func (b *BufferedConn) peekWait(timeout time.Duration) []byte {
	select {
	case <-b.ready:
	case <-time.After(timeout):
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return nil
	}
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

// Read drains the buffered bytes first, then falls through to the
// underlying conn. If the background fill is still in flight when
// Read is first called, blocks until it completes.
func (b *BufferedConn) Read(p []byte) (int, error) {
	// Fast path: bg done, buf available.
	if b.bgDone.Load() {
		b.mu.Lock()
		if len(b.buf) > 0 {
			n := copy(p, b.buf)
			b.buf = b.buf[n:]
			b.mu.Unlock()
			return n, nil
		}
		err := b.bgErr
		b.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return b.Conn.Read(p)
	}
	// Bg still running. Block until it finishes — caller wants the
	// peeked bytes preserved in order.
	<-b.ready
	b.mu.Lock()
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		b.mu.Unlock()
		return n, nil
	}
	err := b.bgErr
	b.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return b.Conn.Read(p)
}

// CloseWrite forwards to the underlying conn if it implements it.
// Embedding net.Conn (interface) doesn't promote concrete-type
// methods, so we have to forward explicitly.
func (b *BufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PeekConn wraps conn in a BufferedConn (with a background fill
// goroutine), waits up to PeekTimeout for the first bytes, runs each
// sniffer, and returns the BufferedConn for downstream use. The
// underlying conn's deadline is NEVER touched — sniff is best-effort
// and never kills the connection.
//
// If no data arrived in the timeout window, returns empty bytes and
// ErrNoData; caller should proceed without sniff override (route by
// IP). The bg fill keeps running so any later-arriving bytes still
// reach the proxy via BufferedConn.Read in order.
func PeekConn(conn net.Conn, sniffers []Sniffer) (string, *BufferedConn, error) {
	bc := newBufferedConn(conn)
	data := bc.peekWait(PeekTimeout)
	if len(data) == 0 {
		return "", bc, ErrNoData
	}
	for _, s := range sniffers {
		if host, ok := s(data); ok && host != "" {
			return host, bc, nil
		}
	}
	return "", bc, ErrNoSniffer
}
