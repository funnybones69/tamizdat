package fragpoc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Handler func(ctx context.Context, conn net.Conn, destination string, shortID [ShortIDLen]byte)

// defaultDestinationLimit intentionally follows the secure-frame wire ceiling.
// FragPoC lab builds use oversized OpOpenSecure destination payloads to measure
// what an LTE path lets through; the real data path still chunks UP/DOWN frames.
const defaultDestinationLimit = 0xffff - secureOverhead

type ServerConfig struct {
	ShortID             [ShortIDLen]byte
	Authorize           func([ShortIDLen]byte) bool
	Handler             Handler
	MaxPayload          int
	SessionTTL          time.Duration
	SessionReapInterval time.Duration
	DownReadTimeout     time.Duration
	OperationTimeout    time.Duration
	DestinationLimit    int
	// PortHintHandler is called when a client sends OpPortHint with a list
	// of desired server ports. The callback should open/validate those ports
	// and return the list of actually-open ports (including the base port).
	// If nil, OpPortHint is rejected with AckErr.
	PortHintHandler func(shortID [ShortIDLen]byte, requestedPorts []int) []int
}

type Server struct {
	config              ServerConfig
	maxPayload          int
	sessionTTL          time.Duration
	sessionReapInterval time.Duration
	downReadTimeout     time.Duration
	operationTimeout    time.Duration
	destinationLimit    int

	mu       sync.Mutex
	sessions map[[SIDLen]byte]*session

	stop      chan struct{}
	closeOnce sync.Once
}

type session struct {
	sid       [SIDLen]byte
	conn      net.Conn
	createdAt time.Time
	lastUsed  atomic.Int64
	closed    atomic.Bool
	secure    bool
	secureKey [32]byte
	upMu      sync.Mutex

	// DOWN producer model: a dedicated goroutine reads from conn and pushes
	// frames into frameCh. Multiple concurrent DOWN handlers each pull a
	// different frame — no lock contention on the read path.
	frameCh      chan downFrame
	producerDone chan struct{}

	// Replay ring buffer for retransmission when a DOWN handler times out
	// without new data or the client needs a specific seq retransmitted.
	replayMu   sync.Mutex
	replayRing [replayRingSize]downFrame
	replayHead int
	replayLen  int

	// Stateful retransmit policy: track how many DOWN responses were served
	// at the same ack value. Retransmit is only triggered after a threshold
	// to avoid premature replay during normal parallel burst (where ack
	// stays at 0 simply because responses are in-flight, not because a
	// frame was lost).
	retransmitMu      sync.Mutex
	lastRetransmitAck uint32
	servedSinceAck    int
}

type downFrame struct {
	seq  uint32
	data []byte
	eof  bool
}

const replayRingSize = 32

func NewServer(config ServerConfig) (*Server, error) {
	if config.Handler == nil {
		return nil, errors.New("fragpoc: Handler is required")
	}
	s := &Server{
		config:              config,
		maxPayload:          maxPayload(config.MaxPayload),
		sessionTTL:          durationDefault(config.SessionTTL, 5*time.Minute),
		sessionReapInterval: durationDefault(config.SessionReapInterval, 30*time.Second),
		downReadTimeout:     durationDefault(config.DownReadTimeout, 15*time.Second),
		operationTimeout:    durationDefault(config.OperationTimeout, 30*time.Second),
		destinationLimit:    intDefault(config.DestinationLimit, defaultDestinationLimit),
		sessions:            make(map[[SIDLen]byte]*session),
		stop:                make(chan struct{}),
	}
	go s.reaperLoop()
	return s, nil
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.ServeConn(ctx, conn)
	}
}

// SessionCount returns the number of live FragPoC sessions. Used by the
// dynamic port-manager as its load signal.
func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if s.operationTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.operationTimeout))
		defer conn.SetDeadline(time.Time{})
	}
	var op [1]byte
	if _, err := io.ReadFull(conn, op[:]); err != nil {
		return
	}
	switch op[0] {
	case OpOpen:
		s.handleOpen(ctx, conn)
	case OpUp:
		s.handleUp(conn)
	case OpDown:
		s.handleDown(conn)
	case OpClose:
		s.handleClose(conn)
	case OpOpenSecure, OpOpenSecureCompat:
		s.handleOpenSecure(ctx, conn)
	case OpUpSecure, OpUpSecureCompat:
		s.handleUpSecure(conn)
	case OpDownSecure, OpDownSecureCompat:
		s.handleDownSecure(conn)
	case OpCloseSecure, OpCloseSecureCompat:
		s.handleCloseSecure(conn)
	case OpPortHint:
		s.handlePortHint(conn)
	default:
		_, _ = conn.Write([]byte{AckErr})
	}
}

func (s *Server) handleOpen(ctx context.Context, conn net.Conn) {
	var shortID [ShortIDLen]byte
	if _, err := io.ReadFull(conn, shortID[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if !s.authorize(shortID) {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if first[0] == secureOpenMarker {
		s.handleOpenSecureBody(ctx, conn, shortID)
		return
	}
	destination, err := readNULStringWithPrefix(conn, first[0], s.destinationLimit)
	if err != nil || destination == "" {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	clientConn, serverConn := newBufferedPipe()
	sess := &session{
		conn:         clientConn,
		createdAt:    time.Now(),
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	sess.touch()
	if _, err := io.ReadFull(rand.Reader, sess.sid[:]); err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	s.addSession(sess)
	resp := make([]byte, 1+SIDLen)
	resp[0] = AckOK
	copy(resp[1:], sess.sid[:])
	if _, err := conn.Write(resp); err != nil {
		s.deleteSession(sess.sid)
		sess.close()
		_ = serverConn.Close()
		return
	}
	go func() {
		defer s.deleteSession(sess.sid)
		defer sess.close()
		s.config.Handler(ctx, serverConn, destination, shortID)
	}()
	go s.downProducer(sess)
}

func (s *Server) handleOpenSecure(ctx context.Context, conn net.Conn) {
	var shortID [ShortIDLen]byte
	if _, err := io.ReadFull(conn, shortID[:]); err != nil {
		return
	}
	s.handleOpenSecureBody(ctx, conn, shortID)
}

func (s *Server) handleOpenSecureBody(ctx context.Context, conn net.Conn, shortID [ShortIDLen]byte) {
	staticKey := deriveSecureStaticKey(shortID)
	respAD := secureResponseAD(OpOpenSecure, shortID[:])
	plain, openNonce, err := readSecureBody(conn, staticKey, secureRequestAD(OpOpenSecure, shortID[:]), s.destinationLimit+1)
	if err != nil {
		return
	}
	writeErr := func() {
		_, _ = writeSecureBody(conn, staticKey, respAD, []byte{AckErr})
	}
	if !s.authorize(shortID) {
		writeErr()
		return
	}
	destination, err := readNULBytes(plain, s.destinationLimit)
	if err != nil || destination == "" {
		writeErr()
		return
	}
	clientConn, serverConn := newBufferedPipe()
	sess := &session{
		conn:         clientConn,
		createdAt:    time.Now(),
		secure:       true,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	sess.touch()
	if _, err := io.ReadFull(rand.Reader, sess.sid[:]); err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		writeErr()
		return
	}
	sess.secureKey = deriveSecureSessionKey(staticKey, sess.sid, openNonce)
	s.addSession(sess)
	resp := make([]byte, 1+SIDLen)
	resp[0] = AckOK
	copy(resp[1:], sess.sid[:])
	if _, err := writeSecureBody(conn, staticKey, respAD, resp); err != nil {
		s.deleteSession(sess.sid)
		sess.close()
		_ = serverConn.Close()
		return
	}
	go func() {
		defer s.deleteSession(sess.sid)
		defer sess.close()
		s.config.Handler(ctx, serverConn, destination, shortID)
	}()
	go s.downProducer(sess)
}

func (s *Server) handleUp(conn net.Conn) {
	sess, ok := s.readSession(conn)
	if !ok {
		return
	}
	if sess.secure {
		s.handleUpSecureSession(conn, sess)
		return
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > MaxUpPayload {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	sess.upMu.Lock()
	_ = sess.conn.SetWriteDeadline(time.Now().Add(upWriteTimeout(s.operationTimeout)))
	_, err := sess.conn.Write(buf)
	_ = sess.conn.SetWriteDeadline(time.Time{})
	sess.upMu.Unlock()
	if err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	sess.touch()
	_, _ = conn.Write([]byte{AckOK})
}

func (s *Server) handleUpSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpUpSecure)
	if !ok {
		return
	}
	s.handleUpSecureSession(conn, sess)
}

func (s *Server) handleUpSecureSession(conn net.Conn, sess *session) {
	respAD := secureResponseAD(OpUpSecure, sess.sid[:])
	writeErr := func() {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
	}
	plain, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpUpSecure, sess.sid[:]), 2+MaxUpPayload)
	if err != nil || len(plain) < 2 {
		writeErr()
		return
	}
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n > MaxUpPayload || len(plain) != 2+n {
		writeErr()
		return
	}
	sess.upMu.Lock()
	_ = sess.conn.SetWriteDeadline(time.Now().Add(upWriteTimeout(s.operationTimeout)))
	_, err = sess.conn.Write(plain[2:])
	_ = sess.conn.SetWriteDeadline(time.Time{})
	sess.upMu.Unlock()
	if err != nil {
		writeErr()
		return
	}
	sess.touch()
	_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckOK})
}

func (s *Server) handleDown(conn net.Conn) {
	sess, ok := s.readSession(conn)
	if !ok {
		return
	}
	if sess.secure {
		s.handleDownSecureSession(conn, sess)
		return
	}
	ack, ok := readDownRequest(conn)
	if !ok {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	_, _ = conn.Write(s.nextDownResponse(sess, ack))
}

func (s *Server) handleDownSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpDownSecure)
	if !ok {
		return
	}
	s.handleDownSecureSession(conn, sess)
}

func (s *Server) handleDownSecureSession(conn net.Conn, sess *session) {
	respAD := secureResponseAD(OpDownSecure, sess.sid[:])
	writeErr := func() {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
	}
	plain, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpDownSecure, sess.sid[:]), DownRequestSize)
	ack, ok := readDownRequestBytes(plain)
	if err != nil || !ok {
		writeErr()
		return
	}
	_, _ = writeSecureBody(conn, sess.secureKey, respAD, s.nextDownResponse(sess, ack))
}

// retransmitGap: minimum gap between a channel frame's seq and the client's
// ack before we consider a retransmission. Prevents retransmitting when
// client is only slightly behind (normal in-flight responses).
const retransmitGap = 4

// retransmitAfter: number of DOWN responses served at the same ack before
// we allow retransmission. This prevents premature replay during a normal
// parallel burst where multiple DOWNs arrive with the same ack because
// responses are still in-flight (not because a frame was lost).
// Must be >= MaxDownWindow to avoid false retransmits during full burst.
const retransmitAfter = MaxDownWindow

// shouldRetransmit updates the per-session stale-ack counter and returns
// whether enough DOWNs have been served at the same ack to indicate a
// probable frame loss (as opposed to a normal parallel burst).
func (sess *session) shouldRetransmit(ack uint32) bool {
	sess.retransmitMu.Lock()
	defer sess.retransmitMu.Unlock()
	if ack > sess.lastRetransmitAck {
		// Client advanced ack — reset counter.
		sess.lastRetransmitAck = ack
		sess.servedSinceAck = 1
		return false
	}
	if ack == sess.lastRetransmitAck {
		sess.servedSinceAck++
		return sess.servedSinceAck > retransmitAfter
	}
	// Stale ack (ack < lastRetransmitAck): in-flight request from before
	// client advanced. Don't modify state, don't retransmit.
	return false
}

func (s *Server) nextDownResponse(sess *session, ack uint32) []byte {
	shouldRT := sess.shouldRetransmit(ack)

	// Channel first: each concurrent DOWN handler pulls a different frame.
	// This is the primary path that enables parallel DOWN throughput.
	select {
	case frame := <-sess.frameCh:
		sess.touch()
		// Retransmit check: only if enough DOWNs at same ack have been
		// served (shouldRT) AND the channel frame is far enough ahead.
		if shouldRT && frame.seq >= ack+retransmitGap {
			if rf, ok := sess.findReplay(ack); ok && rf.seq == ack {
				select {
				case sess.frameCh <- frame: // put back for other DOWNs
				default:
				}
				return encodeDownFrame(rf)
			}
		}
		return encodeDownFrame(frame)
	default:
	}
	// Channel empty — check replay for retransmission. This handles the case
	// where a previous DOWN delivered a frame but the TCP connection failed,
	// so the client needs the same seq re-sent.
	if frame, ok := sess.findReplay(ack); ok {
		return encodeDownFrame(frame)
	}
	// Long-poll: wait for new data from the producer.
	select {
	case frame := <-sess.frameCh:
		sess.touch()
		if shouldRT && frame.seq >= ack+retransmitGap {
			if rf, ok := sess.findReplay(ack); ok && rf.seq == ack {
				select {
				case sess.frameCh <- frame:
				default:
				}
				return encodeDownFrame(rf)
			}
		}
		return encodeDownFrame(frame)
	case <-time.After(s.downReadTimeout):
	case <-sess.producerDone:
	}
	// Timeout or producer done — drain one more from the buffered channel.
	select {
	case frame := <-sess.frameCh:
		sess.touch()
		return encodeDownFrame(frame)
	default:
	}
	// Final fallback: replay or empty frame.
	if frame, ok := sess.findReplay(ack); ok {
		return encodeDownFrame(frame)
	}
	var zero [6]byte
	binary.BigEndian.PutUint32(zero[:4], ack)
	return zero[:]
}

func encodeDownFrame(frame downFrame) []byte {
	resp := make([]byte, 6+len(frame.data))
	binary.BigEndian.PutUint32(resp[:4], frame.seq)
	if frame.eof {
		binary.BigEndian.PutUint16(resp[4:6], 0xffff)
		return resp[:6]
	}
	binary.BigEndian.PutUint16(resp[4:6], uint16(len(frame.data)))
	copy(resp[6:], frame.data)
	return resp
}

func readDownRequest(conn net.Conn) (uint32, bool) {
	var hdr [6]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, false
	}
	ack := binary.BigEndian.Uint32(hdr[:4])
	n := int(binary.BigEndian.Uint16(hdr[4:]))
	if n < 0 || n > DownRequestSize {
		return 0, false
	}
	if n == 0 {
		return ack, true
	}
	_, err := io.CopyN(io.Discard, conn, int64(n))
	return ack, err == nil
}

func readDownRequestBytes(p []byte) (uint32, bool) {
	if len(p) < 6 {
		return 0, false
	}
	ack := binary.BigEndian.Uint32(p[:4])
	n := int(binary.BigEndian.Uint16(p[4:6]))
	if n < 0 || n > DownRequestSize {
		return 0, false
	}
	return ack, len(p) == 6+n
}

func (s *Server) handleClose(conn net.Conn) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if sess := s.getSession(sid); sess != nil && sess.secure {
		s.handleCloseSecureSession(conn, sess)
		return
	}
	if sess := s.deleteSession(sid); sess != nil {
		sess.close()
	}
	_, _ = conn.Write([]byte{AckOK})
}

func (s *Server) handleCloseSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpCloseSecure)
	if !ok {
		return
	}
	s.handleCloseSecureSession(conn, sess)
}

func (s *Server) handleCloseSecureSession(conn net.Conn, sess *session) {
	respAD := secureResponseAD(OpCloseSecure, sess.sid[:])
	if _, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpCloseSecure, sess.sid[:]), 0); err != nil {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
		return
	}
	secureKey := sess.secureKey
	sid := sess.sid
	if deleted := s.deleteSession(sid); deleted != nil {
		deleted.close()
	}
	_, _ = writeSecureBody(conn, secureKey, respAD, []byte{AckOK})
}

func (s *Server) readSession(conn net.Conn) (*session, bool) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return nil, false
	}
	sess := s.getSession(sid)
	if sess == nil {
		_, _ = conn.Write([]byte{AckErr})
		return nil, false
	}
	return sess, true
}

func (s *Server) readSecureSession(conn net.Conn, op byte) (*session, bool) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		return nil, false
	}
	sess := s.getSession(sid)
	if sess == nil || !sess.secure {
		return nil, false
	}
	return sess, true
}

func (s *Server) authorize(shortID [ShortIDLen]byte) bool {
	if s.config.Authorize != nil {
		return s.config.Authorize(shortID)
	}
	return bytes.Equal(shortID[:], s.config.ShortID[:])
}

func (s *Server) addSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	s.sessions[sess.sid] = sess
}

func (s *Server) getSession(sid [SIDLen]byte) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	sess := s.sessions[sid]
	if sess == nil || sess.closed.Load() {
		return nil
	}
	return sess
}

func (s *Server) deleteSession(sid [SIDLen]byte) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[sid]
	delete(s.sessions, sid)
	return sess
}

func (s *Server) cleanupExpiredLocked(now time.Time) {
	for sid, sess := range s.sessions {
		last := time.Unix(0, sess.lastUsed.Load())
		if now.Sub(last) <= s.sessionTTL {
			continue
		}
		delete(s.sessions, sid)
		sess.close()
	}
}

// reaperLoop periodically expires idle sessions so abandoned ones (client
// gone, no CLOSE) cannot accumulate when overall traffic is bursty or sparse.
// Without it a session whose client vanished without CLOSE lingers (handler
// goroutine + buffered pipe + upstream socket) until the next addSession or
// getSession from another client happens to run cleanupExpiredLocked.
func (s *Server) reaperLoop() {
	t := time.NewTicker(s.sessionReapInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.cleanupExpiredLocked(time.Now())
			s.mu.Unlock()
		}
	}
}

// Close stops the background session reaper. Existing sessions are left to
// their TTL or an explicit CLOSE. Safe to call multiple times.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
	})
	return nil
}

func (s *session) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

func (s *session) close() {
	if s == nil || s.closed.Swap(true) {
		return
	}
	_ = s.conn.Close()
}

// downProducer is the single goroutine per session that reads downstream data
// from the upstream handler (via sess.conn) and feeds it into frameCh for
// concurrent DOWN poll handlers to consume. This decouples the read path from
// the per-DOWN-connection handling, enabling parallel DOWN polling.
func (s *Server) downProducer(sess *session) {
	defer close(sess.producerDone)
	buf := make([]byte, s.maxPayload)
	var seq uint32
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(s.downReadTimeout))
		n, err := sess.conn.Read(buf)
		_ = sess.conn.SetReadDeadline(time.Time{})
		if n > 0 {
			sess.touch()
			frame := downFrame{seq: seq, data: append([]byte(nil), buf[:n]...)}
			seq++
			sess.pushReplay(frame)
			select {
			case sess.frameCh <- frame:
			case <-time.After(5 * time.Second):
				return // consumers gone, stop producing
			}
			continue
		}
		if err != nil {
			if isTimeout(err) {
				continue
			}
			// Real error (conn closed, pipe broken, EOF) — push EOF and exit.
			eofFrame := downFrame{seq: seq, eof: true}
			sess.pushReplay(eofFrame)
			select {
			case sess.frameCh <- eofFrame:
			case <-time.After(2 * time.Second):
			}
			return
		}
	}
}

// pushReplay inserts a frame into the session's fixed-size replay ring buffer.
func (sess *session) pushReplay(frame downFrame) {
	sess.replayMu.Lock()
	idx := (sess.replayHead + sess.replayLen) % replayRingSize
	if sess.replayLen == replayRingSize {
		// Ring full — overwrite oldest entry.
		sess.replayHead = (sess.replayHead + 1) % replayRingSize
	} else {
		sess.replayLen++
	}
	sess.replayRing[idx] = frame
	sess.replayMu.Unlock()
}

// findReplay searches the replay ring for retransmission. Prefers exact seq
// match, then closest seq >= ack, then most recent frame.
func (sess *session) findReplay(ack uint32) (downFrame, bool) {
	sess.replayMu.Lock()
	defer sess.replayMu.Unlock()
	if sess.replayLen == 0 {
		return downFrame{}, false
	}
	// Exact match.
	for i := 0; i < sess.replayLen; i++ {
		idx := (sess.replayHead + i) % replayRingSize
		if sess.replayRing[idx].seq == ack {
			return sess.replayRing[idx], true
		}
	}
	// Closest frame with seq >= ack.
	for i := 0; i < sess.replayLen; i++ {
		idx := (sess.replayHead + i) % replayRingSize
		if sess.replayRing[idx].seq >= ack {
			return sess.replayRing[idx], true
		}
	}
	// Last resort: most recent frame.
	idx := (sess.replayHead + sess.replayLen - 1) % replayRingSize
	return sess.replayRing[idx], true
}

func readNULString(r io.Reader, limit int) (string, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return "", err
	}
	return readNULStringWithPrefix(r, first[0], limit)
}

func readNULStringWithPrefix(r io.Reader, first byte, limit int) (string, error) {
	if limit <= 0 {
		limit = 512
	}
	if first == 0 {
		return "", nil
	}
	buf := []byte{first}
	var b [1]byte
	for len(buf) <= limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(buf), nil
		}
		buf = append(buf, b[0])
	}
	return "", fmt.Errorf("fragpoc: NUL string exceeds %d bytes", limit)
}

func readNULBytes(p []byte, limit int) (string, error) {
	if limit <= 0 {
		limit = 512
	}
	for i, b := range p {
		if i > limit {
			break
		}
		if b == 0 {
			return string(p[:i]), nil
		}
	}
	return "", fmt.Errorf("fragpoc: NUL string exceeds %d bytes", limit)
}

func durationDefault(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}

func intDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// upWriteTimeout caps the UP write deadline to prevent holding upMu for
// the full operationTimeout (default 30s) when the upstream handler stalls.
func upWriteTimeout(opTimeout time.Duration) time.Duration {
	const maxUpWrite = 8 * time.Second
	if opTimeout <= 0 || opTimeout > maxUpWrite {
		return maxUpWrite
	}
	return opTimeout
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// handlePortHint processes OpPortHint: client authenticates with ShortID then
// sends a NUL-terminated comma-separated port list. Server opens requested
// ports (via PortHintHandler callback) and responds with AckOK + NUL-terminated
// list of actually-open ports. Protocol wire format:
//
//	Client → [OpPortHint already consumed][ShortID 8B][ports CSV\0]
//	Server → [AckOK][open ports CSV\0]   or   [AckErr]
func (s *Server) handlePortHint(conn net.Conn) {
	var shortID [ShortIDLen]byte
	if _, err := io.ReadFull(conn, shortID[:]); err != nil {
		log.Printf("[fragpoc] PortHint: read shortID: %v", err)
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if !s.authorize(shortID) {
		log.Printf("[fragpoc] PortHint: auth failed for %x", shortID)
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	portsCSV, err := readNULString(conn, 1024)
	if err != nil {
		log.Printf("[fragpoc] PortHint: read ports CSV: %v", err)
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if s.config.PortHintHandler == nil {
		log.Printf("[fragpoc] PortHint: no handler configured")
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	requested := parsePortCSV(portsCSV)
	openPorts := s.config.PortHintHandler(shortID, requested)
	log.Printf("[fragpoc] PortHint from %x: requested=%v opened=%v", shortID[:4], requested, openPorts)
	resp := formatPortCSV(openPorts)
	out := make([]byte, 1+len(resp)+1)
	out[0] = AckOK
	copy(out[1:], resp)
	out[len(out)-1] = 0 // NUL terminator
	_, _ = conn.Write(out)
}

func parsePortCSV(s string) []int {
	var out []int
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, err := strconv.Atoi(tok)
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		out = append(out, p)
	}
	return out
}

func formatPortCSV(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
