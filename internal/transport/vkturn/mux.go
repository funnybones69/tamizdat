package vkturn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	frameHello    byte = 0x01
	frameHelloOK  byte = 0x02
	frameHelloErr byte = 0x03
	frameOpen     byte = 0x10
	frameOpenOK   byte = 0x11
	frameOpenErr  byte = 0x12
	frameData     byte = 0x20
	frameClose    byte = 0x21
	framePing     byte = 0x30

	frameHeaderLen = 7
)

type frame struct {
	typ      byte
	streamID uint32
	payload  []byte
}

func encodeFrame(typ byte, sid uint32, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, errors.New("vkturn: frame payload too large")
	}
	buf := make([]byte, frameHeaderLen+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[7:], payload)
	return buf, nil
}

func decodeFrame(buf []byte) (frame, error) {
	if len(buf) < frameHeaderLen {
		return frame{}, ErrProtocol
	}
	n := int(binary.BigEndian.Uint16(buf[5:7]))
	if len(buf) < frameHeaderLen+n {
		return frame{}, ErrProtocol
	}
	payload := make([]byte, n)
	copy(payload, buf[7:7+n])
	return frame{typ: buf[0], streamID: binary.BigEndian.Uint32(buf[1:5]), payload: payload}, nil
}

type muxSession struct {
	conn       net.Conn
	maxPayload int
	isServer   bool
	handler    Handler
	shortID    [ShortIDLen]byte

	writeMu   sync.Mutex
	mu        sync.Mutex
	streams   map[uint32]*muxStream
	nextID    uint32
	rrClosed  bool
	done      chan struct{}
	closeOnce sync.Once
}

func newMuxSession(conn net.Conn, maxPayload int, isServer bool, shortID [ShortIDLen]byte, handler Handler) *muxSession {
	next := uint32(1)
	if isServer {
		next = 2
	}
	s := &muxSession{
		conn:       conn,
		maxPayload: maxFramePayload(maxPayload),
		isServer:   isServer,
		handler:    handler,
		shortID:    shortID,
		streams:    make(map[uint32]*muxStream),
		nextID:     next,
		done:       make(chan struct{}),
	}
	go s.readLoop()
	return s
}

func (s *muxSession) newClientStream(destination string) (*muxStream, error) {
	s.mu.Lock()
	if s.rrClosed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	id := s.nextID
	s.nextID += 2
	st := newMuxStream(s, id, streamAddr{network: "tcp", address: "vkturn-client"}, streamAddr{network: "tcp", address: destination})
	st.openCh = make(chan error, 1)
	s.streams[id] = st
	s.mu.Unlock()
	if err := s.writeFrame(frameOpen, id, []byte(destination)); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

func (s *muxSession) writeFrame(typ byte, sid uint32, payload []byte) error {
	buf, err := encodeFrame(typ, sid, payload)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.conn.Write(buf)
	return err
}

func (s *muxSession) readLoop() {
	for {
		fr, err := readRawFrame(s.conn)
		if err != nil {
			s.closeWithError(err)
			return
		}
		s.handleFrame(fr)
	}
}

func (s *muxSession) handleFrame(fr frame) {
	switch fr.typ {
	case framePing:
		return
	case frameOpen:
		if !s.isServer {
			return
		}
		destination := string(fr.payload)
		if destination == "" {
			_ = s.writeFrame(frameOpenErr, fr.streamID, nil)
			return
		}
		st := newMuxStream(s, fr.streamID, streamAddr{network: "tcp", address: "vkturn-server"}, streamAddr{network: "tcp", address: destination})
		s.mu.Lock()
		if s.rrClosed {
			s.mu.Unlock()
			return
		}
		s.streams[fr.streamID] = st
		s.mu.Unlock()
		if err := s.writeFrame(frameOpenOK, fr.streamID, nil); err != nil {
			st.remoteClose(err)
			return
		}
		go func() {
			defer st.Close()
			s.handler(st.ctx(), st, destination, s.shortID)
		}()
	case frameOpenOK, frameOpenErr:
		st := s.getStream(fr.streamID)
		if st == nil || st.openCh == nil {
			return
		}
		if fr.typ == frameOpenOK {
			st.openCh <- nil
		} else {
			st.openCh <- ErrAuthFailed
		}
	case frameData:
		st := s.getStream(fr.streamID)
		if st != nil {
			st.push(fr.payload)
		}
	case frameClose:
		st := s.getStream(fr.streamID)
		if st != nil {
			st.remoteClose(io.EOF)
		}
	}
}

func (s *muxSession) getStream(id uint32) *muxStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *muxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *muxSession) closeWithError(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.rrClosed = true
		streams := make([]*muxStream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = make(map[uint32]*muxStream)
		s.mu.Unlock()
		for _, st := range streams {
			st.remoteClose(err)
		}
		close(s.done)
		_ = s.conn.Close()
	})
}

func (s *muxSession) Close() error {
	s.closeWithError(net.ErrClosed)
	return nil
}

type muxStream struct {
	s               *muxSession
	id              uint32
	local, remote   net.Addr
	readCh          chan []byte
	openCh          chan error
	closeOnce       sync.Once
	closed          chan struct{}
	ctxDone         chan struct{}
	left            []byte
	readDeadlineMu  sync.Mutex
	readDeadline    time.Time
	writeDeadlineMu sync.Mutex
	writeDeadline   time.Time
}

func newMuxStream(s *muxSession, id uint32, local, remote net.Addr) *muxStream {
	return &muxStream{s: s, id: id, local: local, remote: remote, readCh: make(chan []byte, 128), closed: make(chan struct{}), ctxDone: make(chan struct{})}
}

func (st *muxStream) ctx() context.Context { return streamContext{done: st.ctxDone} }

type streamContext struct{ done <-chan struct{} }

func (c streamContext) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (c streamContext) Done() <-chan struct{}                   { return c.done }
func (c streamContext) Err() error {
	select {
	case <-c.done:
		return contextCanceled{}
	default:
		return nil
	}
}
func (c streamContext) Value(key any) any { return nil }

type contextCanceled struct{}

func (contextCanceled) Error() string { return "context canceled" }

func (st *muxStream) push(p []byte) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case st.readCh <- cp:
	case <-st.closed:
	}
}

func (st *muxStream) remoteClose(err error) {
	st.closeOnce.Do(func() {
		st.s.removeStream(st.id)
		close(st.closed)
		close(st.ctxDone)
		close(st.readCh)
	})
}

func (st *muxStream) Read(p []byte) (int, error) {
	if len(st.left) > 0 {
		n := copy(p, st.left)
		st.left = st.left[n:]
		return n, nil
	}
	deadline := st.currentReadDeadline()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, &net.OpError{Op: "read", Net: "vkturn", Err: timeoutErr{}}
		}
		timer = time.After(d)
	}
	select {
	case b, ok := <-st.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, b)
		if n < len(b) {
			st.left = append(st.left[:0], b[n:]...)
		}
		return n, nil
	case <-timer:
		return 0, &net.OpError{Op: "read", Net: "vkturn", Err: timeoutErr{}}
	case <-st.closed:
		return 0, io.EOF
	}
}

func (st *muxStream) Write(p []byte) (int, error) {
	select {
	case <-st.closed:
		return 0, net.ErrClosed
	default:
	}
	if deadline := st.currentWriteDeadline(); !deadline.IsZero() && time.Now().After(deadline) {
		return 0, &net.OpError{Op: "write", Net: "vkturn", Err: timeoutErr{}}
	}
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > st.s.maxPayload {
			n = st.s.maxPayload
		}
		if err := st.s.writeFrame(frameData, st.id, p[written:written+n]); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (st *muxStream) Close() error {
	st.closeOnce.Do(func() {
		_ = st.s.writeFrame(frameClose, st.id, nil)
		st.s.removeStream(st.id)
		close(st.closed)
		close(st.ctxDone)
		close(st.readCh)
	})
	return nil
}

func (st *muxStream) LocalAddr() net.Addr  { return st.local }
func (st *muxStream) RemoteAddr() net.Addr { return st.remote }
func (st *muxStream) SetDeadline(t time.Time) error {
	_ = st.SetReadDeadline(t)
	_ = st.SetWriteDeadline(t)
	return nil
}
func (st *muxStream) SetReadDeadline(t time.Time) error {
	st.readDeadlineMu.Lock()
	st.readDeadline = t
	st.readDeadlineMu.Unlock()
	return nil
}
func (st *muxStream) SetWriteDeadline(t time.Time) error {
	st.writeDeadlineMu.Lock()
	st.writeDeadline = t
	st.writeDeadlineMu.Unlock()
	return nil
}
func (st *muxStream) currentReadDeadline() time.Time {
	st.readDeadlineMu.Lock()
	defer st.readDeadlineMu.Unlock()
	return st.readDeadline
}
func (st *muxStream) currentWriteDeadline() time.Time {
	st.writeDeadlineMu.Lock()
	defer st.writeDeadlineMu.Unlock()
	return st.writeDeadline
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
