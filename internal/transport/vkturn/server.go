package vkturn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

type Handler func(ctx context.Context, conn net.Conn, destination string, shortID [ShortIDLen]byte)

type ServerConfig struct {
	ShortID          [ShortIDLen]byte
	Authorize        func([ShortIDLen]byte) bool
	Handler          Handler
	MaxFramePayload  int
	HandshakeTimeout time.Duration
}

type Server struct {
	config           ServerConfig
	maxFramePayload  int
	handshakeTimeout time.Duration
	mu               sync.Mutex
	sessions         map[*muxSession]struct{}
	closeOnce        sync.Once
	closed           chan struct{}
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Handler == nil {
		return nil, errors.New("vkturn: Handler is required")
	}
	return &Server{
		config:           config,
		maxFramePayload:  maxFramePayload(config.MaxFramePayload),
		handshakeTimeout: durationDefault(config.HandshakeTimeout, DefaultConnectTimeout),
		sessions:         make(map[*muxSession]struct{}),
		closed:           make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context, listenAddr string) error {
	ln, err := kcp.ListenWithOptions(listenAddr, nil, 0, 0)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-s.closed:
			_ = ln.Close()
		}
	}()
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closed:
				return net.ErrClosed
			default:
				return err
			}
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	configureKCPConn(conn)
	_ = conn.SetReadDeadline(time.Now().Add(s.handshakeTimeout))
	fr, err := readRawFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || fr.typ != frameHello || len(fr.payload) != ShortIDLen {
		_ = conn.Close()
		return
	}
	var shortID [ShortIDLen]byte
	copy(shortID[:], fr.payload)
	if !s.authorize(shortID) {
		_ = writeRawFrame(conn, frameHelloErr, 0, []byte("auth"))
		_ = conn.Close()
		return
	}
	if err := writeRawFrame(conn, frameHelloOK, 0, nil); err != nil {
		_ = conn.Close()
		return
	}
	sess := newMuxSession(conn, s.maxFramePayload, true, shortID, s.config.Handler)
	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
	go func() {
		<-sess.done
		s.mu.Lock()
		delete(s.sessions, sess)
		s.mu.Unlock()
	}()
}

func (s *Server) authorize(shortID [ShortIDLen]byte) bool {
	if s.config.Authorize != nil {
		return s.config.Authorize(shortID)
	}
	return shortID == s.config.ShortID
}

func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.mu.Lock()
		sessions := make([]*muxSession, 0, len(s.sessions))
		for sess := range s.sessions {
			sessions = append(sessions, sess)
		}
		s.mu.Unlock()
		for _, sess := range sessions {
			_ = sess.Close()
		}
	})
	return nil
}

func readRawFrame(conn net.Conn) (frame, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return frame{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[5:7]))
	buf := make([]byte, frameHeaderLen+n)
	copy(buf, hdr[:])
	if n > 0 {
		if _, err := io.ReadFull(conn, buf[frameHeaderLen:]); err != nil {
			return frame{}, err
		}
	}
	return decodeFrame(buf)
}

func writeRawFrame(conn net.Conn, typ byte, sid uint32, payload []byte) error {
	buf, err := encodeFrame(typ, sid, payload)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}
