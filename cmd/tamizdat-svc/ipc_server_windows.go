//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/funnybones69/tamizdat/internal/svcipc"
)

type ipcServer struct {
	rt   *serviceRuntime
	logs *logHub
	ln   net.Listener
}

func newIPCServer(rt *serviceRuntime, logs *logHub) *ipcServer { return &ipcServer{rt: rt, logs: logs} }

func (s *ipcServer) Serve(ctx context.Context) error {
	ln, err := winio.ListenPipe(svcipc.PipeName, &winio.PipeConfig{SecurityDescriptor: svcipc.PipeSDDL, MessageMode: false})
	if err != nil {
		return err
	}
	s.ln = ln
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("ipc accept: %v", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *ipcServer) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

type ipcConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *ipcConn) write(f svcipc.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return svcipc.WriteFrame(c.conn, f)
}

func (s *ipcServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()
	ic := &ipcConn{conn: conn}
	events, cancelEvents := s.rt.subscribeEvents()
	defer cancelEvents()
	go func() {
		for ev := range events {
			_ = ic.write(ev)
		}
	}()
	br := svcipc.NewFrameReader(conn)
	for {
		f, err := svcipc.ReadFrame(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("ipc read: %v", err)
			}
			return
		}
		if f.Type != svcipc.TypeRequest {
			continue
		}
		resp := svcipc.Frame{ID: f.ID, Type: svcipc.TypeResponse, Method: f.Method}
		payload, err := s.handleRequest(connCtx, f, ic)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Payload = payload
		}
		if err := ic.write(resp); err != nil {
			return
		}
	}
}

func (s *ipcServer) handleRequest(ctx context.Context, f svcipc.Frame, ic *ipcConn) (json.RawMessage, error) {
	switch f.Method {
	case svcipc.MethodPing:
		return svcipc.MustJSON(svcipc.PingResponse{Version: "tamizdat-svc-p0"}), nil
	case svcipc.MethodGetStatus:
		return svcipc.MustJSON(s.rt.snapshot()), nil
	case svcipc.MethodGetStats:
		return svcipc.MustJSON(s.rt.Stats()), nil
	case svcipc.MethodConnect:
		var req svcipc.ConnectRequest
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			return nil, err
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		resp, err := s.rt.Connect(cctx, req)
		if err != nil {
			return nil, err
		}
		return svcipc.MustJSON(resp), nil
	case svcipc.MethodDisconnect:
		dctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		return nil, s.rt.Disconnect(dctx)
	case svcipc.MethodSubscribeLogs:
		var req svcipc.SubscribeLogsRequest
		_ = json.Unmarshal(f.Payload, &req)
		cancel := s.logs.Subscribe(req.TailFromID, func(lines []svcipc.LogLine) {
			if len(lines) > 0 {
				_ = ic.write(svcipc.Frame{Type: svcipc.TypeEvent, Method: svcipc.EventLogLines, Payload: svcipc.MustJSON(lines)})
			}
		})
		go func() { <-ctx.Done(); cancel() }()
		return nil, nil
	case svcipc.MethodGetSettings:
		return svcipc.MustJSON(svcipc.Settings{}), nil
	case svcipc.MethodSetSettings:
		return nil, nil
	default:
		return nil, errors.New("unknown method: " + f.Method)
	}
}
