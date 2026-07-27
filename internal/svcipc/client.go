package svcipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type Client struct {
	conn    net.Conn
	mu      sync.Mutex
	writeMu sync.Mutex
	nextID  atomic.Uint32
	pending map[uint32]chan Frame
	events  chan Frame
	closed  chan struct{}
	once    sync.Once
}

func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:    conn,
		pending: make(map[uint32]chan Frame),
		events:  make(chan Frame, 64),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Client) Events() <-chan Frame { return c.events }

func (c *Client) Close() error {
	c.once.Do(func() {
		_ = c.conn.Close()
		close(c.closed)
		c.mu.Lock()
		for id, ch := range c.pending {
			delete(c.pending, id)
			close(ch)
		}
		c.mu.Unlock()
		close(c.events)
	})
	return nil
}

func (c *Client) readLoop() {
	br := NewFrameReader(c.conn)
	for {
		f, err := ReadFrame(br)
		if err != nil {
			c.failPending()
			return
		}
		if f.Type == TypeEvent {
			select {
			case c.events <- f:
			case <-c.closed:
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[f.ID]
		delete(c.pending, f.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- f
			close(ch)
		}
	}
}

func (c *Client) failPending() {
	c.mu.Lock()
	for id, ch := range c.pending {
		delete(c.pending, id)
		close(ch)
	}
	c.mu.Unlock()
	select {
	case <-c.closed:
	default:
		_ = c.Close()
	}
}

func (c *Client) call(ctx context.Context, method string, req any, resp any) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	id := c.nextID.Add(1)
	ch := make(chan Frame, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return errors.New("svcipc client is closed")
	default:
	}
	c.pending[id] = ch
	c.mu.Unlock()

	c.writeMu.Lock()
	err = WriteFrame(c.conn, Frame{ID: id, Type: TypeRequest, Method: method, Payload: payload})
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}

	select {
	case f, ok := <-ch:
		if !ok {
			return errors.New("pipe closed")
		}
		if f.Error != "" {
			return errors.New(f.Error)
		}
		if resp != nil && len(f.Payload) > 0 {
			if err := json.Unmarshal(f.Payload, resp); err != nil {
				return fmt.Errorf("decode %s response: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *Client) Connect(ctx context.Context, req ConnectRequest) (ConnectResponse, error) {
	var resp ConnectResponse
	return resp, c.call(ctx, MethodConnect, req, &resp)
}
func (c *Client) Disconnect(ctx context.Context) error {
	return c.call(ctx, MethodDisconnect, struct{}{}, nil)
}
func (c *Client) GetStatus(ctx context.Context) (StatusResponse, error) {
	var resp StatusResponse
	return resp, c.call(ctx, MethodGetStatus, struct{}{}, &resp)
}
func (c *Client) GetStats(ctx context.Context) (StatsResponse, error) {
	var resp StatsResponse
	return resp, c.call(ctx, MethodGetStats, struct{}{}, &resp)
}
func (c *Client) Ping(ctx context.Context) (PingResponse, error) {
	var resp PingResponse
	return resp, c.call(ctx, MethodPing, struct{}{}, &resp)
}
func (c *Client) SubscribeLogs(ctx context.Context, req SubscribeLogsRequest) error {
	return c.call(ctx, MethodSubscribeLogs, req, nil)
}
