//go:build windows

package tunengine

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
)

type Engine struct {
	mu   sync.Mutex
	dev  device.Device
	name string
	mtu  int
}

type Session struct {
	mu    sync.Mutex
	stack interface {
		Close()
		Wait()
	}
	handler interface{ Close() }
	dialer  *tamizdatProxyDialer
	closed  bool
}

func New(opts Options) (*Engine, error) {
	if opts.MTU <= 0 {
		return nil, fmt.Errorf("MTU must be > 0, got %d", opts.MTU)
	}
	return &Engine{name: opts.Name, mtu: opts.MTU}, nil
}

func Run(ctx context.Context, opts Options, client ProxyClient) error {
	eng, err := New(opts)
	if err != nil {
		return err
	}
	defer eng.Close()
	sess, err := eng.Start(ctx, opts, client)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return sess.Stop(context.Background())
}

func (e *Engine) Start(ctx context.Context, opts Options, client ProxyClient) (*Session, error) {
	if opts.MTU <= 0 {
		return nil, fmt.Errorf("MTU must be > 0, got %d", opts.MTU)
	}
	if err := e.ensureDevice(opts.Name, opts.MTU); err != nil {
		return nil, err
	}
	dialer := newTamizdatProxyDialer(client, opts.Debug, opts.Dispatcher, opts.DialAttemptTimeout, opts.DialConcurrency, opts.DialActiveConcurrency, opts.DialOpenInterval, opts.DialTargetCooldown, opts.DialTargetCooldownMax, opts.DialMinAttemptBudget, opts.DialRecoveryThreshold, opts.DialRecoveryBackoff, opts.DropPrivateDestinations, opts.DropAllUDP, opts.DropNonDNSUDP, opts.BlockedEndpoints)
	handler := tunnel.New(dialer, statistic.DefaultManager)
	handler.ProcessAsync()

	stackOpts := make([]option.Option, 0, 3)
	if opts.TCPModerateReceiveBuffer {
		stackOpts = append(stackOpts, option.WithTCPModerateReceiveBuffer(true))
	}
	if opts.TCPSendBufferSize > 0 {
		stackOpts = append(stackOpts, option.WithTCPSendBufferSize(opts.TCPSendBufferSize))
	}
	if opts.TCPReceiveBufferSize > 0 {
		stackOpts = append(stackOpts, option.WithTCPReceiveBufferSize(opts.TCPReceiveBufferSize))
	}

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     e.dev,
		TransportHandler: handler,
		Options:          stackOpts,
	})
	if err != nil {
		handler.Close()
		dialer.Stop()
		return nil, fmt.Errorf("create netstack: %w", err)
	}
	sess := &Session{stack: stack, handler: handler, dialer: dialer}
	log.Printf("TUN up: name=%s type=%s mtu=%d", e.dev.Name(), e.dev.Type(), opts.MTU)
	if opts.PostTunUp != nil {
		if err := opts.PostTunUp(); err != nil {
			_ = sess.Stop(ctx)
			return nil, fmt.Errorf("post-tun-up callback: %w", err)
		}
	} else {
		log.Printf("Routes were not modified. Run --route-help for manual Windows route commands.")
	}
	return sess, nil
}

func (e *Engine) ensureDevice(name string, mtu int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dev != nil {
		return nil
	}
	dev, err := tun.Open(name, uint32(mtu))
	if err != nil {
		return fmt.Errorf("open wintun device %q: %w", name, err)
	}
	e.dev = dev
	e.name = name
	e.mtu = mtu
	return nil
}

func (s *Session) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	stack, handler, dialer := s.stack, s.handler, s.dialer
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		if stack != nil {
			stack.Close()
			stack.Wait()
		}
		if handler != nil {
			handler.Close()
		}
		if dialer != nil {
			dialer.Stop()
		}
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) Close() error {
	e.mu.Lock()
	dev := e.dev
	e.dev = nil
	e.mu.Unlock()
	if dev == nil {
		return nil
	}
	if c, ok := dev.(interface{ Close() }); ok {
		c.Close()
	}
	return nil
}
