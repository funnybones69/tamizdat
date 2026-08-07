//go:build windows

package tunengine

import (
	"context"
	"errors"
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
	handler  interface{ Close() }
	dialer   *samizdatProxyDialer
	done     chan struct{}
	stopDone chan struct{}
	stopOnce sync.Once
	closed   bool
	err      error
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
	select {
	case <-ctx.Done():
		return sess.Stop(context.Background())
	case <-sess.Done():
		return errors.Join(sess.Err(), sess.Stop(context.Background()))
	}
}

func (e *Engine) Start(ctx context.Context, opts Options, client ProxyClient) (*Session, error) {
	if opts.MTU <= 0 {
		return nil, fmt.Errorf("MTU must be > 0, got %d", opts.MTU)
	}
	if err := e.ensureDevice(opts.Name, opts.MTU); err != nil {
		return nil, err
	}
	dialer := newSamizdatProxyDialer(client, opts.Debug, opts.Dispatcher, opts.DialAttemptTimeout, opts.DialConcurrency, opts.DialActiveConcurrency, opts.DialOpenInterval, opts.DialTargetCooldown, opts.DialTargetCooldownMax, opts.DialMinAttemptBudget, opts.DialRecoveryThreshold, opts.DialRecoveryBackoff, opts.DropPrivateDestinations, opts.DropAllUDP, opts.DropNonDNSUDP, opts.BlockedEndpoints)
	dialer.dropQUIC = opts.DropQUIC
	handler := tunnel.New(dialer, statistic.DefaultManager)
	setUDPIdleTimeout(handler, opts.UDPIdleTimeout)
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
	sess := &Session{stack: stack, handler: handler, dialer: dialer, done: make(chan struct{}), stopDone: make(chan struct{})}
	go sess.waitStack()
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
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		stack, handler, dialer := s.stack, s.handler, s.dialer
		s.mu.Unlock()
		go func() {
			if stack != nil {
				stack.Close()
				<-s.done
			}
			if handler != nil {
				handler.Close()
			}
			if dialer != nil {
				dialer.Stop()
			}
			close(s.stopDone)
		}()
	})
	select {
	case <-s.stopDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) waitStack() {
	s.stack.Wait()
	s.mu.Lock()
	if !s.closed {
		s.err = fmt.Errorf("tun2socks netstack stopped unexpectedly")
	}
	s.mu.Unlock()
	close(s.done)
}

func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
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
