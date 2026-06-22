//go:build !linux && !windows

package tunengine

import (
	"context"
	"errors"
)

type Engine struct{}
type Session struct{}

func New(Options) (*Engine, error) {
	return nil, errors.New("tun engine is only supported on Linux and Windows")
}
func Run(context.Context, Options, ProxyClient) error {
	return errors.New("tun engine is only supported on Linux and Windows; cross-compile with GOOS=linux GOARCH=arm64 or GOOS=windows GOARCH=amd64")
}
func (e *Engine) Start(context.Context, Options, ProxyClient) (*Session, error) {
	return nil, errors.New("tun engine is only supported on Linux and Windows")
}
func (s *Session) Stop(context.Context) error { return nil }
func (e *Engine) Close() error                { return nil }
