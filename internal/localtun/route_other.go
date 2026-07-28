//go:build !linux

package localtun

import (
	"context"
	"errors"
)

type unsupportedRouteController struct{}

func newRouteController(Config) routeController { return unsupportedRouteController{} }

func (unsupportedRouteController) Setup(context.Context) error {
	return errors.New("panel-managed local TUN routing is supported on Linux only")
}

func (unsupportedRouteController) Cleanup(context.Context) error { return nil }
