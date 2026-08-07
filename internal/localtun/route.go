package localtun

import "context"

type routeController interface {
	Setup(context.Context) error
	Cleanup(context.Context) error
}

type supervisedRouteController interface {
	routeController
	DNSDone() <-chan error
	DNSError() error
	Health(context.Context) error
	EnterFailClosed(context.Context) error
}
