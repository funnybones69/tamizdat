package localtun

import "context"

type routeController interface {
	Setup(context.Context) error
	Cleanup(context.Context) error
}
