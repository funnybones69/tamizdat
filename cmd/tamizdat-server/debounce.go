package main

import (
	"context"
	"time"
)

// debouncedAction runs action once after no Trigger calls have arrived for the
// configured quiet period. Its goroutine and timer are owned by ctx.
type debouncedAction struct {
	ctx         context.Context
	quietPeriod time.Duration
	action      func()
	reset       chan struct{}
	done        chan struct{}
}

func newDebouncedAction(ctx context.Context, quietPeriod time.Duration, action func()) *debouncedAction {
	d := &debouncedAction{
		ctx:         ctx,
		quietPeriod: quietPeriod,
		action:      action,
		reset:       make(chan struct{}),
		done:        make(chan struct{}),
	}
	go d.run()
	return d
}

func (d *debouncedAction) Trigger() {
	if d == nil {
		return
	}
	select {
	case d.reset <- struct{}{}:
	case <-d.ctx.Done():
	case <-d.done:
	}
}

func (d *debouncedAction) Done() <-chan struct{} {
	if d == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return d.done
}

func (d *debouncedAction) run() {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		close(d.done)
	}()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.reset:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d.quietPeriod)
			timerC = timer.C
		case <-timerC:
			timerC = nil
			if d.ctx.Err() != nil {
				return
			}
			if d.action != nil {
				d.action()
			}
		}
	}
}
