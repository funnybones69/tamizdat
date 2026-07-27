//go:build windows

package svcipc

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

func Dial(ctx context.Context) (*Client, error) {
	backoff := 100 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		timeout := backoff
		if deadline, ok := ctx.Deadline(); ok {
			left := time.Until(deadline)
			if left <= 0 {
				return nil, context.DeadlineExceeded
			}
			if timeout > left {
				timeout = left
			}
		}
		conn, err := winio.DialPipe(PipeName, &timeout)
		if err == nil {
			return NewClient(conn), nil
		}
		if !isRetryablePipeError(err) {
			return nil, err
		}
		jitter := time.Duration(rand.Int63n(int64(backoff / 4)))
		wait := backoff + jitter
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
}

func isRetryablePipeError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "pipe") || strings.Contains(s, "file not found") || strings.Contains(s, "not connected") || strings.Contains(s, "broken") || strings.Contains(s, "busy")
}
