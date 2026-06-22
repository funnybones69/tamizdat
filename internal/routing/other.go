//go:build !windows

package routing

import (
	"context"
	"fmt"
	"time"
)

func ConfigureAutoRouting(ctx context.Context, serverHost, tunAlias, tunIP string, tunPrefix int, selectiveHosts []string, bypassHosts []string, selectiveRefresh time.Duration) (func(), error) {
	_ = selectiveHosts
	_ = bypassHosts
	_ = selectiveRefresh
	return nil, fmt.Errorf("auto-routing is implemented only on Windows")
}
