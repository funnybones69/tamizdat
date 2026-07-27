package tamizdat

import (
	"expvar"
	"sync"

	"github.com/funnybones69/tamizdat/internal/userdb"
)

// userExpvarOnce guards expvar.Publish so test harnesses that re-create the
// Server with the same key do not panic with "Reuse of exported var name".
//
// The published variables are:
//
//   - tamizdat_users         — map[user_id]→ {name, online_sessions, bytes_up,
//     bytes_down, current_pool_index, last_seen_at,
//     expires_at, outbound_tag, h2_live_streams, h2_live_tcp_streams,
//     h2_live_udp_streams}
//   - tamizdat_total_users   — number of users in the registry
//   - tamizdat_total_online  — sum of online_sessions across all users
//
// They are panel-facing: tamizdat-panel.py polls them every 1.5s to render
// the user table + traffic counters without scraping SQLite directly.
var userExpvarOnce sync.Once

// userExpvarSource is the live pointer the published expvar funcs read from.
// Server.publishUserExpvars updates it under userExpvarMu so multi-test runs
// (each freshly constructed Server) snapshot the latest registry/db.
var (
	userExpvarMu     sync.RWMutex
	userExpvarServer *Server
)

func (s *Server) publishUserExpvars() {
	if s == nil || s.userRegistry == nil || s.outboundDB == nil || s.accounting == nil {
		return
	}
	userExpvarMu.Lock()
	userExpvarServer = s
	userExpvarMu.Unlock()
	userExpvarOnce.Do(func() {
		expvar.Publish("tamizdat_users", expvar.Func(func() any {
			s := currentUserExpvarServer()
			if s == nil {
				return map[string]any{}
			}
			out, _, _ := s.userExpvarSnapshot()
			return out
		}))
		expvar.Publish("tamizdat_total_users", expvar.Func(func() any {
			s := currentUserExpvarServer()
			if s == nil {
				return 0
			}
			_, total, _ := s.userExpvarSnapshot()
			return total
		}))
		expvar.Publish("tamizdat_total_online", expvar.Func(func() any {
			s := currentUserExpvarServer()
			if s == nil {
				return 0
			}
			_, _, online := s.userExpvarSnapshot()
			return online
		}))
	})
}

func (s *Server) userExpvarSnapshot() (map[string]any, int, int) {
	if s == nil {
		return map[string]any{}, 0, 0
	}
	out, total, online := userdb.ExpvarSnapshot(s.outboundDB, s.userRegistry, s.accounting)
	if s.h2StreamTracker == nil {
		return out, total, online
	}
	for userID, raw := range out {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		active := s.h2StreamTracker.active("user:" + userID)
		m["h2_live_streams"] = active.total
		m["h2_live_tcp_streams"] = active.tcp
		m["h2_live_udp_streams"] = active.udp
		if s.userRelayStreamTracker != nil {
			relay := s.userRelayStreamTracker.active("user:" + userID)
			m["h2_relay_live_streams"] = relay.total
			m["h2_relay_live_tcp_streams"] = relay.tcp
			m["h2_relay_live_udp_streams"] = relay.udp
		}
	}
	return out, total, online
}

func currentUserExpvarServer() *Server {
	userExpvarMu.RLock()
	defer userExpvarMu.RUnlock()
	return userExpvarServer
}
