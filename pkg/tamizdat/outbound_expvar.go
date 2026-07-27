package tamizdat

import (
	"database/sql"
	"expvar"
	"sync"
)

var outboundExpvarOnce sync.Once

var (
	outboundExpvarMu     sync.RWMutex
	outboundExpvarServer *Server
)

func (s *Server) publishOutboundExpvars() {
	if s == nil || s.outboundDB == nil {
		return
	}
	outboundExpvarMu.Lock()
	outboundExpvarServer = s
	outboundExpvarMu.Unlock()
	outboundExpvarOnce.Do(func() {
		expvar.Publish("tamizdat_outbounds", expvar.Func(func() any {
			s := currentOutboundExpvarServer()
			if s == nil {
				return map[string]any{}
			}
			return s.outboundExpvarSnapshot()
		}))
	})
}

func currentOutboundExpvarServer() *Server {
	outboundExpvarMu.RLock()
	defer outboundExpvarMu.RUnlock()
	return outboundExpvarServer
}

func (s *Server) outboundExpvarSnapshot() map[string]any {
	out := map[string]any{}
	if s == nil || s.outboundDB == nil {
		return out
	}
	rows, err := s.outboundDB.Query(`SELECT tag, kind,
        COALESCE(h2_peak_streams, 0),
        COALESCE(h2_peak_tcp_streams, 0),
        COALESCE(h2_peak_udp_streams, 0),
        COALESCE(h2_peak_at, 0)
        FROM outbounds ORDER BY tag`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var (
			tag     string
			kind    string
			peak    int64
			peakTCP int64
			peakUDP int64
			peakAt  int64
		)
		if err := rows.Scan(&tag, &kind, &peak, &peakTCP, &peakUDP, &peakAt); err != nil {
			continue
		}
		snap := outboundStreamSnapshot{}
		if s.outboundStreamTracker != nil {
			snap = s.outboundStreamTracker.snapshot(tag)
		}
		out[tag] = map[string]any{
			"tag":                        tag,
			"kind":                       kind,
			"h2_live_streams":            snap.liveTotal,
			"h2_live_tcp_streams":        snap.liveTCP,
			"h2_live_udp_streams":        snap.liveUDP,
			"h2_peak_streams":            peak,
			"h2_peak_tcp_streams":        peakTCP,
			"h2_peak_udp_streams":        peakUDP,
			"h2_peak_at":                 peakAt,
			"h2_dial_failed_tcp_streams": snap.dialFailedTCP,
			"h2_dial_failed_udp_streams": snap.dialFailedUDP,
			"h2_dial_failed_at":          snap.lastFailedAt,
			"h2_dial_failed_network":     snap.lastFailedNet,
			"h2_dial_failed_error":       snap.lastFailedErr,
		}
	}
	if err := rows.Err(); err != nil && err != sql.ErrNoRows {
		return out
	}
	return out
}
