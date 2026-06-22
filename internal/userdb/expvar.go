package userdb

import (
	"database/sql"
	"time"
)

func ExpvarSnapshot(db *sql.DB, reg *UserRegistry, acc *Accounting) (map[string]any, int, int) {
	out := make(map[string]any)
	users := reg.Snapshot()
	activeSince := time.Now().Add(-90 * time.Second).Unix()
	online, poolIdx, _ := OnlineCounts(db, activeSince)
	activeTransport, _ := ActiveTransports(db, activeSince)
	totalOnline := 0
	for _, u := range users {
		pu, pd := acc.Pending(u.ID)
		n := online[u.ID]
		totalOnline += n
		transport := activeTransport[u.ID]
		if transport == "" && n > 0 {
			transport = "h2"
		}
		out[u.ID] = map[string]any{
			"name":                      u.Name,
			"online_sessions":           n,
			"bytes_up":                  u.BytesUp + pu,
			"bytes_down":                u.BytesDown + pd,
			"current_pool_index":        poolIdx[u.ID],
			"active_transport":          transport,
			"last_seen_at":              u.LastSeenAt,
			"expires_at":                u.ExpiresAt,
			"outbound_tag":              u.OutboundTag,
			"h2_peak_streams":           u.H2PeakStreams,
			"h2_peak_tcp_streams":       u.H2PeakTCPStreams,
			"h2_peak_udp_streams":       u.H2PeakUDPStreams,
			"h2_peak_at":                u.H2PeakAt,
			"h2_relay_peak_streams":     u.H2RelayPeakStreams,
			"h2_relay_peak_tcp_streams": u.H2RelayPeakTCPStreams,
			"h2_relay_peak_udp_streams": u.H2RelayPeakUDPStreams,
			"h2_relay_peak_at":          u.H2RelayPeakAt,
		}
	}
	return out, len(users), totalOnline
}
