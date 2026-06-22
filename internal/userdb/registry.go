package userdb

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Lookup is the (user, pool-index) tuple returned by registry shortid lookups.
// PoolIndex is preserved for wire-shape compatibility with pre-2026-05-09
// callers that distinguished master-shortid (-1) from HKDF pool entries (>=0);
// after the shortid full-B simplification it is always -1.
type Lookup struct {
	UserID    string
	PoolIndex int
}

// User mirrors a row of the users table after schema normalization. Bytes
// accounting (BytesUp+BytesDown) is summed over the rolling-window starting
// at BytesResetAt (0 → since-creation). QuotaBaseline (added in schema v4)
// captures bytes_up+bytes_down at the last operator "Reset Quota" click;
// IsOverQuota subtracts it so the rolling window restarts without erasing
// the lifetime traffic display.
type User struct {
	ID, Name, MasterShortID string
	OutboundTag             string
	PoolSize                int
	ExpiresAt               int64
	BandwidthCap            int64
	// RateLimitMbps caps a single user's throughput at this many Mbits/sec
	// via a token bucket shared across all conns of the user. 0 = unlimited.
	// Distinct from BandwidthCap (which is a total-byte quota). Added v7.
	RateLimitMbps         int
	BytesUp               int64
	BytesDown             int64
	BytesResetAt          int64
	QuotaBaseline         int64
	LastSeenAt            int64
	H2PeakStreams         int64
	H2PeakTCPStreams      int64
	H2PeakUDPStreams      int64
	H2PeakAt              int64
	H2RelayPeakStreams    int64
	H2RelayPeakTCPStreams int64
	H2RelayPeakUDPStreams int64
	H2RelayPeakAt         int64
	// NotificationText carries the per-user notification body the panel
	// pushed via /api/users/<id>/notification or the broadcast endpoint
	// (Phase C, 2026-05-10). The "BROADCAST: " prefix encodes a system-wide
	// scope so the client can render the message slightly differently.
	// Empty = no manual notification (server may still inject auto
	// over_quota / expired notifications independent of this field).
	NotificationText string
	// NotificationPending is the one-shot flag the panel raises (or the
	// server raises on quota overrun). When set, the bundle endpoint
	// emits a NotificationEntry and clears the flag. Independent of
	// NotificationText so server-auto messages don't depend on operator
	// having typed text.
	NotificationPending bool

	// TURN profile push fields are staged by the panel and emitted as a
	// per-user bundle turn_profile. Pending is cleared after successful bundle
	// delivery; Version lets clients ignore old pushes.
	TurnRoomLink         string
	TurnRoomHash         string
	TurnProfilePending   bool
	TurnProfileVersion   int
	TurnProfileUpdatedAt int64
}

// UserRegistry is the in-memory shortid → user map driven by the SQLite
// users table. Reload swaps the maps atomically; LookupHex/LookupBytes
// are read-locked.
type UserRegistry struct {
	mu         sync.RWMutex
	byShortID  map[string]Lookup
	byUserID   map[string]*User
	generation uint64
}

// NewRegistry returns an empty registry. The poolDefault parameter is
// retained for backward-compatible call sites; it is no longer consulted
// after the shortid full-B simplification (HKDF pool derivation removed).
func NewRegistry(_ int) *UserRegistry {
	return &UserRegistry{byShortID: make(map[string]Lookup), byUserID: make(map[string]*User)}
}

// Reload re-reads users from db and atomically swaps the in-memory maps.
// Each user contributes exactly one shortid (master_shortid). Duplicate
// shortids across users abort the reload (UNIQUE constraint also catches
// this in DB).
func (r *UserRegistry) Reload(db *sql.DB) error {
	if r == nil {
		return fmt.Errorf("nil user registry")
	}
	if err := EnsureSchema(db); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, name, master_shortid, outbound_tag,
        COALESCE(pool_size, 1), COALESCE(expires_at, 0), COALESCE(bandwidth_cap, 0),
        COALESCE(rate_limit_mbps, 0),
        bytes_up, bytes_down, COALESCE(bytes_reset_at, 0),
        COALESCE(quota_baseline, 0), COALESCE(last_seen_at, 0),
        COALESCE(h2_peak_streams, 0), COALESCE(h2_peak_tcp_streams, 0),
        COALESCE(h2_peak_udp_streams, 0), COALESCE(h2_peak_at, 0),
        COALESCE(h2_relay_peak_streams, 0), COALESCE(h2_relay_peak_tcp_streams, 0),
        COALESCE(h2_relay_peak_udp_streams, 0), COALESCE(h2_relay_peak_at, 0),
        COALESCE(notification_text, ''), COALESCE(notification_pending, 0),
        COALESCE(turn_room_link, ''), COALESCE(turn_room_hash, ''),
        COALESCE(turn_profile_pending, 0), COALESCE(turn_profile_version, 0),
        COALESCE(turn_profile_updated_at, 0)
        FROM users ORDER BY name, id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := make(map[string]*User)
	byShort := make(map[string]Lookup)
	for rows.Next() {
		u := &User{}
		var notifPending int
		var turnPending int
		if err := rows.Scan(&u.ID, &u.Name, &u.MasterShortID, &u.OutboundTag, &u.PoolSize, &u.ExpiresAt, &u.BandwidthCap, &u.RateLimitMbps, &u.BytesUp, &u.BytesDown, &u.BytesResetAt, &u.QuotaBaseline, &u.LastSeenAt, &u.H2PeakStreams, &u.H2PeakTCPStreams, &u.H2PeakUDPStreams, &u.H2PeakAt, &u.H2RelayPeakStreams, &u.H2RelayPeakTCPStreams, &u.H2RelayPeakUDPStreams, &u.H2RelayPeakAt, &u.NotificationText, &notifPending, &u.TurnRoomLink, &u.TurnRoomHash, &turnPending, &u.TurnProfileVersion, &u.TurnProfileUpdatedAt); err != nil {
			return err
		}
		u.NotificationPending = notifPending != 0
		u.TurnProfilePending = turnPending != 0
		u.MasterShortID, err = NormalizeShortIDHex(u.MasterShortID)
		if err != nil {
			return fmt.Errorf("user %s master_shortid: %w", u.ID, err)
		}
		u.Name = strings.TrimSpace(u.Name)
		if u.Name == "" {
			return fmt.Errorf("user %s has empty name", u.ID)
		}
		if u.OutboundTag == "" {
			u.OutboundTag = "direct"
		}
		if prev, ok := byShort[u.MasterShortID]; ok {
			return fmt.Errorf("shortid collision master %s between %s and %s", u.MasterShortID, prev.UserID, u.ID)
		}
		byShort[u.MasterShortID] = Lookup{UserID: u.ID, PoolIndex: -1}
		cp := *u
		byID[u.ID] = &cp
	}
	if err := rows.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.byShortID = byShort
	r.byUserID = byID
	r.generation++
	r.mu.Unlock()
	return nil
}

// LookupHex resolves a 16-hex-char shortid to (lookup, user, ok).
func (r *UserRegistry) LookupHex(shortID string) (Lookup, *User, bool) {
	if r == nil {
		return Lookup{}, nil, false
	}
	shortID = strings.ToLower(strings.TrimSpace(shortID))
	r.mu.RLock()
	defer r.mu.RUnlock()
	lk, ok := r.byShortID[shortID]
	if !ok {
		return Lookup{}, nil, false
	}
	u := r.byUserID[lk.UserID]
	if u == nil {
		return Lookup{}, nil, false
	}
	cp := *u
	return lk, &cp, true
}

// LookupBytes is a binary [8]byte convenience wrapper around LookupHex.
func (r *UserRegistry) LookupBytes(shortID [8]byte) (Lookup, *User, bool) {
	return r.LookupHex(hex.EncodeToString(shortID[:]))
}

// User returns a copy of the user identified by ID.
func (r *UserRegistry) User(id string) (*User, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	u := r.byUserID[id]
	if u == nil {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// Snapshot returns a copy of every user in the registry.
func (r *UserRegistry) Snapshot() []User {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]User, 0, len(r.byUserID))
	for _, u := range r.byUserID {
		out = append(out, *u)
	}
	return out
}

// ObserveH2Peak updates the registry's cached peak counters after the server
// persists a newer peak. The DB remains authoritative; this keeps expvar from
// lagging until the next full registry reload.
func (r *UserRegistry) ObserveH2Peak(userID string, total, tcp, udp, at int64) {
	if r == nil || userID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.byUserID[userID]
	if u == nil {
		return
	}
	if total > u.H2PeakStreams {
		u.H2PeakStreams = total
	}
	if tcp > u.H2PeakTCPStreams {
		u.H2PeakTCPStreams = tcp
	}
	if udp > u.H2PeakUDPStreams {
		u.H2PeakUDPStreams = udp
	}
	if at > 0 {
		u.H2PeakAt = at
	}
}

// ObserveH2RelayPeak mirrors ObserveH2Peak for next-hop relay counters.
func (r *UserRegistry) ObserveH2RelayPeak(userID string, total, tcp, udp, at int64) {
	if r == nil || userID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.byUserID[userID]
	if u == nil {
		return
	}
	if total > u.H2RelayPeakStreams {
		u.H2RelayPeakStreams = total
	}
	if tcp > u.H2RelayPeakTCPStreams {
		u.H2RelayPeakTCPStreams = tcp
	}
	if udp > u.H2RelayPeakUDPStreams {
		u.H2RelayPeakUDPStreams = udp
	}
	if at > 0 {
		u.H2RelayPeakAt = at
	}
}

// Count returns the number of distinct users in the registry.
func (r *UserRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byUserID)
}

// ShortIDCount returns the total number of registered shortids. After the
// shortid full-B simplification this equals Count().
func (r *UserRegistry) ShortIDCount() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byShortID)
}

// Generation returns a monotonic counter that bumps on each Reload, so
// callers can detect they need to invalidate caches.
func (r *UserRegistry) Generation() uint64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.generation
}

// QuotaWindow is the rolling-window length for BandwidthCap accounting.
// Bytes older than this window since BytesResetAt are considered expired
// and IsOverQuota treats them as "fresh slate". Operator resets the anchor
// manually via the panel "Reset Quota" button OR the auto-rollover triggers
// when window elapses without a manual reset.
const QuotaWindow = 30 * 24 * time.Hour

// IsOverQuota reports whether u has exceeded its 30-day BandwidthCap.
//   - BandwidthCap <= 0: unlimited, never over.
//   - BytesResetAt < (now - QuotaWindow): the rolling window has elapsed
//     and the accumulated bytes are stale; treated as "fresh allotment"
//     (under quota). The next Flush is responsible for re-anchoring
//     bytes_reset_at via the panel quota-reset path.
//   - otherwise: (BytesUp + BytesDown - QuotaBaseline) >= BandwidthCap
//     → over. The baseline subtraction (added in schema v4 quota-reset-
//     split, 2026-05-10) lets the panel "Reset Quota" button restart the
//     rolling-window accounting without erasing the historical
//     bytes_up/bytes_down counters that the operator wants to keep
//     visible as a stat ticker.
//
// nowFunc is injected for testability; callers in production pass nil
// which defaults to time.Now.
func (r *UserRegistry) IsOverQuota(u *User) bool {
	return isOverQuota(u, time.Now)
}

func isOverQuota(u *User, nowFunc func() time.Time) bool {
	if u == nil || u.BandwidthCap <= 0 {
		return false
	}
	now := nowFunc()
	// Window elapsed since the last reset → bytes_reset_at is the anchor;
	// treat aged accumulator as stale (effectively a fresh window). The
	// panel "Reset Quota" button is what re-anchors bytes_reset_at; this
	// auto-rollover protects against forgotten manual resets.
	if u.BytesResetAt > 0 && now.Unix()-u.BytesResetAt > int64(QuotaWindow/time.Second) {
		return false
	}
	// Baseline subtraction: "Reset Quota" stamps QuotaBaseline =
	// BytesUp+BytesDown at the time of the click, so subsequent traffic
	// is what counts against the cap. Defensive clamp at 0 in case
	// counters were rewound out-of-band (shouldn't happen in practice).
	used := u.BytesUp + u.BytesDown - u.QuotaBaseline
	if used < 0 {
		used = 0
	}
	return used >= u.BandwidthCap
}
