package tamizdat

import (
	"fmt"
	"sync"
	"time"
)

type userH2StreamTracker struct {
	mu    sync.Mutex
	byKey map[string]*userH2StreamCounts
}

type userH2StreamCounts struct {
	tcp       int
	udp       int
	peakTotal int
	peakTCP   int
	peakUDP   int
}

type userH2Peak struct {
	total    int
	tcp      int
	udp      int
	advanced bool
}

type userH2Active struct {
	total int
	tcp   int
	udp   int
}

type userH2PeakUpdate struct {
	userID string
	peak   userH2Peak
}

func newUserH2StreamTracker() *userH2StreamTracker {
	return &userH2StreamTracker{byKey: make(map[string]*userH2StreamCounts)}
}

func (a authIdentity) h2StreamTrackerKey() string {
	if a.UserID != "" {
		return "user:" + a.UserID
	}
	var zero [shortIDLen]byte
	if a.ShortID != zero {
		return fmt.Sprintf("shortid:%x", a.ShortID[:])
	}
	return ""
}

func (t *userH2StreamTracker) acquire(key, network string) (func(), userH2Peak) {
	if t == nil || key == "" {
		return func() {}, userH2Peak{}
	}
	t.mu.Lock()
	c := t.byKey[key]
	if c == nil {
		c = &userH2StreamCounts{}
		t.byKey[key] = c
	}
	if network == "udp" {
		c.udp++
	} else {
		c.tcp++
	}
	total := c.tcp + c.udp
	peak := userH2Peak{
		total: c.peakTotal,
		tcp:   c.peakTCP,
		udp:   c.peakUDP,
	}
	if total > c.peakTotal {
		c.peakTotal = total
		peak.total = total
		peak.advanced = true
	}
	if c.tcp > c.peakTCP {
		c.peakTCP = c.tcp
		peak.tcp = c.tcp
		peak.advanced = true
	}
	if c.udp > c.peakUDP {
		c.peakUDP = c.udp
		peak.udp = c.udp
		peak.advanced = true
	}
	peak.total = c.peakTotal
	peak.tcp = c.peakTCP
	peak.udp = c.peakUDP
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.release(key, network)
		})
	}, peak
}

func (t *userH2StreamTracker) release(key, network string) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byKey[key]
	if c == nil {
		return
	}
	if network == "udp" {
		if c.udp > 0 {
			c.udp--
		}
		return
	}
	if c.tcp > 0 {
		c.tcp--
	}
}

func (t *userH2StreamTracker) peak(key string) userH2Peak {
	if t == nil || key == "" {
		return userH2Peak{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byKey[key]
	if c == nil {
		return userH2Peak{}
	}
	return userH2Peak{total: c.peakTotal, tcp: c.peakTCP, udp: c.peakUDP}
}

func (t *userH2StreamTracker) active(key string) userH2Active {
	if t == nil || key == "" {
		return userH2Active{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byKey[key]
	if c == nil {
		return userH2Active{}
	}
	return userH2Active{total: c.tcp + c.udp, tcp: c.tcp, udp: c.udp}
}

func (s *Server) trackUserH2Stream(identity authIdentity, network string) func() {
	if s == nil || s.h2StreamTracker == nil {
		return func() {}
	}
	release, peak := s.h2StreamTracker.acquire(identity.h2StreamTrackerKey(), network)
	if peak.advanced && identity.UserID != "" && s.outboundDB != nil {
		s.enqueueUserH2Peak(identity.UserID, peak)
	}
	return release
}

func (s *Server) trackUserRelayStream(identity authIdentity, network string) func() {
	if s == nil || s.userRelayStreamTracker == nil || identity.UserID == "" {
		return func() {}
	}
	release, peak := s.userRelayStreamTracker.acquire("user:"+identity.UserID, network)
	if peak.advanced {
		s.persistUserH2RelayPeak(identity.UserID, peak)
	}
	return release
}

func (s *Server) startH2PeakPersister() {
	if s == nil || s.h2PeakUpdates != nil {
		return
	}
	ch := make(chan userH2PeakUpdate, 4096)
	s.h2PeakUpdates = ch
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		pending := make(map[string]userH2Peak)
		flush := func() {
			for userID, peak := range pending {
				s.persistUserH2Peak(userID, peak)
				delete(pending, userID)
			}
		}
		for {
			select {
			case <-s.ctx.Done():
				flush()
				return
			case upd := <-ch:
				if upd.userID == "" {
					continue
				}
				cur := pending[upd.userID]
				if upd.peak.total > cur.total {
					cur.total = upd.peak.total
				}
				if upd.peak.tcp > cur.tcp {
					cur.tcp = upd.peak.tcp
				}
				if upd.peak.udp > cur.udp {
					cur.udp = upd.peak.udp
				}
				cur.advanced = true
				pending[upd.userID] = cur
			case <-ticker.C:
				flush()
			}
		}
	}()
}

func (s *Server) enqueueUserH2Peak(userID string, peak userH2Peak) {
	if s == nil || userID == "" || !peak.advanced {
		return
	}
	if s.h2PeakUpdates == nil {
		s.persistUserH2Peak(userID, peak)
		return
	}
	upd := userH2PeakUpdate{userID: userID, peak: peak}
	select {
	case s.h2PeakUpdates <- upd:
	default:
		go s.persistUserH2Peak(userID, peak)
	}
}

func (s *Server) persistUserH2Peak(userID string, peak userH2Peak) {
	if s == nil || s.outboundDB == nil || userID == "" || !peak.advanced {
		return
	}
	now := time.Now().Unix()
	res, err := s.outboundDB.Exec(`UPDATE users SET
        h2_peak_streams=MAX(COALESCE(h2_peak_streams, 0), ?),
        h2_peak_tcp_streams=MAX(COALESCE(h2_peak_tcp_streams, 0), ?),
        h2_peak_udp_streams=MAX(COALESCE(h2_peak_udp_streams, 0), ?),
        h2_peak_at=?,
        updated_at=?
        WHERE id=?
          AND (? > COALESCE(h2_peak_streams, 0)
            OR ? > COALESCE(h2_peak_tcp_streams, 0)
            OR ? > COALESCE(h2_peak_udp_streams, 0))`,
		peak.total, peak.tcp, peak.udp, now, now, userID,
		peak.total, peak.tcp, peak.udp)
	if err != nil {
		s.logf("[tamizdat] h2 peak update failed: %v", err)
		return
	}
	if s.userRegistry != nil {
		if rows, rerr := res.RowsAffected(); rerr == nil && rows > 0 {
			s.userRegistry.ObserveH2Peak(userID, int64(peak.total), int64(peak.tcp), int64(peak.udp), now)
		}
	}
}

func (s *Server) persistUserH2RelayPeak(userID string, peak userH2Peak) {
	if s == nil || s.outboundDB == nil || userID == "" || !peak.advanced {
		return
	}
	now := time.Now().Unix()
	res, err := s.outboundDB.Exec(`UPDATE users SET
        h2_relay_peak_streams=MAX(COALESCE(h2_relay_peak_streams, 0), ?),
        h2_relay_peak_tcp_streams=MAX(COALESCE(h2_relay_peak_tcp_streams, 0), ?),
        h2_relay_peak_udp_streams=MAX(COALESCE(h2_relay_peak_udp_streams, 0), ?),
        h2_relay_peak_at=?,
        updated_at=?
        WHERE id=?
          AND (? > COALESCE(h2_relay_peak_streams, 0)
            OR ? > COALESCE(h2_relay_peak_tcp_streams, 0)
            OR ? > COALESCE(h2_relay_peak_udp_streams, 0))`,
		peak.total, peak.tcp, peak.udp, now, now, userID,
		peak.total, peak.tcp, peak.udp)
	if err != nil {
		s.logf("[tamizdat] relay h2 peak update failed: %v", err)
		return
	}
	if s.userRegistry != nil {
		if rows, rerr := res.RowsAffected(); rerr == nil && rows > 0 {
			s.userRegistry.ObserveH2RelayPeak(userID, int64(peak.total), int64(peak.tcp), int64(peak.udp), now)
		}
	}
}
