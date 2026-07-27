package tamizdat

import (
	"fmt"
	"sync"
	"time"
)

type outboundStreamTracker struct {
	mu    sync.Mutex
	byTag map[string]*outboundStreamCounts
}

type outboundStreamCounts struct {
	tcp       int
	udp       int
	peakTotal int
	peakTCP   int
	peakUDP   int

	dialFailedTCP uint64
	dialFailedUDP uint64
	lastFailedAt  int64
	lastFailedNet string
	lastFailedErr string
}

type outboundStreamPeak struct {
	total    int
	tcp      int
	udp      int
	advanced bool
}

type outboundStreamSnapshot struct {
	liveTotal     int
	liveTCP       int
	liveUDP       int
	peakTotal     int
	peakTCP       int
	peakUDP       int
	dialFailedTCP uint64
	dialFailedUDP uint64
	lastFailedAt  int64
	lastFailedNet string
	lastFailedErr string
}

func newOutboundStreamTracker() *outboundStreamTracker {
	return &outboundStreamTracker{byTag: make(map[string]*outboundStreamCounts)}
}

func (t *outboundStreamTracker) acquire(tag, network string) (func(), outboundStreamPeak) {
	if t == nil || tag == "" {
		return func() {}, outboundStreamPeak{}
	}
	t.mu.Lock()
	c := t.byTag[tag]
	if c == nil {
		c = &outboundStreamCounts{}
		t.byTag[tag] = c
	}
	if network == "udp" {
		c.udp++
	} else {
		c.tcp++
	}
	total := c.tcp + c.udp
	peak := outboundStreamPeak{
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
			t.release(tag, network)
		})
	}, peak
}

func (t *outboundStreamTracker) release(tag, network string) {
	if t == nil || tag == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byTag[tag]
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

func (t *outboundStreamTracker) recordDialFailure(tag, network string, err error) {
	if t == nil || tag == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byTag[tag]
	if c == nil {
		c = &outboundStreamCounts{}
		t.byTag[tag] = c
	}
	if network == "udp" {
		c.dialFailedUDP++
	} else {
		c.dialFailedTCP++
	}
	c.lastFailedAt = time.Now().Unix()
	c.lastFailedNet = network
	if err != nil {
		c.lastFailedErr = fmt.Sprintf("%.240s", err.Error())
	} else {
		c.lastFailedErr = ""
	}
}

func (t *outboundStreamTracker) snapshot(tag string) outboundStreamSnapshot {
	if t == nil || tag == "" {
		return outboundStreamSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byTag[tag]
	if c == nil {
		return outboundStreamSnapshot{}
	}
	return outboundStreamSnapshot{
		liveTotal:     c.tcp + c.udp,
		liveTCP:       c.tcp,
		liveUDP:       c.udp,
		peakTotal:     c.peakTotal,
		peakTCP:       c.peakTCP,
		peakUDP:       c.peakUDP,
		dialFailedTCP: c.dialFailedTCP,
		dialFailedUDP: c.dialFailedUDP,
		lastFailedAt:  c.lastFailedAt,
		lastFailedNet: c.lastFailedNet,
		lastFailedErr: c.lastFailedErr,
	}
}

func (s *Server) trackOutboundStream(tag, network string) func() {
	if s == nil || s.outboundStreamTracker == nil {
		return func() {}
	}
	release, peak := s.outboundStreamTracker.acquire(tag, network)
	if peak.advanced && s.outboundDB != nil {
		s.persistOutboundStreamPeak(tag, peak)
	}
	return release
}

func (s *Server) recordOutboundDialFailure(tag, network string, err error) {
	if s == nil || s.outboundStreamTracker == nil {
		return
	}
	s.outboundStreamTracker.recordDialFailure(tag, network, err)
}

func (s *Server) persistOutboundStreamPeak(tag string, peak outboundStreamPeak) {
	if s == nil || s.outboundDB == nil || tag == "" || !peak.advanced {
		return
	}
	now := time.Now().Unix()
	_, err := s.outboundDB.Exec(`UPDATE outbounds SET
        h2_peak_streams=MAX(COALESCE(h2_peak_streams, 0), ?),
        h2_peak_tcp_streams=MAX(COALESCE(h2_peak_tcp_streams, 0), ?),
        h2_peak_udp_streams=MAX(COALESCE(h2_peak_udp_streams, 0), ?),
        h2_peak_at=?,
        updated_at=?
        WHERE tag=?
          AND (? > COALESCE(h2_peak_streams, 0)
            OR ? > COALESCE(h2_peak_tcp_streams, 0)
            OR ? > COALESCE(h2_peak_udp_streams, 0))`,
		peak.total, peak.tcp, peak.udp, now, now, tag,
		peak.total, peak.tcp, peak.udp)
	if err != nil {
		s.logf("[tamizdat] outbound h2 peak update failed: %v", err)
	}
}
