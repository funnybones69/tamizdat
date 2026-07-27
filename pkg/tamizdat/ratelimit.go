package tamizdat

import (
	"context"
	"io"
	"sync"

	"golang.org/x/time/rate"
)

// userRateLimiters keeps a *rate.Limiter per user so all conns owned by
// the same user share one token bucket. Without sharing, each conn would
// get its own bucket and N parallel speedtest streams would burst N×cap.
//
// The map self-populates on first read; entries are dropped when a user's
// cap is set to 0 (unlimited) via setUserRateLimit, called by the userdb
// reload path. A small mutex around map writes is fine — this is at
// per-stream-establish frequency, not per-byte.
type userRateLimiters struct {
	mu       sync.RWMutex
	byUser   map[string]*rate.Limiter
	mbpsByID map[string]int
}

func newUserRateLimiters() *userRateLimiters {
	return &userRateLimiters{
		byUser:   make(map[string]*rate.Limiter),
		mbpsByID: make(map[string]int),
	}
}

// setMbps publishes a new rate limit for userID. mbps <= 0 means
// "unlimited" — any existing limiter is dropped so new reads see nil
// (= no throttling).
func (u *userRateLimiters) setMbps(userID string, mbps int) {
	if u == nil || userID == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if mbps <= 0 {
		delete(u.byUser, userID)
		delete(u.mbpsByID, userID)
		return
	}
	if existing, ok := u.mbpsByID[userID]; ok && existing == mbps {
		return // unchanged, keep existing limiter (preserves token bucket state)
	}
	bytesPerSec := float64(mbps) * 125_000.0 // 1 Mbit = 125_000 bytes
	// Burst = 1 second of allowance. Big enough for clean speedtest bursts
	// but small enough that average rate honors the cap over a minute.
	burst := int(bytesPerSec)
	u.byUser[userID] = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
	u.mbpsByID[userID] = mbps
}

// limiter returns the per-user limiter or nil for unlimited users.
func (u *userRateLimiters) limiter(userID string) *rate.Limiter {
	if u == nil || userID == "" {
		return nil
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.byUser[userID]
}

// userRateLimiter is the Server-side accessor used by handleTCPConnect /
// handleUDPCONNECT. Returns nil for users without a configured cap.
func (s *Server) userRateLimiter(userID string) *rate.Limiter {
	if s == nil || s.rateLimits == nil {
		return nil
	}
	return s.rateLimits.limiter(userID)
}

// rateLimitedReader is an io.Reader that consumes tokens from a
// *rate.Limiter before returning bytes. We use the limiter's WaitN with
// a background context so throttling can sleep arbitrarily — io.Copy
// just sees slower reads. Read sizes are capped at burst so WaitN never
// rejects the request synchronously.
type rateLimitedReader struct {
	r       io.Reader
	limiter *rate.Limiter
	maxN    int // burst, so WaitN never returns "request larger than burst"
}

func newRateLimitedReader(r io.Reader, lim *rate.Limiter) io.Reader {
	maxN := lim.Burst()
	if maxN <= 0 {
		maxN = 64 * 1024
	}
	return &rateLimitedReader{r: r, limiter: lim, maxN: maxN}
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	if len(p) > r.maxN {
		p = p[:r.maxN]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		// Best-effort throttle. Context.Background means an absurdly low
		// rate against a stuck reader could block forever, but a panic-
		// proof outer io.Copy is supposed to honor the context the conn
		// itself carries (read deadline). Real impact: cap saturates with
		// a few ms of sleep per read.
		_ = r.limiter.WaitN(context.Background(), n)
	}
	return n, err
}
