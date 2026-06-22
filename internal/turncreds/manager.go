package turncreds

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/internal/vkcreds"
	tamizdat "github.com/funnybones69/tamizdat/pkg/tamizdat"
)

// Manager periodically fetches VK TURN credentials and caches them
// for thread-safe read access. It is always instantiated at server
// boot (even when disabled) so SIGHUP can hot-enable it without a
// server restart.
type Manager struct {
	mu              sync.RWMutex
	creds           *vkcreds.Credentials
	fetchedAt       time.Time
	expiresAt       time.Time
	lastErr         error
	lastErrAt       time.Time
	fetchCount      uint64
	errorCount      uint64
	consecutiveErrs uint64

	cfg     atomic.Pointer[vkcreds.Config]
	hash    atomic.Value // string
	enabled atomic.Bool

	refreshCh chan struct{} // non-blocking signal for ForceRefresh
	cancel    context.CancelFunc
	done      chan struct{}
}

// ManagerStatus is the JSON-serialisable snapshot returned by Status().
type ManagerStatus struct {
	Enabled     bool      `json:"enabled"`
	HasCreds    bool      `json:"has_creds"`
	TurnURLs    []string  `json:"turn_urls,omitempty"`
	Username    string    `json:"username,omitempty"`
	Lifetime    int       `json:"lifetime_seconds,omitempty"`
	FetchedAt   time.Time `json:"fetched_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
	FetchCount  uint64    `json:"fetch_count"`
	ErrorCount  uint64    `json:"error_count"`
}

// NewManager creates a Manager. Call Start to begin the background
// refresh loop. The Manager can be created in disabled state and
// hot-enabled later via Reload.
func NewManager(cfg *vkcreds.Config, hash string, enabled bool) *Manager {
	m := &Manager{
		refreshCh: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	m.cfg.Store(cfg)
	m.hash.Store(hash)
	m.enabled.Store(enabled)
	return m
}

// Start launches the background refresh goroutine. It returns
// immediately; the goroutine runs until Stop is called or ctx is
// cancelled.
func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	go m.run(ctx)
}

// Stop cancels the background goroutine and waits for it to exit.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	<-m.done
}

// Reload atomically updates the VK configuration and call hash. When
// transitioning to enabled, a forced refresh is triggered. When
// transitioning to disabled, cached credentials are cleared.
func (m *Manager) Reload(cfg *vkcreds.Config, hash string, enabled bool) {
	m.cfg.Store(cfg)
	m.hash.Store(hash)
	wasEnabled := m.enabled.Swap(enabled)

	if enabled {
		m.ForceRefresh()
	} else if wasEnabled {
		m.mu.Lock()
		m.creds = nil
		m.lastErr = nil
		m.mu.Unlock()
		log.Printf("[turncreds] disabled by settings reload")
	}
}

// ForceRefresh triggers an immediate credential fetch on the next
// loop iteration. Non-blocking; safe to call from any goroutine.
func (m *Manager) ForceRefresh() {
	select {
	case m.refreshCh <- struct{}{}:
	default:
	}
}

// CurrentTURNCreds returns the latest cached TURN credentials
// converted to a TURNCredsEntry suitable for the CoverConfigBundle,
// or nil when no credentials are available (disabled, not yet fetched,
// or expired). Implements tamizdat.TURNCredsProvider.
func (m *Manager) CurrentTURNCreds() *tamizdat.TURNCredsEntry {
	if !m.enabled.Load() {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.creds == nil {
		return nil
	}
	if !m.expiresAt.IsZero() && time.Now().After(m.expiresAt) {
		return nil // truly expired — don't serve stale creds
	}
	return &tamizdat.TURNCredsEntry{
		Username: m.creds.User,
		Password: m.creds.Pass,
		URLs:     m.creds.TurnURLs,
		Lifetime: m.creds.Lifetime,
	}
}

// Status returns a snapshot of the manager state for admin/debug
// endpoints. The username is truncated to 8 characters for safety.
func (m *Manager) Status() ManagerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := ManagerStatus{
		Enabled:    m.enabled.Load(),
		HasCreds:   m.creds != nil,
		FetchCount: m.fetchCount,
		ErrorCount: m.errorCount,
	}
	if m.creds != nil {
		s.TurnURLs = m.creds.TurnURLs
		s.Lifetime = m.creds.Lifetime
		s.FetchedAt = m.fetchedAt
		s.ExpiresAt = m.expiresAt
		if len(m.creds.User) > 8 {
			s.Username = m.creds.User[:8] + "..."
		} else {
			s.Username = m.creds.User
		}
	}
	if m.lastErr != nil {
		s.LastError = m.lastErr.Error()
		s.LastErrorAt = m.lastErrAt
	}
	return s
}

// run is the background refresh loop.
func (m *Manager) run(ctx context.Context) {
	defer close(m.done)

	// Immediate first fetch if enabled.
	if m.enabled.Load() {
		m.doFetch(ctx)
	}

	for {
		nextRefresh := m.computeNextRefresh()

		timer := time.NewTimer(nextRefresh)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.refreshCh:
			timer.Stop()
		case <-timer.C:
		}

		if ctx.Err() != nil {
			return
		}
		if m.enabled.Load() {
			m.doFetch(ctx)
		}
	}
}

// computeNextRefresh returns the duration until the next fetch attempt.
func (m *Manager) computeNextRefresh() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.creds != nil && m.creds.Lifetime > 0 {
		// Refresh at 80% of lifetime.
		fullLife := time.Duration(m.creds.Lifetime) * time.Second
		target := time.Duration(float64(fullLife) * 0.8)
		elapsed := time.Since(m.fetchedAt)
		d := target - elapsed
		if d < 30*time.Second {
			d = 30 * time.Second
		}
		return d
	}

	if m.lastErr != nil {
		// Exponential backoff: 30s, 60s, 120s, 240s, 300s cap.
		shift := m.consecutiveErrs
		if shift > 4 {
			shift = 4
		}
		backoff := 30 * time.Second * time.Duration(1<<shift)
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
		return backoff
	}

	// No creds, no error (disabled or just started): poll every 60s.
	return 60 * time.Second
}

// doFetch calls vkcreds.GetCredentials and updates the cached state.
func (m *Manager) doFetch(ctx context.Context) {
	hash, _ := m.hash.Load().(string)
	if hash == "" {
		m.mu.Lock()
		m.lastErr = fmt.Errorf("turn_vk_call_hash is empty")
		m.lastErrAt = time.Now()
		m.mu.Unlock()
		return
	}

	cfg := m.cfg.Load()
	if cfg == nil || cfg.AppID == "" || cfg.AppSecret == "" {
		m.mu.Lock()
		m.lastErr = fmt.Errorf("VK credentials not configured (app_id or app_secret empty)")
		m.lastErrAt = time.Now()
		m.mu.Unlock()
		return
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	creds, err := vkcreds.GetCredentials(fetchCtx, cfg, hash)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchCount++

	if err != nil {
		m.errorCount++
		m.consecutiveErrs++
		m.lastErr = err
		m.lastErrAt = time.Now()
		log.Printf("[turncreds] fetch #%d failed: %v", m.fetchCount, err)
		return
	}

	m.consecutiveErrs = 0
	m.creds = creds
	m.fetchedAt = time.Now()
	if creds.Lifetime > 0 {
		m.expiresAt = m.fetchedAt.Add(time.Duration(creds.Lifetime) * time.Second)
	} else {
		m.expiresAt = m.fetchedAt.Add(1 * time.Hour) // fallback: 1h
	}
	m.lastErr = nil
	log.Printf("[turncreds] credentials refreshed (#%d): %d TURN URLs, lifetime %ds, expires %s",
		m.fetchCount, len(creds.TurnURLs), creds.Lifetime, m.expiresAt.Format(time.RFC3339))
}
