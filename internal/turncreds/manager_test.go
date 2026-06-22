package turncreds

import (
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/vkcreds"
)

func TestManager_DisabledReturnsNil(t *testing.T) {
	cfg := &vkcreds.Config{
		AppID:     "test",
		AppSecret: "test",
		DeviceID:  "test",
	}
	m := NewManager(cfg, "testhash", false)
	if got := m.CurrentTURNCreds(); got != nil {
		t.Fatalf("disabled manager returned non-nil creds: %+v", got)
	}

	s := m.Status()
	if s.Enabled {
		t.Fatal("status.Enabled should be false")
	}
	if s.HasCreds {
		t.Fatal("status.HasCreds should be false")
	}
}

func TestManager_StatusFields(t *testing.T) {
	cfg := &vkcreds.Config{
		AppID:     "test",
		AppSecret: "test",
		DeviceID:  "test",
	}
	m := NewManager(cfg, "testhash", true)

	// Simulate successful fetch by writing directly to internal state.
	m.mu.Lock()
	m.creds = &vkcreds.Credentials{
		User:     "testuser123456",
		Pass:     "testpass",
		TurnURLs: []string{"turn:relay1.ok.ru:3478"},
		Lifetime: 3600,
	}
	m.fetchedAt = time.Now()
	m.expiresAt = time.Now().Add(time.Hour)
	m.fetchCount = 1
	m.mu.Unlock()

	entry := m.CurrentTURNCreds()
	if entry == nil {
		t.Fatal("expected non-nil TURNCreds")
	}
	if entry.Username != "testuser123456" {
		t.Fatalf("username = %q, want testuser123456", entry.Username)
	}
	if entry.Password != "testpass" {
		t.Fatalf("password = %q, want testpass", entry.Password)
	}
	if len(entry.URLs) != 1 || entry.URLs[0] != "turn:relay1.ok.ru:3478" {
		t.Fatalf("urls = %v, want [turn:relay1.ok.ru:3478]", entry.URLs)
	}
	if entry.Lifetime != 3600 {
		t.Fatalf("lifetime = %d, want 3600", entry.Lifetime)
	}

	s := m.Status()
	if !s.Enabled {
		t.Fatal("status.Enabled should be true")
	}
	if !s.HasCreds {
		t.Fatal("status.HasCreds should be true")
	}
	if s.FetchCount != 1 {
		t.Fatalf("FetchCount = %d, want 1", s.FetchCount)
	}
	// Username should be truncated in status.
	if s.Username != "testuser..." {
		t.Fatalf("status username = %q, want testuser...", s.Username)
	}
}

func TestManager_ExpiredCredsReturnNil(t *testing.T) {
	cfg := &vkcreds.Config{
		AppID:     "test",
		AppSecret: "test",
		DeviceID:  "test",
	}
	m := NewManager(cfg, "testhash", true)

	// Simulate expired credentials.
	m.mu.Lock()
	m.creds = &vkcreds.Credentials{
		User:     "expired",
		Pass:     "expired",
		TurnURLs: []string{"turn:relay.ok.ru:3478"},
		Lifetime: 1,
	}
	m.fetchedAt = time.Now().Add(-2 * time.Hour)
	m.expiresAt = time.Now().Add(-1 * time.Hour)
	m.mu.Unlock()

	if got := m.CurrentTURNCreds(); got != nil {
		t.Fatalf("expired creds should return nil, got: %+v", got)
	}
}

func TestManager_ReloadDisablesClearsCreds(t *testing.T) {
	cfg := &vkcreds.Config{
		AppID:     "test",
		AppSecret: "test",
		DeviceID:  "test",
	}
	m := NewManager(cfg, "testhash", true)

	// Simulate cached creds.
	m.mu.Lock()
	m.creds = &vkcreds.Credentials{
		User:     "user",
		Pass:     "pass",
		TurnURLs: []string{"turn:r.ok.ru:3478"},
		Lifetime: 3600,
	}
	m.expiresAt = time.Now().Add(time.Hour)
	m.mu.Unlock()

	if m.CurrentTURNCreds() == nil {
		t.Fatal("creds should be non-nil before reload")
	}

	// Disable via reload.
	m.Reload(cfg, "newhash", false)

	if got := m.CurrentTURNCreds(); got != nil {
		t.Fatalf("after disabling, creds should be nil, got: %+v", got)
	}
}

func TestManager_ComputeNextRefresh(t *testing.T) {
	cfg := &vkcreds.Config{
		AppID:     "test",
		AppSecret: "test",
		DeviceID:  "test",
	}
	m := NewManager(cfg, "testhash", true)

	// No creds, no error → 60s default.
	d := m.computeNextRefresh()
	if d != 60*time.Second {
		t.Fatalf("no creds/no error: got %v, want 60s", d)
	}

	// With creds, lifetime 3600s → ~2880s (80%).
	m.mu.Lock()
	m.creds = &vkcreds.Credentials{Lifetime: 3600}
	m.fetchedAt = time.Now()
	m.mu.Unlock()

	d = m.computeNextRefresh()
	// Should be close to 2880s (80% of 3600).
	if d < 2800*time.Second || d > 2900*time.Second {
		t.Fatalf("with 3600s lifetime: got %v, want ~2880s", d)
	}

	// With error → backoff starting at 30s.
	m.mu.Lock()
	m.creds = nil
	m.lastErr = errTest
	m.consecutiveErrs = 0
	m.mu.Unlock()

	d = m.computeNextRefresh()
	if d != 30*time.Second {
		t.Fatalf("first error backoff: got %v, want 30s", d)
	}

	// Second consecutive error → 60s.
	m.mu.Lock()
	m.consecutiveErrs = 1
	m.mu.Unlock()

	d = m.computeNextRefresh()
	if d != 60*time.Second {
		t.Fatalf("second error backoff: got %v, want 60s", d)
	}
}

var errTest = func() error {
	return &testError{}
}()

type testError struct{}

func (e *testError) Error() string { return "test error" }
