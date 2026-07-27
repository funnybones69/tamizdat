package wgturnclient

import (
	"context"
	"testing"
	"time"
)

func TestCredentialReuseDuration(t *testing.T) {
	for _, tc := range []struct {
		lifetime int
		want     time.Duration
	}{
		{600, 480 * time.Second},
		{240, 210 * time.Second},
		{60, 55 * time.Second},
		{3, 5 * time.Second},
		{0, 480 * time.Second},
	} {
		if got := credentialReuseDuration(&Credentials{Lifetime: tc.lifetime}); got != tc.want {
			t.Fatalf("lifetime=%d reuse=%s want=%s", tc.lifetime, got, tc.want)
		}
	}
}

func TestPreloadedCredentialsExpireAndAreDeepCopied(t *testing.T) {
	r := &Runner{}
	original := &Credentials{
		User:        "user",
		Pass:        "pass",
		TurnURLs:    []string{"turn.example:3478"},
		TurnServers: []TurnServer{{Host: "turn.example", Port: 3478, Scheme: "turn", Transport: "udp"}},
		Lifetime:    600,
	}
	r.UpdatePreloadedCreds(original)

	got := r.currentPreloadedCreds()
	if got == nil || got.User != "user" || len(got.TurnServers) != 1 {
		t.Fatalf("unexpected cached credentials: %#v", got)
	}
	got.TurnURLs[0] = "mutated"
	got.TurnServers[0].Host = "mutated"
	again := r.currentPreloadedCreds()
	if again.TurnURLs[0] != "turn.example:3478" || again.TurnServers[0].Host != "turn.example" {
		t.Fatalf("cache aliases returned slices: %#v", again)
	}

	r.preloadedCredsExpiry.Store(time.Now().Add(-time.Second).UnixNano())
	if expired := r.currentPreloadedCreds(); expired != nil {
		t.Fatalf("expired credentials returned: %#v", expired)
	}
}

func TestNormalizeWorkerCountClampsAtRouterMaximum(t *testing.T) {
	if got := normalizeWorkerCount(100); got != 20 {
		t.Fatalf("normalizeWorkerCount(100)=%d want=20", got)
	}
	if got := normalizeWorkerCount(1); got != 1 {
		t.Fatalf("normalizeWorkerCount(1)=%d want=1", got)
	}
}

func TestCredentialModeValidation(t *testing.T) {
	base := Config{
		PeerAddr: "127.0.0.1:443",
		VKHashes: []string{"room"},
	}
	for _, mode := range []string{"", "auto", "anonymous-only", "rjs-only"} {
		cfg := base
		cfg.CredentialMode = mode
		r, err := New(cfg)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		want := mode
		if want == "" {
			want = "auto"
		}
		if got := r.getCredentialMode(); got != want {
			t.Fatalf("mode %q normalized to %q, want %q", mode, got, want)
		}
	}
	bad := base
	bad.CredentialMode = "account"
	if _, err := New(bad); err == nil {
		t.Fatal("invalid credential mode accepted")
	}
}

func TestExternalRoomCredentialHelperFeedsMultiRoomCache(t *testing.T) {
	calls := 0
	r, err := New(Config{
		PeerAddr:       "127.0.0.1:443",
		VKHashes:       []string{"room"},
		WorkersPerRoom: 20,
		UseUDP:         true,
		AcquireRoomCredentials: func(_ context.Context, hash string) (*Credentials, error) {
			calls++
			if hash != "room" {
				t.Fatalf("helper hash = %q, want room", hash)
			}
			return &Credentials{
				User: "helper-user", Pass: "helper-pass", Source: "helper",
				TurnURLs: []string{"turn.example:3478"}, Lifetime: 600,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.getCredsWithFallback(context.Background(), &TurnParams{}, "room", NewStats())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got == nil || got.User != "helper-user" || got.Source != "helper" {
		t.Fatalf("external helper was not used: calls=%d creds=%#v", calls, got)
	}
	got.User = "mutated"
	if cached := r.currentRoomCreds("room"); cached == nil || cached.User != "helper-user" {
		t.Fatalf("room cache aliases helper result: %#v", cached)
	}
}
