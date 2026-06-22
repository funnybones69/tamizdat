package vkturn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// persistentCreds is the on-disk schema for cached VK TURN credentials.
//
// The file is written with mode 0600 because User/Pass are secret-capable
// (they authenticate to VK's TURN relays). The cache exists so a router can
// bootstrap the VK TURN transport after a process restart — or after a
// network whitelist cuts off every path except VK itself — without having to
// re-solve a VK captcha. Captchas are gated at credential acquisition, not at
// traffic time, so a persisted credential lets the relay run for the whole
// remaining lifetime with zero VK API contact.
type persistentCreds struct {
	User       string    `json:"turn_user"`
	Pass       string    `json:"turn_pass"`
	TurnURLs   []string  `json:"turn_urls"`
	Lifetime   int       `json:"lifetime"`
	HashDigest string    `json:"hash_digest,omitempty"` // sha256(hash)[:16], provenance only — never the raw hash
	FetchedAt  time.Time `json:"fetched_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (p *persistentCreds) toCredentials() *Credentials {
	if p == nil {
		return nil
	}
	return &Credentials{
		User:     p.User,
		Pass:     p.Pass,
		TurnURLs: append([]string(nil), p.TurnURLs...),
		Lifetime: p.Lifetime,
		Fetched:  p.FetchedAt,
	}
}

// hashDigest returns a stable, non-reversible tag for a VK call hash so the
// cache can record which call link the credentials belong to without ever
// persisting the raw hash.
func hashDigest(hash string) string {
	if hash == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:8])
}

// loadPersistentCreds reads and parses a credential cache file. A missing or
// corrupt file returns an error; callers treat that as "no cache".
func loadPersistentCreds(path string) (*persistentCreds, error) {
	if path == "" {
		return nil, fmt.Errorf("vkturn: empty cred cache path")
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pc persistentCreds
	if err := json.Unmarshal(buf, &pc); err != nil {
		return nil, fmt.Errorf("vkturn: parse cred cache: %w", err)
	}
	if pc.User == "" || pc.Pass == "" || len(pc.TurnURLs) == 0 {
		return nil, fmt.Errorf("vkturn: cred cache missing user/pass/urls")
	}
	return &pc, nil
}

// savePersistentCreds writes credentials to disk atomically (temp file +
// rename) with mode 0600. The parent directory is created if needed. It is
// best-effort from the caller's perspective: a failure to persist must not
// fail credential acquisition, only forgo restart survival.
func savePersistentCreds(path string, pc *persistentCreds) error {
	if path == "" {
		return fmt.Errorf("vkturn: empty cred cache path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vkturn: mkdir cred cache dir: %w", err)
	}
	buf, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return fmt.Errorf("vkturn: marshal cred cache: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".vkturn-creds-*.tmp")
	if err != nil {
		return fmt.Errorf("vkturn: create cred cache temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("vkturn: chmod cred cache temp: %w", err)
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return fmt.Errorf("vkturn: write cred cache temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vkturn: sync cred cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vkturn: close cred cache temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("vkturn: rename cred cache: %w", err)
	}
	return nil
}

// credBackoffDuration returns how long to suppress VK acquisition after
// `fails` consecutive failures. This is the storm-killer: a failed acquisition
// (captcha rejection, BOT detection, network error) must not be retried by the
// next dial — every retry from one IP raises VK's bot risk score and triggers
// *more* captchas, a positive-feedback loop. Schedule: 30s, 1m, 2m, 4m, 8m,
// 16m, capped at 30m.
func credBackoffDuration(fails int) time.Duration {
	if fails <= 0 {
		return 0
	}
	shift := fails - 1
	if shift > 6 {
		shift = 6
	}
	d := 30 * time.Second << uint(shift)
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// defaultCredReuse is how long credentials are reused when VK reports a
// lifetime that is missing or implausibly small (<=120s). VK's advertised
// `lifetime` is unreliable and the TURN allocation is kept warm by periodic
// binding requests, so a conservative fixed reuse window avoids needless
// re-acquisition (and thus needless captchas).
const defaultCredReuse = 30 * time.Minute

// credentialAcquireTimeout is the long control-plane budget for obtaining VK
// TURN credentials. It must be independent from per-flow DialContext deadlines:
// transparent-routing health probes and user TCP dials often use 5s-ish
// deadlines, while VK captcha/auth can take minutes. Binding credential
// acquisition to the short dial context cancels the solver, then the next dial
// starts a brand-new VK challenge — the captcha storm observed on the Keenetic.
// Singleflight acquisition runs under this longer budget; individual dials may
// time out while the one shared acquisition continues in the background.
const credentialAcquireTimeout = 15 * time.Minute

// credExpiry computes the local reuse deadline for a freshly acquired
// credential. A 120s safety margin is subtracted from VK's advertised lifetime
// so the relay rotates before VK actually revokes the credential mid-flight.
func credExpiry(creds *Credentials, now time.Time) time.Time {
	if creds != nil && creds.Lifetime > 120 {
		return now.Add(time.Duration(creds.Lifetime-120) * time.Second)
	}
	return now.Add(defaultCredReuse)
}
