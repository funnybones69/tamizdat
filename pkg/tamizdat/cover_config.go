package tamizdat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	configAuthority        = "tamizdat-config.invalid:443"
	SamizdatProtocolConfig = "config/1"
	// MaxCoverConfigBundleBytes caps the wire size of the bundle. Bumped from
	// 4096 to 8192 in 2026-05-09 to give room for the optional
	// fingerprint_pool / ttl_seconds / expires_at fields without crowding the
	// existing sni_pool. Old bundles parse fine; only the upper bound moved.
	MaxCoverConfigBundleBytes = 8192
)

// CoverConfigBundle is the server-pushed config bundle JSON v1.
//
// Shortid full-B simplification (2026-05-09): the legacy `epoch_key` and
// `shortid_pool_size` fields are no longer modelled. Old bundles containing
// them parse fine (encoding/json ignores unknown fields) — they are tolerated
// for backward-compat but ignored.
//
// Server-pushes-pool (2026-05-09): added optional FingerprintPool, TTLSeconds,
// ExpiresAt fields. Older clients ignore unknown fields; new clients use them
// to rotate uTLS fingerprints from a server-curated weighted pool and to
// detect stale on-disk cache entries.
type CoverConfigBundle struct {
	Version         int                `json:"version"`
	TTLSeconds      int                `json:"ttl_seconds,omitempty"`
	ExpiresAt       int64              `json:"expires_at,omitempty"`
	SNIPool         []SNIEntry         `json:"sni_pool,omitempty"`
	FingerprintPool []FingerprintEntry `json:"fingerprint_pool,omitempty"`
	CoverTargets    []string           `json:"cover_targets,omitempty"`
	CoverGapMinMS   int                `json:"cover_gap_min_ms,omitempty"`
	CoverGapMaxMS   int                `json:"cover_gap_max_ms,omitempty"`

	// PoolVariant is server-authoritative transport pool strategy
	// (2026-05-11): "v1" pins 1 H2 transport, "v2" allows 1-2, "v3"
	// pre-warms 2 up to 4. Empty = client default (V1). Operators flip
	// the server-side `inbound_pool_variant` setting in the panel to
	// push v2/v3 to all connected clients on next bundle fetch.
	PoolVariant string `json:"pool_variant,omitempty"`

	// MinTransports / MaxTransports let the server push an exact H2 transport
	// count to a client. When both are set and equal the client uses that many
	// persistent H2 transports immediately; the PoolVariant seam remains only
	// for backward-compat with older bundles.
	MinTransports int `json:"min_transports,omitempty"`
	MaxTransports int `json:"max_transports,omitempty"`

	// Notification is a one-shot per-user message piggy-backed on the
	// bundle (Stage 3, 2026-05-10). When set, the client SHOULD display
	// it to the user once and dismiss. Server injects per-user when the
	// caller's users.notification_pending=1 (e.g. quota exhausted) and
	// clears the pending flag after a successful body write. Empty in
	// the cached/global bundle; populated by buildBundleForIdentity.
	Notification *NotificationEntry `json:"notification,omitempty"`

	// TURNCreds carries VK TURN relay credentials obtained by the
	// server's turncreds.Manager. Clients that support TURN-based
	// transport use these to establish relay connections through VK
	// infrastructure. Older clients silently ignore the field.
	TURNCreds *TURNCredsEntry `json:"turn_creds,omitempty"`

	// TURNProfile is an operator-pushed per-user TURN room profile. It carries
	// only Tamizdat-owned data: the room/link, monotonically increasing version,
	// and wgturn port advertised by this server's settings. Clients derive peer
	// host/auth from their existing tamizdat:// profile; the panel does not expose
	// peer/password fields. Older clients silently ignore the field.
	TURNProfile *TURNProfileEntry `json:"turn_profile,omitempty"`
}

// TURNCredsEntry carries TURN relay credentials for client-side TURN
// transport. Lifetime is in seconds from the time the credentials
// were issued by VK; clients should re-fetch the bundle before
// lifetime expires to obtain fresh credentials.
type TURNCredsEntry struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	Lifetime int      `json:"lifetime"`
}

// TURNProfileEntry carries a per-user TURN room update pushed from the panel.
// It intentionally omits peer/password UI fields: wgturn is part of this
// Tamizdat server, so clients derive peer host from their existing H2 URI and
// authenticate with the user's master shortID.
type TURNProfileEntry struct {
	Version    int    `json:"version"`
	Provider   string `json:"provider,omitempty"`
	RoomLink   string `json:"room_link,omitempty"`
	RoomHash   string `json:"room_hash,omitempty"`
	WGTurnPort int    `json:"wgturn_port,omitempty"`
}

// NotificationEntry is a one-shot user-facing message delivered via the
// bundle (Stage 3, 2026-05-10).
//
//   - Code:     machine-readable cause, e.g. "quota_exhausted",
//     "expired", "admin_broadcast". Stable across versions
//     so the client can render localized titles/bodies of
//     its own if it prefers over server-supplied text.
//   - Title:    short human-readable title for an OS-level banner.
//   - Body:     longer free-form text, may be empty.
//   - Locale:   BCP-47 hint ("ru", "en", …) for the title/body the
//     server picked. Client may ignore and pick by Code.
//
// Wire size budget: kept compact so the whole bundle still fits under
// MaxCoverConfigBundleBytes (8 KiB).
type NotificationEntry struct {
	Code   string `json:"code"`
	Title  string `json:"title,omitempty"`
	Body   string `json:"body,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// FingerprintEntry is a single weighted entry in the server-pushed
// fingerprint_pool. ID matches a known uTLS HelloID alias known to the
// client (e.g. "chrome_auto", "chrome_131", "chrome_120_pq", "firefox_120",
// "safari_16_0", "ios_14", "edge_106"). Unknown IDs are skipped silently
// so a server can advertise newer fingerprints to clients that don't know
// them yet without breaking old clients.
type FingerprintEntry struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
}

func LoadCoverConfig(path string) (*CoverConfigBundle, error) {
	return loadCoverConfig(path, nil, false)
}

func LoadCoverConfigWithMasquerade(path string, masqPool map[string]string) (*CoverConfigBundle, error) {
	return loadCoverConfig(path, masqPool, true)
}

func loadCoverConfig(path string, masqPool map[string]string, checkMasq bool) (*CoverConfigBundle, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cover config: %w", err)
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return nil, fmt.Errorf("cover config too large: %d > %d bytes", len(buf), MaxCoverConfigBundleBytes)
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(buf, &bundle); err != nil {
		return nil, fmt.Errorf("parse cover config: %w", err)
	}
	if err := bundle.Validate(masqPool, checkMasq); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (b *CoverConfigBundle) Validate(masqPool map[string]string, checkMasq bool) error {
	if b == nil {
		return fmt.Errorf("cover config: nil bundle")
	}
	if b.Version != 1 {
		return fmt.Errorf("cover config: version must be 1, got %d", b.Version)
	}
	// Shortid full-B simplification (2026-05-09): epoch_key and
	// shortid_pool_size fields are no longer modelled or validated. Old
	// on-disk bundles containing them parse fine (encoding/json ignores
	// unknown fields by default) — fields silently dropped.
	if checkMasq {
		for _, e := range b.SNIPool {
			if strings.TrimSpace(e.SNI) == "" {
				return fmt.Errorf("cover config: sni_pool contains empty sni")
			}
			if _, ok := masqPool[e.SNI]; !ok {
				return fmt.Errorf("cover config: sni_pool entry %q is not present in masquerade pool", e.SNI)
			}
		}
	}
	for _, target := range b.CoverTargets {
		if err := validateHostPort(target); err != nil {
			return fmt.Errorf("cover config: cover_target %q: %w", target, err)
		}
	}
	if b.CoverGapMinMS != 0 || b.CoverGapMaxMS != 0 {
		if b.CoverGapMinMS < 1 || b.CoverGapMinMS > 600000 {
			return fmt.Errorf("cover config: cover_gap_min_ms %d out of range [1,600000]", b.CoverGapMinMS)
		}
		if b.CoverGapMaxMS < 1 || b.CoverGapMaxMS > 600000 {
			return fmt.Errorf("cover config: cover_gap_max_ms %d out of range [1,600000]", b.CoverGapMaxMS)
		}
		if b.CoverGapMinMS > b.CoverGapMaxMS {
			return fmt.Errorf("cover config: cover_gap_min_ms greater than cover_gap_max_ms")
		}
	}
	if b.TTLSeconds < 0 {
		return fmt.Errorf("cover config: ttl_seconds must be non-negative, got %d", b.TTLSeconds)
	}
	if b.TTLSeconds > 86400 {
		return fmt.Errorf("cover config: ttl_seconds %d out of range [0,86400]", b.TTLSeconds)
	}
	if b.MinTransports < 0 {
		return fmt.Errorf("cover config: min_transports must be non-negative, got %d", b.MinTransports)
	}
	if b.MaxTransports < 0 {
		return fmt.Errorf("cover config: max_transports must be non-negative, got %d", b.MaxTransports)
	}
	if b.MinTransports > 0 && b.MaxTransports > 0 && b.MaxTransports < b.MinTransports {
		return fmt.Errorf("cover config: max_transports below min_transports")
	}
	for _, fp := range b.FingerprintPool {
		if strings.TrimSpace(fp.ID) == "" {
			return fmt.Errorf("cover config: fingerprint_pool entry has empty id")
		}
		if fp.Weight < 0 {
			return fmt.Errorf("cover config: fingerprint_pool entry %q has negative weight %d", fp.ID, fp.Weight)
		}
	}
	if b.Notification != nil {
		if strings.TrimSpace(b.Notification.Code) == "" {
			return fmt.Errorf("cover config: notification.code is required when notification is set")
		}
		// Title+Body+Locale are free-form; clip server-side rather than reject.
	}
	if b.TURNProfile != nil {
		p := b.TURNProfile
		if p.Version < 0 {
			return fmt.Errorf("cover config: turn_profile.version must be non-negative")
		}
		if strings.TrimSpace(p.Provider) != "" && strings.TrimSpace(p.Provider) != "vk" && strings.TrimSpace(p.Provider) != "yandex" {
			return fmt.Errorf("cover config: turn_profile.provider must be vk or yandex")
		}
		if strings.TrimSpace(p.RoomLink) == "" && strings.TrimSpace(p.RoomHash) == "" {
			return fmt.Errorf("cover config: turn_profile requires room_link or room_hash")
		}
		if p.WGTurnPort != 0 && (p.WGTurnPort < 1 || p.WGTurnPort > 65535) {
			return fmt.Errorf("cover config: turn_profile.wgturn_port out of range")
		}
	}
	return nil
}

func (b *CoverConfigBundle) MarshalForWire() ([]byte, error) {
	if b == nil {
		b = &CoverConfigBundle{Version: 1}
	}
	buf, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal cover config: %w", err)
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return nil, fmt.Errorf("cover config too large after marshal: %d > %d bytes", len(buf), MaxCoverConfigBundleBytes)
	}
	return buf, nil
}

// MarshalForWireWithExpiry returns a wire-form copy of the bundle with the
// dynamic expires_at field rewritten to now+TTLSeconds (when TTLSeconds>0).
// The static fields (sni_pool, fingerprint_pool, cover_targets, gaps,
// ttl_seconds) are unchanged, so the ETag computed over the static body
// stays stable across requests even though expires_at moves with wallclock.
func (b *CoverConfigBundle) MarshalForWireWithExpiry(now time.Time) ([]byte, error) {
	if b == nil {
		return (&CoverConfigBundle{Version: 1}).MarshalForWire()
	}
	clone := *b
	if clone.TTLSeconds > 0 {
		clone.ExpiresAt = now.Add(time.Duration(clone.TTLSeconds) * time.Second).Unix()
	}
	return clone.MarshalForWire()
}

// ETag returns the strong ETag for the static portion of the bundle. Used
// by the server to set a stable Etag header so clients can do HEAD-based
// staleness checks without re-fetching the body. The hash deliberately
// excludes ExpiresAt so that wallclock drift between requests does not
// invalidate the cached body.
func (b *CoverConfigBundle) ETag() string {
	if b == nil {
		return ""
	}
	clone := *b
	clone.ExpiresAt = 0
	buf, err := json.Marshal(clone)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("empty host")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range [1,65535]", p)
	}
	return nil
}
