package tamizdat

import (
	"context"
	"testing"
	"time"
)

// TestUserAuth_OverQuota: a user whose BandwidthCap is exceeded completes
// the TLS+H2 handshake (so they can fetch /tamizdat-config.invalid for a
// NotificationEntry explaining the situation) but their CONNECT is refused
// inside H2 with HTTP 402 — Phase C iOS-notify pipeline (2026-05-10).
// server.go also flips notification_pending=1 in the DB so the panel
// surfaces the overrun. With BundleEnabled=false (legacy default) the user
// would instead drop into masquerade — that case is exercised by
// TestUserAuth_OverQuota_BundleDisabled below.
func TestUserAuth_OverQuota(t *testing.T) {
	env, _ := setupUserDBServer(t, 0)

	// Stamp the user with a tight quota that's already burned through.
	db := openTestUserDB(t, env.dbPath)
	now := time.Now().Unix()
	if _, err := db.Exec(`UPDATE users SET bandwidth_cap=?, bytes_up=?, bytes_down=?, bytes_reset_at=? WHERE id=?`,
		int64(1024*1024), int64(2*1024*1024), int64(0), now, env.userID); err != nil {
		_ = db.Close()
		t.Fatalf("update quota: %v", err)
	}
	_ = db.Close()
	if _, _, err := env.server.ReloadUsers(); err != nil {
		t.Fatalf("ReloadUsers: %v", err)
	}

	client, err := NewClient(ClientConfig{
		ServerAddr:       env.serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        env.serverPubKey,
		ShortID:          env.masterID,
		Fingerprint:      "chrome",
		TCPFragmentation: false,
		ConnectTimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// CONNECT must fail because the H2 handler refuses with 402 for
	// DataPlaneBlocked identities. The TLS+H2 handshake itself succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatalf("expected over-quota CONNECT to fail with HTTP 402")
	}

	// notification_pending must be flipped on by the server.
	db = openTestUserDB(t, env.dbPath)
	defer db.Close()
	var notif int
	if err := db.QueryRow(`SELECT notification_pending FROM users WHERE id=?`, env.userID).Scan(&notif); err != nil {
		t.Fatalf("scan notification_pending: %v", err)
	}
	if notif != 1 {
		t.Fatalf("notification_pending=%d want 1 after over-quota auth", notif)
	}

	// Phase C: TLS+H2 handshake completed so we expect exactly one session
	// row (StartSession fires for the bundle-fetch path even though CONNECT
	// is refused). Multiple rows would indicate runaway reconnect leak.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE user_id=?`, env.userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("over-quota user got %d session rows; expected 1 (bundle path)", n)
	}
}

// TestUserAuth_UnderQuota: a user with usage under cap connects normally and
// notification_pending stays 0.
func TestUserAuth_UnderQuota(t *testing.T) {
	env, echoAddr := setupUserDBServer(t, 0)

	db := openTestUserDB(t, env.dbPath)
	now := time.Now().Unix()
	if _, err := db.Exec(`UPDATE users SET bandwidth_cap=?, bytes_up=?, bytes_down=?, bytes_reset_at=? WHERE id=?`,
		int64(100*1024*1024), int64(10*1024*1024), int64(20*1024*1024), now, env.userID); err != nil {
		_ = db.Close()
		t.Fatalf("update quota: %v", err)
	}
	_ = db.Close()
	if _, _, err := env.server.ReloadUsers(); err != nil {
		t.Fatalf("ReloadUsers: %v", err)
	}

	client, err := NewClient(ClientConfig{
		ServerAddr:       env.serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        env.serverPubKey,
		ShortID:          env.masterID,
		Fingerprint:      "chrome",
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	echoOnce(t, client, echoAddr, []byte("hello-quota-ok"))

	db = openTestUserDB(t, env.dbPath)
	defer db.Close()
	var notif int
	if err := db.QueryRow(`SELECT notification_pending FROM users WHERE id=?`, env.userID).Scan(&notif); err != nil {
		t.Fatalf("scan notification_pending: %v", err)
	}
	if notif != 0 {
		t.Fatalf("notification_pending=%d want 0 (under quota)", notif)
	}
}

// TestUserAuth_QuotaBaselineSubtraction: a user whose lifetime
// bytes_up+bytes_down exceeds BandwidthCap is NOT blocked when
// quota_baseline absorbs all but a small slice of the lifetime traffic
// (operator clicked panel "Reset Quota" earlier — the baseline column
// was bumped to the then-current bytes_up+bytes_down so the rolling
// window restarts from a clean slate).
func TestUserAuth_QuotaBaselineSubtraction(t *testing.T) {
	env, echoAddr := setupUserDBServer(t, 0)

	db := openTestUserDB(t, env.dbPath)
	now := time.Now().Unix()
	// 1 GB cap, 1.5 GB lifetime (1 GB up + 0.5 GB down) but a 1.4 GB
	// baseline → effective usage 100 MB → must connect normally.
	if _, err := db.Exec(`UPDATE users SET bandwidth_cap=?, bytes_up=?, bytes_down=?, bytes_reset_at=?, quota_baseline=? WHERE id=?`,
		int64(1024*1024*1024),
		int64(1024*1024*1024),
		int64(512*1024*1024),
		now,
		int64(1400*1024*1024),
		env.userID); err != nil {
		_ = db.Close()
		t.Fatalf("update quota: %v", err)
	}
	_ = db.Close()
	if _, _, err := env.server.ReloadUsers(); err != nil {
		t.Fatalf("ReloadUsers: %v", err)
	}

	client, err := NewClient(ClientConfig{
		ServerAddr:       env.serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        env.serverPubKey,
		ShortID:          env.masterID,
		Fingerprint:      "chrome",
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	echoOnce(t, client, echoAddr, []byte("hello-baseline-ok"))

	db = openTestUserDB(t, env.dbPath)
	defer db.Close()
	var notif int
	if err := db.QueryRow(`SELECT notification_pending FROM users WHERE id=?`, env.userID).Scan(&notif); err != nil {
		t.Fatalf("scan notification_pending: %v", err)
	}
	if notif != 0 {
		t.Fatalf("notification_pending=%d want 0 (baseline subtraction keeps user under cap)", notif)
	}
}
