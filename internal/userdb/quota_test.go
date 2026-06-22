package userdb

import (
	"testing"
	"time"
)

func mustTime(t *testing.T, layout, value string) time.Time {
	t.Helper()
	tm, err := time.Parse(layout, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return tm
}

func TestQuotaEnforcement_AllowsUnderLimit(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	u := &User{
		BandwidthCap: 100 * 1024 * 1024, // 100 MB
		BytesUp:      10 * 1024 * 1024,
		BytesDown:    20 * 1024 * 1024,
		BytesResetAt: now.Add(-1 * time.Hour).Unix(),
	}
	if isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("user under limit should not be over quota")
	}
}

func TestQuotaEnforcement_DropsOverLimit(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	u := &User{
		BandwidthCap: 100 * 1024 * 1024,
		BytesUp:      60 * 1024 * 1024,
		BytesDown:    50 * 1024 * 1024, // 110 MB total > cap
		BytesResetAt: now.Add(-1 * time.Hour).Unix(),
	}
	if !isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("user over limit should be over quota")
	}
}

func TestQuotaEnforcement_RollingWindowExcludesOldBytes(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	// Reset anchor 31 days ago: window elapsed → stale bytes ignored.
	u := &User{
		BandwidthCap: 100 * 1024 * 1024,
		BytesUp:      80 * 1024 * 1024,
		BytesDown:    40 * 1024 * 1024,
		BytesResetAt: now.Add(-31 * 24 * time.Hour).Unix(),
	}
	if isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("rolling window must forgive bytes older than 30 days")
	}
}

func TestQuotaEnforcement_UnlimitedNeverOver(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	u := &User{
		BandwidthCap: 0, // unlimited
		BytesUp:      100 * 1024 * 1024 * 1024,
		BytesDown:    100 * 1024 * 1024 * 1024,
		BytesResetAt: now.Add(-1 * time.Hour).Unix(),
	}
	if isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("BandwidthCap=0 means unlimited; never over quota")
	}
}

func TestQuotaEnforcement_NilUser(t *testing.T) {
	if isOverQuota(nil, time.Now) {
		t.Fatalf("nil user must not be reported as over quota")
	}
}

// TestQuotaEnforcement_BaselineSubtraction exercises the schema-v4
// quota-reset-split semantics: after operator clicks "Reset Quota" the
// panel sets QuotaBaseline = BytesUp+BytesDown so the accumulated lifetime
// counters stay visible while the rolling window restarts. The over-quota
// check must subtract the baseline before comparing to BandwidthCap.
func TestQuotaEnforcement_BaselineSubtraction(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	// 1 GB cap, lifetime traffic 1.5 GB but baseline 1.4 GB → effective
	// usage is 100 MB, well under the 1 GB cap.
	u := &User{
		BandwidthCap:  1 * 1024 * 1024 * 1024,
		BytesUp:       1 * 1024 * 1024 * 1024, // 1 GB
		BytesDown:     512 * 1024 * 1024,      // 0.5 GB
		QuotaBaseline: 1400 * 1024 * 1024,     // 1.4 GB
		BytesResetAt:  now.Add(-1 * time.Hour).Unix(),
	}
	if isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("baseline subtraction should leave 100 MB effective usage under 1 GB cap")
	}
	// Bump effective usage to 1.1 GB by raising BytesUp → over.
	u.BytesUp = 2 * 1024 * 1024 * 1024 // 2 GB lifetime up + 0.5 GB down = 2.5 GB; minus 1.4 GB baseline = 1.1 GB
	if !isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("baseline subtraction must still detect over-quota when (used - baseline) >= cap")
	}
}

// TestQuotaEnforcement_BaselineClampNonNegative protects against a
// hypothetical out-of-band counter rewind (e.g. an operator manually
// editing bytes_up via sqlite3 CLI). The clamp keeps the function
// monotonically reporting "under quota" rather than wrapping into a
// huge negative used value that overflows.
func TestQuotaEnforcement_BaselineClampNonNegative(t *testing.T) {
	now := mustTime(t, time.RFC3339, "2026-05-10T12:00:00Z")
	u := &User{
		BandwidthCap:  100 * 1024 * 1024,
		BytesUp:       10 * 1024 * 1024,
		BytesDown:     5 * 1024 * 1024,
		QuotaBaseline: 1 * 1024 * 1024 * 1024, // baseline larger than counters
		BytesResetAt:  now.Add(-1 * time.Hour).Unix(),
	}
	if isOverQuota(u, func() time.Time { return now }) {
		t.Fatalf("clamp must report under-quota when baseline > counters")
	}
}

func TestQuotaEnforcement_RegistryWiring(t *testing.T) {
	db := openTestDB(t)
	insertUser(t, db, "u-quota", "alice", testMasterA, "direct", 0)
	// Bake in a cap + bytes via direct UPDATE to bypass create_user/insertUser
	// which don't accept the field.
	if _, err := db.Exec(`UPDATE users SET bandwidth_cap=?, bytes_up=?, bytes_down=?, bytes_reset_at=? WHERE id='u-quota'`,
		int64(50*1024*1024), int64(30*1024*1024), int64(40*1024*1024), time.Now().Unix()); err != nil {
		t.Fatalf("update user quota: %v", err)
	}
	reg := NewRegistry(0)
	if err := reg.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	_, u, ok := reg.LookupHex(testMasterA)
	if !ok {
		t.Fatalf("lookup miss")
	}
	if !reg.IsOverQuota(u) {
		t.Fatalf("70 MB used vs 50 MB cap should be over")
	}
}
