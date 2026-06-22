// Package userdb notifications.go — Stage 3 (2026-05-10).
//
// notification_pending is a one-shot per-user flag set by the panel (e.g.
// when the operator hits "Notify" or when quota auto-exhausts) and consumed
// by the server during the next CoverConfigBundle delivery to that user.
// The server clears the flag after a successful body write so each pending
// notification is delivered at-most-once.
//
// Helpers here are deliberately stateless (no in-memory cache) — the
// notification path is cold (only triggers on bundle fetch, not per-stream),
// so a single SELECT/UPDATE per fetch is cheap and avoids cache-coherency
// hazards with the panel which writes to the same column.
package userdb

import (
	"context"
	"database/sql"
	"fmt"
)

// GetNotificationPending reports whether users.notification_pending = 1 for
// the given user ID. Returns (false, nil) for unknown users so callers can
// treat the absence-of-pending and unknown-user paths uniformly.
func GetNotificationPending(ctx context.Context, db *sql.DB, userID string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("userdb: nil db")
	}
	if userID == "" {
		return false, nil
	}
	var pending int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(notification_pending, 0) FROM users WHERE id = ?`,
		userID,
	).Scan(&pending)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("userdb: get notification_pending: %w", err)
	}
	return pending != 0, nil
}

// ClearNotificationPending sets users.notification_pending = 0 for the
// given user. No-op (nil error) if the user doesn't exist or the column
// was already 0. Bumps updated_at so panel UI reflects the clear.
func ClearNotificationPending(ctx context.Context, db *sql.DB, userID string, nowUnix int64) error {
	if db == nil {
		return fmt.Errorf("userdb: nil db")
	}
	if userID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`UPDATE users SET notification_pending = 0, updated_at = ?
         WHERE id = ? AND notification_pending = 1`,
		nowUnix, userID,
	)
	if err != nil {
		return fmt.Errorf("userdb: clear notification_pending: %w", err)
	}
	return nil
}

// SetNotificationPending sets users.notification_pending = 1. Operator/panel
// path — server itself never raises a notification (only consumes them).
// Provided here for tests + future server-side auto-set on quota-exhaustion.
func SetNotificationPending(ctx context.Context, db *sql.DB, userID string, nowUnix int64) error {
	if db == nil {
		return fmt.Errorf("userdb: nil db")
	}
	if userID == "" {
		return fmt.Errorf("userdb: empty userID")
	}
	res, err := db.ExecContext(ctx,
		`UPDATE users SET notification_pending = 1, updated_at = ?
         WHERE id = ?`,
		nowUnix, userID,
	)
	if err != nil {
		return fmt.Errorf("userdb: set notification_pending: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("userdb: user %s not found", userID)
	}
	return nil
}
