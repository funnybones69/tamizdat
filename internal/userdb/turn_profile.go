package userdb

import (
	"context"
	"database/sql"
	"strings"
)

// ClearTurnProfilePending marks the current per-user TURN profile as delivered.
// The room/link stays in the users row so future panel edits can show the last
// staged value; only the one-shot pending flag is cleared.
func ClearTurnProfilePending(ctx context.Context, db *sql.DB, userID string, updatedAt int64) error {
	if db == nil || strings.TrimSpace(userID) == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE users SET turn_profile_pending=0, updated_at=? WHERE id=?`, updatedAt, userID)
	return err
}
