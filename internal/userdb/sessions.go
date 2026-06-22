package userdb

import (
	"database/sql"
	"strings"
	"time"
)

func StartSession(db *sql.DB, userID, sessionID string, poolIndex int) error {
	return StartSessionWithTransport(db, userID, sessionID, poolIndex, "h2")
}

func StartSessionWithTransport(db *sql.DB, userID, sessionID string, poolIndex int, transport string) error {
	now := time.Now().Unix()
	var idx any
	if poolIndex >= 0 {
		idx = poolIndex
	}
	transport = strings.TrimSpace(transport)
	if transport == "" {
		transport = "h2"
	}
	_, err := db.Exec(`INSERT OR REPLACE INTO user_sessions(user_id, session_id, started_at, bytes_up, bytes_down, last_active_at, pool_index, transport) VALUES(?,?,?,?,?,?,?,?)`, userID, sessionID, now, 0, 0, now, idx, transport)
	return err
}

func EndSession(db *sql.DB, userID, sessionID string) error {
	_, err := db.Exec(`DELETE FROM user_sessions WHERE user_id=? AND session_id=?`, userID, sessionID)
	return err
}

func TouchSession(db *sql.DB, userID, sessionID string) error {
	_, err := db.Exec(`UPDATE user_sessions SET last_active_at=? WHERE user_id=? AND session_id=?`, time.Now().Unix(), userID, sessionID)
	return err
}

func OnlineCounts(db *sql.DB, activeSince int64) (map[string]int, map[string]int, error) {
	rows, err := db.Query(`SELECT user_id, COUNT(*) AS n, COALESCE(MAX(pool_index), -1) AS p FROM user_sessions WHERE last_active_at >= ? GROUP BY user_id`, activeSince)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts := make(map[string]int)
	pool := make(map[string]int)
	for rows.Next() {
		var userID string
		var n, p int
		if err := rows.Scan(&userID, &n, &p); err != nil {
			return nil, nil, err
		}
		counts[userID] = n
		pool[userID] = p
	}
	return counts, pool, rows.Err()
}

func ActiveTransports(db *sql.DB, activeSince int64) (map[string]string, error) {
	rows, err := db.Query(`SELECT user_id, transport, COUNT(*) AS n FROM user_sessions WHERE last_active_at >= ? GROUP BY user_id, transport`, activeSince)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var userID, transport string
		var n int
		if err := rows.Scan(&userID, &transport, &n); err != nil {
			return nil, err
		}
		transport = strings.TrimSpace(transport)
		if transport == "" {
			transport = "h2"
		}
		// Prefer TURN when a user has both an H2 control/session and a wgturn
		// session active: the panel badge should show the data-plane fallback.
		if transport == "turn" || out[userID] == "" {
			out[userID] = transport
		}
	}
	return out, rows.Err()
}

func CountSessions(db *sql.DB, userID string) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE user_id=?`, userID).Scan(&n)
	return n, err
}
