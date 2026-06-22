package userdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// accSep separates user_id from session_id in the in-memory session counter
// map key. The historical value was the literal 4-char ASCII string "\x00"
// (cosmetic typo); patch I-6 still keeps it as a distinct printable separator
// so an existing accumulator key already in flight does NOT silently flip
// across a binary upgrade. The key is process-local: there is no on-disk
// representation, so this is purely a defensive choice.
const accSep = "\x00"

type byteCounter struct {
	up   atomic.Int64
	down atomic.Int64
}

// OnFlushUser fires after a successful Flush commit, once per user that
// had non-zero bytes this window. Best-effort secondary check (the DB
// totals are now ground truth, so the server re-reads them and decides
// what to do).
type OnFlushUser func(userID string, deltaUp, deltaDown int64)

// OnQuotaOverrun fires on the *first* Add() call that crosses a user's
// remaining budget — instantly, not waiting for the next Flush. Server
// installs a hook that calls connTracker.KillUser. Debounced internally
// (one fire per setRemaining cycle); reset by the next SetUserRemaining.
// Designed for speedtest-class bursts: at 50 MB/s a 5-second flush
// window leaks 250 MB past cap; this hook fires within microseconds.
type OnQuotaOverrun func(userID string)

type Accounting struct {
	db        *sql.DB
	mu        sync.Mutex
	users     map[string]*byteCounter
	sessions  map[string]*byteCounter
	outbounds map[string]*byteCounter
	hook      OnFlushUser

	// In-memory budget tracker for the in-Add overrun check. The server
	// publishes "bytes the user can still spend before hitting cap" via
	// SetUserRemaining; Add atomically subtracts every delta and fires
	// onOverrun the moment the counter hits zero. -1 means "unlimited"
	// (BandwidthCap=0); the in-Add path skips those users entirely.
	remaining    sync.Map // userID → *int64 (atomic remaining bytes; -1 = unlimited)
	overrunFired sync.Map // userID → *atomic.Bool (debounce within a budget window)
	onOverrun    OnQuotaOverrun
}

func NewAccounting(db *sql.DB) *Accounting {
	return &Accounting{
		db:        db,
		users:     make(map[string]*byteCounter),
		sessions:  make(map[string]*byteCounter),
		outbounds: make(map[string]*byteCounter),
	}
}

// AddOutbound records bytes that flowed through an outbound tag. Per-outbound
// accounting is independent of per-user accounting: a single user-flow may
// dispatch to one or more outbounds via routing rules, and an outbound may
// serve many users. Bytes are buffered in-memory and flushed to
// outbounds.bytes_up / outbounds.bytes_down by Flush() in the same SQLite
// transaction as the user/session flush.
func (a *Accounting) AddOutbound(tag string, up, down int64) {
	if a == nil || strings.TrimSpace(tag) == "" || (up == 0 && down == 0) {
		return
	}
	a.mu.Lock()
	c := a.outbounds[tag]
	if c == nil {
		c = &byteCounter{}
		a.outbounds[tag] = c
	}
	a.mu.Unlock()
	if up != 0 {
		c.up.Add(up)
	}
	if down != 0 {
		c.down.Add(down)
	}
}

// PendingOutbound returns the in-memory un-flushed (up, down) for a tag.
// Intended for tests; reading it from production code races against Flush.
func (a *Accounting) PendingOutbound(tag string) (int64, int64) {
	if a == nil {
		return 0, 0
	}
	a.mu.Lock()
	c := a.outbounds[tag]
	a.mu.Unlock()
	if c == nil {
		return 0, 0
	}
	return c.up.Load(), c.down.Load()
}

// SetOnFlushUser registers a post-flush hook. Call once at boot before
// Start; not safe to swap concurrently with a running flush.
func (a *Accounting) SetOnFlushUser(h OnFlushUser) {
	if a == nil {
		return
	}
	a.hook = h
}

// SetOnOverrun registers the fast-path overrun hook. Call once at boot.
func (a *Accounting) SetOnOverrun(h OnQuotaOverrun) {
	if a == nil {
		return
	}
	a.onOverrun = h
}

// SetUserRemaining publishes the bytes-left-before-cap budget for userID.
// Server calls this:
//   - at boot for every user with BandwidthCap>0
//   - after each Flush commit (subtract just-persisted bytes)
//   - on SIGHUP-driven userRegistry.Reload (Reset Quota updates baseline)
//
// remaining > 0  : user has budget; in-Add subtracts each delta.
// remaining <= 0 : user is already over (the in-Add path will fire onOverrun
//
//	on the next byte through, allowing the server to clean
//	up any race-y-leftover connections).
//
// remaining = -1 : unlimited (BandwidthCap=0); in-Add skips the check.
//
// Resets the overrun-fired debounce so a fresh Reset Quota lets the same
// user trip onOverrun again next time they exhaust the new budget.
func (a *Accounting) SetUserRemaining(userID string, remaining int64) {
	if a == nil || userID == "" {
		return
	}
	v, ok := a.remaining.Load(userID)
	var p *int64
	if ok {
		p = v.(*int64)
	} else {
		p = new(int64)
		a.remaining.Store(userID, p)
	}
	atomic.StoreInt64(p, remaining)
	// Reset debounce for this user.
	if dv, ok := a.overrunFired.Load(userID); ok {
		dv.(*atomic.Bool).Store(false)
	}
}

// fireOverrunOnce calls onOverrun at most once per SetUserRemaining cycle.
func (a *Accounting) fireOverrunOnce(userID string) {
	if a.onOverrun == nil {
		return
	}
	dv, _ := a.overrunFired.LoadOrStore(userID, new(atomic.Bool))
	if dv.(*atomic.Bool).CompareAndSwap(false, true) {
		a.onOverrun(userID)
	}
}

func (a *Accounting) counter(m map[string]*byteCounter, key string) *byteCounter {
	c := m[key]
	if c == nil {
		c = &byteCounter{}
		m[key] = c
	}
	return c
}

func (a *Accounting) Add(userID, sessionID string, up, down int64) {
	if a == nil || strings.TrimSpace(userID) == "" || (up == 0 && down == 0) {
		return
	}
	a.mu.Lock()
	uc := a.counter(a.users, userID)
	var sc *byteCounter
	if sessionID != "" {
		sc = a.counter(a.sessions, userID+accSep+sessionID)
	}
	a.mu.Unlock()
	if up != 0 {
		uc.up.Add(up)
		if sc != nil {
			sc.up.Add(up)
		}
	}
	if down != 0 {
		uc.down.Add(down)
		if sc != nil {
			sc.down.Add(down)
		}
	}
	// Fast-path quota check: if the server published a remaining-budget for
	// this user, atomically subtract this delta. The first Add that drives
	// the counter to or below zero fires onOverrun (debounced via
	// overrunFired). Skips users with remaining=-1 (unlimited).
	if v, ok := a.remaining.Load(userID); ok {
		p := v.(*int64)
		cur := atomic.LoadInt64(p)
		if cur != -1 {
			newR := atomic.AddInt64(p, -(up + down))
			if newR <= 0 && cur > 0 {
				// Just crossed; fire once.
				a.fireOverrunOnce(userID)
			} else if newR <= 0 {
				// Already over from a prior Add; debounce keeps the hook
				// from firing again until SetUserRemaining resets.
				a.fireOverrunOnce(userID)
			}
		}
	}
}

func (a *Accounting) Pending(userID string) (int64, int64) {
	if a == nil {
		return 0, 0
	}
	a.mu.Lock()
	c := a.users[userID]
	a.mu.Unlock()
	if c == nil {
		return 0, 0
	}
	return c.up.Load(), c.down.Load()
}

// Flush drains the in-memory byteCounter accumulators into a single SQLite
// transaction. On any DB error the swapped-out deltas are restored back into
// the accumulators so the next Flush retries them rather than silently losing
// the bytes (Finding 2 from the I-rerun review).
func (a *Accounting) Flush() error {
	if a == nil || a.db == nil {
		return nil
	}
	type item struct {
		key      string
		up, down int64
	}
	a.mu.Lock()
	users := make([]item, 0, len(a.users))
	for k, c := range a.users {
		up := c.up.Swap(0)
		down := c.down.Swap(0)
		if up != 0 || down != 0 {
			users = append(users, item{k, up, down})
		}
	}
	sessions := make([]item, 0, len(a.sessions))
	for k, c := range a.sessions {
		up := c.up.Swap(0)
		down := c.down.Swap(0)
		if up != 0 || down != 0 {
			sessions = append(sessions, item{k, up, down})
		}
	}
	outbounds := make([]item, 0, len(a.outbounds))
	for k, c := range a.outbounds {
		up := c.up.Swap(0)
		down := c.down.Swap(0)
		if up != 0 || down != 0 {
			outbounds = append(outbounds, item{k, up, down})
		}
	}
	a.mu.Unlock()
	if len(users) == 0 && len(sessions) == 0 && len(outbounds) == 0 {
		return nil
	}

	// Local helper: re-deposit the swapped deltas back to the accumulator
	// when the DB transaction fails, so the next Flush retries instead of
	// dropping the bytes on the floor. Called from the rollback path.
	restore := func() {
		a.mu.Lock()
		for _, it := range users {
			a.counter(a.users, it.key).up.Add(it.up)
			a.counter(a.users, it.key).down.Add(it.down)
		}
		for _, it := range sessions {
			a.counter(a.sessions, it.key).up.Add(it.up)
			a.counter(a.sessions, it.key).down.Add(it.down)
		}
		for _, it := range outbounds {
			a.counter(a.outbounds, it.key).up.Add(it.up)
			a.counter(a.outbounds, it.key).down.Add(it.down)
		}
		a.mu.Unlock()
	}

	tx, err := a.db.Begin()
	if err != nil {
		restore()
		return err
	}
	now := time.Now().Unix()
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, it := range users {
		if _, err := tx.Exec(`UPDATE users SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_seen_at=?, updated_at=? WHERE id=?`, it.up, it.down, now, now, it.key); err != nil {
			restore()
			return err
		}
	}
	for _, it := range sessions {
		parts := strings.SplitN(it.key, accSep, 2)
		if len(parts) != 2 {
			continue
		}
		if _, err := tx.Exec(`UPDATE user_sessions SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_active_at=? WHERE user_id=? AND session_id=?`, it.up, it.down, now, parts[0], parts[1]); err != nil {
			restore()
			return err
		}
	}
	for _, it := range outbounds {
		// updated_at touch lets the panel show "last activity" if it wants
		// to surface idle outbounds in the future. Rows that don't exist
		// in the table (e.g. routing rule pointing at an ephemeral tag that
		// got deleted between dial-time and flush-time) are quietly skipped
		// — UPDATE just affects 0 rows, no error to bubble up.
		if _, err := tx.Exec(`UPDATE outbounds SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, updated_at=? WHERE tag=?`, it.up, it.down, now, it.key); err != nil {
			restore()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		restore()
		return err
	}
	committed = true
	// Post-commit hook: notify caller about every user that had a
	// non-zero delta this window. Used by server.go to short-circuit
	// active connections of users that just crossed the BandwidthCap.
	// The hook is invoked AFTER the DB commit so it observes the
	// freshly-persisted bytes_up/bytes_down (read separately by the
	// server's IsOverQuota check).
	if a.hook != nil {
		for _, it := range users {
			a.hook(it.key, it.up, it.down)
		}
	}
	return nil
}

func (a *Accounting) Start(ctx context.Context, interval time.Duration) {
	if a == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = a.Flush()
				return
			case <-ticker.C:
				if err := a.Flush(); err != nil {
					fmt.Printf("tamizdat user accounting flush: %v\n", err)
				}
			}
		}
	}()
}
