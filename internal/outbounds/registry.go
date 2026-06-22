package outbounds

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS outbounds (
    tag TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    uri TEXT,
    note TEXT,
    bind_iface TEXT,
    h2_peak_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0,
    h2_peak_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS panel_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

// OpenSQLite opens the server outbound SQLite DB and creates its parent dir.
func OpenSQLite(path string) (*sql.DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite path is empty")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite dir %s: %w", dir, err)
		}
	}
	// modernc.org/sqlite DSN: pass busy_timeout via _pragma so the very FIRST
	// connection (used for PRAGMA journal_mode=WAL itself) honours it.
	// Without this, concurrent first-run workers get SQLITE_BUSY because the
	// WAL upgrade requires an exclusive lock and the default busy timeout is 0.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// EnsureSchema creates the Phase 1 schema and direct/default bootstrap rows.
func EnsureSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("nil sqlite db")
	}
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	// BEGIN IMMEDIATE serializes concurrent first-run schema/bootstrap work
	// before any schema reads. That avoids deferred-transaction upgrade races
	// that can otherwise surface as SQLite "database is locked" errors.
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	if _, err := conn.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	// Idempotent column-additions for older DBs. Each new column gets a
	// PRAGMA-probe + conditional ALTER. Fresh DBs already have bind_iface
	// via the CREATE TABLE above; bytes_up/bytes_down are NOT in schemaSQL
	// so this single code-path is the canonical migration for both.
	{
		cols := map[string]bool{}
		probeRows, perr := conn.QueryContext(ctx, `PRAGMA table_info(outbounds)`)
		if perr == nil {
			for probeRows.Next() {
				var (
					cid       int
					name      string
					ctype     string
					notNull   int
					dfltValue sql.NullString
					pk        int
				)
				if err := probeRows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err == nil {
					cols[name] = true
				}
			}
			probeRows.Close()
		}
		if !cols["bind_iface"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN bind_iface TEXT`); err != nil {
				return fmt.Errorf("add outbounds.bind_iface: %w", err)
			}
		}
		// Per-outbound byte accounting (2026-05-12). Columns are written
		// by userdb.Accounting.Flush() — see internal/userdb/accounting.go.
		// DEFAULT 0 + NOT NULL means existing rows get 0 on the ALTER (no
		// backfill needed) and counters monotonically grow until the panel
		// "Reset outbound traffic" button zeros them.
		if !cols["bytes_up"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN bytes_up INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.bytes_up: %w", err)
			}
		}
		if !cols["bytes_down"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN bytes_down INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.bytes_down: %w", err)
			}
		}
		if !cols["h2_peak_streams"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN h2_peak_streams INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.h2_peak_streams: %w", err)
			}
		}
		if !cols["h2_peak_tcp_streams"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN h2_peak_tcp_streams INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.h2_peak_tcp_streams: %w", err)
			}
		}
		if !cols["h2_peak_udp_streams"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN h2_peak_udp_streams INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.h2_peak_udp_streams: %w", err)
			}
		}
		if !cols["h2_peak_at"] {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE outbounds ADD COLUMN h2_peak_at INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add outbounds.h2_peak_at: %w", err)
			}
		}
	}
	now := time.Now().Unix()
	// INSERT OR IGNORE is atomic + idempotent: it avoids concurrent
	// first-run SELECT/INSERT races while preserving operator edits on
	// existing bootstrap rows.
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES('direct', 'direct', NULL, 'Direct dial from server IP', ?, ?)`, now, now); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES('default_outbound_tag', 'direct')`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema_version', '1')`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM settings WHERE key='schema_version'`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

// Registry stores the atomically-swapped outbound tag map.
type Registry struct {
	mu         sync.RWMutex
	byTag      map[string]*trackedDialer
	defaultTag string
	factory    ClientFactory
	recorder   Recorder // optional; per-conn byte attribution. nil = off.
}

func NewRegistry(factory ClientFactory) *Registry {
	return &Registry{
		byTag: map[string]*trackedDialer{
			"direct": newTrackedDialer("direct", DirectDialer{}),
		},
		defaultTag: "direct",
		factory:    factory,
	}
}

func (r *Registry) Reload(db *sql.DB) error {
	if r == nil {
		return fmt.Errorf("nil registry")
	}
	if err := EnsureSchema(db); err != nil {
		return err
	}

	// bind_iface added in 2026-05-10 panel migration so the operator can
	// pin the direct outbound to a specific NIC (split-IP boxes,
	// amnezia/wireguard tunnels). COALESCE keeps older DBs scanning
	// cleanly: NULL → empty → no SO_BINDTODEVICE applied.
	rows, err := db.Query(`SELECT tag, kind, uri, COALESCE(bind_iface, '') FROM outbounds ORDER BY tag`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type outboundRow struct {
		tag       string
		kind      string
		uri       sql.NullString
		bindIface string
	}
	var loaded []outboundRow
	for rows.Next() {
		var row outboundRow
		if err := rows.Scan(&row.tag, &row.kind, &row.uri, &row.bindIface); err != nil {
			return err
		}
		row.tag = strings.TrimSpace(row.tag)
		row.kind = strings.TrimSpace(row.kind)
		row.bindIface = strings.TrimSpace(row.bindIface)
		if row.tag == "" {
			return fmt.Errorf("outbound with empty tag")
		}
		loaded = append(loaded, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	next := make(map[string]*trackedDialer)
	var balancers []outboundRow
	for _, row := range loaded {
		var d Dialer
		switch row.kind {
		case "direct":
			if row.tag != "direct" {
				return fmt.Errorf("direct outbound must use tag 'direct', got %q", row.tag)
			}
			d = DirectDialer{BindIface: row.bindIface}
		case "tamizdat":
			if !row.uri.Valid || strings.TrimSpace(row.uri.String) == "" {
				return fmt.Errorf("tamizdat outbound %q missing uri", row.tag)
			}
			td, err := NewTamizdatDialer(row.uri.String, r.factory)
			if err != nil {
				return fmt.Errorf("tamizdat outbound %q: %w", row.tag, err)
			}
			d = td
		case "blackhole":
			// Drop-on-dial. Routing rules pointing at a blackhole tag
			// block matching traffic (Windows telemetry, ads, …) — see
			// BlackholeDialer doc.
			d = BlackholeDialer{}
		case "balancer":
			balancers = append(balancers, row)
			continue
		default:
			return fmt.Errorf("outbound %q has unsupported kind %q", row.tag, row.kind)
		}
		next[row.tag] = newTrackedDialer(row.tag, d)
	}
	for _, row := range balancers {
		if !row.uri.Valid || strings.TrimSpace(row.uri.String) == "" {
			return fmt.Errorf("balancer outbound %q missing config", row.tag)
		}
		cfg, err := ParseBalancerConfig(row.uri.String)
		if err != nil {
			return fmt.Errorf("balancer outbound %q: %w", row.tag, err)
		}
		bd, err := newBalancerDialer(row.tag, cfg, next)
		if err != nil {
			return fmt.Errorf("balancer outbound %q: %w", row.tag, err)
		}
		next[row.tag] = newTrackedDialer(row.tag, bd)
	}
	if _, ok := next["direct"]; !ok {
		return fmt.Errorf("outbound registry missing required direct outbound")
	}

	defaultTag := "direct"
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='default_outbound_tag'`).Scan(&defaultTag); err != nil && err != sql.ErrNoRows {
		return err
	}
	defaultTag = strings.TrimSpace(defaultTag)
	if defaultTag == "" {
		defaultTag = "direct"
	}
	if _, ok := next[defaultTag]; !ok {
		return fmt.Errorf("default_outbound_tag %q does not reference an outbound", defaultTag)
	}

	r.mu.Lock()
	old := r.byTag
	r.byTag = next
	r.defaultTag = defaultTag
	r.mu.Unlock()

	for _, d := range old {
		d.retire()
	}
	return nil
}

// Resolve returns a leased dialer. Call Close on the returned Dialer when the
// CONNECT stream is finished so retired reload generations can be cleaned up.
func (r *Registry) Resolve(tag string) (Dialer, string) {
	if r == nil {
		d := newTrackedDialer("direct", DirectDialer{})
		return d.acquire(nil), "direct"
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec := r.recorder
	if len(r.byTag) == 0 {
		d := newTrackedDialer("direct", DirectDialer{})
		return d.acquire(rec), "direct"
	}
	resolved := strings.TrimSpace(tag)
	if resolved == "" {
		resolved = r.defaultTag
	}
	d := r.byTag[resolved]
	if d == nil {
		resolved = "direct"
		d = r.byTag[resolved]
	}
	if d == nil {
		d = newTrackedDialer("direct", DirectDialer{})
		resolved = "direct"
	}
	return d.acquire(rec), resolved
}

func (r *Registry) DefaultTag() string {
	if r == nil {
		return "direct"
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultTag == "" {
		return "direct"
	}
	return r.defaultTag
}

// Tags returns a snapshot of the current outbound tag set. Used by the
// server-side routing dispatcher to seed its placeholder Outbound map so
// rules can reference tags that the registry knows about.
func (r *Registry) Tags() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byTag))
	for tag := range r.byTag {
		out = append(out, tag)
	}
	return out
}

func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	old := r.byTag
	r.byTag = nil
	r.defaultTag = "direct"
	r.mu.Unlock()
	var first error
	for _, d := range old {
		if err := d.retire(); first == nil && err != nil {
			first = err
		}
	}
	return first
}

type trackedDialer struct {
	tag    string
	dialer Dialer

	mu      sync.Mutex
	active  int
	retired bool
	closed  bool
}

func newTrackedDialer(tag string, d Dialer) *trackedDialer {
	return &trackedDialer{tag: tag, dialer: d}
}

func (t *trackedDialer) acquire(rec Recorder) *leasedDialer {
	t.mu.Lock()
	t.active++
	t.mu.Unlock()
	return &leasedDialer{t: t, rec: rec}
}

func (t *trackedDialer) rttProbeSnapshot() (RTTSnapshot, bool) {
	if t == nil {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}, false
	}
	t.mu.Lock()
	d := t.dialer
	t.mu.Unlock()
	snapper, ok := d.(rttSnapshotter)
	if !ok || snapper == nil {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}, false
	}
	st := snapper.RTTProbeSnapshot()
	if st.P50Ms < 0 && st.LastMs < 0 {
		return st, false
	}
	return st, true
}

func (t *trackedDialer) retire() error {
	t.mu.Lock()
	if t.retired {
		t.mu.Unlock()
		return nil
	}
	t.retired = true
	if t.active > 0 || t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	d := t.dialer
	t.mu.Unlock()
	if d != nil {
		return d.Close()
	}
	return nil
}

func (t *trackedDialer) release() error {
	t.mu.Lock()
	if t.active > 0 {
		t.active--
	}
	if !t.retired || t.active > 0 || t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	d := t.dialer
	t.mu.Unlock()
	if d != nil {
		return d.Close()
	}
	return nil
}

type leasedDialer struct {
	t   *trackedDialer
	rec Recorder // captured at acquire-time so SetRecorder swaps don't
	// affect in-flight conns dialed under a previous recorder
	once sync.Once
	err  error
}

func (l *leasedDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if l == nil || l.t == nil {
		return nil, fmt.Errorf("outbound lease is closed")
	}
	l.t.mu.Lock()
	if l.t.closed {
		l.t.mu.Unlock()
		return nil, fmt.Errorf("outbound %q is closed", l.t.tag)
	}
	d := l.t.dialer
	tag := l.t.tag
	l.t.mu.Unlock()
	if d == nil {
		return nil, fmt.Errorf("outbound %q has nil dialer", tag)
	}
	// 2026-05-13: stopped wrapping conn in countingConn here. The wrapper
	// hid the underlying *net.TCPConn / *net.UDPConn, breaking downstream
	// type-asserts (iPhone tun2socks UDP relay needs SyscallConn() /
	// SetReadBuffer() on the concrete type — see revert commit 04d3c94).
	// Accounting now happens at the io.Copy site in server.go using the
	// byte counts io.Copy returns; Tag() exposes the outbound name for
	// that book-keeping. The recorder is carried in context so composite
	// dialers (balancer) can pass it to the selected inner lease.
	return d.DialContext(contextWithRecorder(ctx, l.rec), network, target)
}

// DialPacket forwards UDP through whatever dialer kind this lease wraps
// — DirectDialer.DialPacket dials UDP locally, TamizdatDialer.DialPacket
// tunnels UDP via the upstream Tamizdat-Protocol: udp/1 path, Blackhole
// drops. Added 2026-05-11 to route iPhone QUIC traffic via remote
// outbounds (default -> mirror) instead of always exiting the local IP.
func (l *leasedDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	if l == nil || l.t == nil {
		return nil, fmt.Errorf("outbound lease is closed")
	}
	l.t.mu.Lock()
	if l.t.closed {
		l.t.mu.Unlock()
		return nil, fmt.Errorf("outbound %q is closed", l.t.tag)
	}
	d := l.t.dialer
	tag := l.t.tag
	l.t.mu.Unlock()
	if d == nil {
		return nil, fmt.Errorf("outbound %q has nil dialer", tag)
	}
	_ = tag // accounting now happens at the WriteTo/ReadFrom site (server.go)
	// 2026-05-13: no more countingPacketConn wrap — see DialContext comment.
	return d.DialPacket(contextWithRecorder(ctx, l.rec), target)
}

// Tag returns the outbound tag this lease targets. Server-side accounting
// uses it to attribute io.Copy byte counts to the right outbound row in
// the DB (and the per-outbound traffic gauge in the panel).
func (l *leasedDialer) Tag() string {
	if l == nil || l.t == nil {
		return ""
	}
	return l.t.tag
}

// Recorder exposes the lease's recorder so the server-side io.Copy can
// emit per-outbound byte deltas without re-wrapping the conn.
func (l *leasedDialer) Recorder() Recorder {
	if l == nil {
		return nil
	}
	return l.rec
}

func (l *leasedDialer) Close() error {
	if l == nil || l.t == nil {
		return nil
	}
	l.once.Do(func() { l.err = l.t.release() })
	return l.err
}
