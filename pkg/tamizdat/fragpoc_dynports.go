package tamizdat

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	fragPoCScaleInterval   = 5 * time.Second // monitor tick
	fragPoCSessionsPerPort = 4               // roughly one dynamic port per 4 concurrent sessions
	fragPoCScaleDownTicks  = 6               // consecutive low ticks before a close (hysteresis)
	fragPoCRandomLo        = 40000           // default random-mode range low
	fragPoCRandomHi        = 60000           // default random-mode range high
	fragPoCListenAttempts  = 8               // max net.Listen attempts per scale-up
)

type FragPoCPortConfig struct {
	Enabled  bool
	MaxPorts int    // max ADDITIONAL dynamic listeners (base port excluded)
	Mode     string // "list" | "random"
	Pool     []int  // candidate ports, already parsed/validated by the caller
	BindHost string // host to bind dynamic listeners on, e.g. "127.0.0.1"
	BasePort int    // the base -fragpoc-listen port; never reused as a dynamic port
}

type FragPoCPortManager struct {
	cfg FragPoCPortConfig

	mu        sync.Mutex
	listeners map[int]net.Listener
	openOrder []int

	serveFunc    func(net.Listener)
	sessionCount func() int
	logf         func(string, ...any)

	lowTicks int
}

func NewFragPoCPortManager(cfg FragPoCPortConfig, serveFunc func(net.Listener), sessionCount func() int, logf func(string, ...any)) *FragPoCPortManager {
	if serveFunc == nil {
		serveFunc = func(net.Listener) {}
	}
	if sessionCount == nil {
		sessionCount = func() int { return 0 }
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &FragPoCPortManager{
		cfg:          cfg,
		listeners:    make(map[int]net.Listener),
		serveFunc:    serveFunc,
		sessionCount: sessionCount,
		logf:         logf,
	}
}

// ParseFragPoCPortPool parses a spec like "31510-31530,31540,31542" — a
// comma-separated list where each item is a single port or an inclusive
// "lo-hi" range — into a sorted, de-duplicated []int. Each port must be in
// 1..65535 and every range must have lo <= hi. An empty/whitespace spec
// returns (nil, nil).
func ParseFragPoCPortPool(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	seen := make(map[int]struct{})
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, fmt.Errorf("fragpoc port pool: empty item")
		}
		if loText, hiText, ok := strings.Cut(item, "-"); ok {
			lo, err := parseFragPoCPort(strings.TrimSpace(loText))
			if err != nil {
				return nil, fmt.Errorf("fragpoc port pool range %q: %w", item, err)
			}
			hi, err := parseFragPoCPort(strings.TrimSpace(hiText))
			if err != nil {
				return nil, fmt.Errorf("fragpoc port pool range %q: %w", item, err)
			}
			if lo > hi {
				return nil, fmt.Errorf("fragpoc port pool range %q: lo greater than hi", item)
			}
			for p := lo; p <= hi; p++ {
				seen[p] = struct{}{}
			}
			continue
		}

		p, err := parseFragPoCPort(item)
		if err != nil {
			return nil, fmt.Errorf("fragpoc port pool item %q: %w", item, err)
		}
		seen[p] = struct{}{}
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func parseFragPoCPort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range [1,65535]", p)
	}
	return p, nil
}

func (m *FragPoCPortManager) Start(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}
	if m.cfg.Mode == "list" && len(m.cfg.Pool) == 0 {
		m.logf("fragpoc dynamic ports enabled but inert: list mode has no pool")
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// List mode opens every pool port up-front and keeps it open for the
	// whole run (MaxPorts is ignored). A fixed, fully-open port list makes
	// the multi-port smoke test deterministic: every configured port is
	// probeable, so a red lamp means genuinely blocked rather than merely
	// "not yet scaled up under load". Random mode keeps the load-driven
	// reconcile loop below.
	if m.cfg.Mode == "list" {
		for _, p := range m.cfg.Pool {
			m.openFixedPort(p)
		}
		m.logf("fragpoc list mode: opened %d fixed port(s), kept open", len(m.CurrentPorts()))
		go func() {
			<-ctx.Done()
			m.Stop()
		}()
		return
	}
	go func() {
		t := time.NewTicker(fragPoCScaleInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				m.reconcileOnce()
			case <-ctx.Done():
				m.Stop()
				return
			}
		}
	}()
}

// openFixedPort opens one pool listener immediately and registers it; used by
// list mode at Start. The base port is skipped (it is served separately) and
// a bind failure is logged but non-fatal.
func (m *FragPoCPortManager) openFixedPort(port int) {
	if port == m.cfg.BasePort {
		return
	}
	m.mu.Lock()
	if _, ok := m.listeners[port]; ok {
		m.mu.Unlock()
		return
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(m.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		m.mu.Unlock()
		m.logf("WARN fragpoc list port %d bind failed: %v", port, err)
		return
	}
	m.listeners[port] = ln
	m.openOrder = append(m.openOrder, port)
	serveFunc := m.serveFunc
	m.mu.Unlock()
	go serveFunc(ln)
}

func (m *FragPoCPortManager) reconcileOnce() {
	n := m.sessionCount()
	desired := desiredDynamicPorts(n, m.cfg.MaxPorts)

	m.mu.Lock()
	current := len(m.listeners)
	scaleUpBy := 0
	scaleDownBy := 0
	switch {
	case desired > current:
		m.lowTicks = 0
		scaleUpBy = desired - current
	case desired < current:
		m.lowTicks++
		if m.lowTicks >= fragPoCScaleDownTicks {
			m.lowTicks = 0
			scaleDownBy = current - desired
		}
	default:
		m.lowTicks = 0
	}
	m.mu.Unlock()

	for i := 0; i < scaleUpBy; i++ {
		m.scaleUp()
	}
	for i := 0; i < scaleDownBy; i++ {
		m.scaleDown()
	}
}

func desiredDynamicPorts(sessions, max int) int {
	if max <= 0 {
		return 0
	}
	return clamp(ceilDiv(sessions, fragPoCSessionsPerPort)-1, 0, max)
}

func ceilDiv(n, d int) int {
	if n <= 0 || d <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

func clamp(n, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func (m *FragPoCPortManager) scaleUp() {
	attempted := make(map[int]struct{})
	var lastErr error
	attempts := 0

	for attempts < fragPoCListenAttempts {
		m.mu.Lock()
		port, ok := m.scaleUpCandidateLocked(attempted)
		if !ok {
			m.mu.Unlock()
			break
		}
		attempted[port] = struct{}{}
		attempts++

		ln, err := net.Listen("tcp", net.JoinHostPort(m.cfg.BindHost, strconv.Itoa(port)))
		if err != nil {
			m.mu.Unlock()
			lastErr = err
			continue
		}
		m.listeners[port] = ln
		m.openOrder = append(m.openOrder, port)
		count := len(m.listeners)
		serveFunc := m.serveFunc
		m.mu.Unlock()

		go serveFunc(ln)
		m.logf("fragpoc dynamic port opened: %d (%d active)", port, count)
		return
	}

	if lastErr != nil {
		m.logf("WARN fragpoc dynamic port open failed after %d attempt(s): %v", attempts, lastErr)
		return
	}
	m.logf("WARN fragpoc dynamic port open skipped: no available candidate ports")
}

func (m *FragPoCPortManager) scaleUpCandidateLocked(attempted map[int]struct{}) (int, bool) {
	if m.cfg.MaxPorts <= 0 || len(m.listeners) >= m.cfg.MaxPorts {
		return 0, false
	}

	candidates := m.availableCandidatesLocked(attempted)
	if len(candidates) == 0 {
		return 0, false
	}
	if m.cfg.Mode == "list" {
		return candidates[0], true
	}
	return candidates[rand.Intn(len(candidates))], true
}

func (m *FragPoCPortManager) availableCandidatesLocked(attempted map[int]struct{}) []int {
	pool := m.cfg.Pool
	if m.cfg.Mode != "list" && len(pool) == 0 {
		pool = make([]int, 0, fragPoCRandomHi-fragPoCRandomLo+1)
		for p := fragPoCRandomLo; p <= fragPoCRandomHi; p++ {
			pool = append(pool, p)
		}
	}

	candidates := make([]int, 0, len(pool))
	for _, p := range pool {
		if p == m.cfg.BasePort {
			continue
		}
		if _, ok := m.listeners[p]; ok {
			continue
		}
		if _, ok := attempted[p]; ok {
			continue
		}
		candidates = append(candidates, p)
	}
	return candidates
}

func (m *FragPoCPortManager) scaleDown() {
	m.mu.Lock()
	if len(m.openOrder) == 0 {
		m.mu.Unlock()
		return
	}
	last := len(m.openOrder) - 1
	port := m.openOrder[last]
	m.openOrder = m.openOrder[:last]
	ln := m.listeners[port]
	if ln != nil {
		_ = ln.Close()
	}
	delete(m.listeners, port)
	count := len(m.listeners)
	m.mu.Unlock()

	m.logf("fragpoc dynamic port closed: %d (%d active)", port, count)
}

func (m *FragPoCPortManager) CurrentPorts() []int {
	m.mu.Lock()
	defer m.mu.Unlock()

	ports := make([]int, 0, len(m.listeners))
	for p := range m.listeners {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func (m *FragPoCPortManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ln := range m.listeners {
		_ = ln.Close()
	}
	m.listeners = make(map[int]net.Listener)
	m.openOrder = nil
	m.lowTicks = 0
}

// RequestPorts is called when a client sends OpPortHint. It ensures each
// requested port (within the allowed pool or MaxPorts cap) is open, then
// returns the full list of currently-open ports INCLUDING the base port.
// Ports outside 1..65535 or equal to BasePort are silently skipped — the
// base port is always implicitly open.
func (m *FragPoCPortManager) RequestPorts(requested []int) []int {
	if !m.cfg.Enabled {
		// Manager disabled — return just the base port (always open externally).
		return []int{m.cfg.BasePort}
	}
	for _, p := range requested {
		if p < 1 || p > 65535 || p == m.cfg.BasePort {
			continue
		}
		m.openFixedPort(p)
	}
	open := m.CurrentPorts()
	// Prepend the base port (not tracked in m.listeners since it has its
	// own dedicated net.Listener created at startup).
	return append([]int{m.cfg.BasePort}, open...)
}
