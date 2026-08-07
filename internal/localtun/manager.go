package localtun

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	obreg "github.com/funnybones69/tamizdat/internal/outbounds"
	"github.com/funnybones69/tamizdat/internal/rulesdb"
	"github.com/funnybones69/tamizdat/internal/tunengine"
)

const (
	defaultTunName            = "taml0"
	defaultTunAddress         = "198.18.0.1/24"
	defaultTunMTU             = 1280
	healthFailureRestartLimit = 3
)

var safeInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var liveStatus atomic.Value

func init() {
	liveStatus.Store(map[string]any{"state": "disabled"})
	expvar.Publish("tamizdat_local_tun", expvar.Func(func() any { return liveStatus.Load() }))
}

type Config struct {
	UserID        string
	UserName      string
	Enabled       bool
	OutboundTag   string
	Policy        *rulesdb.Snapshot
	Interface     string
	TunName       string
	TunAddress    string
	MTU           int
	AutoRoute     bool
	BypassPrivate bool
	BlockQUIC     bool
	Sniff         bool
	FailClosed    bool
}

func (c Config) normalized() Config {
	c.UserID = strings.TrimSpace(c.UserID)
	c.UserName = strings.TrimSpace(c.UserName)
	c.OutboundTag = strings.TrimSpace(c.OutboundTag)
	c.Interface = strings.TrimSpace(c.Interface)
	c.TunName = strings.TrimSpace(c.TunName)
	c.TunAddress = strings.TrimSpace(c.TunAddress)
	if c.TunName == "" {
		c.TunName = defaultTunName
	}
	if c.TunAddress == "" {
		c.TunAddress = defaultTunAddress
	}
	if c.MTU == 0 {
		c.MTU = defaultTunMTU
	}
	return c
}

func validateConfig(c Config) error {
	if c.UserID == "" || c.UserName == "" {
		return errors.New("local TUN user id and name are required")
	}
	if !safeInterfaceName.MatchString(c.TunName) {
		return fmt.Errorf("invalid local TUN name %q", c.TunName)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("local TUN MTU %d is outside 576..9000", c.MTU)
	}
	prefix, err := netip.ParsePrefix(c.TunAddress)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("local TUN address %q must be an IPv4 CIDR", c.TunAddress)
	}
	if c.AutoRoute {
		if !safeInterfaceName.MatchString(c.Interface) {
			return fmt.Errorf("invalid local source interface %q", c.Interface)
		}
		if c.Interface == c.TunName {
			return errors.New("local source interface must differ from TUN name")
		}
	}
	return nil
}

type Manager struct {
	mu         sync.Mutex
	registry   *obreg.Registry
	rules      *rulesdb.Store
	accounting Accounting
	debug      bool
	cancel     context.CancelFunc
	done       chan error
	current    Config
	generation atomic.Uint64
}

func NewManager(registry *obreg.Registry, rules *rulesdb.Store, accounting Accounting, debug bool) *Manager {
	return &Manager{registry: registry, rules: rules, accounting: accounting, debug: debug}
}

// Reconcile atomically replaces the active local TUN user. v1 intentionally
// permits one enabled local user per server because the policy mark/table and
// TUN device are host-wide resources.
func (m *Manager) Reconcile(configs []Config) error {
	if m == nil {
		return errors.New("nil local TUN manager")
	}
	var selected *Config
	for i := range configs {
		cfg := configs[i].normalized()
		if !cfg.Enabled {
			continue
		}
		if selected != nil {
			return errors.New("only one enabled local TUN user is supported")
		}
		selected = &cfg
	}
	if selected != nil {
		if err := validateConfig(*selected); err != nil {
			return err
		}
		tunnelTag, err := localTunnelOutbound(selected.Policy, selected.UserName)
		if err != nil {
			return err
		}
		if tunnelTag == "" {
			return errors.New("local TUN has no tunnel outbound in applicable Routing rules")
		}
		selected.OutboundTag = tunnelTag
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if selected != nil && m.cancel != nil && *selected == m.current {
		return nil
	}
	if err := m.stopLocked(); err != nil {
		return err
	}
	gen := m.generation.Add(1)
	if selected == nil {
		m.current = Config{}
		m.publish(gen, map[string]any{"state": "disabled"})
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	m.cancel, m.done, m.current = cancel, done, *selected
	m.publish(gen, statusFor(*selected, "starting", "", 0))
	go m.supervise(ctx, done, gen, *selected)
	return nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation.Add(1)
	if err := m.stopLocked(); err != nil {
		return err
	}
	m.current = Config{}
	liveStatus.Store(map[string]any{"state": "disabled"})
	return nil
}

func (m *Manager) stopLocked() error {
	if m.cancel == nil {
		return nil
	}
	if m.done == nil {
		// The previous cleanup failed and its result was already consumed.
		// Retry it, but retain ownership and refuse a new generation until all
		// critical nft/RPDB invariants confirm that the old one is gone.
		if err := cleanupStoppedGeneration(m.current); err != nil {
			return fmt.Errorf("retry local TUN cleanup: %w", err)
		}
		m.cancel = nil
		return nil
	}
	m.cancel()
	done := m.done
	select {
	case err := <-done:
		m.done = nil
		if err != nil {
			return fmt.Errorf("local TUN cleanup failed; refusing overlapping restart: %w", err)
		}
	case <-time.After(16 * time.Second):
		// Never overlap two generations. A late cleanup from the old
		// generation could otherwise delete the new nft table/ip rule and
		// silently strand LAN clients. Keep the cancelled generation owned
		// by the manager so a later reconcile can wait for it again.
		return errors.New("local TUN shutdown timed out; refusing overlapping restart")
	}
	m.cancel, m.done = nil, nil
	return nil
}

func (m *Manager) supervise(ctx context.Context, done chan error, generation uint64, cfg Config) {
	var finalErr error
	defer func() {
		done <- finalErr
		close(done)
	}()
	lastLoggedError := ""
	for {
		startedAt := time.Now().Unix()
		err := m.runOnce(ctx, generation, cfg, startedAt)
		if ctx.Err() != nil {
			// runOnce already tears down its engine. Re-check the host-wide
			// nft/RPDB invariants with a fresh controller and report only that
			// shutdown result to stopLocked, not an earlier runtime failure.
			finalErr = cleanupStoppedGeneration(cfg)
			return
		}
		if err == nil {
			err = errors.New("local TUN stopped unexpectedly")
		}
		clean := cleanError(err)
		m.publish(generation, statusFor(cfg, "error", clean, startedAt))
		if clean != lastLoggedError {
			log.Printf("local TUN %s setup failed: %s", cfg.UserName, clean)
			lastLoggedError = clean
		}
		select {
		case <-ctx.Done():
			finalErr = cleanupStoppedGeneration(cfg)
			return
		case <-time.After(5 * time.Second):
			m.publish(generation, statusFor(cfg, "starting", "", 0))
		}
	}
}

func cleanupStoppedGeneration(cfg Config) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return newRouteController(cfg).Cleanup(cleanupCtx)
}

func (m *Manager) runOnce(ctx context.Context, generation uint64, cfg Config, startedAt int64) error {
	routes := newRouteController(cfg)
	if supervised, ok := routes.(supervisedRouteController); ok && cfg.FailClosed {
		if err := supervised.EnterFailClosed(ctx); err != nil {
			return fmt.Errorf("prepare local TUN killswitch: %w", err)
		}
	} else if err := routes.Cleanup(ctx); err != nil {
		return fmt.Errorf("remove stale local TUN generation: %w", err)
	}
	client := NewClient(m.registry, m.rules, m.accounting, cfg.UserID, cfg.UserName, cfg.OutboundTag, cfg.Sniff)
	defer client.Close()
	opts := tunengine.Options{
		Name:                    cfg.TunName,
		MTU:                     cfg.MTU,
		DialAttemptTimeout:      10 * time.Second,
		DialConcurrency:         128,
		DialActiveConcurrency:   2048,
		UDPIdleTimeout:          4 * time.Minute,
		DropPrivateDestinations: cfg.BypassPrivate,
		DropQUIC:                cfg.BlockQUIC,
		Debug:                   m.debug,
		PostTunUp: func() error {
			if err := routes.Setup(ctx); err != nil {
				return err
			}
			m.publish(generation, statusFor(cfg, "running", "", startedAt))
			return nil
		},
	}
	engine, err := tunengine.New(opts)
	if err != nil {
		return errors.Join(err, m.finishRoutes(ctx, routes, cfg, err))
	}
	session, err := engine.Start(ctx, opts, client)
	if err != nil {
		return errors.Join(err, engine.Close(), m.finishRoutes(ctx, routes, cfg, err))
	}

	var dnsDone <-chan error
	var dnsErr func() error
	var health func(context.Context) error
	if supervised, ok := routes.(supervisedRouteController); ok {
		dnsDone, dnsErr, health = supervised.DNSDone(), supervised.DNSError, supervised.Health
	}
	healthTicker := time.NewTicker(10 * time.Second)
	defer healthTicker.Stop()
	runtimeErr := waitRuntime(ctx, dnsDone, dnsErr, session.Done(), session.Err, healthTicker.C, health)
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopErr := session.Stop(stopCtx)
	engineErr := engine.Close()
	cleanupErr := m.finishRoutes(ctx, routes, cfg, runtimeErr)
	if stopErr != nil {
		stopErr = fmt.Errorf("stop local TUN session: %w", stopErr)
	}
	return errors.Join(runtimeErr, stopErr, engineErr, cleanupErr)
}

func (m *Manager) finishRoutes(ctx context.Context, routes routeController, cfg Config, runtimeErr error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if ctx.Err() == nil && runtimeErr != nil && cfg.FailClosed {
		if supervised, ok := routes.(supervisedRouteController); ok {
			return supervised.EnterFailClosed(cleanupCtx)
		}
	}
	return routes.Cleanup(cleanupCtx)
}

func waitRuntime(
	ctx context.Context,
	dnsDone <-chan error,
	dnsErr func() error,
	sessionDone <-chan struct{},
	sessionErr func() error,
	healthTick <-chan time.Time,
	health func(context.Context) error,
) error {
	consecutiveHealthFailures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dnsDone:
			err := error(nil)
			if dnsErr != nil {
				err = dnsErr()
			}
			if err == nil {
				err = errors.New("ChinaDNS exited unexpectedly")
			}
			return fmt.Errorf("ChinaDNS exited: %w", err)
		case <-sessionDone:
			err := error(nil)
			if sessionErr != nil {
				err = sessionErr()
			}
			if err == nil {
				err = errors.New("TUN session exited unexpectedly")
			}
			return err
		case <-healthTick:
			if health != nil {
				checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := health(checkCtx)
				cancel()
				if err == nil {
					consecutiveHealthFailures = 0
					continue
				}
				consecutiveHealthFailures++
				if consecutiveHealthFailures >= healthFailureRestartLimit {
					return fmt.Errorf("local TUN invariant check: %w", err)
				}
			}
		}
	}
}

func (m *Manager) publish(generation uint64, status map[string]any) {
	if m.generation.Load() == generation {
		liveStatus.Store(status)
	}
}

func statusFor(cfg Config, state, errText string, startedAt int64) map[string]any {
	return map[string]any{
		"user_id": cfg.UserID, "user_name": cfg.UserName, "state": state,
		"interface": cfg.Interface, "tun_name": cfg.TunName, "auto_route": cfg.AutoRoute,
		"fail_closed":  cfg.FailClosed,
		"outbound_tag": cfg.OutboundTag,
		"started_at":   startedAt, "error": errText,
	}
}

func cleanError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\r", " "), "\n", " ")
	if len(text) > 240 {
		text = text[:240]
	}
	return text
}
