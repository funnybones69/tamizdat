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
	defaultTunName    = "taml0"
	defaultTunAddress = "198.18.0.1/24"
	defaultTunMTU     = 1280
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
	if c.AutoRoute && (c.OutboundTag == "" || c.OutboundTag == "direct" || c.OutboundTag == "block") {
		return errors.New("automatic local routing requires a non-direct outbound")
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
	done       chan struct{}
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
	done := make(chan struct{})
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
	m.cancel()
	done := m.done
	if done != nil {
		select {
		case <-done:
		case <-time.After(16 * time.Second):
			// Never overlap two generations. A late cleanup from the old
			// generation could otherwise delete the new nft table/ip rule and
			// silently strand LAN clients. Keep the cancelled generation owned
			// by the manager so a later reconcile can wait for it again.
			return errors.New("local TUN shutdown timed out; refusing overlapping restart")
		}
	}
	m.cancel, m.done = nil, nil
	return nil
}

func (m *Manager) supervise(ctx context.Context, done chan struct{}, generation uint64, cfg Config) {
	defer close(done)
	lastLoggedError := ""
	for {
		startedAt := time.Now().Unix()
		err := m.runOnce(ctx, generation, cfg, startedAt)
		if ctx.Err() != nil {
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
			return
		case <-time.After(5 * time.Second):
			m.publish(generation, statusFor(cfg, "starting", "", 0))
		}
	}
}

func (m *Manager) runOnce(ctx context.Context, generation uint64, cfg Config, startedAt int64) error {
	routes := newRouteController(cfg)
	_ = routes.Cleanup(context.Background())
	defer routes.Cleanup(context.Background())
	client := NewClient(m.registry, m.rules, m.accounting, cfg.UserID, cfg.UserName, cfg.OutboundTag, cfg.Sniff)
	defer client.Close()
	opts := tunengine.Options{
		Name:                    cfg.TunName,
		MTU:                     cfg.MTU,
		DialAttemptTimeout:      10 * time.Second,
		DialConcurrency:         128,
		DialActiveConcurrency:   2048,
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
		return err
	}
	defer engine.Close()
	session, err := engine.Start(ctx, opts, client)
	if err != nil {
		return err
	}
	<-ctx.Done()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := session.Stop(stopCtx); err != nil {
		return fmt.Errorf("stop local TUN session: %w", err)
	}
	return nil
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
