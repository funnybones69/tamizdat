package outbounds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	BalancerModeRoundRobin = "round_robin"
	BalancerModeAlive      = "alive"

	balancerAliveFailureCooldown = 30 * time.Second
)

// BalancerConfig is stored in the outbounds.uri column for kind="balancer".
// Preferred JSON shape:
//
//	{"mode":"round_robin","outbounds":["via-a","via-b"]}
//
// "members" and "targets" are accepted as aliases for operator/API
// convenience. A URI shorthand is also accepted for hand-written DB rows:
// balancer://round_robin?outbounds=a,b.
type BalancerConfig struct {
	Mode              string   `json:"mode"`
	Outbounds         []string `json:"outbounds"`
	FailoverOnHighRTT bool     `json:"failover_on_high_rtt,omitempty"`
	RTTThresholdMs    int64    `json:"rtt_threshold_ms,omitempty"`
}

type rawBalancerConfig struct {
	Mode              string   `json:"mode"`
	Outbounds         []string `json:"outbounds"`
	Members           []string `json:"members"`
	Targets           []string `json:"targets"`
	FailoverOnHighRTT bool     `json:"failover_on_high_rtt"`
	RTTThresholdMs    int64    `json:"rtt_threshold_ms"`
	HighRTTMs         int64    `json:"high_rtt_ms"`
	MaxRTTMs          int64    `json:"max_rtt_ms"`
}

// RTTSnapshot is the balancer-local, import-cycle-free shape of the
// tamizdat.Client RTT probe stats. TamizdatDialer adapts the root client's
// public RTTProbeSnapshot result into this struct via reflection; tests and
// other dialers can implement RTTProbeSnapshot() RTTSnapshot directly.
type RTTSnapshot struct {
	P50Ms  int64
	Count  int
	LastMs int64
}

type rttSnapshotter interface {
	RTTProbeSnapshot() RTTSnapshot
}

func ParseBalancerConfig(raw string) (BalancerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return BalancerConfig{}, errors.New("balancer config is empty")
	}

	var cfg BalancerConfig
	if strings.HasPrefix(raw, "{") {
		var rc rawBalancerConfig
		if err := json.Unmarshal([]byte(raw), &rc); err != nil {
			return BalancerConfig{}, fmt.Errorf("parse balancer json: %w", err)
		}
		cfg.Mode = rc.Mode
		switch {
		case len(rc.Outbounds) > 0:
			cfg.Outbounds = rc.Outbounds
		case len(rc.Members) > 0:
			cfg.Outbounds = rc.Members
		case len(rc.Targets) > 0:
			cfg.Outbounds = rc.Targets
		}
		cfg.FailoverOnHighRTT = rc.FailoverOnHighRTT
		cfg.RTTThresholdMs = firstPositiveInt64(rc.RTTThresholdMs, rc.HighRTTMs, rc.MaxRTTMs)
	} else if strings.HasPrefix(raw, "balancer://") {
		u, err := url.Parse(raw)
		if err != nil {
			return BalancerConfig{}, fmt.Errorf("parse balancer uri: %w", err)
		}
		q := u.Query()
		cfg.Mode = q.Get("mode")
		if cfg.Mode == "" {
			cfg.Mode = strings.Trim(strings.TrimSpace(u.Host), "/")
		}
		if cfg.Mode == "" {
			cfg.Mode = strings.Trim(strings.TrimSpace(u.Path), "/")
		}
		members := q.Get("outbounds")
		if members == "" {
			members = q.Get("members")
		}
		if members == "" {
			members = q.Get("targets")
		}
		cfg.Outbounds = splitBalancerMembers(members)
		cfg.FailoverOnHighRTT = parseBoolish(q.Get("failover_on_high_rtt"))
		cfg.RTTThresholdMs = firstPositiveInt64(
			parsePositiveInt64(q.Get("rtt_threshold_ms")),
			parsePositiveInt64(q.Get("high_rtt_ms")),
			parsePositiveInt64(q.Get("max_rtt_ms")),
		)
	} else {
		return BalancerConfig{}, errors.New("balancer config must be JSON or balancer:// URI")
	}

	mode, err := normalizeBalancerMode(cfg.Mode)
	if err != nil {
		return BalancerConfig{}, err
	}
	members := normalizeBalancerMembers(cfg.Outbounds)
	if len(members) == 0 {
		return BalancerConfig{}, errors.New("balancer must reference at least one outbound")
	}
	if cfg.RTTThresholdMs < 0 {
		cfg.RTTThresholdMs = 0
	}
	return BalancerConfig{Mode: mode, Outbounds: members, FailoverOnHighRTT: cfg.FailoverOnHighRTT, RTTThresholdMs: cfg.RTTThresholdMs}, nil
}

func parseBoolish(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on", "enabled":
		return true
	default:
		return false
	}
}

func parsePositiveInt64(raw string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func firstPositiveInt64(values ...int64) int64 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func normalizeBalancerMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "alive", "failover", "first_alive", "first-alive":
		return BalancerModeAlive, nil
	case "round_robin", "round-robin", "rr":
		return BalancerModeRoundRobin, nil
	default:
		return "", fmt.Errorf("unsupported balancer mode %q", mode)
	}
}

func splitBalancerMembers(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func normalizeBalancerMembers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, tag := range in {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

type balancerMember struct {
	tag    string
	dialer *trackedDialer
}

// BalancerDialer multiplexes dials across already-registered outbound tags.
// It does not own member dialers; the Registry generation owns and retires
// every trackedDialer. Successful dials keep the selected member leased until
// the returned Conn/PacketConn is closed, so a SIGHUP reload cannot close the
// upstream tamizdat client while a stream is still active.
type BalancerDialer struct {
	tag               string
	mode              string
	members           []balancerMember
	next              atomic.Uint64
	aliveCooldown     time.Duration
	failoverOnHighRTT bool
	rttThresholdMs    int64
	cooldowns         []atomic.Int64
	highRTTStates     []atomic.Bool
}

func newBalancerDialer(tag string, cfg BalancerConfig, byTag map[string]*trackedDialer) (*BalancerDialer, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, errors.New("balancer tag is empty")
	}
	mode, err := normalizeBalancerMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	memberTags := normalizeBalancerMembers(cfg.Outbounds)
	if len(memberTags) == 0 {
		return nil, fmt.Errorf("balancer %q must reference at least one outbound", tag)
	}
	members := make([]balancerMember, 0, len(memberTags))
	for _, memberTag := range memberTags {
		if memberTag == tag {
			return nil, fmt.Errorf("balancer %q cannot reference itself", tag)
		}
		tracked := byTag[memberTag]
		if tracked == nil {
			return nil, fmt.Errorf("balancer %q references missing outbound %q", tag, memberTag)
		}
		if _, nested := tracked.dialer.(*BalancerDialer); nested {
			return nil, fmt.Errorf("balancer %q cannot reference nested balancer %q", tag, memberTag)
		}
		members = append(members, balancerMember{tag: memberTag, dialer: tracked})
	}
	rttThresholdMs := cfg.RTTThresholdMs
	if rttThresholdMs < 0 {
		rttThresholdMs = 0
	}
	return &BalancerDialer{
		tag:               tag,
		mode:              mode,
		members:           members,
		aliveCooldown:     balancerAliveFailureCooldown,
		failoverOnHighRTT: cfg.FailoverOnHighRTT && rttThresholdMs > 0,
		rttThresholdMs:    rttThresholdMs,
		cooldowns:         make([]atomic.Int64, len(members)),
		highRTTStates:     make([]atomic.Bool, len(members)),
	}, nil
}

func (b *BalancerDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if b == nil {
		return nil, errors.New("nil balancer outbound")
	}
	var errs []error
	rec := recorderFromContext(ctx)
	for _, choice := range b.orderedMembers() {
		member := choice.member
		lease := member.dialer.acquire(rec)
		conn, err := lease.DialContext(ctx, network, target)
		if err == nil {
			b.noteSuccess(choice.index)
			return &balancerConn{Conn: conn, lease: lease}, nil
		}
		_ = lease.Close()
		b.noteFailure(choice.index)
		errs = append(errs, fmt.Errorf("%s: %w", member.tag, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, b.allFailedError("tcp", target, errs)
}

func (b *BalancerDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	if b == nil {
		return nil, errors.New("nil balancer outbound")
	}
	var errs []error
	rec := recorderFromContext(ctx)
	for _, choice := range b.orderedMembers() {
		member := choice.member
		lease := member.dialer.acquire(rec)
		pc, err := lease.DialPacket(ctx, target)
		if err == nil {
			b.noteSuccess(choice.index)
			return &balancerPacketConn{PacketConn: pc, lease: lease}, nil
		}
		_ = lease.Close()
		b.noteFailure(choice.index)
		errs = append(errs, fmt.Errorf("%s: %w", member.tag, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, b.allFailedError("udp", target, errs)
}

func (b *BalancerDialer) Close() error { return nil }

type balancerChoice struct {
	index  int
	member balancerMember
}

type balancerRTTChoice struct {
	choice balancerChoice
	rttMs  int64
}

func (b *BalancerDialer) orderedMembers() []balancerChoice {
	n := len(b.members)
	if n == 0 {
		return nil
	}
	if b.mode == BalancerModeAlive {
		return b.orderedAliveMembers(time.Now())
	}
	start := int((b.next.Add(1) - 1) % uint64(n))
	ordered := make([]balancerChoice, 0, n)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ordered = append(ordered, balancerChoice{index: idx, member: b.members[idx]})
	}
	return ordered
}

func (b *BalancerDialer) orderedAliveMembers(now time.Time) []balancerChoice {
	n := len(b.members)
	healthy := make([]balancerChoice, 0, n)
	highRTT := make([]balancerRTTChoice, 0, n)
	cooling := make([]balancerChoice, 0, n)
	nowNS := now.UnixNano()
	for i, member := range b.members {
		choice := balancerChoice{index: i, member: member}
		if i < len(b.cooldowns) && b.cooldowns[i].Load() > nowNS {
			cooling = append(cooling, choice)
			continue
		}
		if rttMs, high := b.noteHighRTTIfUnhealthy(i); high {
			highRTT = append(highRTT, balancerRTTChoice{choice: choice, rttMs: rttMs})
			continue
		}
		healthy = append(healthy, choice)
	}
	if len(highRTT) > 1 {
		sort.SliceStable(highRTT, func(i, j int) bool {
			return highRTT[i].rttMs < highRTT[j].rttMs
		})
	}
	ordered := make([]balancerChoice, 0, n)
	ordered = append(ordered, healthy...)
	for _, candidate := range highRTT {
		ordered = append(ordered, candidate.choice)
	}
	return append(ordered, cooling...)
}

func (b *BalancerDialer) noteHighRTTIfUnhealthy(index int) (int64, bool) {
	if b == nil || b.mode != BalancerModeAlive || !b.failoverOnHighRTT || b.rttThresholdMs <= 0 {
		return 0, false
	}
	if index < 0 || index >= len(b.members) || index >= len(b.highRTTStates) {
		return 0, false
	}
	st, ok := b.members[index].dialer.rttProbeSnapshot()
	if !ok {
		b.highRTTStates[index].Store(false)
		return 0, false
	}
	rttMs, ok := balancerRTTMetricMs(st)
	if !ok {
		b.highRTTStates[index].Store(false)
		return 0, false
	}
	if b.highRTTStates[index].Load() {
		if rttMs > b.rttRecoveryThresholdMs() {
			return rttMs, true
		}
		b.highRTTStates[index].Store(false)
		return rttMs, false
	}
	if rttMs > b.rttThresholdMs {
		b.highRTTStates[index].Store(true)
		return rttMs, true
	}
	return rttMs, false
}

func (b *BalancerDialer) rttRecoveryThresholdMs() int64 {
	if b == nil || b.rttThresholdMs <= 1 {
		return 0
	}
	recovery := (b.rttThresholdMs * 9) / 10
	if recovery >= b.rttThresholdMs {
		recovery = b.rttThresholdMs - 1
	}
	if recovery < 1 {
		recovery = 1
	}
	return recovery
}

func balancerRTTMetricMs(st RTTSnapshot) (int64, bool) {
	p50 := st.P50Ms
	last := st.LastMs
	if p50 < 0 && last < 0 {
		return 0, false
	}
	if p50 < 0 {
		return last, true
	}
	if last < 0 {
		return p50, true
	}
	if last > p50 {
		return last, true
	}
	return p50, true
}

func (b *BalancerDialer) noteFailure(index int) {
	if b == nil || b.mode != BalancerModeAlive || b.aliveCooldown <= 0 || index < 0 || index >= len(b.cooldowns) {
		return
	}
	b.cooldowns[index].Store(time.Now().Add(b.aliveCooldown).UnixNano())
}

func (b *BalancerDialer) noteSuccess(index int) {
	if b == nil || b.mode != BalancerModeAlive || index < 0 || index >= len(b.cooldowns) {
		return
	}
	b.cooldowns[index].Store(0)
}

func (b *BalancerDialer) allFailedError(network, target string, errs []error) error {
	if len(errs) == 0 {
		return fmt.Errorf("balancer %q has no outbounds", b.tag)
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return fmt.Errorf("balancer %q: all %s outbounds failed for %s: %s", b.tag, network, target, strings.Join(parts, "; "))
}

type balancerConn struct {
	net.Conn
	lease *leasedDialer
	once  sync.Once
	err   error
}

func (c *balancerConn) OutboundTag() string {
	if c == nil || c.lease == nil {
		return ""
	}
	return c.lease.Tag()
}

func (c *balancerConn) Recorder() Recorder {
	if c == nil || c.lease == nil {
		return nil
	}
	return c.lease.Recorder()
}

func (c *balancerConn) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		var connErr error
		if c.Conn != nil {
			connErr = c.Conn.Close()
		}
		leaseErr := c.lease.Close()
		if connErr != nil {
			c.err = connErr
		} else {
			c.err = leaseErr
		}
	})
	return c.err
}

type balancerPacketConn struct {
	net.PacketConn
	lease *leasedDialer
	once  sync.Once
	err   error
}

func (c *balancerPacketConn) OutboundTag() string {
	if c == nil || c.lease == nil {
		return ""
	}
	return c.lease.Tag()
}

func (c *balancerPacketConn) Recorder() Recorder {
	if c == nil || c.lease == nil {
		return nil
	}
	return c.lease.Recorder()
}

func (c *balancerPacketConn) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		var pcErr error
		if c.PacketConn != nil {
			pcErr = c.PacketConn.Close()
		}
		leaseErr := c.lease.Close()
		if pcErr != nil {
			c.err = pcErr
		} else {
			c.err = leaseErr
		}
	})
	return c.err
}
