package outbounds

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
)

type balancerCallRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *balancerCallRecorder) add(tag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, tag)
}

func (r *balancerCallRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

type recordingBalancerDialer struct {
	tag      string
	rec      *balancerCallRecorder
	failTCP  atomic.Bool
	failUDP  atomic.Bool
	rttMs    atomic.Int64
	closeCnt atomic.Int32
}

func (d *recordingBalancerDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	d.rec.add(d.tag)
	if d.failTCP.Load() {
		return nil, errors.New("dial " + d.tag + " failed")
	}
	a, b := net.Pipe()
	go func() {
		<-ctx.Done()
		_ = b.Close()
	}()
	return a, nil
}

func (d *recordingBalancerDialer) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	d.rec.add(d.tag + ":udp")
	if d.failUDP.Load() {
		return nil, errors.New("udp " + d.tag + " failed")
	}
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func (d *recordingBalancerDialer) Close() error {
	d.closeCnt.Add(1)
	return nil
}

func (d *recordingBalancerDialer) RTTProbeSnapshot() RTTSnapshot {
	v := d.rttMs.Load()
	if v <= 0 {
		return RTTSnapshot{P50Ms: -1, LastMs: -1}
	}
	return RTTSnapshot{P50Ms: v, LastMs: v, Count: 8}
}

func newTestBalancer(t *testing.T, tag, mode string, members ...*recordingBalancerDialer) *BalancerDialer {
	t.Helper()
	cfg := BalancerConfig{Mode: mode}
	for _, member := range members {
		cfg.Outbounds = append(cfg.Outbounds, member.tag)
	}
	return newTestBalancerWithConfig(t, tag, cfg, members...)
}

func newTestBalancerWithConfig(t *testing.T, tag string, cfg BalancerConfig, members ...*recordingBalancerDialer) *BalancerDialer {
	t.Helper()
	byTag := make(map[string]*trackedDialer)
	for _, member := range members {
		byTag[member.tag] = newTrackedDialer(member.tag, member)
	}
	b, err := newBalancerDialer(tag, cfg, byTag)
	if err != nil {
		t.Fatalf("newBalancerDialer: %v", err)
	}
	return b
}

func TestParseBalancerConfigAcceptsHighRTTFailoverFields(t *testing.T) {
	cfg, err := ParseBalancerConfig(`{"mode":"alive","outbounds":["primary","backup"],"failover_on_high_rtt":true,"rtt_threshold_ms":750}`)
	if err != nil {
		t.Fatalf("ParseBalancerConfig: %v", err)
	}
	if !cfg.FailoverOnHighRTT {
		t.Fatalf("FailoverOnHighRTT = false, want true")
	}
	if cfg.RTTThresholdMs != 750 {
		t.Fatalf("RTTThresholdMs = %d, want 750", cfg.RTTThresholdMs)
	}
}

func TestBalancerAliveSkipsHighRTTPrimaryWithRTTHysteresis(t *testing.T) {
	rec := &balancerCallRecorder{}
	primary := &recordingBalancerDialer{tag: "primary", rec: rec}
	backup := &recordingBalancerDialer{tag: "backup", rec: rec}
	primary.rttMs.Store(1200)
	backup.rttMs.Store(100)
	b := newTestBalancerWithConfig(t, "alive", BalancerConfig{
		Mode:              "alive",
		Outbounds:         []string{"primary", "backup"},
		FailoverOnHighRTT: true,
		RTTThresholdMs:    750,
	}, primary, backup)

	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext with high RTT primary: %v", err)
	}
	_ = conn.Close()
	primary.rttMs.Store(700) // below threshold, but above 90% recovery threshold
	conn, err = b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext during RTT hysteresis: %v", err)
	}
	_ = conn.Close()
	primary.rttMs.Store(600)
	conn, err = b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext after RTT recovery: %v", err)
	}
	_ = conn.Close()

	want := []string{"backup", "backup", "primary"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("high-RTT failover calls = %v, want %v", got, want)
	}
}

func TestBalancerAliveUsesPriorityWithinRTTThresholdAndFastestWhenAllHigh(t *testing.T) {
	rec := &balancerCallRecorder{}
	primary := &recordingBalancerDialer{tag: "primary", rec: rec}
	mid := &recordingBalancerDialer{tag: "mid", rec: rec}
	fast := &recordingBalancerDialer{tag: "fast", rec: rec}
	primary.rttMs.Store(600)
	mid.rttMs.Store(180)
	fast.rttMs.Store(100)
	b := newTestBalancerWithConfig(t, "alive", BalancerConfig{
		Mode:              "alive",
		Outbounds:         []string{"primary", "mid", "fast"},
		FailoverOnHighRTT: true,
		RTTThresholdMs:    200,
	}, primary, mid, fast)

	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext with later in-threshold members: %v", err)
	}
	_ = conn.Close()

	mid.rttMs.Store(300)
	fast.rttMs.Store(250)
	conn, err = b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext with all members above threshold: %v", err)
	}
	_ = conn.Close()

	want := []string{"mid", "fast"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("high-RTT priority/fastest calls = %v, want %v", got, want)
	}
}

func TestBalancerRoundRobinRotatesMembers(t *testing.T) {
	rec := &balancerCallRecorder{}
	members := []*recordingBalancerDialer{
		{tag: "a", rec: rec},
		{tag: "b", rec: rec},
		{tag: "c", rec: rec},
	}
	b := newTestBalancer(t, "rr", "round_robin", members...)

	for i := 0; i < 5; i++ {
		conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
		if err != nil {
			t.Fatalf("DialContext %d: %v", i, err)
		}
		_ = conn.Close()
	}

	want := []string{"a", "b", "c", "a", "b"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("round-robin calls = %v, want %v", got, want)
	}
}

func TestBalancerRoundRobinFallsForwardWhenSelectedMemberFails(t *testing.T) {
	rec := &balancerCallRecorder{}
	a := &recordingBalancerDialer{tag: "a", rec: rec}
	bMember := &recordingBalancerDialer{tag: "b", rec: rec}
	a.failTCP.Store(true)
	b := newTestBalancer(t, "rr", "round_robin", a, bMember)

	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	want := []string{"a", "b"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback calls = %v, want %v", got, want)
	}
}

func TestBalancerAliveSkipsFailedPrimaryOnNextDial(t *testing.T) {
	rec := &balancerCallRecorder{}
	primary := &recordingBalancerDialer{tag: "primary", rec: rec}
	backup := &recordingBalancerDialer{tag: "backup", rec: rec}
	primary.failTCP.Store(true)
	b := newTestBalancer(t, "alive", "alive", primary, backup)

	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext while primary down: %v", err)
	}
	_ = conn.Close()
	primary.failTCP.Store(false)
	conn, err = b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext during primary cooldown: %v", err)
	}
	_ = conn.Close()

	want := []string{"primary", "backup", "backup"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("alive calls = %v, want %v", got, want)
	}
}

func TestBalancerKeepsSelectedMemberLeaseUntilConnClose(t *testing.T) {
	rec := &balancerCallRecorder{}
	member := &recordingBalancerDialer{tag: "a", rec: rec}
	byTag := map[string]*trackedDialer{"a": newTrackedDialer("a", member)}
	b, err := newBalancerDialer("bal", BalancerConfig{Mode: "alive", Outbounds: []string{"a"}}, byTag)
	if err != nil {
		t.Fatalf("newBalancerDialer: %v", err)
	}
	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	if err := byTag["a"].retire(); err != nil {
		t.Fatalf("retire member while conn open: %v", err)
	}
	if got := member.closeCnt.Load(); got != 0 {
		t.Fatalf("member closed while balancer-returned conn still open: %d", got)
	}
	_ = conn.Close()
	if got := member.closeCnt.Load(); got != 1 {
		t.Fatalf("member close count after conn close = %d, want 1", got)
	}
}

func TestBalancerDialPacketUsesSameSelectionPolicy(t *testing.T) {
	rec := &balancerCallRecorder{}
	a := &recordingBalancerDialer{tag: "a", rec: rec}
	bMember := &recordingBalancerDialer{tag: "b", rec: rec}
	a.failUDP.Store(true)
	b := newTestBalancer(t, "alive", "alive", a, bMember)

	pc, err := b.DialPacket(context.Background(), "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	_ = pc.Close()

	want := []string{"a:udp", "b:udp"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("udp calls = %v, want %v", got, want)
	}
}

func TestParseBalancerConfigAcceptsJSONAliases(t *testing.T) {
	cfg, err := ParseBalancerConfig(`{"mode":"rr","members":["a","b"]}`)
	if err != nil {
		t.Fatalf("ParseBalancerConfig: %v", err)
	}
	if cfg.Mode != "round_robin" {
		t.Fatalf("mode = %q, want round_robin", cfg.Mode)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(cfg.Outbounds, want) {
		t.Fatalf("outbounds = %v, want %v", cfg.Outbounds, want)
	}
}

func TestRegistryLoadsBalancerOutbound(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`, "bal", "balancer", `{"mode":"alive","outbounds":["direct"]}`, "test", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES('default_outbound_tag', 'bal') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry(func(configurl.Config) (Client, error) { return &fakeClient{}, nil })
	if err := r.Reload(db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	lease, tag := r.Resolve("")
	if tag != "bal" {
		t.Fatalf("resolved default tag = %q, want bal", tag)
	}
	_ = lease.Close()
}

func TestRegistryRejectsBalancerWithMissingMember(t *testing.T) {
	db := openTestDB(t)
	if err := EnsureSchema(db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO outbounds(tag, kind, uri, note, created_at, updated_at) VALUES(?,?,?,?,?,?)`, "bal", "balancer", `{"mode":"alive","outbounds":["missing"]}`, "test", now, now); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry(func(configurl.Config) (Client, error) { return &fakeClient{}, nil })
	err := r.Reload(db)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Reload err = %v, want missing member error", err)
	}
}

func TestBalancerAllMembersFailedErrorListsAttempts(t *testing.T) {
	rec := &balancerCallRecorder{}
	a := &recordingBalancerDialer{tag: "a", rec: rec}
	bMember := &recordingBalancerDialer{tag: "b", rec: rec}
	a.failTCP.Store(true)
	bMember.failTCP.Store(true)
	b := newTestBalancer(t, "alive", "alive", a, bMember)

	_, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err == nil {
		t.Fatalf("DialContext unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
		t.Fatalf("error %q should list failed member tags", err)
	}
}

func TestParseBalancerConfigTripleSlashModePath(t *testing.T) {
	cfg, err := ParseBalancerConfig("balancer:///round_robin?outbounds=a,b")
	if err != nil {
		t.Fatalf("ParseBalancerConfig: %v", err)
	}
	if cfg.Mode != BalancerModeRoundRobin {
		t.Fatalf("mode = %q, want %q", cfg.Mode, BalancerModeRoundRobin)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(cfg.Outbounds, want) {
		t.Fatalf("outbounds = %v, want %v", cfg.Outbounds, want)
	}
}

func TestBalancerRoundRobinDoesNotPanicAfterUint32Wrap(t *testing.T) {
	rec := &balancerCallRecorder{}
	a := &recordingBalancerDialer{tag: "a", rec: rec}
	bMember := &recordingBalancerDialer{tag: "b", rec: rec}
	b := newTestBalancer(t, "rr", "round_robin", a, bMember)
	b.next.Store(1<<32 - 1)

	conn, err := b.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	want := []string{"b"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("round-robin calls after uint32 wrap = %v, want %v", got, want)
	}
}

type testBalancerRecorder struct{}

func (testBalancerRecorder) AddOutbound(string, int64, int64) {}

func TestBalancerConnExposesSelectedMemberTagAndRecorder(t *testing.T) {
	rec := &balancerCallRecorder{}
	member := &recordingBalancerDialer{tag: "a", rec: rec}
	tracked := newTrackedDialer("a", member)
	b, err := newBalancerDialer("bal", BalancerConfig{Mode: "alive", Outbounds: []string{"a"}}, map[string]*trackedDialer{"a": tracked})
	if err != nil {
		t.Fatalf("newBalancerDialer: %v", err)
	}
	outer := newTrackedDialer("bal", b)
	var recorder Recorder = testBalancerRecorder{}
	lease := outer.acquire(recorder)
	defer lease.Close()

	conn, err := lease.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	tagged, ok := conn.(interface{ OutboundTag() string })
	if !ok {
		t.Fatalf("balancer conn does not expose selected outbound tag")
	}
	if got := tagged.OutboundTag(); got != "a" {
		t.Fatalf("selected outbound tag = %q, want a", got)
	}
	recorded, ok := conn.(interface{ Recorder() Recorder })
	if !ok {
		t.Fatalf("balancer conn does not expose recorder")
	}
	if got := recorded.Recorder(); got == nil {
		t.Fatalf("selected member recorder is nil")
	}
}

// Keep io imported until the fake connection path is exercised by compile-time
// interface checks in older Go toolchains that prune blank generic net.Pipe use.
var _ = io.ErrClosedPipe
