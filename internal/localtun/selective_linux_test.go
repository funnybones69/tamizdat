//go:build linux

package localtun

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/funnybones69/tamizdat/internal/rulesdb"
)

func TestSelectiveNFTConfigStagesHooksAndPreservesMarks(t *testing.T) {
	policy := ingressPolicy{dynamicGroups: 1, rules: []ingressRule{
		{index: 0, action: ingressDirect, domains: []string{"sync.example"}},
		{index: 1, action: ingressTunnel, domains: []string{"blocked.example"}},
		{index: 2, action: ingressTunnel, ipv4: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{index: 3, action: ingressDirect},
	}}
	r := &selectiveRouteController{cfg: Config{Interface: "br-lan", BypassPrivate: true}}
	got := r.nftConfig(policy, []string{"br-lan", "phy0-ap0"})
	for _, want := range []string{
		`iifname { "br-lan", "phy0-ap0" }`,
		`th dport 853 drop`,
		`fib daddr type local return`,
		`ip daddr @r14 meta mark set (meta mark & 0xffffff00) | 0x9d return`,
		`ip6 daddr @r16 reject with icmpv6 addr-unreachable`,
		`ip daddr @r24 meta mark set (meta mark & 0xffffff00) | 0x9d return`,
		`set r14 { type ipv4_addr; flags interval; }`,
		`set r24 { type ipv4_addr; flags interval; auto-merge;`,
		`chain killswitch`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("nft config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `hook prerouting`) {
		t.Fatalf("default phase-1 config must not publish a hook:\n%s", got)
	}
	if strings.Contains(got, `meta mark set 0x9d`) {
		t.Fatalf("nft config overwrites mwan3/pbr mark bits:\n%s", got)
	}
	if strings.Contains(got, `ip6 daddr @r16 meta mark set`) {
		t.Fatalf("IPv6-only destinations must not be sent to the IPv4-only TUN:\n%s", got)
	}
	fib := strings.Index(got, "fib daddr type local return")
	dot := strings.Index(got, "th dport 853 drop")
	policyRule := strings.Index(got, "ip daddr @r14")
	if fib < 0 || dot < 0 || policyRule < 0 || fib > dot || fib > policyRule {
		t.Fatalf("hairpin FIB bypass must precede DoT and policy rules:\n%s", got)
	}
	checkNFTSyntax(t, got)
}

func TestSelectiveNFTConfigRoutesRuleMissThroughUserFallback(t *testing.T) {
	policy := ingressPolicy{rules: []ingressRule{{
		index: 0, action: ingressDirect, ipv4: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}}}
	r := &selectiveRouteController{cfg: Config{
		Interface: "br-lan", BypassPrivate: true, FallbackTag: "balancer",
	}}
	got := r.nftConfig(policy, []string{"br-lan"})
	directRule := `iifname "br-lan" meta l4proto { tcp, udp } ip daddr @r04 return`
	fallbackRule := `iifname "br-lan" meta l4proto { tcp, udp } meta nfproto ipv4 meta mark set (meta mark & 0xffffff00) | 0x9d return`
	directPos, fallbackPos := strings.Index(got, directRule), strings.Index(got, fallbackRule)
	if directPos < 0 || fallbackPos < 0 {
		t.Fatalf("missing direct rule or balancer fallback mark:\n%s", got)
	}
	if fallbackPos <= directPos {
		t.Fatalf("fallback mark must follow explicit rules:\n%s", got)
	}
	if !strings.Contains(got, `iifname "br-lan" meta l4proto { tcp, udp } meta nfproto ipv6 reject with icmpv6 addr-unreachable`) {
		t.Fatalf("IPv4-only fallback must reject unmatched IPv6:\n%s", got)
	}
	checkNFTSyntax(t, got)
}

func TestFailClosedStagePublishesKillswitchAndDNSRedirect(t *testing.T) {
	r := &selectiveRouteController{cfg: Config{Interface: "br-lan", BypassPrivate: true, FailClosed: true}}
	got := r.nftConfig(ingressPolicy{}, []string{"br-lan"})
	for _, want := range []string{
		`hook prerouting priority mangle`,
		`jump killswitch`,
		`type nat hook prerouting priority -105`,
		`udp dport 53 redirect to :53`,
		`tcp dport 53 redirect to :53`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fail-closed stage missing %q:\n%s", want, got)
		}
	}
	checkNFTSyntax(t, got)
}

func TestSetupPublishesHooksOnlyAfterRouteAndRule(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	if err := r.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	routeAt := strings.Index(joined, "ip route replace table 157")
	ruleAt := strings.Index(joined, "ip rule add priority 11570")
	activateAt := strings.LastIndex(joined, "jump classify")
	if routeAt < 0 || ruleAt < routeAt || activateAt < ruleAt {
		t.Fatalf("unsafe setup order:\n%s", joined)
	}
	if !strings.Contains(joined, "udp dport 53 redirect to :53") || !strings.Contains(joined, "tcp dport 53 redirect to :53") {
		t.Fatalf("DNS interception was not atomically activated:\n%s", joined)
	}
}

func TestSetupAcceptsFallbackOnlyPolicy(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	r.cfg.Policy = &rulesdb.Snapshot{}
	r.cfg.FallbackTag = "balancer"
	if err := r.Setup(context.Background()); err != nil {
		t.Fatalf("fallback-only setup rejected: %v", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, `meta nfproto ipv4 meta mark set (meta mark & 0xffffff00) | 0x9d return`) {
		t.Fatalf("fallback-only classifier does not mark unmatched IPv4:\n%s", joined)
	}
	if !strings.Contains(joined, "jump classify") {
		t.Fatalf("fallback-only classifier was not activated:\n%s", joined)
	}
}

func TestPartialSetupRollsBackWithoutPublishingClassifier(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	r.run = func(_ context.Context, stdin []byte, name string, args ...string) error {
		entry := name + " " + strings.Join(args, " ")
		if len(stdin) > 0 {
			entry += "\n" + string(stdin)
		}
		commands = append(commands, entry)
		if name == "ip" && strings.Join(args, " ") == "rule add priority 11570 fwmark 0x9d/0xff lookup 157" {
			return errors.New("injected ip rule failure")
		}
		return nil
	}
	err := r.Setup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "injected ip rule failure") {
		t.Fatalf("Setup error = %v", err)
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "jump classify") {
		t.Fatalf("classifier was published after partial setup failure:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route flush table 157") || !strings.Contains(joined, "nft delete table inet tamizdat_local") {
		t.Fatalf("partial setup was not rolled back:\n%s", joined)
	}
}

func TestCleanupStopsBeforeRemovingRouteWhenHookDetachFails(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "nft" {
			return "exists", nil
		}
		return "", nil
	}
	r.run = func(_ context.Context, stdin []byte, name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " ")+"\n"+string(stdin))
		if name == "nft" && strings.Contains(string(stdin), "delete chain") {
			return errors.New("injected nft detach failure")
		}
		return nil
	}
	if err := r.Cleanup(context.Background()); err == nil {
		t.Fatal("Cleanup unexpectedly succeeded")
	}
	for _, command := range commands {
		if strings.HasPrefix(command, "ip rule del") || strings.HasPrefix(command, "ip route flush") {
			t.Fatalf("cleanup removed route while marking hook may still exist: %s", command)
		}
	}
}

func TestCleanupCollectsFailuresAndStillRemovesInactiveState(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	tableDeleted := false
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if name == "nft" && strings.HasPrefix(joined, "list table") {
			if tableDeleted {
				return "", objectNotFoundError("nft list table")
			}
			return "table exists", nil
		}
		if name == "nft" && strings.HasPrefix(joined, "list chain") {
			return "chain exists", nil
		}
		return "", nil
	}
	r.run = func(_ context.Context, stdin []byte, name string, args ...string) error {
		entry := name + " " + strings.Join(args, " ") + "\n" + string(stdin)
		commands = append(commands, entry)
		joined := strings.Join(args, " ")
		if name == "ip" && strings.HasPrefix(joined, "rule del priority 11570") {
			return errors.New("injected rule cleanup failure")
		}
		if name == "nft" && joined == "delete table inet tamizdat_local" {
			tableDeleted = true
		}
		return nil
	}
	err := r.Cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "injected rule cleanup failure") {
		t.Fatalf("Cleanup error = %v", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "ip route flush table 157") || !strings.Contains(joined, "nft delete table inet tamizdat_local") {
		t.Fatalf("cleanup stopped after a non-hook failure:\n%s", joined)
	}
}

func TestVerifyCleanupTreatsMissingFibTablesAsClean(t *testing.T) {
	missingTable := func(family string) error {
		t.Helper()
		cmd := exec.Command("sh", "-c", "printf 'Error: "+family+": FIB table does not exist. Dump terminated\\n' >&2; exit 2")
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
			t.Fatalf("missing-table emulator exit = %v, want status 2", err)
		}
		return &commandError{
			command: "ip route show table 157",
			output:  strings.TrimSpace(string(out)),
			cause:   err,
		}
	}

	r := &selectiveRouteController{}
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "nft":
			return "", objectNotFoundError("nft list table")
		case name == "ip" && strings.HasPrefix(joined, "rule show"):
			return "", nil
		case name == "ip" && joined == "route show table 157":
			return "", missingTable("ipv4")
		case name == "ip" && joined == "-6 route show table 157":
			return "", missingTable("ipv6")
		default:
			t.Fatalf("unexpected cleanup verification command: %s %s", name, joined)
			return "", nil
		}
	}
	if err := r.verifyCleanup(context.Background()); err != nil {
		t.Fatalf("verifyCleanup rejected absent FIB tables: %v", err)
	}
}

func TestVerifyCleanupDetectsStaleIPv6Route(t *testing.T) {
	r := &selectiveRouteController{}
	var sawIPv6 bool
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "nft":
			return "", objectNotFoundError("nft list table")
		case name == "ip" && strings.HasPrefix(joined, "rule show"):
			return "", nil
		case name == "ip" && joined == "route show table 157":
			return "", nil
		case name == "ip" && joined == "-6 route show table 157":
			sawIPv6 = true
			return "default dev taml0", nil
		default:
			t.Fatalf("unexpected cleanup verification command: %s %s", name, joined)
			return "", nil
		}
	}
	err := r.verifyCleanup(context.Background())
	if !sawIPv6 || err == nil || !strings.Contains(err.Error(), "ip -6 route table 157 still exists") {
		t.Fatalf("verifyCleanup IPv6 result: saw=%v err=%v", sawIPv6, err)
	}
}

func TestIPv6CleanupAlwaysTargetsPolicyTable(t *testing.T) {
	const want = "ip -6 route del table 157 default dev taml0"
	tests := []struct {
		name string
		run  func(*selectiveRouteController) error
	}{
		{name: "setup stale-state removal", run: func(r *selectiveRouteController) error { return r.Setup(context.Background()) }},
		{name: "cleanup", run: func(r *selectiveRouteController) error { return r.Cleanup(context.Background()) }},
		{name: "fail-closed", run: func(r *selectiveRouteController) error {
			r.cfg.FailClosed = true
			return r.EnterFailClosed(context.Background())
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commands []string
			r := commandMockController(&commands)
			if err := tt.run(r); err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(commands, "\n")
			if !strings.Contains(joined, want) {
				t.Fatalf("IPv6 cleanup did not target table 157:\n%s", joined)
			}
			if strings.Contains(joined, "ip -6 route del default dev taml0") {
				t.Fatalf("IPv6 cleanup still targets the main table:\n%s", joined)
			}
		})
	}
}

func TestEnterFailClosedAtomicallyReplacesLegacyTable(t *testing.T) {
	var commands []string
	r := commandMockController(&commands)
	r.cfg.FailClosed = true
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "nft" && strings.HasPrefix(strings.Join(args, " "), "list table") {
			return "legacy table exists", nil
		}
		return "", nil
	}
	if err := r.EnterFailClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	for _, want := range []string{"delete table inet tamizdat_local", "chain killswitch", "jump killswitch", "udp dport 53 redirect to :53", "tcp dport 53 redirect to :53"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("fail-closed replacement missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "jump classify") {
		t.Fatalf("classifier remained active during fail-closed transition:\n%s", joined)
	}
}

func TestHealthWithoutAutoRouteChecksOnlyLink(t *testing.T) {
	r := &selectiveRouteController{cfg: Config{TunName: "taml0"}}
	var commands []string
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "1: taml0: <POINTOPOINT,UP,LOWER_UP> mtu 1280 state UNKNOWN", nil
	}
	if err := r.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "link show dev taml0") {
		t.Fatalf("manual-route health commands = %v", commands)
	}
}

func TestHealthRequiresDNSRedirectHook(t *testing.T) {
	r := &selectiveRouteController{cfg: Config{TunName: "taml0", AutoRoute: true}}
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "ip" && strings.Contains(joined, "link show"):
			return "1: taml0: <POINTOPOINT,UP,LOWER_UP> mtu 1280 state UNKNOWN", nil
		case name == "ip" && strings.Contains(joined, "route show"):
			return "default dev taml0", nil
		case name == "ip" && strings.Contains(joined, "rule show"):
			return "11570: from all fwmark 0x9d/0xff lookup 157", nil
		case name == "nft" && strings.HasSuffix(joined, "prerouting"):
			return "jump classify", nil
		case name == "nft" && strings.HasSuffix(joined, "dns_prerouting"):
			return "udp dport 53 redirect to :53", nil
		default:
			return "", nil
		}
	}
	err := r.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "DNS redirect invariant") {
		t.Fatalf("Health error = %v, want missing TCP DNS redirect", err)
	}
}

func objectNotFoundError(command string) error {
	return &commandError{command: command, output: "No such file or directory", cause: errors.New("exit status 1")}
}

func commandMockController(commands *[]string) *selectiveRouteController {
	r := &selectiveRouteController{cfg: Config{
		UserID: "local-1", UserName: "router-lan", Interface: "lo", TunName: "taml0",
		TunAddress: "198.18.0.1/24", MTU: 1280, AutoRoute: true, BypassPrivate: true,
		Policy: &rulesdb.Snapshot{Rules: []rulesdb.Loaded{{
			Priority: 1, OutboundTag: "sync", Match: rulesdb.Match{
				IP: []string{"203.0.113.0/24"}, User: []string{"router-lan"},
			},
		}}},
	}}
	r.run = func(_ context.Context, stdin []byte, name string, args ...string) error {
		entry := name + " " + strings.Join(args, " ")
		if len(stdin) > 0 {
			entry += "\n" + string(stdin)
		}
		*commands = append(*commands, entry)
		return nil
	}
	r.output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "nft" {
			return "", &commandError{command: "nft", output: "No such file or directory", cause: errors.New("exit status 1")}
		}
		return "", nil
	}
	return r
}

func checkNFTSyntax(t *testing.T, config string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(config)
	if out, err := cmd.CombinedOutput(); err != nil {
		if bytes.Contains(out, []byte("Operation not permitted")) {
			t.Logf("nft syntax check skipped without CAP_NET_ADMIN: %s", out)
			return
		}
		t.Fatalf("nft -c failed: %v: %s\n%s", err, out, config)
	}
}
