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
	policyRule := strings.Index(got, "ip daddr @r14")
	if fib < 0 || policyRule < 0 || fib > policyRule {
		t.Fatalf("hairpin FIB bypass must precede policy rules:\n%s", got)
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
