//go:build linux

package localtun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	localNFTTable = "tamizdat_local"
	localRuleMark = "0x9d/0xff"
	localTableID  = "157"
	localPriority = "11570"
)

type linuxRouteController struct{ cfg Config }

func newRouteController(cfg Config) routeController { return &selectiveRouteController{cfg: cfg} }

func (r *linuxRouteController) Setup(ctx context.Context) error {
	if err := runCommand(ctx, nil, "ip", "addr", "replace", r.cfg.TunAddress, "dev", r.cfg.TunName); err != nil {
		return err
	}
	if err := runCommand(ctx, nil, "ip", "link", "set", "dev", r.cfg.TunName, "mtu", fmt.Sprint(r.cfg.MTU), "up"); err != nil {
		return err
	}
	if !r.cfg.AutoRoute {
		return nil
	}
	// The bridge may appear after the service during boot. Keep this check in
	// the supervised run path (not static validation) so the manager retries
	// until the selected LAN interface is actually available.
	if _, err := net.InterfaceByName(r.cfg.Interface); err != nil {
		return fmt.Errorf("local source interface %q is unavailable: %w", r.cfg.Interface, err)
	}
	if err := runCommand(ctx, nil, "ip", "route", "replace", "table", localTableID, "default", "dev", r.cfg.TunName); err != nil {
		return err
	}
	_ = runCommand(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID)
	if err := runCommand(ctx, nil, "ip", "rule", "add", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID); err != nil {
		_ = runCommand(context.Background(), nil, "ip", "route", "flush", "table", localTableID)
		return err
	}
	_ = runCommand(ctx, nil, "nft", "delete", "table", "inet", localNFTTable)
	if err := runCommand(ctx, []byte(r.nftConfig()), "nft", "-f", "-"); err != nil {
		_ = r.cleanupPolicy(context.Background())
		return err
	}
	return nil
}

func (r *linuxRouteController) Cleanup(ctx context.Context) error {
	// Fail open: stop marking LAN packets before removing the policy route.
	if err := runCommandIgnoreNotFound(ctx, nil, "nft", "delete", "table", "inet", localNFTTable); err != nil {
		return err
	}
	return r.cleanupPolicy(ctx)
}

func (r *linuxRouteController) cleanupPolicy(ctx context.Context) error {
	return errors.Join(
		runCommandIgnoreNotFound(ctx, nil, "ip", "rule", "del", "priority", localPriority, "fwmark", localRuleMark, "lookup", localTableID),
		runCommandIgnoreNotFound(ctx, nil, "ip", "route", "flush", "table", localTableID),
	)
}

func (r *linuxRouteController) nftConfig() string {
	bypass := []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"}
	if r.cfg.BypassPrivate {
		bypass = append(bypass, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
	}
	return fmt.Sprintf(`table inet %s {
  set bypass_v4 {
    type ipv4_addr
    flags interval
    elements = { %s }
  }
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname %q fib daddr type local return
    iifname %q ip daddr @bypass_v4 return
    iifname %q meta l4proto { tcp, udp } meta mark set (meta mark & 0xffffff00) | 0x9d
  }
}
`, localNFTTable, strings.Join(bypass, ", "), r.cfg.Interface, r.cfg.Interface, r.cfg.Interface)
}

type commandError struct {
	command string
	output  string
	cause   error
}

func (e *commandError) Error() string { return e.command + ": " + e.output }
func (e *commandError) Unwrap() error { return e.cause }

func runCommand(parent context.Context, stdin []byte, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(out))
	if len(message) > 300 {
		message = message[:300]
	}
	if message == "" {
		message = err.Error()
	}
	return &commandError{command: strings.Join(append([]string{name}, args...), " "), output: message, cause: err}
}

func runCommandIgnoreNotFound(parent context.Context, stdin []byte, name string, args ...string) error {
	err := runCommand(parent, stdin, name, args...)
	if isCommandNotFound(err) {
		return nil
	}
	return err
}

func isCommandNotFound(err error) bool {
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		return false
	}
	// A missing ip/nft executable is not an idempotent cleanup success. Only
	// kernel/userspace ENOENT reports for the requested object may be ignored.
	if errors.Is(commandErr.cause, os.ErrNotExist) {
		return false
	}
	text := strings.ToLower(commandErr.output)
	return strings.Contains(text, "no such file or directory") || strings.Contains(text, "does not exist")
}

func commandOutput(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	message := strings.TrimSpace(string(out))
	if err == nil {
		return message, nil
	}
	if message == "" {
		message = err.Error()
	}
	return "", &commandError{command: strings.Join(append([]string{name}, args...), " "), output: message, cause: err}
}
