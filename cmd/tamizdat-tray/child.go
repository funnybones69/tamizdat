//go:build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Child supervises one tamizdat-tun-windows.exe subprocess. The TUN engine
// itself owns route setup (--auto-route=true by default), so this wrapper
// only handles:
//   - building the argv from Config
//   - capturing stdout / stderr into the log ring
//   - graceful stop on cancel + grace period before kill
//   - exit notification so the tray can flip the icon back to red.
type Child struct {
	cfg     *Config
	tunExe  string
	logf    func(format string, args ...any)
	onExit  func()
	onReady func() // fired when the TUN engine reports auto-route installed

	// readyTimeout: if the child neither reports auto-route nor exits
	// within this window after Start(), treat it as a failed connect:
	// kill it, fire onExit, so the tray flips back from Disconnect → Connect.
	readyTimeout time.Duration

	mu       sync.Mutex
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	running  bool
	readyHit bool          // set true once onReady fired for this run
	exited   chan struct{} // closed by the single cmd.Wait() goroutine when the process is fully reaped
}

func newChild(tunExe string, cfg *Config, logf func(string, ...any), onExit, onReady func()) *Child {
	return &Child{
		tunExe: tunExe, cfg: cfg, logf: logf, onExit: onExit, onReady: onReady,
		// Auto-route installation includes wintun adapter creation, DNS
		// resolve of the server hostname, original-gateway snapshot, and
		// several `route`/`netsh` invocations. 20 s leaves comfortable
		// headroom even on a sluggish box; anything past that is "stuck".
		readyTimeout: 20 * time.Second,
	}
}

func (c *Child) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *Child) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("already running")
	}
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	args := []string{
		"-config", c.cfg.buildURI(),
		"-transport", c.cfg.Transport,
		"-fragpoc-workers", strconv.Itoa(c.cfg.FragPoCWorkers),
		"-fragpoc-down-window", strconv.Itoa(c.cfg.FragPoCDownWindow),
		"-fragpoc-secure=" + strconv.FormatBool(c.cfg.FragPoCSecure),
		"-fragpoc-udp-policy", c.cfg.FragPoCUDPPolicy,
		"-tun-name", c.cfg.TUN.Name,
		"-tun-ip", c.cfg.TUN.IP,
		"-tun-prefix", strconv.Itoa(c.cfg.TUN.Prefix),
		"-mtu", strconv.Itoa(c.cfg.TUN.MTU),
	}
	if c.cfg.Debug {
		args = append(args, "-debug")
	}
	if c.cfg.DebugListen != "" {
		args = append(args, "-debug-listen", c.cfg.DebugListen)
	}
	if c.cfg.FragPoCDialConcurrency > 0 {
		args = append(args, "-dial-concurrency", strconv.Itoa(c.cfg.FragPoCDialConcurrency))
	}
	if c.cfg.FragPoCActiveConcurrency > 0 {
		args = append(args, "-dial-active-concurrency", strconv.Itoa(c.cfg.FragPoCActiveConcurrency))
	}
	if c.cfg.FragPoCDialTimeoutMS > 0 {
		args = append(args, "-dial-attempt-timeout", strconv.Itoa(c.cfg.FragPoCDialTimeoutMS)+"ms")
	}
	if c.cfg.FragPoCOpenIntervalMS > 0 {
		args = append(args, "-dial-open-interval", strconv.Itoa(c.cfg.FragPoCOpenIntervalMS)+"ms")
	}
	if c.cfg.FragPoCTargetCooldownMS != 0 {
		args = append(args, "-dial-target-cooldown", strconv.Itoa(c.cfg.FragPoCTargetCooldownMS)+"ms")
	}
	if c.cfg.FragPoCTargetCooldownMaxMS != 0 {
		args = append(args, "-dial-target-cooldown-max", strconv.Itoa(c.cfg.FragPoCTargetCooldownMaxMS)+"ms")
	}
	if c.cfg.FragPoCMinAttemptMS > 0 {
		args = append(args, "-dial-min-attempt-budget", strconv.Itoa(c.cfg.FragPoCMinAttemptMS)+"ms")
	}
	if c.cfg.FragPoCRecoveryThreshold != 0 {
		args = append(args, "-dial-recovery-threshold", strconv.Itoa(c.cfg.FragPoCRecoveryThreshold))
	}
	if c.cfg.FragPoCRecoveryBackoffMS != 0 {
		args = append(args, "-dial-recovery-backoff", strconv.Itoa(c.cfg.FragPoCRecoveryBackoffMS)+"ms")
	}
	if len(c.cfg.BypassRoutes) > 0 {
		args = append(args, "-bypass-routes", strings.Join(c.cfg.BypassRoutes, ","))
	}
	c.logf("connect: starting TUN engine server=%s transport=%s profile=%s", c.cfg.Server, c.cfg.Transport, shortProfileHash(c.cfg))

	cmd := exec.CommandContext(ctx, c.tunExe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000200, // CREATE_NEW_PROCESS_GROUP
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start: %w", err)
	}

	exited := make(chan struct{})

	c.mu.Lock()
	c.cmd = cmd
	c.cancel = cancel
	c.running = true
	c.readyHit = false
	c.exited = exited
	c.mu.Unlock()

	go c.pump(stdout, "tun")
	go c.pump(stderr, "tun")

	// Single owner of cmd.Wait(): doing it twice triggers Go stdlib's
	// "Wait was already called" guard and returns instantly with an
	// error, which would defeat any other Stop() waiter relying on the
	// child being reaped. Stop() instead blocks on <-c.exited which is
	// closed here once Wait() actually returns.
	go func() {
		_ = cmd.Wait()
		c.mu.Lock()
		c.running = false
		c.cancel = nil
		c.cmd = nil
		c.mu.Unlock()
		close(exited)
		c.logf("child exited")
		if c.onExit != nil {
			c.onExit()
		}
	}()

	// Readiness watchdog: if neither onReady nor cmd.Wait() fires within
	// readyTimeout, the child is stuck (no admin / wintun missing /
	// hung in route install). Kill it so the tray flips back to Connect
	// instead of staying on a misleading Disconnect.
	go c.readyWatchdog()

	return nil
}

func (c *Child) readyWatchdog() {
	d := c.readyTimeout
	if d <= 0 {
		return
	}
	time.Sleep(d)
	c.mu.Lock()
	running := c.running
	ready := c.readyHit
	cancel := c.cancel
	c.mu.Unlock()
	if !running {
		return // already exited; cmd.Wait() callback has handled it
	}
	if ready {
		return // happy path
	}
	c.logf("connect failed: TUN engine did not report ready in %s — killing child", d)
	if cancel != nil {
		cancel()
	}
}

// Stop signals the child to terminate and blocks until it has been
// reaped (or the grace period expires, at which point it gets SIGKILL
// and we wait a little more for the kill to land).
//
// Stop is safe to call concurrently: the second caller observes
// exited==nil after the first reap and returns immediately.
func (c *Child) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	cmd := c.cmd
	exited := c.exited
	c.mu.Unlock()

	if cancel == nil || cmd == nil || exited == nil {
		return
	}
	c.logf("stopping child …")
	cancel() // exec.CommandContext sends Kill() on cancel

	// First grace: TUN engine's signal handler tears down routes + closes
	// upstream. On Windows the cancel arrives as a TerminateProcess after
	// stdlib doesn't get a clean shutdown channel — but routes-cleanup
	// in the engine is in deferred-fn paths, so we still give it time.
	select {
	case <-exited:
		return
	case <-time.After(4 * time.Second):
	}

	// Hard kill. The reaper goroutine WILL see Wait() return after this.
	c.logf("child not responding — hard kill")
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		c.logf("child still not reaped 2s after SIGKILL — giving up wait")
	}
}

func (c *Child) pump(r io.Reader, tag string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		ready := onReadyHit(line)
		if ready || shouldLogTunLine(line) {
			c.logf("[%s] %s", tag, sanitizeLogLine(line))
		}
		if ready {
			c.mu.Lock()
			already := c.readyHit
			c.readyHit = true
			c.mu.Unlock()
			if !already && c.onReady != nil {
				c.onReady()
			}
		}
	}
	if err := sc.Err(); err != nil {
		c.logf("[%s] read error: %v", tag, err)
	}
}

func shortProfileHash(cfg *Config) string {
	key := profileStateKey(cfg)
	if len(key) > 12 {
		return key[:12]
	}
	if key == "" {
		return "unknown"
	}
	return key
}

// onReadyHit matches the TUN engine's "I'm fully up" log lines. The
// markers come straight from internal/routing/windows.go:
//
//	"auto-route: default 0.0.0.0/0 via TUN ifIndex=N gw=..."  — full tunnel
//	"auto-route: selective mode — default route untouched"     — selective mode
//
// Either of those means routes are installed and traffic should flow.
// 'auto-route: assigned' (TUN IP set, route may still be pending) is a
// fallback marker so the icon goes green ~1 sec earlier in normal mode.
func onReadyHit(line string) bool {
	for _, m := range []string{
		"auto-route: default",
		"auto-route: selective",
		"auto-route: assigned",
	} {
		if containsFold(line, m) {
			return true
		}
	}
	return false
}

// containsFold is a case-insensitive ASCII substring check.
func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
