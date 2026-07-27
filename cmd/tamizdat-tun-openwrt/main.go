//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tamizdat-tun-linux", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "wgturn server UDP endpoint host:port")
	roomsFile := fs.String("vk-hash-file", "", "0600 file with one VK room hash/link per line")
	workersPerRoom := fs.Int("vk-workers-per-room", 20, "workers per room (1..20; 20 enables the full per-room pool)")
	passwordFile := fs.String("vk-turn-pass-file", "", "0600 file containing relay connection password")
	tunName := fs.String("tun-name", "tamtun0", "Linux TUN interface name")
	mtu := fs.Int("tun-mtu", 1280, "TUN MTU")
	listen := fs.String("listen", "127.0.0.1:19090", "local relay listen address")
	deviceID := fs.String("vk-device-id", "keenetic-tamizdat-tun-linux", "stable VK device id")
	credentialMode := fs.String("vk-credential-mode", "auto", "credential provider: auto, anonymous-only, or rjs-only")
	captchaMode := fs.String("vk-captcha-mode", "rjs", "captcha solver: rjs with local fallback, or manual")
	captchaDir := fs.String("vk-captcha-dir", "", "root-only CAPTCHA handoff directory")
	captchaWait := fs.Duration("vk-captcha-wait", 15*time.Minute, "local CAPTCHA fallback wait budget")
	credsCache := fs.String("vk-creds-cache", "", "0600 per-room TURN credential cache")
	credentialHelper := fs.String("vk-credential-helper", "", "proven single-room anonymous VKCalls helper binary")
	profileURIFile := fs.String("vk-profile-uri-file", "", "0600 file containing the Tamizdat profile URI used by the helper")
	helperWorkDir := fs.String("vk-credential-helper-dir", "/var/run/tamizdat/cred-helper", "root-only helper work directory")
	stateFile := fs.String("state-file", "/tmp/tamizdat-wgturn-state.json", "redacted runtime state file")
	credentialsStateFile := fs.String("credentials-state-file", "/tmp/tamizdat-wgturn-state-credentials.json", "redacted credential state file")
	pidfile := fs.String("pidfile", "", "write process id to this file")
	_ = fs.Bool("debug", false, "enable verbose logs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*server) == "" || strings.TrimSpace(*roomsFile) == "" || strings.TrimSpace(*passwordFile) == "" {
		fs.Usage()
		return 2
	}
	if *pidfile != "" {
		if err := os.WriteFile(*pidfile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer os.Remove(*pidfile)
	}
	rooms, err := readPrivateLines(*roomsFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	rooms = wgturnclient.NormalizeVKCallHashes(rooms)
	if len(rooms) < 1 || len(rooms) > 4 || len(rooms) != len(readLinesForValidation(*roomsFile)) {
		fmt.Fprintln(stderr, "rooms file must contain 1..4 unique normalized rooms")
		return 2
	}
	password, err := readPrivateValue(*passwordFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var acquireRoomCredentials func(context.Context, string) (*wgturnclient.Credentials, error)
	if strings.TrimSpace(*credentialHelper) != "" {
		profileURI, err := readPrivateValue(*profileURIFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if err := validateCredentialHelper(*credentialHelper, *helperWorkDir); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		acquireRoomCredentials = newLegacyCredentialAcquirer(*credentialHelper, profileURI, *helperWorkDir, *mtu)
	}
	preloaded, err := loadCredentialCache(*credsCache, rooms)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var activeWorkers atomic.Int64
	var attached atomic.Bool
	var tunAddress atomic.Value
	tunAddress.Store("")
	expectedWorkers := int64(len(rooms) * *workersPerRoom)
	readyRooms := make(map[string]struct{}, len(preloaded))
	for room := range preloaded {
		readyRooms[room] = struct{}{}
	}
	var readyRoomsMu sync.Mutex

	ctx, stopSignal := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignal()
	configCh := make(chan string, 1)
	runner, err := wgturnclient.New(wgturnclient.Config{
		Listen: *listen, PeerAddr: *server, WorkersPerRoom: *workersPerRoom,
		BondV2: len(rooms) > 1,
		UseUDP: true, UseTCP: false, VKHashes: rooms, ConnPassword: password,
		DeviceID: *deviceID, CredentialMode: *credentialMode,
		CaptchaMode: *captchaMode, CaptchaDir: *captchaDir, CaptchaWait: *captchaWait,
		PreloadedCredsByHash: preloaded, AcquireRoomCredentials: acquireRoomCredentials,
		OnWorkerCount: func(count int) {
			activeWorkers.Store(int64(count))
			state := "starting"
			if attached.Load() {
				state = "attached"
			}
			_ = writeState(*stateFile, len(rooms), int(activeWorkers.Load()), int(expectedWorkers), state, tunAddress.Load().(string))
		},
		OnRoomCredentials: func(hash string, creds *wgturnclient.Credentials) {
			if err := updateCredentialCache(*credsCache, hash, creds); err != nil {
				log.Printf("credential cache update failed: %v", err)
			}
			readyRoomsMu.Lock()
			readyRooms[hash] = struct{}{}
			readyCount := len(readyRooms)
			readyRoomsMu.Unlock()
			_ = writeCredentialState(*credentialsStateFile, readyCount, creds)
		},
		OnConfig: func(config string) {
			select {
			case configCh <- config:
			default:
			}
		},
	})
	if err != nil {
		log.Printf("runner init: %v", err)
		return 1
	}
	runnerDone := make(chan error, 1)
	go func() { runnerDone <- runner.Start(ctx) }()
	var wgConfig string
	select {
	case wgConfig = <-configCh:
	case err := <-runnerDone:
		if err != nil {
			log.Printf("runner exited before WG config: %v", err)
		}
		return 1
	case <-ctx.Done():
		return 0
	}
	attach, err := runner.AttachWireGuardKernel(wgConfig, *tunName, *mtu)
	if err != nil {
		log.Printf("kernel WireGuard attach: %v", err)
		runner.Shutdown()
		return 1
	}
	defer attach.Stop()
	runtimeAddress, err := configureKernelTUNAddress(*tunName, attach.Addresses)
	if err != nil {
		log.Printf("kernel TUN address: %v", err)
		runner.Shutdown()
		return 1
	}
	tunAddress.Store(runtimeAddress)
	log.Printf("multi-room TUN ready: rooms=%d workers=%d tun=%s", len(rooms), len(rooms)*(*workersPerRoom), *tunName)
	attached.Store(true)
	_ = writeState(*stateFile, len(rooms), int(activeWorkers.Load()), int(expectedWorkers), "attached", runtimeAddress)
	select {
	case err := <-runnerDone:
		if err != nil {
			log.Printf("runner stopped: %v", err)
			return 1
		}
	case <-ctx.Done():
		runner.Shutdown()
		return 0
	}
	return 0
}

func configureKernelTUNAddress(tunName string, addresses []netip.Addr) (string, error) {
	var selected netip.Addr
	for _, addr := range addresses {
		if addr.Is4() {
			selected = addr
			break
		}
	}
	if !selected.IsValid() {
		return "", fmt.Errorf("server configuration contains no IPv4 interface address")
	}
	prefix := selected.String() + "/32"
	if out, err := exec.Command("ip", "addr", "replace", prefix, "dev", tunName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip addr replace: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "link", "set", tunName, "up").CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip link set up: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return selected.String(), nil
}

func validateCredentialHelper(helperPath, workRoot string) error {
	st, err := os.Stat(helperPath)
	if err != nil {
		return fmt.Errorf("credential helper: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("credential helper must be an executable regular file")
	}
	cleanRoot := filepath.Clean(workRoot)
	if !filepath.IsAbs(cleanRoot) || cleanRoot == string(filepath.Separator) {
		return fmt.Errorf("credential helper directory must be a safe absolute path")
	}
	if err := os.MkdirAll(cleanRoot, 0700); err != nil {
		return fmt.Errorf("credential helper directory: %w", err)
	}
	if err := os.Chmod(cleanRoot, 0700); err != nil {
		return fmt.Errorf("credential helper directory mode: %w", err)
	}
	return nil
}

func newLegacyCredentialAcquirer(helperPath, profileURI, workRoot string, mtu int) func(context.Context, string) (*wgturnclient.Credentials, error) {
	return func(ctx context.Context, room string) (*wgturnclient.Credentials, error) {
		digest := roomHashDigest(room)
		if len(digest) < 8 {
			return nil, fmt.Errorf("invalid room digest")
		}
		root := filepath.Clean(workRoot)
		dir := filepath.Join(root, digest)
		if filepath.Dir(dir) != root {
			return nil, fmt.Errorf("unsafe helper work path")
		}
		if err := os.RemoveAll(dir); err != nil {
			return nil, fmt.Errorf("clear helper work directory: %w", err)
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create helper work directory: %w", err)
		}
		defer os.RemoveAll(dir)

		roomFile := filepath.Join(dir, "room")
		cacheFile := filepath.Join(dir, "credentials.json")
		pidFile := filepath.Join(dir, "helper.pid")
		if err := writePrivateAtomic(roomFile, []byte(room), 0600); err != nil {
			return nil, err
		}
		tunName := "tamcr" + digest[:8]
		_ = exec.Command("ip", "link", "del", tunName).Run()
		defer exec.Command("ip", "link", "del", tunName).Run()

		helperCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		args := legacyCredentialHelperArgs(profileURI, roomFile, cacheFile, pidFile, tunName, mtu)
		cmd := exec.CommandContext(helperCtx, helperPath, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start credential helper: %w", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		finished := false
		defer func() {
			if !finished && cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
			}
		}()

		// The legacy runtime persists credentials immediately before starting
		// its worker. Poll quickly so the credential-only helper can be reaped
		// without adding avoidable startup latency.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if data, err := os.ReadFile(cacheFile); err == nil {
				loaded, parseErr := loadLegacyCredentialCache(data, []string{room})
				if parseErr == nil && loaded[room] != nil {
					creds := loaded[room]
					creds.Source = "handoff-anonymous-helper"
					return creds, nil
				}
			}
			select {
			case err := <-done:
				finished = true
				if err == nil {
					err = fmt.Errorf("helper exited before publishing credentials")
				}
				return nil, fmt.Errorf("credential helper exited: %w", err)
			case <-helperCtx.Done():
				return nil, fmt.Errorf("credential helper timeout: %w", helperCtx.Err())
			case <-ticker.C:
			}
		}
	}
}

func legacyCredentialHelperArgs(profileURI, roomFile, cacheFile, pidFile, tunName string, mtu int) []string {
	return []string{
		"-transport", "vkturn",
		"-uri", profileURI,
		"-tun-name", tunName,
		"-tun-addr", "198.19.255.1/32",
		"-tun-mtu", fmt.Sprintf("%d", mtu),
		"-vk-hash-file", roomFile,
		"-vk-workers", "1",
		"-vk-turn-udp=true",
		"-vk-credential-mode", "auto",
		"-vk-captcha-mode", "rjs",
		"-vk-device-id", "keenetic-tamizdat-tun-linux",
		"-vk-creds-cache", cacheFile,
		"-pidfile", pidFile,
		// This process is a credential provider, not a data-plane worker. Point
		// its one mandatory legacy worker at a closed local port so it cannot
		// consume one of the room's 20 server-side TURN allocation slots.
		"-vk-turn-host", "127.0.0.1",
		"-vk-turn-port", "9",
	}
}

func writeState(path string, rooms, active, expected int, state, tunAddress string) error {
	if path == "" {
		return nil
	}
	status := map[string]any{"state": state, "rooms_configured": rooms, "workers_active": active, "workers_expected": expected, "updated_at": time.Now().Unix()}
	if tunAddress != "" {
		status["tun_address"] = tunAddress
	}
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return writePrivateAtomic(path, b, 0600)
}

func writeCredentialState(path string, rooms int, creds *wgturnclient.Credentials) error {
	if path == "" || creds == nil {
		return nil
	}
	source := creds.Source
	if source == "" {
		source = "anonymous-vkcalls"
	}
	b, err := json.Marshal(map[string]any{"state": "ready", "rooms_ready": rooms, "source": source, "refreshed_at": time.Now().Unix(), "expires_at": time.Now().Add(time.Duration(creds.Lifetime) * time.Second).Unix(), "urls": len(creds.TurnURLs)})
	if err != nil {
		return err
	}
	return writePrivateAtomic(path, b, 0600)
}

func writePrivateAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tamizdat-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type cacheEntry struct {
	Credentials *wgturnclient.Credentials `json:"credentials"`
	AcquiredAt  time.Time                 `json:"acquired_at"`
}

type credentialCache struct {
	Version int                   `json:"version"`
	Rooms   map[string]cacheEntry `json:"rooms"`
}

type legacyTurnServer struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
	Transport string `json:"transport"`
}

// legacyCredentialCache is the single-room schema written by the currently
// deployed tamizdat-tun-linux. Supporting it makes room #1 migration atomic:
// the new process can start from the credential that the old process refreshed
// immediately before the upgrade.
type legacyCredentialCache struct {
	Version       int                `json:"version"`
	Username      string             `json:"username"`
	Password      string             `json:"password"`
	TurnServers   []string           `json:"turn_servers"`
	TurnServersV2 []legacyTurnServer `json:"turn_servers_v2"`
	LifetimeSec   int                `json:"lifetime_sec"`
	HashDigest    string             `json:"hash_digest"`
	FetchedAt     time.Time          `json:"fetched_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
}

func loadCredentialCache(path string, rooms []string) (map[string]*wgturnclient.Credentials, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential cache must be a regular 0600 file: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache credentialCache
	if err := json.Unmarshal(b, &cache); err != nil {
		return nil, fmt.Errorf("credential cache decode: %w", err)
	}
	if cache.Rooms == nil {
		return loadLegacyCredentialCache(b, rooms)
	}
	out := make(map[string]*wgturnclient.Credentials)
	for _, room := range rooms {
		entry, ok := cache.Rooms[room]
		if !ok || entry.Credentials == nil || entry.AcquiredAt.IsZero() {
			continue
		}
		remaining := time.Until(entry.AcquiredAt.Add(time.Duration(entry.Credentials.Lifetime) * time.Second))
		if remaining > 2*time.Minute {
			creds := cloneCachedCredentials(entry.Credentials)
			creds.Lifetime = int(remaining.Seconds())
			out[room] = creds
		}
	}
	return out, nil
}

func loadLegacyCredentialCache(data []byte, rooms []string) (map[string]*wgturnclient.Credentials, error) {
	var legacy legacyCredentialCache
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("legacy credential cache decode: %w", err)
	}
	if len(rooms) == 0 || legacy.Username == "" || legacy.Password == "" {
		return nil, nil
	}
	if legacy.HashDigest != "" && !strings.EqualFold(legacy.HashDigest, roomHashDigest(rooms[0])) {
		return nil, nil
	}
	remaining := time.Until(legacy.ExpiresAt)
	if legacy.ExpiresAt.IsZero() && !legacy.FetchedAt.IsZero() && legacy.LifetimeSec > 0 {
		remaining = time.Until(legacy.FetchedAt.Add(time.Duration(legacy.LifetimeSec) * time.Second))
	}
	if remaining <= 2*time.Minute {
		return nil, nil
	}
	creds := &wgturnclient.Credentials{
		User: legacy.Username, Pass: legacy.Password, Source: "legacy-cache",
		TurnURLs: append([]string(nil), legacy.TurnServers...), Lifetime: int(remaining.Seconds()),
	}
	for _, server := range legacy.TurnServersV2 {
		creds.TurnServers = append(creds.TurnServers, wgturnclient.TurnServer{
			Host: server.Host, Port: server.Port, Scheme: server.Scheme, Transport: server.Transport,
		})
	}
	if len(creds.TurnURLs) == 0 && len(creds.TurnServers) == 0 {
		return nil, nil
	}
	return map[string]*wgturnclient.Credentials{rooms[0]: creds}, nil
}

func roomHashDigest(room string) string {
	sum := sha256.Sum256([]byte(room))
	return hex.EncodeToString(sum[:8])
}

func cloneCachedCredentials(creds *wgturnclient.Credentials) *wgturnclient.Credentials {
	if creds == nil {
		return nil
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	dup.TurnServers = append([]wgturnclient.TurnServer(nil), creds.TurnServers...)
	return &dup
}

func updateCredentialCache(path, room string, creds *wgturnclient.Credentials) error {
	if strings.TrimSpace(path) == "" || creds == nil {
		return nil
	}
	cache := credentialCache{Version: 1, Rooms: map[string]cacheEntry{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cache)
		if cache.Rooms == nil {
			cache.Rooms = map[string]cacheEntry{}
			cache.Version = 1
		}
	}
	cache.Rooms[room] = cacheEntry{Credentials: creds, AcquiredAt: time.Now()}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vkturn-creds-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(cache); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func readPrivateLines(path string) ([]string, error) { return readPrivateLinesImpl(path, true) }
func readLinesForValidation(path string) []string {
	lines, _ := readPrivateLinesImpl(path, false)
	return lines
}
func readPrivateValue(path string) (string, error) {
	lines, err := readPrivateLinesImpl(path, true)
	if err != nil {
		return "", err
	}
	if len(lines) != 1 || strings.TrimSpace(lines[0]) == "" {
		return "", fmt.Errorf("private value file must contain one non-empty line")
	}
	return strings.TrimSpace(lines[0]), nil
}
func readPrivateLinesImpl(path string, checkMode bool) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("file must be regular and mode 0600: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	if checkMode && len(out) == 0 {
		return nil, fmt.Errorf("file is empty: %s", path)
	}
	return out, nil
}
