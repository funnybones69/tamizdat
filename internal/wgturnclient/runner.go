package wgturnclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListen  = "127.0.0.1:9000"
	defaultWorkers = workersPerGroup
	maxWorkers     = 20
	// MaxRooms and the worker limits are exported so CLI validation, the
	// capability manifest, and the runtime share one production contract.
	MaxRooms            = 6
	MaxWorkersPerRoom   = 20
	MaxMultiRoomWorkers = MaxRooms * MaxWorkersPerRoom
	defaultVKAppID      = "6287487"
	defaultVKAppSecret  = "QbYic1K3lEV5kTGiqlq2"
	defaultUserAgent    = "Mozilla/5.0"
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Config struct {
	Listen   string
	PeerAddr string
	Workers  int
	// WorkersPerRoom enables explicit multi-room fanout. When positive, each
	// VKHashes entry receives this many workers and Workers is ignored. The
	// normal production path keeps Workers capped at maxWorkers.
	WorkersPerRoom       int
	UseUDP               bool
	UseTCP               bool
	VKHashes             []string
	SecondaryHash        string
	DeviceID             string
	ConnPassword         string
	VKAppID              string
	VKAppSecret          string
	UserAgent            string
	CaptchaMode          string
	CaptchaDir           string
	CaptchaWait          time.Duration
	CredentialMode       string
	NoDNS                bool
	PreloadedCreds       *Credentials
	PreloadedCredsByHash map[string]*Credentials
	// AcquireRoomCredentials optionally supplies fresh per-room TURN material
	// from an external, locally trusted helper. OpenWrt uses this to preserve
	// the proven anonymous helper as the first provider while retaining the
	// built-in autonomous providers as fallback.
	AcquireRoomCredentials func(context.Context, string) (*Credentials, error)
	BondV2                 bool
	WorkerRateBPS          int
	OnConfig               func(string)
	OnQuota                func(string)
	OnWorkerCount          func(int)
	OnEvent                EventFunc
	// OnCredentials is called after a fresh legacy single-room acquisition.
	OnCredentials func(*Credentials)
	// OnRoomCredentials identifies the room so router clients can persist
	// independent short-lived TURN material without mixing room quotas.
	OnRoomCredentials func(string, *Credentials)
	Dialer            DialContextFunc

	TurnHost    string
	TurnPort    string
	SNI         string
	SplitTunnel bool
}

type Runner struct {
	cfg Config

	vkAppID              atomic.Value
	vkAppSecret          atomic.Value
	captchaMode          atomic.Value
	credentialMode       atomic.Value
	noDNS                atomic.Bool
	userAgent            atomic.Value
	preloadedCreds       atomic.Pointer[Credentials]
	preloadedCredsMu     sync.Mutex
	preloadedCredsExpiry atomic.Int64
	roomCredsMu          sync.Mutex
	roomCreds            map[string]roomCredentialCacheEntry

	captchaResultCh chan string
	vkSemaphore     chan struct{}
	captchaWVSem    chan struct{}

	cacheMutex         sync.Mutex
	cachedSuccessToken string
	cachedTokenUsages  int32
	groupAuthMutex     sync.Mutex
	roomAuthMu         sync.Mutex
	roomAuthLocks      map[string]*sync.Mutex
	forcedCredsMu      sync.Mutex
	forcedCredsAt      map[string]time.Time

	pauseFlag int32

	runtimeMu sync.Mutex
	cancel    context.CancelFunc
	localConn net.PacketConn
}

func New(cfg Config) (*Runner, error) {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	cfg.PeerAddr = strings.TrimSpace(cfg.PeerAddr)
	cfg.SecondaryHash = strings.TrimSpace(cfg.SecondaryHash)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	if cfg.DeviceID == "" {
		cfg.DeviceID = "unknown"
	}
	cfg.VKAppID = strings.TrimSpace(cfg.VKAppID)
	if cfg.VKAppID == "" {
		cfg.VKAppID = defaultVKAppID
	}
	cfg.VKAppSecret = strings.TrimSpace(cfg.VKAppSecret)
	if cfg.VKAppSecret == "" {
		cfg.VKAppSecret = defaultVKAppSecret
	}
	cfg.CaptchaMode = strings.TrimSpace(cfg.CaptchaMode)
	if cfg.CaptchaMode == "" {
		cfg.CaptchaMode = "rjs"
	}
	cfg.CaptchaDir = strings.TrimSpace(cfg.CaptchaDir)
	if cfg.CaptchaWait <= 0 {
		cfg.CaptchaWait = 15 * time.Minute
	}
	cfg.CredentialMode = strings.ToLower(strings.TrimSpace(cfg.CredentialMode))
	if cfg.CredentialMode == "" {
		cfg.CredentialMode = "auto"
	}
	if cfg.CredentialMode != "auto" && cfg.CredentialMode != "anonymous-only" && cfg.CredentialMode != "rjs-only" {
		return nil, fmt.Errorf("credential mode must be auto, anonymous-only, or rjs-only")
	}
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if !cfg.UseTCP && !cfg.UseUDP {
		cfg.UseTCP = true
	}
	if cfg.WorkerRateBPS <= 0 {
		cfg.WorkerRateBPS = DefaultWorkerRateBPS
	}
	cfg.VKHashes = normalizeHashes(cfg.VKHashes)
	if len(cfg.VKHashes) == 0 && cfg.PreloadedCreds != nil {
		cfg.VKHashes = []string{"preloaded"}
	}
	if cfg.PeerAddr == "" || len(cfg.VKHashes) == 0 {
		return nil, fmt.Errorf("нужны PeerAddr и VKHashes")
	}
	if cfg.WorkersPerRoom > 0 {
		if len(cfg.VKHashes) > MaxRooms {
			return nil, fmt.Errorf("multi-room supports at most %d rooms", MaxRooms)
		}
		if cfg.BondV2 && len(cfg.VKHashes) < 2 {
			return nil, fmt.Errorf("Bond v2 requires multi-room mode with at least 2 rooms")
		}
		if cfg.WorkersPerRoom > MaxWorkersPerRoom {
			return nil, fmt.Errorf("workers per room must be between 1 and %d", MaxWorkersPerRoom)
		}
		if cfg.SecondaryHash != "" {
			return nil, fmt.Errorf("secondary hash is incompatible with multi-room mode")
		}
		if cfg.PreloadedCreds != nil {
			return nil, fmt.Errorf("single preloaded credential set is incompatible with multi-room mode")
		}
		configuredRooms := make(map[string]struct{}, len(cfg.VKHashes))
		for _, hash := range cfg.VKHashes {
			configuredRooms[hash] = struct{}{}
		}
		for hash, creds := range cfg.PreloadedCredsByHash {
			if _, ok := configuredRooms[hash]; !ok {
				return nil, fmt.Errorf("preloaded room credentials contain an unconfigured room")
			}
			if creds == nil {
				return nil, fmt.Errorf("preloaded room credentials contain an empty entry")
			}
		}
		cfg.Workers = cfg.WorkersPerRoom * len(cfg.VKHashes)
		if cfg.Workers > MaxMultiRoomWorkers {
			return nil, fmt.Errorf("multi-room worker total exceeds %d", MaxMultiRoomWorkers)
		}
	} else {
		if len(cfg.PreloadedCredsByHash) > 0 {
			return nil, fmt.Errorf("room-scoped preloaded credentials require multi-room mode")
		}
		if cfg.BondV2 {
			return nil, fmt.Errorf("Bond v2 requires WorkersPerRoom multi-room mode")
		}
		cfg.Workers = normalizeWorkerCount(cfg.Workers)
	}

	r := &Runner{
		cfg:             cfg,
		captchaResultCh: make(chan string, 1),
		vkSemaphore:     make(chan struct{}, 2),
		captchaWVSem:    make(chan struct{}, 1),
		roomCreds:       make(map[string]roomCredentialCacheEntry),
		roomAuthLocks:   make(map[string]*sync.Mutex),
		forcedCredsAt:   make(map[string]time.Time),
	}
	r.vkAppID.Store(cfg.VKAppID)
	r.vkAppSecret.Store(cfg.VKAppSecret)
	r.captchaMode.Store(cfg.CaptchaMode)
	r.credentialMode.Store(cfg.CredentialMode)
	r.userAgent.Store(cfg.UserAgent)
	r.noDNS.Store(cfg.NoDNS)
	if cfg.PreloadedCreds != nil {
		r.UpdatePreloadedCreds(cfg.PreloadedCreds)
	}
	for hash, creds := range cfg.PreloadedCredsByHash {
		r.updateRoomCreds(hash, creds)
	}
	return r, nil
}

func (r *Runner) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	if err := r.setRuntime(cancel, nil); err != nil {
		cancel()
		return err
	}
	defer func() {
		cancel()
		r.clearRuntime()
	}()

	peer, err := net.ResolveUDPAddr("udp", r.cfg.PeerAddr)
	if err != nil {
		return fmt.Errorf("ошибка разбора пира: %w", err)
	}

	tp := &TurnParams{
		Host:          r.cfg.TurnHost,
		Port:          r.cfg.TurnPort,
		Hashes:        r.cfg.VKHashes,
		SecondaryHash: r.cfg.SecondaryHash,
		Sni:           r.cfg.SNI,
	}

	localConn, err := net.ListenPacket("udp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("ошибка слушателя %s: %w", r.cfg.Listen, err)
	}
	r.setLocalConn(localConn)
	defer localConn.Close()
	if uc, ok := localConn.(*net.UDPConn); ok {
		// This is one shared dispatcher socket, so retain the single-room
		// capacity. Per-worker TURN sockets use an adaptive memory profile.
		_ = uc.SetReadBuffer(singleRoomSocketBufSize)
		_ = uc.SetWriteBuffer(singleRoomSocketBufSize)
	}
	stopLocalConn := context.AfterFunc(runCtx, func() { _ = localConn.Close() })
	defer stopLocalConn()

	_, localPort, _ := net.SplitHostPort(r.cfg.Listen)
	if localPort == "" {
		localPort = "9000"
	}

	plans := buildWorkerGroupPlans(r.cfg.Workers, len(r.cfg.VKHashes), r.cfg.WorkersPerRoom)
	numGroups := len(plans)

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK App: %s", r.cfg.VKAppID)
	log.Printf("[КЛИЕНТ] Воркеров: %d (комнат: %d, на комнату: %d, групп: %d, максимум в группе: %d)", r.cfg.Workers, len(r.cfg.VKHashes), r.cfg.WorkersPerRoom, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(r.cfg.VKHashes))
	log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", r.cfg.Listen, r.cfg.PeerAddr)
	proto := "TCP"
	if r.cfg.UseUDP {
		proto = "UDP"
	}
	log.Printf("[КЛИЕНТ] Протокол: %s", proto)
	log.Printf("[КЛИЕНТ] Device ID: %s", r.cfg.DeviceID)
	log.Printf("[КЛИЕНТ] Обход капчи: %s", r.getCaptchaMode())
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")

	stats := NewStats()
	if r.cfg.BondV2 {
		atomic.StoreInt32(&stats.BondRoomsConfigured, int32(len(r.cfg.VKHashes)))
		atomic.StoreInt32(&stats.BondWorkersRequestedPerRoom, int32(r.cfg.WorkersPerRoom))
	}
	bondID := bondRunnerIdentity{}
	if r.cfg.BondV2 {
		var idErr error
		bondID, idErr = newBondRunnerIdentity()
		if idErr != nil {
			return idErr
		}
		emitEvent(r.cfg.OnEvent, "info", "bond v2 enabled rooms=%d runIDLen=%d tokenLen=%d", len(r.cfg.VKHashes), len(bondID.RunID), len(bondID.Token))
	}
	shutdownCh := make(chan struct{})
	go func() {
		<-runCtx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcherWithOptions(runCtx, localConn, stats, r.cfg.BondV2, len(r.cfg.VKHashes), r.cfg.WorkerRateBPS, r.cfg.OnEvent)
	disp.onWorkerCount = r.cfg.OnWorkerCount
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}
			finalConf := ensureConfigMTU(rawConf)
			if r.cfg.SplitTunnel {
				finalConf = ModifyConfigForSplitTunnel(finalConf, peer.IP)
			}
			if r.cfg.OnConfig != nil {
				r.cfg.OnConfig(finalConf)
			}
		case <-runCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1
	roomWaitReady := make([]<-chan struct{}, len(r.cfg.VKHashes))
	broker := &configBroker{ch: configCh}

	for g, plan := range plans {
		myWaitReady := roomWaitReady[plan.hashIndex]
		var mySignalReady chan<- struct{}
		if g+1 < numGroups && plans[g+1].hashIndex == plan.hashIndex {
			ch := make(chan struct{})
			mySignalReady = ch
			roomWaitReady[plan.hashIndex] = ch
		} else {
			roomWaitReady[plan.hashIndex] = nil
		}

		ids := make([]int, plan.workerCount)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		cycle := time.Duration(defaultCycleSecs) * time.Second

		wg.Add(1)
		go func(groupID int, cycleDir time.Duration, workerIDs []int, startHashIndex int, roomID int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			r.workerGroup(runCtx, groupID, startHashIndex, roomID, tp, peer, disp, localPort, r.cfg.UseUDP,
				broker, workerIDs, cycleDir, &r.pauseFlag, r.cfg.DeviceID, r.cfg.ConnPassword, stats, waitR, sigR, r.cfg.Dialer, r.cfg.BondV2, bondID)
		}(gID, cycle, ids, plan.hashIndex, plan.roomID, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
	return nil
}

func (r *Runner) Shutdown() {
	r.runtimeMu.Lock()
	cancel := r.cancel
	localConn := r.localConn
	r.runtimeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if localConn != nil {
		_ = localConn.Close()
	}
}

// UpdatePreloadedCreds atomically swaps the credentials used by the next
// worker-group rotation. External helpers can refresh VK TURN creds out of
// band and publish only short-lived TURN material here, without uploading raw
// VK cookies/passwords to the router.
func (r *Runner) UpdatePreloadedCreds(creds *Credentials) {
	if creds == nil {
		return
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	if len(creds.TurnServers) > 0 {
		dup.TurnServers = append([]TurnServer(nil), creds.TurnServers...)
	}
	r.preloadedCredsMu.Lock()
	defer r.preloadedCredsMu.Unlock()
	r.preloadedCredsExpiry.Store(time.Now().Add(credentialReuseDuration(creds)).UnixNano())
	r.preloadedCreds.Store(&dup)
}

func (r *Runner) currentPreloadedCreds() *Credentials {
	r.preloadedCredsMu.Lock()
	defer r.preloadedCredsMu.Unlock()
	creds := r.preloadedCreds.Load()
	if creds == nil {
		return nil
	}
	expires := r.preloadedCredsExpiry.Load()
	if expires > 0 && time.Now().UnixNano() >= expires {
		r.preloadedCreds.Store(nil)
		return nil
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	dup.TurnServers = append([]TurnServer(nil), creds.TurnServers...)
	return &dup
}

func credentialReuseDuration(creds *Credentials) time.Duration {
	lifetime := 600
	if creds != nil && creds.Lifetime > 0 {
		lifetime = creds.Lifetime
	}
	safety := 120
	if lifetime <= 240 {
		safety = 30
	}
	if lifetime <= 60 {
		safety = 5
	}
	seconds := lifetime - safety
	if seconds < 5 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}

func (r *Runner) getCredentialMode() string {
	if value := r.credentialMode.Load(); value != nil {
		if mode, ok := value.(string); ok && mode != "" {
			return mode
		}
	}
	return "auto"
}

func (r *Runner) SetPaused(paused bool) {
	if paused {
		atomic.StoreInt32(&r.pauseFlag, 1)
		return
	}
	atomic.StoreInt32(&r.pauseFlag, 0)
}

func (r *Runner) SubmitCaptchaResult(result string) {
	r.drainCaptchaResult()
	r.captchaResultCh <- result
}

func (r *Runner) drainCaptchaResult() {
	select {
	case <-r.captchaResultCh:
	default:
	}
}

func (r *Runner) setRuntime(cancel context.CancelFunc, localConn net.PacketConn) error {
	r.runtimeMu.Lock()
	defer r.runtimeMu.Unlock()
	if r.cancel != nil {
		return fmt.Errorf("runner already started")
	}
	r.cancel = cancel
	r.localConn = localConn
	return nil
}

func (r *Runner) setLocalConn(localConn net.PacketConn) {
	r.runtimeMu.Lock()
	r.localConn = localConn
	r.runtimeMu.Unlock()
}

func (r *Runner) clearRuntime() {
	r.runtimeMu.Lock()
	r.cancel = nil
	r.localConn = nil
	r.runtimeMu.Unlock()
}

func normalizeWorkerCount(n int) int {
	if n <= 0 {
		n = defaultWorkers
	}
	if n > maxWorkers {
		n = maxWorkers
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (r *Runner) credentialLock(hash string) *sync.Mutex {
	if r.cfg.WorkersPerRoom <= 0 {
		return &r.groupAuthMutex
	}
	key := normalizeVKCallHash(hash)
	r.roomAuthMu.Lock()
	defer r.roomAuthMu.Unlock()
	lock := r.roomAuthLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		r.roomAuthLocks[key] = lock
	}
	return lock
}

func normalizeHashes(hashes []string) []string {
	result := make([]string, 0, len(hashes))
	seen := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		hash = normalizeVKCallHash(hash)
		if hash == "" {
			continue
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		result = append(result, hash)
	}
	return result
}

// NormalizeVKCallHashes normalizes invite URLs/hashes and removes duplicates
// without exposing the room values in logs or errors.
func NormalizeVKCallHashes(hashes []string) []string {
	return normalizeHashes(hashes)
}

func ensureConfigMTU(conf string) string {
	if strings.Contains(conf, "MTU =") {
		return conf
	}
	lines := strings.Split(conf, "\n")
	newLines := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.TrimSpace(line) == "[Interface]" {
			newLines = append(newLines, "MTU = 1280")
		}
	}
	return strings.Join(newLines, "\n")
}
