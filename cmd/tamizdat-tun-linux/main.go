package main

import (
	"context"
	"encoding/hex"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	"github.com/funnybones69/tamizdat/internal/tunengine"
	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

const (
	defaultVKAppID     = "6287487"
	defaultVKAppSecret = "QbYic1K3lEV5kTGiqlq2"
	defaultVKUserAgent = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36"
	defaultVKDeviceID  = "keenetic-tamizdat-tun-linux"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tamizdat-tun-linux", flag.ContinueOnError)
	fs.SetOutput(stderr)

	// TUN device.
	tunName := fs.String("tun-name", "tun0", "Linux TUN interface name")
	tunAddr := fs.String("tun-addr", "172.19.0.1/30", "IPv4 address (CIDR) assigned to the TUN device. Empty disables auto-assignment.")
	tunMTU := fs.Int("tun-mtu", 1480, "TUN MTU")

	// Auth — either full URI, or individual fields for diagnostics.
	uriFlag := fs.String("uri", "", "Full tamizdat:// URI")
	serverFlag := fs.String("server", "", "Upstream tamizdat-server host:port")
	serverNameFlag := fs.String("servername", "", "TLS SNI / cover domain")
	pubkeyFlag := fs.String("pubkey", "", "Server X25519 public key (64 hex chars)")
	shortIDFlag := fs.String("shortid", "", "Master shortid (16 hex chars)")
	fpFlag := fs.String("fp", "mix", "uTLS fingerprint pool")

	// Transport.
	transport := fs.String("transport", "h2", "Transport mode: h2 or vkturn")
	tcpFrag := fs.Bool("tcpfrag", true, "Enable tamizdat TCP ClientHello fragmentation")
	poolVariant := fs.String("pool-variant", "v1", "H2 transport pool variant")
	strictSingleH2 := fs.Bool("strict-single-h2", false, "STRICT mode: never spawn lite transport, always 1 TCP/443")
	ignoreSigterm := fs.Bool("ignore-sigterm", false, "Ignore early SIGTERM/SIGHUP from Keenetic SSH/start-stop-daemon; init stop uses kill -9 fallback")

	// VK TURN.
	vkHash := fs.String("vk-hash", "", "VK call join hash/link(s) for -transport vkturn; comma-separated")
	vkHashFile := fs.String("vk-hash-file", "", "Read VK call join hash/link(s) from a local 0600 file (keeps it out of argv)")
	vkWorkers := fs.Int("vk-workers", 12, "VK TURN/DTLS workers (per room with multiple -vk-hash values; production multi-room requires 20)")
	vkTurnUDP := fs.Bool("vk-turn-udp", false, "Use UDP to the VK TURN server instead of TCP-to-TURN")
	vkTurnHost := fs.String("vk-turn-host", "", "Override TURN host from VK response")
	vkTurnPort := fs.String("vk-turn-port", "", "Override TURN port from VK response")
	vkFrame := fs.Int("vk-frame", 1150, "VK TURN max DTLS application payload per frame")
	vkTurnUser := fs.String("vk-turn-user", "", "Pre-shared TURN username (bypasses VK captcha)")
	vkTurnPass := fs.String("vk-turn-pass", "", "Pre-shared TURN password (bypasses VK captcha)")
	vkTurnURLs := fs.String("vk-turn-urls", "", "Pre-shared TURN server URLs, comma-separated")
	vkCredsCache := fs.String("vk-creds-cache", "", "Path to persist acquired VK TURN credentials (0600)")
	vkDirect := fs.Bool("vk-direct", false, "Debug/test: bypass VK TURN and connect DTLS directly to -server UDP")
	vkAppID := fs.String("vk-app-id", defaultVKAppID, "VK App ID used by anonymous credential flow")
	vkAppSecret := fs.String("vk-app-secret", defaultVKAppSecret, "VK App secret used by anonymous credential flow")
	vkUserAgent := fs.String("vk-user-agent", defaultVKUserAgent, "User-Agent used by VK credential flow")
	vkDeviceID := fs.String("vk-device-id", defaultVKDeviceID, "Stable device id for VK bot profile generation")

	// Router fallback is accountless: anonymous VKCalls first, then headless RJS;
	// if VK rejects headless automation, a secure local-browser handoff is used.
	vkCaptchaMode := fs.String("vk-captcha-mode", "rjs", "Captcha solver: rjs (then local-browser fallback) or manual")
	vkCredentialMode := fs.String("vk-credential-mode", "auto", "Credential provider: auto, anonymous-only, or rjs-only (forced fallback diagnostics)")
	vkCaptchaDir := fs.String("vk-captcha-dir", "", "Secure directory for local-browser captcha handoff")
	vkCaptchaWait := fs.Duration("vk-captcha-wait", 15*time.Minute, "Wait budget for local-browser captcha handoff")

	// Process / observability.
	soMarkFlag := fs.String("so-mark", "0", "Hex SO_MARK applied to outbound transport sockets, e.g. 0x42. 0 = disabled")
	pidfileFlag := fs.String("pidfile", "", "Write PID to this file on startup, remove on graceful exit. Empty = disabled")
	debugFlag := fs.Bool("debug", false, "Enable verbose flow logs")
	debugListenFlag := fs.String("debug-listen", "", "Listen addr for /debug/vars expvar HTTP. Empty = off")

	// gVisor netstack tuning.
	tcpModerateReceiveBuffer := fs.Bool("tcp-moderate-receive-buffer", true, "Enable gVisor TCP receive-buffer auto-tuning")
	tcpSendBufferSize := fs.Int("tcp-send-buffer-size", 0, "Optional gVisor TCP send buffer size in bytes (0 = default)")
	tcpReceiveBufferSize := fs.Int("tcp-receive-buffer-size", 0, "Optional gVisor TCP receive buffer size in bytes (0 = default)")
	dialAttemptTimeout := fs.Duration("dial-attempt-timeout", 3*time.Second, "Per-attempt timeout for opening a proxied TCP/UDP flow")
	dialConcurrency := fs.Int("dial-concurrency", 0, "Maximum concurrent proxied opens from TUN. 0 = unlimited/default")
	dialActiveConcurrency := fs.Int("dial-active-concurrency", 0, "Maximum active proxied TCP sessions from TUN. 0 = unlimited/default")
	dialOpenInterval := fs.Duration("dial-open-interval", 0, "Minimum interval between starting outer TCP OPEN attempts")
	dialTargetCooldown := fs.Duration("dial-target-cooldown", 0, "Cooldown after failed proxied open to the same ip:port")
	dialTargetCooldownMax := fs.Duration("dial-target-cooldown-max", 0, "Maximum adaptive per-target cooldown")
	dialMinAttemptBudget := fs.Duration("dial-min-attempt-budget", 0, "Minimum caller deadline remaining before starting an outer transport dial")
	dialRecoveryThreshold := fs.Int("dial-recovery-threshold", 0, "Consecutive failed open admissions before pausing new opens")
	dialRecoveryBackoff := fs.Duration("dial-recovery-backoff", 0, "Global pause after --dial-recovery-threshold failures")

	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: %s [flags]

Examples:
  H2:
    %s -uri "tamizdat://host:443/?sni=...&pubkey=...&shortid=..." -tun-name tun0 -so-mark 0x42

  VK TURN:
    %s -transport vkturn -uri "tamizdat://host:443/?sni=...&pubkey=...&shortid=..." -vk-hash "https://vk.ru/call/join/..." -vk-creds-cache /opt/etc/keenetic-panel/vkturn-creds.json

Flags:
`, fs.Name(), fs.Name(), fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	vkHashValue := strings.TrimSpace(*vkHash)
	if path := strings.TrimSpace(*vkHashFile); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: -vk-hash-file: %v\n", err)
			return 2
		}
		vkHashValue = strings.TrimSpace(string(raw))
	}

	parsed, err := parseConfig(*uriFlag, *serverFlag, *serverNameFlag, *pubkeyFlag, *shortIDFlag, *fpFlag)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		fs.Usage()
		return 2
	}
	mode := strings.ToLower(strings.TrimSpace(*transport))
	if mode == "" {
		mode = "h2"
	}
	if mode != "h2" && mode != "vkturn" {
		fmt.Fprintln(stderr, "error: -transport must be h2 or vkturn")
		return 2
	}
	if *strictSingleH2 {
		*poolVariant = "v1"
	}
	if mode == "vkturn" && !*vkDirect && vkHashValue == "" && strings.TrimSpace(*vkTurnUser) == "" && strings.TrimSpace(*vkCredsCache) == "" {
		fmt.Fprintln(stderr, "error: -transport vkturn requires -vk-hash, -vk-creds-cache, or complete -vk-turn-user/-vk-turn-pass/-vk-turn-urls")
		return 2
	}
	if strings.TrimSpace(*vkTurnUser) != "" || strings.TrimSpace(*vkTurnPass) != "" || strings.TrimSpace(*vkTurnURLs) != "" {
		if strings.TrimSpace(*vkTurnUser) == "" || strings.TrimSpace(*vkTurnPass) == "" || strings.TrimSpace(*vkTurnURLs) == "" {
			fmt.Fprintln(stderr, "error: pre-shared VK TURN creds require all of -vk-turn-user/-vk-turn-pass/-vk-turn-urls")
			return 2
		}
	}

	soMark, err := parseSOMark(*soMarkFlag)
	if err != nil {
		fmt.Fprintf(stderr, "error: -so-mark: %v\n", err)
		return 2
	}
	var dialFunc tamizdat.DialFunc
	if soMark != 0 {
		dialFunc = makeSOMarkDialer(soMark)
		log.Printf("outbound SO_MARK enabled: 0x%x", soMark)
	}

	if pf := strings.TrimSpace(*pidfileFlag); pf != "" {
		if err := writePIDFile(pf); err != nil {
			fmt.Fprintf(stderr, "error: pidfile: %v\n", err)
			return 1
		}
		defer func() {
			if rmErr := os.Remove(pf); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("pidfile remove: %v", rmErr)
			}
		}()
	}

	var proxyClient tunengine.ProxyClient
	switch mode {
	case "h2":
		proxyClient, err = tamizdat.NewClient(tamizdat.ClientConfig{
			ServerAddr:       parsed.ServerAddr,
			ServerName:       parsed.ServerName,
			ServerNames:      parsed.ServerNames,
			PublicKey:        parsed.PublicKey,
			MasterShortID:    parsed.MasterShortID,
			Fingerprint:      parsed.Fingerprint,
			MinTransports:    parsed.MinTransports,
			MaxTransports:    parsed.MaxTransports,
			BootstrapSNI:     parsed.BootstrapSNI,
			TCPFragmentation: *tcpFrag,
			PoolVariant:      *poolVariant,
			Dialer:           dialFunc,
		})
		if err != nil {
			fmt.Fprintf(stderr, "client init: %v\n", err)
			return 1
		}
	case "vkturn":
		if *vkDirect {
			fmt.Fprintln(stderr, "error: -vk-direct is unsupported in production wgturn mode")
			return 2
		}
		if *vkWorkers < 1 || *vkWorkers > 20 {
			fmt.Fprintln(stderr, "error: -vk-workers must be between 1 and 20")
			return 2
		}
		vkHashes := tamizdat.ParseVKTurnHashes(vkHashValue)
		totalWorkers, workersPerRoom, bondV2, planErr := planWGTurnRooms(vkHashes, *vkWorkers)
		if planErr != nil {
			fmt.Fprintf(stderr, "error: %v\n", planErr)
			return 2
		}
		captchaMode := strings.ToLower(strings.TrimSpace(*vkCaptchaMode))
		if captchaMode != "rjs" && captchaMode != "manual" {
			fmt.Fprintln(stderr, "error: -vk-captcha-mode must be rjs or manual")
			return 2
		}
		if *vkCaptchaWait <= 0 {
			fmt.Fprintln(stderr, "error: -vk-captcha-wait must be positive")
			return 2
		}
		if *vkFrame > 0 {
			log.Printf("vk-frame=%d ignored in production wgturn mode", *vkFrame)
		}
		password := hex.EncodeToString(parsed.MasterShortID[:])
		proxyClient, err = newWGTurnProxyClient(context.Background(), wgturnProxyConfig{
			Listen:         "127.0.0.1:19000",
			PeerAddr:       parsed.ServerAddr,
			Workers:        totalWorkers,
			WorkersPerRoom: workersPerRoom,
			BondV2:         bondV2,
			UseUDP:         *vkTurnUDP,
			VKHashes:       vkHashes,
			DeviceID:       firstNonEmpty(*vkDeviceID, defaultVKDeviceID),
			ConnPassword:   password,
			VKAppID:        strings.TrimSpace(*vkAppID),
			VKAppSecret:    strings.TrimSpace(*vkAppSecret),
			UserAgent:      firstNonEmpty(*vkUserAgent, defaultVKUserAgent),
			CaptchaMode:    firstNonEmpty(*vkCaptchaMode, "rjs"),
			CaptchaDir:     strings.TrimSpace(*vkCaptchaDir),
			CaptchaWait:    *vkCaptchaWait,
			CredentialMode: strings.ToLower(strings.TrimSpace(*vkCredentialMode)),
			TurnHost:       strings.TrimSpace(*vkTurnHost),
			TurnPort:       strings.TrimSpace(*vkTurnPort),
			SNI:            firstSNI(parsed.ServerName),
			CredCache:      strings.TrimSpace(*vkCredsCache),
			TURNUser:       strings.TrimSpace(*vkTurnUser),
			TURNPass:       strings.TrimSpace(*vkTurnPass),
			TURNURLs:       tamizdat.ParseVKTurnHashes(*vkTurnURLs),
			Dialer:         dialFunc,
		})
		if err != nil {
			fmt.Fprintf(stderr, "wgturn client init: %v\n", err)
			return 1
		}
	}
	defer proxyClient.Close()

	expvar.Publish("tamizdat_transport", expvar.Func(func() interface{} { return mode }))
	if addr := strings.TrimSpace(*debugListenFlag); addr != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			fmt.Fprintf(stderr, "debug-listen: %v\n", lerr)
			return 1
		}
		log.Printf("expvar /debug/vars listening on %s", ln.Addr())
		go func() { _ = (&http.Server{Handler: http.DefaultServeMux}).Serve(ln) }()
	}

	signalList := []os.Signal{os.Interrupt}
	if *ignoreSigterm {
		// Keenetic's admin SSH/init environment can deliver early parent/session
		// signals to freshly backgrounded jobs. The router init script has a
		// kill -9 fallback for real stops, so keep these ignored only when
		// explicitly requested.
		signal.Ignore(syscall.SIGTERM, syscall.SIGHUP)
		log.Printf("SIGTERM/SIGHUP ignored by -ignore-sigterm; stop wrapper will use kill -9 fallback")
	} else {
		signalList = append(signalList, syscall.SIGTERM)
	}
	ctx, stop := signal.NotifyContext(context.Background(), signalList...)
	defer stop()

	opts := tunengine.Options{
		Name:                     *tunName,
		MTU:                      *tunMTU,
		Debug:                    *debugFlag,
		TCPModerateReceiveBuffer: *tcpModerateReceiveBuffer,
		TCPSendBufferSize:        *tcpSendBufferSize,
		TCPReceiveBufferSize:     *tcpReceiveBufferSize,
		DialAttemptTimeout:       *dialAttemptTimeout,
		DialConcurrency:          *dialConcurrency,
		DialActiveConcurrency:    *dialActiveConcurrency,
		DialOpenInterval:         *dialOpenInterval,
		DialTargetCooldown:       *dialTargetCooldown,
		DialTargetCooldownMax:    *dialTargetCooldownMax,
		DialMinAttemptBudget:     *dialMinAttemptBudget,
		DialRecoveryThreshold:    *dialRecoveryThreshold,
		DialRecoveryBackoff:      *dialRecoveryBackoff,
		PostTunUp: func() error {
			if strings.TrimSpace(*tunAddr) == "" {
				log.Printf("tun-addr empty: caller is responsible for IP assignment + link up")
				return nil
			}
			return assignTunAddr(*tunName, *tunAddr)
		},
	}

	cacheState := "off"
	if strings.TrimSpace(*vkCredsCache) != "" {
		cacheState = "on"
	}
	log.Printf("tamizdat TUN starting: server=%s transport=%s sni=%s fp=%s pool=%q tun=%s mtu=%d so-mark=0x%x vk_cache=%s",
		parsed.ServerAddr, mode, parsed.ServerName, parsed.Fingerprint, *poolVariant, opts.Name, opts.MTU, soMark, cacheState)

	if err := tunengine.Run(ctx, opts, proxyClient); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "tun: %v\n", err)
		return 1
	}
	log.Printf("shutdown complete")
	return 0
}

func planWGTurnRooms(hashes []string, workers int) (totalWorkers, workersPerRoom int, bondV2 bool, err error) {
	rooms := len(hashes)
	if rooms < 1 {
		return 0, 0, false, errors.New("VK TURN requires at least one room")
	}
	if rooms > 4 {
		return 0, 0, false, fmt.Errorf("VK TURN supports at most 4 rooms, got %d", rooms)
	}
	if workers < 1 || workers > 20 {
		return 0, 0, false, fmt.Errorf("VK TURN workers must be between 1 and 20, got %d", workers)
	}
	if rooms == 1 {
		return workers, 0, false, nil
	}
	if workers != 20 {
		return 0, 0, false, fmt.Errorf("multi-room production mode requires exactly 20 workers per room, got %d", workers)
	}
	return rooms * workers, workers, true, nil
}

type parsedConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	PublicKey     []byte
	MasterShortID [8]byte
	Fingerprint   string
	MinTransports int
	MaxTransports int
	BootstrapSNI  string
}

func parseConfig(uri, server, serverName, pubHex, shortIDHex, fp string) (parsedConfig, error) {
	if strings.TrimSpace(uri) != "" {
		if strings.TrimSpace(server) != "" || strings.TrimSpace(pubHex) != "" || strings.TrimSpace(shortIDHex) != "" {
			return parsedConfig{}, errors.New("-uri is mutually exclusive with -server/-pubkey/-shortid")
		}
		cfg, err := configurl.Parse(uri)
		if err != nil {
			return parsedConfig{}, err
		}
		return parsedConfig{
			ServerAddr:    cfg.ServerAddr,
			ServerName:    cfg.ServerName,
			ServerNames:   cfg.ServerNames,
			PublicKey:     cfg.PublicKey,
			MasterShortID: cfg.MasterShortID,
			Fingerprint:   firstNonEmpty(cfg.Fingerprint, fp),
			MinTransports: cfg.MinTransports,
			MaxTransports: cfg.MaxTransports,
			BootstrapSNI:  cfg.BootstrapSNI,
		}, nil
	}
	if strings.TrimSpace(server) == "" || strings.TrimSpace(shortIDHex) == "" {
		return parsedConfig{}, errors.New("must pass -uri OR all required individual fields (-server/-shortid, plus -pubkey/-servername for h2)")
	}
	sid, err := decodeHex(shortIDHex, 8)
	if err != nil {
		return parsedConfig{}, fmt.Errorf("-shortid: %w", err)
	}
	var masterShortID [8]byte
	copy(masterShortID[:], sid)
	var pub []byte
	if strings.TrimSpace(pubHex) != "" {
		pub, err = decodeHex(pubHex, 32)
		if err != nil {
			return parsedConfig{}, fmt.Errorf("-pubkey: %w", err)
		}
	}
	serverName = strings.TrimSpace(serverName)
	return parsedConfig{
		ServerAddr:    strings.TrimSpace(server),
		ServerName:    firstSNI(serverName),
		ServerNames:   parseSNIPool(serverName),
		PublicKey:     pub,
		MasterShortID: masterShortID,
		Fingerprint:   firstNonEmpty(fp, "mix"),
		BootstrapSNI:  firstSNI(serverName),
	}, nil
}

func decodeHex(s string, want int) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != want*2 {
		return nil, fmt.Errorf("expected %d hex chars (%d bytes), got %d", want*2, want, len(s))
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseSOMark(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

func writePIDFile(path string) error {
	pid := os.Getpid()
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d\n", pid); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func assignTunAddr(name, addrCIDR string) error {
	if name == "" {
		return errors.New("tun name empty")
	}
	if addrCIDR == "" {
		return errors.New("tun addr empty")
	}
	if _, _, err := net.ParseCIDR(addrCIDR); err != nil {
		return fmt.Errorf("parse tun-addr CIDR %q: %w", addrCIDR, err)
	}
	if out, err := runIP("addr", "add", addrCIDR, "dev", name); err != nil {
		lower := strings.ToLower(out)
		if !strings.Contains(lower, "file exists") {
			return fmt.Errorf("ip addr add %s dev %s: %v (%s)", addrCIDR, name, err, strings.TrimSpace(out))
		}
	}
	if out, err := runIP("link", "set", name, "up"); err != nil {
		return fmt.Errorf("ip link set %s up: %v (%s)", name, err, strings.TrimSpace(out))
	}
	log.Printf("tun configured: %s addr=%s up", name, addrCIDR)
	return nil
}

func runIP(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func parseSNIPool(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstSNI(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ','); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
