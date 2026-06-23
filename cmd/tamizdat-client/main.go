// Command tamizdat-client runs a local SOCKS5 proxy that tunnels connections
// through a Tamizdat server.
//
// Supported SOCKS5 surface:
//   - CMD: CONNECT (0x01) and UDP ASSOCIATE (0x03); BIND (0x02) is rejected
//     with reply 0x07.
//   - ATYP: IPv4 (0x01), domain (0x03, remote DNS / socks5h semantics), and
//     IPv6 (0x04).
//   - AUTH: NO AUTH (0x00) by default; optional USER/PASS (0x02) when
//     --auth-user/--auth-pass are configured.
//   - Default listen: 127.0.0.1:1080 (loopback only).
//
// Usage:
//
//	tamizdat-client -config-file ./profile.uri -listen 127.0.0.1:1080
//	tamizdat-client -server host:port -servername NAME -pubkey HEX -shortid HEX -listen 127.0.0.1:1080
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/internal/configurl"
	"github.com/funnybones69/tamizdat/internal/transport/fragpoc"
	"github.com/funnybones69/tamizdat/pkg/tamizdat"
)

type socksDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, address string) (net.PacketConn, error)
}

type closeableSocksDialer interface {
	socksDialer
	Close() error
}

type socksConfig struct {
	Debug    bool
	AuthUser string
	AuthPass string
}

func (cfg socksConfig) authConfigured() bool {
	return cfg.AuthUser != "" || cfg.AuthPass != ""
}

func main() {
	var (
		profileURI        string
		profileFile       = flag.String("config-file", "", "Path to file containing a tamizdat:// profile URI (recommended; avoids putting secrets in argv)")
		serverAddr        = flag.String("server", "", "Tamizdat server addr host:port")
		serverName        = flag.String("servername", "", "TLS ServerName (SNI) — cover domain")
		pubHex            = flag.String("pubkey", "", "Server X25519 public key (hex, 64 chars)")
		shortIDHex        = flag.String("shortid", "", "Short ID (hex, 16 chars)")
		listenAddr        = flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen addr")
		transport         = flag.String("transport", "h2", "Transport mode: h2, fragpoc, or vkturn")
		fragPoCWorkers    = flag.Int("fragpoc-workers", fragpoc.DefaultWorkers, "FragPoC short-TCP operation budget per client (1-120)")
		fragPoCDownWindow = flag.Int("fragpoc-down-window", 0, "FragPoC concurrent DOWN polls per logical stream. 0 = legacy window 1; experimental.")
		fragPoCMaxPayload = flag.Int("fragpoc-max-payload", 0, "FragPoC client DOWN data chunk cap in bytes. 0 = transport default; use ~220 with a microchunk LTE server.")
		fragPoCPortPool   = flag.String("fragpoc-port-pool", "", "FragPoC client: extra server ports to spread per-op dials across — comma-separated ports and/or \"lo-hi\" ranges, e.g. \"31510-31560\". Empty = single port.")
		fragPoCSecure     = flag.Bool("fragpoc-secure", false, "Enable FragPoC secure-v1 AEAD framing")
		vkHash            = flag.String("vk-hash", "", "VK call join hash/link(s) for --transport vkturn; comma-separated")
		vkDirect          = flag.Bool("vk-direct", false, "Debug/test: bypass VK TURN and connect DTLS directly to --server UDP")
		vkWorkers         = flag.Int("vk-workers", 12, "VK TURN/DTLS worker sessions")
		vkTurnUDP         = flag.Bool("vk-turn-udp", false, "Use UDP to the VK TURN server instead of TCP-to-TURN")
		vkTurnHost        = flag.String("vk-turn-host", "", "Override TURN host from VK response")
		vkTurnPort        = flag.String("vk-turn-port", "", "Override TURN port from VK response")
		vkFrame           = flag.Int("vk-frame", 1150, "VK TURN max DTLS application payload per frame")
		vkTurnUser        = flag.String("vk-turn-user", "", "Pre-shared TURN username (bypasses VK captcha)")
		vkTurnPass        = flag.String("vk-turn-pass", "", "Pre-shared TURN password (bypasses VK captcha)")
		vkTurnURLs        = flag.String("vk-turn-urls", "", "Pre-shared TURN server URLs, comma-separated")
		vkCredsCache      = flag.String("vk-creds-cache", "", "Path to persist acquired VK TURN credentials (0600). Survives restarts and bootstraps the relay after a whitelist blocks all but VK, without re-solving a captcha.")
		vkCaptchaDir      = flag.String("vk-captcha-dir", "", "Directory for human-in-the-loop captcha break-glass: writes challenge.json and awaits result-<id>.json (success_token solved in a real browser on the LAN). Empty uses the automated solver.")
		fingerprint       = flag.String("fp", "mix", "uTLS fingerprint (mix/chrome/firefox/safari)")
		tcpFrag           = flag.Bool("tcpfrag", true, "Enable TCP fragmentation on ClientHello")
		rotationOverlap   = flag.Int("rotation-overlap", -1, "Debug: V1 byte-cap rotation overlap allowance; -1 uses variant default")
		debug             = flag.Bool("debug", false, "Enable debug logs")
		authUser          = flag.String("auth-user", "", "SOCKS5 username for RFC 1929 USER/PASS auth (requires --auth-pass)")
		authPass          = flag.String("auth-pass", "", "SOCKS5 password for RFC 1929 USER/PASS auth (requires --auth-user)")
	)
	flag.StringVar(&profileURI, "config", "", "tamizdat:// profile URI (prefer --config-file to avoid exposing secrets in argv)")
	flag.StringVar(&profileURI, "uri", "", "Alias for --config")
	flag.Parse()

	if *profileFile != "" {
		if strings.TrimSpace(profileURI) != "" {
			log.Fatal("--config/--uri and --config-file are mutually exclusive")
		}
		b, err := os.ReadFile(*profileFile)
		if err != nil {
			log.Fatalf("read --config-file: %v", err)
		}
		profileURI = strings.TrimSpace(string(b))
	}
	if strings.TrimSpace(profileURI) != "" {
		if *serverAddr != "" || *serverName != "" || *pubHex != "" || *shortIDHex != "" {
			log.Fatal("--config/--uri cannot be combined with --server/--servername/--pubkey/--shortid")
		}
		if err := applyProfileURI(profileURI, serverAddr, serverName, pubHex, shortIDHex, fingerprint, transport); err != nil {
			log.Fatalf("--config: %v", err)
		}
	}

	mode := strings.ToLower(strings.TrimSpace(*transport))
	if mode == "" {
		mode = "h2"
	}
	if mode != "h2" && mode != "fragpoc" && mode != "vkturn" {
		log.Fatal("--transport must be h2, fragpoc, or vkturn")
	}
	if *serverAddr == "" || *shortIDHex == "" {
		log.Fatal("--server and --shortid required")
	}
	if mode == "h2" && (*serverName == "" || *pubHex == "") {
		log.Fatal("--servername and --pubkey required for --transport h2")
	}
	if mode == "vkturn" && !*vkDirect && strings.TrimSpace(*vkHash) == "" && *vkTurnUser == "" {
		log.Fatal("--vk-hash or --vk-turn-user/--vk-turn-pass required for --transport vkturn unless --vk-direct is set")
	}
	if (*authUser == "") != (*authPass == "") {
		log.Fatal("--auth-user and --auth-pass must be set together")
	}

	b, err := hex.DecodeString(*shortIDHex)
	if err != nil || len(b) != 8 {
		log.Fatal("--shortid must be exactly 16 hex characters")
	}
	var masterShortID [8]byte
	copy(masterShortID[:], b)

	var client closeableSocksDialer
	switch mode {
	case "h2":
		pub, err := hex.DecodeString(*pubHex)
		if err != nil || len(pub) != 32 {
			log.Fatal("--pubkey must be 64 hex chars (32 bytes)")
		}
		cfg := tamizdat.ClientConfig{
			ServerAddr:       *serverAddr,
			ServerName:       firstSNI(*serverName),
			ServerNames:      parseSNIPool(*serverName),
			PublicKey:        pub,
			MasterShortID:    masterShortID,
			Fingerprint:      *fingerprint,
			TCPFragmentation: *tcpFrag,
		}
		if *rotationOverlap >= 0 {
			cfg.RotationOverlapAllowance = *rotationOverlap
		}
		client, err = tamizdat.NewClient(cfg)
		if err != nil {
			log.Fatalf("client init: %v", err)
		}
	case "fragpoc":
		fragPoCPool, perr := tamizdat.ParseFragPoCPortPool(*fragPoCPortPool)
		if perr != nil {
			log.Fatalf("--fragpoc-port-pool: %v", perr)
		}
		client, err = fragpoc.NewClient(fragpoc.ClientConfig{
			ServerAddr:      *serverAddr,
			ShortID:         masterShortID,
			Secure:          *fragPoCSecure,
			MaxPayload:      *fragPoCMaxPayload,
			Workers:         *fragPoCWorkers,
			DownWindow:      *fragPoCDownWindow,
			DynamicPortPool: fragPoCPool,
		})
		if err != nil {
			log.Fatalf("fragpoc client init: %v", err)
		}
	case "vkturn":
		client, err = tamizdat.NewVKTurnClient(tamizdat.VKTurnClientConfig{
			ServerAddr:      *serverAddr,
			ShortID:         masterShortID,
			VKHashes:        tamizdat.ParseVKTurnHashes(*vkHash),
			SNI:             firstSNI(*serverName),
			Workers:         *vkWorkers,
			UseUDP:          *vkTurnUDP,
			TURNHost:        *vkTurnHost,
			TURNPort:        *vkTurnPort,
			Direct:          *vkDirect,
			MaxFramePayload: *vkFrame,
			ConnectTimeout:  30 * time.Second,
			TURNUser:        *vkTurnUser,
			TURNPass:        *vkTurnPass,
			TURNURLs:        tamizdat.ParseVKTurnHashes(*vkTurnURLs),
			CredCachePath:   *vkCredsCache,
			CaptchaDir:      *vkCaptchaDir,
		})
		if err != nil {
			log.Fatalf("vkturn client init: %v", err)
		}
	}
	defer client.Close()

	socksCfg := socksConfig{
		Debug:    *debug,
		AuthUser: *authUser,
		AuthPass: *authPass,
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("tamizdat SOCKS5 listening on %s → %s (transport=%s SNI=%s)", *listenAddr, *serverAddr, mode, firstSNI(*serverName))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutdown")
		ln.Close()
		client.Close()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if socksCfg.Debug {
				log.Printf("accept: %v", err)
			}
			return
		}
		go handleSocks(conn, client, socksCfg)
	}
}

func applyProfileURI(raw string, serverAddr, serverName, pubHex, shortIDHex, fingerprint, transport *string) error {
	raw = strings.TrimSpace(raw)
	cfg, err := configurl.Parse(raw)
	if err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	profileTransport := strings.ToLower(strings.TrimSpace(u.Query().Get("transport")))
	if profileTransport != "" && profileTransport != "h2" {
		return fmt.Errorf("profile transport %q is not supported by tamizdat-client --config yet; use explicit flags for advanced transports", profileTransport)
	}
	if tr := strings.ToLower(strings.TrimSpace(*transport)); tr != "" && tr != "h2" {
		return fmt.Errorf("--config supports H2 profiles only; got --transport %s", *transport)
	}
	*transport = "h2"
	*serverAddr = cfg.ServerAddr
	*serverName = strings.Join(cfg.ServerNames, ",")
	*pubHex = hex.EncodeToString(cfg.PublicKey)
	*shortIDHex = hex.EncodeToString(cfg.MasterShortID[:])
	if cfg.Fingerprint != "" {
		*fingerprint = cfg.Fingerprint
	}
	return nil
}

// Minimal SOCKS5 (TCP CONNECT, optional RFC 1929 USER/PASS auth). Spec RFC 1928.
func handleSocks(c net.Conn, sc socksDialer, cfg socksConfig) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))

	if cfg.Debug {
		log.Printf("socks5 conn from %s", c.RemoteAddr())
	}

	if err := negotiateSocksAuth(c, cfg); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 {
		_, _ = c.Write([]byte{0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	switch buf[1] {
	case 0x01:
		// CONNECT — falls through to existing TCP path below.
	case 0x03:
		// UDP ASSOCIATE — handle entirely in udpAssociateLoop and return.
		handleUDPAssociate(c, sc, cfg)
		return
	default:
		// BIND etc — not supported.
		_, _ = c.Write([]byte{0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
	case 0x03: // domain
		if n < 5 || n < 5+int(buf[4])+2 {
			return
		}
		host = string(buf[5 : 5+int(buf[4])])
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		host = net.IP(buf[4:20]).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portStart := n - 2
	port := binary.BigEndian.Uint16(buf[portStart : portStart+2])
	dest := fmt.Sprintf("%s:%d", host, port)

	c.SetReadDeadline(time.Time{})

	// Dial via tamizdat
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tunnel, err := sc.DialContext(ctx, "tcp", dest)
	if err != nil {
		if cfg.Debug {
			log.Printf("dial %s: %v", dest, err)
		}
		_, _ = c.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer tunnel.Close()

	// SOCKS5 success reply (bound addr ignored by most clients)
	if _, err := c.Write([]byte{0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Bidirectional copy. Wait for both halves so clients that half-close the
	// upload side after a request do not make us drop the response side.
	done := make(chan copyResult, 2)
	go copyConn(done, "client->tunnel", tunnel, c)
	go copyConn(done, "tunnel->client", c, tunnel)
	first := <-done
	if cfg.Debug {
		log.Printf("socks5 %s copy done: %s n=%d err=%v", dest, first.Direction, first.N, first.Err)
	}
	second := <-done
	if cfg.Debug {
		log.Printf("socks5 %s copy done: %s n=%d err=%v", dest, second.Direction, second.N, second.Err)
	}
}

type copyResult struct {
	Direction string
	N         int64
	Err       error
}

func copyConn(done chan<- copyResult, direction string, dst net.Conn, src net.Conn) {
	n, err := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	done <- copyResult{Direction: direction, N: n, Err: err}
}

func negotiateSocksAuth(c net.Conn, cfg socksConfig) error {
	// Greeting: VER NMETHODS METHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	method := byte(0x00) // NO AUTH
	if cfg.authConfigured() {
		method = 0x02 // USER/PASS
	}
	if !socksMethodOffered(methods, method) {
		_, _ = c.Write([]byte{0x05, 0xff})
		return fmt.Errorf("no acceptable SOCKS5 auth method")
	}
	if _, err := c.Write([]byte{0x05, method}); err != nil {
		return err
	}
	if method != 0x02 {
		return nil
	}
	return authenticateSocksUserPass(c, cfg)
}

func socksMethodOffered(methods []byte, want byte) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

func authenticateSocksUserPass(c net.Conn, cfg socksConfig) error {
	// RFC 1929: VER(0x01) ULEN UNAME PLEN PASSWD
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		_, _ = c.Write([]byte{0x01, 0x01})
		return fmt.Errorf("unsupported SOCKS5 auth version %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, username); err != nil {
		return err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(c, passLen); err != nil {
		return err
	}
	password := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}

	userOK := constantTimeStringEqual(string(username), cfg.AuthUser)
	passOK := constantTimeStringEqual(string(password), cfg.AuthPass)
	if userOK != 1 || passOK != 1 {
		_, _ = c.Write([]byte{0x01, 0x01})
		return fmt.Errorf("SOCKS5 auth failed")
	}
	_, err := c.Write([]byte{0x01, 0x00})
	return err
}

func constantTimeStringEqual(got, want string) int {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) & subtle.ConstantTimeEq(int32(len(got)), int32(len(want)))
}

// parseSNIPool splits a comma-separated SNI list. Single value returns a
// 1-element slice (or nil). The legacy ServerName field receives the first
// entry; the pool contains all entries for client-side per-transport rotation.
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

// firstSNI returns the first entry of a comma-separated SNI list, or the
// trimmed input if no comma. Used as legacy ClientConfig.ServerName fallback.
func firstSNI(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ','); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
