//go:build linux

package wgturn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	pionudp "github.com/pion/transport/v4/udp"
	"golang.zx2c4.com/wireguard/device"
)

const wgturnUDPBufferSize = 4 * 1024 * 1024

// Config holds the configuration for a wgturn Server.
type Config struct {
	ListenAddr string // e.g. "0.0.0.0:56000"
	WGPort     int    // internal WireGuard listen port, e.g. 56001
	Password   string // optional shared fallback password for client auth
	ConfigDir  string // directory for wg-keys.dat, devices.json
	WGSubnet   string // e.g. "10.66.66.0/24"
	WGServerIP string // e.g. "10.66.66.1"

	// Authenticate is the panel/userdb-aware auth hook. The legacy shared
	// Password remains supported; when Password does not match, Authenticate
	// may accept e.g. a per-user Tamizdat shortid and return identity metadata.
	Authenticate   Authenticator
	OnIdentityDone func(ClientIdentity)

	// Phase 2G — when both are set, wgturn uses a userspace netstack
	// instead of a kernel TUN + iptables MASQUERADE. Flows are dialed via
	// Outbounds.Resolve(tag). FlowRouter can choose the tag per flow; otherwise
	// OutboundTag is used as a fixed fallback.
	Outbounds   OutboundResolver
	OutboundTag string
	FlowRouter  FlowRouter
	Accounting  Accounting
}

// ClientIdentity is the authenticated Tamizdat user behind a wgturn device.
// Empty fields mean legacy shared-password auth with no panel user binding.
type ClientIdentity struct {
	ShortIDHex string
	UserID     string
	UserName   string
	SessionID  string
}

// Authenticator validates one GETCONF request. Return reason="" on success;
// non-empty reason is sent as DENIED:<reason>.
type Authenticator func(ctx context.Context, deviceID, password string) (ClientIdentity, string)

// Flow describes one TCP/UDP flow decapsulated from WireGuard.
type Flow struct {
	Network  string // "tcp" or "udp"
	SourceIP string
	DestHost string
	DestPort int
	Identity ClientIdentity
}

// FlowRouter chooses an outbound tag for a decapsulated wgturn flow.
// Return "" to use the registry default/fixed fallback, or "block" to drop.
type FlowRouter func(ctx context.Context, flow Flow) string

// Accounting is the subset of the Tamizdat user accounting sink that wgturn
// needs. Keeping the interface local avoids importing the top-level server or
// userdb packages from internal/wgturn.
type Accounting interface {
	Add(userID, sessionID string, up, down int64)
	AddOutbound(tag string, up, down int64)
}

// clientDevice represents a client device with a WireGuard keypair.
type clientDevice struct {
	deviceID string
	ip       string
	privKey  string
	pubKey   string
}

// clientDeviceJSON is the JSON-serialisable form of clientDevice.
type clientDeviceJSON struct {
	DeviceID string `json:"device_id"`
	IP       string `json:"ip"`
	PrivKey  string `json:"priv_key"`
	PubKey   string `json:"pub_key"`
}

// Server is a DTLS+WireGuard inbound listener.
type Server struct {
	cfg Config

	keys     *wgKeys
	wgDev    *device.Device
	wgIface  string // empty when running in netstack/bridge mode
	listener net.Listener

	// Phase 2G — alive only in bridge mode.
	bridge *OutboundBridge

	mu             sync.Mutex
	devices        map[string]*clientDevice
	identitiesByIP map[string]ClientIdentity

	activeConns int32
	totalConns  int64
}

// NewServer creates a new wgturn Server. It loads or generates WireGuard keys
// and restores any previously-saved device registrations. The server is not
// started until Start() is called.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "/etc/tamizdat/wgturn"
	}
	if cfg.WGSubnet == "" {
		cfg.WGSubnet = "10.66.66.0/24"
	}
	if cfg.WGServerIP == "" {
		cfg.WGServerIP = "10.66.66.1"
	}
	if cfg.WGPort == 0 {
		cfg.WGPort = 56001
	}

	keys, err := loadOrGenerateKeys(cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("wgturn keys: %w", err)
	}

	s := &Server{
		cfg:            cfg,
		keys:           keys,
		devices:        make(map[string]*clientDevice),
		identitiesByIP: make(map[string]ClientIdentity),
	}
	s.loadDevices()

	return s, nil
}

func listenDTLSWithUDPBuffers(addr *net.UDPAddr, cfg *dtls.Config) (net.Listener, error) {
	acceptHandshake := func(packet []byte) bool {
		pkts, err := recordlayer.UnpackDatagram(packet)
		if err != nil || len(pkts) == 0 {
			return false
		}
		h := &recordlayer.Header{}
		if err := h.Unmarshal(pkts[0]); err != nil {
			return false
		}
		return h.ContentType == protocol.ContentTypeHandshake
	}

	udpListener, err := (&pionudp.ListenConfig{
		AcceptFilter:    acceptHandshake,
		ReadBufferSize:  wgturnUDPBufferSize,
		WriteBufferSize: wgturnUDPBufferSize,
	}).Listen("udp", addr)
	if err != nil {
		return nil, err
	}
	listener, err := dtls.NewListener(dtlsnet.PacketListenerFromListener(udpListener), cfg)
	if err != nil {
		_ = udpListener.Close()
		return nil, err
	}
	return listener, nil
}

// Start brings up the WireGuard device, configures NAT (legacy) OR an
// outbound bridge (Phase 2G), and begins accepting DTLS connections.
// It blocks until ctx is cancelled or the listener is closed.
func (s *Server) Start(ctx context.Context) error {
	bridgeMode := s.cfg.Outbounds != nil

	var (
		wgDev     *device.Device
		ifaceName string
		err       error
	)

	if bridgeMode {
		// Phase 2G — netstack mode. No kernel TUN, no iptables.
		var tnet *userTun
		wgDev, tnet, err = createNetstackTUN(s.keys, s.cfg.WGPort, s.cfg.WGServerIP)
		if err != nil {
			return fmt.Errorf("wgturn netstack WireGuard: %w", err)
		}
		s.wgDev = wgDev
		s.wgIface = "" // no kernel iface in netstack mode

		// Outbound bridge — TCP/UDP forwarders attach to the netstack
		// and ferry every accepted flow to the resolver.
		s.bridge = NewOutboundBridge(tnet, s.cfg.Outbounds, s.cfg.OutboundTag, s, s.cfg.FlowRouter, s.cfg.Accounting)
		log.Printf("[wgturn] outbound bridge mode active, tag=%q", s.cfg.OutboundTag)
	} else {
		// Legacy path — kernel TUN + iptables MASQUERADE.
		wgDev, ifaceName, err = createTUN(s.keys, s.cfg.WGPort)
		if err != nil {
			return fmt.Errorf("wgturn WireGuard: %w", err)
		}
		s.wgDev = wgDev
		s.wgIface = ifaceName

		serverCIDR := s.cfg.WGServerIP + "/24"
		if err := configureInterface(ifaceName, serverCIDR); err != nil {
			wgDev.Close()
			return fmt.Errorf("wgturn interface: %w", err)
		}
		if err := setupNAT(ifaceName, s.cfg.WGSubnet); err != nil {
			wgDev.Close()
			return fmt.Errorf("wgturn NAT: %w", err)
		}
	}

	// Re-add persisted peers.
	s.mu.Lock()
	for _, dev := range s.devices {
		if err := addPeerToWG(wgDev, dev.pubKey, dev.ip); err != nil {
			log.Printf("[wgturn] restore peer %s: %v", dev.deviceID, err)
		}
	}
	s.mu.Unlock()

	// Start the UAPI socket.
	startUAPI(wgDev, ifaceName)

	// Set up the DTLS listener.
	addr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("wgturn resolve listen addr: %w", err)
	}

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("wgturn self-sign cert: %w", err)
	}

	dtlsCfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := listenDTLSWithUDPBuffers(addr, dtlsCfg)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("wgturn DTLS listen: %w", err)
	}
	s.listener = listener

	// Close listener on context cancellation.
	context.AfterFunc(ctx, func() { listener.Close() })

	log.Printf("[wgturn] DTLS listening on %s, WG on 127.0.0.1:%d, udp_buffer=%d", s.cfg.ListenAddr, s.cfg.WGPort, wgturnUDPBufferSize)

	// Accept loop.
	var wg sync.WaitGroup
	for {
		dtlsConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.handleConn(ctx, c)
		}(dtlsConn)
	}
}

// Shutdown tears down the WireGuard device and closes the DTLS listener.
func (s *Server) Shutdown() {
	if s.listener != nil {
		s.listener.Close()
	}
	if s.bridge != nil {
		s.bridge.Close()
	}
	if s.wgDev != nil {
		s.wgDev.Close()
		// Only delete the kernel iface if we created one (legacy mode).
		if s.wgIface != "" {
			runCmdSilent("ip", "link", "del", s.wgIface)
		}
	}
}

func (s *Server) setIdentityForIP(ip string, identity ClientIdentity) {
	if strings.TrimSpace(ip) == "" {
		return
	}
	s.mu.Lock()
	if s.identitiesByIP == nil {
		s.identitiesByIP = make(map[string]ClientIdentity)
	}
	s.identitiesByIP[ip] = identity
	s.mu.Unlock()
}

func (s *Server) IdentityForIP(ip string) (ClientIdentity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.identitiesByIP[ip]
	return id, ok
}

// getNextIP returns the next available IP in the WireGuard subnet.
// Must be called with s.mu held.
func (s *Server) getNextIP() string {
	used := make(map[string]bool)
	for _, dev := range s.devices {
		used[dev.ip] = true
	}
	// Parse the subnet base from WGServerIP (e.g. "10.66.66").
	parts := splitIPPrefix(s.cfg.WGServerIP)
	for i := 2; i <= 250; i++ {
		ip := fmt.Sprintf("%s.%d", parts, i)
		if !used[ip] {
			return ip
		}
	}
	return ""
}

// splitIPPrefix returns the first three octets of an IPv4 address.
func splitIPPrefix(ip string) string {
	// "10.66.66.1" -> "10.66.66"
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[:i]
		}
	}
	return ip
}

// --- device persistence ---

func (s *Server) devicesFile() string {
	return filepath.Join(s.cfg.ConfigDir, "devices.json")
}

func (s *Server) loadDevices() {
	data, err := os.ReadFile(s.devicesFile())
	if err != nil {
		return
	}
	var devs []clientDeviceJSON
	if err := json.Unmarshal(data, &devs); err != nil {
		log.Printf("[wgturn] load devices: %v", err)
		return
	}
	for _, d := range devs {
		s.devices[d.DeviceID] = &clientDevice{
			deviceID: d.DeviceID,
			ip:       d.IP,
			privKey:  d.PrivKey,
			pubKey:   d.PubKey,
		}
	}
	log.Printf("[wgturn] restored %d device(s)", len(devs))
}

// saveDevices persists the device map to disk. Must be called with s.mu held.
func (s *Server) saveDevices() {
	devs := make([]clientDeviceJSON, 0, len(s.devices))
	for _, d := range s.devices {
		devs = append(devs, clientDeviceJSON{
			DeviceID: d.deviceID,
			IP:       d.ip,
			PrivKey:  d.privKey,
			PubKey:   d.pubKey,
		})
	}
	data, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		log.Printf("[wgturn] marshal devices: %v", err)
		return
	}
	if err := os.WriteFile(s.devicesFile(), data, 0600); err != nil {
		log.Printf("[wgturn] write devices: %v", err)
	}
}
