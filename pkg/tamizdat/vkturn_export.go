package tamizdat

import (
	"context"
	"net"
	"time"

	"github.com/funnybones69/tamizdat/internal/transport/vkturn"
)

// VKTurnClientConfig configures the VK-call TURN/DTLS fallback transport.
// It is intentionally exposed from the public package because iOS gomobile
// code cannot import internal/transport/vkturn directly.
type VKTurnClientConfig struct {
	ServerAddr      string
	ShortID         [8]byte
	VKHashes        []string
	VKAppID         string
	VKAppSecret     string
	UserAgent       string
	DeviceID        string
	SNI             string
	Workers         int
	UseUDP          bool
	TURNHost        string
	TURNPort        string
	Direct          bool
	MaxFramePayload int
	ConnectTimeout  time.Duration
	SessionTimeout  time.Duration
	Dialer          DialFunc

	// Pre-shared TURN credentials bypass the VK API captcha flow.
	// If TURNUser and TURNPass are set, VKHashes is not required.
	TURNUser string
	TURNPass string
	TURNURLs []string

	// CredCachePath persists acquired VK TURN credentials to disk (0600) so
	// they survive restarts and bootstrap the relay after a network whitelist
	// blocks everything except VK, without re-solving a captcha. Empty disables
	// persistence (in-memory cache only).
	CredCachePath string

	// CaptchaDir routes VK captchas to a filesystem human-in-the-loop solver
	// (break-glass): challenge.json is written here and a result file with the
	// success_token is awaited, produced by a real browser on the LAN. Empty
	// keeps the automated solver.
	CaptchaDir string
}

type VKTurnClient struct{ inner *vkturn.Client }

func NewVKTurnClient(config VKTurnClientConfig) (*VKTurnClient, error) {
	cc := vkturn.ClientConfig{
		ServerAddr:      config.ServerAddr,
		ShortID:         config.ShortID,
		VKHashes:        config.VKHashes,
		VKAppID:         config.VKAppID,
		VKAppSecret:     config.VKAppSecret,
		UserAgent:       config.UserAgent,
		DeviceID:        config.DeviceID,
		SNI:             config.SNI,
		Workers:         config.Workers,
		UseUDP:          config.UseUDP,
		TURNHost:        config.TURNHost,
		TURNPort:        config.TURNPort,
		Direct:          config.Direct,
		MaxFramePayload: config.MaxFramePayload,
		ConnectTimeout:  config.ConnectTimeout,
		SessionTimeout:  config.SessionTimeout,
		CredCachePath:   config.CredCachePath,
		CaptchaDir:      config.CaptchaDir,
	}
	if config.Dialer != nil {
		cc.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
			return config.Dialer(ctx, network, address)
		}
	}
	// Pre-shared credentials bypass the VK captcha flow entirely.
	if config.TURNUser != "" && config.TURNPass != "" {
		cc.Credentials = &vkturn.Credentials{
			User:     config.TURNUser,
			Pass:     config.TURNPass,
			TurnURLs: config.TURNURLs,
		}
	}
	client, err := vkturn.NewClient(cc)
	if err != nil {
		return nil, err
	}
	return &VKTurnClient{inner: client}, nil
}

func (c *VKTurnClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.inner.DialContext(ctx, network, address)
}

func (c *VKTurnClient) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	return c.inner.DialUDP(ctx, address)
}

func (c *VKTurnClient) Close() error { return c.inner.Close() }

func ParseVKTurnHashes(raw string) []string { return vkturn.ParseHashes(raw) }
