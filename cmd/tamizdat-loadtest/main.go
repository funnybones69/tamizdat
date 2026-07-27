// Command tamizdat-loadtest runs a browser-like many-connection load test
// against a local Tamizdat server/client pair. It intentionally exercises many
// short SOCKS5 CONNECTs through the Tamizdat client instead of a single bulk
// transfer, then emits a JSON report with latency, TTFB, throughput, and expvar
// pool/limiter state.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/pkg/tamizdat"
	"golang.org/x/net/proxy"
)

type loadConfig struct {
	Concurrency              int
	Duration                 time.Duration
	OriginSize               int
	ThinkTimeMin             time.Duration
	ThinkTimeMax             time.Duration
	BytesPerTransportSoftCap int64
	PoolVariant              string
	MaxTransports            int
	RotationOverlap          int
	Out                      string
	EnableDebug              bool
	Verbose                  bool
	ServerListen             string
	SocksListen              string
	OriginListen             string
	DebugListen              string
	RequestTimeout           time.Duration
}

type report struct {
	Config                   reportConfig   `json:"config"`
	Summary                  summaryReport  `json:"summary"`
	TimeseriesThroughputMbps []float64      `json:"timeseries_throughput_mbps"`
	ClientExpvarSnapshot     map[string]any `json:"client_expvar_snapshot"`
}

type reportConfig struct {
	Concurrency              int     `json:"concurrency"`
	DurationSec              float64 `json:"duration_sec"`
	OriginSize               int     `json:"origin_size"`
	ThinkTimeMinMS           int64   `json:"think_time_min_ms"`
	ThinkTimeMaxMS           int64   `json:"think_time_max_ms"`
	BytesPerTransportSoftCap int64   `json:"bytes_per_transport_soft_cap"`
	PoolVariant              string  `json:"pool_variant"`
	MaxTransports            int     `json:"max_transports"`
	RotationOverlap          int     `json:"rotation_overlap"`
	EnableDebug              bool    `json:"enable_debug"`
	ServerListen             string  `json:"server_listen"`
	SocksListen              string  `json:"socks_listen"`
	OriginListen             string  `json:"origin_listen"`
	DebugListen              string  `json:"debug_listen,omitempty"`
}

type summaryReport struct {
	TotalRequests  int            `json:"total_requests"`
	SuccessCount   int            `json:"success_count"`
	SuccessRate    float64        `json:"success_rate"`
	Errors         map[string]int `json:"errors"`
	LatencyMS      statReport     `json:"latency_ms"`
	ThroughputMbps statReport     `json:"throughput_mbps"`
	TTFBMS         statReport     `json:"ttfb_ms"`
}

type statReport struct {
	P50    float64 `json:"p50"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
	Mean   float64 `json:"mean"`
	Stddev float64 `json:"stddev"`
}

type requestMetric struct {
	Start   time.Time
	End     time.Time
	Latency time.Duration
	TTFB    time.Duration
	Bytes   int64
	Outcome string
	Err     string
}

type keyMaterial struct {
	PrivateKey []byte
	PublicKey  []byte
	ShortID    [8]byte
	CertPEM    []byte
	KeyPEM     []byte
}

type localOrigin struct {
	server *http.Server
	ln     net.Listener
	addr   string
}

type socksServer struct {
	ln     net.Listener
	client *tamizdat.Client
	closed chan struct{}
	once   sync.Once
}

func main() {
	cfg := parseFlags()
	if !cfg.Verbose {
		log.SetOutput(io.Discard)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	report, err := runHarness(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tamizdat-loadtest: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tamizdat-loadtest: marshal report: %v\n", err)
		os.Exit(1)
	}
	out = append(out, '\n')
	if cfg.Out != "" {
		if err := os.WriteFile(cfg.Out, out, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tamizdat-loadtest: write %s: %v\n", cfg.Out, err)
			os.Exit(1)
		}
	}
	_, _ = os.Stdout.Write(out)
}

func defaultLoadConfig() loadConfig {
	return loadConfig{
		Concurrency:              200,
		Duration:                 10 * time.Minute,
		OriginSize:               50_000,
		ThinkTimeMin:             100 * time.Millisecond,
		ThinkTimeMax:             2 * time.Second,
		BytesPerTransportSoftCap: 0,
		PoolVariant:              "v2",
		MaxTransports:            0,
		RotationOverlap:          0,
		Out:                      "/tmp/loadtest-baseline.json",
		EnableDebug:              true,
		ServerListen:             "127.0.0.1:7780",
		SocksListen:              "127.0.0.1:1080",
		OriginListen:             "127.0.0.1:9001",
		DebugListen:              "127.0.0.1:6060",
		RequestTimeout:           30 * time.Second,
	}
}

func parseFlags() loadConfig {
	cfg := defaultLoadConfig()
	flag.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "number of concurrent browser-like workers")
	flag.DurationVar(&cfg.Duration, "duration", cfg.Duration, "load-test duration")
	flag.IntVar(&cfg.OriginSize, "origin-size", cfg.OriginSize, "bytes returned by /random?size=N")
	flag.DurationVar(&cfg.ThinkTimeMin, "think-time-min", cfg.ThinkTimeMin, "minimum per-worker think time")
	flag.DurationVar(&cfg.ThinkTimeMax, "think-time-max", cfg.ThinkTimeMax, "maximum per-worker think time")
	flag.Int64Var(&cfg.BytesPerTransportSoftCap, "bytes-per-transport-soft-cap", cfg.BytesPerTransportSoftCap, "client transport byte soft cap; 0 disables rotation")
	flag.StringVar(&cfg.PoolVariant, "pool-variant", cfg.PoolVariant, "transport pool variant: v1, v2, v3, or empty explicit sizing")
	flag.IntVar(&cfg.MaxTransports, "max-transports", cfg.MaxTransports, "override max simultaneous transports; 0 uses variant default")
	flag.IntVar(&cfg.RotationOverlap, "rotation-overlap", cfg.RotationOverlap, "extra transient bulk transports allowed while a capped transport drains")
	flag.StringVar(&cfg.Out, "out", cfg.Out, "path for JSON report; empty disables file write")
	flag.BoolVar(&cfg.EnableDebug, "enable-debug", cfg.EnableDebug, "enable localhost /debug/vars expvar endpoint")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "enable harness and tamizdat debug logs on stderr")

	// Operational overrides for avoiding port conflicts in CI or parallel runs.
	flag.StringVar(&cfg.ServerListen, "server-listen", cfg.ServerListen, "Tamizdat server listen address")
	flag.StringVar(&cfg.SocksListen, "socks-listen", cfg.SocksListen, "local SOCKS5 listen address")
	flag.StringVar(&cfg.OriginListen, "origin-listen", cfg.OriginListen, "dummy HTTPS origin listen address")
	flag.StringVar(&cfg.DebugListen, "debug-listen", cfg.DebugListen, "debug expvar listen address when -enable-debug=true")
	flag.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "per-request deadline")
	flag.Parse()
	return cfg
}

func runHarness(parent context.Context, cfg loadConfig) (*report, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	cleanupOnce := sync.Once{}
	cleanup := func() { cleanupOnce.Do(cancel) }
	defer cleanup()

	origin, err := startOriginServer(ctx, cfg.OriginListen, cfg.OriginSize)
	if err != nil {
		return nil, err
	}
	defer origin.close(context.Background())

	keys, err := generateKeyMaterial()
	if err != nil {
		return nil, err
	}

	serverAddr, server, err := startTamizdatServer(ctx, cfg, keys, origin.addr)
	if err != nil {
		return nil, err
	}
	serverCloseOnce := sync.Once{}
	closeServer := func() { serverCloseOnce.Do(func() { server.Close() }) }
	defer closeServer()

	client, err := newLoadClient(cfg, serverAddr, keys)
	if err != nil {
		return nil, err
	}
	clientClosed := false
	defer func() {
		if !clientClosed {
			_ = client.Close()
		}
	}()

	socks, err := startSOCKSServer(ctx, cfg.SocksListen, client)
	if err != nil {
		return nil, err
	}
	socksClosed := false
	defer func() {
		if !socksClosed {
			_ = socks.Close()
		}
	}()

	if cfg.Verbose {
		log.Printf("origin=%s server=%s socks=%s debug=%s", origin.addr, serverAddr, socks.addr(), cfg.DebugListen)
	}

	start := time.Now()
	metrics := driveLoad(ctx, cfg, socks.addr(), origin.addr)
	end := time.Now()

	// Let stream close accounting and pool gauges settle, then snapshot before
	// cleanup so operators can inspect the steady-state pool shape at test end.
	time.Sleep(200 * time.Millisecond)
	beforeCleanup := snapshotExpvars(cfg)
	report := buildReport(cfg, metrics, beforeCleanup, start, end)

	// Also record post-cleanup transport gauge state. The primary schema field
	// transports_alive_at_end remains the pre-cleanup snapshot; this extra field
	// makes leak checks unambiguous for automated callers.
	_ = socks.Close()
	socksClosed = true
	_ = client.Close()
	clientClosed = true
	closeServer()
	origin.close(context.Background())
	cleanup()
	time.Sleep(100 * time.Millisecond)
	afterCleanup := snapshotExpvars(cfg)
	report.ClientExpvarSnapshot["transports_alive_after_cleanup"] = transportAlive(afterCleanup)
	return report, nil
}

func (cfg loadConfig) validate() error {
	if cfg.Concurrency <= 0 {
		return fmt.Errorf("-concurrency must be > 0")
	}
	if cfg.Duration <= 0 {
		return fmt.Errorf("-duration must be > 0")
	}
	if cfg.OriginSize < 0 {
		return fmt.Errorf("-origin-size must be >= 0")
	}
	if cfg.ThinkTimeMin < 0 || cfg.ThinkTimeMax < 0 {
		return fmt.Errorf("think time must be >= 0")
	}
	if cfg.ThinkTimeMax < cfg.ThinkTimeMin {
		return fmt.Errorf("-think-time-max must be >= -think-time-min")
	}
	if cfg.BytesPerTransportSoftCap < 0 {
		return fmt.Errorf("-bytes-per-transport-soft-cap must be >= 0")
	}
	if cfg.MaxTransports < 0 {
		return fmt.Errorf("-max-transports must be >= 0")
	}
	if cfg.RotationOverlap < 0 {
		return fmt.Errorf("-rotation-overlap must be >= 0")
	}
	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("-request-timeout must be > 0")
	}
	switch strings.TrimSpace(cfg.PoolVariant) {
	case "", "v1", "v2", "v3", "v1-strict":
		return nil
	default:
		return fmt.Errorf("-pool-variant must be one of v1, v2, v3, v1-strict, or empty")
	}
}

func generateKeyMaterial() (keyMaterial, error) {
	priv, pub, err := tamizdat.GenerateKeyPair()
	if err != nil {
		return keyMaterial{}, fmt.Errorf("generate X25519 keypair: %w", err)
	}
	shortID, err := tamizdat.GenerateShortID()
	if err != nil {
		return keyMaterial{}, fmt.Errorf("generate short ID: %w", err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert("loadtest.local", []string{"loadtest.local", "127.0.0.1"})
	if err != nil {
		return keyMaterial{}, fmt.Errorf("generate server cert: %w", err)
	}
	return keyMaterial{PrivateKey: priv, PublicKey: pub, ShortID: shortID, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func startOriginServer(ctx context.Context, listen string, defaultSize int) (*localOrigin, error) {
	certPEM, keyPEM, err := generateSelfSignedCert("loadtest-origin.local", []string{"loadtest-origin.local", "127.0.0.1"})
	if err != nil {
		return nil, fmt.Errorf("origin cert: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("origin keypair: %w", err)
	}

	block := make([]byte, 1<<20)
	if _, err := crand.Read(block); err != nil {
		return nil, fmt.Errorf("origin random block: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/random", func(w http.ResponseWriter, r *http.Request) {
		size := defaultSize
		if raw := strings.TrimSpace(r.URL.Query().Get("size")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				http.Error(w, "bad size", http.StatusBadRequest)
				return
			}
			size = parsed
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		for remaining := size; remaining > 0; {
			n := remaining
			if n > len(block) {
				n = len(block)
			}
			if _, err := w.Write(block[:n]); err != nil {
				return
			}
			remaining -= n
		}
	})

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("origin listen %s: %w", listen, err)
	}
	origin := &localOrigin{
		server: &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0)},
		ln:     ln,
		addr:   ln.Addr().String(),
	}
	go func() {
		<-ctx.Done()
		origin.close(context.Background())
	}()
	go func() {
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := origin.server.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("origin server: %v", err)
		}
	}()
	return origin, nil
}

func (o *localOrigin) close(ctx context.Context) {
	if o == nil || o.server == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = o.server.Shutdown(shutdownCtx)
	_ = o.ln.Close()
}

func startTamizdatServer(ctx context.Context, cfg loadConfig, keys keyMaterial, allowedDestination string) (string, *tamizdat.Server, error) {
	server, err := tamizdat.NewServer(tamizdat.ServerConfig{
		ListenAddr:              cfg.ServerListen,
		PrivateKey:              keys.PrivateKey,
		MasterShortID:           keys.ShortID,
		CertPEM:                 keys.CertPEM,
		KeyPEM:                  keys.KeyPEM,
		MasqueradeDomain:        "loadtest.local",
		MasqueradeAddr:          allowedDestination,
		RecordFragmentation:     true,
		DisableDefaultSecurity:  true,
		Debug:                   cfg.EnableDebug,
		DebugListenAddr:         cfg.DebugListen,
		DisableOutboundRegistry: true,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			loadtestProxyHandler(ctx, conn, destination, allowedDestination)
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("create tamizdat server: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.ServerListen)
	if err != nil {
		server.Close()
		return "", nil, fmt.Errorf("tamizdat server listen %s: %w", cfg.ServerListen, err)
	}
	addr := ln.Addr().String()
	_ = ctx
	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("tamizdat server: %v", err)
		}
	}()
	return addr, server, nil
}

func loadtestProxyHandler(ctx context.Context, conn net.Conn, destination, allowedDestination string) {
	defer conn.Close()
	if destination != allowedDestination {
		return
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	target, err := d.DialContext(ctx, "tcp", destination)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		closeWrite(target)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		closeWrite(conn)
	}()
	wg.Wait()
}

func newLoadClient(cfg loadConfig, serverAddr string, keys keyMaterial) (*tamizdat.Client, error) {
	minTransports, maxTransports := poolSizing(cfg)
	client, err := tamizdat.NewClient(tamizdat.ClientConfig{
		ServerAddr:               serverAddr,
		PrimarySNI:               "loadtest.local",
		ServerName:               "loadtest.local",
		ServerNames:              []string{"loadtest.local"},
		PublicKey:                keys.PublicKey,
		MasterShortID:            keys.ShortID,
		Fingerprint:              "chrome",
		TCPFragmentation:         true,
		RecordFragmentation:      true,
		DisableDefaultSecurity:   true,
		PoolVariant:              "",
		MinTransports:            minTransports,
		MaxTransports:            maxTransports,
		RotationOverlapAllowance: cfg.RotationOverlap,
		BytesPerTransportSoftCap: cfg.BytesPerTransportSoftCap,
		CoverTrafficEnabled:      false,
		ConnectTimeout:           15 * time.Second,
		IdleTimeout:              5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("create tamizdat client: %w", err)
	}
	return client, nil
}

func poolSizing(cfg loadConfig) (int, int) {
	variant := strings.TrimSpace(cfg.PoolVariant)
	minTransports, maxTransports := 1, 2
	switch variant {
	case "v1", "v1-strict":
		minTransports, maxTransports = 1, 1
	case "v2", "":
		minTransports, maxTransports = 1, 2
	case "v3":
		minTransports, maxTransports = 2, 4
	}
	if cfg.MaxTransports > 0 {
		maxTransports = cfg.MaxTransports
		if minTransports > maxTransports {
			minTransports = maxTransports
		}
	}
	if minTransports < 1 {
		minTransports = 1
	}
	if maxTransports < minTransports {
		maxTransports = minTransports
	}
	return minTransports, maxTransports
}

func startSOCKSServer(ctx context.Context, listen string, client *tamizdat.Client) (*socksServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("socks listen %s: %w", listen, err)
	}
	s := &socksServer{ln: ln, client: client, closed: make(chan struct{})}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	go s.serve(ctx)
	return s, nil
}

func (s *socksServer) addr() string {
	if s == nil || s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *socksServer) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		err = s.ln.Close()
	})
	return err
}

func (s *socksServer) serve(ctx context.Context) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			case <-ctx.Done():
				return
			default:
				log.Printf("socks accept: %v", err)
				return
			}
		}
		go s.handle(ctx, conn)
	}
}

func (s *socksServer) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := socksNegotiateNoAuth(c); err != nil {
		return
	}
	destination, err := socksReadConnectRequest(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tunnel, err := s.client.DialContext(dialCtx, "tcp", destination)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer tunnel.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(tunnel, c)
		closeWrite(tunnel)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, tunnel)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
}

func socksNegotiateNoAuth(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("not socks5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0x00 {
			_, err := c.Write([]byte{0x05, 0x00})
			return err
		}
	}
	_, _ = c.Write([]byte{0x05, 0xff})
	return fmt.Errorf("no acceptable auth method")
}

func socksReadConnectRequest(c net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("bad socks version")
	}
	if hdr[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("only CONNECT supported")
	}
	var host string
	switch hdr[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("bad address type")
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func driveLoad(ctx context.Context, cfg loadConfig, socksAddr, originAddr string) []requestMetric {
	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	results := make(chan requestMetric, cfg.Concurrency*2)
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for workerID := 0; workerID < cfg.Concurrency; workerID++ {
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(id)*7919))
			dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: cfg.RequestTimeout})
			if err != nil {
				results <- requestMetric{Start: time.Now(), End: time.Now(), Outcome: "socks_refused", Err: err.Error()}
				return
			}
			for {
				select {
				case <-runCtx.Done():
					return
				default:
				}
				results <- issueRequest(runCtx, cfg, dialer, originAddr)
				if !sleepThinkTime(runCtx, rng, cfg.ThinkTimeMin, cfg.ThinkTimeMax) {
					return
				}
			}
		}(workerID)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	metrics := make([]requestMetric, 0, cfg.Concurrency)
	for metric := range results {
		metrics = append(metrics, metric)
	}
	return metrics
}

func issueRequest(ctx context.Context, cfg loadConfig, dialer proxy.Dialer, originAddr string) requestMetric {
	start := time.Now()
	metric := requestMetric{Start: start, Outcome: "error"}
	finish := func(outcome string, err error) requestMetric {
		metric.End = time.Now()
		metric.Latency = metric.End.Sub(start)
		metric.Outcome = outcome
		if err != nil {
			metric.Err = err.Error()
		}
		return metric
	}
	if err := ctx.Err(); err != nil {
		return finish("timeout", err)
	}

	conn, err := dialer.Dial("tcp", originAddr)
	if err != nil {
		return finish(classifyError(err), err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.RequestTimeout))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "loadtest-origin.local",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return finish(classifyError(err), err)
	}

	request := fmt.Sprintf("GET /random?size=%d HTTP/1.1\r\nHost: loadtest-origin.local\r\nUser-Agent: tamizdat-loadtest/1\r\nAccept: */*\r\nConnection: close\r\n\r\n", cfg.OriginSize)
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return finish(classifyError(err), err)
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	metric.TTFB = time.Since(start)
	if err != nil {
		return finish(classifyError(err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return finish("http_error", fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	n, err := io.Copy(io.Discard, resp.Body)
	metric.Bytes = n
	if err != nil {
		return finish(classifyError(err), err)
	}
	if n != int64(cfg.OriginSize) {
		return finish("short_body", fmt.Errorf("read %d bytes, want %d", n, cfg.OriginSize))
	}
	return finish("success", nil)
}

func sleepThinkTime(ctx context.Context, rng *mrand.Rand, min, max time.Duration) bool {
	delay := min
	if max > min {
		delta := int64(max - min)
		delay += time.Duration(rng.Int63n(delta + 1))
	}
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func classifyError(err error) string {
	if err == nil {
		return "success"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "handshake rate limited"):
		return "handshake_rate_limited"
	case strings.Contains(s, "socks") || strings.Contains(s, "connection refused") || strings.Contains(s, "proxy rejected"):
		return "socks_refused"
	case strings.Contains(s, "reset") || strings.Contains(s, "broken pipe") || strings.Contains(s, "eof"):
		return "reset"
	case strings.Contains(s, "deadline") || strings.Contains(s, "timeout") || strings.Contains(s, "context deadline"):
		return "timeout"
	default:
		return "error"
	}
}

func buildReport(cfg loadConfig, metrics []requestMetric, expvars map[string]any, start, end time.Time) *report {
	summary := summarizeMetrics(metrics, start, end)
	cfgForReport := reportConfig{
		Concurrency:              cfg.Concurrency,
		DurationSec:              cfg.Duration.Seconds(),
		OriginSize:               cfg.OriginSize,
		ThinkTimeMinMS:           cfg.ThinkTimeMin.Milliseconds(),
		ThinkTimeMaxMS:           cfg.ThinkTimeMax.Milliseconds(),
		BytesPerTransportSoftCap: cfg.BytesPerTransportSoftCap,
		PoolVariant:              cfg.PoolVariant,
		MaxTransports:            cfg.MaxTransports,
		RotationOverlap:          cfg.RotationOverlap,
		EnableDebug:              cfg.EnableDebug,
		ServerListen:             cfg.ServerListen,
		SocksListen:              cfg.SocksListen,
		OriginListen:             cfg.OriginListen,
		DebugListen:              cfg.DebugListen,
	}
	snapshot := compactExpvarSnapshot(expvars, summary.Errors["handshake_rate_limited"])
	return &report{
		Config:                   cfgForReport,
		Summary:                  summary,
		TimeseriesThroughputMbps: buildThroughputSeries(metrics, start, end),
		ClientExpvarSnapshot:     snapshot,
	}
}

func summarizeMetrics(metrics []requestMetric, start, end time.Time) summaryReport {
	errorsByType := map[string]int{
		"timeout":                0,
		"reset":                  0,
		"handshake_rate_limited": 0,
		"socks_refused":          0,
	}
	latencies := make([]float64, 0, len(metrics))
	ttfbs := make([]float64, 0, len(metrics))
	success := 0
	var totalBytes int64
	for _, metric := range metrics {
		if metric.Outcome == "success" {
			success++
			totalBytes += metric.Bytes
			latencies = append(latencies, float64(metric.Latency)/float64(time.Millisecond))
			ttfbs = append(ttfbs, float64(metric.TTFB)/float64(time.Millisecond))
			continue
		}
		outcome := metric.Outcome
		if outcome == "" {
			outcome = "error"
		}
		errorsByType[outcome]++
	}

	throughputSeries := buildThroughputSeries(metrics, start, end)
	throughput := summarizeFloats(throughputSeries)
	if elapsed := end.Sub(start).Seconds(); elapsed > 0 {
		throughput.Mean = (float64(totalBytes) * 8) / elapsed / 1_000_000
	}

	successRate := 0.0
	if len(metrics) > 0 {
		successRate = float64(success) / float64(len(metrics))
	}
	return summaryReport{
		TotalRequests:  len(metrics),
		SuccessCount:   success,
		SuccessRate:    successRate,
		Errors:         errorsByType,
		LatencyMS:      summarizeFloats(latencies),
		ThroughputMbps: throughput,
		TTFBMS:         summarizeFloats(ttfbs),
	}
}

func buildThroughputSeries(metrics []requestMetric, start, end time.Time) []float64 {
	elapsed := end.Sub(start)
	buckets := int(math.Ceil(elapsed.Seconds()))
	if buckets < 1 {
		buckets = 1
	}
	bytesByBucket := make([]int64, buckets)
	for _, metric := range metrics {
		if metric.Outcome != "success" {
			continue
		}
		idx := int(metric.End.Sub(start).Seconds())
		if idx < 0 {
			idx = 0
		}
		if idx >= buckets {
			idx = buckets - 1
		}
		bytesByBucket[idx] += metric.Bytes
	}
	out := make([]float64, buckets)
	for i, bytes := range bytesByBucket {
		out[i] = float64(bytes) * 8 / 1_000_000
	}
	return out
}

func summarizeFloats(values []float64) statReport {
	if len(values) == 0 {
		return statReport{}
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, v := range values {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(values))
	return statReport{
		P50:    percentile(values, 50),
		P95:    percentile(values, 95),
		P99:    percentile(values, 99),
		Mean:   mean,
		Stddev: math.Sqrt(variance),
	}
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	idx := int(float64(len(copyValues)-1) * p / 100)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(copyValues) {
		idx = len(copyValues) - 1
	}
	return copyValues[idx]
}

func snapshotExpvars(cfg loadConfig) map[string]any {
	if cfg.EnableDebug && cfg.DebugListen != "" && !strings.HasSuffix(cfg.DebugListen, ":0") {
		if snap, err := fetchExpvarsOverHTTP(cfg.DebugListen); err == nil {
			return snap
		}
	}
	snap := make(map[string]any)
	expvar.Do(func(kv expvar.KeyValue) {
		if strings.HasPrefix(kv.Key, "tamizdat") {
			snap[kv.Key] = parseExpvarValue(kv.Value.String())
		}
	})
	return snap
}

func fetchExpvarsOverHTTP(addr string) (map[string]any, error) {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/debug/vars")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("debug vars HTTP %d", resp.StatusCode)
	}
	var snap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, err
	}
	return snap, nil
}

func parseExpvarValue(raw string) any {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		return v
	}
	return raw
}

// compactExpvarSnapshot trims the raw expvar dump to the keys consumers of
// the loadtest JSON output care about.
//
// Schema note (2026-05-09): the "realtimeAlive" key was removed by the
// realtime-classifier cleanup (commit 2863b8c). The corresponding source
// metric "tamizdat.pool.transports.realtime.alive" is no longer published by
// the library, and "transports_alive_at_end" is now equal to "bulkAlive"
// (single-pool bulk-only). External tooling that parsed the previous schema
// will see the field as absent rather than nil; guard with a presence check
// or default-to-0 on the consumer side.
func compactExpvarSnapshot(raw map[string]any, handshakeRateLimited int) map[string]any {
	bulkAlive := numberFromAny(raw["tamizdat.pool.transports.bulk.alive"])
	snapshot := map[string]any{
		"transports_total_ever":   numberFromAny(raw["tamizdat.handshake.duration_nanos_count"]),
		"transports_alive_at_end": bulkAlive,
		"bulkAlive":               bulkAlive,
		"ErrHandshakeRateLimited": handshakeRateLimited,
		"connectAuthOK":           numberFromAny(raw["tamizdat.connect.auth_ok"]),
		"connectMasquerade":       numberFromAny(raw["tamizdat.connect.masquerade_dispatched"]),
		"masqRateLimited":         numberFromAny(raw["tamizdat.masquerade.rate_limited"]),
		"raw":                     raw,
	}
	return snapshot
}

func transportAlive(raw map[string]any) int64 {
	return numberFromAny(raw["tamizdat.pool.transports.bulk.alive"])
}

func numberFromAny(v any) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}

func generateSelfSignedCert(commonName string, hosts []string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := crand.Int(crand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"tamizdat loadtest"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if host != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func closeWrite(conn net.Conn) {
	if conn == nil {
		return
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func shortIDHex(id [8]byte) string {
	return hex.EncodeToString(id[:])
}
