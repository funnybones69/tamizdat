package fragpoc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fragpocMetricsInterval is how often the client logs a [FRAGPOC-METRICS] line
// describing op-token and DOWN-scheduler occupancy. This is a PoC diagnostic
// to confirm where resources accumulate under load; widen it once anti-stick
// reapers are in place.
const fragpocMetricsInterval = 10 * time.Second

// defaultDownPollTimeout bounds a single DOWN long-poll. The previous 30s
// default (OperationTimeout) meant a hung poll pinned its short-TCP connection
// and token for half a minute, starving every other operation; the server
// long-poll is sub-second to a couple of seconds, so 5s is a safe backstop.
const defaultDownPollTimeout = 5 * time.Second

// fragPoCClientPortCooldown is how long the dial rotator skips a pooled
// server port after a dial to it fails — the server has most likely scaled
// that listener down. The base port is never cooled.
const fragPoCClientPortCooldown = 30 * time.Second

// dnsReserve is the size of the priority op-token pool reserved for DNS flows
// (UDP :53). DNS ops draw from this pool instead of the shared data pool, so
// a DNS query never waits behind a saturated bulk transfer — the operator's
// "DNS gets queue priority" knob. Additive: it does not shrink the data pool.
const dnsReserve = 8

type ClientConfig struct {
	ServerAddr string
	ShortID    [ShortIDLen]byte
	Secure     bool
	MaxPayload int
	Workers    int
	// DownWindow is the per-logical-stream number of concurrent DOWN polls.
	// 0 keeps the legacy conservative window of 1. Values above MaxDownWindow
	// or the DOWN worker budget are clamped.
	DownWindow       int
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	DownPollTimeout  time.Duration
	// DynamicPortPool is an optional set of ADDITIONAL server ports the client
	// spreads its per-op dials across (the server opens these dynamically under
	// load). Empty = single-port behaviour. The base port from ServerAddr is
	// always used and is the fallback when a pooled port is unreachable.
	DynamicPortPool []int
	Dialer          DialFunc
}

type Client struct {
	config             ClientConfig
	maxPayload         int
	workers            int
	downWorkers        int
	downWindow         int
	opTokens           chan struct{}
	downTokens         chan struct{}
	downPollTimeout    time.Duration
	dnsTokens          chan struct{}
	scheduler          *downScheduler
	serverHost         string
	serverPort         string
	basePortNum        int
	dialPorts          []int // rotation set: [basePort] + pooled ports, de-duplicated
	portMu             sync.Mutex
	portRR             int // round-robin cursor
	portCooldown       map[int]time.Time
	resolveMu          sync.Mutex
	resolvedServerAddr string
	closeOnce          sync.Once
	stopMetrics        chan struct{}
	openConns          atomic.Int64
	openConnsPeak      atomic.Int64
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, errors.New("fragpoc: ServerAddr is required")
	}
	host, port, err := net.SplitHostPort(config.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("fragpoc: invalid ServerAddr: %w", err)
	}
	workers := workerCount(config.Workers)
	downWorkers := downWorkerCount(workers)
	client := &Client{
		config:          config,
		maxPayload:      maxPayload(config.MaxPayload),
		workers:         workers,
		downWorkers:     downWorkers,
		downWindow:      downWindowCount(workers, config.DownWindow),
		opTokens:        make(chan struct{}, workers),
		downTokens:      make(chan struct{}, downWorkers),
		downPollTimeout: durationDefault(config.DownPollTimeout, defaultDownPollTimeout),
		dnsTokens:       make(chan struct{}, dnsReserve),
		serverHost:      host,
		serverPort:      port,
		portCooldown:    make(map[int]time.Time),
		stopMetrics:     make(chan struct{}),
	}
	if len(config.DynamicPortPool) > 0 {
		basePort, err := strconv.Atoi(port)
		if err == nil && basePort >= 1 && basePort <= 65535 {
			client.basePortNum = basePort
			client.dialPorts = []int{basePort}
			seen := map[int]struct{}{basePort: {}}
			for _, p := range config.DynamicPortPool {
				if p < 1 || p > 65535 || p == basePort {
					continue
				}
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				client.dialPorts = append(client.dialPorts, p)
			}
		}
	}
	client.scheduler = newDownScheduler(client)
	go client.metricsLoop()
	return client, nil
}

// metricsLoop periodically logs op-token and DOWN-scheduler occupancy so a
// baseline run can show which client-side resource accumulates under load.
func (c *Client) metricsLoop() {
	t := time.NewTicker(fragpocMetricsInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stopMetrics:
			return
		case <-t.C:
			opTokens := 0
			if c.opTokens != nil {
				opTokens = len(c.opTokens)
			}
			downTokens := 0
			if c.downTokens != nil {
				downTokens = len(c.downTokens)
			}
			activeConns, queuedConns, inFlight := 0, 0, 0
			if c.scheduler != nil {
				activeConns, queuedConns, inFlight = c.scheduler.stats()
			}
			openConns := c.openConns.Load()
			openPeak := c.openConnsPeak.Swap(openConns)
			log.Printf("[FRAGPOC-METRICS] op_tokens=%d/%d down_tokens=%d/%d sched_conns=%d sched_queued=%d sched_inflight=%d down_workers=%d down_window=%d open_conns=%d open_conns_peak=%d",
				opTokens, cap(c.opTokens), downTokens, cap(c.downTokens), activeConns, queuedConns, inFlight, c.downWorkers, c.downWindow, openConns, openPeak)
		}
	}
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedNetwork, network)
	}
	if address == "" {
		return nil, errors.New("fragpoc: empty destination")
	}
	isDNS := isDNSDestination(address)
	opened, err := c.open(dnsContext(ctx, isDNS), address)
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		client:     c,
		sid:        opened.sid,
		secureKey:  opened.secureKey,
		isDNS:      isDNS,
		localAddr:  streamAddr{network: "tcp", address: "fragpoc-client"},
		remoteAddr: streamAddr{network: "tcp", address: address},
		downCh:     make(chan downResult, c.downWindow*2),
		errCh:      make(chan error, 1),
		done:       make(chan struct{}),
		pending:    make(map[uint32][]byte),
	}
	return conn, nil
}

func (c *Client) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	if address == "" {
		return nil, errors.New("fragpoc: empty UDP destination")
	}
	conn, err := c.DialContext(ctx, "tcp", UDPDestinationPrefix+address)
	if err != nil {
		return nil, err
	}
	return newUDPFramedPacketConn(conn, streamAddr{network: "udp", address: address}), nil
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.stopMetrics)
		if c.scheduler != nil {
			c.scheduler.close()
		}
	})
	return nil
}

type openResult struct {
	sid       [SIDLen]byte
	secureKey [32]byte
}

func (c *Client) open(ctx context.Context, destination string) (openResult, error) {
	if c.config.Secure {
		return c.openSecure(ctx, destination)
	}
	req := make([]byte, 1+ShortIDLen+len(destination)+1)
	req[0] = OpOpen
	copy(req[1:1+ShortIDLen], c.config.ShortID[:])
	copy(req[1+ShortIDLen:], destination)
	resp, err := c.exchangeFixed(ctx, req, 1+SIDLen)
	if err != nil {
		return openResult{}, err
	}
	if resp[0] != AckOK {
		return openResult{}, ErrAuthFailed
	}
	var sid [SIDLen]byte
	copy(sid[:], resp[1:])
	return openResult{sid: sid}, nil
}

func (c *Client) openSecure(ctx context.Context, destination string) (openResult, error) {
	staticKey := deriveSecureStaticKey(c.config.ShortID)
	reqPlain := make([]byte, len(destination)+1)
	copy(reqPlain, destination)
	nonce, err := newSecureNonce()
	if err != nil {
		return openResult{}, err
	}
	req := make([]byte, 1+ShortIDLen+1)
	req[0] = secureWireOp(OpOpenSecure)
	copy(req[1:1+ShortIDLen], c.config.ShortID[:])
	req[1+ShortIDLen] = secureOpenMarker
	resp, err := c.exchangeSecure(ctx, req, staticKey, secureRequestAD(OpOpenSecure, c.config.ShortID[:]), secureResponseAD(OpOpenSecure, c.config.ShortID[:]), reqPlain, 1+SIDLen, nonce[:])
	if err != nil {
		return openResult{}, err
	}
	if resp[0] != AckOK {
		return openResult{}, ErrAuthFailed
	}
	var sid [SIDLen]byte
	copy(sid[:], resp[1:])
	return openResult{sid: sid, secureKey: deriveSecureSessionKey(staticKey, sid, nonce[:])}, nil
}

func (c *Client) sendUp(ctx context.Context, sid [SIDLen]byte, secureKey [32]byte, p []byte) error {
	if len(p) > MaxUpPayload {
		return fmt.Errorf("fragpoc: UP chunk too large: %d > %d", len(p), MaxUpPayload)
	}
	if c.config.Secure {
		reqPlain := make([]byte, 2+len(p))
		binary.BigEndian.PutUint16(reqPlain[:2], uint16(len(p)))
		copy(reqPlain[2:], p)
		req := make([]byte, 1+SIDLen)
		req[0] = secureWireOp(OpUpSecure)
		copy(req[1:], sid[:])
		resp, err := c.exchangeSecure(ctx, req, secureKey, secureRequestAD(OpUpSecure, sid[:]), secureResponseAD(OpUpSecure, sid[:]), reqPlain, 1, nil)
		if err != nil {
			return err
		}
		if resp[0] != AckOK {
			return ErrProtocol
		}
		return nil
	}
	req := make([]byte, 1+SIDLen+2+len(p))
	req[0] = OpUp
	copy(req[1:1+SIDLen], sid[:])
	binary.BigEndian.PutUint16(req[1+SIDLen:1+SIDLen+2], uint16(len(p)))
	copy(req[1+SIDLen+2:], p)
	resp, err := c.exchangeFixed(ctx, req, 1)
	if err != nil {
		return err
	}
	if resp[0] != AckOK {
		return ErrProtocol
	}
	return nil
}

type downResult struct {
	seq uint32
	buf []byte
	eof bool
}

func (c *Client) down(ctx context.Context, sid [SIDLen]byte, secureKey [32]byte, ack uint32) (downResult, error) {
	if err := c.acquireDownToken(ctx); err != nil {
		return downResult{}, err
	}
	defer c.releaseDownToken()

	padLen := downRequestPaddingLen()
	var req []byte
	if c.config.Secure {
		req = make([]byte, 1+SIDLen)
		req[0] = secureWireOp(OpDownSecure)
		copy(req[1:], sid[:])
	} else {
		req = make([]byte, 1+SIDLen+4+2+padLen)
		req[0] = OpDown
		copy(req[1:1+SIDLen], sid[:])
		binary.BigEndian.PutUint32(req[1+SIDLen:1+SIDLen+4], ack)
		binary.BigEndian.PutUint16(req[1+SIDLen+4:1+SIDLen+6], uint16(padLen))
		fillDownRequestPadding(req[1+SIDLen+6:], sid)
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return downResult{}, err
	}
	defer conn.Close()
	if c.config.Secure {
		reqPlain := make([]byte, 4+2+padLen)
		binary.BigEndian.PutUint32(reqPlain[:4], ack)
		binary.BigEndian.PutUint16(reqPlain[4:6], uint16(padLen))
		fillDownRequestPadding(reqPlain[6:], sid)

		var framed bytes.Buffer
		framed.Grow(len(req) + secureNonceLen + 2 + len(reqPlain) + secureOverhead)
		_, _ = framed.Write(req)
		if _, err := writeSecureBody(&framed, secureKey, secureRequestAD(OpDownSecure, sid[:]), reqPlain); err != nil {
			return downResult{}, err
		}
		if _, err := conn.Write(framed.Bytes()); err != nil {
			return downResult{}, err
		}
	} else if _, err := conn.Write(req); err != nil {
		return downResult{}, err
	}
	applyDeadlineFromContext(conn, ctx)
	var plain []byte
	if c.config.Secure {
		body, _, err := readSecureBody(conn, secureKey, secureResponseAD(OpDownSecure, sid[:]), 6+c.maxPayload)
		if err != nil {
			return downResult{}, err
		}
		plain = body
	} else {
		plain = make([]byte, 6)
		if _, err := io.ReadFull(conn, plain); err != nil {
			return downResult{}, err
		}
	}
	if len(plain) < 6 {
		return downResult{}, ErrProtocol
	}
	res := downResult{seq: binary.BigEndian.Uint32(plain[:4])}
	n := binary.BigEndian.Uint16(plain[4:6])
	if n == 0xffff {
		res.eof = true
		return res, nil
	}
	if int(n) > c.maxPayload {
		return downResult{}, fmt.Errorf("%w: DOWN chunk too large: %d", ErrProtocol, n)
	}
	if n == 0 {
		return res, nil
	}
	if c.config.Secure {
		if len(plain) != 6+int(n) {
			return downResult{}, ErrProtocol
		}
		res.buf = append([]byte(nil), plain[6:]...)
		return res, nil
	}
	buf := make([]byte, int(n))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return downResult{}, err
	}
	res.buf = buf
	return res, nil
}

// downRequestPadMin and downRequestPadMax bound the randomised DOWN poll
// request padding. The DOWN poll is the highest-frequency FragPoC op and its
// request was a fixed size — the protocol's strongest size fingerprint.
// Randomising the pad length per request breaks that signature. The max
// keeps the secure request plaintext (6 + padLen) within the server's
// DownRequestSize acceptance ceiling, so this needs no server-side change:
// the server reads the pad length from the frame and skips exactly that many
// bytes.
const (
	downRequestPadMin = 128
	downRequestPadMax = 480
)

// downRequestPaddingLen returns a random padding length for a DOWN poll
// request, uniformly in [downRequestPadMin, downRequestPadMax].
func downRequestPaddingLen() int {
	return downRequestPadMin + rand.Intn(downRequestPadMax-downRequestPadMin+1)
}

// upChunkMin and upChunkMax bound the randomised UP payload chunk size. Write
// splits outbound data into chunks of a random size in this range (it was a
// fixed MaxPayload), so a bulk transfer no longer emits a stream of
// identically sized UP frames. upChunkMax stays within the server's
// MaxUpPayload acceptance ceiling.
const (
	upChunkMin = 480
	upChunkMax = 620
)

// randomUpChunk returns a random UP payload chunk size, uniformly in
// [upChunkMin, upChunkMax].
func randomUpChunk() int {
	return upChunkMin + rand.Intn(upChunkMax-upChunkMin+1)
}

func fillDownRequestPadding(p []byte, sid [SIDLen]byte) {
	for i := range p {
		p[i] = sid[i%len(sid)] ^ byte(0x51+i*17)
	}
}

func (c *Client) closeSession(ctx context.Context, sid [SIDLen]byte, secureKey [32]byte) error {
	if c.config.Secure {
		req := make([]byte, 1+SIDLen)
		req[0] = secureWireOp(OpCloseSecure)
		copy(req[1:], sid[:])
		resp, err := c.exchangeSecure(ctx, req, secureKey, secureRequestAD(OpCloseSecure, sid[:]), secureResponseAD(OpCloseSecure, sid[:]), nil, 1, nil)
		if err != nil {
			return err
		}
		if resp[0] != AckOK {
			return ErrProtocol
		}
		return nil
	}
	req := make([]byte, 1+SIDLen)
	req[0] = OpClose
	copy(req[1:], sid[:])
	resp, err := c.exchangeFixed(ctx, req, 1)
	if err != nil {
		return err
	}
	if resp[0] != AckOK {
		return ErrProtocol
	}
	return nil
}

func (c *Client) exchangeSecure(ctx context.Context, prefix []byte, key [32]byte, reqAD []byte, respAD []byte, reqPlain []byte, respLimit int, nonce []byte) ([]byte, error) {
	if err := c.acquireOpToken(ctx); err != nil {
		return nil, err
	}
	defer c.releaseOpToken(ctx)
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var req bytes.Buffer
	req.Grow(len(prefix) + secureNonceLen + 2 + len(reqPlain) + secureOverhead)
	_, _ = req.Write(prefix)
	if nonce != nil {
		if err := writeSecureBodyWithNonce(&req, key, reqAD, nonce, reqPlain); err != nil {
			return nil, err
		}
	} else if _, err := writeSecureBody(&req, key, reqAD, reqPlain); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, err
	}
	applyDeadlineFromContext(conn, ctx)
	resp, _, err := readSecureBody(conn, key, respAD, respLimit)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) exchangeFixed(ctx context.Context, req []byte, respLen int) ([]byte, error) {
	if err := c.acquireOpToken(ctx); err != nil {
		return nil, err
	}
	defer c.releaseOpToken(ctx)
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	applyDeadlineFromContext(conn, ctx)
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialRaw(ctx)
	if err != nil {
		return nil, err
	}
	// RST-close: a FragPoC op is a strict request/response over a fresh,
	// short-lived connection — once the response is read the connection is
	// disposable. SetLinger(0) makes Close() send RST instead of FIN, so the
	// server/emulator frees its connection slot at once instead of lingering
	// through a FIN teardown, and the client avoids TIME_WAIT port churn.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	n := c.openConns.Add(1)
	for {
		peak := c.openConnsPeak.Load()
		if n <= peak || c.openConnsPeak.CompareAndSwap(peak, n) {
			break
		}
	}
	return &countedConn{Conn: conn, client: c}, nil
}

func (c *Client) dialRaw(ctx context.Context) (net.Conn, error) {
	timeout := connectTimeout(c.config.ConnectTimeout)
	if c.config.Dialer != nil {
		return c.config.Dialer(ctx, "tcp", c.config.ServerAddr)
	}
	addr, err := c.serverDialAddr(ctx)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: timeout}
	if !c.rotationEnabled() {
		return d.DialContext(ctx, "tcp", addr)
	}
	rhost, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	port := c.nextDialPort()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(rhost, strconv.Itoa(port)))
	if err == nil {
		c.markPortResult(port, true)
		return conn, nil
	}
	c.markPortResult(port, false)
	if port != c.basePortNum {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(rhost, strconv.Itoa(c.basePortNum)))
	}
	return nil, err
}

func (c *Client) rotationEnabled() bool {
	return len(c.dialPorts) > 1
}

func (c *Client) nextDialPort() int {
	c.portMu.Lock()
	defer c.portMu.Unlock()

	if len(c.dialPorts) == 0 {
		return c.basePortNum
	}
	now := time.Now()
	for range c.dialPorts {
		port := c.dialPorts[c.portRR]
		c.portRR = (c.portRR + 1) % len(c.dialPorts)
		if port == c.basePortNum {
			return port
		}
		until, cooled := c.portCooldown[port]
		if !cooled || !now.Before(until) {
			return port
		}
	}
	return c.basePortNum
}

func (c *Client) markPortResult(port int, ok bool) {
	c.portMu.Lock()
	defer c.portMu.Unlock()

	if ok {
		delete(c.portCooldown, port)
		return
	}
	if port != c.basePortNum {
		if c.portCooldown == nil {
			c.portCooldown = make(map[int]time.Time)
		}
		c.portCooldown[port] = time.Now().Add(fragPoCClientPortCooldown)
	}
}

// countedConn wraps a server connection so the client can report how many real
// TCP connections to the server are open at once via the [FRAGPOC-METRICS]
// open_conns / open_conns_peak fields. The counter decrement is idempotent.
type countedConn struct {
	net.Conn
	client    *Client
	closeOnce sync.Once
}

func (cc *countedConn) Close() error {
	cc.closeOnce.Do(func() {
		cc.client.openConns.Add(-1)
	})
	return cc.Conn.Close()
}

func (c *Client) serverDialAddr(ctx context.Context) (string, error) {
	if c.serverHost == "" || c.serverPort == "" {
		return c.config.ServerAddr, nil
	}
	if net.ParseIP(c.serverHost) != nil {
		return c.config.ServerAddr, nil
	}
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	if c.resolvedServerAddr != "" {
		return c.resolvedServerAddr, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, c.serverHost)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			c.resolvedServerAddr = net.JoinHostPort(v4.String(), c.serverPort)
			return c.resolvedServerAddr, nil
		}
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("fragpoc: resolve %s: no addresses", c.serverHost)
	}
	c.resolvedServerAddr = net.JoinHostPort(ips[0].IP.String(), c.serverPort)
	return c.resolvedServerAddr, nil
}

// opTokenPool returns the op-token pool a request should use: the small
// reserved dnsTokens pool for DNS flows (so a DNS query never queues behind a
// saturated bulk transfer), the shared opTokens pool otherwise.
func (c *Client) opTokenPool(ctx context.Context) chan struct{} {
	if ctxIsDNS(ctx) && c.dnsTokens != nil {
		return c.dnsTokens
	}
	return c.opTokens
}

func (c *Client) acquireOpToken(ctx context.Context) error {
	pool := c.opTokenPool(ctx)
	if pool == nil {
		return nil
	}
	select {
	case pool <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseOpToken(ctx context.Context) {
	pool := c.opTokenPool(ctx)
	if pool == nil {
		return
	}
	select {
	case <-pool:
	default:
	}
}

func (c *Client) acquireDownToken(ctx context.Context) error {
	if c.downTokens == nil {
		return nil
	}
	select {
	case c.downTokens <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseDownToken() {
	if c.downTokens == nil {
		return
	}
	select {
	case <-c.downTokens:
	default:
	}
}

// dnsContextKey tags a context as belonging to a DNS flow so acquireOpToken
// routes the request to the reserved dnsTokens pool.
type dnsContextKey struct{}

func dnsContext(ctx context.Context, isDNS bool) context.Context {
	if !isDNS {
		return ctx
	}
	return context.WithValue(ctx, dnsContextKey{}, true)
}

func ctxIsDNS(ctx context.Context) bool {
	v, _ := ctx.Value(dnsContextKey{}).(bool)
	return v
}

// isDNSDestination reports whether a dial address targets port 53 — DNS.
// DialUDP prefixes UDP destinations with UDPDestinationPrefix, so a DNS query
// arrives here as "udp:host:53"; the ":53" suffix catches it.
func isDNSDestination(address string) bool {
	return strings.HasSuffix(address, ":53")
}

const maxPendingFrames = 16

type Conn struct {
	client     *Client
	sid        [SIDLen]byte
	secureKey  [32]byte
	localAddr  net.Addr
	remoteAddr net.Addr
	isDNS      bool

	readMu  sync.Mutex
	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  atomic.Bool
	eof     atomic.Bool
	readBuf []byte
	downCh  chan downResult
	errCh   chan error
	done    chan struct{}
	pending map[uint32][]byte
	nextSeq uint32
	eofSeq  uint32
	haveEOF bool
	recvAck atomic.Uint32

	downOnce sync.Once
	doneOnce sync.Once

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	schedInFlight     int
	schedWindow       int
	schedNextPoll     time.Time
	schedIdleDelay    time.Duration
	schedErrorDelay   time.Duration
	schedLastProgress time.Time
	schedLastPayload  time.Time
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.startDownWorkers()
	for len(c.readBuf) == 0 {
		if buf, ok := c.pending[c.nextSeq]; ok {
			delete(c.pending, c.nextSeq)
			c.nextSeq++
			c.recvAck.Store(c.nextSeq)
			c.readBuf = buf
			break
		}
		if c.haveEOF && c.eofSeq == c.nextSeq {
			c.nextSeq++
			c.recvAck.Store(c.nextSeq)
			c.eof.Store(true)
			c.closeDone()
			return 0, io.EOF
		}
		deadline, err := c.deadline(true)
		if err != nil {
			return 0, err
		}
		var timer <-chan time.Time
		var t *time.Timer
		if !deadline.IsZero() {
			t = time.NewTimer(time.Until(deadline))
			timer = t.C
		}
		select {
		case res := <-c.downCh:
			if t != nil {
				t.Stop()
			}
			if res.eof {
				if res.seq < c.nextSeq {
					c.eof.Store(true)
					c.closeDone()
					return 0, io.EOF
				}
				c.haveEOF = true
				c.eofSeq = res.seq
				continue
			}
			if len(res.buf) == 0 || res.seq < c.nextSeq {
				continue
			}
			if res.seq == c.nextSeq {
				c.nextSeq++
				c.recvAck.Store(c.nextSeq)
				c.readBuf = res.buf
				break
			}
			if _, exists := c.pending[res.seq]; !exists && len(c.pending) < maxPendingFrames {
				c.pending[res.seq] = res.buf
			}
		case err := <-c.errCh:
			if t != nil {
				t.Stop()
			}
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		case <-c.done:
			if t != nil {
				t.Stop()
			}
			if c.eof.Load() {
				return 0, io.EOF
			}
			return 0, net.ErrClosed
		case <-timer:
			return 0, os.ErrDeadlineExceeded
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		n := randomUpChunk()
		if n > len(p) {
			n = len(p)
		}
		ctx, cancel, err := c.contextFor(false)
		if err != nil {
			return total, err
		}
		ctx = dnsContext(ctx, c.isDNS)
		err = c.client.sendUp(ctx, c.sid, c.secureKey, p[:n])
		cancel()
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed.Swap(true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout(c.client.config.OperationTimeout))
	defer cancel()
	c.closeDone()
	return c.client.closeSession(dnsContext(ctx, c.isDNS), c.sid, c.secureKey)
}

func (c *Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *Conn) contextFor(read bool) (context.Context, context.CancelFunc, error) {
	deadline, err := c.deadline(read)
	if err != nil {
		return nil, nil, err
	}
	if !deadline.IsZero() {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		return ctx, cancel, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout(c.client.config.OperationTimeout))
	return ctx, cancel, nil
}

func (c *Conn) deadline(read bool) (time.Time, error) {
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	c.deadlineMu.Unlock()
	if !deadline.IsZero() {
		if time.Now().After(deadline) {
			return time.Time{}, os.ErrDeadlineExceeded
		}
	}
	return deadline, nil
}

func (c *Conn) startDownWorkers() {
	c.downOnce.Do(func() {
		if c.client.scheduler != nil {
			c.client.scheduler.addConn(c)
		}
	})
}

type downPollOutcome int

const (
	downPollData downPollOutcome = iota
	downPollIdle
	downPollEOF
	downPollTransient
	downPollFatal
	downPollClosed
)

func (c *Conn) runScheduledDownPoll() downPollOutcome {
	select {
	case <-c.done:
		return downPollClosed
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.client.downPollTimeout)
	res, err := c.client.down(dnsContext(ctx, c.isDNS), c.sid, c.secureKey, c.recvAck.Load())
	cancel()
	if err != nil {
		if isTransientDownError(err) {
			return downPollTransient
		}
		select {
		case c.errCh <- err:
		default:
		}
		c.closeDone()
		return downPollFatal
	}
	if !res.eof && len(res.buf) == 0 {
		return downPollIdle
	}
	select {
	case c.downCh <- res:
	case <-c.done:
		return downPollClosed
	}
	if res.eof {
		return downPollEOF
	}
	return downPollData
}

func isTransientDownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (c *Conn) closeDone() {
	c.doneOnce.Do(func() {
		if c.client != nil && c.client.scheduler != nil {
			c.client.scheduler.removeConn(c)
		}
		close(c.done)
	})
}

func applyDeadlineFromContext(conn net.Conn, ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

// ProbePort runs one OpOpenSecure round-trip against the FragPoC server on a
// specific host:port — the building block of the multi-port smoke test. It
// returns nil when the port is reachable AND the FragPoC protocol answered
// with AckOK; otherwise an error (dial failure, timeout, or protocol
// mismatch). probeDest is deliberately unresolvable, so the server's handler
// fails its upstream dial and drops the probe session within seconds. The
// caller should bound the probe with a context deadline.
func ProbePort(ctx context.Context, host string, port int, shortID [ShortIDLen]byte) error {
	timeout := connectTimeout(0)
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	applyDeadlineFromContext(conn, ctx)

	staticKey := deriveSecureStaticKey(shortID)
	const probeDest = "fragpoc-smoke.invalid:80"
	reqPlain := make([]byte, len(probeDest)+1)
	copy(reqPlain, probeDest)
	nonce, err := newSecureNonce()
	if err != nil {
		return err
	}
	prefix := make([]byte, 1+ShortIDLen+1)
	prefix[0] = secureWireOp(OpOpenSecure)
	copy(prefix[1:1+ShortIDLen], shortID[:])
	prefix[1+ShortIDLen] = secureOpenMarker
	var req bytes.Buffer
	req.Grow(len(prefix) + secureNonceLen + 2 + len(reqPlain) + secureOverhead)
	_, _ = req.Write(prefix)
	if err := writeSecureBodyWithNonce(&req, staticKey, secureRequestAD(OpOpenSecure, shortID[:]), nonce[:], reqPlain); err != nil {
		return err
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return err
	}
	resp, _, err := readSecureBody(conn, staticKey, secureResponseAD(OpOpenSecure, shortID[:]), 1+SIDLen)
	if err != nil {
		return err
	}
	if len(resp) != 1+SIDLen || resp[0] != AckOK {
		return fmt.Errorf("%w: probe ack rejected", ErrProtocol)
	}
	return nil
}
