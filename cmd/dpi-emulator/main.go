package main

import (
	"context"
	"encoding/hex"
	"flag"
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

type config struct {
	listen                    string
	upstream                  string
	maxDownstream             int64
	largeDownstream           int64
	minUpstreamForLargeDown   int64
	maxInflightPerClient      int
	connectTimeout            time.Duration
	randomConnectDelay        time.Duration
	randomDropPermille        int
	blockFirstDownstreamBytes map[byte]struct{}
	verbose                   bool
}

type limiter struct {
	mu     sync.Mutex
	active map[string]int
	limit  int
}

func main() {
	cfg := parseFlags()
	if cfg.upstream == "" {
		log.Fatal("--upstream is required")
	}
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.listen, err)
	}
	log.Printf("dpi-emulator listening on %s -> %s max_down=%d large_down=%d min_up_for_large=%d max_inflight_per_client=%d",
		ln.Addr(), cfg.upstream, cfg.maxDownstream, cfg.largeDownstream, cfg.minUpstreamForLargeDown, cfg.maxInflightPerClient)
	lim := &limiter{active: make(map[string]int), limit: cfg.maxInflightPerClient}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go handleConn(cfg, lim, conn)
	}
}

func parseFlags() config {
	var (
		mode                    = flag.String("mode", "megafon-2026", "Preset mode: megafon-2026 or custom")
		listen                  = flag.String("listen", "127.0.0.1:18443", "Listen address")
		upstream                = flag.String("upstream", "", "Upstream address host:port")
		maxDownstream           = flag.Int64("max-downstream", 700, "Drop a TCP flow before forwarding downstream bytes above this total")
		largeDownstream         = flag.Int64("large-downstream", 480, "Downstream total considered large for upstream warmup checks")
		minUpstreamForLargeDown = flag.Int64("min-upstream-for-large-down", 500, "Minimum upstream total before a large downstream response is allowed")
		maxInflightPerClient    = flag.Int("max-inflight-per-client", 120, "Maximum concurrent accepted TCP flows per client IP; 0 disables")
		connectTimeout          = flag.Duration("connect-timeout", 10*time.Second, "Upstream connect timeout")
		randomConnectDelay      = flag.Duration("random-connect-delay", 0, "Optional random delay before upstream connect, uniformly [0,d]")
		randomDropPermille      = flag.Int("random-drop-permille", 0, "Optional random flow drop probability in permille")
		blockFirstDownHex       = flag.String("block-first-down-hex", "", "Comma-separated first downstream bytes to drop, e.g. 16,47,53")
		verbose                 = flag.Bool("verbose", false, "Verbose per-flow logging")
	)
	flag.Parse()
	if *mode == "megafon-2026" {
		// Defaults already represent the observed useful model. The branch is
		// intentionally explicit so future presets can alter defaults here.
	}
	blocked, err := parseBlockedBytes(*blockFirstDownHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "block-first-down-hex: %v\n", err)
		os.Exit(2)
	}
	return config{
		listen:                    *listen,
		upstream:                  *upstream,
		maxDownstream:             *maxDownstream,
		largeDownstream:           *largeDownstream,
		minUpstreamForLargeDown:   *minUpstreamForLargeDown,
		maxInflightPerClient:      *maxInflightPerClient,
		connectTimeout:            *connectTimeout,
		randomConnectDelay:        *randomConnectDelay,
		randomDropPermille:        *randomDropPermille,
		blockFirstDownstreamBytes: blocked,
		verbose:                   *verbose,
	}
}

func parseBlockedBytes(s string) (map[byte]struct{}, error) {
	out := make(map[byte]struct{})
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(part, "0x"))
		if part == "" {
			continue
		}
		if len(part)%2 == 1 {
			part = "0" + part
		}
		b, err := hex.DecodeString(part)
		if err != nil || len(b) != 1 {
			if n, nerr := strconv.ParseUint(part, 10, 8); nerr == nil {
				out[byte(n)] = struct{}{}
				continue
			}
			return nil, fmt.Errorf("bad byte %q", part)
		}
		out[b[0]] = struct{}{}
	}
	return out, nil
}

func handleConn(cfg config, lim *limiter, client net.Conn) {
	clientIP := hostOnly(client.RemoteAddr())
	if !lim.acquire(clientIP) {
		if cfg.verbose {
			log.Printf("drop client=%s reason=inflight_limit", client.RemoteAddr())
		}
		_ = client.Close()
		return
	}
	defer lim.release(clientIP)
	defer client.Close()

	if cfg.randomDropPermille > 0 && rand.Intn(1000) < cfg.randomDropPermille {
		if cfg.verbose {
			log.Printf("drop client=%s reason=random", client.RemoteAddr())
		}
		return
	}
	if cfg.randomConnectDelay > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(cfg.randomConnectDelay) + 1)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.connectTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.upstream)
	if err != nil {
		if cfg.verbose {
			log.Printf("drop client=%s reason=upstream_connect err=%v", client.RemoteAddr(), err)
		}
		return
	}
	defer upstream.Close()

	var upBytes atomic.Int64
	var downBytes atomic.Int64
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		copyUpstream(client, upstream, &upBytes, closeBoth)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		copyDownstream(cfg, upstream, client, &upBytes, &downBytes, closeBoth)
	}()
	<-done
	closeBoth()
	<-done
	if cfg.verbose {
		log.Printf("flow client=%s up=%d down=%d", client.RemoteAddr(), upBytes.Load(), downBytes.Load())
	}
}

func copyUpstream(src net.Conn, dst net.Conn, upBytes *atomic.Int64, closeBoth func()) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			upBytes.Add(int64(n))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				closeBoth()
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				closeBoth()
			}
			return
		}
	}
}

func copyDownstream(cfg config, src net.Conn, dst net.Conn, upBytes *atomic.Int64, downBytes *atomic.Int64, closeBoth func()) {
	buf := make([]byte, 32*1024)
	var sawFirst bool
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if !sawFirst {
				sawFirst = true
				if _, blocked := cfg.blockFirstDownstreamBytes[buf[0]]; blocked {
					if cfg.verbose {
						log.Printf("drop reason=first_downstream_byte byte=0x%02x", buf[0])
					}
					closeBoth()
					return
				}
			}
			nextDown := downBytes.Load() + int64(n)
			if cfg.maxDownstream > 0 && nextDown > cfg.maxDownstream {
				if cfg.verbose {
					log.Printf("drop reason=max_downstream up=%d down_next=%d max=%d", upBytes.Load(), nextDown, cfg.maxDownstream)
				}
				closeBoth()
				return
			}
			if cfg.largeDownstream > 0 &&
				cfg.minUpstreamForLargeDown > 0 &&
				nextDown >= cfg.largeDownstream &&
				upBytes.Load() < cfg.minUpstreamForLargeDown {
				if cfg.verbose {
					log.Printf("drop reason=small_upstream_large_downstream up=%d down_next=%d need_up=%d",
						upBytes.Load(), nextDown, cfg.minUpstreamForLargeDown)
				}
				closeBoth()
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				closeBoth()
				return
			}
			downBytes.Add(int64(n))
		}
		if err != nil {
			if err != io.EOF {
				closeBoth()
			}
			return
		}
	}
}

func (l *limiter) acquire(clientIP string) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[clientIP] >= l.limit {
		return false
	}
	l.active[clientIP]++
	return true
}

func (l *limiter) release(clientIP string) {
	if l.limit <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[clientIP] <= 1 {
		delete(l.active, clientIP)
		return
	}
	l.active[clientIP]--
}

func hostOnly(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
