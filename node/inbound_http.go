package node

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// HTTPInbound implements an HTTP/1.1 CONNECT proxy. Plain (non-CONNECT) HTTP
// proxying with header rewriting is intentionally NOT implemented — for plain
// HTTP, configure the client to use CONNECT (which most do).
//
// Auth: empty creds = no auth required; otherwise Basic Authentication is
// enforced (Proxy-Authorization: Basic base64(user:pass)).
type HTTPInbound struct {
	tag      string
	listen   string
	username string
	password string

	ln     net.Listener
	closed atomic.Bool
}

func NewHTTPInbound(tag, listen string, raw json.RawMessage) (*HTTPInbound, error) {
	var s HTTPSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("http inbound %q settings: %w", tag, err)
		}
	}
	if listen == "" {
		return nil, fmt.Errorf("http inbound %q: listen required", tag)
	}
	if (s.Username == "") != (s.Password == "") {
		return nil, fmt.Errorf("http inbound %q: username and password must be set together", tag)
	}
	return &HTTPInbound{
		tag:      tag,
		listen:   listen,
		username: s.Username,
		password: s.Password,
	}, nil
}

func (h *HTTPInbound) Tag() string { return h.tag }

func (h *HTTPInbound) Start(ctx context.Context, d InboundDispatcher) error {
	ln, err := net.Listen("tcp", h.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", h.listen, err)
	}
	h.ln = ln
	go func() {
		<-ctx.Done()
		h.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if h.closed.Load() {
				return nil
			}
			return err
		}
		go h.handle(ctx, c, d)
	}
}

func (h *HTTPInbound) Close() error {
	if h.closed.Swap(true) {
		return nil
	}
	if h.ln != nil {
		return h.ln.Close()
	}
	return nil
}

func (h *HTTPInbound) handle(ctx context.Context, c net.Conn, d InboundDispatcher) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if h.username != "" || h.password != "" {
		if !h.checkAuth(req) {
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"samizdat\"\r\n" +
				"Connection: close\r\n\r\n"))
			return
		}
	}
	if req.Method != http.MethodConnect {
		_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n" +
			"Connection: close\r\n\r\n"))
		return
	}

	host, portStr, err := net.SplitHostPort(req.RequestURI)
	if err != nil {
		// req.RequestURI for CONNECT is "host:port"
		host = req.RequestURI
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	dreq := &Request{
		Network:    NetworkTCP,
		TargetHost: strings.TrimSuffix(host, "."),
		TargetPort: port,
		InboundTag: h.tag,
	}
	if tcpAddr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		dreq.SourceIP = tcpAddr.IP
	}

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tunnel, _, err := d.Dispatch(dctx, dreq)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer tunnel.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// If client wrote anything ahead of the CONNECT body, drain any buffered
	// bytes from bufio.Reader into the tunnel before splicing.
	if buffered := br.Buffered(); buffered > 0 {
		peek, _ := br.Peek(buffered)
		_, _ = tunnel.Write(peek)
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(tunnel, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, tunnel); done <- struct{}{} }()
	<-done
}

func (h *HTTPInbound) checkAuth(req *http.Request) bool {
	auth := req.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	idx := strings.IndexByte(string(dec), ':')
	if idx < 0 {
		return false
	}
	u := dec[:idx]
	p := dec[idx+1:]
	uok := subtle.ConstantTimeCompare([]byte(h.username), u) == 1
	pok := subtle.ConstantTimeCompare([]byte(h.password), p) == 1
	return uok && pok
}
