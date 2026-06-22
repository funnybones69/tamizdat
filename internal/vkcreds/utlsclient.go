package vkcreds

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	utls "github.com/bogdanfinn/utls"
)

// NewChromeHTTPClient returns an *http.Client whose transport performs TLS
// handshakes using a Chrome-120 ClientHello (via uTLS) and sends HTTP/2
// frames with a Chrome-identical fingerprint (SETTINGS values/order,
// WINDOW_UPDATE increment, pseudo-header order).
//
// Why this matters: VK's anti-bot layer fingerprints not just the TLS
// ClientHello (JA3/JA4) but also the HTTP/2 connection preface. Go's
// default golang.org/x/net/http2.Transport emits a dramatically different
// Akamai-h2 fingerprint from Chrome:
//
//	Go:     2:0,4:4194304,5:1048576,6:10485760|1073741824|0|a,m,p,s
//	Chrome: 1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p
//
// We fix this by using bogdanfinn/fhttp/http2 (a fork of x/net/http2 with
// configurable SETTINGS, connection flow, and pseudo-header ordering) and
// wrapping it in a thin adapter so that the rest of vkcreds still operates
// on standard net/http types.
//
// Timeouts:
//   - Dial: 15 s
//   - TLS handshake: 10 s
//   - Idle keep-alive: 90 s
//   - Per-request: 0 (callers use context cancellation or set their own).
func NewChromeHTTPClient() *http.Client {
	dialTimeout := 15 * time.Second
	tlsTimeout := 10 * time.Second
	idleTimeout := 90 * time.Second

	dialer := &net.Dialer{Timeout: dialTimeout}

	// utlsDialTLS dials TCP, then upgrades to TLS using a Chrome-120
	// ClientHello. The returned net.Conn wraps *utls.UConn with a
	// ConnectionState() adapter so fhttp/http2 can read the ALPN result.
	//
	// Signature matches fhttp/http2.Transport.DialTLS (no context param);
	// we use the dialer's own timeout as the implicit deadline.
	utlsDialTLS := func(network, addr string, _ *utls.Config) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()

		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		tlsCfg := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		uConn := utls.UClient(tcpConn, tlsCfg, utls.HelloChrome_133,
			false, // withRandomTLSExtensionOrder — false for deterministic Chrome fingerprint
			false, // withForceHttp1 — false, we want h2
			false, // withDisableHttp3
		)

		if tlsTimeout > 0 {
			if err := uConn.SetDeadline(time.Now().Add(tlsTimeout)); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
		}

		if err := uConn.Handshake(); err != nil {
			_ = uConn.Close()
			return nil, err
		}

		// Clear the handshake deadline; subsequent I/O uses per-request
		// deadlines managed by the h2 transport.
		if err := uConn.SetDeadline(time.Time{}); err != nil {
			_ = uConn.Close()
			return nil, err
		}

		return &utlsTLSConn{UConn: uConn}, nil
	}

	// Chrome 120-133 HTTP/2 connection fingerprint.
	//
	// SETTINGS frame (sent in exactly this order):
	//   HEADER_TABLE_SIZE      = 65536
	//   ENABLE_PUSH            = 0
	//   INITIAL_WINDOW_SIZE    = 6291456
	//   MAX_HEADER_LIST_SIZE   = 262144
	//
	// WINDOW_UPDATE on stream 0: 15663105 (~15 MB target connection window)
	//
	// Pseudo-header order: :method, :authority, :scheme, :path
	// (Go default is :authority, :method, :path, :scheme — instant bot flag)
	h2t := &fhttp2.Transport{
		DialTLS:            utlsDialTLS,
		DisableCompression: false,
		ReadIdleTimeout:    idleTimeout,
		PingTimeout:        10 * time.Second,

		// SETTINGS values — all four that Chrome sends, nothing more.
		Settings: map[fhttp2.SettingID]uint32{
			fhttp2.SettingHeaderTableSize:   65536,
			fhttp2.SettingEnablePush:        0,
			fhttp2.SettingInitialWindowSize: 6291456,
			fhttp2.SettingMaxHeaderListSize: 262144,
		},
		// Wire order must match Chrome exactly.
		SettingsOrder: []fhttp2.SettingID{
			fhttp2.SettingHeaderTableSize,
			fhttp2.SettingEnablePush,
			fhttp2.SettingInitialWindowSize,
			fhttp2.SettingMaxHeaderListSize,
		},

		// Stream-0 WINDOW_UPDATE: Chrome sends 15663105.
		// bogdanfinn/fhttp defaults to this, but we set it explicitly
		// so a library upgrade never silently changes the fingerprint.
		ConnectionFlow: 15663105,

		// Internal flow/decoder state must match the SETTINGS we advertise.
		HeaderTableSize:   65536,
		InitialWindowSize: 6291456,

		// Pseudo-header emission order on HEADERS frames.
		PseudoHeaderOrder: []string{
			":method", ":authority", ":scheme", ":path",
		},
	}

	// Cookie jar is essential: VK sets session cookies when the captcha
	// redirect page is fetched and expects them in subsequent API calls.
	// Without a jar, VK sees disconnected requests → instant BOT flag.
	jar, _ := cookiejar.New(nil)

	return &http.Client{
		Transport: &chromeH2Adapter{transport: h2t},
		Jar:       jar,
	}
}

// chromeH2Adapter wraps bogdanfinn/fhttp/http2.Transport (which operates on
// fhttp request/response types) as a standard net/http.RoundTripper.
//
// The conversion is cheap: both packages define Header as
// map[string][]string, URL as *net/url.URL, Body as io.ReadCloser, etc.
// We copy the struct fields without allocating intermediate buffers.
type chromeH2Adapter struct {
	transport *fhttp2.Transport
}

// RoundTrip implements net/http.RoundTripper by converting the request to
// fhttp types, executing it on the Chrome-fingerprinted h2 transport, and
// converting the response back.
func (a *chromeH2Adapter) RoundTrip(req *http.Request) (*http.Response, error) {
	fReq := &fhttp.Request{
		Method:        req.Method,
		URL:           req.URL,
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        fhttp.Header(req.Header),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
	}
	fReq = fReq.WithContext(req.Context())

	fResp, err := a.transport.RoundTrip(fReq)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		Status:           fResp.Status,
		StatusCode:       fResp.StatusCode,
		Proto:            fResp.Proto,
		ProtoMajor:       fResp.ProtoMajor,
		ProtoMinor:       fResp.ProtoMinor,
		Header:           http.Header(fResp.Header),
		Body:             fResp.Body,
		ContentLength:    fResp.ContentLength,
		TransferEncoding: fResp.TransferEncoding,
		Close:            fResp.Close,
		Uncompressed:     fResp.Uncompressed,
		Request:          req,
	}, nil
}

// utlsTLSConn wraps *utls.UConn so that it satisfies the interface that
// fhttp/http2 expects from a TLS connection: a ConnectionState() method
// that returns crypto/tls.ConnectionState (not the utls variant).
type utlsTLSConn struct {
	*utls.UConn
}

// ConnectionState returns a crypto/tls.ConnectionState populated from the
// uTLS connection state. Only the fields that http2.Transport inspects are
// forwarded; the rest are left at their zero values.
func (c *utlsTLSConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            s.Version,
		HandshakeComplete:  s.HandshakeComplete,
		NegotiatedProtocol: s.NegotiatedProtocol,
		ServerName:         s.ServerName,
	}
}
