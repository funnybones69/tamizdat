package tamizdat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestAuthenticatedPathShadowDialsMasqueradeOrigin(t *testing.T) {
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer originLn.Close()

	shadowDials := make(chan struct{}, 2)
	go func() {
		for {
			conn, err := originLn.Accept()
			if err != nil {
				return
			}
			shadowDials <- struct{}{}
			_ = conn.Close()
		}
	}()

	serverConfig, clientConfig := p06AuthConfigs(t, originLn.Addr().String())
	srv, serverAddr, serveDone := p06StartServer(t, serverConfig)
	defer p06StopServer(t, srv, serveDone)
	clientConfig.ServerAddr = serverAddr

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	transport, err := client.createTransport(ctx)
	if err != nil {
		t.Fatalf("authenticated TLS/H2 handshake: %v", err)
	}
	defer transport.close()

	select {
	case <-shadowDials:
	case <-time.After(time.Second):
		t.Fatal("authenticated path did not shadow-dial masquerade origin")
	}

	select {
	case <-shadowDials:
		t.Fatal("authenticated path shadow-dialed masquerade origin more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAuthenticatedPathContinuesWhenShadowDialOriginFails(t *testing.T) {
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed origin address: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	serverConfig, clientConfig := p06AuthConfigs(t, closedAddr)
	srv, serverAddr, serveDone := p06StartServer(t, serverConfig)
	defer p06StopServer(t, srv, serveDone)
	clientConfig.ServerAddr = serverAddr

	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	transport, err := client.createTransport(ctx)
	if err != nil {
		t.Fatalf("authenticated TLS/H2 handshake after origin dial failure: %v", err)
	}
	defer transport.close()
}

func TestMasqueradeIdleTimeoutClosesBeforeMaxDuration(t *testing.T) {
	clientHello := []byte("clienthello")
	originReceived := make(chan []byte, 1)

	originAddr, stopOrigin := p06StartOrigin(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, len(clientHello)+1)
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			originReceived <- nil
			return
		}
		originReceived <- buf
		_, _ = io.Copy(io.Discard, conn)
	})
	defer stopOrigin()

	m := NewMasquerade("ok.ru", originAddr, 100*time.Millisecond, 10*time.Second)
	m.DialTimeout = time.Second

	serverSide, probeSide := net.Pipe()
	defer probeSide.Close()

	done := make(chan error, 1)
	go func() {
		done <- m.ProxyConnection(serverSide, clientHello)
	}()

	probeSide.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := probeSide.Write([]byte("x")); err != nil {
		t.Fatalf("probe write: %v", err)
	}

	select {
	case got := <-originReceived:
		want := append(append([]byte(nil), clientHello...), 'x')
		if !bytes.Equal(got, want) {
			t.Fatalf("origin received %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive forwarded ClientHello + probe byte")
	}

	start := time.Now()
	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 350*time.Millisecond {
			t.Fatalf("masquerade closed after %s, want idle close within ~200ms", elapsed)
		}
	case <-time.After(350 * time.Millisecond):
		t.Fatal("masquerade connection stayed open past IdleTimeout; MaxDuration would be the only deadline")
	}
}

func TestMasqueradeIdleTimeoutResetsWithBidirectionalTraffic(t *testing.T) {
	clientHello := []byte("clienthello")
	originReady := make(chan struct{}, 1)

	originAddr, stopOrigin := p06StartOrigin(t, func(conn net.Conn) {
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, len(clientHello))); err != nil {
			return
		}
		originReady <- struct{}{}
		buf := make([]byte, 1)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	})
	defer stopOrigin()

	m := NewMasquerade("ok.ru", originAddr, 100*time.Millisecond, 2*time.Second)
	m.DialTimeout = time.Second

	serverSide, probeSide := net.Pipe()
	defer probeSide.Close()

	done := make(chan error, 1)
	go func() {
		done <- m.ProxyConnection(serverSide, clientHello)
	}()

	select {
	case <-originReady:
	case <-time.After(time.Second):
		t.Fatal("origin did not receive forwarded ClientHello")
	}

	buf := make([]byte, 1)
	for i := 0; i < 5; i++ {
		want := byte('a' + i)
		probeSide.SetDeadline(time.Now().Add(time.Second))
		if _, err := probeSide.Write([]byte{want}); err != nil {
			t.Fatalf("active write %d: %v", i, err)
		}
		n, err := probeSide.Read(buf)
		if err != nil {
			t.Fatalf("active read %d: %v", i, err)
		}
		if n != 1 || buf[0] != want {
			t.Fatalf("active echo %d = %q, want %q", i, buf[:n], []byte{want})
		}
		select {
		case err := <-done:
			t.Fatalf("masquerade closed during active bidirectional traffic: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case err := <-done:
		t.Fatalf("masquerade closed before traffic stopped: %v", err)
	default:
	}

	_ = probeSide.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("masquerade did not return after probe close")
	}
}

func p06AuthConfigs(t *testing.T, masqueradeAddr string) (ServerConfig, ClientConfig) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := p06TestCertPEM(t)

	serverConfig := ServerConfig{
		PrivateKey:               priv,
		MasterShortID:            shortID,
		CertPEM:                  certPEM,
		KeyPEM:                   keyPEM,
		MasqueradeDomain:         "ok.ru",
		MasqueradeAddr:           masqueradeAddr,
		MasqueradeMaxDuration:    10 * time.Second,
		DisableDefaultSecurity:   true,
		DisableMasqueradePrewarm: true, // p06 tests count exact origin dials
		// A-RR-2: shadowDialOrigin now routes via the pool when a probe
		// SNI matches an entry. Pin the pool to the test listener so the
		// "did the shadow dial fire?" assertion still observes the dial
		// on the test-controlled address (rather than the auto-filled
		// default RU pool, which would resolve "ok.ru" via real DNS).
		MasqueradePool: map[string]string{"ok.ru": masqueradeAddr},
		Handler:        func(context.Context, net.Conn, string) {},
	}
	clientConfig := ClientConfig{
		ServerName:             "ok.ru",
		PublicKey:              pub,
		ShortID:                shortID,
		DisableDefaultSecurity: true,
	}
	return serverConfig, clientConfig
}

func p06StartServer(t *testing.T, config ServerConfig) (*Server, string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	srv, err := NewServer(config)
	if err != nil {
		ln.Close()
		t.Fatalf("NewServer: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ln)
	}()
	return srv, ln.Addr().String(), serveDone
}

func p06StopServer(t *testing.T, srv *Server, serveDone <-chan error) {
	t.Helper()
	if err := srv.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("server serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func p06StartOrigin(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()
	stop := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("origin handler did not stop")
		}
	}
	return ln.Addr().String(), stop
}

func p06TestCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ok.ru"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ok.ru", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
