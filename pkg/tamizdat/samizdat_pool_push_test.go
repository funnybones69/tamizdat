package tamizdat

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPoolPushFetchAndApplyOverrides(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	var sawMagic bool
	tr := &h2Transport{
		serverAddr: "server.example:443",
		h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodConnect || r.Host != configAuthority || r.Header.Get(SamizdatProtocolHeader) != SamizdatProtocolConfig {
				t.Fatalf("unexpected config request: method=%s host=%s proto=%s", r.Method, r.Host, r.Header.Get(SamizdatProtocolHeader))
			}
			sawMagic = true
			body := `{"version":1,"epoch_key":"ep-current","shortid_pool_size":5,"sni_pool":[{"sni":"vk.com","weight":200}],"cover_targets":["mc.yandex.ru:443"],"cover_gap_min_ms":1000,"cover_gap_max_ms":2000}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}),
	}
	c := &Client{config: ClientConfig{MasterShortID: master, PrimarySNI: "ok.ru", ServerName: "ok.ru"}}
	initialTargets := []string{"default.example:443"}
	c.cover = &coverDriver{c: c, stop: make(chan struct{})}
	c.cover.targets.Store(&initialTargets)
	c.cover.gapMin.Store(int64(coverGapMin))
	c.cover.gapMax.Store(int64(coverGapMax))

	if err := c.fetchAndApplyBundle(context.Background(), tr); err != nil {
		t.Fatalf("fetchAndApplyBundle: %v", err)
	}
	if !sawMagic {
		t.Fatal("config magic CONNECT was not issued")
	}
	// Shortid full-B simplification (2026-05-09): derived shortid pool is
	// gone; pickShortID always returns master. Bundle's epoch_key and
	// shortid_pool_size are tolerated for backward-compat but ignored.
	if got := c.cover.targets.Load(); got == nil || len(*got) != 1 || (*got)[0] != "mc.yandex.ru:443" {
		t.Fatalf("cover targets = %v", got)
	}
	if c.cover.gapMin.Load() != int64(time.Second) || c.cover.gapMax.Load() != int64(2*time.Second) {
		t.Fatalf("cover gaps = %s/%s", time.Duration(c.cover.gapMin.Load()), time.Duration(c.cover.gapMax.Load()))
	}
	if got := c.serverPushedSNIPool.Load(); got == nil || len(*got) != 1 || (*got)[0].SNI != "vk.com" {
		t.Fatalf("server pushed SNI pool = %v", got)
	}

	if got := c.pickShortID(); got != master {
		t.Fatalf("pickShortID = %x, want master %x (post-simplification: always master)", got, master)
	}

	pickedBundleSNI := false
	for i := 0; i < 50; i++ {
		if sni := c.pickServerName(); sni == "vk.com" {
			pickedBundleSNI = true
			break
		}
	}
	if !pickedBundleSNI {
		t.Fatal("pickServerName never picked server-pushed SNI across 50 trials")
	}
}

func TestPoolPushEndToEndNewClientServer(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	master, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	bundlePath := t.TempDir() + "/bundle.json"
	bundleJSON := `{"version":1,"epoch_key":"ep-push-e2e","shortid_pool_size":8,"sni_pool":[{"sni":"vk.com","weight":1000}],"cover_targets":["mc.yandex.ru:443","an.yandex.ru:443"],"cover_gap_min_ms":1000,"cover_gap_max_ms":2000}`
	if err := os.WriteFile(bundlePath, []byte(bundleJSON), 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:      "127.0.0.1:0",
		PrivateKey:      serverPriv,
		MasterShortID:   master,
		CoverConfigPath: bundlePath,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		MasqueradePool:  map[string]string{"vk.com": ""},
		Handler:         poolPushEchoHandler,
	})

	beforeReceived := expvarIntValue("tamizdat_bundle_received_total")
	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              serverPub,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
		CoverTrafficEnabled:    true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn := poolPushDialAndEcho(t, client, "example.org:443")
	conn.Close()
	waitForExpvarAtLeast(t, "tamizdat_bundle_received_total", beforeReceived+1)
	waitForExpvarAtLeast(t, "tamizdat_bundle_applied_total", beforeApplied+1)

	if client.cover == nil {
		t.Fatal("cover driver was not started")
	}
	targetsPtr := client.cover.targets.Load()
	if targetsPtr == nil || len(*targetsPtr) == 0 {
		t.Fatalf("cover targets not applied: %v", targetsPtr)
	}
	bundleTargets := map[string]struct{}{"mc.yandex.ru:443": {}, "an.yandex.ru:443": {}}
	for i := 0; i < 10; i++ {
		target := (*targetsPtr)[i%len(*targetsPtr)]
		if _, ok := bundleTargets[target]; !ok {
			t.Fatalf("cover target sample %q not in bundle targets %v", target, bundleTargets)
		}
	}

	pickedBundleSNI := false
	for i := 0; i < 200; i++ {
		if client.pickServerName() == "vk.com" {
			pickedBundleSNI = true
			break
		}
	}
	if !pickedBundleSNI {
		t.Fatal("SNI sample never picked pushed sni_pool entry")
	}
	// Shortid full-B simplification (2026-05-09): pickShortID always returns
	// master regardless of bundle's deprecated epoch_key/shortid_pool_size.
	if got := client.pickShortID(); got != master {
		t.Fatalf("pickShortID = %x, want master %x", got, master)
	}
}

func TestPoolPushBackwardCompatNoBundle(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	master, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: master,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler:       poolPushEchoHandler,
	})

	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		PrimarySNI:             "ok.ru",
		ServerName:             "ok.ru",
		PublicKey:              serverPub,
		MasterShortID:          master,
		Fingerprint:            "chrome",
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn := poolPushDialAndEcho(t, client, "example.org:443")
	conn.Close()
	waitForExpvarAtLeast(t, "tamizdat_bundle_applied_total", beforeApplied+1)
	// Shortid full-B simplification: derived pool removed; pickShortID
	// always returns master regardless of bundle.
	if got := client.pickShortID(); got != master {
		t.Fatalf("pickShortID after empty bundle = %x, want master %x", got, master)
	}

	conn = poolPushDialAndEcho(t, client, "example.org:443")
	conn.Close()
}

func TestPoolPushBackwardCompatE2AD38FClientBinary(t *testing.T) {
	// 2026-05-01 wire rename: project renamed samizdat -> tamizdat including the
	// HKDF auth label ("SAMIZDAT v1" -> "TAMIZDAT v1"), magic CONNECT authority
	// ("samizdat-config.invalid" -> "tamizdat-config.invalid"), and protocol header
	// ("samizdat-protocol" -> "tamizdat-protocol"). The e2ad38f binary computes
	// PSK with the old label, so it can no longer authenticate against the new
	// server. This is an INTENTIONAL clean break documented in NOTICE.md; the
	// test is preserved as a structural placeholder but skipped.
	t.Skip("intentional clean break vs e2ad38f after tamizdat wire rename (NOTICE.md)")
	oldClientPath := buildOldClientE2AD38F(t)
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	master, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: master,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			poolPushProxyToDestination(conn, destination)
		},
	})

	socksProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("SOCKS probe listener: %v", err)
	}
	socksAddr := socksProbe.Addr().String()
	_ = socksProbe.Close()

	cmd := exec.Command(
		oldClientPath,
		"-server", ln.Addr().String(),
		"-servername", "test.example.com",
		"-pubkey", hex.EncodeToString(serverPub),
		"-shortid", hex.EncodeToString(master[:]),
		"-listen", socksAddr,
		"-tcpfrag=false",
	)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start e2ad38f client: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := waitTCP(socksAddr, 5*time.Second); err != nil {
		t.Fatalf("e2ad38f client did not listen: %v; logs=%s", err, logs.String())
	}

	echoHost, echoPort, err := splitHostPortUint16(echoLn.Addr().String())
	if err != nil {
		t.Fatalf("echo address: %v", err)
	}
	if err := socksConnectAndEcho(socksAddr, echoHost, echoPort, []byte("old-client-compat")); err != nil {
		t.Fatalf("SOCKS echo through e2ad38f client: %v; logs=%s", err, logs.String())
	}
}

func TestBundleFetchEmptyBodyFallback(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	tr := &h2Transport{serverAddr: "server.example:443", h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodConnect || r.Host != configAuthority || r.Header.Get(SamizdatProtocolHeader) != SamizdatProtocolConfig {
			t.Fatalf("unexpected config request: method=%s host=%s proto=%s", r.Method, r.Host, r.Header.Get(SamizdatProtocolHeader))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	c := &Client{config: ClientConfig{MasterShortID: master, PrimarySNI: "ok.ru", ServerName: "ok.ru"}}
	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	beforeErrors := expvarIntValue("tamizdat_bundle_fetch_errors_total")

	if err := c.fetchAndApplyBundle(context.Background(), tr); err != nil {
		t.Fatalf("fetchAndApplyBundle empty body: %v", err)
	}
	if got := expvarIntValue("tamizdat_bundle_applied_total"); got != beforeApplied {
		t.Fatalf("bundle applied counter = %d, want unchanged %d", got, beforeApplied)
	}
	if got := expvarIntValue("tamizdat_bundle_fetch_errors_total"); got != beforeErrors {
		t.Fatalf("bundle fetch errors = %d, want unchanged %d", got, beforeErrors)
	}
	// Shortid full-B simplification: derived pool removed; pickShortID
	// always returns master.
	picked := c.pickShortID()
	if picked != master {
		t.Fatalf("pickShortID after empty body = %x, want master %x", picked, master)
	}
}

func TestBundleFetchNon200Fallback(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	tr := &h2Transport{serverAddr: "server.example:443", h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodConnect || r.Host != configAuthority || r.Header.Get(SamizdatProtocolHeader) != SamizdatProtocolConfig {
			t.Fatalf("unexpected config request: method=%s host=%s proto=%s", r.Method, r.Host, r.Header.Get(SamizdatProtocolHeader))
		}
		return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad gateway"))}, nil
	})}
	c := &Client{config: ClientConfig{MasterShortID: master, PrimarySNI: "ok.ru", ServerName: "ok.ru"}}
	beforeApplied := expvarIntValue("tamizdat_bundle_applied_total")
	beforeErrors := expvarIntValue("tamizdat_bundle_fetch_errors_total")

	if err := c.fetchAndApplyBundle(context.Background(), tr); err == nil {
		t.Fatal("fetchAndApplyBundle non-200 returned nil error")
	}
	if got := expvarIntValue("tamizdat_bundle_applied_total"); got != beforeApplied {
		t.Fatalf("bundle applied counter = %d, want unchanged %d", got, beforeApplied)
	}
	if got := expvarIntValue("tamizdat_bundle_fetch_errors_total"); got != beforeErrors+1 {
		t.Fatalf("bundle fetch errors = %d, want %d", got, beforeErrors+1)
	}
	// Shortid full-B simplification: derived pool removed; pickShortID
	// always returns master.
	picked := c.pickShortID()
	if picked != master {
		t.Fatalf("pickShortID after non-200 = %x, want master %x", picked, master)
	}
}

func TestPoolPushOversizedBodyFallsBack(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	tr := &h2Transport{serverAddr: "server.example:443", h2Roundtrip: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", MaxCoverConfigBundleBytes+1)))}, nil
	})}
	c := &Client{config: ClientConfig{MasterShortID: master, PrimarySNI: "ok.ru", ServerName: "ok.ru"}}
	if err := c.fetchAndApplyBundle(context.Background(), tr); err == nil {
		t.Fatal("oversized config body accepted")
	}
	if got := c.pickShortID(); got != master {
		t.Fatalf("fallback shortID = %x, want master %x", got, master)
	}
}

func poolPushEchoHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func poolPushDialAndEcho(t *testing.T, client *Client, destination string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	payload := []byte("pool-push-ping")
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		conn.Close()
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
	return conn
}

func buildOldClientE2AD38F(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.Mkdir(srcDir, 0755); err != nil {
		t.Fatalf("mkdir old client source dir: %v", err)
	}

	archive := exec.Command("sh", "-c", "git archive e2ad38f | tar -x -C \"$1\"", "sh", srcDir)
	if out, err := archive.CombinedOutput(); err != nil {
		t.Skipf("e2ad38f client build unavailable: git archive failed: %v; output=%s", err, truncateTestOutput(out))
	}

	oldClientPath := filepath.Join(tmp, "oldclient")
	build := exec.Command("go", "build", "-o", oldClientPath, "./cmd/samizdat-client")
	build.Dir = srcDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("e2ad38f client build unavailable: go build failed: %v; output=%s", err, truncateTestOutput(out))
	}
	return oldClientPath
}

func poolPushProxyToDestination(conn net.Conn, destination string) {
	defer conn.Close()
	backend, err := net.DialTimeout("tcp", destination, 5*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, backend)
		done <- struct{}{}
	}()
	<-done
}

func splitHostPortUint16(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port64), nil
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		return fmt.Errorf("timeout waiting for %s", addr)
	}
	return lastErr
}

func socksConnectAndEcho(addr, host string, port uint16, payload []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("SOCKS method reply %x", buf)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		return fmt.Errorf("SOCKS connect reply head %x", head)
	}
	var rest int
	switch head[3] {
	case 0x01:
		rest = 4 + 2
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return err
		}
		rest = int(lb[0]) + 2
	case 0x04:
		rest = 16 + 2
	default:
		return fmt.Errorf("bad SOCKS reply ATYP %x", head[3])
	}
	if rest > 0 {
		if _, err := io.ReadFull(conn, make([]byte, rest)); err != nil {
			return err
		}
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch got %q want %q", got, payload)
	}
	return nil
}

func truncateTestOutput(out []byte) string {
	const max = 4096
	if len(out) <= max {
		return string(out)
	}
	return string(out[:max]) + "...(truncated)"
}

func waitForExpvarAtLeast(t *testing.T, name string, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := expvarIntValue(name); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s = %d, want >= %d", name, expvarIntValue(name), want)
}
