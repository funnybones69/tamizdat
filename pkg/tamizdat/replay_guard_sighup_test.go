package tamizdat

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestReplayGuard_PreservedAcrossSIGHUP_Reload is the C-3 regression test.
//
// Bug to guard against: if `s.replayGuard` is recreated inside the SIGHUP
// reload handlers (ReloadOutbounds / ReloadUsers / equivalent SIGHUP-driven
// helpers in cmd/tamizdat-server), the in-memory seen-nonce map gets wiped
// and a 5-min replay window opens — captured ClientHellos that were
// previously rejected as replays would be accepted again.
//
// What the test does:
//  1. Spawn an in-process tamizdat-server with embedded handler (no
//     ServerDBPath, so `ReloadOutbounds` and `ReloadUsers` are no-ops that
//     return "registry disabled" errors but do not panic — the cmd/SIGHUP
//     loop logs the error and proceeds; we replicate that flow here).
//  2. Capture a real ClientHello via the same Dialer-tap pattern used by
//     TestP03ReplayRejectionIncrementsExpvar.
//  3. Replay it raw — assert the server rejects it (replay-guard fires;
//     tamizdat.replay.hits increments).
//  4. Trigger the SIGHUP-equivalent reload paths
//     (ReloadOutbounds + ReloadUsers).
//  5. Snapshot s.replayGuard pointer; it MUST be the same instance after
//     reload — replayGuard is a long-lived field on Server, not a
//     SIGHUP-rebuildable resource.
//  6. Replay the captured ClientHello a second time — assert it is STILL
//     rejected. If the reload had wiped the guard, the second replay
//     would re-trigger the masquerade-fall-through but be visible as a
//     stable replay-hits counter (no further increment) which would be
//     wrong.
func TestReplayGuard_PreservedAcrossSIGHUP_Reload(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	srv, ln := startTestServer(t, ServerConfig{
		ListenAddr:             "127.0.0.1:0",
		PrivateKey:             serverPriv,
		MasterShortID:          shortID,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		DisableDefaultSecurity: true,
		Handler: func(ctx context.Context, conn net.Conn, _ string) {
			defer conn.Close()
		},
	})

	// Snapshot the replayGuard pointer before any reload.
	guardBefore := srv.replayGuard
	if guardBefore == nil {
		t.Fatal("server has no replayGuard")
	}

	// Capture a real ClientHello + complete one successful auth.
	var captured *captureWriteConn
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "cover.example",
		PublicKey:              serverPub,
		ShortID:                shortID,
		WireVersion:            2,
		TCPFragmentation:       false,
		DisableDefaultSecurity: true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			captured = &captureWriteConn{Conn: conn}
			return captured, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := client.DialContext(ctx, "tcp", "example.org:443")
	cancel()
	if err != nil {
		t.Fatalf("initial DialContext: %v", err)
	}
	_ = conn.Close()
	clientHello := captured.Bytes()
	if len(clientHello) == 0 {
		t.Fatal("did not capture ClientHello")
	}

	// First replay — replay-guard fires, hits counter increments.
	hitsBefore := expvarIntValue("tamizdat.replay.hits")
	replay1, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial replay #1: %v", err)
	}
	if _, err := replay1.Write(clientHello); err != nil {
		t.Fatalf("write replay #1: %v", err)
	}
	_ = replay1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = replay1.Read(make([]byte, 1))
	_ = replay1.Close()
	hitsAfterFirstReplay := expvarIntValue("tamizdat.replay.hits")
	if hitsAfterFirstReplay <= hitsBefore {
		t.Fatalf("first replay did not register: hits %d -> %d", hitsBefore, hitsAfterFirstReplay)
	}

	// SIGHUP-equivalent: invoke the same reload helpers cmd/tamizdat-server
	// runs inside the SIGHUP goroutine. Embedded test has no SQLite DB, so
	// these return "registry disabled" errors — mirroring how the real
	// SIGHUP loop would log the error and continue. The KEY assertion is
	// that calling them does NOT recreate replayGuard.
	if _, _, err := srv.ReloadOutbounds(); err == nil {
		// Returning an error is expected without ServerDBPath; nil here
		// is also fine (later refactor may add a no-op success path).
		// We don't assert err != nil to keep the test stable across
		// reload-helper signature changes.
	}
	if _, _, err := srv.ReloadUsers(); err == nil {
		// Same as above.
	}

	// replayGuard pointer MUST be unchanged.
	guardAfter := srv.replayGuard
	if guardAfter != guardBefore {
		t.Fatalf("replayGuard pointer changed across reload: before=%p after=%p (this would wipe the seen-nonce map)", guardBefore, guardAfter)
	}

	// Second replay — must STILL reject. If reload had wiped the guard,
	// hitsAfterSecondReplay would equal hitsAfterFirstReplay (the second
	// replay would have re-passed verify and not bumped the hits counter
	// since the guard would not see it as a duplicate). We assert hits
	// strictly increases — proving the seen-nonce map survived reload.
	replay2, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial replay #2: %v", err)
	}
	if _, err := replay2.Write(clientHello); err != nil {
		t.Fatalf("write replay #2: %v", err)
	}
	_ = replay2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = replay2.Read(make([]byte, 1))
	_ = replay2.Close()
	hitsAfterSecondReplay := expvarIntValue("tamizdat.replay.hits")
	if hitsAfterSecondReplay <= hitsAfterFirstReplay {
		t.Fatalf(
			"replay-guard did NOT survive reload: hits %d (after #1) -> %d (after reload+#2). "+
				"Expected strictly greater than %d to prove seen-nonce map preserved.",
			hitsAfterFirstReplay, hitsAfterSecondReplay, hitsAfterFirstReplay,
		)
	}
}
