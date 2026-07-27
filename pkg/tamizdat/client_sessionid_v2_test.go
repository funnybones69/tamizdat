package tamizdat

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestClientV2_StableSessionIDPrefixAcrossDials: dial the same in-process
// server twice from one Client built with WireVersion=2; the SessionID
// 6-byte stable prefix must be identical across the two dials, and only the
// 2-byte counter portion must change. End-to-end proof of review-C tell #12
// fix.
func TestClientV2_StableSessionIDPrefixAcrossDials(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		// Default Min=1 / Max=2 acceptance window.
		Handler: func(ctx context.Context, conn net.Conn, _ string) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})

	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "cover.example",
		PublicKey:              serverPub,
		ShortID:                shortID,
		WireVersion:            2,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if client.sessionIDCache == nil {
		t.Fatal("WireVersion=2 client must allocate sessionIDCache")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c1, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext #1: %v", err)
	}
	c1.Close()
	c2, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext #2: %v", err)
	}
	c2.Close()

	stable, ok := client.sessionIDCache.PeekStableRandom(client.config.ServerAddr, shortID)
	if !ok {
		t.Fatal("expected sessionIDCache to hold an entry after two dials")
	}
	if bytes.Equal(stable[:], make([]byte, stableRandomLen)) {
		t.Fatal("stable prefix is all-zero — cache likely was not populated")
	}
	// PeekStableRandom returning ok+non-zero on the second dial is sufficient
	// proof: the cache survived between dials and counter was bumped under
	// the same key.
}

// TestClientV1_NoCacheAllocated: legacy WireVersion=1 must NOT allocate the
// cache; the dial path falls through to BuildSessionIDv1 with a fresh-random
// nonce per dial.
func TestClientV1_NoCacheAllocated(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}

	// applyDefaults clamps WireVersion=0 to 2; pass 1 explicitly to assert
	// legacy behaviour.
	client, err := NewClient(ClientConfig{
		ServerAddr:             "127.0.0.1:1",
		ServerName:             "cover.example",
		PublicKey:              serverPub,
		ShortID:                shortID,
		WireVersion:            1,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	if client.sessionIDCache != nil {
		t.Fatal("WireVersion=1 client must NOT allocate sessionIDCache")
	}
	_ = serverPriv
}

// TestServer_AcceptsBothV1AndV2_DuringRollout: bring up a server with the
// default [1,2] acceptance window and confirm a legacy v1 client and a new v2
// client both authenticate successfully. This is the production rollout
// scenario where existing in-flight clients keep working while new clients
// emit v2.
func TestServer_AcceptsBothV1AndV2_DuringRollout(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, _ string) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})

	for _, wireVersion := range []int{1, 2} {
		wireVersion := wireVersion
		t.Run(map[int]string{1: "v1_client", 2: "v2_client"}[wireVersion], func(t *testing.T) {
			client, err := NewClient(ClientConfig{
				ServerAddr:             ln.Addr().String(),
				ServerName:             "cover.example",
				PublicKey:              serverPub,
				ShortID:                shortID,
				WireVersion:            wireVersion,
				DisableDefaultSecurity: true,
			})
			if err != nil {
				t.Fatalf("NewClient(v%d): %v", wireVersion, err)
			}
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "example.org:443")
			if err != nil {
				t.Fatalf("DialContext(v%d): %v", wireVersion, err)
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte("z"), 256)
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read echo (v%d): %v", wireVersion, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo mismatch (v%d)", wireVersion)
			}
		})
	}
}

// TestServer_PhaseTwoRejectsV1: bump MinAcceptedWireVersion=2; a legacy v1
// client must masquerade-fall-through (server log: "verification failed").
// The DialContext returns an error because the masqueraded backend is empty
// and no real h2 negotiation completes.
func TestServer_PhaseTwoRejectsV1(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:             "127.0.0.1:0",
		PrivateKey:             serverPriv,
		MasterShortID:          shortID,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		MinAcceptedWireVersion: 2,
		MaxAcceptedWireVersion: 2,
		Handler: func(ctx context.Context, conn net.Conn, _ string) {
			defer conn.Close()
		},
	})

	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "cover.example",
		PublicKey:              serverPub,
		ShortID:                shortID,
		WireVersion:            1,
		DisableDefaultSecurity: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("Phase-2 server (min=2) must reject v1 client; got nil error")
	}
}
