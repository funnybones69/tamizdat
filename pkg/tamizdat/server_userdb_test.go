package tamizdat

import (
	"context"
	"database/sql"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/userdb"

	_ "modernc.org/sqlite"
)

// userDBTestEnv holds the artefacts a Phase 2 server-level test needs to
// drive a Server backed by a freshly-populated user table.
type userDBTestEnv struct {
	server       *Server
	listener     net.Listener
	serverAddr   string
	serverPubKey []byte
	masterID     [8]byte
	masterHex    string
	userID       string
	dbPath       string
}

// openTestUserDB opens the same SQLite DSN the production OpenSQLite uses
// (busy_timeout=5000 + journal_mode=WAL + foreign_keys=on). Tests use this
// directly to inspect / mutate the DB without an import cycle through
// internal/outbounds.
func openTestUserDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	return db
}

func setupUserDBServer(t *testing.T, expiresAt int64) (*userDBTestEnv, string) {
	t.Helper()
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	masterHex, err := userdb.GenerateMasterShortID()
	if err != nil {
		t.Fatalf("GenerateMasterShortID: %v", err)
	}
	masterBytes, err := hex.DecodeString(masterHex)
	if err != nil {
		t.Fatalf("decode master: %v", err)
	}
	var master [8]byte
	copy(master[:], masterBytes)
	certPEM, keyPEM := generateSelfSignedCert(t)

	dbPath := filepath.Join(t.TempDir(), "data.db")
	{
		db := openTestUserDB(t, dbPath)
		if err := userdb.EnsureSchema(db); err != nil {
			t.Fatalf("EnsureSchema: %v", err)
		}
		userID := "u-" + masterHex
		now := time.Now().Unix()
		var ex any
		if expiresAt > 0 {
			ex = expiresAt
		}
		_, err = db.Exec(`INSERT INTO users(id, name, master_shortid, outbound_tag, expires_at, created_at, updated_at)
            VALUES(?, 'alice', ?, 'direct', ?, ?, ?)`, userID, masterHex, ex, now, now)
		if err != nil {
			t.Fatalf("insert user: %v", err)
		}
		_ = db.Close()
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
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	echoAddr := echoLn.Addr().String()

	server, ln := startTestServer(t, ServerConfig{
		ListenAddr:              "127.0.0.1:0",
		PrivateKey:              serverPriv,
		MasterShortID:           master,
		CertPEM:                 certPEM,
		KeyPEM:                  keyPEM,
		MasqueradeDomain:        "",
		ServerDBPath:            dbPath,
		DisableOutboundRegistry: true,
		LegacyShortIDPath:       filepath.Join(t.TempDir(), "no-such-shortid.hex"),
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			target, err := net.DialTimeout("tcp", echoAddr, 5*time.Second)
			if err != nil {
				return
			}
			defer target.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
			<-done
		},
	})
	return &userDBTestEnv{
		server:       server,
		listener:     ln,
		serverAddr:   ln.Addr().String(),
		serverPubKey: serverPub,
		masterID:     master,
		masterHex:    masterHex,
		userID:       "u-" + masterHex,
		dbPath:       dbPath,
	}, echoAddr
}

func echoOnce(t *testing.T, client *Client, dst string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", dst)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

// TestUserAuth_MasterShortID: a client connecting with the user's
// master_shortid is identified, and a session row is created in user_sessions.
func TestUserAuth_MasterShortID(t *testing.T) {
	env, echoAddr := setupUserDBServer(t, 0)

	client, err := NewClient(ClientConfig{
		ServerAddr:       env.serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        env.serverPubKey,
		ShortID:          env.masterID,
		Fingerprint:      "chrome",
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	echoOnce(t, client, echoAddr, []byte("hello-master"))
	waitForSessionCount(t, env.dbPath, env.userID, 1, 2*time.Second)

	db := openTestUserDB(t, env.dbPath)
	defer db.Close()
	var poolIdx sql.NullInt64
	if err := db.QueryRow(`SELECT pool_index FROM user_sessions WHERE user_id=?`, env.userID).Scan(&poolIdx); err != nil {
		t.Fatalf("scan pool_index: %v", err)
	}
	if poolIdx.Valid {
		t.Fatalf("master connect should set pool_index=NULL; got %d", poolIdx.Int64)
	}
}

// TestUserAuth_ExpiredUser: an expired user completes the TLS+H2 handshake
// (Phase C iOS-notify pipeline, 2026-05-10) so they can fetch the config
// bundle with a NotificationEntry explaining why their app stopped working.
// Their CONNECT is refused inside H2 with HTTP 402. notification_pending=1
// is flipped on so the panel surfaces the expired state.
func TestUserAuth_ExpiredUser(t *testing.T) {
	expired := time.Now().Add(-1 * time.Hour).Unix()
	env, _ := setupUserDBServer(t, expired)

	client, err := NewClient(ClientConfig{
		ServerAddr:       env.serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        env.serverPubKey,
		ShortID:          env.masterID,
		Fingerprint:      "chrome",
		TCPFragmentation: false,
		ConnectTimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// CONNECT must fail because the H2 handler refuses with 402 for
	// DataPlaneBlocked identities. The TLS+H2 handshake itself succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatalf("expected expired-user CONNECT to fail with HTTP 402")
	}

	db := openTestUserDB(t, env.dbPath)
	defer db.Close()
	// notification_pending must be flipped on by the expired-user auth path.
	var notif int
	if err := db.QueryRow(`SELECT notification_pending FROM users WHERE id=?`, env.userID).Scan(&notif); err != nil {
		t.Fatalf("scan notification_pending: %v", err)
	}
	if notif != 1 {
		t.Fatalf("notification_pending=%d want 1 after expired auth", notif)
	}
	// Phase C: TLS+H2 handshake completed so we expect exactly one session
	// row (StartSession fires for the bundle-fetch path even though CONNECT
	// is refused).
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE user_id=?`, env.userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired user got %d session rows; expected 1 (bundle path)", n)
	}
}

// TestSharedURI_MultipleSessions: three simultaneous connects with the same
// master shortid produce three user_sessions rows with the SAME user_id.
func TestSharedURI_MultipleSessions(t *testing.T) {
	env, echoAddr := setupUserDBServer(t, 0)

	const N = 3
	clients := make([]*Client, N)
	conns := make([]net.Conn, N)
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
		for _, cl := range clients {
			if cl != nil {
				_ = cl.Close()
			}
		}
	}()
	for i := 0; i < N; i++ {
		c, err := NewClient(ClientConfig{
			ServerAddr:       env.serverAddr,
			ServerName:       "test.example.com",
			PublicKey:        env.serverPubKey,
			ShortID:          env.masterID,
			Fingerprint:      "chrome",
			TCPFragmentation: false,
		})
		if err != nil {
			t.Fatalf("NewClient[%d]: %v", i, err)
		}
		clients[i] = c
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := c.DialContext(ctx, "tcp", echoAddr)
		cancel()
		if err != nil {
			t.Fatalf("DialContext[%d]: %v", i, err)
		}
		conns[i] = conn
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("ReadFull[%d]: %v", i, err)
		}
	}

	waitForSessionCount(t, env.dbPath, env.userID, N, 3*time.Second)
}

func waitForSessionCount(t *testing.T, dbPath, userID string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got int
	for time.Now().Before(deadline) {
		db := openTestUserDB(t, dbPath)
		err := db.QueryRow(`SELECT COUNT(*) FROM user_sessions WHERE user_id=?`, userID).Scan(&got)
		_ = db.Close()
		if err == nil && got >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("waitForSessionCount user=%s want>=%d got %d", userID, want, got)
}
