package fragpoc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestCountedConnDecrementsOpenConnsOnce verifies the open-connection counter
// (the [FRAGPOC-METRICS] open_conns field) is decremented exactly once when a
// wrapped server connection is closed, even if Close is called twice.
func TestCountedConnDecrementsOpenConnsOnce(t *testing.T) {
	c := &Client{}
	p1, p2 := net.Pipe()
	defer p2.Close()
	c.openConns.Add(1)
	cc := &countedConn{Conn: p1, client: c}
	if got := c.openConns.Load(); got != 1 {
		t.Fatalf("openConns before close = %d, want 1", got)
	}
	if err := cc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := c.openConns.Load(); got != 0 {
		t.Fatalf("openConns after close = %d, want 0", got)
	}
	_ = cc.Close()
	if got := c.openConns.Load(); got != 0 {
		t.Fatalf("openConns after double close = %d, want 0", got)
	}
}

func TestClientServerEcho(t *testing.T) {
	client, stop := startEchoServer(t, [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8})
	defer stop()

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", buf)
	}
}

func TestSecureClientServerEcho(t *testing.T) {
	client, stop := startEchoServer(t, [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8})
	defer stop()
	client.config.Secure = true

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", buf)
	}
}

func TestSecureOpenHidesDestination(t *testing.T) {
	shortID := [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	destination := "secret.example.invalid:443"
	captured := make(chan []byte, 1)
	client, err := NewClient(ClientConfig{
		ServerAddr: "unused:443",
		ShortID:    shortID,
		Secure:     true,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				var prefix [1 + ShortIDLen + 1]byte
				if _, err := io.ReadFull(serverConn, prefix[:]); err != nil {
					return
				}
				var hdr [secureNonceLen + 2]byte
				if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
					return
				}
				sealed := make([]byte, int(binary.BigEndian.Uint16(hdr[secureNonceLen:])))
				if _, err := io.ReadFull(serverConn, sealed); err != nil {
					return
				}
				raw := append(append([]byte{}, prefix[:]...), hdr[:]...)
				raw = append(raw, sealed...)
				captured <- raw

				staticKey := deriveSecureStaticKey(shortID)
				plain, _, err := readSecureBody(bytes.NewReader(append(hdr[:], sealed...)), staticKey, secureRequestAD(OpOpenSecure, shortID[:]), 512)
				if err != nil || string(plain) != destination+"\x00" {
					return
				}
				var sid [SIDLen]byte
				copy(sid[:], []byte("secure-open!"))
				resp := make([]byte, 1+SIDLen)
				resp[0] = AckOK
				copy(resp[1:], sid[:])
				_, _ = writeSecureBody(serverConn, staticKey, secureResponseAD(OpOpenSecure, shortID[:]), resp)
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	if _, err := client.open(context.Background(), destination); err != nil {
		t.Fatalf("open: %v", err)
	}
	req := <-captured
	if req[0] != secureWireOp(OpOpenSecure) {
		t.Fatalf("op = 0x%02x, want secure open wire op", req[0])
	}
	if req[1+ShortIDLen] != secureOpenMarker {
		t.Fatalf("secure open marker = 0x%02x, want 0x%02x", req[1+ShortIDLen], secureOpenMarker)
	}
	if bytes.Contains(req, []byte(destination)) {
		t.Fatalf("secure OPEN exposed destination in request bytes")
	}
}

func TestClientSplitsLargeWrite(t *testing.T) {
	client, stop := startEchoServer(t, [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8})
	defer stop()

	conn, err := client.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	want := bytes.Repeat([]byte("x"), MaxPayload*3+17)
	if n, err := conn.Write(want); err != nil || n != len(want) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(want))
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch")
	}
}

func TestClientServerUDPStream(t *testing.T) {
	shortID := [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		ShortID:         shortID,
		DownReadTimeout: 20 * time.Millisecond,
		Handler: func(ctx context.Context, conn net.Conn, destination string, gotShortID [ShortIDLen]byte) {
			defer conn.Close()
			if destination != UDPDestinationPrefix+"8.8.8.8:53" {
				t.Errorf("destination = %q, want UDP-prefixed target", destination)
				return
			}
			pc := newUDPFramedPacketConn(conn, streamAddr{network: "udp", address: "8.8.8.8:53"})
			buf := make([]byte, 2048)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				t.Errorf("server UDP ReadFrom: %v", err)
				return
			}
			if string(buf[:n]) != "ping" {
				t.Errorf("server got %q, want ping", buf[:n])
				return
			}
			_, _ = pc.WriteTo([]byte("pong"), nil)
			time.Sleep(100 * time.Millisecond)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Serve(ctx, ln)
	}()
	client, err := NewClient(ClientConfig{
		ServerAddr:       ln.Addr().String(),
		ShortID:          shortID,
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	pc, err := client.DialUDP(context.Background(), "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("ping"), nil); err != nil {
		t.Fatalf("UDP WriteTo: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("UDP ReadFrom: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("got %q, want pong", buf[:n])
	}
	if addr == nil || addr.String() != "8.8.8.8:53" {
		t.Fatalf("addr = %v, want 8.8.8.8:53", addr)
	}
}

func TestOpenRejectsWrongShortID(t *testing.T) {
	client, stop := startEchoServer(t, [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8})
	defer stop()
	client.config.ShortID = [ShortIDLen]byte{8, 7, 6, 5, 4, 3, 2, 1}

	if _, err := client.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("DialContext with wrong shortid succeeded")
	}
}

func TestReadReordersDownChunks(t *testing.T) {
	conn := newManualConn()
	conn.downCh <- downResult{seq: 1, buf: []byte("world")}
	conn.downCh <- downResult{seq: 0, buf: []byte("hello ")}

	got := make([]byte, len("hello world"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want hello world", got)
	}
}

func TestReadHonorsEOFSequence(t *testing.T) {
	conn := newManualConn()
	conn.downCh <- downResult{seq: 1, eof: true}
	conn.downCh <- downResult{seq: 0, buf: []byte("ok")}

	var got [2]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got[:]) != "ok" {
		t.Fatalf("got %q, want ok", got)
	}
	if _, err := conn.Read(got[:]); err != io.EOF {
		t.Fatalf("Read after EOF = %v, want io.EOF", err)
	}
}

func TestServerReplaysUnackedDownFrame(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:         [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DownReadTimeout: 20 * time.Millisecond,
		Handler:         func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newBufferedPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &session{
		conn:         clientConn,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	go srv.downProducer(sess)
	go func() {
		_, _ = serverConn.Write([]byte("abc"))
	}()

	first := srv.nextDownResponse(sess, 0)
	if got := string(first[6:]); got != "abc" {
		t.Fatalf("first DOWN data = %q, want abc", got)
	}
	replay := srv.nextDownResponse(sess, 0)
	if binary.BigEndian.Uint32(replay[:4]) != 0 || string(replay[6:]) != "abc" {
		t.Fatalf("replay = seq %d data %q, want seq 0 abc", binary.BigEndian.Uint32(replay[:4]), replay[6:])
	}
}

func TestServerReplaysStableEOF(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:         [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DownReadTimeout: 20 * time.Millisecond,
		Handler:         func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newBufferedPipe()
	defer clientConn.Close()
	_ = serverConn.Close()
	sess := &session{
		conn:         clientConn,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	go srv.downProducer(sess)
	// Give producer time to read EOF and push to channel/replay.
	time.Sleep(50 * time.Millisecond)

	first := srv.nextDownResponse(sess, 0)
	replay := srv.nextDownResponse(sess, 0)
	if binary.BigEndian.Uint32(first[:4]) != 0 || binary.BigEndian.Uint16(first[4:6]) != 0xffff {
		t.Fatalf("first EOF frame = seq %d len 0x%x", binary.BigEndian.Uint32(first[:4]), binary.BigEndian.Uint16(first[4:6]))
	}
	if !bytes.Equal(first, replay) {
		t.Fatalf("EOF replay changed: first=%x replay=%x", first, replay)
	}
}

// TestParallelDownReturnsDistinctFrames verifies the core parallel-DOWN
// guarantee: when multiple DOWN handlers call nextDownResponse concurrently
// with the same ack, they each get a DIFFERENT frame from the producer
// channel, not duplicates from replay.
func TestParallelDownReturnsDistinctFrames(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:         [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DownReadTimeout: 500 * time.Millisecond,
		Handler:         func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newBufferedPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &session{
		conn:         clientConn,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	go srv.downProducer(sess)

	// Feed 4 distinct chunks into the upstream pipe so the producer has
	// data to distribute across parallel DOWN handlers.
	chunks := []string{"aaa", "bbb", "ccc", "ddd"}
	go func() {
		for _, c := range chunks {
			_, _ = serverConn.Write([]byte(c))
			time.Sleep(5 * time.Millisecond) // let producer read each
		}
	}()
	// Give producer time to read all chunks into frameCh.
	time.Sleep(100 * time.Millisecond)

	// Fire 4 parallel DOWNs with the SAME ack=0 (simulating parallel polls
	// before any data has been consumed by the client).
	const n = 4
	type result struct {
		seq  uint32
		data string
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			resp := srv.nextDownResponse(sess, 0)
			seq := binary.BigEndian.Uint32(resp[:4])
			dataLen := binary.BigEndian.Uint16(resp[4:6])
			var data string
			if dataLen != 0 && dataLen != 0xffff && len(resp) >= 6+int(dataLen) {
				data = string(resp[6 : 6+dataLen])
			}
			results <- result{seq: seq, data: data}
		}()
	}

	seqs := make(map[uint32]bool)
	for i := 0; i < n; i++ {
		r := <-results
		if seqs[r.seq] {
			t.Fatalf("duplicate seq %d (data=%q) — parallel DOWNs must return distinct frames", r.seq, r.data)
		}
		seqs[r.seq] = true
	}
	if len(seqs) != n {
		t.Fatalf("got %d distinct seqs, want %d — parallel DOWNs not distributing frames", len(seqs), n)
	}
}

// TestRetransmitUnderContinuousFlow verifies that if seq0 is "lost" (client
// keeps sending ack=0) while the producer streams data continuously, the
// server must return seq0 from replay within a bounded number of DOWN
// responses — not starve replay by always preferring channel data.
func TestRetransmitUnderContinuousFlow(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:         [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DownReadTimeout: 200 * time.Millisecond,
		Handler:         func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newBufferedPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &session{
		conn:         clientConn,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	go srv.downProducer(sess)

	// Feed 20 chunks continuously.
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = serverConn.Write([]byte(fmt.Sprintf("chunk%02d", i)))
			time.Sleep(5 * time.Millisecond)
		}
	}()
	time.Sleep(150 * time.Millisecond) // let producer fill channel

	// Simulate: seq0 was "lost" — client keeps sending ack=0.
	// First DOWN consumes seq0 from channel (this is the "lost" one).
	first := srv.nextDownResponse(sess, 0)
	firstSeq := binary.BigEndian.Uint32(first[:4])
	if firstSeq != 0 {
		t.Fatalf("first response seq=%d, want 0", firstSeq)
	}

	// Now seq0 is gone from channel but in replay ring.
	// Send sequential DOWNs with ack=0 (client stuck).
	// Server MUST return seq0 from replay within this budget.
	// Budget must exceed retransmitAfter (= MaxDownWindow) + 1 so the
	// stateful stale-ack counter has time to trigger retransmission.
	// Adding margin to avoid fragile boundary-condition passes.
	const budget = MaxDownWindow + 4
	gotSeq0 := false
	for i := 0; i < budget; i++ {
		resp := srv.nextDownResponse(sess, 0)
		seq := binary.BigEndian.Uint32(resp[:4])
		if seq == 0 {
			gotSeq0 = true
			break
		}
	}
	if !gotSeq0 {
		t.Fatalf("server did not retransmit seq0 within %d DOWNs — replay starvation", budget)
	}
}

// TestParallelDownBurstWithoutLoss verifies the normal no-loss case: when a
// burst of parallel DOWN polls arrives before the client advances ack, the
// server should spend the window on distinct new frames, not replay seq0 early.
// This is the counterpart to TestRetransmitUnderContinuousFlow — together they
// assert the two invariants: burst ≠ premature replay, loss ≠ starvation.
func TestParallelDownBurstWithoutLoss(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:         [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DownReadTimeout: 200 * time.Millisecond,
		Handler:         func(context.Context, net.Conn, string, [ShortIDLen]byte) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newBufferedPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &session{
		conn:         clientConn,
		frameCh:      make(chan downFrame, 16),
		producerDone: make(chan struct{}),
	}
	go srv.downProducer(sess)

	const n = MaxDownWindow

	// Fill producer with a full window of chunks — simulates a large download burst.
	for i := 0; i < n; i++ {
		if _, err := serverConn.Write([]byte(fmt.Sprintf("burst%02d", i))); err != nil {
			t.Fatalf("write burst chunk %d: %v", i, err)
		}
	}
	time.Sleep(100 * time.Millisecond) // let producer read all into frameCh

	// A full-window burst of sequential DOWNs with ack=0 (client hasn't
	// processed any yet).
	// All must return distinct seqs — no premature replay.
	seqs := make(map[uint32]bool, n)
	for i := 0; i < n; i++ {
		resp := srv.nextDownResponse(sess, 0)
		seq := binary.BigEndian.Uint32(resp[:4])
		if seqs[seq] {
			t.Fatalf("duplicate seq %d in no-loss burst after %d responses", seq, i+1)
		}
		seqs[seq] = true
	}
	if len(seqs) != n {
		t.Fatalf("got %d distinct seqs, want %d", len(seqs), n)
	}
}

// TestParallelDownWindowEchoesLargeStream verifies the real client loop:
// with DownWindow > 1, a larger stream is delivered in order instead of
// getting stuck behind replay/pending behavior.
func TestParallelDownWindowEchoesLargeStream(t *testing.T) {
	for _, downWindow := range []int{1, 10} {
		t.Run(fmt.Sprintf("down_window_%d", downWindow), func(t *testing.T) {
			testParallelDownWindowEchoesLargeStream(t, downWindow)
		})
	}
}

func testParallelDownWindowEchoesLargeStream(t *testing.T, downWindow int) {
	shortID := [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		ShortID:         shortID,
		DownReadTimeout: 20 * time.Millisecond,
		Handler: func(ctx context.Context, conn net.Conn, destination string, gotShortID [ShortIDLen]byte) {
			defer conn.Close()
			if destination != "example.com:80" {
				t.Errorf("destination = %q, want example.com:80", destination)
				return
			}
			if gotShortID != shortID {
				t.Errorf("shortid = %x, want %x", gotShortID, shortID)
				return
			}
			_, _ = io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ln.Close()
	go func() {
		_ = srv.Serve(ctx, ln)
	}()
	client, err := NewClient(ClientConfig{
		ServerAddr:       ln.Addr().String(),
		ShortID:          shortID,
		OperationTimeout: 2 * time.Second,
		Workers:          64,
		DownWindow:       downWindow,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	conn, err := client.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write payload: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull echo stream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("payload mismatch at byte %d: got %q want %q", i, got[i], payload[i])
			}
		}
	}
}

func TestWorkerCountCapsAtMax(t *testing.T) {
	if got := workerCount(MaxWorkers + 1); got != MaxWorkers {
		t.Fatalf("workerCount(MaxWorkers+1) = %d, want %d", got, MaxWorkers)
	}
}

func TestDownWorkerCountLeavesControlReserve(t *testing.T) {
	tests := []struct {
		workers int
		want    int
	}{
		{workers: 1, want: 1},
		{workers: 2, want: 1},
		{workers: 4, want: 2},
		{workers: 8, want: 4},
		{workers: 16, want: 12},
		{workers: 32, want: 24},
		{workers: 64, want: 52},
		{workers: 120, want: 96},
	}
	for _, tt := range tests {
		if got := downWorkerCount(tt.workers); got != tt.want {
			t.Fatalf("downWorkerCount(%d) = %d, want %d", tt.workers, got, tt.want)
		}
	}
}

func TestDownUsesSharedOperationToken(t *testing.T) {
	var dialed int32
	client := &Client{
		config: ClientConfig{
			Dialer: func(context.Context, string, string) (net.Conn, error) {
				atomic.AddInt32(&dialed, 1)
				return nil, errors.New("dial should be blocked by down token")
			},
		},
		maxPayload: MaxPayload,
		opTokens:   make(chan struct{}, 1),
		downTokens: make(chan struct{}, 1),
	}
	client.downTokens <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.down(ctx, [SIDLen]byte{1}, [32]byte{}, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("down error = %v, want context deadline", err)
	}
	if got := atomic.LoadInt32(&dialed); got != 0 {
		t.Fatalf("dialed %d time(s), want 0 while down token is exhausted", got)
	}
}

func TestSchedulerStartsIdleConnWithSingleDownPoll(t *testing.T) {
	var calls int32
	unblock := make(chan struct{})
	client, err := NewClient(ClientConfig{
		ServerAddr:       "unused:443",
		OperationTimeout: time.Second,
		Workers:          8,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			atomic.AddInt32(&calls, 1)
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				if _, err := readTestDownRequest(serverConn); err != nil {
					return
				}
				<-unblock
				_, _ = serverConn.Write(make([]byte, 6))
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	defer close(unblock)

	conn := &Conn{
		client:  client,
		sid:     [SIDLen]byte{1},
		downCh:  make(chan downResult, client.downWindow*2),
		errCh:   make(chan error, 1),
		done:    make(chan struct{}),
		pending: make(map[uint32][]byte),
	}
	defer conn.closeDone()
	conn.startDownWorkers()

	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("idle conn started %d DOWN polls, want 1", got)
	}
}

func TestDownWindowCountDefaults(t *testing.T) {
	// With configured=0, downWindowCount returns 1 (server default).
	for _, workers := range []int{1, 4, 8, 16, 64, 120} {
		if got := downWindowCount(workers, 0); got != 1 {
			t.Fatalf("downWindowCount(%d, 0) = %d, want 1", workers, got)
		}
	}
	// With configured > 0, respects the value capped at MaxDownWindow and downWorkers.
	if got := downWindowCount(64, 10); got != 10 {
		t.Fatalf("downWindowCount(64, 10) = %d, want 10", got)
	}
	if got := downWindowCount(64, MaxDownWindow+5); got != MaxDownWindow {
		t.Fatalf("downWindowCount(64, %d) = %d, want %d", MaxDownWindow+5, got, MaxDownWindow)
	}
}

func TestDefaultOperationTimeoutExceedsServerLongPoll(t *testing.T) {
	if operationTimeout(0) <= durationDefault(0, 15*time.Second) {
		t.Fatalf("default operation timeout must exceed server DOWN long-poll timeout")
	}
	if connectTimeout(0) >= operationTimeout(0) {
		t.Fatalf("default connect timeout should stay shorter than operation timeout")
	}
}

func TestScheduledDownPollConsumesOneOperationToken(t *testing.T) {
	client := &Client{
		config: ClientConfig{
			OperationTimeout: time.Second,
			Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, context.DeadlineExceeded
			},
		},
		maxPayload: maxPayload(0),
		opTokens:   make(chan struct{}, 1),
		serverHost: "127.0.0.1",
		serverPort: "1",
		downWindow: 1,
	}
	conn := &Conn{
		client:      client,
		downCh:      make(chan downResult, 2),
		errCh:       make(chan error, 1),
		done:        make(chan struct{}),
		pending:     make(map[uint32][]byte),
		schedWindow: 1,
	}

	if outcome := conn.runScheduledDownPoll(); outcome != downPollTransient {
		t.Fatalf("runScheduledDownPoll outcome = %v, want transient", outcome)
	}
	if got := len(client.opTokens); got != 0 {
		t.Fatalf("operation tokens held after scheduled DOWN = %d, want 0", got)
	}
}

func TestServerServeConnTimesOutIncompleteRequest(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ShortID:          [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		OperationTimeout: 20 * time.Millisecond,
		Handler: func(context.Context, net.Conn, string, [ShortIDLen]byte) {
			t.Fatal("handler should not run for incomplete OPEN")
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		srv.ServeConn(context.Background(), serverConn)
		close(done)
	}()
	if _, err := clientConn.Write([]byte{OpOpen}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeConn did not return after operation timeout")
	}
}

// readTestDownRequest reads one non-secure OpDown request frame from a test
// pipe: the fixed 1+SIDLen+4+2 header followed by the padding, whose length
// the client randomises per request (see downRequestPaddingLen).
func readTestDownRequest(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 1+SIDLen+4+2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	pad := make([]byte, int(binary.BigEndian.Uint16(hdr[1+SIDLen+4:])))
	if _, err := io.ReadFull(r, pad); err != nil {
		return nil, err
	}
	return append(hdr, pad...), nil
}

func TestDownRequestCarriesWarmupPaddingAndAck(t *testing.T) {
	var sid [SIDLen]byte
	copy(sid[:], []byte("abc123xyz789"))
	gotReq := make(chan []byte, 1)
	client, err := NewClient(ClientConfig{
		ServerAddr: "unused:443",
		ShortID:    [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				req, _ := readTestDownRequest(serverConn)
				gotReq <- req
				_, _ = serverConn.Write(make([]byte, 6))
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.down(context.Background(), sid, [32]byte{}, 7); err != nil {
		t.Fatalf("down: %v", err)
	}
	req := <-gotReq
	if req[0] != OpDown {
		t.Fatalf("op = %x, want %x", req[0], OpDown)
	}
	if !bytes.Equal(req[1:1+SIDLen], sid[:]) {
		t.Fatalf("sid mismatch")
	}
	if ack := binary.BigEndian.Uint32(req[1+SIDLen : 1+SIDLen+4]); ack != 7 {
		t.Fatalf("ack = %d, want 7", ack)
	}
	padLen := int(binary.BigEndian.Uint16(req[1+SIDLen+4 : 1+SIDLen+6]))
	if padLen < downRequestPadMin || padLen > downRequestPadMax {
		t.Fatalf("pad len = %d, want in [%d, %d]", padLen, downRequestPadMin, downRequestPadMax)
	}
	if len(req) != 1+SIDLen+4+2+padLen {
		t.Fatalf("DOWN request len = %d, want %d", len(req), 1+SIDLen+4+2+padLen)
	}
	if bytes.Count(req[1+SIDLen+6:], []byte{0}) == padLen {
		t.Fatalf("padding is all zero")
	}
}

func TestDownWorkerRetriesTransientTimeout(t *testing.T) {
	var sid [SIDLen]byte
	copy(sid[:], []byte("retrytimeout"))
	var calls int32
	client, err := NewClient(ClientConfig{
		ServerAddr:       "unused:443",
		OperationTimeout: time.Second,
		Workers:          2,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return nil, timeoutErr{}
			}
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				_, _ = readTestDownRequest(serverConn)
				resp := make([]byte, 8)
				binary.BigEndian.PutUint32(resp[:4], 0)
				binary.BigEndian.PutUint16(resp[4:6], 2)
				copy(resp[6:], []byte("ok"))
				_, _ = serverConn.Write(resp)
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	conn := &Conn{
		client:  client,
		sid:     sid,
		downCh:  make(chan downResult, client.downWindow*2),
		errCh:   make(chan error, 1),
		done:    make(chan struct{}),
		pending: make(map[uint32][]byte),
	}
	defer conn.closeDone()

	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q, want ok", got)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatalf("dial calls = %d, want at least 2", atomic.LoadInt32(&calls))
	}
}

func TestSchedulerLimitsConcurrentDownPolls(t *testing.T) {
	var active int32
	var maxActive int32
	unblock := make(chan struct{})
	client, err := NewClient(ClientConfig{
		ServerAddr:       "unused:443",
		OperationTimeout: time.Second,
		Workers:          8,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				if _, err := readTestDownRequest(serverConn); err != nil {
					return
				}
				now := atomic.AddInt32(&active, 1)
				for {
					seen := atomic.LoadInt32(&maxActive)
					if now <= seen || atomic.CompareAndSwapInt32(&maxActive, seen, now) {
						break
					}
				}
				<-unblock
				atomic.AddInt32(&active, -1)
				_, _ = serverConn.Write(make([]byte, 6))
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	for i := 0; i < 16; i++ {
		conn := &Conn{
			client:  client,
			sid:     [SIDLen]byte{byte(i + 1)},
			downCh:  make(chan downResult, client.downWindow*2),
			errCh:   make(chan error, 1),
			done:    make(chan struct{}),
			pending: make(map[uint32][]byte),
		}
		conn.startDownWorkers()
		defer conn.closeDone()
	}
	time.Sleep(100 * time.Millisecond)
	if got, want := atomic.LoadInt32(&maxActive), int32(client.downWorkers); got > want {
		t.Fatalf("max active DOWN polls = %d, want <= %d", got, want)
	}
	close(unblock)
}

func TestSchedulerBackpressuresFullDownBuffer(t *testing.T) {
	var calls int32
	client, err := NewClient(ClientConfig{
		ServerAddr:       "unused:443",
		OperationTimeout: time.Second,
		Workers:          2,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			atomic.AddInt32(&calls, 1)
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				if _, err := readTestDownRequest(serverConn); err != nil {
					return
				}
				resp := make([]byte, 8)
				binary.BigEndian.PutUint32(resp[:4], 2)
				binary.BigEndian.PutUint16(resp[4:6], 2)
				copy(resp[6:], []byte("ok"))
				_, _ = serverConn.Write(resp)
			}()
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn := &Conn{
		client:  client,
		sid:     [SIDLen]byte{1},
		downCh:  make(chan downResult, client.downWindow*2),
		errCh:   make(chan error, 1),
		done:    make(chan struct{}),
		pending: make(map[uint32][]byte),
	}
	defer conn.closeDone()
	for i := 0; i < cap(conn.downCh); i++ {
		conn.downCh <- downResult{seq: uint32(i), buf: []byte{byte(i)}}
	}
	conn.startDownWorkers()
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("dial calls while downCh full = %d, want 0", got)
	}

	<-conn.downCh
	deadline := time.After(500 * time.Millisecond)
	for atomic.LoadInt32(&calls) == 0 {
		select {
		case <-deadline:
			t.Fatal("scheduler did not resume after downCh had capacity")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestOpTokenLimitsConcurrentRequests(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr: "unused:443",
		ShortID:    [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Workers:    1,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.acquireOpToken(context.Background()); err != nil {
		t.Fatalf("first acquireOpToken: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := client.acquireOpToken(ctx); err == nil {
		t.Fatal("second acquireOpToken succeeded while token was held")
	}
	client.releaseOpToken(context.Background())
	if err := client.acquireOpToken(context.Background()); err != nil {
		t.Fatalf("acquireOpToken after release: %v", err)
	}
	client.releaseOpToken(context.Background())
}

func TestServerDialAddrCachesHostnameResolution(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr: "127.0.0.1:443",
		ShortID:    [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, err := client.serverDialAddr(context.Background()); err != nil || got != "127.0.0.1:443" {
		t.Fatalf("serverDialAddr literal = %q, %v; want 127.0.0.1:443, nil", got, err)
	}

	client, err = NewClient(ClientConfig{
		ServerAddr: "example.invalid:443",
		ShortID:    [ShortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8},
	})
	if err != nil {
		t.Fatalf("NewClient hostname: %v", err)
	}
	client.resolvedServerAddr = "203.0.113.7:443"
	if got, err := client.serverDialAddr(context.Background()); err != nil || got != "203.0.113.7:443" {
		t.Fatalf("serverDialAddr cached = %q, %v; want cached addr", got, err)
	}
}

func startEchoServer(t *testing.T, shortID [ShortIDLen]byte) (*Client, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		ShortID:         shortID,
		DownReadTimeout: 50 * time.Millisecond,
		Handler: func(ctx context.Context, conn net.Conn, destination string, gotShortID [ShortIDLen]byte) {
			defer conn.Close()
			if destination != "example.com:80" {
				t.Errorf("destination = %q, want example.com:80", destination)
			}
			if gotShortID != shortID {
				t.Errorf("shortid = %x, want %x", gotShortID, shortID)
			}
			_, _ = io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx, ln)
	}()
	client, err := NewClient(ClientConfig{
		ServerAddr:       ln.Addr().String(),
		ShortID:          shortID,
		OperationTimeout: time.Second,
	})
	if err != nil {
		cancel()
		_ = ln.Close()
		t.Fatalf("NewClient: %v", err)
	}
	return client, func() {
		cancel()
		_ = ln.Close()
	}
}

func newManualConn() *Conn {
	conn := &Conn{
		client:  &Client{},
		downCh:  make(chan downResult, 4),
		errCh:   make(chan error, 1),
		done:    make(chan struct{}),
		pending: make(map[uint32][]byte),
	}
	conn.downOnce.Do(func() {})
	return conn
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
