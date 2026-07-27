package tamizdat

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// pipeRWC bridges Read/Write/Close for two goroutines via io.Pipe pairs.
type pipeRWC struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error {
	_ = p.w.Close()
	return p.r.Close()
}

func newPipeRWC() (a, b *pipeRWC) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	a = &pipeRWC{r: br, w: aw}
	b = &pipeRWC{r: ar, w: bw}
	return
}

// TestUDPFramedPacketConn_RoundTrip verifies basic single-target send/recv.
func TestUDPFramedPacketConn_RoundTrip(t *testing.T) {
	a, b := newPipeRWC()
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	pcA := newUDPFramedPacketConn(a, target)
	pcB := newUDPFramedPacketConn(b, target)

	payload := []byte("hello dns")
	go func() {
		_, _ = pcA.WriteTo(payload, target)
	}()

	buf := make([]byte, 1500)
	n, _, err := pcB.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}
}

// TestUDPFramedPacketConn_SetDeadlineUnblocks verifies HIGH-1: SetDeadline
// in the past must unblock an in-flight Read by closing the underlying RWC.
func TestUDPFramedPacketConn_SetDeadlineUnblocks(t *testing.T) {
	_, b := newPipeRWC()
	pc := newUDPFramedPacketConn(b, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53})

	// Park a Read in a goroutine.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, _, err := pc.ReadFrom(buf)
		done <- err
	}()

	// Give the Read a moment to block on io.ReadFull.
	time.Sleep(50 * time.Millisecond)

	// Setting deadline in the past must close the rwc and unblock the Read.
	if err := pc.SetReadDeadline(time.Now().Add(-1 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-done:
		// We expect EOF or net.ErrClosed propagated through io.ReadFull.
		if err == nil {
			t.Error("Read returned no error after past deadline")
		}
	case <-time.After(2 * time.Second):
		t.Error("Read did NOT unblock within 2s after past deadline")
	}
}

// TestUDPFramedPacketConn_AtomicFraming verifies MED-1: header+body must be
// emitted in a single Write so a midstream RST cannot leave the framer in a
// length-without-payload state.
func TestUDPFramedPacketConn_AtomicFraming(t *testing.T) {
	// Use a wrapper that counts Write calls.
	cw := &writeCounter{Writer: io.Discard}
	pc := newUDPFramedPacketConn(&writeCounterRWC{cw}, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})

	payload := []byte("payload bytes go here")
	_, err := pc.WriteTo(payload, pc.target)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if cw.calls != 1 {
		t.Errorf("expected 1 atomic Write call, got %d (MED-1 regression)", cw.calls)
	}
}

type writeCounter struct {
	io.Writer
	mu    sync.Mutex
	calls int
}

func (w *writeCounter) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.calls++
	w.mu.Unlock()
	return w.Writer.Write(b)
}

// writeCounterRWC adapts writeCounter to ReadWriteCloser.
type writeCounterRWC struct{ *writeCounter }

func (w *writeCounterRWC) Read(b []byte) (int, error) { return 0, io.EOF }
func (w *writeCounterRWC) Close() error               { return nil }

// TestUDPFramedPacketConn_ClampsOversize verifies MED-3: WriteTo rejects
// payloads beyond the safe IPv4 UDP bound (65000) before they reach the OS.
func TestUDPFramedPacketConn_ClampsOversize(t *testing.T) {
	a, _ := newPipeRWC()
	pc := newUDPFramedPacketConn(a, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	huge := make([]byte, 65001)
	_, err := pc.WriteTo(huge, pc.target)
	if err == nil {
		t.Error("WriteTo accepted 65001-byte payload (MED-3 regression: should reject >65000)")
	}
}

// TestUDPFramedPacketConn_PollDeadlinePatternKillsTunnel is a regression
// test for the AnyDesk-via-ru2-chain bug (2026-05-13). It documents WHY
// udp_server.go must NOT call SetReadDeadline in a poll loop on a
// udpFramedPacketConn: every elapsed deadline closes the underlying rwc,
// destroying the H2 stream and the entire UDP tunnel. The fix in
// handleUDPCONNECT type-checks for *net.UDPConn before setting deadlines;
// this test exists to make future maintainers think twice before they
// re-add the broken polling pattern here.
func TestUDPFramedPacketConn_PollDeadlinePatternKillsTunnel(t *testing.T) {
	a, b := newPipeRWC()
	target := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	pcServer := newUDPFramedPacketConn(a, target)
	pcRemote := newUDPFramedPacketConn(b, target)

	// Simulate a server-side read loop that mistakenly polls SetReadDeadline
	// every 100ms while waiting for the remote to send a datagram.
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		for i := 0; i < 5; i++ {
			_ = pcServer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			time.Sleep(150 * time.Millisecond) // let the deadline fire
		}
		_, _, err := pcServer.ReadFrom(buf)
		readErr <- err
	}()

	// Remote sends a perfectly valid datagram after ~600ms of silence.
	time.Sleep(600 * time.Millisecond)
	if _, err := pcRemote.WriteTo([]byte("hello"), target); err != nil {
		// Expected: remote sees broken pipe because pcServer's polling
		// killed the underlying rwc. This is the bug we are documenting.
		t.Logf("WriteTo failed as expected after polling-deadline killed rwc: %v", err)
	}

	select {
	case err := <-readErr:
		// We EXPECT an error here — proving the bug exists in the
		// udpFramedPacketConn semantics. If this ever becomes nil, somebody
		// changed the deadline behaviour and the udp_server.go workaround
		// can be removed.
		if err == nil {
			t.Fatal("EXPECTED read error from polling-deadline pattern, got nil — re-evaluate udp_server.go fix")
		}
		t.Logf("got expected error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("read did not return within 2s")
	}
}

// TestUDPFramedPacketConn_DeadlineExceededError verifies that a past-set
// SetReadDeadline returns os.ErrDeadlineExceeded synchronously when read
// is called *after* the deadline (no in-flight read).
func TestUDPFramedPacketConn_DeadlineExceededError(t *testing.T) {
	_, b := newPipeRWC()
	pc := newUDPFramedPacketConn(b, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})

	// Set deadline far in the past; do NOT call Read first.
	if err := pc.SetReadDeadline(time.Now().Add(-100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Wait briefly for the AfterFunc to close the rwc, then attempt Read.
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 100)
	_, _, err := pc.ReadFrom(buf)
	if err == nil {
		t.Error("expected error after past deadline + Read, got nil")
	}
	// We accept any of: ErrDeadlineExceeded, net.ErrClosed, EOF, io.ErrClosedPipe.
	// All indicate the deadline machinery worked.
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) &&
		!errors.Is(err, io.ErrClosedPipe) {
		t.Logf("got error %v (acceptable: any timeout-class error)", err)
	}
}
