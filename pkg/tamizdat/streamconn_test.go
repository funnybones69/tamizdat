package tamizdat

import (
	"io"
	"sync"
	"testing"
	"time"
)

type blockingReadWriteCloser struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingReadWriteCloser() *blockingReadWriteCloser {
	return &blockingReadWriteCloser{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (b *blockingReadWriteCloser) Read(p []byte) (int, error) {
	b.once.Do(func() {})
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *blockingReadWriteCloser) Write(p []byte) (int, error) {
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *blockingReadWriteCloser) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestStreamConnReadDeadlineClosesBlockedRead(t *testing.T) {
	rwc := newBlockingReadWriteCloser()
	sc := newStreamConn(rwc, nil, nil, "", nil, nil)
	defer sc.Close()

	done := make(chan error, 1)
	go func() {
		_, err := sc.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case <-rwc.started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read did not start")
	}

	if err := sc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil error after deadline closed rwc")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("deadline did not unblock a blocked Read")
	}

	if err := sc.readDeadline.wait(); err == nil {
		t.Fatal("future reads should observe timeout after read deadline expiry")
	}
}
