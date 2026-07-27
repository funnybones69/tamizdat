package svcipc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTripUsesLittleEndianLength(t *testing.T) {
	payload := json.RawMessage(`{"config_uri":"tamizdat://example","pool_variant":"v2"}`)
	want := Frame{ID: 42, Type: TypeRequest, Method: MethodConnect, Payload: payload}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	wire := buf.Bytes()
	if len(wire) < 4 {
		t.Fatalf("short wire frame: %d bytes", len(wire))
	}
	bodyLen := binary.LittleEndian.Uint32(wire[:4])
	if int(bodyLen) != len(wire)-4 {
		t.Fatalf("length prefix=%d body=%d", bodyLen, len(wire)-4)
	}
	got, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.ID != want.ID || got.Type != want.Type || got.Method != want.Method || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round-trip mismatch:\nwant=%+v\n got=%+v", want, got)
	}
}

func TestReadFrameHandlesPayloadLargerThanScannerLimit(t *testing.T) {
	payload := json.RawMessage(`"` + strings.Repeat("x", 70*1024) + `"`)
	want := Frame{ID: 7, Type: TypeEvent, Method: EventLogLine, Payload: payload}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(NewFrameReader(&buf))
	if err != nil {
		t.Fatalf("ReadFrame large payload: %v", err)
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("payload mismatch: got %d want %d", len(got.Payload), len(payload))
	}
}

func TestWriteFrameRetriesShortWrites(t *testing.T) {
	want := Frame{ID: 99, Type: TypeEvent, Method: EventLogLine, Payload: json.RawMessage(`{"msg":"short"}`)}
	conn := &shortWriteConn{limit: 3}
	if err := WriteFrame(conn, want); err != nil {
		t.Fatalf("WriteFrame short-write conn: %v", err)
	}
	got, err := ReadFrame(NewFrameReader(bytes.NewReader(conn.buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadFrame after short writes: %v", err)
	}
	if got.ID != want.ID || got.Method != want.Method || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round-trip mismatch after short writes: want=%+v got=%+v", want, got)
	}
	if conn.writes < 3 {
		t.Fatalf("short-write path was not exercised; writes=%d", conn.writes)
	}
}

type shortWriteConn struct {
	buf    bytes.Buffer
	limit  int
	writes int
}

func (c *shortWriteConn) Read([]byte) (int, error) { return 0, nil }
func (c *shortWriteConn) Write(p []byte) (int, error) {
	c.writes++
	if c.limit > 0 && len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.buf.Write(p)
}
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
