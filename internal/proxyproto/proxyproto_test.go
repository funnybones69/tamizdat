package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn backed by a bytes.Buffer for reads. Writes
// are accepted but ignored. Deadlines are no-ops (we don't exercise them).
type fakeConn struct {
	r io.Reader
}

func (f *fakeConn) Read(b []byte) (int, error)         { return f.r.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func newFake(b []byte) *fakeConn { return &fakeConn{r: bytes.NewReader(b)} }

// buildV2 assembles a v2 header. cmd: 0=LOCAL, 1=PROXY. fam: 0=UNSPEC,
// 1=INET, 2=INET6, 3=UNIX. proto: 0=UNSPEC, 1=STREAM, 2=DGRAM. addrBuf is
// the address block content (IPv4 = 12B, IPv6 = 36B).
func buildV2(cmd, fam, proto byte, addrBuf []byte) []byte {
	out := make([]byte, 0, 16+len(addrBuf))
	out = append(out, v2Signature...)
	out = append(out, 0x20|cmd)     // version 2 << 4 | cmd
	out = append(out, fam<<4|proto) // family << 4 | proto
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(addrBuf)))
	out = append(out, lenBuf[:]...)
	out = append(out, addrBuf...)
	return out
}

func TestV2_IPv4_Happy(t *testing.T) {
	addr := make([]byte, 12)
	copy(addr[0:4], net.ParseIP("203.0.113.42").To4())
	copy(addr[4:8], net.ParseIP("198.51.100.1").To4())
	binary.BigEndian.PutUint16(addr[8:10], 54321) // src port
	binary.BigEndian.PutUint16(addr[10:12], 443)  // dst port

	hdr := buildV2(1, 1, 1, addr)
	payload := append(hdr, []byte("subsequent-tls-bytes")...)

	real, r, err := ReadHeader(newFake(payload), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tcp, ok := real.(*net.TCPAddr)
	if !ok {
		t.Fatalf("real not *net.TCPAddr: %T", real)
	}
	if !tcp.IP.Equal(net.ParseIP("203.0.113.42")) {
		t.Fatalf("src IP = %v want 203.0.113.42", tcp.IP)
	}
	if tcp.Port != 54321 {
		t.Fatalf("src port = %d want 54321", tcp.Port)
	}
	leftover, _ := io.ReadAll(r)
	if string(leftover) != "subsequent-tls-bytes" {
		t.Fatalf("leftover = %q", leftover)
	}
}

func TestV2_IPv6_Happy(t *testing.T) {
	addr := make([]byte, 36)
	copy(addr[0:16], net.ParseIP("2001:db8::1").To16())
	copy(addr[16:32], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(addr[32:34], 54321)
	binary.BigEndian.PutUint16(addr[34:36], 443)

	hdr := buildV2(1, 2, 1, addr)
	real, _, err := ReadHeader(newFake(hdr), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tcp := real.(*net.TCPAddr)
	if !tcp.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("src IP = %v", tcp.IP)
	}
	if tcp.Port != 54321 {
		t.Fatalf("src port = %d", tcp.Port)
	}
}

func TestV2_LOCAL(t *testing.T) {
	hdr := buildV2(0, 0, 0, nil) // LOCAL + UNSPEC
	real, _, err := ReadHeader(newFake(hdr), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if real != nil {
		t.Fatalf("LOCAL must return nil real, got %v", real)
	}
}

func TestV2_TLV_Ignored(t *testing.T) {
	// IPv4 base + TLV (12 + 4 = 16 byte addr block).
	addr := make([]byte, 12+4)
	copy(addr[0:4], net.ParseIP("203.0.113.42").To4())
	copy(addr[4:8], net.ParseIP("198.51.100.1").To4())
	binary.BigEndian.PutUint16(addr[8:10], 54321)
	binary.BigEndian.PutUint16(addr[10:12], 443)
	// TLV: type=0x03 (PP2_TYPE_CRC32C), len=1, value=0xab
	addr[12] = 0x03
	addr[13] = 0x00
	addr[14] = 0x01
	addr[15] = 0xab

	hdr := buildV2(1, 1, 1, addr)
	real, _, err := ReadHeader(newFake(hdr), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tcp := real.(*net.TCPAddr)
	if !tcp.IP.Equal(net.ParseIP("203.0.113.42")) {
		t.Fatalf("src IP = %v", tcp.IP)
	}
}

func TestV2_BadVersion(t *testing.T) {
	hdr := buildV2(1, 1, 1, make([]byte, 12))
	hdr[12] = 0x31 // version 3 << 4 | cmd 1
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestV2_ShortAddrBlock(t *testing.T) {
	hdr := buildV2(1, 1, 1, make([]byte, 8)) // claim INET but only 8 bytes
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestV1_TCP4_Happy(t *testing.T) {
	hdr := []byte("PROXY TCP4 203.0.113.42 198.51.100.1 54321 443\r\n")
	payload := append(hdr, []byte("subsequent")...)
	real, r, err := ReadHeader(newFake(payload), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tcp := real.(*net.TCPAddr)
	if !tcp.IP.Equal(net.ParseIP("203.0.113.42")) {
		t.Fatalf("src IP = %v", tcp.IP)
	}
	if tcp.Port != 54321 {
		t.Fatalf("src port = %d", tcp.Port)
	}
	leftover, _ := io.ReadAll(r)
	if string(leftover) != "subsequent" {
		t.Fatalf("leftover = %q", leftover)
	}
}

func TestV1_TCP6_Happy(t *testing.T) {
	hdr := []byte("PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n")
	real, _, err := ReadHeader(newFake(hdr), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tcp := real.(*net.TCPAddr)
	if !tcp.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("src IP = %v", tcp.IP)
	}
}

func TestV1_UNKNOWN(t *testing.T) {
	hdr := []byte("PROXY UNKNOWN\r\n")
	real, _, err := ReadHeader(newFake(hdr), 0)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if real != nil {
		t.Fatalf("UNKNOWN must return nil real, got %v", real)
	}
}

func TestV1_BadProto(t *testing.T) {
	hdr := []byte("PROXY UDP4 1.2.3.4 5.6.7.8 100 200\r\n")
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestV1_NoCRLF(t *testing.T) {
	hdr := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 100 200\n") // missing \r
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestNotPROXY_RawTLS(t *testing.T) {
	// Raw TLS hello starts with 0x16 0x03 0x01 ...
	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x7c, 0x03, 0x03}
	tlsHello = append(tlsHello, bytes.Repeat([]byte{0x42}, 100)...)

	real, r, err := ReadHeader(newFake(tlsHello), 0)
	if !errors.Is(err, ErrNotPROXY) {
		t.Fatalf("want ErrNotPROXY, got %v", err)
	}
	if real != nil {
		t.Fatalf("real must be nil, got %v", real)
	}
	// Reader should still let us read the original bytes (no consumption).
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, tlsHello) {
		t.Fatalf("reader lost bytes; got len %d want %d", len(got), len(tlsHello))
	}
}

func TestConn_RemoteAddr(t *testing.T) {
	real := &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1234}
	w := Wrap(&fakeConn{}, real, bytes.NewReader([]byte("hi")))
	if w.RemoteAddr().String() != "8.8.8.8:1234" {
		t.Fatalf("RemoteAddr = %s", w.RemoteAddr())
	}
	w2 := Wrap(&fakeConn{}, nil, nil)
	if w2.RemoteAddr().String() != "127.0.0.1:0" {
		t.Fatalf("fallback RemoteAddr = %s", w2.RemoteAddr())
	}
}

func TestConn_ReadLeftover(t *testing.T) {
	w := Wrap(&fakeConn{}, nil, strings.NewReader("hello"))
	buf := make([]byte, 5)
	n, err := w.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("Read: n=%d err=%v", n, err)
	}
	if string(buf) != "hello" {
		t.Fatalf("Read = %q", buf)
	}
}

func TestParseCIDRs(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"127.0.0.1/32", 1},
		{"127.0.0.1", 1},
		{"127.0.0.1/32, 10.0.0.0/8", 2},
		{"::1", 1},
		{"::1/128, 2001:db8::/32", 2},
	}
	for _, c := range cases {
		got, err := ParseCIDRs(c.in)
		if err != nil {
			t.Errorf("ParseCIDRs(%q): %v", c.in, err)
			continue
		}
		if len(got) != c.want {
			t.Errorf("ParseCIDRs(%q): got %d nets, want %d", c.in, len(got), c.want)
		}
	}
	if _, err := ParseCIDRs("not-an-ip"); err == nil {
		t.Errorf("expected error on bad input")
	}
}

func TestIsTrusted(t *testing.T) {
	nets, _ := ParseCIDRs("127.0.0.1/32, 10.0.0.0/8, 2001:db8::/32")

	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", false},
		{"10.1.2.3", true},
		{"11.0.0.1", false},
		{"2001:db8::cafe", true},
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		got := IsTrusted(&net.TCPAddr{IP: ip}, nets)
		if got != c.want {
			t.Errorf("IsTrusted(%s) = %v want %v", c.ip, got, c.want)
		}
	}

	// Empty trust list = fail closed.
	if IsTrusted(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, nil) {
		t.Errorf("empty trust list must reject all")
	}
}

func TestV1_LineExceedsBufferRejected(t *testing.T) {
	hdr := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 100 200" + strings.Repeat("x", MaxHeaderSize*2))
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want oversized-line rejection", err)
	}
}

func TestV1_BadDestinationFields(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
		want string
	}{
		{
			name: "bad dst IP",
			hdr:  "PROXY TCP4 1.2.3.4 not-an-ip 100 200\r\n",
			want: "bad dst IP",
		},
		{
			name: "bad dst port",
			hdr:  "PROXY TCP4 1.2.3.4 5.6.7.8 100 99999\r\n",
			want: "bad dst port",
		},
		{
			name: "TCP4 non-IPv4 dst",
			hdr:  "PROXY TCP4 1.2.3.4 2001:db8::1 100 200\r\n",
			want: "non-IPv4 dst",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadHeader(newFake([]byte(tc.hdr)), 0)
			if err == nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestV2_DgramTransportRejected(t *testing.T) {
	addr := make([]byte, 12)
	copy(addr[0:4], net.ParseIP("203.0.113.42").To4())
	copy(addr[4:8], net.ParseIP("198.51.100.1").To4())
	binary.BigEndian.PutUint16(addr[8:10], 54321)
	binary.BigEndian.PutUint16(addr[10:12], 443)

	hdr := buildV2(1, 1, 2, addr)
	_, _, err := ReadHeader(newFake(hdr), 0)
	if err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	if !strings.Contains(err.Error(), "non-STREAM") {
		t.Fatalf("error = %v, want non-STREAM transport rejection", err)
	}
}
