// Package proxyproto parses HAProxy PROXY protocol headers (v1 text and v2
// binary) from inbound TCP connections so the tamizdat server can recover
// the real client IP/port when fronted by nginx or haproxy with
// `proxy_protocol on`.
//
// Protocol spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
//
// Security model:
//   - The PROXY header is only honoured when the connection arrives from a
//     trusted upstream (whitelist of CIDRs). Otherwise an attacker could
//     spoof their source IP, defeating per-IP rate limits and ban lists.
//   - The trust check happens in the caller (server.go); this package only
//     provides parsing primitives.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// v2Signature is the 12-byte fixed prefix of every PROXY v2 header.
//
//	\r \n \r \n \0 \r \n Q U I T \n
var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// v1Prefix is the 6-byte fixed prefix of every PROXY v1 header.
const v1Prefix = "PROXY "

// MaxHeaderSize bounds how many bytes ReadHeader will consume looking for a
// header. v2 max addr block is 216 bytes (AF_UNIX); add 16 for fixed header
// and a generous TLV margin. v1 max line is 107 bytes ("PROXY TCP6 <ip6>
// <ip6> <port> <port>\r\n").
const MaxHeaderSize = 536

// ErrNotPROXY indicates the connection's first bytes do not match either
// v1 or v2 signature. The caller may decide to treat the connection as a
// raw TLS hello (legacy / direct path).
var ErrNotPROXY = errors.New("proxyproto: not a PROXY protocol header")

// ErrMalformed indicates a header started with v1/v2 signature but the
// remainder failed parsing.
var ErrMalformed = errors.New("proxyproto: malformed header")

// ReadHeader peeks the first bytes of conn, parses a v1 or v2 PROXY header
// if present, and returns:
//
//   - real: the real client TCPAddr from the header. nil when the header
//     uses LOCAL command or AF_UNSPEC family (treat as proxy-internal
//     health check).
//   - reader: an io.Reader holding any leftover bytes (TLVs/buffered) that
//     must be drained before reading from conn directly. Always non-nil.
//   - err: ErrNotPROXY if neither v1 nor v2 signature matches; ErrMalformed
//     wrapped with a more specific message on parse failure; otherwise the
//     I/O error.
//
// The caller is expected to wrap conn in a Conn{Conn: original, real:
// real, reader: reader} so that subsequent code sees the corrected
// RemoteAddr() and reads bytes through the leftover-aware Reader.
func ReadHeader(conn net.Conn, timeout time.Duration) (real net.Addr, reader io.Reader, err error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	br := bufio.NewReaderSize(conn, MaxHeaderSize)

	sig, err := br.Peek(len(v2Signature))
	if err != nil {
		// Couldn't even peek 12 bytes — propagate I/O error. Caller closes.
		return nil, br, fmt.Errorf("peek signature: %w", err)
	}

	if bytes.Equal(sig, v2Signature) {
		return readV2(br)
	}
	if bytes.HasPrefix(sig, []byte(v1Prefix)) {
		return readV1(br)
	}
	// Looks like raw TLS hello (or arbitrary garbage). Hand the buffered
	// reader back so the caller can decide whether to fail or fall through.
	return nil, br, ErrNotPROXY
}

func readV2(br *bufio.Reader) (net.Addr, io.Reader, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, br, fmt.Errorf("%w: read v2 fixed header: %v", ErrMalformed, err)
	}

	versionCmd := hdr[12]
	if versionCmd>>4 != 2 {
		return nil, br, fmt.Errorf("%w: v2 wrong version: %d", ErrMalformed, versionCmd>>4)
	}
	cmd := versionCmd & 0x0F

	famProto := hdr[13]
	family := famProto >> 4
	proto := famProto & 0x0F
	// Tamizdat listens on TCP, so PROXY commands carrying IPv4/IPv6
	// addresses must describe a STREAM transport. LOCAL/UNSPEC remains
	// acceptable for proxy-internal health checks.
	if cmd == 1 && (family == 1 || family == 2) && proto != 1 {
		return nil, br, fmt.Errorf("%w: v2 PROXY with non-STREAM transport: %d", ErrMalformed, proto)
	}

	addrLen := binary.BigEndian.Uint16(hdr[14:16])
	if int(addrLen) > MaxHeaderSize-16 {
		return nil, br, fmt.Errorf("%w: v2 addr block too large: %d", ErrMalformed, addrLen)
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(br, addrBuf); err != nil {
		return nil, br, fmt.Errorf("%w: read v2 addr block: %v", ErrMalformed, err)
	}

	// LOCAL or AF_UNSPEC: ignore addresses, return nil real-addr. Caller
	// keeps original RemoteAddr (the upstream proxy IP) which is what we
	// want for health checks.
	if cmd == 0 || family == 0 {
		return nil, br, nil
	}
	if cmd != 1 {
		return nil, br, fmt.Errorf("%w: v2 unknown cmd: %d", ErrMalformed, cmd)
	}

	switch family {
	case 1: // AF_INET (IPv4)
		if len(addrBuf) < 12 {
			return nil, br, fmt.Errorf("%w: v2 INET addr too short: %d", ErrMalformed, len(addrBuf))
		}
		srcIP := make(net.IP, 4)
		copy(srcIP, addrBuf[0:4])
		srcPort := binary.BigEndian.Uint16(addrBuf[8:10])
		return &net.TCPAddr{IP: srcIP, Port: int(srcPort)}, br, nil
	case 2: // AF_INET6
		if len(addrBuf) < 36 {
			return nil, br, fmt.Errorf("%w: v2 INET6 addr too short: %d", ErrMalformed, len(addrBuf))
		}
		srcIP := make(net.IP, 16)
		copy(srcIP, addrBuf[0:16])
		srcPort := binary.BigEndian.Uint16(addrBuf[32:34])
		return &net.TCPAddr{IP: srcIP, Port: int(srcPort)}, br, nil
	case 3: // AF_UNIX
		// Tamizdat is TCP-only; treat as LOCAL and skip addr translation.
		return nil, br, nil
	default:
		return nil, br, fmt.Errorf("%w: v2 unsupported family: %d", ErrMalformed, family)
	}
}

func readV1(br *bufio.Reader) (net.Addr, io.Reader, error) {
	// v1 line is at most 107 bytes (TCP6 with full IPv6 strings + ports).
	// ReadSlice('\n') is bounded by br's buffer (MaxHeaderSize) and returns
	// bufio.ErrBufferFull instead of accumulating unbounded data.
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, br, fmt.Errorf("%w: v1 line exceeds %d bytes", ErrMalformed, MaxHeaderSize)
		}
		return nil, br, fmt.Errorf("%w: v1 read line: %v", ErrMalformed, err)
	}
	lineStr := string(line)
	if !strings.HasSuffix(lineStr, "\r\n") {
		return nil, br, fmt.Errorf("%w: v1 missing CRLF terminator", ErrMalformed)
	}
	lineStr = strings.TrimSuffix(lineStr, "\r\n")

	// "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443"
	if !strings.HasPrefix(lineStr, v1Prefix) {
		return nil, br, fmt.Errorf("%w: v1 missing prefix", ErrMalformed)
	}
	rest := strings.TrimPrefix(lineStr, v1Prefix)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return nil, br, fmt.Errorf("%w: v1 empty body", ErrMalformed)
	}

	proto := fields[0]
	if proto == "UNKNOWN" {
		// "PROXY UNKNOWN [...]" — don't translate addr.
		return nil, br, nil
	}
	if proto != "TCP4" && proto != "TCP6" {
		return nil, br, fmt.Errorf("%w: v1 unknown proto: %q", ErrMalformed, proto)
	}
	if len(fields) != 5 {
		return nil, br, fmt.Errorf("%w: v1 wrong field count: %d", ErrMalformed, len(fields))
	}

	srcIP := net.ParseIP(fields[1])
	if srcIP == nil {
		return nil, br, fmt.Errorf("%w: v1 bad src IP %q", ErrMalformed, fields[1])
	}
	dstIP := net.ParseIP(fields[2])
	if dstIP == nil {
		return nil, br, fmt.Errorf("%w: v1 bad dst IP %q", ErrMalformed, fields[2])
	}
	srcPort, err := strconv.ParseUint(fields[3], 10, 16)
	if err != nil {
		return nil, br, fmt.Errorf("%w: v1 bad src port %q: %v", ErrMalformed, fields[3], err)
	}
	if _, err := strconv.ParseUint(fields[4], 10, 16); err != nil {
		return nil, br, fmt.Errorf("%w: v1 bad dst port %q: %v", ErrMalformed, fields[4], err)
	}
	if proto == "TCP4" {
		srcIP = srcIP.To4()
		if srcIP == nil {
			return nil, br, fmt.Errorf("%w: v1 TCP4 with non-IPv4 src", ErrMalformed)
		}
		if dstIP.To4() == nil {
			return nil, br, fmt.Errorf("%w: v1 TCP4 with non-IPv4 dst", ErrMalformed)
		}
	}
	return &net.TCPAddr{IP: srcIP, Port: int(srcPort)}, br, nil
}

// Conn wraps a net.Conn, exposing the real client RemoteAddr() recovered
// from a PROXY header. Reads draw first from the leftover Reader (any
// bytes the bufio.Reader buffered past the header) before falling through
// to the underlying conn.
type Conn struct {
	net.Conn
	real   net.Addr
	reader io.Reader
}

// Wrap constructs a Conn. real may be nil — in which case RemoteAddr()
// falls back to the underlying conn (used for v2 LOCAL command). reader
// must be the io.Reader returned by ReadHeader.
func Wrap(c net.Conn, real net.Addr, reader io.Reader) *Conn {
	if reader == nil {
		reader = c
	}
	return &Conn{Conn: c, real: real, reader: reader}
}

// RemoteAddr returns the real client address from the PROXY header if
// present, otherwise the underlying conn's RemoteAddr (e.g. for LOCAL).
func (c *Conn) RemoteAddr() net.Addr {
	if c.real != nil {
		return c.real
	}
	return c.Conn.RemoteAddr()
}

// Read pulls from the leftover Reader first (bufio buffer holding bytes
// that came in the same packet as the PROXY header), then falls through.
func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// IsTrusted returns true if remote falls inside any of the supplied
// trusted CIDRs. Used by the caller to decide whether to call ReadHeader
// at all. If trusted is empty, returns false (fail closed).
func IsTrusted(remote net.Addr, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, n := range trusted {
		if n.Contains(tcp.IP) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a comma-separated CIDR list (e.g.
// "127.0.0.1/32,10.0.0.0/8") into []*net.IPNet. Empty string yields nil
// (no trusted upstream — fail closed at IsTrusted).
func ParseCIDRs(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Allow bare IP without /mask — promote to /32 or /128.
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("proxyproto: bad CIDR/IP %q", p)
			}
			if ip.To4() != nil {
				p = p + "/32"
			} else {
				p = p + "/128"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("proxyproto: bad CIDR %q: %w", p, err)
		}
		out = append(out, n)
	}
	return out, nil
}
