package node

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// SocksOutbound forwards each Dial as a SOCKS5 CONNECT request to an upstream
// SOCKS5 proxy (e.g. another samizdat-node, ssh -D, etc.).
//
// Supported: NO AUTH (0x00) and USER/PASS (0x02).
// Unsupported: GSSAPI, SOCKS5 BIND, SOCKS5 UDP-ASSOCIATE.
type SocksOutbound struct {
	tag      string
	addr     string
	username string
	password string
	timeout  time.Duration
}

func NewSocksOutbound(tag string, raw json.RawMessage) (*SocksOutbound, error) {
	var s SocksOutSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("socks outbound %q settings: %w", tag, err)
		}
	}
	if s.Addr == "" {
		return nil, fmt.Errorf("socks outbound %q: addr required", tag)
	}
	return &SocksOutbound{
		tag:      tag,
		addr:     s.Addr,
		username: s.Username,
		password: s.Password,
		timeout:  10 * time.Second,
	}, nil
}

func (s *SocksOutbound) Tag() string { return s.tag }

func (s *SocksOutbound) Dial(ctx context.Context, req *Request) (net.Conn, error) {
	d := net.Dialer{Timeout: s.timeout}
	c, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream socks: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.timeout)
	}
	_ = c.SetDeadline(deadline)
	if err := s.handshake(c, req); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (s *SocksOutbound) Close() error { return nil }

func (s *SocksOutbound) handshake(c net.Conn, req *Request) error {
	// Greeting: VER NMETHODS METHODS
	methods := []byte{0x00}
	if s.username != "" || s.password != "" {
		methods = []byte{0x02}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(greet); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("upstream not SOCKS5 (ver=%d)", resp[0])
	}
	switch resp[1] {
	case 0x00:
		// no auth, ok
	case 0x02:
		if s.username == "" && s.password == "" {
			return fmt.Errorf("upstream wants USER/PASS but none configured")
		}
		// RFC 1929: VER ULEN UNAME PLEN PASSWD
		buf := []byte{0x01, byte(len(s.username))}
		buf = append(buf, s.username...)
		buf = append(buf, byte(len(s.password)))
		buf = append(buf, s.password...)
		if _, err := c.Write(buf); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(c, ar); err != nil {
			return err
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("upstream auth rejected (status=%d)", ar[1])
		}
	default:
		return fmt.Errorf("upstream rejected auth methods (selected=0x%02x)", resp[1])
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	host := req.TargetHost
	atyp, addrBytes, err := encodeSocksAddr(host)
	if err != nil {
		return err
	}
	out := []byte{0x05, 0x01, 0x00, atyp}
	out = append(out, addrBytes...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(req.TargetPort))
	out = append(out, pb...)
	if _, err := c.Write(out); err != nil {
		return err
	}
	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("upstream CONNECT failed (rep=%d)", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		if _, err := io.ReadFull(c, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0])+2)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.ReadFull(c, make([]byte, 16+2)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("upstream bad ATYP %d", hdr[3])
	}
	return nil
}

func encodeSocksAddr(host string) (atyp byte, body []byte, err error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return 0x01, v4, nil
		}
		return 0x04, ip.To16(), nil
	}
	if len(host) > 255 {
		return 0, nil, fmt.Errorf("hostname too long (%d)", len(host))
	}
	return 0x03, append([]byte{byte(len(host))}, []byte(strings.ToLower(host))...), nil
}

// itoa is a tiny helper to avoid pulling strconv into outbound_freedom.go
// for a single conversion. Kept package-private.
func itoa(n int) string { return strconv.Itoa(n) }
