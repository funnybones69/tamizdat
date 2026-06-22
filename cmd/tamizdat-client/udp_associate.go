package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// handleUDPAssociate implements RFC 1928 §6/7 UDP ASSOCIATE.
//
// Wire format of inner UDP datagrams (between SOCKS5 client and our relay):
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
//
// RSV must be 0x0000, FRAG=0x00 (we don't fragment). ATYP: 0x01 IPv4, 0x03
// domain, 0x04 IPv6. DST.PORT big-endian.
//
// Lifecycle: while the SOCKS5 control TCP connection (c) is alive, the UDP
// relay socket is open. When c closes, we tear down all in-flight tunnel
// PacketConns and close the relay socket. Per RFC: control TCP closing ends
// the UDP association.
func handleUDPAssociate(c net.Conn, sc socksDialer, cfg socksConfig) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()

	bnd := relay.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0] = 0x05 // VER
	reply[1] = 0x00 // SUCCESS
	reply[2] = 0x00 // RSV
	reply[3] = 0x01 // ATYP IPv4
	copy(reply[4:8], bnd.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(bnd.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}
	if cfg.Debug {
		log.Printf("UDP ASSOCIATE relay open at %s", bnd)
	}

	// Map (innerDst → tunnel-PacketConn) so we don't open a new H2 stream
	// per packet for the same destination. Also track the SOCKS5 client's
	// observed UDP source so we know where to forward responses.
	type flow struct {
		pc        net.PacketConn // tunneled PacketConn from sc.DialUDP(dst)
		clientSrc *net.UDPAddr   // last observed SOCKS5-client UDP src
	}
	var (
		flowMu  sync.Mutex
		flows   = make(map[string]*flow)        // key = innerDst "host:port"
		clients = make(map[string]*net.UDPAddr) // for write-path back
	)
	closeAll := func() {
		flowMu.Lock()
		for _, f := range flows {
			_ = f.pc.Close()
		}
		flows = nil
		flowMu.Unlock()
	}
	defer closeAll()

	// Watcher: when control TCP closes (peer-side), tear everything down.
	go func() {
		buf := [1]byte{}
		_ = c.SetReadDeadline(time.Time{})
		_, _ = c.Read(buf[:]) // blocks until connection closes
		_ = relay.Close()
		closeAll()
	}()

	rbuf := make([]byte, 65535)
	for {
		n, src, err := relay.ReadFromUDP(rbuf)
		if err != nil {
			return
		}
		// Parse inner SOCKS5-UDP header.
		if n < 4 {
			continue
		}
		if rbuf[0] != 0 || rbuf[1] != 0 {
			continue // RSV nonzero
		}
		if rbuf[2] != 0 {
			continue // FRAG unsupported
		}
		var (
			dstHost string
			dstPort uint16
			dataOff int
		)
		switch rbuf[3] {
		case 0x01: // IPv4
			if n < 4+4+2 {
				continue
			}
			dstHost = net.IPv4(rbuf[4], rbuf[5], rbuf[6], rbuf[7]).String()
			dstPort = binary.BigEndian.Uint16(rbuf[8:10])
			dataOff = 10
		case 0x03: // domain
			if n < 5 {
				continue
			}
			dl := int(rbuf[4])
			if n < 5+dl+2 {
				continue
			}
			dstHost = string(rbuf[5 : 5+dl])
			dstPort = binary.BigEndian.Uint16(rbuf[5+dl : 5+dl+2])
			dataOff = 5 + dl + 2
		case 0x04: // IPv6
			if n < 4+16+2 {
				continue
			}
			dstHost = net.IP(rbuf[4:20]).String()
			dstPort = binary.BigEndian.Uint16(rbuf[20:22])
			dataOff = 22
		default:
			continue
		}
		dest := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))
		data := rbuf[dataOff:n]

		flowMu.Lock()
		f, ok := flows[dest]
		if !ok {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			pc, derr := sc.DialUDP(ctx, dest)
			cancel()
			if derr != nil {
				flowMu.Unlock()
				if cfg.Debug {
					log.Printf("UDP DialUDP %s: %v", dest, derr)
				}
				continue
			}
			f = &flow{pc: pc}
			flows[dest] = f
			// Spawn return-direction goroutine for this flow.
			go pumpUDPReturn(relay, pc, dest, src, &flowMu, clients, cfg)
		}
		// Track client-source per-dest (for return path).
		clients[dest] = src
		f.clientSrc = src
		flowMu.Unlock()
		// Write inner UDP datagram into the tamizdat tunnel.
		// PacketConn target ignored: tamizdat's UDP-CONNECT is single-target,
		// but the underlying udpFramedPacketConn rejects any non-nil address
		// whose String() differs from the CONNECT authority — pass nil to
		// signal "use the bound target" without triggering the single-target
		// guard. (Was previously passing &dummyAddr{} which got rejected with
		// 'tamizdat: udp tunnel is bound to a single target' and silently
		// dropped all SOCKS5-UDP datagrams.)
		if _, werr := f.pc.WriteTo(data, nil); werr != nil && cfg.Debug {
			log.Printf("UDP tunnel WriteTo %s: %v", dest, werr)
		}
	}
}

// pumpUDPReturn reads tunnel responses for one (dest) flow and forwards to
// the most-recent SOCKS5 client source observed for that flow, wrapped in
// the SOCKS5-UDP header.
func pumpUDPReturn(relay *net.UDPConn, pc net.PacketConn, dest string, initialClient *net.UDPAddr, mu *sync.Mutex, clients map[string]*net.UDPAddr, cfg socksConfig) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return
	}
	portN, _ := strconv.Atoi(portStr)
	headerATYPDst := buildSOCKS5UDPDstHeader(host, uint16(portN))

	buf := make([]byte, 65535)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if err != io.EOF && cfg.Debug {
				log.Printf("UDP tunnel read %s: %v", dest, err)
			}
			return
		}
		// Pick latest client-src for this dest.
		mu.Lock()
		client := initialClient
		if c, ok := clients[dest]; ok && c != nil {
			client = c
		}
		mu.Unlock()
		out := make([]byte, 0, len(headerATYPDst)+n)
		out = append(out, headerATYPDst...)
		out = append(out, buf[:n]...)
		_, _ = relay.WriteToUDP(out, client)
	}
}

// buildSOCKS5UDPDstHeader returns RSV(2)=0 FRAG(1)=0 ATYP+DST.ADDR+DST.PORT
// suitable to prepend to a return-direction UDP datagram.
func buildSOCKS5UDPDstHeader(host string, port uint16) []byte {
	hdr := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			hdr = append(hdr, 0x01)
			hdr = append(hdr, v4...)
		} else {
			hdr = append(hdr, 0x04)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		// Domain
		hdr = append(hdr, 0x03)
		hdr = append(hdr, byte(len(host)))
		hdr = append(hdr, []byte(host)...)
	}
	pp := make([]byte, 2)
	binary.BigEndian.PutUint16(pp, port)
	hdr = append(hdr, pp...)
	return hdr
}

// Avoid "imported and not used" if fmt is otherwise unreferenced when lint
// is strict about init-time use.
var _ = fmt.Sprintf
