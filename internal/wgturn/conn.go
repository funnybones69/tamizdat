//go:build linux

package wgturn

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const (
	keepaliveInterval = 5 * time.Second
	handshakeTimeout  = 30 * time.Second
	readTimeout       = 90 * time.Second
	getconfWaitTime   = 5 * time.Minute
	readyWaitTime     = 10 * time.Minute
	dns               = "1.1.1.1"
	keepalive         = 25
)

// bufPool reuses 1600-byte buffers for packet proxying.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1600)
		return &b
	},
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

// handleConn processes a single DTLS client connection. It implements the
// GETCONF/READY/WAKEUP protocol and proxies WireGuard packets.
func (s *Server) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	atomic.AddInt64(&s.totalConns, 1)
	atomic.AddInt32(&s.activeConns, 1)
	defer atomic.AddInt32(&s.activeConns, -1)

	buf := make([]byte, 1600)
	clientConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	firstPacket := buf[:n]
	firstStr := string(firstPacket)

	// --- GETCONF protocol ---
	if strings.HasPrefix(firstStr, "GETCONF:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(firstStr, "GETCONF:")), "|")
		clientPort := "9000"
		deviceID := "unknown"
		password := ""
		if len(parts) > 0 {
			clientPort = parts[0]
		}
		if len(parts) > 1 {
			deviceID = parts[1]
		}
		if len(parts) > 2 {
			password = parts[2]
		}

		identity, denyReason := s.authenticateClient(ctx, deviceID, password)
		if denyReason != "" {
			clientConn.Write([]byte("DENIED:" + denyReason))
			log.Printf("[wgturn] denied (%s) from device %s", denyReason, deviceID)
			return
		}

		s.mu.Lock()
		dev, exists := s.devices[deviceID]
		if !exists {
			dev = &clientDevice{deviceID: deviceID, ip: s.getNextIP()}
			privB64, pubB64, keyErr := generateKeyPair()
			if keyErr == nil && dev.ip != "" {
				dev.privKey = privB64
				dev.pubKey = pubB64
				s.devices[deviceID] = dev
				s.saveDevices()
				pubHex, _ := b64ToHex(pubB64)
				s.wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.ip))
				log.Printf("[wgturn] new device %s (IP: %s)", deviceID, dev.ip)
			} else {
				dev = nil
			}
		}
		s.mu.Unlock()

		if dev != nil {
			// Keep the device IP -> authenticated Tamizdat user mapping beyond
			// this individual DTLS/GETCONF connection. A wgturn client may use
			// several worker connections for the same WireGuard device; removing
			// the identity when the control/worker connection closes makes later
			// decapsulated flows lose their user match and fall through to the
			// default outbound routing rule.
			s.setIdentityForIP(dev.ip, identity)
			conf := buildClientConfig(s.keys.serverPublic, dev.privKey, dev.ip, clientPort)
			clientConn.Write([]byte(conf))
		} else {
			clientConn.Write([]byte("NOCONF"))
			return
		}

		// Wait for the client to send the next message (WG handshake or READY).
		clientConn.SetReadDeadline(time.Now().Add(getconfWaitTime))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
		firstStr = string(firstPacket)
	}

	// --- READY handshake ---
	if firstStr == "READY" {
		clientConn.Write([]byte("READY_OK"))
		clientConn.SetReadDeadline(time.Now().Add(readyWaitTime))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	}

	// --- WireGuard proxy ---
	wgEndpoint := fmt.Sprintf("127.0.0.1:%d", s.cfg.WGPort)
	wgConn, err := net.Dial("udp", wgEndpoint)
	if err != nil {
		log.Printf("[wgturn] dial WG endpoint: %v", err)
		return
	}
	defer wgConn.Close()

	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}

	// Forward the first WireGuard packet.
	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

	var proxyWg sync.WaitGroup
	proxyWg.Add(3)

	// WAKEUP keepalive (prevents Android Doze from killing the connection).
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-ticker.C:
				if _, err := clientConn.Write([]byte("WAKEUP")); err != nil {
					return
				}
			}
		}
	}()

	// Client -> WireGuard.
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			clientConn.SetReadDeadline(time.Now().Add(readTimeout))
			nn, err := clientConn.Read(*b)
			if err != nil {
				return
			}
			if nn == 6 && string((*b)[:6]) == "WAKEUP" {
				continue
			}
			if _, err := wgConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	// WireGuard -> Client.
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			wgConn.SetReadDeadline(time.Now().Add(readTimeout))
			nn, err := wgConn.Read(*b)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if pctx.Err() != nil {
						return
					}
					continue
				}
				return
			}
			if _, err := clientConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	proxyWg.Wait()
}

func (s *Server) authenticateClient(ctx context.Context, deviceID, password string) (ClientIdentity, string) {
	if s.cfg.Password != "" && password == s.cfg.Password {
		return ClientIdentity{}, ""
	}
	if s.cfg.Authenticate != nil {
		identity, reason := s.cfg.Authenticate(ctx, deviceID, password)
		if reason == "" {
			return identity, ""
		}
		return ClientIdentity{}, reason
	}
	return ClientIdentity{}, "wrong_password"
}

// buildClientConfig generates the WireGuard client config sent over GETCONF.
func buildClientConfig(serverPublic, clientPrivate, clientIP, clientPort string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%s
PersistentKeepalive = %d`,
		clientPrivate, clientIP, dns, wgMTU,
		serverPublic, clientPort, keepalive,
	)
}

// addPeerToWG registers a client device as a WireGuard peer.
func addPeerToWG(wgDev *device.Device, pubKeyB64, ip string) error {
	pubHex, err := b64ToHex(pubKeyB64)
	if err != nil {
		return err
	}
	return wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, ip))
}
