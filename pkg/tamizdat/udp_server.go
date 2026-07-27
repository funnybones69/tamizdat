package tamizdat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// UDP tunnel server handler. Accepts CONNECT with Samizdat-Protocol: udp/1.
// Bridges length-prefixed UDP datagrams from the H2 stream to a single UDP
// target (the CONNECT authority) via a dedicated ephemeral net.UDPConn.

const (
	udpServerIdleTimeout = 90 * time.Second
	udpServerMaxDatagram = 65535
	// udpServerReadPoll is retained ONLY for the direct-UDP (*net.UDPConn)
	// path where SetReadDeadline cheaply yields a Timeout() error and we
	// continue the loop. It MUST NOT be used on udpFramedPacketConn (the
	// chain-hop outbound) because that implementation closes the underlying
	// H2 stream when the deadline elapses — killing the entire tunnel on a
	// 2s silence gap. We branch on the conn type at runtime (see the
	// upstream pump below) and only set deadlines on UDPConns.
	udpServerReadPoll = 2 * time.Second
)

func (s *Server) handleUDPCONNECT(w http.ResponseWriter, r *http.Request, destination string, identity authIdentity) {
	clientAddr := "-"
	if r != nil && r.RemoteAddr != "" {
		clientAddr = r.RemoteAddr
	}
	closedDst := destination
	closedClient := clientAddr
	defer func() {
		s.logShapeEvent(fmt.Sprintf("stream_close client=%s dst=%s proto=udp",
			closedClient, closedDst))
	}()
	// CRIT-0: validate destination + dial resolved IP -- defeats SSRF
	// (private/loopback/cloud-metadata) and DNS-rebinding TOCTOU.
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		http.Error(w, "bad destination", http.StatusBadRequest)
		return
	}
	target, err := ResolveAndValidateDestination(r.Context(), host, port)
	if err != nil {
		safeIntAdd(ssrfRejectedUDP, 1)
		s.logf("[samizdat-udp] rejected destination %s: %v", destination, err)
		http.Error(w, "destination rejected", http.StatusBadRequest)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		s.logf("[samizdat-udp] resolve %s: %v", destination, err)
		http.Error(w, "resolve failed", http.StatusBadGateway)
		return
	}

	// Routing-aware UDP dial (2026-05-11): previously this path bypassed
	// the routing engine entirely and always exited from the server's
	// local IP. That broke iPhone QUIC traffic that was supposed to
	// chain through a remote outbound (e.g. anarki user -> mirror) —
	// QUIC packets exited ru2 directly, hit RU geo-block, ChatGPT
	// failed. Now resolves outbound by routing rule, then dials UDP
	// via the outbound's DialPacket (direct = local socket, tamizdat =
	// upstream Samizdat-Protocol: udp/1 tunnel).
	udpPacket, outboundTag, err := s.dialUDPViaRouting(r.Context(), host, port, target, identity)
	if err != nil {
		s.recordOutboundDialFailure(outboundTag, "udp", err)
		s.logf("[samizdat-udp] dial %s outbound=%s: %v", destination, outboundTag, err)
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	defer udpPacket.Close()
	releaseUserRelayTrack := s.trackUserRelayStream(identity, "udp")
	defer releaseUserRelayTrack()
	releaseOutboundTrack := s.trackOutboundStream(outboundTag, "udp")
	defer releaseOutboundTrack()
	s.logShapeEvent(fmt.Sprintf("stream_route user=%s session=%s dst=%s outbound=%s pick=%q proto=udp",
		identity.UserID, identity.SessionID, destination, outboundTag, outboundTag))
	safeIntAdd(tunnelsUDPOpened, 1)
	defer safeIntAdd(tunnelsUDPClosed, 1)
	var flowBytes int64
	defer func() { observeFlowBytes(flowBytes) }()
	// Per-outbound + per-user byte tally — accumulated by the two pump
	// goroutines via atomic; flushed once at function exit. Same pattern as
	// the TCP path (proxyBidirectionalCounted in server.go) so accounting
	// matches. Per-user attribution is critical for QUIC-heavy clients
	// (iPhone YouTube etc.) — before 2026-05-13 we were only crediting
	// per-outbound, so the user gauges undercounted ~80% of typical video
	// traffic (the QUIC/UDP slice was invisible to the per-user accumulator).
	var udpUp, udpDown int64
	defer func() {
		if s.accounting == nil {
			return
		}
		if outboundTag != "" {
			s.accounting.AddOutbound(outboundTag, udpUp, udpDown)
		}
		if identity.UserID != "" && (udpUp != 0 || udpDown != 0) {
			s.accounting.Add(identity.UserID, identity.SessionID, udpUp, udpDown)
		}
	}()
	// Per-user token-bucket rate limiter (nil = unlimited). Shared with the
	// TCP path, so a user with 50 Mbps cap can't blow it via UDP either.
	rl := s.userRateLimiter(identity.UserID)

	// Send 200 OK to signal client the tunnel is ready.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	s.logf("[samizdat-udp] OPEN %s", destination)

	// Bidirectional pump:
	//   downstream: H2 stream -> UDP socket (write to target)
	//   upstream:   UDP socket -> H2 stream (write framed responses to client)
	//
	// Both directions reset an idle timer; whichever idles for udpServerIdleTimeout
	// closes the tunnel. HIGH-3: when ctx is cancelled, udpConn.Close() in the
	// watchdog wakes any in-flight ReadFromUDP immediately rather than waiting
	// for the next deadline poll.
	idleResetCh := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Idle watchdog — closes udpPacket on idle/cancel to unblock ReadFrom.
	go func() {
		t := time.NewTimer(udpServerIdleTimeout)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = udpPacket.Close()
				return
			case <-idleResetCh:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(udpServerIdleTimeout)
			case <-t.C:
				s.logf("[samizdat-udp] IDLE_CLOSE %s", destination)
				_ = udpPacket.Close()
				cancel()
				return
			}
		}
	}()

	// Downstream: client → H2 → UDP target (PacketConn.WriteTo(target))
	go func() {
		defer cancel()
		body := r.Body
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(body, hdr[:]); err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed") {
					s.logf("[samizdat-udp] dn-hdr %s: %v", destination, err)
				}
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if n == 0 {
				continue
			}
			if n > udpServerMaxDatagram {
				s.logf("[samizdat-udp] dn-oversize %s: %d", destination, n)
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(body, buf); err != nil {
				return
			}
			if rl != nil {
				_ = rl.WaitN(ctx, len(buf))
			}
			// FIX 2026-05-13 (AnyDesk-via-ru2-chain): no per-write deadline.
			// On the chain-hop path udpPacket is a *udpFramedPacketConn whose
			// SetWriteDeadline closes the underlying H2 stream when the
			// deadline elapses, which catastrophically tore down RDP/AnyDesk
			// tunnels on any brief flow-control stall. The watchdog +
			// ctx.Done() above already bound how long this goroutine lives;
			// a slow write just back-pressures the inbound H2 stream which
			// is the correct behaviour.
			if _, err := udpPacket.WriteTo(buf, udpAddr); err != nil {
				s.logf("[samizdat-udp] dn-write %s: %v", destination, err)
				return
			}
			atomic.AddInt64(&flowBytes, int64(len(buf)))
			atomic.AddInt64(&udpUp, int64(len(buf)))
			bytesClientToTarget.Add(int64(len(buf)))
			select {
			case idleResetCh <- struct{}{}:
			default:
			}
		}
	}()

	// Upstream: UDP target → H2 → client.
	//
	// FIX 2026-05-13 (AnyDesk-via-ru2-chain): only set ReadDeadline on
	// direct *net.UDPConn outbounds. For the chain-hop outbound (where
	// udpPacket is a *udpFramedPacketConn over H2), SetReadDeadline closes
	// the underlying H2 stream when the deadline fires — every 2 seconds
	// of upstream silence destroyed the tunnel, which is exactly the
	// AnyDesk symptom the operator reported. The watchdog goroutine above
	// closes udpPacket on ctx.Done(), which unblocks ReadFrom on both
	// conn types; the read-poll was redundant defense-in-depth.
	_, isRealUDP := udpPacket.(*net.UDPConn)
	flusher, _ := w.(http.Flusher)
	rbuf := make([]byte, udpServerMaxDatagram)
	var hdr [2]byte
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isRealUDP {
			_ = udpPacket.SetReadDeadline(time.Now().Add(udpServerReadPoll))
		}
		n, _, err := udpPacket.ReadFrom(rbuf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				s.logf("[samizdat-udp] up-read %s: %v", destination, err)
			}
			return
		}
		if n == 0 || n > udpServerMaxDatagram {
			continue
		}
		if rl != nil {
			_ = rl.WaitN(ctx, n)
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := w.Write(hdr[:]); err != nil {
			return
		}
		if _, err := w.Write(rbuf[:n]); err != nil {
			return
		}
		atomic.AddInt64(&flowBytes, int64(n))
		atomic.AddInt64(&udpDown, int64(n))
		bytesTargetToClient.Add(int64(n))
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case idleResetCh <- struct{}{}:
		default:
		}
	}
}

func (s *Server) handleFragPoCUDP(ctx context.Context, stream net.Conn, destination string, identity authIdentity) {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		s.logf("[fragpoc-udp] bad destination %s: %v", destination, err)
		return
	}
	target, err := ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		safeIntAdd(ssrfRejectedUDP, 1)
		s.logf("[fragpoc-udp] rejected destination %s: %v", destination, err)
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		s.logf("[fragpoc-udp] resolve %s: %v", destination, err)
		return
	}
	udpPacket, outboundTag, err := s.dialUDPViaRouting(ctx, host, port, target, identity)
	if err != nil {
		s.logf("[fragpoc-udp] dial %s outbound=%s: %v", destination, outboundTag, err)
		return
	}
	defer udpPacket.Close()
	s.logShapeEvent(fmt.Sprintf("stream_route user=%s session=%s dst=%s outbound=%s pick=%q proto=fragpoc-udp",
		identity.UserID, identity.SessionID, destination, outboundTag, outboundTag))
	safeIntAdd(tunnelsUDPOpened, 1)
	defer safeIntAdd(tunnelsUDPClosed, 1)

	var flowBytes int64
	defer func() { observeFlowBytes(flowBytes) }()
	var udpUp, udpDown int64
	defer func() {
		if s.accounting == nil {
			return
		}
		if outboundTag != "" {
			s.accounting.AddOutbound(outboundTag, udpUp, udpDown)
		}
		if identity.UserID != "" && (udpUp != 0 || udpDown != 0) {
			s.accounting.Add(identity.UserID, identity.SessionID, udpUp, udpDown)
		}
	}()
	rl := s.userRateLimiter(identity.UserID)

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer stream.Close()
	idleResetCh := make(chan struct{}, 8)
	go func() {
		t := time.NewTimer(udpServerIdleTimeout)
		defer t.Stop()
		for {
			select {
			case <-relayCtx.Done():
				_ = udpPacket.Close()
				_ = stream.Close()
				return
			case <-idleResetCh:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(udpServerIdleTimeout)
			case <-t.C:
				s.logf("[fragpoc-udp] IDLE_CLOSE %s", destination)
				_ = udpPacket.Close()
				_ = stream.Close()
				cancel()
				return
			}
		}
	}()

	go func() {
		defer cancel()
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(stream, hdr[:]); err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed") {
					s.logf("[fragpoc-udp] dn-hdr %s: %v", destination, err)
				}
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if n == 0 {
				continue
			}
			if n > udpServerMaxDatagram {
				s.logf("[fragpoc-udp] dn-oversize %s: %d", destination, n)
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(stream, buf); err != nil {
				return
			}
			if rl != nil {
				_ = rl.WaitN(relayCtx, len(buf))
			}
			if _, err := udpPacket.WriteTo(buf, udpAddr); err != nil {
				s.logf("[fragpoc-udp] dn-write %s: %v", destination, err)
				return
			}
			atomic.AddInt64(&flowBytes, int64(len(buf)))
			atomic.AddInt64(&udpUp, int64(len(buf)))
			bytesClientToTarget.Add(int64(len(buf)))
			select {
			case idleResetCh <- struct{}{}:
			default:
			}
		}
	}()

	_, isRealUDP := udpPacket.(*net.UDPConn)
	rbuf := make([]byte, udpServerMaxDatagram)
	var hdr [2]byte
	for {
		select {
		case <-relayCtx.Done():
			return
		default:
		}
		if isRealUDP {
			_ = udpPacket.SetReadDeadline(time.Now().Add(udpServerReadPoll))
		}
		n, _, err := udpPacket.ReadFrom(rbuf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				s.logf("[fragpoc-udp] up-read %s: %v", destination, err)
			}
			return
		}
		if n == 0 || n > udpServerMaxDatagram {
			continue
		}
		if rl != nil {
			_ = rl.WaitN(relayCtx, n)
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := stream.Write(hdr[:]); err != nil {
			return
		}
		if _, err := stream.Write(rbuf[:n]); err != nil {
			return
		}
		atomic.AddInt64(&flowBytes, int64(n))
		atomic.AddInt64(&udpDown, int64(n))
		bytesTargetToClient.Add(int64(n))
		select {
		case idleResetCh <- struct{}{}:
		default:
		}
	}
}
