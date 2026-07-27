//go:build linux

package wgturn

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBondFrameRoundTripAndValidation(t *testing.T) {
	payload := []byte("wg")
	encoded, err := encodeBondFrame(bondFrameData, 0x1234, 42, payload)
	if err != nil {
		t.Fatalf("encodeBondFrame: %v", err)
	}
	const golden = "545a423202051234000000000000002a7767"
	if got := hex.EncodeToString(encoded); got != golden {
		t.Fatalf("wire vector=%s want=%s", got, golden)
	}
	decoded, err := decodeBondFrame(encoded)
	if err != nil {
		t.Fatalf("decodeBondFrame: %v", err)
	}
	if decoded.Type != bondFrameData || decoded.Flags != 0x1234 || decoded.Sequence != 42 || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("decoded frame = %#v", decoded)
	}

	cases := map[string][]byte{
		"short":   encoded[:bondHeaderSize-1],
		"magic":   append([]byte(nil), encoded...),
		"version": append([]byte(nil), encoded...),
		"type":    append([]byte(nil), encoded...),
	}
	cases["magic"][0] = 'X'
	cases["version"][4] = 3
	cases["type"][5] = 99
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBondFrame(frame); err == nil {
				t.Fatal("decodeBondFrame accepted invalid frame")
			}
		})
	}
	if _, err := encodeBondFrame(bondFrameData, 0, 1, make([]byte, bondMaxDataPayload+1)); err == nil {
		t.Fatal("encodeBondFrame accepted oversized DATA")
	}
	if _, err := encodeBondFrame(bondFrameBind, 0, 0, make([]byte, bondMaxBindPayload+1)); err == nil {
		t.Fatal("encodeBondFrame accepted oversized BIND")
	}
}

func bindForTest(wantConfig bool, room, worker int) bondBind {
	return bondBind{
		DeviceID: "device-a", RunID: "0123456789abcdef", Token: "0123456789abcdef0123456789abcdef",
		Room: room, Worker: worker, LocalPort: json.RawMessage("9000"),
		WantConfig: wantConfig, Password: map[bool]string{true: "password"}[wantConfig],
	}
}

func TestBondBindValidation(t *testing.T) {
	bind := bindForTest(true, 0, 1)
	payload, err := json.Marshal(bind)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseBondBind(payload)
	if err != nil {
		t.Fatalf("parseBondBind: %v", err)
	}
	if port, err := got.localPortString(); err != nil || port != "9000" {
		t.Fatalf("local port = %q, %v", port, err)
	}

	join := bindForTest(false, 1, 2)
	join.Password = "must-not-leak-to-joiner"
	payload, _ = json.Marshal(join)
	if _, err := parseBondBind(payload); err == nil {
		t.Fatal("token-only join with password was accepted")
	}

	stringPort := bindForTest(false, 1, 2)
	stringPort.LocalPort = json.RawMessage(`"9001"`)
	payload, _ = json.Marshal(stringPort)
	parsed, err := parseBondBind(payload)
	if err != nil {
		t.Fatalf("string local_port: %v", err)
	}
	if port, _ := parsed.localPortString(); port != "9001" {
		t.Fatalf("string local_port = %q", port)
	}

	for name, mutate := range map[string]func(*bondBind){
		"room limit":        func(b *bondBind) { b.Room = bondMaxRooms },
		"worker zero":       func(b *bondBind) { b.Worker = 0 },
		"worker over limit": func(b *bondBind) { b.Worker = bondMaxWorkers + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bindForTest(false, 0, 1)
			mutate(&invalid)
			payload, _ := json.Marshal(invalid)
			if _, err := parseBondBind(payload); err == nil {
				t.Fatal("out-of-range BIND slot was accepted")
			}
		})
	}
	capable, err := encodeBondFrame(bondFrameBind, bondFlagLatency, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseBondBindFrame(capable); err != nil {
		t.Fatalf("capability BIND was rejected: %v", err)
	}
	legacy, err := encodeBondFrame(bondFrameBind, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseBondBindFrame(legacy); err == nil {
		t.Fatal("BIND without latency-lane capability was accepted")
	}
	unknown, err := encodeBondFrame(bondFrameBind, bondFlagLatency|0x8000, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseBondBindFrame(unknown); err == nil {
		t.Fatal("BIND with unknown capability flag was accepted")
	}
}

func payloadStrings(packets [][]byte) []string {
	out := make([]string, len(packets))
	for i, packet := range packets {
		out[i] = string(packet)
	}
	return out
}

func TestBondReorderInOrderGapTimeoutLateAndWindow(t *testing.T) {
	now := time.Unix(100, 0)
	r := newPacketReorder(30 * time.Millisecond)
	if got := r.push(1, []byte("1"), now); len(got) != 1 || string(got[0]) != "1" {
		t.Fatalf("sequence 1 = %v", payloadStrings(got))
	}
	if got := r.push(3, []byte("3"), now); len(got) != 0 {
		t.Fatalf("sequence 3 emitted early: %v", payloadStrings(got))
	}
	if got := payloadStrings(r.push(2, []byte("2"), now)); len(got) != 2 || got[0] != "2" || got[1] != "3" {
		t.Fatalf("1,3,2 reorder = %v", got)
	}
	_ = r.push(2, []byte("late"), now)
	if r.late != 1 {
		t.Fatalf("late = %d, want 1", r.late)
	}

	timed := newPacketReorder(30 * time.Millisecond)
	_ = timed.push(2, []byte("2"), now)
	if got := timed.flushExpired(now.Add(29 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("gap flushed before hold: %v", payloadStrings(got))
	}
	if got := payloadStrings(timed.flushExpired(now.Add(30 * time.Millisecond))); len(got) != 1 || got[0] != "2" || timed.gaps != 1 {
		t.Fatalf("timeout flush = %v gaps=%d", got, timed.gaps)
	}

	duplicate := newPacketReorder(time.Second)
	_ = duplicate.push(2, []byte("2"), now)
	_ = duplicate.push(2, []byte("2-again"), now)
	if duplicate.duplicate != 1 || duplicate.buffered != 1 {
		t.Fatalf("duplicate=%d buffered=%d", duplicate.duplicate, duplicate.buffered)
	}

	pressure := newPacketReorder(time.Second)
	_ = pressure.push(2, []byte("2"), now)
	got := payloadStrings(pressure.push(300, []byte("300"), now))
	if len(got) != 2 || got[0] != "2" || got[1] != "300" || pressure.buffered > bondReorderWindow {
		t.Fatalf("window pressure output=%v buffered=%d", got, pressure.buffered)
	}
}

func TestBondLatencyLaneBypassesBulkGapUplink(t *testing.T) {
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bond := &serverBond{
		wgConn:         serverConn,
		ctx:            ctx,
		cancel:         cancel,
		rooms:          map[int]*bondRoom{0: {workers: make(map[int]*bondWorker)}},
		bulkReorder:    newPacketReorder(bondReorderHold),
		latencyReorder: newPacketReorder(bondReorderHold),
		wgWrite:        make(chan []byte, 4),
	}
	writerDone := make(chan struct{})
	go func() {
		bond.runWGWriter()
		close(writerDone)
	}()

	now := time.Unix(100, 0)
	bulkReady, valid := bond.acceptDataFrame(0, bondFrame{
		Type: bondFrameData, Sequence: 2,
		Payload: bytes.Repeat([]byte{'b'}, bondSmallPacketMax+1),
	}, now)
	if !valid || len(bulkReady) != 0 {
		t.Fatalf("bulk gap valid=%t ready=%d", valid, len(bulkReady))
	}
	if _, valid := bond.acceptDataFrame(0, bondFrame{Type: bondFrameData, Flags: 0x8000, Sequence: 1, Payload: []byte("invalid")}, now); valid {
		t.Fatal("unknown DATA lane flag was accepted")
	}

	start := time.Now()
	latencyReady, valid := bond.acceptDataFrame(0, bondFrame{
		Type: bondFrameData, Flags: bondFlagLatency, Sequence: 1, Payload: []byte("latency"),
	}, now)
	if !valid || len(latencyReady) != 1 || string(latencyReady[0]) != "latency" {
		t.Fatalf("latency valid=%t ready=%q", valid, latencyReady)
	}
	if elapsed := time.Since(start); elapsed >= bondReorderHold {
		t.Fatalf("latency lane waited %v (reorder hold %v)", elapsed, bondReorderHold)
	}
	bond.enqueueWG(latencyReady)
	_ = peerConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := peerConn.Read(buf)
	if err != nil || string(buf[:n]) != "latency" {
		t.Fatalf("WG latency packet=%q err=%v", buf[:n], err)
	}

	cancel()
	_ = serverConn.Close()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("WG writer did not stop")
	}
}

func TestBondLatencyLaneUsesIndependentDownlinkSequence(t *testing.T) {
	bond := &serverBond{}

	flags, sequence := bond.nextOutboundFrameMeta(bondSmallPacketMax + 1)
	if flags != 0 || sequence != 1 {
		t.Fatalf("bulk flags=%#x sequence=%d want 0/1", flags, sequence)
	}
	flags, sequence = bond.nextOutboundFrameMeta(bondSmallPacketMax)
	if flags != bondFlagLatency || sequence != 1 {
		t.Fatalf("latency flags=%#x sequence=%d want %#x/1", flags, sequence, bondFlagLatency)
	}
	flags, sequence = bond.nextOutboundFrameMeta(bondSmallPacketMax + 1)
	if flags != 0 || sequence != 2 {
		t.Fatalf("bulk2 flags=%#x sequence=%d want 0/2; latency packets must not create bulk gaps", flags, sequence)
	}
}

type bondAcquireResult struct {
	bond *serverBond
	typ  bondFrameType
	body []byte
}

func newBondTestServer(t *testing.T, authStarted, authRelease chan struct{}, authCalls, provisionCalls, dialCalls *atomic.Int32) (*Server, *[]net.Conn) {
	t.Helper()
	peers := &[]net.Conn{}
	s := &Server{
		cfg: Config{Authenticate: func(_ context.Context, deviceID, password string) (ClientIdentity, string) {
			authCalls.Add(1)
			if authStarted != nil {
				select {
				case authStarted <- struct{}{}:
				default:
				}
			}
			if authRelease != nil {
				<-authRelease
			}
			if deviceID != "device-a" || password != "password" {
				return ClientIdentity{}, "wrong_password"
			}
			return ClientIdentity{UserID: "user-a", SessionID: "session-a"}, ""
		}},
		devices: make(map[string]*clientDevice), identitiesByIP: make(map[string]ClientIdentity),
		bonds: make(map[bondKey]*serverBond), bondClaims: make(map[bondKey]*bondClaim),
	}
	s.bondProvision = func(localPort, deviceID string) (*clientDevice, string, error) {
		provisionCalls.Add(1)
		return &clientDevice{deviceID: deviceID, ip: "10.66.66.2"}, "config:" + localPort, nil
	}
	s.bondDialWG = func() (net.Conn, error) {
		dialCalls.Add(1)
		server, peer := net.Pipe()
		*peers = append(*peers, peer)
		return server, nil
	}
	t.Cleanup(func() {
		s.bondsMu.Lock()
		bonds := make([]*serverBond, 0, len(s.bonds))
		for _, bond := range s.bonds {
			bonds = append(bonds, bond)
		}
		s.bondsMu.Unlock()
		for _, bond := range bonds {
			s.removeBond(bond)
		}
		for _, peer := range *peers {
			_ = peer.Close()
		}
	})
	return s, peers
}

func TestBondAuthenticatedClaimTokenJoinWaitAndSharedSocket(t *testing.T) {
	var authCalls, provisionCalls, dialCalls atomic.Int32
	authStarted := make(chan struct{}, 1)
	authRelease := make(chan struct{})
	s, _ := newBondTestServer(t, authStarted, authRelease, &authCalls, &provisionCalls, &dialCalls)
	ctx := context.Background()

	if bond, typ, _ := s.acquireBond(ctx, bindForTest(false, 1, 1)); bond != nil || typ != bondFrameBindWait {
		t.Fatalf("early join = bond %p type %d, want WAIT", bond, typ)
	}

	claimResult := make(chan bondAcquireResult, 1)
	go func() {
		bond, typ, body := s.acquireBond(ctx, bindForTest(true, 0, 1))
		claimResult <- bondAcquireResult{bond: bond, typ: typ, body: body}
	}()
	<-authStarted
	if bond, typ, _ := s.acquireBond(ctx, bindForTest(false, 1, 1)); bond != nil || typ != bondFrameBindWait {
		t.Fatalf("join during auth = bond %p type %d, want WAIT", bond, typ)
	}
	if bond, typ, _ := s.acquireBond(ctx, bindForTest(true, 0, 1)); bond != nil || typ != bondFrameBindWait {
		t.Fatalf("second claimant during auth = bond %p type %d, want WAIT", bond, typ)
	}
	close(authRelease)
	created := <-claimResult
	if created.bond == nil || created.typ != bondFrameBindConfig || string(created.body) != "config:9000" {
		t.Fatalf("claim result = %#v", created)
	}

	joined, typ, _ := s.acquireBond(ctx, bindForTest(false, 1, 1))
	if joined != created.bond || typ != bondFrameBindOK {
		t.Fatalf("token join bond=%p type=%d", joined, typ)
	}
	if retry, retryType, _ := s.acquireBond(ctx, bindForTest(true, 0, 1)); retry != created.bond || retryType != bondFrameBindConfig {
		t.Fatalf("claimant retry bond=%p type=%d", retry, retryType)
	}
	if recovered, recoveredType, body := s.acquireBond(ctx, bindForTest(true, 2, 2)); recovered != created.bond || recoveredType != bondFrameBindConfig || string(body) != "config:9000" {
		t.Fatalf("config recovery bond=%p type=%d body=%q", recovered, recoveredType, body)
	}
	badToken := bindForTest(false, 1, 2)
	badToken.Token = "wrong-token"
	if bond, typ, _ := s.acquireBond(ctx, badToken); bond != nil || typ != bondFrameError {
		t.Fatalf("bad-token join bond=%p type=%d", bond, typ)
	}
	if authCalls.Load() != 1 || provisionCalls.Load() != 1 || dialCalls.Load() != 1 {
		t.Fatalf("calls auth=%d provision=%d dial=%d, want 1/1/1", authCalls.Load(), provisionCalls.Load(), dialCalls.Load())
	}
}

func TestBondFailedSetupClosesIdentityAndShutdownRejectsNewClaims(t *testing.T) {
	var authCalls, provisionCalls, dialCalls, identityDone atomic.Int32
	s, _ := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	s.cfg.OnIdentityDone = func(identity ClientIdentity) {
		if identity.SessionID == "session-a" {
			identityDone.Add(1)
		}
	}
	s.bondDialWG = func() (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("dial failed")
	}
	if bond, typ, body := s.acquireBond(context.Background(), bindForTest(true, 0, 1)); bond != nil || typ != bondFrameError || string(body) != "wg_unavailable" {
		t.Fatalf("failed setup bond=%p type=%d body=%q", bond, typ, body)
	}
	if identityDone.Load() != 1 {
		t.Fatalf("identity cleanup calls=%d want=1", identityDone.Load())
	}

	s.bondClosed.Store(true)
	beforeAuth := authCalls.Load()
	closedBind := bindForTest(true, 1, 1)
	closedBind.RunID = "run-shutdown-0001"
	if bond, typ, body := s.acquireBond(context.Background(), closedBind); bond != nil || typ != bondFrameError || string(body) != "server_shutdown" {
		t.Fatalf("shutdown claim bond=%p type=%d body=%q", bond, typ, body)
	}
	if authCalls.Load() != beforeAuth {
		t.Fatal("shutdown claim reached authenticator")
	}
}

func TestBondShutdownClearsInflightClaimBeforeWGDial(t *testing.T) {
	var authCalls, provisionCalls, dialCalls, identityDone atomic.Int32
	authStarted := make(chan struct{}, 1)
	authRelease := make(chan struct{})
	s, _ := newBondTestServer(t, authStarted, authRelease, &authCalls, &provisionCalls, &dialCalls)
	s.cfg.OnIdentityDone = func(ClientIdentity) { identityDone.Add(1) }
	result := make(chan bondAcquireResult, 1)
	go func() {
		bond, typ, body := s.acquireBond(context.Background(), bindForTest(true, 0, 1))
		result <- bondAcquireResult{bond: bond, typ: typ, body: body}
	}()
	<-authStarted
	s.Shutdown()
	close(authRelease)
	got := <-result
	if got.bond != nil || got.typ != bondFrameError || string(got.body) != "server_shutdown" {
		t.Fatalf("shutdown result bond=%p type=%d body=%q", got.bond, got.typ, got.body)
	}
	if dialCalls.Load() != 0 || provisionCalls.Load() != 0 {
		t.Fatalf("shutdown raced into provision/dial: provision=%d dial=%d", provisionCalls.Load(), dialCalls.Load())
	}
	if identityDone.Load() != 1 {
		t.Fatalf("shutdown identity callbacks=%d want=1", identityDone.Load())
	}
	s.bondsMu.Lock()
	claims, bonds := len(s.bondClaims), len(s.bonds)
	s.bondsMu.Unlock()
	if claims != 0 || bonds != 0 {
		t.Fatalf("shutdown state claims=%d bonds=%d", claims, bonds)
	}
}

type countedBondConn struct {
	net.Conn
	active       *atomic.Int32
	closeStarted chan struct{}
	closeRelease <-chan struct{}
	once         sync.Once
	closeErr     error
}

func (c *countedBondConn) Close() error {
	c.once.Do(func() {
		if c.closeStarted != nil {
			close(c.closeStarted)
		}
		if c.closeRelease != nil {
			<-c.closeRelease
		}
		c.closeErr = c.Conn.Close()
		c.active.Add(-1)
	})
	return c.closeErr
}

func updateAtomicMax(max *atomic.Int32, value int32) {
	for {
		old := max.Load()
		if value <= old || max.CompareAndSwap(old, value) {
			return
		}
	}
}

func TestBondDifferentRunWaitsForWGSocketClosure(t *testing.T) {
	var authCalls, provisionCalls, dialCalls, identityDone atomic.Int32
	var activeSockets, maxActiveSockets atomic.Int32
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	var releaseClose sync.Once
	releaseOldClose := func() { releaseClose.Do(func() { close(closeRelease) }) }
	s, peers := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	t.Cleanup(releaseOldClose)
	s.cfg.OnIdentityDone = func(ClientIdentity) { identityDone.Add(1) }
	s.bondDialWG = func() (net.Conn, error) {
		dialCalls.Add(1)
		server, peer := net.Pipe()
		*peers = append(*peers, peer)
		active := activeSockets.Add(1)
		updateAtomicMax(&maxActiveSockets, active)
		counted := &countedBondConn{Conn: server, active: &activeSockets}
		if dialCalls.Load() == 1 {
			counted.closeStarted = closeStarted
			counted.closeRelease = closeRelease
		}
		return counted, nil
	}

	runA := bindForTest(true, 0, 1)
	runA.RunID = "run-000000000001"
	runA.Token = "token-000000000000000000000000001"
	bondA, typ, _ := s.acquireBond(context.Background(), runA)
	if bondA == nil || typ != bondFrameBindConfig {
		t.Fatalf("create run A bond=%p type=%d", bondA, typ)
	}

	workerServer, workerClient := net.Pipe()
	defer workerClient.Close()
	joinA := runA
	joinA.WantConfig = false
	joinA.Password = ""
	joinA.Worker = 1
	workerA := bondA.addWorker(context.Background(), joinA, workerServer)
	workerDone := make(chan struct{})
	go func() {
		bondA.runWorker(workerA)
		close(workerDone)
	}()
	data, _ := encodeBondFrame(bondFrameData, 0, 1, []byte("run-a-uplink"))
	if _, err := workerClient.Write(data); err != nil {
		t.Fatal(err)
	}
	_ = (*peers)[0].SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := (*peers)[0].Read(buf)
	if err != nil || string(buf[:n]) != "run-a-uplink" {
		t.Fatalf("run A WG packet=%q err=%v", buf[:n], err)
	}

	runB := bindForTest(true, 1, 1)
	runB.RunID = "run-000000000002"
	runB.Token = "token-000000000000000000000000002"
	type acquireResult struct {
		bond *serverBond
		typ  bondFrameType
		body []byte
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		bond, typ, body := s.acquireBond(context.Background(), runB)
		acquired <- acquireResult{bond: bond, typ: typ, body: body}
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old WG socket close did not start")
	}
	if activeSockets.Load() != 1 || dialCalls.Load() != 1 {
		t.Fatalf("socket overlap while close blocked: active=%d dials=%d", activeSockets.Load(), dialCalls.Load())
	}
	select {
	case result := <-acquired:
		t.Fatalf("replacement completed before old socket closed: bond=%p type=%d body=%q", result.bond, result.typ, result.body)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOldClose()
	var result acquireResult
	select {
	case result = <-acquired:
	case <-time.After(time.Second):
		t.Fatal("replacement run did not finish after old socket closed")
	}
	if result.bond == nil || result.typ != bondFrameBindConfig {
		t.Fatalf("replacement response bond=%p type=%d body=%q", result.bond, result.typ, result.body)
	}
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("old run worker was not cancelled")
	}
	if got := activeSockets.Load(); got != 1 {
		t.Fatalf("active WG sockets after replacement=%d want=1", got)
	}
	if got := identityDone.Load(); got != 1 {
		t.Fatalf("retired identity callbacks=%d want=1", got)
	}

	if got := maxActiveSockets.Load(); got != 1 {
		t.Fatalf("max concurrent WG sockets=%d want=1", got)
	}
	s.removeBond(result.bond)
	if got := identityDone.Load(); got != 2 {
		t.Fatalf("identity callbacks after two retired runs=%d want=2", got)
	}
}

func TestBondWaitRetryStaysOnSameConnection(t *testing.T) {
	var authCalls, provisionCalls, dialCalls atomic.Int32
	s, _ := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	join := bindForTest(false, 1, 20)
	key := bondKey{deviceID: join.DeviceID, runID: join.RunID}
	s.bondsMu.Lock()
	s.bondClaims[key] = &bondClaim{token: join.Token}
	s.bondsMu.Unlock()

	payload, err := json.Marshal(join)
	if err != nil {
		t.Fatal(err)
	}
	first, err := encodeBondFrame(bondFrameBind, bondFlagLatency, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleBondConn(context.Background(), serverConn, first)
	}()

	readResponse := func(want bondFrameType) {
		t.Helper()
		_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, bondHeaderSize+bondMaxBindPayload)
		n, readErr := clientConn.Read(buf)
		if readErr != nil {
			t.Fatalf("read response: %v", readErr)
		}
		frame, decodeErr := decodeBondFrame(buf[:n])
		if decodeErr != nil || frame.Type != want {
			t.Fatalf("response type=%d err=%v want=%d", frame.Type, decodeErr, want)
		}
	}
	readResponse(bondFrameBindWait)

	// Complete the competing claimant, then retry the identical BIND over the
	// same DTLS/net.Conn. The worker must receive BIND_OK without a redial.
	s.finishBondClaim(key, nil)
	claimant := bindForTest(true, 0, 1)
	bond, typ, _ := s.acquireBond(context.Background(), claimant)
	if bond == nil || typ != bondFrameBindConfig {
		t.Fatalf("claimant bond=%p type=%d", bond, typ)
	}
	_ = clientConn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := clientConn.Write(first); err != nil {
		t.Fatalf("retry BIND: %v", err)
	}
	readResponse(bondFrameBindOK)
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("same-connection BIND handler did not exit")
	}
}

func TestBondEmptyClaimCleanupAndWorkerInheritsBondCancellation(t *testing.T) {
	var authCalls, provisionCalls, dialCalls, identityDone atomic.Int32
	s, _ := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	s.cfg.OnIdentityDone = func(ClientIdentity) { identityDone.Add(1) }

	bond, typ, _ := s.acquireBond(context.Background(), bindForTest(true, 0, 1))
	if bond == nil || typ != bondFrameBindConfig {
		t.Fatalf("create bond=%p type=%d", bond, typ)
	}
	bond.mu.Lock()
	bond.cleanupGrace = 20 * time.Millisecond
	bond.mu.Unlock()
	bond.armEmptyCleanup() // replace the production grace timer for the test

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.bondsMu.Lock()
		_, exists := s.bonds[bond.key]
		s.bondsMu.Unlock()
		if !exists {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.bondsMu.Lock()
	_, exists := s.bonds[bond.key]
	s.bondsMu.Unlock()
	if exists {
		t.Fatal("empty authenticated bond was not cleaned up")
	}
	deadline = time.Now().Add(time.Second)
	for identityDone.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if identityDone.Load() != 1 {
		t.Fatalf("identity cleanup calls=%d want=1", identityDone.Load())
	}

	// A worker must be owned by bond.ctx, not just the server parent context.
	secondBind := bindForTest(true, 0, 1)
	secondBind.RunID = "run-worker-owner1"
	secondBind.Token = "token-worker-owner-000000000000001"
	second, secondType, _ := s.acquireBond(context.Background(), secondBind)
	if second == nil || secondType != bondFrameBindConfig {
		t.Fatalf("create second bond=%p type=%d", second, secondType)
	}
	serverConn, peerConn := net.Pipe()
	defer serverConn.Close()
	defer peerConn.Close()
	worker := second.addWorker(context.Background(), bindForTest(false, 1, 1), serverConn)
	second.cancel()
	select {
	case <-worker.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("worker did not inherit bond cancellation")
	}
}

func TestBondWorkerRotationAndFinalCleanup(t *testing.T) {
	var authCalls, provisionCalls, dialCalls atomic.Int32
	s, _ := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	bond, typ, _ := s.acquireBond(context.Background(), bindForTest(true, 0, 1))
	if bond == nil || typ != bondFrameBindConfig {
		t.Fatalf("create bond=%p type=%d", bond, typ)
	}
	bond.cleanupGrace = 20 * time.Millisecond

	firstConn, firstPeer := net.Pipe()
	defer firstConn.Close()
	defer firstPeer.Close()
	first := bond.addWorker(context.Background(), bindForTest(false, 1, 7), firstConn)
	secondConn, secondPeer := net.Pipe()
	defer secondConn.Close()
	defer secondPeer.Close()
	second := bond.addWorker(context.Background(), bindForTest(false, 1, 7), secondConn)
	select {
	case <-first.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("rotated worker was not cancelled")
	}
	bond.mu.Lock()
	workers := bond.workers
	bond.mu.Unlock()
	if workers != 1 {
		t.Fatalf("active workers after rotation=%d want=1", workers)
	}
	bond.removeWorker(first)
	bond.mu.Lock()
	workers = bond.workers
	bond.mu.Unlock()
	if workers != 1 {
		t.Fatalf("stale worker removal changed count to %d", workers)
	}
	bond.removeWorker(second)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.bondsMu.Lock()
		_, exists := s.bonds[bond.key]
		s.bondsMu.Unlock()
		if !exists {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("bond was not removed after final-worker grace")
}

func testSchedulerBond(primary int, roomWorkers map[int]int) *serverBond {
	bond := &serverBond{rooms: make(map[int]*bondRoom), primaryRoom: primary}
	for roomID, count := range roomWorkers {
		room := &bondRoom{workers: make(map[int]*bondWorker)}
		for workerID := 0; workerID < count; workerID++ {
			room.workers[workerID] = &bondWorker{room: roomID, worker: workerID, send: make(chan []byte, 8)}
			room.workerOrder = append(room.workerOrder, workerID)
		}
		bond.rooms[roomID] = room
		bond.roomOrder = append(bond.roomOrder, roomID)
	}
	sort.Ints(bond.roomOrder)
	return bond
}

func drainWorkerFrames(room *bondRoom) int {
	total := 0
	for _, worker := range room.workers {
		for {
			select {
			case <-worker.send:
				total++
			default:
				goto nextWorker
			}
		}
	nextWorker:
	}
	return total
}

func TestBondSchedulerRoomRRPrimaryFailoverAndWorkerRotation(t *testing.T) {
	bond := testSchedulerBond(1, map[int]int{0: 2, 1: 2, 2: 1})
	for i := 0; i < 6; i++ {
		if !bond.schedule([]byte{byte(i)}, bondSmallPacketMax+1) {
			t.Fatal("large packet was not scheduled")
		}
	}
	for roomID, want := range map[int]int{0: 2, 1: 2, 2: 2} {
		if got := drainWorkerFrames(bond.rooms[roomID]); got != want {
			t.Fatalf("room %d large packets=%d want=%d", roomID, got, want)
		}
	}

	for i := 0; i < 3; i++ {
		if !bond.schedule([]byte{byte(i)}, bondSmallPacketMax) {
			t.Fatal("small packet was not scheduled")
		}
	}
	if got := drainWorkerFrames(bond.rooms[1]); got != 3 {
		t.Fatalf("primary small packets=%d want=3", got)
	}
	if got := drainWorkerFrames(bond.rooms[0]) + drainWorkerFrames(bond.rooms[2]); got != 0 {
		t.Fatalf("small packets escaped healthy primary: %d", got)
	}

	for _, worker := range bond.rooms[1].workers {
		for len(worker.send) < cap(worker.send) {
			worker.send <- []byte("full")
		}
	}
	if !bond.schedule([]byte("failover"), 100) {
		t.Fatal("small packet did not fail over from saturated primary")
	}
	if got := drainWorkerFrames(bond.rooms[2]); got != 1 {
		t.Fatalf("failover packets in next room=%d want=1", got)
	}

	workers := testSchedulerBond(0, map[int]int{0: 2})
	for i := 0; i < 4; i++ {
		if !workers.schedule([]byte{byte(i)}, 1000) {
			t.Fatal("worker rotation schedule failed")
		}
	}
	for workerID, worker := range workers.rooms[0].workers {
		if got := len(worker.send); got != 2 {
			t.Fatalf("worker %d packets=%d want=2", workerID, got)
		}
	}
}

func TestBondHandleConnDataReachesOneSharedWGConn(t *testing.T) {
	var authCalls, provisionCalls, dialCalls atomic.Int32
	s, peers := newBondTestServer(t, nil, nil, &authCalls, &provisionCalls, &dialCalls)
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer clientConn.Close()
	go s.handleConn(ctx, serverConn)

	bindPayload, _ := json.Marshal(bindForTest(true, 0, 1))
	bindFrame, _ := encodeBondFrame(bondFrameBind, bondFlagLatency, 0, bindPayload)
	if _, err := clientConn.Write(bindFrame); err != nil {
		t.Fatalf("write BIND: %v", err)
	}
	responseBuf := make([]byte, bondHeaderSize+bondMaxBindPayload)
	n, err := clientConn.Read(responseBuf)
	if err != nil {
		t.Fatalf("read BIND_CONFIG: %v", err)
	}
	response, err := decodeBondFrame(responseBuf[:n])
	if err != nil || response.Type != bondFrameBindConfig || string(response.Payload) != "config:9000" {
		t.Fatalf("BIND response=%#v err=%v", response, err)
	}

	dataFrame, _ := encodeBondFrame(bondFrameData, 0, 1, []byte("encrypted-wg"))
	if _, err := clientConn.Write(dataFrame); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	if len(*peers) != 1 {
		t.Fatalf("WG sockets=%d want=1", len(*peers))
	}
	_ = (*peers)[0].SetReadDeadline(time.Now().Add(time.Second))
	wgPacket := make([]byte, 64)
	n, err = (*peers)[0].Read(wgPacket)
	if err != nil || string(wgPacket[:n]) != "encrypted-wg" {
		t.Fatalf("WG packet=%q err=%v", wgPacket[:n], err)
	}

	// The reverse direction must return through this same bond-owned WG socket,
	// framed with the server sequence space, rather than a last-roaming worker
	// endpoint.
	if _, err := (*peers)[0].Write([]byte("encrypted-downlink")); err != nil {
		t.Fatalf("write WG downlink: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	n, err = clientConn.Read(responseBuf)
	if err != nil {
		t.Fatalf("read downlink DATA: %v", err)
	}
	downlink, err := decodeBondFrame(responseBuf[:n])
	if err != nil || downlink.Type != bondFrameData || downlink.Flags != bondFlagLatency || downlink.Sequence != 1 || string(downlink.Payload) != "encrypted-downlink" {
		t.Fatalf("downlink=%#v err=%v", downlink, err)
	}
}

func TestLegacyPacketsAreNotBondFrames(t *testing.T) {
	legacy := []byte("GETCONF:9000|device|password")
	if isBondPacket(legacy) {
		t.Fatal("legacy GETCONF classified as Bond v2")
	}
	rawWG := []byte{1, 0, 0, 0, 99, 88, 77}
	if isBondPacket(rawWG) {
		t.Fatal("legacy raw WireGuard packet classified as Bond v2")
	}
	config := buildClientConfig("server-key", "client-key", "10.66.66.2", "9000")
	if !bytes.Contains([]byte(config), []byte("Endpoint = 127.0.0.1:9000")) || !bytes.Contains([]byte(config), []byte("MTU = 1280")) {
		t.Fatalf("legacy config changed unexpectedly: %q", config)
	}
}
