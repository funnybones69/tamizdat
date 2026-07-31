package wgturnclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBondFrameEncodeDecodeValidation(t *testing.T) {
	encoded, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: 0x1234, Seq: 42, Payload: []byte("wg")})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	const golden = "545a423202051234000000000000002a7767"
	if got := hex.EncodeToString(encoded); got != golden {
		t.Fatalf("wire vector=%s want=%s", got, golden)
	}
	decoded, err := decodeBondFrame(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Type != bondFrameData || decoded.Flags != 0x1234 || decoded.Seq != 42 || string(decoded.Payload) != "wg" {
		t.Fatalf("decoded=%+v", decoded)
	}
	if _, err := decodeBondFrame([]byte("short")); err == nil {
		t.Fatal("expected short frame rejection")
	}
	bad := append([]byte(nil), encoded...)
	copy(bad[0:4], []byte("BAD!"))
	if _, err := decodeBondFrame(bad); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("expected bad magic error, got %v", err)
	}
	bad = append([]byte(nil), encoded...)
	bad[4] = 9
	if _, err := decodeBondFrame(bad); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected bad version error, got %v", err)
	}
	oversized := bytes.Repeat([]byte{'x'}, bondMaxBindJSON+1)
	if _, err := encodeBondFrame(bondFrame{Type: bondFrameBind, Payload: oversized}); err == nil {
		t.Fatal("expected oversized bind rejection")
	}
	if _, err := encodeBondFrame(bondFrame{Type: bondFrameData, Payload: bytes.Repeat([]byte{'x'}, bondMaxDataPayload+1)}); err == nil {
		t.Fatal("expected oversized DATA rejection")
	}
	if _, err := encodeBondFrame(bondFrame{Type: 99}); err == nil {
		t.Fatal("expected invalid frame type rejection")
	}
}

func TestBondBindConfigAndTokenOnlyJoin(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	seen := make(chan bondBindPayload, 1)
	go func() {
		buf := make([]byte, 8192)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		frame, err := decodeBondFrame(buf[:n])
		if err != nil {
			return
		}
		var bind bondBindPayload
		_ = json.Unmarshal(frame.Payload, &bind)
		seen <- bind
		resp, _ := bondFramePayload(bondFrameBindConfig, []byte("[Interface]\n"))
		_, _ = server.Write(resp)
	}()
	conf, err := RequestBondV2Bind(client, bondBindPayload{DeviceID: "dev", RunID: "run", Token: "token", Room: 1, Worker: 2, LocalPort: "9000", WantConfig: true, Password: "secret"}, true)
	if err != nil {
		t.Fatalf("bind config: %v", err)
	}
	if conf != "[Interface]\n" {
		t.Fatalf("conf=%q", conf)
	}
	bind := <-seen
	if !bind.WantConfig || bind.Password != "secret" || bind.Room != 1 || bind.Worker != 2 {
		t.Fatalf("bind payload=%+v", bind)
	}

	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	seen2 := make(chan bondBindPayload, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := server2.Read(buf)
		frame, _ := decodeBondFrame(buf[:n])
		var bind bondBindPayload
		_ = json.Unmarshal(frame.Payload, &bind)
		seen2 <- bind
		resp, _ := bondFramePayload(bondFrameBindOK, nil)
		_, _ = server2.Write(resp)
	}()
	if conf, err := RequestBondV2Bind(client2, bondBindPayload{DeviceID: "dev", RunID: "run", Token: "token", Room: 0, Worker: 3, Password: "must-not-send"}, false); err != nil || conf != "" {
		t.Fatalf("token bind conf=%q err=%v", conf, err)
	}
	if bind := <-seen2; bind.Password != "" || bind.WantConfig {
		t.Fatalf("token-only leaked password or want_config: %+v", bind)
	}
}

func TestBondBindWaitRetryAndExplicitErrors(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		buf := make([]byte, 8192)
		n, _ := server.Read(buf)
		_, _ = decodeBondFrame(buf[:n])
		wait, _ := bondFramePayload(bondFrameBindWait, nil)
		_, _ = server.Write(wait)
		n, _ = server.Read(buf)
		_, _ = decodeBondFrame(buf[:n])
		ok, _ := bondFramePayload(bondFrameBindOK, nil)
		_, _ = server.Write(ok)
	}()
	start := time.Now()
	if _, err := RequestBondV2Bind(client, bondBindPayload{DeviceID: "d", RunID: "r", Token: "t"}, false); err != nil {
		t.Fatalf("bind wait retry: %v", err)
	}
	if time.Since(start) < bondBindInitialBackoff {
		t.Fatal("BIND_WAIT did not back off")
	}

	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	go func() {
		buf := make([]byte, 8192)
		_, _ = server2.Read(buf)
		_, _ = server2.Write([]byte("legacy-response"))
	}()
	if _, err := RequestBondV2Bind(client2, bondBindPayload{DeviceID: "d", RunID: "r", Token: "t"}, false); err == nil || !strings.Contains(err.Error(), "BONDV2_NEGOTIATION") {
		t.Fatalf("expected explicit negotiation error, got %v", err)
	}
}

func TestBondBindRejectsServerWithoutLatencyLaneCapability(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		buf := make([]byte, 8192)
		_, _ = server.Read(buf)
		legacyOK, _ := encodeBondFrame(bondFrame{Type: bondFrameBindOK})
		_, _ = server.Write(legacyOK)
	}()
	_, err := RequestBondV2Bind(client, bondBindPayload{DeviceID: "d", RunID: "r", Token: "t"}, false)
	if err == nil || !strings.Contains(err.Error(), "BONDV2_NEGOTIATION") || !strings.Contains(err.Error(), "latency-lane") {
		t.Fatalf("expected latency-lane negotiation error, got %v", err)
	}
}

func TestBondSchedulerLargeRRSmallPinnedFailover(t *testing.T) {
	s := newBondScheduler()
	workers := []*WorkerSlot{
		{ID: 1, RoomID: 0, SendCh: make(chan []byte, 4)},
		{ID: 2, RoomID: 1, SendCh: make(chan []byte, 4)},
		{ID: 3, RoomID: 2, SendCh: make(chan []byte, 4)},
	}
	var rooms []int
	for i := 0; i < 6; i++ {
		w, ok := s.chooseAndSend(workers, []byte{byte(i)}, bondSmallPacketMax+1)
		if !ok {
			t.Fatal("large packet not scheduled")
		}
		rooms = append(rooms, w.RoomID)
		<-w.SendCh
	}
	want := []int{0, 1, 2, 0, 1, 2}
	for i := range want {
		if rooms[i] != want[i] {
			t.Fatalf("large rooms=%v want %v", rooms, want)
		}
	}
	for i := 0; i < 3; i++ {
		w, ok := s.chooseAndSend(workers, []byte{1}, bondSmallPacketMax)
		if !ok || w.RoomID != 0 {
			t.Fatalf("small packet room=%v ok=%t, want room 0", w, ok)
		}
		<-w.SendCh
	}
	for i := 0; i < cap(workers[0].SendCh); i++ {
		workers[0].SendCh <- []byte("fill")
	}
	w, ok := s.chooseAndSend(workers, []byte{1}, bondSmallPacketMax)
	if !ok || w.RoomID != 1 {
		t.Fatalf("small failover room=%v ok=%t, want room 1", w, ok)
	}
}

func TestWorkerTokenBucketPacesBulkAtConfiguredRateAndPrioritizesLatencyDebt(t *testing.T) {
	now := time.Unix(1, 0)
	bucket := newWorkerTokenBucket(DefaultWorkerRateBPS, func() time.Time { return now })
	if !bucket.admit(workerBurstBytes, false) {
		t.Fatal("full bucket rejected its configured burst")
	}

	bulkBytes := 0
	for i := 0; i < 100; i++ {
		now = now.Add(10 * time.Millisecond)
		for bucket.admit(50, false) {
			bulkBytes += 50
		}
	}
	if bulkBytes < 7200 || bulkBytes > 7300 {
		t.Fatalf("one-second sustained bulk allowance=%d bytes, want about 7250", bulkBytes)
	}

	debt := newWorkerTokenBucket(DefaultWorkerRateBPS, func() time.Time { return now })
	if !debt.admit(workerBurstBytes, false) {
		t.Fatal("failed to drain initial burst")
	}
	if !debt.admit(bondSmallPacketMax, true) || !debt.admit(bondSmallPacketMax, true) {
		t.Fatal("latency traffic was rejected instead of entering debt")
	}
	now = now.Add(100 * time.Millisecond)
	if debt.admit(100, false) {
		t.Fatal("bulk traffic bypassed outstanding latency debt")
	}
	if !debt.admit(bondSmallPacketMax, true) {
		t.Fatal("latency traffic was rejected while the bucket remained in debt")
	}
	now = now.Add(time.Second)
	if !debt.admit(workerBurstBytes, false) {
		t.Fatal("bulk traffic did not resume after debt repayment")
	}
}

func TestBondSchedulerBulkSpillsToNextWorkerWhenFirstBucketEmpty(t *testing.T) {
	now := time.Unix(2, 0)
	first := &WorkerSlot{ID: 1, RoomID: 0, SendCh: make(chan []byte, 1)}
	second := &WorkerSlot{ID: 2, RoomID: 0, SendCh: make(chan []byte, 1)}
	first.bucket = newWorkerTokenBucket(DefaultWorkerRateBPS, func() time.Time { return now })
	second.bucket = newWorkerTokenBucket(DefaultWorkerRateBPS, func() time.Time { return now })
	if !first.bucket.admit(workerBurstBytes, false) {
		t.Fatal("failed to drain first worker bucket")
	}

	s := newBondScheduler(DefaultWorkerRateBPS)
	w, ok := s.chooseAndSend([]*WorkerSlot{first, second}, []byte("bulk"), bondSmallPacketMax+1)
	if !ok || w != second {
		t.Fatalf("bulk spill worker=%v ok=%t, want second worker", w, ok)
	}
}

func TestBondDispatcherCountsShaperDropWithoutConsumingSequence(t *testing.T) {
	now := time.Unix(3, 0)
	worker := &WorkerSlot{ID: 1, RoomID: 0, SendCh: make(chan []byte, 1)}
	worker.bucket = newWorkerTokenBucket(DefaultWorkerRateBPS, func() time.Time { return now })
	if !worker.bucket.admit(workerBurstBytes, false) {
		t.Fatal("failed to drain worker bucket")
	}
	stats := NewStats()
	d := &Dispatcher{
		workers:       []*WorkerSlot{worker},
		stats:         stats,
		bondSched:     newBondScheduler(DefaultWorkerRateBPS),
		workerRateBPS: DefaultWorkerRateBPS,
	}
	d.dispatchBond(bytes.Repeat([]byte{'x'}, bondSmallPacketMax+1))
	if got := stats.BondShaperDrops; got != 1 {
		t.Fatalf("shaper drops=%d want=1", got)
	}
	if seq := d.bondBulkSeq.Load(); seq != 0 {
		t.Fatalf("dropped bulk packet consumed sequence %d", seq)
	}

	d.dispatchBond([]byte("latency"))
	frame, err := decodeBondFrame(<-worker.SendCh)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq != 1 || frame.Flags != bondFlagLatency {
		t.Fatalf("first accepted latency frame seq=%d flags=%d, want 1/%d", frame.Seq, frame.Flags, bondFlagLatency)
	}
}

func TestBondLatencyLaneUsesIndependentUplinkSequence(t *testing.T) {
	stats := NewStats()
	worker := &WorkerSlot{ID: 1, RoomID: 0, SendCh: make(chan []byte, 3)}
	d := &Dispatcher{
		stats:     stats,
		bondV2:    true,
		bondSched: newBondScheduler(),
		workers:   []*WorkerSlot{worker},
	}

	d.dispatchBond(bytes.Repeat([]byte{'b'}, bondSmallPacketMax+1))
	d.dispatchBond([]byte("latency"))
	d.dispatchBond(bytes.Repeat([]byte{'c'}, bondSmallPacketMax+1))

	bulk, err := decodeBondFrame(<-worker.SendCh)
	if err != nil {
		t.Fatal(err)
	}
	latency, err := decodeBondFrame(<-worker.SendCh)
	if err != nil {
		t.Fatal(err)
	}
	bulk2, err := decodeBondFrame(<-worker.SendCh)
	if err != nil {
		t.Fatal(err)
	}
	if bulk.Flags != 0 || bulk.Seq != 1 {
		t.Fatalf("bulk flags=%#x seq=%d want 0/1", bulk.Flags, bulk.Seq)
	}
	if latency.Flags != bondFlagLatency || latency.Seq != 1 {
		t.Fatalf("latency flags=%#x seq=%d want %#x/1", latency.Flags, latency.Seq, bondFlagLatency)
	}
	if bulk2.Flags != 0 || bulk2.Seq != 2 {
		t.Fatalf("bulk2 flags=%#x seq=%d want 0/2; latency packets must not create bulk gaps", bulk2.Flags, bulk2.Seq)
	}
}

type bondRecordingPacketConn struct {
	writes chan []byte
}

func (c *bondRecordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *bondRecordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	cp := append([]byte(nil), p...)
	c.writes <- cp
	return len(p), nil
}

func (c *bondRecordingPacketConn) Close() error                     { return nil }
func (c *bondRecordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *bondRecordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *bondRecordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bondRecordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestBondLatencyLaneBypassesBulkGapDownlink(t *testing.T) {
	stats := NewStats()
	conn := &bondRecordingPacketConn{writes: make(chan []byte, 2)}
	d := &Dispatcher{
		localConn:          conn,
		stats:              stats,
		bondV2:             true,
		bondBulkReorder:    newBondReorderBuffer(stats),
		bondLatencyReorder: newBondReorderBuffer(stats),
	}
	var client net.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}
	d.clientAddr.Store(&client)

	// Bulk sequence 1 is deliberately absent. Sequence 2 must remain held in
	// the bulk lane while latency sequence 1 crosses independently.
	bulk, err := encodeBondFrame(bondFrame{
		Type:    bondFrameData,
		Seq:     2,
		Payload: bytes.Repeat([]byte{'b'}, bondSmallPacketMax+1),
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handleBondReturn(bulk)
	select {
	case packet := <-conn.writes:
		t.Fatalf("bulk gap emitted early: %q", packet)
	default:
	}

	latency, err := encodeBondFrame(bondFrame{
		Type: bondFrameData, Flags: bondFlagLatency, Seq: 1, Payload: []byte("latency"),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d.handleBondReturn(latency)
	select {
	case packet := <-conn.writes:
		if string(packet) != "latency" {
			t.Fatalf("downlink packet=%q", packet)
		}
		if elapsed := time.Since(start); elapsed >= bondReorderHold {
			t.Fatalf("latency lane waited %v (reorder hold %v)", elapsed, bondReorderHold)
		}
	default:
		t.Fatal("latency packet was held behind bulk gap")
	}
}

func TestBondReorderContiguousTimeoutLateDuplicateWindow(t *testing.T) {
	stats := NewStats()
	now := time.Unix(0, 0)
	r := newBondReorderBuffer(stats)
	r.now = func() time.Time { return now }
	if out := r.push(1, []byte("one")); len(out) != 1 || string(out[0]) != "one" {
		t.Fatalf("seq1 out=%q", out)
	}
	if out := r.push(3, []byte("three")); len(out) != 0 {
		t.Fatalf("seq3 before gap filled out=%q", out)
	}
	if out := r.push(2, []byte("two")); len(out) != 2 || string(out[0]) != "two" || string(out[1]) != "three" {
		t.Fatalf("1,3,2 out=%q", out)
	}
	if out := r.push(3, []byte("dup")); len(out) != 0 || stats.BondReorderLate == 0 {
		t.Fatalf("duplicate out=%q late=%d", out, stats.BondReorderLate)
	}
	bufferedDuplicate := newBondReorderBuffer(stats)
	_ = bufferedDuplicate.push(2, []byte("two"))
	_ = bufferedDuplicate.push(2, []byte("two-again"))
	if stats.BondReorderDuplicates != 1 {
		t.Fatalf("buffered duplicates=%d want=1", stats.BondReorderDuplicates)
	}
	if out := r.push(6, []byte("six")); len(out) != 0 {
		t.Fatalf("gap out=%q", out)
	}
	now = now.Add(bondReorderHold + time.Millisecond)
	if out := r.flushExpired(); len(out) != 1 || string(out[0]) != "six" || stats.BondReorderGaps == 0 {
		t.Fatalf("timeout out=%q gaps=%d", out, stats.BondReorderGaps)
	}
	if out := r.push(400, []byte("pressure")); len(out) != 1 || string(out[0]) != "pressure" {
		t.Fatalf("window pressure out=%q", out)
	}
}

func TestBondFourRoomAsymmetricDelayLossReorders(t *testing.T) {
	const total = 100
	stats := NewStats()
	reorder := newBondReorderBuffer(stats)
	scheduler := newBondScheduler()
	workers := make([]*WorkerSlot, 4)
	roomPackets := make([]int, 4)
	for room := range workers {
		worker := &WorkerSlot{ID: room + 1, RoomID: room, SendCh: make(chan []byte, 64)}
		worker.bucket = newWorkerTokenBucket(DefaultWorkerRateBPS, nil)
		worker.bucket.burst = 1 << 20
		worker.bucket.tokens = worker.bucket.burst
		workers[room] = worker
	}
	for seq := 1; seq <= total; seq++ {
		frame, err := encodeBondFrame(bondFrame{Type: bondFrameData, Seq: uint64(seq), Payload: []byte{byte(seq)}})
		if err != nil {
			t.Fatal(err)
		}
		worker, ok := scheduler.chooseAndSend(workers, frame, bondSmallPacketMax+1)
		if !ok {
			t.Fatalf("sequence %d was not scheduled", seq)
		}
		roomPackets[worker.RoomID]++
	}
	for room, got := range roomPackets {
		if got != total/4 {
			t.Fatalf("room %d packets=%d want=%d", room, got, total/4)
		}
	}

	arrivals := make(chan bondFrame, total)
	var deliveries sync.WaitGroup
	for room, worker := range workers {
		delay := time.Duration(1+room*2) * time.Millisecond
		for len(worker.SendCh) > 0 {
			frameBytes := <-worker.SendCh
			frame, err := decodeBondFrame(frameBytes)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Seq == 37 {
				continue
			}
			deliveries.Add(1)
			go func(frame bondFrame, delay time.Duration) {
				defer deliveries.Done()
				time.Sleep(delay + time.Duration(frame.Seq%3)*time.Millisecond)
				arrivals <- frame
			}(frame, delay)
		}
	}
	go func() {
		deliveries.Wait()
		close(arrivals)
	}()

	var ordered []int
	for frame := range arrivals {
		for _, payload := range reorder.push(frame.Seq, frame.Payload) {
			ordered = append(ordered, int(payload[0]))
		}
	}
	time.Sleep(bondReorderHold + 5*time.Millisecond)
	for _, payload := range reorder.flushExpired() {
		ordered = append(ordered, int(payload[0]))
	}
	if len(ordered) != total-1 {
		t.Fatalf("ordered packets=%d want=%d gaps=%d late=%d", len(ordered), total-1, stats.BondReorderGaps, stats.BondReorderLate)
	}
	want := 1
	for _, got := range ordered {
		if want == 37 {
			want++
		}
		if got != want {
			t.Fatalf("out of order: got=%d want=%d sequence=%v", got, want, ordered)
		}
		want++
	}
	if stats.BondReorderGaps != 1 || stats.BondReorderLate != 0 {
		t.Fatalf("gaps=%d late=%d want=1/0", stats.BondReorderGaps, stats.BondReorderLate)
	}
}

func TestDispatcherShutdownUnblocksReadLoop(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	d := NewDispatcherWithOptions(context.Background(), conn, NewStats(), true, 2, DefaultWorkerRateBPS, nil)
	done := make(chan struct{})
	go func() {
		d.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher shutdown remained blocked in ReadFrom")
	}
}

func TestBondV2ValidationLegacyDefaultAndPartialRoomCaches(t *testing.T) {
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, Workers: 20, PreloadedCreds: testRoomCreds("legacy"), BondV2: true}); err == nil {
		t.Fatal("expected BondV2 legacy rejection")
	}
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, WorkersPerRoom: 20, VKHashes: []string{"room-a"}, PreloadedCredsByHash: map[string]*Credentials{"room-a": testRoomCreds("a")}, BondV2: true}); err == nil {
		t.Fatal("expected BondV2 one-room rejection")
	}
	r, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, Workers: 20, PreloadedCreds: testRoomCreds("legacy")})
	if err != nil {
		t.Fatalf("legacy New: %v", err)
	}
	if r.cfg.BondV2 {
		t.Fatal("legacy default unexpectedly enabled BondV2")
	}
	multi, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, WorkersPerRoom: 20, VKHashes: []string{"room-a", "room-b"}, PreloadedCredsByHash: map[string]*Credentials{"room-a": testRoomCreds("a")}, BondV2: true})
	if err != nil {
		t.Fatalf("BondV2 must allow partial room cache and acquire missing rooms anonymously: %v", err)
	}
	if got := multi.currentRoomCreds("room-b"); got != nil {
		t.Fatalf("missing room unexpectedly preloaded: %#v", got)
	}
	if err := multi.UpdatePreloadedCredsByHash(map[string]*Credentials{}); err != nil {
		t.Fatalf("empty live room credential update should be allowed: %v", err)
	}
}

func testRoomCreds(user string) *Credentials {
	return &Credentials{User: user, Pass: "pass", TurnURLs: []string{"turn.example:3478"}, Lifetime: 600}
}
