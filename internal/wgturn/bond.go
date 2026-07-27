//go:build linux

package wgturn

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bondVersion            = 2
	bondHeaderSize         = 16
	bondMaxBindPayload     = 4096
	bondMaxDataPayload     = 4096
	bondReorderWindow      = 256
	bondReorderHold        = 30 * time.Millisecond
	bondSmallPacketMax     = 384
	bondWorkerQueue        = 128
	bondWGQueue            = 512
	bondMaxRooms           = 4
	bondMaxWorkers         = 80
	bondBindMaxAttempts    = 8
	bondCleanupGrace       = 10 * time.Second
	bondMaxRunsPerDevice   = 1
	bondMaxActiveAndClaims = 512
	bondFlagLatency        = uint16(1 << 0)
)

var bondMagic = [4]byte{'T', 'Z', 'B', '2'}

type bondFrameType uint8

const (
	bondFrameBind bondFrameType = iota + 1
	bondFrameBindWait
	bondFrameBindOK
	bondFrameBindConfig
	bondFrameData
	bondFrameKeepalive
	bondFrameError
)

type bondFrame struct {
	Type     bondFrameType
	Flags    uint16
	Sequence uint64
	Payload  []byte
}

func isBondPacket(p []byte) bool {
	return len(p) >= len(bondMagic) && string(p[:len(bondMagic)]) == string(bondMagic[:])
}

func encodeBondFrame(typ bondFrameType, flags uint16, sequence uint64, payload []byte) ([]byte, error) {
	if typ < bondFrameBind || typ > bondFrameError {
		return nil, errors.New("invalid bond frame type")
	}
	limit := bondMaxDataPayload
	if typ == bondFrameBind {
		limit = bondMaxBindPayload
	}
	if len(payload) > limit {
		return nil, errors.New("bond frame payload too large")
	}
	out := make([]byte, bondHeaderSize+len(payload))
	copy(out[:4], bondMagic[:])
	out[4] = bondVersion
	out[5] = byte(typ)
	binary.BigEndian.PutUint16(out[6:8], flags)
	binary.BigEndian.PutUint64(out[8:16], sequence)
	copy(out[bondHeaderSize:], payload)
	return out, nil
}

func decodeBondFrame(p []byte) (bondFrame, error) {
	if len(p) < bondHeaderSize || !isBondPacket(p) {
		return bondFrame{}, errors.New("invalid bond frame magic or length")
	}
	if p[4] != bondVersion {
		return bondFrame{}, errors.New("unsupported bond frame version")
	}
	typ := bondFrameType(p[5])
	if typ < bondFrameBind || typ > bondFrameError {
		return bondFrame{}, errors.New("invalid bond frame type")
	}
	payload := p[bondHeaderSize:]
	limit := bondMaxDataPayload
	if typ == bondFrameBind {
		limit = bondMaxBindPayload
	}
	if len(payload) > limit {
		return bondFrame{}, errors.New("bond frame payload too large")
	}
	return bondFrame{
		Type:     typ,
		Flags:    binary.BigEndian.Uint16(p[6:8]),
		Sequence: binary.BigEndian.Uint64(p[8:16]),
		Payload:  payload,
	}, nil
}

type bondBind struct {
	DeviceID   string          `json:"device_id"`
	RunID      string          `json:"run_id"`
	Token      string          `json:"token"`
	Room       int             `json:"room"`
	Worker     int             `json:"worker"`
	LocalPort  json.RawMessage `json:"local_port"`
	WantConfig bool            `json:"want_config"`
	Password   string          `json:"password,omitempty"`
}

func (b bondBind) localPortString() (string, error) {
	var port int
	if len(b.LocalPort) == 0 {
		return "", errors.New("missing local_port")
	}
	if err := json.Unmarshal(b.LocalPort, &port); err != nil {
		var text string
		if err := json.Unmarshal(b.LocalPort, &text); err != nil {
			return "", errors.New("invalid local_port")
		}
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return "", errors.New("invalid local_port")
		}
		port = parsed
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid local_port")
	}
	return strconv.Itoa(port), nil
}

func parseBondBind(payload []byte) (bondBind, error) {
	if len(payload) == 0 || len(payload) > bondMaxBindPayload {
		return bondBind{}, errors.New("invalid BIND payload size")
	}
	var bind bondBind
	if err := json.Unmarshal(payload, &bind); err != nil {
		return bondBind{}, errors.New("invalid BIND JSON")
	}
	if bind.DeviceID == "" || len(bind.DeviceID) > 256 || len(bind.RunID) < 16 || len(bind.RunID) > 128 || len(bind.Token) < 32 || len(bind.Token) > 256 {
		return bondBind{}, errors.New("invalid BIND identity")
	}
	// Client worker IDs are intentionally one-based (1..80); they are also the
	// IDs shown in worker logs.  Accepting only 0..79 made the exact 4x20 pool
	// fail permanently on worker 80.
	if bind.Room < 0 || bind.Room >= bondMaxRooms || bind.Worker < 1 || bind.Worker > bondMaxWorkers {
		return bondBind{}, errors.New("invalid BIND slot")
	}
	if _, err := bind.localPortString(); err != nil {
		return bondBind{}, err
	}
	if !bind.WantConfig && bind.Password != "" {
		return bondBind{}, errors.New("joiner must not send password")
	}
	return bind, nil
}

type bondKey struct {
	deviceID string
	runID    string
}

type bondClaim struct {
	token string
}

func bondTokenMatches(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type bondRoomMetrics struct {
	upPackets   uint64
	upBytes     uint64
	downPackets uint64
	downBytes   uint64
	drops       uint64
}

type bondWorker struct {
	room   int
	worker int
	conn   net.Conn
	send   chan []byte
	ctx    context.Context
	cancel context.CancelFunc
}

type bondRoom struct {
	workers     map[int]*bondWorker
	workerOrder []int
	rr          uint64
	metrics     bondRoomMetrics
}

type packetReorder struct {
	next      uint64
	hold      time.Duration
	gapSince  time.Time
	slots     [bondReorderWindow]*reorderPacket
	buffered  int
	gaps      uint64
	late      uint64
	duplicate uint64
}

type reorderPacket struct {
	sequence uint64
	payload  []byte
}

func newPacketReorder(hold time.Duration) *packetReorder {
	return &packetReorder{next: 1, hold: hold}
}

func (r *packetReorder) push(sequence uint64, payload []byte, now time.Time) [][]byte {
	if sequence == 0 || sequence < r.next {
		r.late++
		return nil
	}
	var out [][]byte
	for sequence-r.next >= bondReorderWindow {
		lowest, ok := r.lowest()
		if !ok {
			r.gaps += sequence - r.next
			r.next = sequence
			break
		}
		r.advanceTo(lowest)
		out = append(out, r.drain()...)
	}
	idx := sequence % bondReorderWindow
	if old := r.slots[idx]; old != nil {
		if old.sequence == sequence {
			r.duplicate++
			return nil
		}
		// This can only occur after window pressure. Discard the stale slot.
		r.buffered--
	}
	r.slots[idx] = &reorderPacket{sequence: sequence, payload: payload}
	r.buffered++
	out = append(out, r.drain()...)
	if r.buffered > 0 && r.gapSince.IsZero() {
		r.gapSince = now
	}
	if r.buffered == 0 {
		r.gapSince = time.Time{}
	}
	return out
}

func (r *packetReorder) flushExpired(now time.Time) [][]byte {
	if r.buffered == 0 || r.gapSince.IsZero() || now.Sub(r.gapSince) < r.hold {
		return nil
	}
	lowest, ok := r.lowest()
	if !ok {
		return nil
	}
	r.advanceTo(lowest)
	out := r.drain()
	if r.buffered > 0 {
		r.gapSince = now
	} else {
		r.gapSince = time.Time{}
	}
	return out
}

func (r *packetReorder) advanceTo(sequence uint64) {
	if sequence > r.next {
		r.gaps += sequence - r.next
		r.next = sequence
	}
}

func (r *packetReorder) lowest() (uint64, bool) {
	var lowest uint64
	for _, p := range r.slots {
		if p != nil && (lowest == 0 || p.sequence < lowest) {
			lowest = p.sequence
		}
	}
	return lowest, lowest != 0
}

func (r *packetReorder) drain() [][]byte {
	var out [][]byte
	for {
		idx := r.next % bondReorderWindow
		p := r.slots[idx]
		if p == nil || p.sequence != r.next {
			return out
		}
		r.slots[idx] = nil
		r.buffered--
		out = append(out, p.payload)
		r.next++
	}
}

type serverBond struct {
	server    *Server
	key       bondKey
	token     string
	identity  ClientIdentity
	device    *clientDevice
	config    string
	wgConn    net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closing   atomic.Bool

	mu                 sync.Mutex
	rooms              map[int]*bondRoom
	roomOrder          []int
	primaryRoom        int
	claimRoom          int
	claimWorker        int
	rrRoom             uint64
	workers            int
	emptyGen           uint64
	cleanupGrace       time.Duration
	cleanupTimer       *time.Timer
	bulkReorder        *packetReorder
	latencyReorder     *packetReorder
	wgWrite            chan []byte
	outBulkSequence    atomic.Uint64
	outLatencySequence atomic.Uint64
	wgWriteDrop        atomic.Uint64
	scheduleDrop       atomic.Uint64
	badFrames          atomic.Uint64
}

func (s *Server) dialBondWG() (net.Conn, error) {
	if s.bondDialWG != nil {
		return s.bondDialWG()
	}
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", s.cfg.WGPort))
	if err != nil {
		return nil, err
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(2 * 1024 * 1024)
		_ = uc.SetWriteBuffer(2 * 1024 * 1024)
	}
	return conn, nil
}

func (s *Server) provisionBondDevice(localPort, deviceID string) (*clientDevice, string, error) {
	if s.bondProvision != nil {
		return s.bondProvision(localPort, deviceID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, exists := s.devices[deviceID]
	if !exists {
		dev = &clientDevice{deviceID: deviceID, ip: s.getNextIP()}
		privB64, pubB64, err := generateKeyPair()
		if err != nil || dev.ip == "" {
			return nil, "", errors.New("device provisioning failed")
		}
		dev.privKey, dev.pubKey = privB64, pubB64
		s.devices[deviceID] = dev
		s.saveDevices()
		if s.wgDev == nil {
			delete(s.devices, deviceID)
			return nil, "", errors.New("WireGuard device unavailable")
		}
		pubHex, err := b64ToHex(pubB64)
		if err != nil {
			return nil, "", err
		}
		if err := s.wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.ip)); err != nil {
			return nil, "", err
		}
		log.Printf("[wgturn-bond] new device %s (IP: %s)", deviceID, dev.ip)
	}
	return dev, buildClientConfig(s.keys.serverPublic, dev.privKey, dev.ip, localPort), nil
}

func (s *Server) acquireBond(ctx context.Context, bind bondBind) (*serverBond, bondFrameType, []byte) {
	if s.bondClosed.Load() || ctx.Err() != nil {
		return nil, bondFrameError, []byte("server_shutdown")
	}
	key := bondKey{deviceID: bind.DeviceID, runID: bind.RunID}
	s.bondsMu.Lock()
	if bond := s.bonds[key]; bond != nil {
		s.bondsMu.Unlock()
		if !bondTokenMatches(bond.token, bind.Token) {
			return nil, bondFrameError, []byte("token_mismatch")
		}
		if bond.closing.Load() {
			return nil, bondFrameBindWait, []byte("bond_device_busy")
		}
		if bind.WantConfig {
			// A claimant may lose the BIND_CONFIG response after the bond was
			// committed. Any worker holding the runner's 256-bit token may recover
			// the same config; tying recovery to one transient worker slot makes a
			// successful bond permanently unusable after that connection dies.
			return bond, bondFrameBindConfig, []byte(bond.config)
		}
		return bond, bondFrameBindOK, nil
	}
	if claim := s.bondClaims[key]; claim != nil {
		s.bondsMu.Unlock()
		if !bondTokenMatches(claim.token, bind.Token) {
			return nil, bondFrameError, []byte("token_mismatch")
		}
		return nil, bondFrameBindWait, nil
	}
	if !bind.WantConfig {
		s.bondsMu.Unlock()
		return nil, bondFrameBindWait, nil
	}
	if len(s.bonds)+len(s.bondClaims) >= bondMaxActiveAndClaims {
		s.bondsMu.Unlock()
		return nil, bondFrameError, []byte("bond_capacity")
	}
	// An already authenticated run may be unreachable through an orphaned
	// TURN allocation for minutes after a router crash.  Do not let that stale
	// server-side object block a fresh password-bearing claimant.  We still
	// serialize claimants per device, so only one replacement can authenticate
	// and commit at a time.
	claimsForDevice := 0
	for claimKey := range s.bondClaims {
		if claimKey.deviceID == bind.DeviceID {
			claimsForDevice++
		}
	}
	if claimsForDevice >= bondMaxRunsPerDevice {
		s.bondsMu.Unlock()
		// A concurrent replacement is already authenticating.
		return nil, bondFrameBindWait, []byte("bond_device_busy")
	}
	s.bondClaims[key] = &bondClaim{token: bind.Token}
	s.bondsMu.Unlock()

	identity, deny := s.authenticateClient(ctx, bind.DeviceID, bind.Password)
	if deny != "" {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("denied:" + deny)
	}
	identityNeedsClose := true
	defer func() {
		if identityNeedsClose && s.cfg.OnIdentityDone != nil && identity.SessionID != "" {
			s.cfg.OnIdentityDone(identity)
		}
	}()
	if s.bondClosed.Load() || ctx.Err() != nil {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("server_shutdown")
	}
	// Authentication succeeded.  Retire any older run for this device before
	// opening the replacement WG socket.  Token-only workers from the old run
	// cannot take the device back because only WantConfig carries the password.
	retired := s.retireDeviceBonds(key)
	if retired > 0 {
		log.Printf("[wgturn-bond] authenticated takeover retired_runs=%d active_runs_for_device=0", retired)
	}
	localPort, err := bind.localPortString()
	if err != nil {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("invalid_bind")
	}
	dev, config, err := s.provisionBondDevice(localPort, bind.DeviceID)
	if err != nil {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("provision_failed")
	}
	if s.bondClosed.Load() || ctx.Err() != nil {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("server_shutdown")
	}
	wgConn, err := s.dialBondWG()
	if err != nil {
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("wg_unavailable")
	}
	if s.bondClosed.Load() || ctx.Err() != nil {
		_ = wgConn.Close()
		s.finishBondClaim(key, nil)
		return nil, bondFrameError, []byte("server_shutdown")
	}
	bctx, cancel := context.WithCancel(ctx)
	bond := &serverBond{
		server: s, key: key, token: bind.Token, identity: identity, device: dev,
		config: config, wgConn: wgConn, ctx: bctx, cancel: cancel,
		rooms: make(map[int]*bondRoom), primaryRoom: bind.Room,
		claimRoom: bind.Room, claimWorker: bind.Worker,
		cleanupGrace:   bondCleanupGrace,
		bulkReorder:    newPacketReorder(bondReorderHold),
		latencyReorder: newPacketReorder(bondReorderHold),
		wgWrite:        make(chan []byte, bondWGQueue),
	}
	winner := s.finishBondClaim(key, bond)
	if winner != bond {
		bond.close()
		if s.bondClosed.Load() {
			return nil, bondFrameError, []byte("server_shutdown")
		}
		if winner != nil && bondTokenMatches(winner.token, bind.Token) {
			return winner, bondFrameBindConfig, []byte(winner.config)
		}
		return nil, bondFrameError, []byte("bond_race")
	}
	// A successfully authenticated claimant may disconnect before its
	// BIND_CONFIG response is written. Arm cleanup before any worker joins so
	// that the shared WG socket and identity cannot remain orphaned.
	bond.armEmptyCleanup()
	s.setIdentityForIP(dev.ip, identity)
	go bond.runWGReader()
	go bond.runWGWriter()
	go bond.runMetrics()
	go func() {
		<-bctx.Done()
		s.removeBond(bond)
	}()
	log.Printf("[wgturn-bond] created bond_v2_active=1 primary_room=%d active_runs_for_device=1 shared_wg_sockets=1", bind.Room)
	identityNeedsClose = false
	return bond, bondFrameBindConfig, []byte(config)
}

// retireDeviceBonds synchronously closes committed runs for the same device
// except keep.  The map entries are removed before close so a late cleanup
// callback from the old run cannot delete the replacement.
func (s *Server) retireDeviceBonds(keep bondKey) int {
	var retiring []*serverBond
	s.bondsMu.Lock()
	for key, bond := range s.bonds {
		if key.deviceID != keep.deviceID || key == keep {
			continue
		}
		bond.closing.Store(true)
		delete(s.bonds, key)
		retiring = append(retiring, bond)
	}
	s.bondsMu.Unlock()
	for _, bond := range retiring {
		bond.close()
	}
	return len(retiring)
}

func (s *Server) finishBondClaim(key bondKey, bond *serverBond) *serverBond {
	s.bondsMu.Lock()
	defer s.bondsMu.Unlock()
	delete(s.bondClaims, key)
	if bond == nil {
		return nil
	}
	if s.bondClosed.Load() {
		return nil
	}
	if existing := s.bonds[key]; existing != nil {
		return existing
	}
	s.bonds[key] = bond
	return bond
}

func (s *Server) removeBond(bond *serverBond) {
	if bond == nil {
		return
	}
	// Keep the retiring bond discoverable until close has synchronously closed
	// its connected WG socket. A different run therefore remains in BIND_WAIT
	// and cannot overlap the old peer endpoint even for a scheduler tick.
	bond.close()
	s.bondsMu.Lock()
	if s.bonds[bond.key] == bond {
		delete(s.bonds, bond.key)
	}
	s.bondsMu.Unlock()
}

func (b *serverBond) close() {
	b.closing.Store(true)
	b.closeOnce.Do(func() {
		b.cancel()
		_ = b.wgConn.Close()
		b.mu.Lock()
		if b.cleanupTimer != nil {
			b.cleanupTimer.Stop()
			b.cleanupTimer = nil
		}
		for _, room := range b.rooms {
			for _, worker := range room.workers {
				worker.cancel()
				_ = worker.conn.SetDeadline(time.Now())
			}
		}
		workers := b.workers
		roomMetrics := make(map[int]bondRoomMetrics, len(b.rooms))
		for id, room := range b.rooms {
			roomMetrics[id] = room.metrics
		}
		bulkGaps, bulkLate, bulkDuplicates := b.bulkReorder.gaps, b.bulkReorder.late, b.bulkReorder.duplicate
		latencyGaps, latencyLate, latencyDuplicates := b.latencyReorder.gaps, b.latencyReorder.late, b.latencyReorder.duplicate
		b.mu.Unlock()
		log.Printf("[wgturn-bond] closed workers=%d rooms=%v active_runs_for_device=0 shared_wg_sockets=0 bulk_reorder_gaps=%d bulk_late=%d bulk_duplicates=%d latency_reorder_gaps=%d latency_late=%d latency_duplicates=%d wg_queue_drops=%d scheduler_drops=%d bad_frames=%d",
			workers, roomMetrics, bulkGaps, bulkLate, bulkDuplicates, latencyGaps, latencyLate, latencyDuplicates, b.wgWriteDrop.Load(), b.scheduleDrop.Load(), b.badFrames.Load())
		if b.server.cfg.OnIdentityDone != nil && b.identity.SessionID != "" {
			b.server.cfg.OnIdentityDone(b.identity)
		}
	})
}

func bondLatencyLane(flags uint16) (bool, bool) {
	if flags & ^bondFlagLatency != 0 {
		return false, false
	}
	return flags&bondFlagLatency != 0, true
}

func (b *serverBond) acceptDataFrame(roomID int, frame bondFrame, now time.Time) ([][]byte, bool) {
	latency, valid := bondLatencyLane(frame.Flags)
	if !valid || frame.Sequence == 0 || len(frame.Payload) == 0 {
		return nil, false
	}
	payload := append([]byte(nil), frame.Payload...)
	b.mu.Lock()
	if room := b.rooms[roomID]; room != nil {
		room.metrics.upPackets++
		room.metrics.upBytes += uint64(len(payload))
	}
	reorder := b.bulkReorder
	if latency {
		reorder = b.latencyReorder
	}
	ready := reorder.push(frame.Sequence, payload, now)
	b.mu.Unlock()
	return ready, true
}

func (b *serverBond) armEmptyCleanup() {
	b.mu.Lock()
	b.armEmptyCleanupLocked()
	b.mu.Unlock()
}

// armEmptyCleanupLocked schedules owner cleanup only while no workers are
// attached. emptyGen makes a timer that raced with addWorker harmless.
// b.mu must be held.
func (b *serverBond) armEmptyCleanupLocked() {
	if b.workers != 0 {
		return
	}
	if b.cleanupTimer != nil {
		b.cleanupTimer.Stop()
	}
	b.emptyGen++
	gen := b.emptyGen
	grace := b.cleanupGrace
	if grace <= 0 {
		grace = bondCleanupGrace
	}
	b.cleanupTimer = time.AfterFunc(grace, func() {
		b.mu.Lock()
		stillEmpty := b.workers == 0 && b.emptyGen == gen
		if stillEmpty {
			b.cleanupTimer = nil
		}
		b.mu.Unlock()
		if stillEmpty {
			b.server.removeBond(b)
		}
	})
}

func (b *serverBond) addWorker(_ context.Context, bind bondBind, conn net.Conn) *bondWorker {
	ctx, cancel := context.WithCancel(b.ctx)
	worker := &bondWorker{room: bind.Room, worker: bind.Worker, conn: conn, send: make(chan []byte, bondWorkerQueue), ctx: ctx, cancel: cancel}
	b.mu.Lock()
	if b.cleanupTimer != nil {
		b.cleanupTimer.Stop()
		b.cleanupTimer = nil
	}
	room := b.rooms[bind.Room]
	if room == nil {
		room = &bondRoom{workers: make(map[int]*bondWorker)}
		b.rooms[bind.Room] = room
		b.roomOrder = append(b.roomOrder, bind.Room)
		sort.Ints(b.roomOrder)
	}
	if old := room.workers[bind.Worker]; old != nil {
		old.cancel()
		_ = old.conn.SetDeadline(time.Now())
	} else {
		b.workers++
		room.workerOrder = append(room.workerOrder, bind.Worker)
		sort.Ints(room.workerOrder)
	}
	room.workers[bind.Worker] = worker
	b.emptyGen++
	b.mu.Unlock()
	return worker
}

func (b *serverBond) removeWorker(worker *bondWorker) {
	b.mu.Lock()
	room := b.rooms[worker.room]
	if room == nil || room.workers[worker.worker] != worker {
		b.mu.Unlock()
		return
	}
	delete(room.workers, worker.worker)
	for i, id := range room.workerOrder {
		if id == worker.worker {
			room.workerOrder = append(room.workerOrder[:i], room.workerOrder[i+1:]...)
			break
		}
	}
	b.workers--
	if b.workers == 0 {
		b.armEmptyCleanupLocked()
	}
	b.mu.Unlock()
}

func (b *serverBond) runWorker(worker *bondWorker) {
	defer worker.cancel()
	defer b.removeWorker(worker)
	context.AfterFunc(worker.ctx, func() { _ = worker.conn.SetDeadline(time.Now()) })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-worker.ctx.Done():
				return
			case frame := <-worker.send:
				_ = worker.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := worker.conn.Write(frame); err != nil {
					worker.cancel()
					return
				}
			case <-ticker.C:
				frame, _ := encodeBondFrame(bondFrameKeepalive, 0, 0, nil)
				_ = worker.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := worker.conn.Write(frame); err != nil {
					worker.cancel()
					return
				}
			}
		}
	}()

	buf := make([]byte, bondHeaderSize+bondMaxDataPayload)
	for worker.ctx.Err() == nil {
		_ = worker.conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := worker.conn.Read(buf)
		if err != nil {
			break
		}
		frame, err := decodeBondFrame(buf[:n])
		if err != nil {
			b.badFrames.Add(1)
			break
		}
		switch frame.Type {
		case bondFrameKeepalive:
			continue
		case bondFrameData:
			ready, valid := b.acceptDataFrame(worker.room, frame, time.Now())
			if !valid {
				b.badFrames.Add(1)
				continue
			}
			b.enqueueWG(ready)
		default:
			b.badFrames.Add(1)
			worker.cancel()
		}
	}
	worker.cancel()
	wg.Wait()
}

func (b *serverBond) enqueueWG(packets [][]byte) {
	for _, packet := range packets {
		select {
		case b.wgWrite <- packet:
		case <-b.ctx.Done():
			return
		default:
			b.wgWriteDrop.Add(1)
		}
	}
}

func (b *serverBond) runWGWriter() {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case packet := <-b.wgWrite:
			_ = b.wgConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := b.wgConn.Write(packet); err != nil {
				b.cancel()
				return
			}
		case now := <-ticker.C:
			b.mu.Lock()
			ready := b.bulkReorder.flushExpired(now)
			ready = append(ready, b.latencyReorder.flushExpired(now)...)
			b.mu.Unlock()
			b.enqueueWG(ready)
		}
	}
}

func (b *serverBond) runMetrics() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			workersByRoom := make(map[int]int, len(b.rooms))
			metricsByRoom := make(map[int]bondRoomMetrics, len(b.rooms))
			for roomID, room := range b.rooms {
				workersByRoom[roomID] = len(room.workers)
				metricsByRoom[roomID] = room.metrics
			}
			bulkGaps, bulkLate, bulkDuplicates := b.bulkReorder.gaps, b.bulkReorder.late, b.bulkReorder.duplicate
			latencyGaps, latencyLate, latencyDuplicates := b.latencyReorder.gaps, b.latencyReorder.late, b.latencyReorder.duplicate
			b.mu.Unlock()
			log.Printf("[wgturn-bond] stats bond_v2_active=1 active_runs_for_device=1 shared_wg_sockets=1 workers_by_room=%v room_metrics=%+v bulk_reorder_gaps=%d bulk_late=%d bulk_duplicates=%d latency_reorder_gaps=%d latency_late=%d latency_duplicates=%d wg_queue_drops=%d scheduler_drops=%d bad_frames=%d",
				workersByRoom, metricsByRoom, bulkGaps, bulkLate, bulkDuplicates, latencyGaps, latencyLate, latencyDuplicates, b.wgWriteDrop.Load(), b.scheduleDrop.Load(), b.badFrames.Load())
		}
	}
}

func (b *serverBond) runWGReader() {
	buf := make([]byte, bondMaxDataPayload)
	for b.ctx.Err() == nil {
		_ = b.wgConn.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := b.wgConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && b.ctx.Err() == nil {
				continue
			}
			b.cancel()
			return
		}
		flags, sequence := b.nextOutboundFrameMeta(n)
		frame, err := encodeBondFrame(bondFrameData, flags, sequence, buf[:n])
		if err != nil {
			continue
		}
		b.schedule(frame, n)
	}
}

// nextOutboundFrameMeta keeps the bulk and latency sequence spaces truly
// independent. Advancing the bulk counter for a latency packet creates a
// permanent artificial gap at the peer, forcing a reorder timeout for every
// small WireGuard packet.
func (b *serverBond) nextOutboundFrameMeta(payloadLen int) (uint16, uint64) {
	if payloadLen <= bondSmallPacketMax {
		return bondFlagLatency, b.outLatencySequence.Add(1)
	}
	return 0, b.outBulkSequence.Add(1)
}

func (b *serverBond) schedule(frame []byte, payloadLen int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	activeRooms := 0
	for _, id := range b.roomOrder {
		room := b.rooms[id]
		if len(room.workers) > 0 {
			activeRooms++
		}
	}
	if activeRooms == 0 {
		b.scheduleDrop.Add(1)
		return false
	}
	start := 0
	if payloadLen <= bondSmallPacketMax {
		ordinal := 0
		found := false
		for _, id := range b.roomOrder {
			if len(b.rooms[id].workers) == 0 {
				continue
			}
			if id >= b.primaryRoom {
				start, found = ordinal, true
				break
			}
			ordinal++
		}
		if !found {
			start = 0
		}
	} else {
		start = int(b.rrRoom % uint64(activeRooms))
	}
	for roomOffset := 0; roomOffset < activeRooms; roomOffset++ {
		roomIndex := (start + roomOffset) % activeRooms
		roomID := b.activeRoomAt(roomIndex)
		room := b.rooms[roomID]
		workerStart := int(room.rr % uint64(len(room.workerOrder)))
		for workerOffset := 0; workerOffset < len(room.workerOrder); workerOffset++ {
			workerIndex := (workerStart + workerOffset) % len(room.workerOrder)
			worker := room.workers[room.workerOrder[workerIndex]]
			select {
			case worker.send <- frame:
				room.rr = uint64(workerIndex + 1)
				room.metrics.downPackets++
				room.metrics.downBytes += uint64(payloadLen)
				if payloadLen > bondSmallPacketMax {
					b.rrRoom = uint64(roomIndex + 1)
				}
				return true
			default:
				room.metrics.drops++
			}
		}
	}
	b.scheduleDrop.Add(1)
	return false
}

// activeRoomAt returns an active room by sorted active-room ordinal. b.mu must
// be held. Room/worker order is updated only on joins/leaves, not per packet.
func (b *serverBond) activeRoomAt(want int) int {
	ordinal := 0
	for _, id := range b.roomOrder {
		if len(b.rooms[id].workers) == 0 {
			continue
		}
		if ordinal == want {
			return id
		}
		ordinal++
	}
	return b.roomOrder[0]
}

func sameBondBindAttempt(a, b bondBind) bool {
	if a.DeviceID != b.DeviceID || a.RunID != b.RunID || !bondTokenMatches(a.Token, b.Token) ||
		a.Room != b.Room || a.Worker != b.Worker || a.WantConfig != b.WantConfig || a.Password != b.Password {
		return false
	}
	aPort, aErr := a.localPortString()
	bPort, bErr := b.localPortString()
	return aErr == nil && bErr == nil && aPort == bPort
}

func parseBondBindFrame(packet []byte) (bondBind, error) {
	frame, err := decodeBondFrame(packet)
	if err != nil || frame.Type != bondFrameBind || frame.Flags != bondFlagLatency || frame.Sequence != 0 {
		return bondBind{}, errors.New("invalid BIND frame")
	}
	return parseBondBind(frame.Payload)
}

func writeBondControl(conn net.Conn, typ bondFrameType, payload []byte) error {
	frame, err := encodeBondFrame(typ, bondFlagLatency, 0, payload)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(frame)
	return err
}

func (s *Server) handleBondConn(ctx context.Context, conn net.Conn, first []byte) {
	packet := first
	var initial bondBind
	for attempt := 0; attempt < bondBindMaxAttempts; attempt++ {
		bind, err := parseBondBindFrame(packet)
		if err != nil {
			_ = writeBondControl(conn, bondFrameError, []byte("invalid_bind"))
			return
		}
		if attempt == 0 {
			initial = bind
		} else if !sameBondBindAttempt(initial, bind) {
			_ = writeBondControl(conn, bondFrameError, []byte("bind_changed"))
			return
		}

		bond, responseType, response := s.acquireBond(ctx, bind)
		if err := writeBondControl(conn, responseType, response); err != nil {
			return
		}
		if responseType != bondFrameBindWait || bond != nil {
			if bond == nil {
				return
			}
			worker := bond.addWorker(ctx, bind, conn)
			bond.runWorker(worker)
			return
		}

		// BIND_WAIT explicitly means retry this negotiation on the same DTLS
		// association. Keep the handler alive for the client's bounded backoff
		// loop instead of forcing every concurrent worker to redial TURN/DTLS.
		buf := make([]byte, bondHeaderSize+bondMaxBindPayload)
		_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		n, err := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		packet = buf[:n]
	}
	_ = writeBondControl(conn, bondFrameError, []byte("bind_wait_limit"))
}
