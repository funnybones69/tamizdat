package wgturnclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const (
	bondMagic                     = "TZB2"
	bondVersion            byte   = 2
	bondHeaderLen                 = 16
	bondMaxBindJSON               = 4096
	bondMaxDataPayload            = 4096
	bondSmallPacketMax            = 384
	bondReorderWindow             = 256
	bondReorderHold               = 30 * time.Millisecond
	bondBindMaxAttempts           = 8
	bondBindInitialBackoff        = 125 * time.Millisecond
	bondFlagLatency        uint16 = 1 << 0
)

type EventFunc func(level, message string)

type bondFrameType byte

const (
	bondFrameBind       bondFrameType = 1
	bondFrameBindWait   bondFrameType = 2
	bondFrameBindOK     bondFrameType = 3
	bondFrameBindConfig bondFrameType = 4
	bondFrameData       bondFrameType = 5
	bondFrameKeepalive  bondFrameType = 6
	bondFrameError      bondFrameType = 7
)

type bondFrame struct {
	Type    bondFrameType
	Flags   uint16
	Seq     uint64
	Payload []byte
}

type bondBindPayload struct {
	DeviceID   string `json:"device_id"`
	RunID      string `json:"run_id"`
	Token      string `json:"token"`
	Room       int    `json:"room"`
	Worker     int    `json:"worker"`
	LocalPort  string `json:"local_port"`
	WantConfig bool   `json:"want_config"`
	Password   string `json:"password,omitempty"`
}

type bondRunnerIdentity struct {
	RunID string
	Token string
}

type bondNegotiationError struct{ Reason string }

func (e bondNegotiationError) Error() string { return "BONDV2_NEGOTIATION: " + e.Reason }

func newBondRunnerIdentity() (bondRunnerIdentity, error) {
	runID, err := randomB64(16)
	if err != nil {
		return bondRunnerIdentity{}, fmt.Errorf("bond run id random: %w", err)
	}
	token, err := randomB64(32)
	if err != nil {
		return bondRunnerIdentity{}, fmt.Errorf("bond token random: %w", err)
	}
	return bondRunnerIdentity{RunID: runID, Token: token}, nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encodeBondFrame(frame bondFrame) ([]byte, error) {
	if frame.Type < bondFrameBind || frame.Type > bondFrameError {
		return nil, fmt.Errorf("invalid bond frame type %d", frame.Type)
	}
	limit := bondMaxDataPayload
	if frame.Type == bondFrameBind {
		limit = bondMaxBindJSON
	}
	if len(frame.Payload) > limit {
		return nil, fmt.Errorf("bond frame payload too large")
	}
	out := make([]byte, bondHeaderLen+len(frame.Payload))
	copy(out[0:4], bondMagic)
	out[4] = bondVersion
	out[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(out[6:8], frame.Flags)
	binary.BigEndian.PutUint64(out[8:16], frame.Seq)
	copy(out[bondHeaderLen:], frame.Payload)
	return out, nil
}

func decodeBondFrame(buf []byte) (bondFrame, error) {
	if len(buf) < bondHeaderLen {
		return bondFrame{}, fmt.Errorf("bond frame too short")
	}
	if string(buf[0:4]) != bondMagic {
		return bondFrame{}, fmt.Errorf("bond bad magic")
	}
	if buf[4] != bondVersion {
		return bondFrame{}, fmt.Errorf("bond unsupported version %d", buf[4])
	}
	ft := bondFrameType(buf[5])
	if ft < bondFrameBind || ft > bondFrameError {
		return bondFrame{}, fmt.Errorf("bond unknown frame type %d", ft)
	}
	payload := buf[bondHeaderLen:]
	limit := bondMaxDataPayload
	if ft == bondFrameBind {
		limit = bondMaxBindJSON
	}
	if len(payload) > limit {
		return bondFrame{}, fmt.Errorf("bond frame payload too large")
	}
	return bondFrame{Type: ft, Flags: binary.BigEndian.Uint16(buf[6:8]), Seq: binary.BigEndian.Uint64(buf[8:16]), Payload: payload}, nil
}

func encodeBondBind(p bondBindPayload) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > bondMaxBindJSON {
		return nil, fmt.Errorf("bind json too large")
	}
	return encodeBondFrame(bondFrame{Type: bondFrameBind, Flags: bondFlagLatency, Payload: b})
}

func bondFramePayload(ft bondFrameType, payload []byte) ([]byte, error) {
	flags := uint16(0)
	switch ft {
	case bondFrameBindWait, bondFrameBindOK, bondFrameBindConfig, bondFrameError:
		flags = bondFlagLatency
	}
	return encodeBondFrame(bondFrame{Type: ft, Flags: flags, Payload: payload})
}

type bondScheduler struct {
	roomRR   int
	primary  int
	workerRR map[int]int
}

func newBondScheduler() *bondScheduler { return &bondScheduler{workerRR: make(map[int]int)} }

func (s *bondScheduler) choose(workers []*WorkerSlot, pkt []byte, size int) (*WorkerSlot, bool) {
	rooms := activeRooms(workers)
	if len(rooms) == 0 {
		return nil, false
	}
	if size <= bondSmallPacketMax {
		start := 0
		for i, room := range rooms {
			if room == s.primary {
				start = i
				break
			}
		}
		for i := 0; i < len(rooms); i++ {
			room := rooms[(start+i)%len(rooms)]
			if w, ok := s.chooseInRoom(workers, room, pkt); ok {
				s.primary = room
				return w, true
			}
		}
		return nil, false
	}
	start := s.roomRR % len(rooms)
	for i := 0; i < len(rooms); i++ {
		roomIdx := (start + i) % len(rooms)
		room := rooms[roomIdx]
		if w, ok := s.chooseInRoom(workers, room, pkt); ok {
			s.roomRR = (roomIdx + 1) % len(rooms)
			return w, true
		}
	}
	return nil, false
}

func activeRooms(workers []*WorkerSlot) []int {
	seen := make(map[int]struct{}, 4)
	for _, w := range workers {
		if w != nil {
			seen[w.RoomID] = struct{}{}
		}
	}
	rooms := make([]int, 0, len(seen))
	for room := range seen {
		rooms = append(rooms, room)
	}
	sort.Ints(rooms)
	return rooms
}

func (s *bondScheduler) chooseInRoom(workers []*WorkerSlot, room int, pkt []byte) (*WorkerSlot, bool) {
	var roomWorkers []*WorkerSlot
	for _, w := range workers {
		if w != nil && w.RoomID == room {
			roomWorkers = append(roomWorkers, w)
		}
	}
	if len(roomWorkers) == 0 {
		return nil, false
	}
	start := s.workerRR[room] % len(roomWorkers)
	for i := 0; i < len(roomWorkers); i++ {
		idx := (start + i) % len(roomWorkers)
		w := roomWorkers[idx]
		select {
		case w.SendCh <- pkt:
			s.workerRR[room] = (idx + 1) % len(roomWorkers)
			return w, true
		default:
		}
	}
	return nil, false
}

func (s *bondScheduler) chooseAndSend(workers []*WorkerSlot, pkt []byte, size int) (*WorkerSlot, bool) {
	return s.choose(workers, pkt, size)
}

type bondReorderBuffer struct {
	expect uint64
	buf    map[uint64][]byte
	first  time.Time
	now    func() time.Time
	stats  *Stats
}

func newBondReorderBuffer(stats *Stats) *bondReorderBuffer {
	if stats == nil {
		stats = NewStats()
	}
	return &bondReorderBuffer{expect: 1, buf: make(map[uint64][]byte, bondReorderWindow), now: time.Now, stats: stats}
}

func (r *bondReorderBuffer) push(seq uint64, payload []byte) [][]byte {
	if seq == 0 {
		atomic.AddInt64(&r.stats.BondReorderLate, 1)
		return nil
	}
	if seq < r.expect {
		atomic.AddInt64(&r.stats.BondReorderLate, 1)
		return nil
	}
	if seq == r.expect {
		out := [][]byte{payload}
		r.expect++
		out = append(out, r.drainContiguous()...)
		if len(r.buf) == 0 {
			r.first = time.Time{}
		}
		return out
	}
	if _, exists := r.buf[seq]; exists {
		atomic.AddInt64(&r.stats.BondReorderDuplicates, 1)
		return nil
	}
	if seq-r.expect >= bondReorderWindow {
		atomic.AddInt64(&r.stats.BondReorderGaps, 1)
		r.expect = seq
		r.buf = make(map[uint64][]byte, bondReorderWindow)
		r.first = time.Time{}
		return r.push(seq, payload)
	}
	cp := append([]byte(nil), payload...)
	r.buf[seq] = cp
	if r.first.IsZero() {
		r.first = r.now()
	}
	return nil
}

func bondLatencyLane(flags uint16) (bool, bool) {
	if flags & ^bondFlagLatency != 0 {
		return false, false
	}
	return flags&bondFlagLatency != 0, true
}

func (r *bondReorderBuffer) flushExpired() [][]byte {
	if len(r.buf) == 0 || r.first.IsZero() || r.now().Sub(r.first) < bondReorderHold {
		return nil
	}
	var lowest uint64
	for seq := range r.buf {
		if lowest == 0 || seq < lowest {
			lowest = seq
		}
	}
	if lowest > r.expect {
		atomic.AddInt64(&r.stats.BondReorderGaps, int64(lowest-r.expect))
		r.expect = lowest
	}
	payload := r.buf[lowest]
	delete(r.buf, lowest)
	r.expect = lowest + 1
	out := [][]byte{payload}
	out = append(out, r.drainContiguous()...)
	if len(r.buf) == 0 {
		r.first = time.Time{}
	} else {
		r.first = r.now()
	}
	return out
}

func (r *bondReorderBuffer) drainContiguous() [][]byte {
	var out [][]byte
	for {
		p, ok := r.buf[r.expect]
		if !ok {
			return out
		}
		delete(r.buf, r.expect)
		out = append(out, p)
		r.expect++
	}
}

func emitEvent(onEvent EventFunc, level, format string, args ...interface{}) {
	if onEvent == nil {
		return
	}
	onEvent(level, fmt.Sprintf(format, args...))
}

func sanitizeErrForEvent(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	if len(msg) > 180 {
		msg = msg[:180] + "…"
	}
	return msg
}

type stringError []byte

func (e stringError) Error() string { return string(e) }
