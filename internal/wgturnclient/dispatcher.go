package wgturnclient

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const returnChBuf = 384

type WorkerSlot struct {
	ID     int
	RoomID int
	SendCh chan []byte
}

type Dispatcher struct {
	localConn       net.PacketConn
	clientAddr      atomic.Pointer[net.Addr]
	mu              sync.Mutex
	workers         []*WorkerSlot
	rrIndex         int
	ReturnCh        chan []byte
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	stats           *Stats
	onWorkerCount   func(int)
	countGeneration uint64 // guarded by mu
	notifyMu        sync.Mutex
	lastNotified    uint64 // guarded by notifyMu

	bondV2             bool
	bondBulkSeq        atomic.Uint64
	bondLatencySeq     atomic.Uint64
	bondSched          *bondScheduler
	bondBulkReorder    *bondReorderBuffer
	bondLatencyReorder *bondReorderBuffer
	bondEvent          EventFunc
	bondRooms          int
	reorderTicker      *time.Ticker
}

func NewDispatcher(ctx context.Context, localConn net.PacketConn, stats *Stats) *Dispatcher {
	return NewDispatcherWithOptions(ctx, localConn, stats, false, 0, nil)
}

func NewDispatcherWithOptions(ctx context.Context, localConn net.PacketConn, stats *Stats, bondV2 bool, rooms int, onEvent EventFunc) *Dispatcher {
	if ctx == nil {
		ctx = context.Background()
	}
	if stats == nil {
		stats = NewStats()
	}
	dctx, dcancel := context.WithCancel(ctx)
	d := &Dispatcher{
		localConn: localConn,
		ReturnCh:  make(chan []byte, returnChBuf),
		ctx:       dctx,
		cancel:    dcancel,
		stats:     stats,
		bondV2:    bondV2,
		bondEvent: onEvent,
		bondRooms: rooms,
	}
	if bondV2 {
		d.bondSched = newBondScheduler()
		d.bondBulkReorder = newBondReorderBuffer(d.stats)
		d.bondLatencyReorder = newBondReorderBuffer(d.stats)
		d.reorderTicker = time.NewTicker(bondReorderHold / 2)
	}

	d.wg.Add(2)
	go d.readLoop()
	go d.writeLoop()
	return d
}

func (d *Dispatcher) Shutdown() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	// ReadFrom is not context-aware. Closing the owned packet socket releases
	// readLoop immediately; Runner may close it again safely during teardown.
	if d.localConn != nil {
		_ = d.localConn.Close()
	}
	if d.reorderTicker != nil {
		d.reorderTicker.Stop()
	}
	d.wg.Wait()
}

func (d *Dispatcher) notifyWorkerCount(generation uint64, count int) {
	if d.onWorkerCount == nil {
		return
	}
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	if generation <= d.lastNotified {
		return
	}
	d.lastNotified = generation
	d.onWorkerCount(count)
}

func (d *Dispatcher) Register(w *WorkerSlot) {
	d.mu.Lock()
	d.workers = append(d.workers, w)
	count := len(d.workers)
	d.countGeneration++
	generation := d.countGeneration
	d.mu.Unlock()
	d.notifyWorkerCount(generation, count)
	if d.bondV2 {
		if w.RoomID >= 0 && w.RoomID < len(d.stats.BondWorkersActive) {
			atomic.AddInt32(&d.stats.BondWorkersActive[w.RoomID], 1)
		}
		log.Printf("[ДИСП] Bond v2 воркер #%d room=%d зарегистрирован (всего: %d)", w.ID, w.RoomID, count)
		return
	}
	log.Printf("[ДИСП] Воркер #%d зарегистрирован (всего: %d)", w.ID, count)
}

func (d *Dispatcher) Unregister(slot *WorkerSlot) {
	d.mu.Lock()
	removed := false
	for i, w := range d.workers {
		if w == slot {
			d.workers = append(d.workers[:i], d.workers[i+1:]...)
			removed = true
			break
		}
	}
	remaining := len(d.workers)
	if removed {
		d.countGeneration++
	}
	generation := d.countGeneration
	d.mu.Unlock()
	if removed {
		d.notifyWorkerCount(generation, remaining)
		if d.bondV2 && slot.RoomID >= 0 && slot.RoomID < len(d.stats.BondWorkersActive) {
			atomic.AddInt32(&d.stats.BondWorkersActive[slot.RoomID], -1)
		}
	}
	log.Printf("[ДИСП] Воркер #%d отключён (осталось: %d)", slot.ID, remaining)
}

func (d *Dispatcher) readLoop() {
	defer d.wg.Done()
	if d.localConn == nil {
		return
	}

	buf := make([]byte, readBufSize)
	for {
		if err := d.ctx.Err(); err != nil {
			return
		}

		n, addr, err := d.localConn.ReadFrom(buf)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		d.clientAddr.Store(&addr)
		atomic.AddInt64(&d.stats.TotalBytesUp, int64(n))

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if d.bondV2 {
			d.dispatchBond(pkt)
			continue
		}
		d.dispatchLegacy(pkt)
	}
}

func (d *Dispatcher) dispatchLegacy(pkt []byte) {
	d.mu.Lock()
	nw := len(d.workers)
	if nw == 0 {
		d.mu.Unlock()
		return
	}

	sent := false
	startIdx := d.rrIndex % nw
	for i := 0; i < nw; i++ {
		idx := (startIdx + i) % nw
		w := d.workers[idx]
		select {
		case w.SendCh <- pkt:
			d.rrIndex = (idx + 1) % nw
			sent = true
		default:
		}
		if sent {
			break
		}
	}
	if !sent {
		d.rrIndex = (startIdx + 1) % nw
	}
	d.mu.Unlock()
}

func (d *Dispatcher) dispatchBond(payload []byte) {
	flags := uint16(0)
	var seq uint64
	if len(payload) <= bondSmallPacketMax {
		flags = bondFlagLatency
		seq = d.bondLatencySeq.Add(1)
	} else {
		seq = d.bondBulkSeq.Add(1)
	}
	frame, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: flags, Seq: seq, Payload: payload})
	if err != nil {
		emitEvent(d.bondEvent, "error", "bond encode data error err=%s", sanitizeErrForEvent(err))
		return
	}
	d.mu.Lock()
	if len(d.workers) == 0 {
		d.mu.Unlock()
		return
	}
	w, sent := d.bondSched.chooseAndSend(d.workers, frame, len(payload))
	if sent {
		atomic.AddInt64(&d.stats.BondFramesUp, 1)
		atomic.AddInt64(&d.stats.BondBytesUp, int64(len(payload)))
		if w.RoomID >= 0 && w.RoomID < len(d.stats.BondRoomPackets) {
			atomic.AddInt64(&d.stats.BondRoomPackets[w.RoomID], 1)
			atomic.AddInt64(&d.stats.BondRoomBytes[w.RoomID], int64(len(payload)))
		}
		if flags&bondFlagLatency != 0 {
			atomic.AddInt64(&d.stats.BondLatencyFramesUp, 1)
		}
	} else {
		atomic.AddInt64(&d.stats.BondQueueDrops, 1)
		for _, room := range activeRooms(d.workers) {
			if room >= 0 && room < len(d.stats.BondRoomDrops) {
				atomic.AddInt64(&d.stats.BondRoomDrops[room], 1)
			}
		}
	}
	d.mu.Unlock()
}

func (d *Dispatcher) writeLoop() {
	defer d.wg.Done()

	for {
		if !d.bondV2 {
			select {
			case <-d.ctx.Done():
				return
			case pkt := <-d.ReturnCh:
				d.writeWGPacket(pkt)
			}
			continue
		}
		select {
		case <-d.ctx.Done():
			return
		case pkt := <-d.ReturnCh:
			d.handleBondReturn(pkt)
		case <-d.reorderTicker.C:
			for _, payload := range d.bondBulkReorder.flushExpired() {
				d.writeWGPacket(payload)
			}
			for _, payload := range d.bondLatencyReorder.flushExpired() {
				d.writeWGPacket(payload)
			}
		}
	}
}

func (d *Dispatcher) handleBondReturn(pkt []byte) {
	frame, err := decodeBondFrame(pkt)
	if err != nil {
		atomic.AddInt64(&d.stats.BondReorderLate, 1)
		emitEvent(d.bondEvent, "warn", "bond downlink invalid frame err=%s", sanitizeErrForEvent(err))
		return
	}
	if frame.Type == bondFrameKeepalive {
		return
	}
	if frame.Type == bondFrameError {
		emitEvent(d.bondEvent, "error", "bond server error err=%s", sanitizeErrForEvent(stringError(frame.Payload)))
		return
	}
	if frame.Type != bondFrameData {
		emitEvent(d.bondEvent, "warn", "bond downlink unexpected type=%d", frame.Type)
		return
	}
	latency, valid := bondLatencyLane(frame.Flags)
	if !valid || frame.Seq == 0 || len(frame.Payload) == 0 {
		atomic.AddInt64(&d.stats.BondInvalidFrames, 1)
		emitEvent(d.bondEvent, "warn", "bond downlink invalid DATA flags=%d", frame.Flags)
		return
	}
	atomic.AddInt64(&d.stats.BondFramesDown, 1)
	atomic.AddInt64(&d.stats.BondBytesDown, int64(len(frame.Payload)))
	reorder := d.bondBulkReorder
	if latency {
		reorder = d.bondLatencyReorder
		atomic.AddInt64(&d.stats.BondLatencyFramesDown, 1)
	}
	for _, payload := range reorder.push(frame.Seq, frame.Payload) {
		d.writeWGPacket(payload)
	}
}

func (d *Dispatcher) writeWGPacket(pkt []byte) {
	addrPtr := d.clientAddr.Load()
	if addrPtr == nil || d.localConn == nil {
		return
	}
	addr := *addrPtr
	if _, err := d.localConn.WriteTo(pkt, addr); err != nil {
		return
	}
	atomic.AddInt64(&d.stats.TotalBytesDown, int64(len(pkt)))
}
