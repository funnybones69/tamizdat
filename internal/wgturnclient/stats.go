package wgturnclient

import (
	"log"
	"sync/atomic"
	"time"
)

type Stats struct {
	ActiveConnections int32
	Reconnects        int64
	TotalBytesUp      int64
	TotalBytesDown    int64
	CredsErrors       int64

	BondFramesUp                int64
	BondFramesDown              int64
	BondBytesUp                 int64
	BondBytesDown               int64
	BondQueueDrops              int64
	BondReorderGaps             int64
	BondReorderLate             int64
	BondReorderDuplicates       int64
	BondInvalidFrames           int64
	BondNegotiationFailures     int64
	BondLatencyFramesUp         int64
	BondLatencyFramesDown       int64
	BondRoomsConfigured         int32
	BondWorkersRequestedPerRoom int32
	BondWorkersActive           [maxRooms]int32
	BondRoomPackets             [maxRooms]int64
	BondRoomBytes               [maxRooms]int64
	BondRoomDrops               [maxRooms]int64
	BondRoomRXPackets           [maxRooms]int64
	BondRoomRXBytes             [maxRooms]int64
	BondRoomCredentialErrors    [maxRooms]int64
	BondRoomSessionErrors       [maxRooms]int64
	BondRoomQuotaErrors         [maxRooms]int64
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			active := atomic.LoadInt32(&s.ActiveConnections)
			up := atomic.LoadInt64(&s.TotalBytesUp)
			down := atomic.LoadInt64(&s.TotalBytesDown)
			totalMB := float64(up+down) / (1024.0 * 1024.0)

			log.Printf("[СТАТИСТИКА] Активных: %d | Трафик: %.2f МБ", active, totalMB)
			bondUp := atomic.LoadInt64(&s.BondFramesUp)
			bondDown := atomic.LoadInt64(&s.BondFramesDown)
			if bondUp+bondDown > 0 || atomic.LoadInt32(&s.BondRoomsConfigured) > 0 {
				roomPackets := make([]int64, len(s.BondRoomPackets))
				roomBytes := make([]int64, len(s.BondRoomBytes))
				roomDrops := make([]int64, len(s.BondRoomDrops))
				roomRXPackets := make([]int64, len(s.BondRoomRXPackets))
				roomRXBytes := make([]int64, len(s.BondRoomRXBytes))
				workersActive := make([]int32, len(s.BondWorkersActive))
				roomCredentialErrors := make([]int64, len(s.BondRoomCredentialErrors))
				roomSessionErrors := make([]int64, len(s.BondRoomSessionErrors))
				roomQuotaErrors := make([]int64, len(s.BondRoomQuotaErrors))
				for i := range roomPackets {
					roomPackets[i] = atomic.LoadInt64(&s.BondRoomPackets[i])
					roomBytes[i] = atomic.LoadInt64(&s.BondRoomBytes[i])
					roomDrops[i] = atomic.LoadInt64(&s.BondRoomDrops[i])
					roomRXPackets[i] = atomic.LoadInt64(&s.BondRoomRXPackets[i])
					roomRXBytes[i] = atomic.LoadInt64(&s.BondRoomRXBytes[i])
					workersActive[i] = atomic.LoadInt32(&s.BondWorkersActive[i])
					roomCredentialErrors[i] = atomic.LoadInt64(&s.BondRoomCredentialErrors[i])
					roomSessionErrors[i] = atomic.LoadInt64(&s.BondRoomSessionErrors[i])
					roomQuotaErrors[i] = atomic.LoadInt64(&s.BondRoomQuotaErrors[i])
				}
				log.Printf("[BOND] bond_v2_active=1 rooms_configured=%d workers_requested_per_room=%d workers_active_per_room=%v frames_up=%d frames_down=%d latency_frames_up=%d latency_frames_down=%d bytes_up=%d bytes_down=%d queue_drops=%d reorder_gaps=%d late=%d duplicates=%d invalid_frames=%d negotiation_failures=%d room_tx_packets=%v room_tx_bytes=%v room_rx_packets=%v room_rx_bytes=%v room_drops=%v room_credential_errors=%v room_session_errors=%v room_quota_errors=%v",
					atomic.LoadInt32(&s.BondRoomsConfigured), atomic.LoadInt32(&s.BondWorkersRequestedPerRoom), workersActive,
					bondUp, bondDown, atomic.LoadInt64(&s.BondLatencyFramesUp), atomic.LoadInt64(&s.BondLatencyFramesDown),
					atomic.LoadInt64(&s.BondBytesUp), atomic.LoadInt64(&s.BondBytesDown),
					atomic.LoadInt64(&s.BondQueueDrops), atomic.LoadInt64(&s.BondReorderGaps), atomic.LoadInt64(&s.BondReorderLate),
					atomic.LoadInt64(&s.BondReorderDuplicates), atomic.LoadInt64(&s.BondInvalidFrames), atomic.LoadInt64(&s.BondNegotiationFailures),
					roomPackets, roomBytes, roomRXPackets, roomRXBytes, roomDrops,
					roomCredentialErrors, roomSessionErrors, roomQuotaErrors)
			}
		}
	}
}
