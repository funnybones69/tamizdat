package tamizdat

import (
	"errors"
	"testing"
)

func TestOutboundStreamTrackerTracksLivePeaksAndDialFailures(t *testing.T) {
	tr := newOutboundStreamTracker()

	releaseTCP, peak := tr.acquire("sync2", "tcp")
	if !peak.advanced || peak.total != 1 || peak.tcp != 1 || peak.udp != 0 {
		t.Fatalf("first tcp peak = %+v", peak)
	}
	releaseUDP, peak := tr.acquire("sync2", "udp")
	if !peak.advanced || peak.total != 2 || peak.tcp != 1 || peak.udp != 1 {
		t.Fatalf("first udp peak = %+v", peak)
	}

	got := tr.snapshot("sync2")
	if got.liveTotal != 2 || got.liveTCP != 1 || got.liveUDP != 1 {
		t.Fatalf("live snapshot = %+v", got)
	}
	if got.peakTotal != 2 || got.peakTCP != 1 || got.peakUDP != 1 {
		t.Fatalf("peak snapshot = %+v", got)
	}

	tr.recordDialFailure("sync2", "tcp", errors.New("handshake rate limited"))
	tr.recordDialFailure("sync2", "udp", errors.New("connection refused"))
	got = tr.snapshot("sync2")
	if got.dialFailedTCP != 1 || got.dialFailedUDP != 1 || got.lastFailedNet != "udp" || got.lastFailedErr != "connection refused" {
		t.Fatalf("dial failure snapshot = %+v", got)
	}

	releaseTCP()
	releaseUDP()
	got = tr.snapshot("sync2")
	if got.liveTotal != 0 || got.liveTCP != 0 || got.liveUDP != 0 {
		t.Fatalf("live after release = %+v", got)
	}
}
