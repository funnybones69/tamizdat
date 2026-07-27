package tamizdat

import "testing"

func TestUserH2StreamTrackerTracksTotalAndNetworkPeaks(t *testing.T) {
	tr := newUserH2StreamTracker()
	key := "user:u1"

	release1, peak := tr.acquire(key, "tcp")
	if !peak.advanced || peak.total != 1 || peak.tcp != 1 || peak.udp != 0 {
		t.Fatalf("first tcp peak = %+v", peak)
	}
	release2, peak := tr.acquire(key, "udp")
	if !peak.advanced || peak.total != 2 || peak.tcp != 1 || peak.udp != 1 {
		t.Fatalf("first udp peak = %+v", peak)
	}
	release2()
	release1()

	releaseBelow, peak := tr.acquire(key, "tcp")
	if peak.advanced {
		t.Fatalf("re-enter below previous total/tcp peak should not advance: %+v", peak)
	}
	release3, peak := tr.acquire(key, "tcp")
	if !peak.advanced || peak.total != 2 || peak.tcp != 2 || peak.udp != 1 {
		t.Fatalf("second tcp peak = %+v", peak)
	}
	release3()
	releaseBelow()
	got := tr.peak(key)
	if got.total != 2 || got.tcp != 2 || got.udp != 1 {
		t.Fatalf("stored peak = %+v", got)
	}
}

func TestUserH2StreamTrackerTracksActiveByNetwork(t *testing.T) {
	tr := newUserH2StreamTracker()
	key := "user:u1"

	releaseTCP, _ := tr.acquire(key, "tcp")
	releaseUDP, _ := tr.acquire(key, "udp")
	got := tr.active(key)
	if got.total != 2 || got.tcp != 1 || got.udp != 1 {
		t.Fatalf("active = %+v", got)
	}

	releaseUDP()
	got = tr.active(key)
	if got.total != 1 || got.tcp != 1 || got.udp != 0 {
		t.Fatalf("active after udp release = %+v", got)
	}

	releaseTCP()
	got = tr.active(key)
	if got.total != 0 || got.tcp != 0 || got.udp != 0 {
		t.Fatalf("active after all release = %+v", got)
	}
}
