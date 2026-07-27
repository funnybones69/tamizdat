package tamizdat

import (
	"expvar"
	"testing"
)

// TestRealtimeClassifierExpvarsRemoved is the G-RR-1 regression guard:
// after the realtime classifier (Plan B+ Hybrid) was deleted on
// 2026-05-09, none of its expvar keys must reappear. Catches accidental
// re-introduction of the realtime classifier or any cargo-cult metric
// that looks like it.
//
// If a future change legitimately re-introduces realtime classification,
// this test must be updated alongside it. The forbidden-list is the set
// of keys the deleted classifier exposed.
func TestRealtimeClassifierExpvarsRemoved(t *testing.T) {
	// Force telemetry init in case earlier tests skipped it.
	initTelemetry()
	initReplayExpvars()

	forbidden := []string{
		"tamizdat_active_realtime",
		"tamizdat_locked_realtime",
		"tamizdat_top_flow",
		"tamizdat_locked_flows",
		// Defensive aliases — close-enough names that earlier drafts
		// experimented with. If any of these show up, something
		// resembling the classifier crept back in.
		"tamizdat.realtime.active",
		"tamizdat.realtime.locked",
		"tamizdat.realtime.top_flow",
		"tamizdat.realtime.locked_flows",
	}
	bad := make([]string, 0)
	for _, name := range forbidden {
		if expvar.Get(name) != nil {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("realtime-classifier expvars re-introduced: %v\n"+
			"The classifier was deleted on 2026-05-09 (no measurable benefit per bench).\n"+
			"If you legitimately re-added it, update this test alongside the change.",
			bad)
	}
}
