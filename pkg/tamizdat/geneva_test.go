package tamizdat

import (
	"testing"
)

func TestStrategiesProduceSegments(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i % 256)
	}
	for _, s := range fragStrategies {
		segs := s.Fn(data)
		if len(segs) == 0 {
			t.Errorf("strategy %s returned 0 segments", s.Name)
			continue
		}
		// Re-assembly should equal the original.
		var total int
		for _, seg := range segs {
			total += len(seg)
		}
		if total != len(data) {
			t.Errorf("strategy %s: segment total %d != input %d", s.Name, total, len(data))
		}
	}
}

func TestBanditPickAndReport(t *testing.T) {
	b := &genevaBandit{stats: map[string]*serverStats{}, epsilon: 0.0} // pure exploit
	server := "127.0.0.1:18447"

	// Cold start: bandit has no info → falls back to first strategy by Wilson tie.
	first := b.pick(server)
	if first == "" {
		t.Fatal("bandit pick returned empty")
	}

	// Reward "midpoint" repeatedly; punish others. Should converge.
	for i := 0; i < 500; i++ {
		b.reportOutcome(server, "midpoint", true)
		b.reportOutcome(server, "sni_split", false)
		b.reportOutcome(server, "first_byte", false)
		b.reportOutcome(server, "two_thirds", false)
		b.reportOutcome(server, "hdr_then_body", false)
	}
	picked := b.pick(server)
	if picked != "midpoint" {
		t.Errorf("after rewarding midpoint 50x and punishing others, bandit picked %q (expected midpoint)", picked)
	}
}

func TestBanditPerServerIsolation(t *testing.T) {
	b := &genevaBandit{stats: map[string]*serverStats{}, epsilon: 0.0}
	for i := 0; i < 30; i++ {
		b.reportOutcome("server-a:443", "first_byte", true)
		b.reportOutcome("server-a:443", "midpoint", false)
		b.reportOutcome("server-b:443", "midpoint", true)
		b.reportOutcome("server-b:443", "first_byte", false)
	}
	if got := b.pick("server-a:443"); got != "first_byte" {
		t.Errorf("server-a expected first_byte, got %q", got)
	}
	if got := b.pick("server-b:443"); got != "midpoint" {
		t.Errorf("server-b expected midpoint, got %q", got)
	}
}

func TestStrategyByNameFallback(t *testing.T) {
	// Unknown name should not panic — fall back to sni_split.
	fn := strategyByName("nonexistent_strategy_42")
	if fn == nil {
		t.Fatal("strategyByName returned nil for unknown name")
	}
	segs := fn(make([]byte, 100))
	if len(segs) == 0 {
		t.Error("fallback strategy returned 0 segments")
	}
}
