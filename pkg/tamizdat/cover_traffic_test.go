package tamizdat

import (
	"strings"
	"testing"
)

// TestDefaultCoverTargets verifies the diversified cover-target pool is
// non-empty and every entry is host:port form on the canonical TLS port 443.
//
// Cover targets are by-design HTTPS endpoints (we mimic a browser making
// background fetches to RU CDN/analytics sites) so :443 is a hard
// requirement, not over-fitting.
//
// We additionally check for at least one subdomain entry (e.g. mc.yandex.ru)
// to enforce traffic-shape diversity (compass v3 cleanup: avoid the old
// 5-homepage default that produced a homogeneous flow profile).
func TestDefaultCoverTargets(t *testing.T) {
	got := defaultCoverTargets()
	if len(got) < 5 {
		t.Fatalf("defaultCoverTargets returned %d entries, want >=5 for diversity", len(got))
	}
	for _, target := range got {
		if !strings.HasSuffix(target, ":443") {
			t.Errorf("cover target %q must end in :443 (cover traffic must look like HTTPS)", target)
		}
		host := strings.TrimSuffix(target, ":443")
		if host == "" || strings.ContainsAny(host, " /") {
			t.Errorf("cover target %q has malformed host part", target)
		}
	}
	hasSubdomain := false
	for _, target := range got {
		host := strings.TrimSuffix(target, ":443")
		if strings.Count(host, ".") >= 2 {
			hasSubdomain = true
			break
		}
	}
	if !hasSubdomain {
		t.Error("defaultCoverTargets is too homogeneous: expected at least one subdomain for traffic-shape diversity")
	}
}

// TestCoverGapBounds verifies the gap helper stays within configured bounds.
func TestCoverGapBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		gap := coverRandUint64n(uint64(coverGapMax - coverGapMin))
		if gap >= uint64(coverGapMax-coverGapMin) {
			t.Errorf("iter %d: gap %d >= max %d", i, gap, coverGapMax-coverGapMin)
		}
	}
}
