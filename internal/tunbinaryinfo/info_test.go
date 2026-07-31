package tunbinaryinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentDescribesSixRoomReleaseContract(t *testing.T) {
	i := Current()
	if i.MaxRooms != 6 || i.MaxWorkersPerRoom != 20 || i.MaxWorkersTotal != 120 {
		t.Fatalf("limits=%d x %d = %d, want 6 x 20 = 120", i.MaxRooms, i.MaxWorkersPerRoom, i.MaxWorkersTotal)
	}
	required := []string{
		"autonomous_captcha_rjs",
		"bond_traffic_shaper",
		"credential_generation_safe_invalidation",
		"inner_tcp",
		"inner_udp",
		"per_room_credentials",
		"quota_rotation_after_attach",
		"retry_uses_latest_credentials",
		"wgturn_bond_v2",
	}
	features := make(map[string]bool, len(i.Features))
	for _, feature := range i.Features {
		features[feature] = true
	}
	for _, feature := range required {
		if !features[feature] {
			t.Fatalf("required capability %q is absent", feature)
		}
	}
}

func TestCurrentIsMachineReadable(t *testing.T) {
	b, err := json.Marshal(Current())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"max_rooms":6`) || !strings.Contains(string(b), `"max_workers_total":120`) {
		t.Fatalf("unexpected capability JSON: %s", b)
	}
}

func TestVersionLineCannotGrowExtraLines(t *testing.T) {
	oldVersion, oldBuildID := Version, BuildID
	defer func() { Version, BuildID = oldVersion, oldBuildID }()
	Version = "release\nspoof"
	BuildID = "build with spaces"
	line := VersionLine()
	if strings.ContainsAny(line, "\r\n") || !strings.Contains(line, "version=release_spoof") || !strings.Contains(line, "build_id=build_with_spaces") {
		t.Fatalf("unsafe version line: %q", line)
	}
}
