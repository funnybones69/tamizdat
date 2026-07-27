package tamizdat

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTURNProfileRoundtripPresent(t *testing.T) {
	src := &CoverConfigBundle{
		Version: 2,
		TURNProfile: &TURNProfileEntry{
			Version:    7,
			Provider:   "vk",
			RoomLink:   "https://vk.com/call/join/[REDACTED]",
			RoomHash:   "[REDACTED]",
			WGTurnPort: 5000,
		},
	}
	wire, err := src.MarshalForWire()
	if err != nil {
		t.Fatalf("MarshalForWire: %v", err)
	}
	if !strings.Contains(string(wire), `"turn_profile"`) {
		t.Fatalf("wire missing turn_profile: %s", string(wire))
	}
	var dst CoverConfigBundle
	if err := json.Unmarshal(wire, &dst); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if dst.TURNProfile == nil {
		t.Fatal("TURNProfile missing after unmarshal")
	}
	if dst.TURNProfile.Provider != "vk" || dst.TURNProfile.Version != 7 || dst.TURNProfile.WGTurnPort != 5000 {
		t.Fatalf("TURNProfile mismatch: %+v", dst.TURNProfile)
	}
}

func TestTURNProfileRoundtripAbsent(t *testing.T) {
	src := &CoverConfigBundle{Version: 1}
	wire, err := src.MarshalForWire()
	if err != nil {
		t.Fatalf("MarshalForWire: %v", err)
	}
	if strings.Contains(string(wire), "turn_profile") {
		t.Fatalf("wire should not contain turn_profile key when nil: %s", string(wire))
	}
}

func TestTURNProfileValidateRequiresRoom(t *testing.T) {
	b := &CoverConfigBundle{
		Version:     1,
		TURNProfile: &TURNProfileEntry{Provider: "vk", WGTurnPort: 5000},
	}
	if err := b.Validate(nil, false); err == nil {
		t.Fatal("Validate accepted turn_profile without room link/hash")
	} else if !strings.Contains(err.Error(), "turn_profile requires") {
		t.Fatalf("error text should mention missing room: %v", err)
	}
}

func TestTURNProfileValidatePortRange(t *testing.T) {
	b := &CoverConfigBundle{
		Version:     1,
		TURNProfile: &TURNProfileEntry{Provider: "vk", RoomHash: "abc", WGTurnPort: 70000},
	}
	if err := b.Validate(nil, false); err == nil {
		t.Fatal("Validate accepted out-of-range wgturn_port")
	} else if !strings.Contains(err.Error(), "wgturn_port") {
		t.Fatalf("error text should mention wgturn_port: %v", err)
	}
}
