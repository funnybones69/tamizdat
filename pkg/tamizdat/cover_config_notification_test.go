package tamizdat

import (
	"encoding/json"
	"strings"
	"testing"
)

// Stage 3 (2026-05-10): Notification field roundtrips through MarshalForWire
// and back through Unmarshal. Tests cover present + omitted cases and
// validation of Code-required-when-set.
func TestNotificationRoundtrip_Present(t *testing.T) {
	src := &CoverConfigBundle{
		Version: 1,
		Notification: &NotificationEntry{
			Code:   "quota_exhausted",
			Title:  "Квота исчерпана",
			Body:   "Лимит трафика исчерпан.",
			Locale: "ru",
		},
	}
	wire, err := src.MarshalForWire()
	if err != nil {
		t.Fatalf("MarshalForWire: %v", err)
	}
	if !strings.Contains(string(wire), `"notification"`) {
		t.Fatalf("wire missing notification: %s", string(wire))
	}
	var dst CoverConfigBundle
	if err := json.Unmarshal(wire, &dst); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if dst.Notification == nil {
		t.Fatal("Notification missing after unmarshal")
	}
	if dst.Notification.Code != "quota_exhausted" {
		t.Fatalf("Code mismatch: got %q", dst.Notification.Code)
	}
	if dst.Notification.Title != "Квота исчерпана" {
		t.Fatalf("Title mismatch: got %q", dst.Notification.Title)
	}
	if dst.Notification.Locale != "ru" {
		t.Fatalf("Locale mismatch: got %q", dst.Notification.Locale)
	}
}

// Notification omitted when nil — JSON output must not contain the key
// (clients on older wire codecs will get the same bytes they did pre-Stage-3).
func TestNotificationRoundtrip_Absent(t *testing.T) {
	src := &CoverConfigBundle{Version: 1}
	wire, err := src.MarshalForWire()
	if err != nil {
		t.Fatalf("MarshalForWire: %v", err)
	}
	if strings.Contains(string(wire), "notification") {
		t.Fatalf("wire should not contain notification key when nil: %s", string(wire))
	}
}

// Validate rejects a notification with empty Code.
func TestNotificationValidate_RequiresCode(t *testing.T) {
	b := &CoverConfigBundle{
		Version:      1,
		Notification: &NotificationEntry{Code: "  ", Title: "x"},
	}
	if err := b.Validate(nil, false); err == nil {
		t.Fatal("Validate accepted notification with empty code")
	} else if !strings.Contains(err.Error(), "notification.code") {
		t.Fatalf("error text should mention notification.code: %v", err)
	}
}

// Validate accepts a Notification with code only (Title/Body/Locale optional).
func TestNotificationValidate_CodeOnlyOK(t *testing.T) {
	b := &CoverConfigBundle{
		Version:      1,
		Notification: &NotificationEntry{Code: "expired"},
	}
	if err := b.Validate(nil, false); err != nil {
		t.Fatalf("Validate rejected code-only notification: %v", err)
	}
}
