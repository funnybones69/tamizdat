package tamizdat

import (
	"encoding/hex"
	"testing"
)

// shortIDFromHex parses a 16-char hex string into an 8-byte shortID.
// Test-only helper; previously lived in shortid_derive_test.go which was
// removed in the shortid full-B simplification (2026-05-09).
func shortIDFromHex(t *testing.T, s string) [8]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	if len(b) != 8 {
		t.Fatalf("shortIDFromHex: want 8 bytes, got %d", len(b))
	}
	var id [8]byte
	copy(id[:], b)
	return id
}
