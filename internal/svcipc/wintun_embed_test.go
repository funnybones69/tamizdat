package svcipc

import "testing"

func TestEmbeddedWintunSHA256Pinned(t *testing.T) {
	if got := EmbeddedWintunSHA256(); got != WintunSHA256 {
		t.Fatalf("embedded wintun sha256=%s want %s", got, WintunSHA256)
	}
}
