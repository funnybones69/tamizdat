package tamizdat

import (
	"testing"
)

// TestExtractX25519FromKeyShare verifies the standard-key_share parser
// against synthesized ClientHellos.
func TestExtractX25519FromKeyShare_Standalone(t *testing.T) {
	// ClientHello with one X25519 entry in key_share.
	ch := buildKeyShareClientHello(t, []keyShareEntry{
		{group: 0x001D, key: bytes32slice(0x42)},
	})
	got, err := ExtractX25519FromKeyShare(ch)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got != bytes32(0x42) {
		t.Errorf("got pub = %x, want %x", got, bytes32(0x42))
	}
}

func TestExtractX25519FromKeyShare_HybridFirst(t *testing.T) {
	// Hybrid X25519MLKEM768 entry FIRST + standalone X25519 SECOND.
	// Parser must skip the hybrid and return the standalone (compass v2 §5.1
	// edge case: client must NOT use MlkemEcdhe pubkey for samizdat auth).
	hybridKey := make([]byte, 1216) // X25519MLKEM768 length
	for i := range hybridKey {
		hybridKey[i] = byte(i)
	}
	ch := buildKeyShareClientHello(t, []keyShareEntry{
		{group: 0x11EC, key: hybridKey}, // X25519MLKEM768
		{group: 0x001D, key: bytes32slice(0x99)},
	})
	got, err := ExtractX25519FromKeyShare(ch)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got != bytes32(0x99) {
		t.Errorf("got pub = %x, want standalone X25519 0x99...", got)
	}
}

func TestExtractX25519FromKeyShare_NoStandalone(t *testing.T) {
	// Only hybrid entry — must fail (we don't accept hybrid for samizdat auth).
	hybridKey := make([]byte, 1216)
	ch := buildKeyShareClientHello(t, []keyShareEntry{
		{group: 0x11EC, key: hybridKey},
	})
	_, err := ExtractX25519FromKeyShare(ch)
	if err == nil {
		t.Error("expected error when only hybrid X25519MLKEM768 present, got nil")
	}
}

func TestExtractX25519FromKeyShare_NoKeyShareExt(t *testing.T) {
	ch := buildKeyShareClientHello(t, nil) // no key_share extension at all
	_, err := ExtractX25519FromKeyShare(ch)
	if err == nil {
		t.Error("expected error when key_share extension absent")
	}
}

// === helpers ===

type keyShareEntry struct {
	group uint16
	key   []byte
}

func bytes32slice(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// buildKeyShareClientHello builds a minimal valid ClientHello payload (without
// the 5-byte record header) carrying the supplied key_share entries.
func buildKeyShareClientHello(t *testing.T, entries []keyShareEntry) []byte {
	t.Helper()

	// Build extensions: only key_share if entries non-nil.
	exts := []byte{}
	if entries != nil {
		// key_share content: list_length(2) + entries
		list := []byte{}
		for _, e := range entries {
			ent := []byte{
				byte(e.group >> 8), byte(e.group),
				byte(len(e.key) >> 8), byte(len(e.key)),
			}
			ent = append(ent, e.key...)
			list = append(list, ent...)
		}
		body := []byte{byte(len(list) >> 8), byte(len(list))}
		body = append(body, list...)
		// extension header: type(2) + length(2)
		ext := []byte{0x00, 0x33, byte(len(body) >> 8), byte(len(body))}
		ext = append(ext, body...)
		exts = ext
	}

	// extensions block = 2-byte length + ext bytes
	extBlock := []byte{byte(len(exts) >> 8), byte(len(exts))}
	extBlock = append(extBlock, exts...)

	// ClientHello body.
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id_len = 0
	// cipher_suites: 1 cipher
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	// compression_methods: 1 null
	body = append(body, 0x01, 0x00)
	body = append(body, extBlock...)

	// Handshake header: type(1)=ClientHello + length(3)
	out := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	out = append(out, body...)
	return out
}
