package tamizdat

import (
	"bytes"
	"testing"
)

// helper: build a (psk, ephPub, shortID) triple for SessionID round-trip tests.
func newAuthTriple(t *testing.T) (psk, ephPub []byte, shortID [shortIDLen]byte) {
	t.Helper()
	serverPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ephPriv, ephPub, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("GenerateEphemeralKeyPair: %v", err)
	}
	shortID, err = GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	psk, err = DeriveServerPSK(serverPriv, ephPub, shortID)
	if err != nil {
		t.Fatalf("DeriveServerPSK: %v", err)
	}
	// Sanity: client side derives the same key.
	clientPSK, err := DeriveClientPSK(ephPriv, mustExtractPub(t, serverPriv), shortID)
	if err != nil {
		t.Fatalf("DeriveClientPSK: %v", err)
	}
	if !bytes.Equal(psk, clientPSK) {
		t.Fatalf("server and client PSK differ")
	}
	return psk, ephPub, shortID
}

func mustExtractPub(t *testing.T, priv []byte) []byte {
	t.Helper()
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	return pub
}

// TestVerifySessionIDv2Single_RoundTrip: client v2 build, server v2 verify
// returns OK. Sanity that the new wire format is end-to-end consistent.
func TestVerifySessionIDv2Single_RoundTrip(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	sid, err := BuildSessionIDv2(psk, shortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv2: %v", err)
	}
	ok, err := VerifySessionIDv2Single(sid[:], psk, ephPub, shortID)
	if err != nil {
		t.Fatalf("VerifySessionIDv2Single err: %v", err)
	}
	if !ok {
		t.Fatal("VerifySessionIDv2Single rejected its own build")
	}
}

// TestVerifySessionIDv1_v2_AreCrossIncompatible: v1-built SessionID must
// fail v2 verify (and vice versa) — the version byte 0x01 vs 0x02 is the
// only thing distinguishing them, so cross-version use must reject.
func TestVerifySessionIDv1_v2_AreCrossIncompatible(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	v1, err := BuildSessionIDv1(psk, shortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv1: %v", err)
	}
	v2, err := BuildSessionIDv2(psk, shortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv2: %v", err)
	}
	if ok, _ := VerifySessionIDv2Single(v1[:], psk, ephPub, shortID); ok {
		t.Fatal("v1 SessionID must NOT verify under v2 (HMAC tag prefix differs)")
	}
	if ok, _ := VerifySessionIDv1Single(v2[:], psk, ephPub, shortID); ok {
		t.Fatal("v2 SessionID must NOT verify under v1 (HMAC tag prefix differs)")
	}
}

// TestVerifySessionIDAny_AcceptsBothInWindow: with min=1/max=2 the rollout
// gate accepts either format — used by the live server during Phase 1.
func TestVerifySessionIDAny_AcceptsBothInWindow(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	v1, _ := BuildSessionIDv1(psk, shortID, ephPub, nil)
	v2, _ := BuildSessionIDv2(psk, shortID, ephPub, nil)

	gotV, ok, err := VerifySessionIDAny(v1[:], psk, ephPub, shortID, 1, 2)
	if err != nil || !ok || gotV != sessionIDVersionV1 {
		t.Fatalf("v1 in [1,2] window: ok=%v gotV=0x%02x err=%v", ok, gotV, err)
	}
	gotV, ok, err = VerifySessionIDAny(v2[:], psk, ephPub, shortID, 1, 2)
	if err != nil || !ok || gotV != sessionIDVersionV2 {
		t.Fatalf("v2 in [1,2] window: ok=%v gotV=0x%02x err=%v", ok, gotV, err)
	}
}

// TestVerifySessionIDAny_PhaseTwoRejectsV1: once the operator bumps min to 2
// (Phase 2 of the rollout) the server stops accepting legacy v1 SessionIDs.
func TestVerifySessionIDAny_PhaseTwoRejectsV1(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	v1, _ := BuildSessionIDv1(psk, shortID, ephPub, nil)
	v2, _ := BuildSessionIDv2(psk, shortID, ephPub, nil)

	if _, ok, _ := VerifySessionIDAny(v1[:], psk, ephPub, shortID, 2, 2); ok {
		t.Fatal("Phase-2 server (min=2) must reject v1 SessionID")
	}
	if _, ok, _ := VerifySessionIDAny(v2[:], psk, ephPub, shortID, 2, 2); !ok {
		t.Fatal("Phase-2 server (min=2) must accept v2 SessionID")
	}
}

// TestVerifySessionIDAny_ForwardCompatRejectsUnknownVersion: a SessionID
// built with a future version byte (e.g. 0x03) must reject when the server
// only understands [1, 2]. Today we cannot synthesize a v3 directly via the
// public API, so we tamper the HMAC tag against a v3 prefix using the
// internal sessionIDTag helper and confirm the server gate refuses.
func TestVerifySessionIDAny_ForwardCompatRejectsUnknownVersion(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	// Build a "v3"-like SessionID by computing the tag with version byte 0x03.
	var sid [sessionIDLen]byte
	copy(sid[:shortIDLen], shortID[:])
	// Random nonce just to keep wire sane; tag below uses it.
	for i := shortIDLen; i < shortIDLen+nonceLen; i++ {
		sid[i] = byte(i)
	}
	tag := sessionIDTag(psk, shortID, sid[shortIDLen:shortIDLen+nonceLen], ephPub, 0x03)
	copy(sid[shortIDLen+nonceLen:], tag)

	if _, ok, _ := VerifySessionIDAny(sid[:], psk, ephPub, shortID, 1, 2); ok {
		t.Fatal("server gate must reject SessionID with unknown future version byte")
	}
}

// TestVerifySessionIDv1Single_DropsAllowlistTautology: the slice-of-allowed-
// shortIDs form is preserved (Deprecated) but the new exact-match form is
// what the hot path uses. Both must agree on accept/reject.
func TestVerifySessionIDv1Single_DropsAllowlistTautology(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	sid, err := BuildSessionIDv1(psk, shortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv1: %v", err)
	}

	okSingle, err := VerifySessionIDv1Single(sid[:], psk, ephPub, shortID)
	if err != nil {
		t.Fatalf("VerifySessionIDv1Single err: %v", err)
	}
	if !okSingle {
		t.Fatal("v1 single-version verify rejected its own build")
	}

	verified, okSlice, err := VerifySessionIDv1(sid[:], psk, ephPub, [][shortIDLen]byte{shortID})
	if err != nil || !okSlice {
		t.Fatalf("legacy slice form rejected: ok=%v err=%v", okSlice, err)
	}
	if verified != shortID {
		t.Fatal("legacy slice form returned wrong shortID")
	}

	// Wrong expected shortID rejects under exact-match.
	var other [shortIDLen]byte
	copy(other[:], shortID[:])
	other[0] ^= 0xFF
	if ok, _ := VerifySessionIDv1Single(sid[:], psk, ephPub, other); ok {
		t.Fatal("exact-match must reject when expectedShortID does not match SessionID prefix")
	}
}
