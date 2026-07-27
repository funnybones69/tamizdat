package tamizdat

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func TestECDHAgreementRFC7748Vector(t *testing.T) {
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	expectedShared := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	gotAlicePub, err := PublicKeyFromPrivate(alicePriv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate(alice): %v", err)
	}
	if !bytes.Equal(gotAlicePub, alicePub) {
		t.Fatalf("alice public key mismatch\n got %x\nwant %x", gotAlicePub, alicePub)
	}
	gotBobPub, err := PublicKeyFromPrivate(bobPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate(bob): %v", err)
	}
	if !bytes.Equal(gotBobPub, bobPub) {
		t.Fatalf("bob public key mismatch\n got %x\nwant %x", gotBobPub, bobPub)
	}

	aliceShared, err := ECDHSharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("ECDHSharedSecret(alice,bob): %v", err)
	}
	bobShared, err := ECDHSharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("ECDHSharedSecret(bob,alice): %v", err)
	}
	if !bytes.Equal(aliceShared, expectedShared) {
		t.Fatalf("alice shared mismatch\n got %x\nwant %x", aliceShared, expectedShared)
	}
	if !bytes.Equal(bobShared, expectedShared) {
		t.Fatalf("bob shared mismatch\n got %x\nwant %x", bobShared, expectedShared)
	}
}

func TestDerivePSKHKDFSHA256Vector(t *testing.T) {
	shared := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	expected := mustHex(t, "2970598714616771d32347ea1b3d1f17adb5322c66dd802592aa219017df3139")

	got, err := DerivePSKFromSharedSecret(shared, shortID)
	if err != nil {
		t.Fatalf("DerivePSKFromSharedSecret: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("PSK mismatch\n got %x\nwant %x", got, expected)
	}
}

func TestSessionIDV1VectorAndVerify(t *testing.T) {
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := [nonceLen]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	expectedSID := mustHex(t, "01020304050607080011223344556677e29e0733847160f5515a607a5009f03e")

	clientPSK, err := DeriveClientPSK(alicePriv, bobPub, shortID)
	if err != nil {
		t.Fatalf("DeriveClientPSK: %v", err)
	}
	sid, err := BuildSessionIDv1(clientPSK, shortID, alicePub, nonce[:])
	if err != nil {
		t.Fatalf("BuildSessionIDv1: %v", err)
	}
	if !bytes.Equal(sid[:], expectedSID) {
		t.Fatalf("SessionID mismatch\n got %x\nwant %x", sid, expectedSID)
	}

	serverPSK, err := DeriveServerPSK(bobPriv, alicePub, shortID)
	if err != nil {
		t.Fatalf("DeriveServerPSK: %v", err)
	}
	if !bytes.Equal(clientPSK, serverPSK) {
		t.Fatalf("client/server PSK mismatch\nclient %x\nserver %x", clientPSK, serverPSK)
	}
	gotShortID, ok, err := VerifySessionIDv1(sid[:], serverPSK, alicePub, [][shortIDLen]byte{shortID})
	if err != nil {
		t.Fatalf("VerifySessionIDv1: %v", err)
	}
	if !ok || gotShortID != shortID {
		t.Fatalf("VerifySessionIDv1 = (%x,%v), want (%x,true)", gotShortID, ok, shortID)
	}
}

func TestSessionIDV1BindsEphemeralPublicKey(t *testing.T) {
	psk := mustHex(t, "2970598714616771d32347ea1b3d1f17adb5322c66dd802592aa219017df3139")
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := [nonceLen]byte{8, 7, 6, 5, 4, 3, 2, 1}
	ephPub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	sid, err := BuildSessionIDv1(psk, shortID, ephPub, nonce[:])
	if err != nil {
		t.Fatalf("BuildSessionIDv1: %v", err)
	}
	_, ok, err := VerifySessionIDv1(sid[:], psk, ephPub, [][shortIDLen]byte{shortID})
	if err != nil || !ok {
		t.Fatalf("VerifySessionIDv1(valid) = %v, %v", ok, err)
	}

	tampered := append([]byte(nil), ephPub...)
	tampered[0] ^= 0x80
	_, ok, err = VerifySessionIDv1(sid[:], psk, tampered, [][shortIDLen]byte{shortID})
	if err != nil {
		t.Fatalf("VerifySessionIDv1(tampered): %v", err)
	}
	if ok {
		t.Fatal("VerifySessionIDv1 accepted SessionID after eph_pub tamper")
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{byte(0x01)})
	mac.Write(shortID[:])
	mac.Write(nonce[:])
	mac.Write(tampered)
	tamperedTag := mac.Sum(nil)[:hmacTagLen]
	if hmac.Equal(sid[shortIDLen+nonceLen:], tamperedTag) {
		t.Fatal("test vector unexpectedly did not depend on eph_pub")
	}
}

func TestSessionIDV1RejectsLegacyBinding(t *testing.T) {
	psk := mustHex(t, "2970598714616771d32347ea1b3d1f17adb5322c66dd802592aa219017df3139")
	shortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	nonce := [nonceLen]byte{1, 1, 2, 3, 5, 8, 13, 21}
	ephPub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	var legacy [sessionIDLen]byte
	copy(legacy[:shortIDLen], shortID[:])
	copy(legacy[shortIDLen:shortIDLen+nonceLen], nonce[:])
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce[:])
	copy(legacy[shortIDLen+nonceLen:], mac.Sum(nil)[:hmacTagLen])

	_, ok, err := VerifySessionIDv1(legacy[:], psk, ephPub, [][shortIDLen]byte{shortID})
	if err != nil {
		t.Fatalf("VerifySessionIDv1(legacy): %v", err)
	}
	if ok {
		t.Fatal("VerifySessionIDv1 accepted legacy HMAC(nonce) binding")
	}
}
