package tamizdat

import (
	"testing"
	"time"
)

func TestVerifySessionIDWithServerKeyShortIDTimingSimilar(t *testing.T) {
	serverPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(server): %v", err)
	}
	ephPriv, ephPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(ephemeral): %v", err)
	}
	_ = ephPriv

	goodShortID := [shortIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	badShortID := [shortIDLen]byte{8, 7, 6, 5, 4, 3, 2, 1}
	allowed := [][shortIDLen]byte{goodShortID}

	goodPSK, err := DeriveServerPSK(serverPriv, ephPub, goodShortID)
	if err != nil {
		t.Fatalf("DeriveServerPSK(good): %v", err)
	}
	goodBadTag, err := BuildSessionIDv1(goodPSK, goodShortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv1(good): %v", err)
	}
	goodBadTag[sessionIDLen-1] ^= 0x80

	badPSK, err := DeriveServerPSK(serverPriv, ephPub, badShortID)
	if err != nil {
		t.Fatalf("DeriveServerPSK(bad): %v", err)
	}
	badShortIDValidTag, err := BuildSessionIDv1(badPSK, badShortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv1(bad): %v", err)
	}

	// Warm CPU caches and curve setup.
	for i := 0; i < 10; i++ {
		_, _, _ = VerifySessionIDv1WithServerKey(goodBadTag[:], serverPriv, ephPub, allowed)
		_, _, _ = VerifySessionIDv1WithServerKey(badShortIDValidTag[:], serverPriv, ephPub, allowed)
	}

	measure := func(session []byte) time.Duration {
		start := time.Now()
		for i := 0; i < 100; i++ {
			_, ok, err := VerifySessionIDv1WithServerKey(session, serverPriv, ephPub, allowed)
			if err != nil {
				t.Fatalf("VerifySessionIDv1WithServerKey: %v", err)
			}
			if ok {
				t.Fatal("invalid session unexpectedly verified")
			}
		}
		return time.Since(start)
	}

	badShortIDDuration := measure(badShortIDValidTag[:])
	goodBadTagDuration := measure(goodBadTag[:])
	diff := badShortIDDuration - goodBadTagDuration
	if diff < 0 {
		diff = -diff
	}
	maxDuration := badShortIDDuration
	if goodBadTagDuration > maxDuration {
		maxDuration = goodBadTagDuration
	}
	if diff > maxDuration/2+2*time.Millisecond {
		t.Fatalf("timing diverged too much: bad-shortID=%s good-shortID-bad-tag=%s diff=%s", badShortIDDuration, goodBadTagDuration, diff)
	}
}
