package tamizdat

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// authLabel is the HKDF info string for deriving the auth key.
	authLabel = "TAMIZDAT v1"
	// authKeyLen is the length of the derived HMAC key.
	authKeyLen = 32
	// sessionIDLen is the TLS SessionID field length.
	sessionIDLen = 32
	// hmacTagLen is the truncated HMAC-SHA256 tag length in the SessionID.
	hmacTagLen = 16
	// shortIDLen is the length of the pre-shared short identifier.
	shortIDLen = 8
	// nonceLen is the auth nonce length (8 bytes to fit in SessionID layout:
	// 8 shortID + 8 nonce + 16 HMAC tag = 32 bytes).
	nonceLen = 8
	// x25519KeyLen is the encoded length of X25519 public/private keys and shared secrets.
	x25519KeyLen = 32

	// sessionIDVersionV1 / sessionIDVersionV2 are the HMAC tag-prefix bytes
	// distinguishing wire formats. v1 is the legacy fresh-random-per-dial
	// SessionID; v2 keeps the same layout but is built by the client from a
	// cached (server_addr, shortID) -> 6-byte stable random + 2-byte
	// per-dial counter so the SessionID prefix is stable across reconnects
	// within session-ticket lifetime (review-C tell #12 - Wu/Xue 2024).
	sessionIDVersionV1 byte = 0x01
	sessionIDVersionV2 byte = 0x02
)

// GenerateKeyPair generates a new X25519 keypair for use as server credentials.
// Returns (privateKey, publicKey, error).
func GenerateKeyPair() ([]byte, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// GenerateShortID generates a random 8-byte short identifier.
func GenerateShortID() ([shortIDLen]byte, error) {
	var id [shortIDLen]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf("generating short ID: %w", err)
	}
	return id, nil
}

// PublicKeyFromPrivate computes the X25519 public key for a raw 32-byte private key.
func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	return priv.PublicKey().Bytes(), nil
}

// GenerateEphemeralKeyPair generates a fresh X25519 keypair for one client dial.
// The returned private key must be discarded after the SessionID/PSK are built.
func GenerateEphemeralKeyPair() (privateKey []byte, publicKey []byte, err error) {
	return GenerateKeyPair()
}

// ECDHSharedSecret computes X25519(privateKey, peerPublicKey).
func ECDHSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != x25519KeyLen {
		return nil, fmt.Errorf("X25519 private key length %d, want %d", len(privateKey), x25519KeyLen)
	}
	if len(peerPublicKey) != x25519KeyLen {
		return nil, fmt.Errorf("X25519 public key length %d, want %d", len(peerPublicKey), x25519KeyLen)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	return shared, nil
}

// derivePSK derives a 32-byte auth key with HKDF-SHA256.
//
// P0.3 ECDH-A changed the IKM from the legacy public server key to the
// X25519 shared secret. The signature remains []byte + shortID so legacy
// callers still compile until ECDH-C wires the new ECDH flow into client/server.
func derivePSK(sharedSecret []byte, shortID [shortIDLen]byte) ([]byte, error) {
	if len(sharedSecret) != x25519KeyLen {
		return nil, fmt.Errorf("shared secret length %d, want %d", len(sharedSecret), x25519KeyLen)
	}
	// salt = shortID, ikm = X25519 shared secret, info = "TAMIZDAT v1".
	hkdfReader := hkdf.New(sha256.New, sharedSecret, shortID[:], []byte(authLabel))
	key := make([]byte, authKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return key, nil
}

// DerivePSKFromSharedSecret derives the P0.3 auth key from an X25519 shared secret.
func DerivePSKFromSharedSecret(sharedSecret []byte, shortID [shortIDLen]byte) ([]byte, error) {
	return derivePSK(sharedSecret, shortID)
}

// DeriveClientPSK derives the P0.3 auth key on the client from its ephemeral
// private key and the server's long-lived static public key.
func DeriveClientPSK(ephemeralPrivateKey, serverPublicKey []byte, shortID [shortIDLen]byte) ([]byte, error) {
	shared, err := ECDHSharedSecret(ephemeralPrivateKey, serverPublicKey)
	if err != nil {
		return nil, err
	}
	return derivePSK(shared, shortID)
}

// DeriveServerPSK derives the P0.3 auth key on the server from its long-lived
// static private key and the client's ephemeral public key.
func DeriveServerPSK(serverPrivateKey, ephemeralPublicKey []byte, shortID [shortIDLen]byte) ([]byte, error) {
	shared, err := ECDHSharedSecret(serverPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	return derivePSK(shared, shortID)
}

// BuildSessionIDv1 constructs a P0.3 SessionID.
// Layout: shortID(8) || nonce(8) || hmac_tag(16), where
// hmac_tag = HMAC-SHA256(PSK, version || shortID || nonce || eph_pub)[:16].
// If nonce is nil, a fresh random nonce is generated; otherwise it must be 8 bytes.
func BuildSessionIDv1(psk []byte, shortID [shortIDLen]byte, ephemeralPublicKey []byte, nonce []byte) ([sessionIDLen]byte, error) {
	return buildSessionID(psk, shortID, ephemeralPublicKey, nonce, sessionIDVersionV1)
}

// BuildSessionIDv2 constructs a SessionID with the v2 HMAC version tag.
// Wire layout is identical to v1 (shortID(8) || nonce(8) || hmac_tag(16)),
// but the HMAC input is prefixed with 0x02 instead of 0x01.
//
// review-C tell #12 (Wu/Xue 2024): real Chrome 131+ keeps the SessionID
// stable across reconnects within session-ticket lifetime. The client
// caches a 6-byte stable random per (server_addr, shortID) and uses a
// 2-byte counter for the trailing nonce bytes - caller composes the
// 8-byte nonce as `stable_random_6 || counter_uint16_be` and passes it
// here. The counter ensures the replay key
// (`SHA-256(SessionID || eph_pub)[:16]`) stays unique across dials so
// the server-side replay window protection is preserved unchanged.
//
// If nonce is nil, a fresh random 8-byte nonce is generated (same as v1)
// - used by tests and by the cache miss path before the cache has been
// seeded with a stable random.
func BuildSessionIDv2(psk []byte, shortID [shortIDLen]byte, ephemeralPublicKey []byte, nonce []byte) ([sessionIDLen]byte, error) {
	return buildSessionID(psk, shortID, ephemeralPublicKey, nonce, sessionIDVersionV2)
}

func buildSessionID(psk []byte, shortID [shortIDLen]byte, ephemeralPublicKey []byte, nonce []byte, version byte) ([sessionIDLen]byte, error) {
	var sessionID [sessionIDLen]byte
	if len(psk) != authKeyLen {
		return sessionID, fmt.Errorf("PSK length %d, want %d", len(psk), authKeyLen)
	}
	if len(ephemeralPublicKey) != x25519KeyLen {
		return sessionID, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}

	copy(sessionID[:shortIDLen], shortID[:])
	nonceDst := sessionID[shortIDLen : shortIDLen+nonceLen]
	if nonce == nil {
		if _, err := io.ReadFull(rand.Reader, nonceDst); err != nil {
			return sessionID, fmt.Errorf("generating nonce: %w", err)
		}
	} else {
		if len(nonce) != nonceLen {
			return sessionID, fmt.Errorf("nonce length %d, want %d", len(nonce), nonceLen)
		}
		copy(nonceDst, nonce)
	}

	tag := sessionIDTag(psk, shortID, nonceDst, ephemeralPublicKey, version)
	copy(sessionID[shortIDLen+nonceLen:], tag)
	return sessionID, nil
}

// VerifySessionIDv1 checks whether a P0.3 SessionID contains a valid tag bound
// to the provided ephemeral public key and one allowed shortID.
//
// Deprecated: prefer VerifySessionIDv1Single (single expected shortID) or
// VerifySessionIDAny (accepts both v1 and v2 wire formats during the rollout
// window). The slice-of-allowed-shortIDs form is retained for historical
// callers / tests that explicitly want allowlist semantics.
func VerifySessionIDv1(sessionID []byte, psk []byte, ephemeralPublicKey []byte, allowedShortIDs [][shortIDLen]byte) ([shortIDLen]byte, bool, error) {
	return verifySessionIDSlice(sessionID, psk, ephemeralPublicKey, allowedShortIDs, sessionIDVersionV1)
}

// VerifySessionIDv1Single is the exact-match version of VerifySessionIDv1:
// it verifies only against `expectedShortID` and skips the linear allowlist
// scan. Hot-path callers (handleConnection) use this - they already know
// which shortID the SessionID claims (first 8 bytes), and the allowlist
// check there was tautological since the slice was always [{shortID}].
func VerifySessionIDv1Single(sessionID []byte, psk []byte, ephemeralPublicKey []byte, expectedShortID [shortIDLen]byte) (bool, error) {
	return verifySessionIDExact(sessionID, psk, ephemeralPublicKey, expectedShortID, sessionIDVersionV1)
}

// VerifySessionIDv2Single verifies a v2 SessionID against a single expected
// shortID. v2 uses HMAC tag-prefix 0x02; the wire layout (32 bytes:
// shortID(8)+nonce(8)+tag(16)) is identical to v1 - only the tag-prefix byte
// differs. The replay-key calculation upstream is unchanged
// (`SHA-256(SessionID || eph_pub)[:16]`); uniqueness across dials is now
// provided by the 2-byte counter in the nonce field, since the same client
// reuses the 6-byte stable random across reconnects.
func VerifySessionIDv2Single(sessionID []byte, psk []byte, ephemeralPublicKey []byte, expectedShortID [shortIDLen]byte) (bool, error) {
	return verifySessionIDExact(sessionID, psk, ephemeralPublicKey, expectedShortID, sessionIDVersionV2)
}

// VerifySessionIDAny tries the active wire versions in
// [minAccepted .. maxAccepted] (inclusive) against expectedShortID and
// returns success on the first match. Used during the v1->v2 transition
// where both wire formats coexist on production servers. Server-side
// gating is enforced by ServerConfig.MinAcceptedWireVersion (default 1)
// and ServerConfig.MaxAcceptedWireVersion (default 2). Wire versions
// outside the supported range [1..2] are rejected (forward-compat:
// server refuses unknown future bumps until upgraded).
//
// Returns (matchedVersion, true, nil) on success and (0, false, nil) on
// reject. Returned version is the byte that matched (1 or 2).
func VerifySessionIDAny(sessionID []byte, psk []byte, ephemeralPublicKey []byte, expectedShortID [shortIDLen]byte, minAccepted, maxAccepted int) (byte, bool, error) {
	if minAccepted < int(sessionIDVersionV1) {
		minAccepted = int(sessionIDVersionV1)
	}
	if maxAccepted > int(sessionIDVersionV2) {
		maxAccepted = int(sessionIDVersionV2)
	}
	if minAccepted > maxAccepted {
		return 0, false, nil
	}
	for v := minAccepted; v <= maxAccepted; v++ {
		ok, err := verifySessionIDExact(sessionID, psk, ephemeralPublicKey, expectedShortID, byte(v))
		if err != nil {
			return 0, false, err
		}
		if ok {
			return byte(v), true, nil
		}
	}
	return 0, false, nil
}

func verifySessionIDExact(sessionID []byte, psk []byte, ephemeralPublicKey []byte, expectedShortID [shortIDLen]byte, version byte) (bool, error) {
	if len(sessionID) != sessionIDLen {
		return false, nil
	}
	if len(psk) != authKeyLen {
		return false, fmt.Errorf("PSK length %d, want %d", len(psk), authKeyLen)
	}
	if len(ephemeralPublicKey) != x25519KeyLen {
		return false, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}
	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])
	if candidateShortID != expectedShortID {
		return false, nil
	}
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]
	expectedTag := sessionIDTag(psk, candidateShortID, nonce, ephemeralPublicKey, version)
	if !hmac.Equal(tag, expectedTag) {
		return false, nil
	}
	return true, nil
}

func verifySessionIDSlice(sessionID []byte, psk []byte, ephemeralPublicKey []byte, allowedShortIDs [][shortIDLen]byte, version byte) ([shortIDLen]byte, bool, error) {
	var zero [shortIDLen]byte
	if len(sessionID) != sessionIDLen {
		return zero, false, nil
	}
	if len(psk) != authKeyLen {
		return zero, false, fmt.Errorf("PSK length %d, want %d", len(psk), authKeyLen)
	}
	if len(ephemeralPublicKey) != x25519KeyLen {
		return zero, false, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}

	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])
	if !shortIDAllowed(candidateShortID, allowedShortIDs) {
		return zero, false, nil
	}
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]
	expectedTag := sessionIDTag(psk, candidateShortID, nonce, ephemeralPublicKey, version)
	if !hmac.Equal(tag, expectedTag) {
		return zero, false, nil
	}
	return candidateShortID, true, nil
}

// VerifySessionIDv1WithServerKey derives the PSK from serverPrivateKey and
// ephemeralPublicKey, then verifies the v1 SessionID.
func VerifySessionIDv1WithServerKey(sessionID []byte, serverPrivateKey []byte, ephemeralPublicKey []byte, allowedShortIDs [][shortIDLen]byte) ([shortIDLen]byte, bool, error) {
	var zero [shortIDLen]byte
	if len(sessionID) != sessionIDLen {
		return zero, false, nil
	}
	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])

	// Timing-oracle hardening: derive and verify the HMAC for the candidate
	// shortID before consulting the server's allowed-shortID pool. Unknown
	// shortIDs and known-shortID/bad-tag probes therefore both pay the same
	// X25519+HKDF+HMAC cost before they fail.
	psk, err := DeriveServerPSK(serverPrivateKey, ephemeralPublicKey, candidateShortID)
	if err != nil {
		return zero, false, err
	}
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]
	expectedTag := sessionIDTag(psk, candidateShortID, nonce, ephemeralPublicKey, sessionIDVersionV1)
	tagOK := hmac.Equal(tag, expectedTag)
	allowed := shortIDAllowed(candidateShortID, allowedShortIDs)
	if !tagOK || !allowed {
		return zero, false, nil
	}
	return candidateShortID, true, nil
}

// sessionIDTag computes the HMAC-SHA256 tag for the given version (0x01 v1, 0x02 v2).
func sessionIDTag(psk []byte, shortID [shortIDLen]byte, nonce []byte, ephemeralPublicKey []byte, version byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{version})
	mac.Write(shortID[:])
	mac.Write(nonce)
	mac.Write(ephemeralPublicKey)
	return mac.Sum(nil)[:hmacTagLen]
}

// sessionIDTagV1 is the v1-only specialization kept for callers that hard-code
// the v1 byte (avoids passing a literal 0x01 at every call site).
func sessionIDTagV1(psk []byte, shortID [shortIDLen]byte, nonce []byte, ephemeralPublicKey []byte) []byte {
	return sessionIDTag(psk, shortID, nonce, ephemeralPublicKey, sessionIDVersionV1)
}

func shortIDAllowed(candidate [shortIDLen]byte, allowedShortIDs [][shortIDLen]byte) bool {
	for _, allowed := range allowedShortIDs {
		if candidate == allowed {
			return true
		}
	}
	return false
}

// derivePublicKey computes the X25519 public key from a private key.
// Returns both the original private key and the derived public key.
func derivePublicKey(privateKey []byte) ([]byte, []byte, error) {
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing public key: %w", err)
	}
	return privateKey, publicKey, nil
}

// ExtractSessionID extracts the session_id field from raw ClientHello bytes.
func ExtractSessionID(clientHello []byte) ([]byte, error) {
	if len(clientHello) < 6 {
		return nil, errors.New("ClientHello too short")
	}

	pos := 0
	if clientHello[0] == 0x01 { // HandshakeTypeClientHello
		if len(clientHello) < 4 {
			return nil, errors.New("ClientHello too short for handshake header")
		}
		pos = 4
	}

	// Skip client_version(2) + random(32)
	pos += 2 + 32
	if pos >= len(clientHello) {
		return nil, errors.New("ClientHello too short for session_id length")
	}

	sessionIDLength := int(clientHello[pos])
	pos++
	if pos+sessionIDLength > len(clientHello) {
		return nil, errors.New("ClientHello session_id exceeds data")
	}

	sessionID := make([]byte, sessionIDLength)
	copy(sessionID, clientHello[pos:pos+sessionIDLength])
	return sessionID, nil
}
