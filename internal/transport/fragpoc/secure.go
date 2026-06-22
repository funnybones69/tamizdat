package fragpoc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Canonical secure opcodes. Kept for AD derivation and backward-compatible servers.
	OpOpenSecure  byte = 0x81
	OpUpSecure    byte = 0x82
	OpDownSecure  byte = 0x83
	OpCloseSecure byte = 0x84

	// Historical low-byte aliases accepted by servers. New clients instead reuse
	// the plain opcode bytes (0x01..0x04) for secure sessions because the LTE path
	// under test stalls even on 0x06, while AEAD AD still uses canonical opcodes.
	OpOpenSecureCompat  byte = 0x06
	OpUpSecureCompat    byte = 0x07
	OpDownSecureCompat  byte = 0x08
	OpCloseSecureCompat byte = 0x09

	secureOverhead        = chacha20poly1305.Overhead
	secureNonceLen        = chacha20poly1305.NonceSize
	secureOpenMarker byte = '!'
)

func isSecureOp(op byte) bool {
	return (op >= OpOpenSecure && op <= OpCloseSecure) || (op >= OpOpenSecureCompat && op <= OpCloseSecureCompat)
}

func secureWireOp(op byte) byte {
	switch op {
	case OpOpenSecure:
		return OpOpen
	case OpUpSecure:
		return OpUp
	case OpDownSecure:
		return OpDown
	case OpCloseSecure:
		return OpClose
	default:
		return op
	}
}

func plainOpForSecure(op byte) byte {
	switch op {
	case OpOpenSecure, OpOpenSecureCompat:
		return OpOpen
	case OpUpSecure, OpUpSecureCompat:
		return OpUp
	case OpDownSecure, OpDownSecureCompat:
		return OpDown
	case OpCloseSecure, OpCloseSecureCompat:
		return OpClose
	default:
		return op
	}
}

func deriveSecureStaticKey(shortID [ShortIDLen]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("tamizdat fragpoc secure static v1\x00"))
	_, _ = h.Write(shortID[:])
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func deriveSecureSessionKey(staticKey [32]byte, sid [SIDLen]byte, openNonce []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("tamizdat fragpoc secure session v1\x00"))
	_, _ = h.Write(staticKey[:])
	_, _ = h.Write(sid[:])
	_, _ = h.Write(openNonce)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func secureRequestAD(op byte, id []byte) []byte {
	ad := make([]byte, 0, 2+len(id))
	ad = append(ad, 'q', op)
	ad = append(ad, id...)
	return ad
}

func secureResponseAD(op byte, id []byte) []byte {
	ad := make([]byte, 0, 2+len(id))
	ad = append(ad, 'r', op)
	ad = append(ad, id...)
	return ad
}

func newSecureNonce() ([secureNonceLen]byte, error) {
	var nonce [secureNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

func writeSecureBody(w io.Writer, key [32]byte, ad []byte, plaintext []byte) ([]byte, error) {
	nonce, err := newSecureNonce()
	if err != nil {
		return nil, err
	}
	return nonce[:], writeSecureBodyWithNonce(w, key, ad, nonce[:], plaintext)
}

func writeSecureBodyWithNonce(w io.Writer, key [32]byte, ad []byte, nonce []byte, plaintext []byte) error {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return err
	}
	if len(nonce) != aead.NonceSize() {
		return fmt.Errorf("%w: bad secure nonce size %d", ErrProtocol, len(nonce))
	}
	sealed := aead.Seal(nil, nonce, plaintext, ad)
	if len(sealed) > 0xffff {
		return fmt.Errorf("%w: secure body too large: %d", ErrProtocol, len(sealed))
	}
	hdr := make([]byte, secureNonceLen+2)
	copy(hdr, nonce)
	binary.BigEndian.PutUint16(hdr[secureNonceLen:], uint16(len(sealed)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err = w.Write(sealed)
	return err
}

func readSecureBody(r io.Reader, key [32]byte, ad []byte, plaintextLimit int) ([]byte, []byte, error) {
	var hdr [secureNonceLen + 2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, nil, err
	}
	sealedLen := int(binary.BigEndian.Uint16(hdr[secureNonceLen:]))
	if plaintextLimit >= 0 && sealedLen > plaintextLimit+secureOverhead {
		return nil, nil, fmt.Errorf("%w: secure body too large: %d", ErrProtocol, sealedLen)
	}
	sealed := make([]byte, sealedLen)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, hdr[:secureNonceLen], sealed, ad)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: secure open failed", ErrProtocol)
	}
	if plaintextLimit >= 0 && len(plaintext) > plaintextLimit {
		return nil, nil, fmt.Errorf("%w: secure plaintext too large: %d", ErrProtocol, len(plaintext))
	}
	nonce := make([]byte, secureNonceLen)
	copy(nonce, hdr[:secureNonceLen])
	return plaintext, nonce, nil
}
