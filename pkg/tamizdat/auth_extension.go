package tamizdat

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// clientHelloBody returns the ClientHello body (after the handshake header)
// from either a TLS record (starts with 0x16) or a raw handshake message
// (starts with 0x01). Used by ExtractX25519FromKeyShare for both code paths.
func clientHelloBody(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("ClientHello empty")
	}
	pos := 0
	if data[0] == 0x16 { // TLS Handshake record
		if len(data) < 5 {
			return nil, errors.New("TLS record too short")
		}
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recordLen {
			return nil, errors.New("TLS record length exceeds data")
		}
		pos = 5
		data = data[pos : pos+recordLen]
	}
	if len(data) == 0 {
		return nil, errors.New("ClientHello empty after TLS record header")
	}
	if data[0] == 0x01 { // HandshakeTypeClientHello
		if len(data) < 4 {
			return nil, errors.New("ClientHello too short for handshake header")
		}
		handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if len(data) < 4+handshakeLen {
			return nil, errors.New("ClientHello handshake length exceeds data")
		}
		return data[4 : 4+handshakeLen], nil
	}
	return data, nil
}

// ExtractX25519FromKeyShare parses the standard TLS 1.3 key_share extension
// (type 0x0033) from a buffered ClientHello *payload* (bytes after the 5-byte
// record header) and returns the X25519 (group 0x001D) entry's pubkey. This
// is the compass v2 §5.1 fix: instead of carrying samizdat's ephemeral pub
// in a private extension 0xFE0C, we use the X25519 keypair uTLS already
// generated for the standard TLS-1.3 ECDH. Reality does the same.
//
// Returns the 32-byte X25519 pubkey on success. Errors if no key_share or
// no standalone X25519 entry is present (real Chrome 131+ always sends one
// even alongside X25519MLKEM768 hybrid).
func ExtractX25519FromKeyShare(payload []byte) ([x25519KeyLen]byte, error) {
	var zero [x25519KeyLen]byte
	body, err := clientHelloBody(payload)
	if err != nil {
		return zero, err
	}

	// Walk: legacy_version(2) + random(32) + session_id(1+) + cipher_suites(2+) +
	// compression_methods(1+) + extensions(2+ length-prefixed)
	if len(body) < 34 {
		return zero, fmt.Errorf("clientHello body truncated (header)")
	}
	body = body[34:]

	if len(body) < 1 {
		return zero, fmt.Errorf("clientHello: missing session_id length")
	}
	sidLen := int(body[0])
	if len(body) < 1+sidLen {
		return zero, fmt.Errorf("clientHello: session_id truncated")
	}
	body = body[1+sidLen:]

	if len(body) < 2 {
		return zero, fmt.Errorf("clientHello: missing cipher_suites length")
	}
	csLen := int(body[0])<<8 | int(body[1])
	if len(body) < 2+csLen {
		return zero, fmt.Errorf("clientHello: cipher_suites truncated")
	}
	body = body[2+csLen:]

	if len(body) < 1 {
		return zero, fmt.Errorf("clientHello: missing compression length")
	}
	cmLen := int(body[0])
	if len(body) < 1+cmLen {
		return zero, fmt.Errorf("clientHello: compression truncated")
	}
	body = body[1+cmLen:]

	if len(body) < 2 {
		return zero, fmt.Errorf("clientHello: missing extensions length")
	}
	extLen := int(body[0])<<8 | int(body[1])
	if len(body) < 2+extLen {
		return zero, fmt.Errorf("clientHello: extensions truncated")
	}
	exts := body[2 : 2+extLen]

	for len(exts) >= 4 {
		extType := uint16(exts[0])<<8 | uint16(exts[1])
		eLen := int(exts[2])<<8 | int(exts[3])
		if len(exts) < 4+eLen {
			return zero, fmt.Errorf("extension truncated")
		}
		extBody := exts[4 : 4+eLen]
		exts = exts[4+eLen:]
		if extType != 0x0033 { // key_share
			continue
		}
		// key_share body for ClientHello: client_shares list, prefixed with 2-byte length.
		if len(extBody) < 2 {
			return zero, fmt.Errorf("key_share extension empty")
		}
		listLen := int(extBody[0])<<8 | int(extBody[1])
		if len(extBody) < 2+listLen {
			return zero, fmt.Errorf("key_share list truncated")
		}
		list := extBody[2 : 2+listLen]
		for len(list) >= 4 {
			group := uint16(list[0])<<8 | uint16(list[1])
			keLen := int(list[2])<<8 | int(list[3])
			if len(list) < 4+keLen {
				return zero, fmt.Errorf("key_share entry truncated")
			}
			keyExchange := list[4 : 4+keLen]
			list = list[4+keLen:]
			if group == 0x001D && len(keyExchange) == x25519KeyLen {
				// Standalone X25519 found.
				var out [x25519KeyLen]byte
				copy(out[:], keyExchange)
				return out, nil
			}
			// Skip MLKEM hybrid (group 0x11EC); compass v2 §5.1 edge case.
		}
		return zero, fmt.Errorf("key_share has no standalone X25519 entry")
	}
	return zero, fmt.Errorf("key_share extension not present")
}
