package tamizdat

import (
	"encoding/binary"
	"errors"
)

// parseSNIFromClientHello extracts the server_name (SNI) value from a TLS
// ClientHello payload (the bytes after the 5-byte record header). Returns
// empty string with no error if no SNI extension is present.
//
// Used by the server to route auth-failed connections to the matching
// masquerade origin (cover-SNI rotation, compass P1.1). Lightweight parser:
// only walks far enough to find the SNI extension; no certificate validation,
// no full ClientHello parse.
func parseSNIFromClientHello(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", errors.New("clientHello: payload too short")
	}
	// Handshake header: type(1) + length(3)
	if payload[0] != 1 { // ClientHello = type 1
		return "", errors.New("clientHello: not a ClientHello message")
	}
	chLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if len(body) < chLen {
		return "", errors.New("clientHello: body truncated")
	}
	body = body[:chLen]

	// legacy_version(2) + random(32)
	if len(body) < 34 {
		return "", errors.New("clientHello: header truncated")
	}
	body = body[34:]

	// legacy_session_id (1-byte length + opaque)
	if len(body) < 1 {
		return "", errors.New("clientHello: missing session_id")
	}
	sidLen := int(body[0])
	if len(body) < 1+sidLen {
		return "", errors.New("clientHello: session_id truncated")
	}
	body = body[1+sidLen:]

	// cipher_suites (2-byte length + opaque)
	if len(body) < 2 {
		return "", errors.New("clientHello: missing cipher_suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+csLen {
		return "", errors.New("clientHello: cipher_suites truncated")
	}
	body = body[2+csLen:]

	// compression_methods (1-byte length + opaque)
	if len(body) < 1 {
		return "", errors.New("clientHello: missing compression_methods")
	}
	cmLen := int(body[0])
	if len(body) < 1+cmLen {
		return "", errors.New("clientHello: compression_methods truncated")
	}
	body = body[1+cmLen:]

	// extensions block (2-byte length + opaque). Optional in old TLS but
	// always present in TLS 1.2+ ClientHellos that include SNI.
	if len(body) < 2 {
		return "", nil // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	if len(body) < 2+extLen {
		return "", errors.New("clientHello: extensions truncated")
	}
	exts := body[2 : 2+extLen]

	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		eLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+eLen {
			return "", errors.New("clientHello: extension truncated")
		}
		extBody := exts[4 : 4+eLen]
		exts = exts[4+eLen:]

		// server_name extension = 0
		if extType != 0 {
			continue
		}
		// SNI extension structure:
		//   ServerNameList: list_length(2) + list-of(NameType(1) + HostName(2-len + str))
		if len(extBody) < 2 {
			return "", errors.New("SNI extension empty")
		}
		listLen := int(binary.BigEndian.Uint16(extBody[:2]))
		if len(extBody) < 2+listLen {
			return "", errors.New("SNI list truncated")
		}
		list := extBody[2 : 2+listLen]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			if len(list) < 3+nameLen {
				return "", errors.New("SNI name truncated")
			}
			nameVal := list[3 : 3+nameLen]
			list = list[3+nameLen:]
			if nameType == 0 { // host_name
				return string(nameVal), nil
			}
		}
		return "", nil
	}
	return "", nil
}
