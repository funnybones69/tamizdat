package sniff

import (
	"encoding/binary"
	"strings"
)

// TLSClientHello parses a TLS handshake record's ClientHello and returns
// the server_name extension hostname (SNI) if present.
//
// TLS 1.0-1.3 ClientHello binary layout (RFC 5246 §7.4.1.2, RFC 6066 §3):
//
//	Record header (5 bytes):
//	  byte 0     content_type = 0x16 (handshake)
//	  bytes 1-2  legacy_version (0x0301-0x0304)
//	  bytes 3-4  fragment_length (uint16 big-endian)
//
//	Handshake header (4 bytes):
//	  byte 0     msg_type = 0x01 (client_hello)
//	  bytes 1-3  length (uint24 big-endian)
//
//	ClientHello body:
//	  bytes 0-1   legacy_version
//	  bytes 2-33  random (32 bytes)
//	  uint8       legacy_session_id_length, then bytes
//	  uint16      cipher_suites_length, then bytes
//	  uint8       compression_methods_length, then bytes
//	  uint16      extensions_length, then extension blocks
//
//	Each extension block:
//	  uint16 ext_type
//	  uint16 ext_length
//	  ext_length bytes
//
//	server_name (ext_type 0x0000):
//	  uint16 list_length
//	  list entries:
//	    uint8 name_type (0x00 = host_name)
//	    uint16 name_length
//	    name_length bytes (ASCII)
//
// We tolerate extra trailing bytes (some clients send extensions we
// don't care about). Returns (hostname, true) on first valid SNI found.
func TLSClientHello(data []byte) (string, bool) {
	// Need at minimum a record header + handshake header + body cursor.
	if len(data) < 5 {
		return "", false
	}
	// content_type = handshake
	if data[0] != 0x16 {
		return "", false
	}
	// legacy_version: 0x0301 (TLS 1.0) through 0x0303 (TLS 1.2); TLS 1.3
	// still uses 0x0303 in the record layer for compatibility.
	if data[1] != 0x03 {
		return "", false
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen < 4 || 5+recordLen > len(data) {
		// Truncated record. We may still have a complete ClientHello if
		// the truncation is just trailing extensions; try anyway with
		// what we have.
		recordLen = len(data) - 5
	}
	body := data[5 : 5+recordLen]
	if len(body) < 4 {
		return "", false
	}
	// Handshake header
	if body[0] != 0x01 {
		return "", false
	}
	// handshake length is uint24 big-endian
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hello := body[4:]
	if hsLen < len(hello) {
		hello = hello[:hsLen]
	}
	return parseClientHelloExtensions(hello)
}

// parseClientHelloExtensions walks past the ClientHello fixed-format
// prefix and into the extensions block, looking for SNI.
func parseClientHelloExtensions(hello []byte) (string, bool) {
	// legacy_version(2) + random(32) = 34 bytes fixed
	if len(hello) < 34 {
		return "", false
	}
	p := 34

	// session_id
	if p >= len(hello) {
		return "", false
	}
	sidLen := int(hello[p])
	p++
	if p+sidLen > len(hello) {
		return "", false
	}
	p += sidLen

	// cipher_suites length(2) + bytes
	if p+2 > len(hello) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(hello[p : p+2]))
	p += 2
	if p+csLen > len(hello) {
		return "", false
	}
	p += csLen

	// compression_methods length(1) + bytes
	if p+1 > len(hello) {
		return "", false
	}
	cmLen := int(hello[p])
	p++
	if p+cmLen > len(hello) {
		return "", false
	}
	p += cmLen

	// extensions length(2) + extension blocks
	if p+2 > len(hello) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(hello[p : p+2]))
	p += 2
	extEnd := p + extLen
	if extEnd > len(hello) {
		extEnd = len(hello)
	}

	for p+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hello[p : p+2])
		extDataLen := int(binary.BigEndian.Uint16(hello[p+2 : p+4]))
		p += 4
		if p+extDataLen > extEnd {
			return "", false
		}
		if extType == 0x0000 { // server_name
			name, ok := parseSNI(hello[p : p+extDataLen])
			if ok {
				return name, true
			}
			return "", false
		}
		p += extDataLen
	}
	return "", false
}

// parseSNI extracts the first host_name entry from a server_name
// extension data block.
func parseSNI(ext []byte) (string, bool) {
	if len(ext) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	if listLen+2 > len(ext) {
		return "", false
	}
	list := ext[2 : 2+listLen]
	p := 0
	for p+3 <= len(list) {
		nameType := list[p]
		nameLen := int(binary.BigEndian.Uint16(list[p+1 : p+3]))
		p += 3
		if p+nameLen > len(list) {
			return "", false
		}
		if nameType == 0x00 { // host_name
			name := string(list[p : p+nameLen])
			// SNI host names are case-insensitive ASCII per RFC 6066;
			// normalize to lower so routing rules don't surprise.
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				return "", false
			}
			return name, true
		}
		p += nameLen
	}
	return "", false
}
