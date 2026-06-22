package sniff

import (
	"bytes"
	"strings"
)

// HTTPHost parses an HTTP/1.x request prefix and returns the Host
// header value if present. Used to sniff plain-text HTTP CONNECTs
// (rare but supported for completeness).
//
// We don't strictly validate the full HTTP grammar — just enough to
// recognize a request line followed by Host:. Returns (host, true) on
// first valid Host header.
func HTTPHost(data []byte) (string, bool) {
	if len(data) < 16 {
		return "", false
	}
	// Quick reject: must start with a known HTTP method token.
	if !looksLikeHTTPMethod(data) {
		return "", false
	}
	// Split on \r\n; header lines come after the request-line.
	idx := bytes.Index(data, []byte("\r\n"))
	if idx < 0 || idx+2 >= len(data) {
		return "", false
	}
	headerBlock := data[idx+2:]
	// Iterate headers until empty line or end of buffer.
	for len(headerBlock) > 0 {
		end := bytes.Index(headerBlock, []byte("\r\n"))
		var line []byte
		if end < 0 {
			line = headerBlock
			headerBlock = nil
		} else {
			line = headerBlock[:end]
			headerBlock = headerBlock[end+2:]
		}
		if len(line) == 0 {
			return "", false // end of headers, no Host
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		if name != "host" {
			continue
		}
		val := strings.TrimSpace(string(line[colon+1:]))
		// Strip port if present (Host: example.com:8080).
		if i := strings.IndexByte(val, ':'); i >= 0 {
			val = val[:i]
		}
		val = strings.ToLower(val)
		if val == "" {
			return "", false
		}
		return val, true
	}
	return "", false
}

// looksLikeHTTPMethod returns true if the buffer starts with one of
// the common HTTP method tokens followed by a space. Cheap pre-check
// to avoid running header parsing on TLS data.
func looksLikeHTTPMethod(data []byte) bool {
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
	}
	for _, m := range methods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}
