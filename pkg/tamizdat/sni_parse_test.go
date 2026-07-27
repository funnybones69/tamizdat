package tamizdat

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// minimalClientHello builds a tiny but structurally valid ClientHello payload
// (without the 5-byte record header) carrying the supplied SNI host_name.
// Used by sni_parse + masquerade pool tests.
func minimalClientHello(sni string) []byte {
	var b bytes.Buffer

	// Build the SNI extension body.
	var sniExt bytes.Buffer
	sniExt.Write([]byte{0, 0}) // server_name extension type = 0
	// extension data length placeholder
	sniData := bytes.Buffer{}
	// ServerNameList: list_length(2) + entries
	entry := bytes.Buffer{}
	entry.WriteByte(0) // host_name name_type
	binary.Write(&entry, binary.BigEndian, uint16(len(sni)))
	entry.WriteString(sni)
	binary.Write(&sniData, binary.BigEndian, uint16(entry.Len()))
	sniData.Write(entry.Bytes())
	// Now write extension body length + body
	binary.Write(&sniExt, binary.BigEndian, uint16(sniData.Len()))
	sniExt.Write(sniData.Bytes())

	// Extensions block: 2-byte length + entries
	extBlock := bytes.Buffer{}
	binary.Write(&extBlock, binary.BigEndian, uint16(sniExt.Len()))
	extBlock.Write(sniExt.Bytes())

	// ClientHello body: legacy_version(2) + random(32) + session_id_len(1) +
	// cipher_suites_len(2) + cipher_suites(2 = one cipher) + compression_methods_len(1)
	// + compression(1) + extensions
	body := bytes.Buffer{}
	body.Write([]byte{0x03, 0x03}) // legacy_version TLS 1.2
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0)              // session_id_len = 0
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(1)              // compression_methods_len = 1
	body.WriteByte(0)              // null compression
	body.Write(extBlock.Bytes())

	// Handshake header: type(1)=ClientHello + length(3)
	b.WriteByte(1)
	b.Write([]byte{
		byte(body.Len() >> 16),
		byte(body.Len() >> 8),
		byte(body.Len()),
	})
	b.Write(body.Bytes())

	return b.Bytes()
}

func TestParseSNIFromClientHello(t *testing.T) {
	tests := []string{"ok.ru", "vk.com", "mail.ru", "*.ok.ru", "abcdefghijklmnop.example.com"}
	for _, want := range tests {
		ch := minimalClientHello(want)
		got, err := parseSNIFromClientHello(ch)
		if err != nil {
			t.Errorf("parseSNI(%q) error: %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("parseSNI(%q) = %q, want %q", want, got, want)
		}
	}
}

func TestParseSNIEmptyExtensions(t *testing.T) {
	// ClientHello WITHOUT SNI extension — body has no extensions block at all.
	body := bytes.Buffer{}
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0) // session_id len 0
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01})
	body.WriteByte(1)
	body.WriteByte(0)
	// No extensions trailer.

	ch := bytes.Buffer{}
	ch.WriteByte(1)
	ch.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	ch.Write(body.Bytes())

	got, err := parseSNIFromClientHello(ch.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty SNI, got %q", got)
	}
}

func TestParseSNITruncated(t *testing.T) {
	full := minimalClientHello("ok.ru")
	for i := 1; i < len(full); i++ {
		_, err := parseSNIFromClientHello(full[:i])
		if err == nil {
			// Truncating mid-message should always error.
			t.Errorf("parseSNI on truncated[:%d] returned no error", i)
		}
	}
}
