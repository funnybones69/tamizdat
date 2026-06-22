package main

import (
	"strings"
	"testing"
)

func TestSanitizeLogLineRedactsProfileMaterial(t *testing.T) {
	line := "spawn -config tamizdat://server.example.com:443/?pubkey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&shortid=0123456789abcdef#PC"
	got := sanitizeLogLine(line)
	for _, secret := range []string{
		"server.example.com:443",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"shortid=0123456789abcdef",
	} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitized log still contains %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "-config [redacted]") && !strings.Contains(got, "tamizdat://[redacted]") {
		t.Fatalf("missing config/URI redaction marker: %s", got)
	}
}

func TestSanitizeLogLineRedactsConfigArgAndQueryKeys(t *testing.T) {
	got := sanitizeLogLine("-config tamizdat://x/?shortid=abcd&pubkey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if strings.Contains(got, "tamizdat://x") || strings.Contains(got, "abcd") || strings.Contains(got, "0123456789abcdef") {
		t.Fatalf("sanitized log leaked config material: %s", got)
	}
}

func TestShouldLogTunLineKeepsOnlyImportantLines(t *testing.T) {
	important := []string{
		"auto-route: default 0.0.0.0/0 via TUN ifIndex=42",
		"auto-route: selective mode — default route untouched",
		"ERROR dial tcp: connection refused",
		"route add failed: access denied",
		"wintun adapter created",
		"dns setup failed",
	}
	for _, line := range important {
		if !shouldLogTunLine(line) {
			t.Fatalf("important line was suppressed: %q", line)
		}
	}
	noise := []string{
		"accepted tcp connection 127.0.0.1:12345",
		"copy loop started",
		"bytes up=1024 down=2048",
		"http2 ping ok",
	}
	for _, line := range noise {
		if shouldLogTunLine(line) {
			t.Fatalf("noise line was logged: %q", line)
		}
	}
}
