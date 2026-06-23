package main

import "testing"

const testProfilePubKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"

func TestApplyProfileURIConfiguresH2Client(t *testing.T) {
	serverAddr := ""
	serverName := ""
	pubHex := ""
	shortIDHex := ""
	fingerprint := "mix"
	transport := "h2"

	raw := "tamizdat://2222222222222222@server.example.com:443/?sni=cover1.example.com,cover2.example.com&pubkey=" + testProfilePubKeyHex + "&fp=chrome"
	if err := applyProfileURI(raw, &serverAddr, &serverName, &pubHex, &shortIDHex, &fingerprint, &transport); err != nil {
		t.Fatalf("applyProfileURI: %v", err)
	}
	if serverAddr != "server.example.com:443" {
		t.Fatalf("serverAddr = %q", serverAddr)
	}
	if serverName != "cover1.example.com,cover2.example.com" {
		t.Fatalf("serverName = %q", serverName)
	}
	if pubHex != testProfilePubKeyHex {
		t.Fatalf("pubHex = %q", pubHex)
	}
	if shortIDHex != "2222222222222222" {
		t.Fatalf("shortIDHex = %q", shortIDHex)
	}
	if fingerprint != "chrome" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
	if transport != "h2" {
		t.Fatalf("transport = %q", transport)
	}
}

func TestApplyProfileURIRejectsNonH2Transport(t *testing.T) {
	serverAddr := ""
	serverName := ""
	pubHex := ""
	shortIDHex := ""
	fingerprint := "mix"
	transport := "h2"

	raw := "tamizdat://2222222222222222@server.example.com:443/?pubkey=" + testProfilePubKeyHex + "&transport=vkturn"
	if err := applyProfileURI(raw, &serverAddr, &serverName, &pubHex, &shortIDHex, &fingerprint, &transport); err == nil {
		t.Fatal("expected error for non-H2 profile transport")
	}
}

func TestApplyProfileURIPreservesExplicitTransportGuard(t *testing.T) {
	serverAddr := ""
	serverName := ""
	pubHex := ""
	shortIDHex := ""
	fingerprint := "mix"
	transport := "fragpoc"

	raw := "tamizdat://2222222222222222@server.example.com:443/?pubkey=" + testProfilePubKeyHex
	if err := applyProfileURI(raw, &serverAddr, &serverName, &pubHex, &shortIDHex, &fingerprint, &transport); err == nil {
		t.Fatal("expected error for --config with explicit non-H2 --transport")
	}
}
