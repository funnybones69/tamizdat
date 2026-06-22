// Package wgturn implements a DTLS+WireGuard inbound listener for tamizdat.
//
// It accepts WireGuard-over-DTLS connections (compatible with WDTT clients
// that tunnel through VK TURN relays). The DTLS layer uses AES-128-GCM with
// a self-signed certificate and connection-ID extension for NAT rebinding
// resilience. Inside the DTLS tunnel the client speaks the GETCONF / READY /
// WAKEUP protocol to obtain a WireGuard config, then bidirectional WireGuard
// packets are proxied to a local userspace WireGuard instance.
package wgturn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// wgKeys holds a WireGuard server+client keypair in base64 encoding.
type wgKeys struct {
	serverPrivate string
	serverPublic  string
	clientPrivate string
	clientPublic  string
}

// b64ToHex decodes a base64-encoded 32-byte key and returns its hex form.
func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key length %d != 32", len(b))
	}
	return hex.EncodeToString(b), nil
}

// generateKeyPair creates a new Curve25519 keypair for WireGuard and returns
// private and public keys as base64 strings.
func generateKeyPair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

// loadOrGenerateKeys loads the server and client WireGuard keys from
// <dir>/wg-keys.dat or generates and persists new ones.
func loadOrGenerateKeys(dir string) (*wgKeys, error) {
	f := filepath.Join(dir, "wg-keys.dat")
	if data, err := os.ReadFile(f); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) >= 4 {
			keys := &wgKeys{
				serverPrivate: strings.TrimSpace(lines[0]),
				serverPublic:  strings.TrimSpace(lines[1]),
				clientPrivate: strings.TrimSpace(lines[2]),
				clientPublic:  strings.TrimSpace(lines[3]),
			}
			for _, k := range []string{keys.serverPrivate, keys.serverPublic,
				keys.clientPrivate, keys.clientPublic} {
				if _, err := b64ToHex(k); err != nil {
					goto generate
				}
			}
			log.Printf("[wgturn] keys loaded from %s", f)
			return keys, nil
		}
	}
generate:
	log.Println("[wgturn] generating new WireGuard keys...")
	sPriv, sPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	cPriv, cPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	keys := &wgKeys{sPriv, sPub, cPriv, cPub}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(f, []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n",
		keys.serverPrivate, keys.serverPublic,
		keys.clientPrivate, keys.clientPublic)), 0600); err != nil {
		return nil, fmt.Errorf("write keys: %w", err)
	}
	log.Printf("[wgturn] keys saved to %s", f)
	return keys, nil
}
