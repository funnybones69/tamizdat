//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

func TestOpenWrtInitFlagContract(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(-h) exit code = %d, want 2", code)
	}
	help := stderr.String()
	for _, name := range []string{
		"server", "tun-name", "tun-mtu", "vk-hash-file",
		"vk-workers-per-room", "vk-turn-pass-file", "vk-credential-mode",
		"vk-captcha-mode", "vk-captcha-dir", "vk-captcha-wait",
		"vk-creds-cache", "vk-credential-helper", "vk-profile-uri-file",
		"vk-credential-helper-dir", "pidfile", "debug",
	} {
		if !strings.Contains(help, "-"+name) {
			t.Errorf("OpenWrt init flag -%s is missing from help", name)
		}
	}
}

func TestLoadLegacyCredentialCacheForFirstRoom(t *testing.T) {
	room := "room-one"
	legacy := legacyCredentialCache{
		Version: 2, Username: "user", Password: "pass",
		TurnServers:   []string{"turn.example:3478"},
		TurnServersV2: []legacyTurnServer{{Host: "turn.example", Port: 3478, Scheme: "turn", Transport: "udp"}},
		LifetimeSec:   3600, HashDigest: roomHashDigest(room),
		FetchedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadLegacyCredentialCache(data, []string{room, "room-two"})
	if err != nil {
		t.Fatal(err)
	}
	creds := got[room]
	if creds == nil || creds.User != "user" || creds.Pass != "pass" {
		t.Fatalf("legacy room credentials not migrated: %#v", creds)
	}
	if creds.Source != "legacy-cache" || len(creds.TurnURLs) != 1 || len(creds.TurnServers) != 1 {
		t.Fatalf("legacy metadata not migrated: %#v", creds)
	}
	if _, exists := got["room-two"]; exists {
		t.Fatal("single-room legacy cache must only seed room #1")
	}
}

func TestLoadLegacyCredentialCacheRejectsWrongRoom(t *testing.T) {
	legacy := legacyCredentialCache{
		Username: "user", Password: "pass", TurnServers: []string{"turn.example:3478"},
		HashDigest: roomHashDigest("another-room"), ExpiresAt: time.Now().Add(time.Hour),
	}
	data, _ := json.Marshal(legacy)
	got, err := loadLegacyCredentialCache(data, []string{"room-one"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("cache with a different room digest was accepted")
	}
}

func TestLoadCredentialCacheDoesNotExtendLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	cache := credentialCache{Version: 1, Rooms: map[string]cacheEntry{
		"room-one": {
			Credentials: &testCredentials,
			AcquiredAt:  time.Now().Add(-10 * time.Minute),
		},
	}}
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCredentialCache(path, []string{"room-one"})
	if err != nil {
		t.Fatal(err)
	}
	if got["room-one"] == nil {
		t.Fatal("fresh modern cache was not loaded")
	}
	if got["room-one"].Lifetime >= testCredentials.Lifetime-60 {
		t.Fatalf("cached lifetime was extended: got %d, original %d", got["room-one"].Lifetime, testCredentials.Lifetime)
	}
}

func TestLegacyCredentialHelperCannotConsumeRoomQuota(t *testing.T) {
	args := legacyCredentialHelperArgs("profile", "room", "cache", "pid", "tamcred0", 1280)
	values := make(map[string]string)
	for i := 0; i+1 < len(args); i++ {
		if len(args[i]) > 0 && args[i][0] == '-' {
			values[args[i]] = args[i+1]
		}
	}
	if values["-vk-turn-host"] != "127.0.0.1" || values["-vk-turn-port"] != "9" {
		t.Fatalf("credential helper can reach a real TURN allocation: %v", args)
	}
	if values["-vk-workers"] != "1" || values["-vk-creds-cache"] != "cache" {
		t.Fatalf("credential helper arguments incomplete: %v", args)
	}
}

var testCredentials = wgturnclient.Credentials{
	User: "user", Pass: "pass", TurnURLs: []string{"turn.example:3478"}, Lifetime: 3600,
}
