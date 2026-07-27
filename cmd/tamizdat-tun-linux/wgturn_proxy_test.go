package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

func TestSaveAndLoadWGTurnCreds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	creds := &wgturnclient.Credentials{
		User:     "turn-user",
		Pass:     "turn-pass",
		TurnURLs: []string{"turn.example:3478", "secure.example:5349"},
		TurnServers: []wgturnclient.TurnServer{
			{Host: "turn.example", Port: 3478, Scheme: "turn", Transport: "udp"},
			{Host: "secure.example", Port: 5349, Scheme: "turns", Transport: "tcp"},
		},
		Lifetime: 720,
	}
	if err := saveWGTurnCreds(path, []string{"room-hash"}, creds); err != nil {
		t.Fatalf("saveWGTurnCreds: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("cache mode=%o want=600", st.Mode().Perm())
	}

	loaded, _, err := loadWGTurnCreds(wgturnProxyConfig{CredCache: path})
	if err != nil {
		t.Fatalf("loadWGTurnCreds: %v", err)
	}
	if loaded.User != creds.User || loaded.Pass != creds.Pass || len(loaded.TurnServers) != 2 {
		t.Fatalf("round trip mismatch: %#v", loaded)
	}
	if loaded.TurnServers[1].Scheme != "turns" || loaded.TurnServers[1].Transport != "tcp" {
		t.Fatalf("transport metadata lost: %#v", loaded.TurnServers)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["hash_digest"] == "room-hash" || wire["hash_digest"] == "" {
		t.Fatalf("room hash was not safely digested: %#v", wire["hash_digest"])
	}
}

func TestLoadWGTurnCredsRejectsExpiredCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expired.json")
	raw := []byte(`{"username":"u","password":"p","turn_servers":["turn.example:3478"],"expires_at":"2000-01-01T00:00:00Z"}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWGTurnCreds(wgturnProxyConfig{CredCache: path}); err == nil {
		t.Fatal("expected expired cache rejection")
	}
}

func TestSaveWGTurnCredsSetsFutureExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	before := time.Now()
	if err := saveWGTurnCreds(path, nil, &wgturnclient.Credentials{
		User: "u", Pass: "p", TurnURLs: []string{"turn.example:3478"}, Lifetime: 60,
	}); err != nil {
		t.Fatal(err)
	}
	_, expires, err := parseWGTurnCredsJSON(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if !expires.After(before.Add(50 * time.Second)) {
		t.Fatalf("unexpected expiry: %s", expires)
	}
}

func TestRoomCredentialCachePathsAndLoadAreRoomScoped(t *testing.T) {
	base := filepath.Join(t.TempDir(), "vkturn-creds.json")
	hashes := []string{"room-alpha", "room-beta"}
	paths := []string{
		roomCredentialCachePath(base, hashes[0]),
		roomCredentialCachePath(base, hashes[1]),
	}
	if paths[0] == paths[1] || paths[0] == base || paths[1] == base {
		t.Fatalf("room paths are not isolated: %#v", paths)
	}
	for i, path := range paths {
		if err := saveWGTurnCreds(path, []string{hashes[i]}, &wgturnclient.Credentials{
			User: "u" + string(rune('0'+i)), Pass: "p", TurnURLs: []string{"turn.example:3478"}, Lifetime: 600,
		}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, sigs := loadWGTurnRoomCreds(wgturnProxyConfig{CredCache: base, VKHashes: hashes})
	if len(loaded) != 2 || len(sigs) != 2 {
		t.Fatalf("loaded=%d sigs=%d", len(loaded), len(sigs))
	}
	if loaded[hashes[0]].User == loaded[hashes[1]].User {
		t.Fatalf("room credentials were mixed: %#v", loaded)
	}
}

func TestPlanWGTurnRooms(t *testing.T) {
	tests := []struct {
		name      string
		rooms     int
		workers   int
		wantTotal int
		wantPer   int
		wantBond  bool
		wantErr   bool
	}{
		{name: "legacy one room", rooms: 1, workers: 12, wantTotal: 12},
		{name: "one room twenty", rooms: 1, workers: 20, wantTotal: 20},
		{name: "two full rooms", rooms: 2, workers: 20, wantTotal: 40, wantPer: 20, wantBond: true},
		{name: "four full rooms", rooms: 4, workers: 20, wantTotal: 80, wantPer: 20, wantBond: true},
		{name: "multi room partial forbidden", rooms: 4, workers: 12, wantErr: true},
		{name: "too many rooms", rooms: 5, workers: 20, wantErr: true},
		{name: "no rooms", rooms: 0, workers: 20, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hashes := make([]string, tc.rooms)
			for i := range hashes {
				hashes[i] = "room"
			}
			total, per, bond, err := planWGTurnRooms(hashes, tc.workers)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%t", err, tc.wantErr)
			}
			if err == nil && (total != tc.wantTotal || per != tc.wantPer || bond != tc.wantBond) {
				t.Fatalf("got total=%d per=%d bond=%t; want total=%d per=%d bond=%t", total, per, bond, tc.wantTotal, tc.wantPer, tc.wantBond)
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
