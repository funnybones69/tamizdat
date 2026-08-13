package buildinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentUsesStampedIdentity(t *testing.T) {
	oldVersion, oldBuildID, oldCommit, oldBuildTime := Version, BuildID, Commit, BuildTime
	defer func() { Version, BuildID, Commit, BuildTime = oldVersion, oldBuildID, oldCommit, oldBuildTime }()
	Version = "v0.2.0\nspoof"
	BuildID = "release 42"
	Commit = "0123456789abcdef"
	BuildTime = "2026-08-14T01:02:03Z"

	i := Current("tamizdat-server-app")
	if i.Version != "v0.2.0_spoof" || i.BuildID != "release_42" || i.Commit != "0123456789abcdef" {
		t.Fatalf("unexpected stamped identity: %+v", i)
	}
	line := VersionLine("tamizdat-server-app")
	if strings.ContainsAny(line, "\r\n") || !strings.Contains(line, "commit=0123456789ab") {
		t.Fatalf("unsafe version line: %q", line)
	}
}

func TestCurrentJSONIsMachineReadable(t *testing.T) {
	raw, err := JSON("tamizdat-server-app")
	if err != nil {
		t.Fatal(err)
	}
	var got Info
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || got.Binary != "tamizdat-server-app" || got.Version == "" || got.BuildID == "" {
		t.Fatalf("incomplete identity: %+v", got)
	}
}
