// Package buildinfo exposes one immutable identity format for every Tamizdat
// binary. Release builds stamp the exported variables with -ldflags=-X; local
// builds fall back to Go's embedded VCS metadata and remain visibly non-release.
package buildinfo

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

const Schema = 1

var (
	Version   = "dev"
	BuildID   = ""
	Commit    = ""
	BuildTime = ""
)

type Info struct {
	Schema    int    `json:"schema"`
	Binary    string `json:"binary"`
	Version   string `json:"version"`
	BuildID   string `json:"build_id"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"go_version"`
}

func Current(binary string) Info {
	info := Info{
		Schema:    Schema,
		Binary:    clean(binary),
		Version:   cleanDefault(Version, "dev"),
		BuildID:   clean(BuildID),
		Commit:    clean(Commit),
		BuildTime: clean(BuildTime),
		GoVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = clean(bi.Main.Version)
		}
		for _, setting := range bi.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = clean(setting.Value)
				}
			case "vcs.time":
				if info.BuildTime == "" {
					info.BuildTime = clean(setting.Value)
				}
			case "vcs.modified":
				info.Dirty = setting.Value == "true"
			}
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.BuildTime == "" {
		info.BuildTime = "unknown"
	}
	if info.BuildID == "" {
		info.BuildID = localBuildID(info.Commit, info.Dirty)
	}
	return info
}

func VersionLine(binary string) string {
	i := Current(binary)
	return fmt.Sprintf("%s version=%s build_id=%s commit=%s build_time=%s dirty=%t go=%s",
		i.Binary, i.Version, i.BuildID, shortCommit(i.Commit), i.BuildTime, i.Dirty, clean(i.GoVersion))
}

func JSON(binary string) ([]byte, error) {
	return json.Marshal(Current(binary))
}

func clean(value string) string {
	value = strings.Join(strings.Fields(value), "_")
	if value == "" {
		return ""
	}
	return value
}

func cleanDefault(value, fallback string) string {
	if value = clean(value); value != "" {
		return value
	}
	return fallback
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func localBuildID(commit string, dirty bool) string {
	id := "dev-" + shortCommit(commit)
	if dirty {
		id += "-dirty"
	}
	return id
}
