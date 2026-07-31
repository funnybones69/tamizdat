package tunbinaryinfo

import (
	"fmt"
	"strings"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

const (
	BinaryName = "tamizdat-tun-linux"
	Schema     = 1
)

// Release builds override these values with -ldflags=-X. Explicit defaults
// make an accidental developer build visibly non-release.
var (
	Version              = "dev"
	BuildID              = "unversioned"
	SourceID             = "unknown"
	BaselineBinarySHA256 = "9b1f302975f7cb5b615863c8b8782df1fa779f0cc435b369e3ef8e371f3ddcae"
)

type Info struct {
	Schema               int      `json:"schema"`
	Binary               string   `json:"binary"`
	Version              string   `json:"version"`
	BuildID              string   `json:"build_id"`
	SourceID             string   `json:"source_id"`
	BaselineBinarySHA256 string   `json:"baseline_binary_sha256"`
	MaxRooms             int      `json:"max_rooms"`
	MaxWorkersPerRoom    int      `json:"max_workers_per_room"`
	MaxWorkersTotal      int      `json:"max_workers_total"`
	Features             []string `json:"features"`
}

func Current() Info {
	return Info{
		Schema:               Schema,
		Binary:               BinaryName,
		Version:              Version,
		BuildID:              BuildID,
		SourceID:             SourceID,
		BaselineBinarySHA256: BaselineBinarySHA256,
		MaxRooms:             wgturnclient.MaxRooms,
		MaxWorkersPerRoom:    wgturnclient.MaxWorkersPerRoom,
		MaxWorkersTotal:      wgturnclient.MaxMultiRoomWorkers,
		Features: []string{
			"autonomous_captcha_rjs",
			"bond_traffic_shaper",
			"credential_cache",
			"credential_generation_safe_invalidation",
			"inner_tcp",
			"inner_udp",
			"kernel_tun",
			"legacy_credential_helper",
			"local_captcha_fallback",
			"per_room_credentials",
			"quota_rotation_after_attach",
			"retry_uses_latest_credentials",
			"tzb2_getconf",
			"wgturn_bond_v2",
		},
	}
}

func VersionLine() string {
	i := Current()
	return fmt.Sprintf("%s version=%s build_id=%s source_id=%s baseline_sha256=%s rooms=%d workers_per_room=%d workers_total=%d",
		i.Binary, clean(i.Version), clean(i.BuildID), clean(i.SourceID), clean(i.BaselineBinarySHA256),
		i.MaxRooms, i.MaxWorkersPerRoom, i.MaxWorkersTotal)
}

func clean(value string) string {
	return strings.Join(strings.Fields(value), "_")
}
