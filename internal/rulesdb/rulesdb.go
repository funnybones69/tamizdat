// Package rulesdb loads the Panel v5 `routing_rules` SQLite table and
// compiles it into a node.Dispatcher used by tamizdat-server to pick the
// outbound tag for each handled CONNECT.
//
// The dispatcher is rule-evaluation-only: every Outbound is a no-op stub.
// The server still uses internal/outbounds.Registry for the actual dial.
// This package therefore lives outside the root `tamizdat` package to keep
// the inbound_tamizdat → tamizdat import edge clean (no node ⇄ tamizdat
// cycle).
package rulesdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/funnybones69/tamizdat/node"
)

// Match is the JSON shape stored in routing_rules.match_json.
//
// All fields are optional; an empty match means "match anything". When
// multiple categories are populated the semantics follow node.Rule: AND
// across categories, OR within each list.
type Match struct {
	GeoIP      []string `json:"geoip,omitempty"`
	Geosite    []string `json:"geosite,omitempty"`
	IP         []string `json:"ip,omitempty"`
	Domain     []string `json:"domain,omitempty"`
	Source     []string `json:"source,omitempty"`
	Port       string   `json:"port,omitempty"`
	Network    string   `json:"network,omitempty"`
	InboundTag []string `json:"inbound_tag,omitempty"`
	User       []string `json:"user,omitempty"`
}

// Loaded pairs the SQLite row scalars with the parsed match payload.
type Loaded struct {
	Priority    int
	OutboundTag string
	Match       Match
}

// tagStub is the placeholder Outbound used by the routing-only dispatcher.
// Dial is never invoked: the server consults Dispatcher.Resolve() to get the
// tag and routes the actual dial through internal/outbounds.Registry, which
// owns the real net.Dialer / tamizdat client per outbound tag.
type tagStub struct{ tag string }

func (t tagStub) Tag() string { return t.tag }
func (t tagStub) Dial(context.Context, *node.Request) (net.Conn, error) {
	return nil, fmt.Errorf("rulesdb.tagStub.Dial: routing-only outbound %q has no dialer", t.tag)
}
func (t tagStub) Close() error { return nil }

// Load reads enabled rows from routing_rules ordered by priority.
//
// Hierarchical ordering (folders v1, 2026-05-10):
//
// When the panel has migrated to the folders schema, every routing rule is
// either ungrouped (folder_id IS NULL) or sits inside a folder. Folders
// and ungrouped rules are siblings in the *global* priority queue:
//   - routing_folders.priority = global queue position of the whole folder.
//   - routing_rules.priority   = intra-folder position when folder_id IS NOT NULL,
//     OR the global queue position when folder_id IS NULL.
//
// We compose a UNION ALL whose row shape is (gp, ip, id, tag, json):
//   - ungrouped: gp = rules.priority,    ip = 0
//   - grouped:   gp = folders.priority,  ip = rules.priority
//
// then ORDER BY gp ASC, ip ASC, id ASC. This yields the exact "folders are
// first-class siblings, intra-folder ordering is independent" semantics
// described in the v1 design: dragging a folder up in the global queue
// moves all its rules together; rule positions within one folder are
// independent from positions inside other folders.
//
// Backward compatibility: if the routing_folders table doesn't exist yet
// (older panel DB) we fall back to the legacy flat query
// "ORDER BY priority ASC, id ASC". The fallback is also used when
// routing_rules has no folder_id column (pre-folders migration), which we
// detect by sniffing the SQL error message returned from the UNION query.
// An absent routing_rules table itself yields an empty slice + nil error
// so server boot is robust against an unmigrated DB.
func Load(db *sql.DB) ([]Loaded, error) {
	if db == nil {
		return nil, nil
	}

	const hierQuery = `
WITH ungrouped AS (
  SELECT outbound_tag, match_json,
         priority AS gp, 0 AS ip, id
  FROM routing_rules
  WHERE enabled=1 AND folder_id IS NULL
), grouped AS (
  SELECT r.outbound_tag, r.match_json,
         f.priority AS gp, r.priority AS ip, r.id
  FROM routing_rules r
  JOIN routing_folders f ON r.folder_id = f.id
  WHERE r.enabled=1 AND f.enabled=1
)
SELECT outbound_tag, match_json, gp, ip, id FROM (
  SELECT * FROM ungrouped UNION ALL SELECT * FROM grouped
) ORDER BY gp ASC, ip ASC, id ASC`

	rows, err := db.Query(hierQuery)
	if err != nil {
		msg := strings.ToLower(err.Error())
		// "no such table: routing_folders" → pre-folders panel; fall back.
		// "no such table: routing_rules"   → fresh/unmigrated DB; empty.
		// "no such column: folder_id"      → pre-folders panel; fall back.
		if strings.Contains(msg, "no such table") {
			if strings.Contains(msg, "routing_rules") && !strings.Contains(msg, "routing_folders") {
				return nil, nil
			}
			return loadFlat(db)
		}
		if strings.Contains(msg, "no such column") {
			return loadFlat(db)
		}
		return nil, fmt.Errorf("query routing_rules (hierarchical): %w", err)
	}
	defer rows.Close()
	var out []Loaded
	for rows.Next() {
		var tag, raw string
		var gp, ip int
		var id int64
		if err := rows.Scan(&tag, &raw, &gp, &ip, &id); err != nil {
			return nil, fmt.Errorf("scan routing_rules: %w", err)
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		var m Match
		if strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				return nil, fmt.Errorf("routing_rules id=%d: parse match_json: %w", id, err)
			}
		}
		// Loaded.Priority is exposed for diagnostics only; downstream
		// match logic relies on slice order. We surface the global
		// priority (gp) to mirror the legacy "rule priority" mental
		// model — within a folder, all rules share their folder's gp.
		_ = ip
		out = append(out, Loaded{Priority: gp, OutboundTag: tag, Match: m})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// loadFlat is the legacy pre-folders query, used as fallback when the
// panel DB hasn't been migrated to the folders schema.
func loadFlat(db *sql.DB) ([]Loaded, error) {
	rows, err := db.Query(`SELECT priority, outbound_tag, match_json FROM routing_rules WHERE enabled=1 ORDER BY priority ASC, id ASC`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("query routing_rules (flat): %w", err)
	}
	defer rows.Close()
	var out []Loaded
	for rows.Next() {
		var pr int
		var tag, raw string
		if err := rows.Scan(&pr, &tag, &raw); err != nil {
			return nil, fmt.Errorf("scan routing_rules: %w", err)
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		var m Match
		if strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				return nil, fmt.Errorf("routing_rules priority=%d: parse match_json: %w", pr, err)
			}
		}
		out = append(out, Loaded{Priority: pr, OutboundTag: tag, Match: m})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Build compiles loaded rules + the known outbound tag set into a
// node.Dispatcher. Returns (nil, nil) when there are zero rules — the
// caller treats that as "no routing rule layer; resolve via registry
// default like before".
//
// This is the legacy entry point that uses only the curated in-tree geo
// fallback. Callers that want the full xray .dat datasets (auto-downloaded
// by node.GeoDataUpdater) should use BuildWithGeoDB.
func Build(rules []Loaded, knownTags []string, defaultTag string) (*node.Dispatcher, error) {
	return BuildWithGeoDB(rules, knownTags, defaultTag, nil)
}

// BuildWithGeoDB is Build, plus an optional parsed xray .dat database for
// resolving geoip:/geosite: tokens. nil geoDB falls back to curated maps.
func BuildWithGeoDB(rules []Loaded, knownTags []string, defaultTag string, geoDB *node.GeoDB) (*node.Dispatcher, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	tagSet := make(map[string]struct{}, len(knownTags)+len(rules)+1)
	for _, t := range knownTags {
		if t != "" {
			tagSet[t] = struct{}{}
		}
	}
	for _, r := range rules {
		tagSet[r.OutboundTag] = struct{}{}
	}
	if defaultTag != "" {
		tagSet[defaultTag] = struct{}{}
	}
	// "block" is a panel UX convention for blackhole; allow it as a tag
	// even if no outbound row exists (server treats it as drop-the-conn).
	tagSet["block"] = struct{}{}

	outbounds := make(map[string]node.Outbound, len(tagSet))
	firstTag := ""
	for t := range tagSet {
		outbounds[t] = tagStub{tag: t}
		if firstTag == "" {
			firstTag = t
		}
	}

	nrules := make([]*node.Rule, 0, len(rules))
	for _, r := range rules {
		nrules = append(nrules, &node.Rule{
			GeoIP:      append([]string(nil), r.Match.GeoIP...),
			Geosite:    append([]string(nil), r.Match.Geosite...),
			IP:         append([]string(nil), r.Match.IP...),
			Domain:     append([]string(nil), r.Match.Domain...),
			Source:     append([]string(nil), r.Match.Source...),
			Port:       r.Match.Port,
			Network:    r.Match.Network,
			InboundTag: append([]string(nil), r.Match.InboundTag...),
			User:       append([]string(nil), r.Match.User...),
			Outbound:   r.OutboundTag,
		})
	}
	compiled, err := node.CompileRulesWithGeoDB(nrules, geoDB)
	if err != nil {
		return nil, fmt.Errorf("compile routing_rules: %w", err)
	}
	resolvedDefault := defaultTag
	if resolvedDefault == "" {
		resolvedDefault = firstTag
	}
	if _, ok := outbounds[resolvedDefault]; !ok {
		resolvedDefault = firstTag
	}
	return node.NewDispatcher(outbounds, compiled, resolvedDefault, firstTag, "AsIs")
}

// Snapshot pairs a published dispatcher with the resolved default tag.
type Snapshot struct {
	Dispatcher *node.Dispatcher
	DefaultTag string
}

// Store is a tiny atomic holder so SIGHUP can publish a new dispatcher
// without locking the hot path.
type Store struct {
	v atomic.Pointer[Snapshot]
}

// Load returns the latest published snapshot. nil ⇒ no routing layer.
func (s *Store) Load() *Snapshot {
	if s == nil {
		return nil
	}
	return s.v.Load()
}

// Store publishes snap atomically.
func (s *Store) Store(snap *Snapshot) {
	if s == nil {
		return
	}
	s.v.Store(snap)
}

// Resolve runs the published dispatcher (if any) against a synthetic
// node.Request and returns the chosen outbound tag. Returns "" when no
// dispatcher is published so the caller falls back to the registry default.
// inboundTag is set on the request so user-/inbound-scoped rules can match.
func Resolve(ctx context.Context, snap *Snapshot, network, host string, port int, inboundTag, user string) string {
	if snap == nil || snap.Dispatcher == nil {
		return ""
	}
	req := &node.Request{
		Network:    network,
		TargetHost: host,
		TargetPort: port,
		InboundTag: inboundTag,
		User:       user,
	}
	tag, _ := snap.Dispatcher.Resolve(ctx, req)
	return tag
}

// ResolveTCP preserves the historical TCP-only helper signature.
func ResolveTCP(ctx context.Context, snap *Snapshot, host string, port int, inboundTag, user string) string {
	return Resolve(ctx, snap, "tcp", host, port, inboundTag, user)
}
