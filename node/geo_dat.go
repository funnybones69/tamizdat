package node

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

// geoDatLogger is a package-level seam so tests can capture warning output.
// Defaults to log.Printf; tests reassign and restore in t.Cleanup.
var geoDatLogger = log.Printf

type GeoIP struct {
	CountryCode string
	CIDR        []netip.Prefix
}

type GeoSite struct {
	CountryCode string
	Domain      []DomainRule
}

type DomainRule struct {
	Type  string // "Plain", "RootDomain", "Regex", "Full"
	Value string
}

type GeoDB struct {
	geoip   map[string][]netip.Prefix
	geosite map[string][]DomainRule
}

func LoadGeoDB(geoipPath, geositePath string) (*GeoDB, error) {
	// Backward-compat single-source wrapper. Empty string → skip that side.
	var ipPaths, sitePaths []string
	if strings.TrimSpace(geoipPath) != "" {
		ipPaths = []string{geoipPath}
	}
	if strings.TrimSpace(geositePath) != "" {
		sitePaths = []string{geositePath}
	}
	return LoadGeoDBMulti(ipPaths, sitePaths)
}

// LoadGeoDBMulti is the multi-source variant of LoadGeoDB. It loads every
// non-empty path in geoipPaths / geositePaths and merges their entries
// keyed by CountryCode (lower-cased). Phase 4 (2026-05-10) ships this to
// let operators combine e.g. Loyalsoldier (global blocklist) with
// runetfreedom (RKN-specific) or a private blocklist for their use-case.
//
// Merge semantics:
//   - For each unique (side, CountryCode), entries from later paths are
//     APPENDED (set-deduplicated) to earlier ones. Order of paths is the
//     order operators wrote them; their intent is "all of these, combined".
//   - Duplicate CIDRs are deduplicated via prefix-string equality.
//   - Duplicate DomainRules are deduplicated via (Type,Value) equality.
//   - Missing-file is non-fatal: loadGeoIPDat / loadGeositeDat already
//     log + skip; the merge accumulates whatever succeeded.
//
// Returns (nil, nil) when no files contributed any entries — matches the
// single-source LoadGeoDB contract so existing call-sites need no changes.
func LoadGeoDBMulti(geoipPaths, geositePaths []string) (*GeoDB, error) {
	db := &GeoDB{
		geoip:   make(map[string][]netip.Prefix),
		geosite: make(map[string][]DomainRule),
	}
	loaded := false
	for _, p := range geoipPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		ok, err := loadGeoIPDatMerge(db, p)
		if err != nil {
			return nil, err
		}
		loaded = loaded || ok
	}
	for _, p := range geositePaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		ok, err := loadGeositeDatMerge(db, p)
		if err != nil {
			return nil, err
		}
		loaded = loaded || ok
	}
	if !loaded {
		return nil, nil
	}
	return db, nil
}

// loadGeoIPDat is the single-source loader (overwrite-on-conflict). Retained
// for callers that need exact-match-one-file semantics. Phase 4 merge users
// should call loadGeoIPDatMerge instead.
func loadGeoIPDat(db *GeoDB, path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Operator explicitly configured this path (caller already checked
			// it's non-empty before calling us). Silent ENOENT was misleading —
			// it made operators think they were using xray's full dataset when
			// they were actually falling back to the curated 14-prefix shortlist.
			geoDatLogger("warning: configured geoip.dat at %q not found, falling back to curated in-tree shortlist", path)
			return false, nil
		}
		return false, fmt.Errorf("read geoip dat %q: %w", path, err)
	}
	entries, err := parseGeoIPList(data)
	if err != nil {
		return false, fmt.Errorf("parse geoip dat %q: %w", path, err)
	}
	for _, entry := range entries {
		key := normalizeGeoName(entry.CountryCode)
		if key == "" {
			continue
		}
		db.geoip[key] = clonePrefixes(entry.CIDR)
	}
	return true, nil
}

// loadGeoIPDatMerge is the Phase-4 multi-source variant. It APPENDS entries
// to the running db rather than overwriting. Duplicate CIDRs (same prefix
// string) within a single key are deduplicated so feeding overlapping
// sources doesn't bloat the routing dispatcher's lookup table.
func loadGeoIPDatMerge(db *GeoDB, path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			geoDatLogger("warning: configured geoip.dat at %q not found, falling back to curated in-tree shortlist", path)
			return false, nil
		}
		return false, fmt.Errorf("read geoip dat %q: %w", path, err)
	}
	entries, err := parseGeoIPList(data)
	if err != nil {
		return false, fmt.Errorf("parse geoip dat %q: %w", path, err)
	}
	for _, entry := range entries {
		key := normalizeGeoName(entry.CountryCode)
		if key == "" {
			continue
		}
		// Build a dedup set from the existing entries for this key, then
		// append novel prefixes from the new source.
		seen := make(map[string]struct{}, len(db.geoip[key])+len(entry.CIDR))
		for _, p := range db.geoip[key] {
			seen[p.String()] = struct{}{}
		}
		for _, p := range entry.CIDR {
			s := p.String()
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			db.geoip[key] = append(db.geoip[key], p)
		}
	}
	return true, nil
}

func loadGeositeDat(db *GeoDB, path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// See comment in loadGeoIPDat — same misleading-silent-fallback story.
			geoDatLogger("warning: configured geosite.dat at %q not found, falling back to curated in-tree shortlist", path)
			return false, nil
		}
		return false, fmt.Errorf("read geosite dat %q: %w", path, err)
	}
	entries, err := parseGeoSiteList(data)
	if err != nil {
		return false, fmt.Errorf("parse geosite dat %q: %w", path, err)
	}
	for _, entry := range entries {
		key := normalizeGeoName(entry.CountryCode)
		if key == "" {
			continue
		}
		db.geosite[key] = cloneDomainRules(entry.Domain)
	}
	return true, nil
}

// loadGeositeDatMerge is the Phase-4 multi-source variant of loadGeositeDat.
// Dedups domain rules by (Type, Value) pair so two sources that both contain
// the same "domain:example.com" don't get the matcher compiled twice.
func loadGeositeDatMerge(db *GeoDB, path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			geoDatLogger("warning: configured geosite.dat at %q not found, falling back to curated in-tree shortlist", path)
			return false, nil
		}
		return false, fmt.Errorf("read geosite dat %q: %w", path, err)
	}
	entries, err := parseGeoSiteList(data)
	if err != nil {
		return false, fmt.Errorf("parse geosite dat %q: %w", path, err)
	}
	for _, entry := range entries {
		key := normalizeGeoName(entry.CountryCode)
		if key == "" {
			continue
		}
		type ruleKey struct{ Type, Value string }
		seen := make(map[ruleKey]struct{}, len(db.geosite[key])+len(entry.Domain))
		for _, r := range db.geosite[key] {
			seen[ruleKey{r.Type, r.Value}] = struct{}{}
		}
		for _, r := range entry.Domain {
			rk := ruleKey{r.Type, r.Value}
			if _, dup := seen[rk]; dup {
				continue
			}
			seen[rk] = struct{}{}
			db.geosite[key] = append(db.geosite[key], r)
		}
	}
	return true, nil
}

func (db *GeoDB) GeoIPCIDRs(name string) []netip.Prefix {
	key := normalizeGeoName(name)
	if db != nil && db.geoip != nil {
		if cidrs, ok := db.geoip[key]; ok && len(cidrs) > 0 {
			return clonePrefixes(cidrs)
		}
	}
	if cidrs, ok := curatedGeoIP[key]; ok {
		return clonePrefixes(cidrs)
	}
	return nil
}

func (db *GeoDB) GeositeMatchers(name string) []domainMatcher {
	matchers, _, _ := geositeMatchersFor(db, name)
	return matchers
}

// GeositeDomainValues returns concrete domain-like values for a geosite group.
// It is intended for DNS/nftset based integrations such as the OpenWrt LuCI
// client. Regex rules are skipped because dnsmasq nftset rules cannot represent
// arbitrary regular expressions.
func (db *GeoDB) GeositeDomainValues(name string) []string {
	rules, ok := geositeRulesFor(db, name)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		typ := strings.ToLower(strings.TrimSpace(rule.Type))
		if typ == "regex" || typ == "regexp" {
			continue
		}
		value := strings.Trim(strings.ToLower(strings.TrimSpace(rule.Value)), ".")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func geositeMatchersFor(db *GeoDB, name string) ([]domainMatcher, bool, error) {
	rules, ok := geositeRulesFor(db, name)
	if !ok {
		return nil, false, nil
	}
	matchers := make([]domainMatcher, 0, len(rules))
	for _, rule := range rules {
		m, err := domainRuleToMatcher(rule)
		if err != nil {
			return nil, true, err
		}
		matchers = append(matchers, m)
	}
	return matchers, true, nil
}

func geositeRulesFor(db *GeoDB, name string) ([]DomainRule, bool) {
	key := normalizeGeoName(name)
	if db != nil && db.geosite != nil {
		if rules, ok := db.geosite[key]; ok && len(rules) > 0 {
			return cloneDomainRules(rules), true
		}
	}
	if rules, ok := curatedGeosite[key]; ok && len(rules) > 0 {
		return cloneDomainRules(rules), true
	}
	return nil, false
}

func domainRuleToMatcher(rule DomainRule) (domainMatcher, error) {
	value := strings.ToLower(strings.TrimSpace(rule.Value))
	if value == "" {
		return nil, fmt.Errorf("empty domain rule value")
	}
	switch strings.ToLower(strings.TrimSpace(rule.Type)) {
	case "plain":
		return keywordMatch{s: value}, nil
	case "rootdomain", "domain":
		return suffixMatch{s: value}, nil
	case "regex", "regexp":
		re, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("regex compile: %w", err)
		}
		return regexMatch{re: re}, nil
	case "full":
		return fullMatch{s: value}, nil
	default:
		return nil, fmt.Errorf("unknown domain rule type %q", rule.Type)
	}
}

func normalizeGeoName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if left, right, ok := strings.Cut(name, ":"); ok {
		switch left {
		case "geoip", "geosite":
			name = strings.TrimSpace(right)
		}
	}
	return name
}

func parseGeoIPList(data []byte) ([]GeoIP, error) {
	var out []GeoIP
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return nil, err
		}
		data = rest
		if field.num == 1 && field.typ == 2 {
			entry, err := parseGeoIPMessage(field.bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
	}
	return out, nil
}

func parseGeoIPMessage(data []byte) (GeoIP, error) {
	var out GeoIP
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return GeoIP{}, err
		}
		data = rest
		switch field.num {
		case 1:
			if field.typ == 2 {
				out.CountryCode = string(field.bytes)
			}
		case 2:
			if field.typ == 2 {
				prefix, err := parseCIDRMessage(field.bytes)
				if err != nil {
					return GeoIP{}, err
				}
				out.CIDR = append(out.CIDR, prefix)
			}
		}
	}
	return out, nil
}

func parseCIDRMessage(data []byte) (netip.Prefix, error) {
	var ipBytes []byte
	prefixBits := 0
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return netip.Prefix{}, err
		}
		data = rest
		switch field.num {
		case 1:
			if field.typ == 2 {
				ipBytes = append(ipBytes[:0], field.bytes...)
			}
		case 2:
			if field.typ == 0 {
				prefixBits = int(field.varint)
			}
		}
	}
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR IP bytes length %d", len(ipBytes))
	}
	addr = addr.Unmap()
	maxBits := 32
	if addr.Is6() && !addr.Is4In6() {
		maxBits = 128
	}
	if prefixBits < 0 || prefixBits > maxBits {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length %d for %s", prefixBits, addr)
	}
	return netip.PrefixFrom(addr, prefixBits).Masked(), nil
}

func parseGeoSiteList(data []byte) ([]GeoSite, error) {
	var out []GeoSite
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return nil, err
		}
		data = rest
		if field.num == 1 && field.typ == 2 {
			entry, err := parseGeoSiteMessage(field.bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
	}
	return out, nil
}

func parseGeoSiteMessage(data []byte) (GeoSite, error) {
	var out GeoSite
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return GeoSite{}, err
		}
		data = rest
		switch field.num {
		case 1:
			if field.typ == 2 {
				out.CountryCode = string(field.bytes)
			}
		case 2:
			if field.typ == 2 {
				rule, err := parseDomainRuleMessage(field.bytes)
				if err != nil {
					return GeoSite{}, err
				}
				out.Domain = append(out.Domain, rule)
			}
		}
	}
	return out, nil
}

func parseDomainRuleMessage(data []byte) (DomainRule, error) {
	out := DomainRule{Type: "Plain"}
	for len(data) > 0 {
		field, rest, err := nextProtoField(data)
		if err != nil {
			return DomainRule{}, err
		}
		data = rest
		switch field.num {
		case 1:
			if field.typ == 0 {
				typeName, err := domainRuleTypeName(field.varint)
				if err != nil {
					return DomainRule{}, err
				}
				out.Type = typeName
			}
		case 2:
			if field.typ == 2 {
				out.Value = string(field.bytes)
			}
		}
	}
	return out, nil
}

func domainRuleTypeName(v uint64) (string, error) {
	switch v {
	case 0:
		return "Plain", nil
	case 1:
		return "Regex", nil
	case 2:
		return "RootDomain", nil
	case 3:
		return "Full", nil
	default:
		return "", fmt.Errorf("unknown domain rule type number %d", v)
	}
}

type protoField struct {
	num    int
	typ    int
	bytes  []byte
	varint uint64
}

func nextProtoField(data []byte) (protoField, []byte, error) {
	key, n := binary.Uvarint(data)
	if n <= 0 {
		return protoField{}, nil, fmt.Errorf("invalid protobuf field key")
	}
	data = data[n:]
	field := protoField{num: int(key >> 3), typ: int(key & 0x7)}
	if field.num <= 0 {
		return protoField{}, nil, fmt.Errorf("invalid protobuf field number %d", field.num)
	}
	switch field.typ {
	case 0:
		v, n := binary.Uvarint(data)
		if n <= 0 {
			return protoField{}, nil, fmt.Errorf("invalid protobuf varint for field %d", field.num)
		}
		field.varint = v
		return field, data[n:], nil
	case 1:
		if len(data) < 8 {
			return protoField{}, nil, fmt.Errorf("truncated protobuf fixed64 for field %d", field.num)
		}
		return field, data[8:], nil
	case 2:
		l, n := binary.Uvarint(data)
		if n <= 0 {
			return protoField{}, nil, fmt.Errorf("invalid protobuf length for field %d", field.num)
		}
		data = data[n:]
		if l > uint64(len(data)) {
			return protoField{}, nil, fmt.Errorf("truncated protobuf length-delimited field %d", field.num)
		}
		field.bytes = data[:int(l)]
		return field, data[int(l):], nil
	case 5:
		if len(data) < 4 {
			return protoField{}, nil, fmt.Errorf("truncated protobuf fixed32 for field %d", field.num)
		}
		return field, data[4:], nil
	default:
		return protoField{}, nil, fmt.Errorf("unsupported protobuf wire type %d for field %d", field.typ, field.num)
	}
}

func clonePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Prefix, len(in))
	copy(out, in)
	return out
}

func cloneDomainRules(in []DomainRule) []DomainRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]DomainRule, len(in))
	copy(out, in)
	return out
}
