package tamizdat

import "strings"

// Default Russian-cover SNI pool (compass v2 §5.7 / §3.10). Curated subset
// of high-traffic RU sites that:
//   - Are in the Roskomnadzor "socially significant services" whitelist (never
//     blocked even during regional shutdowns or mobile-whitelist regimes).
//   - Appear in Tranco Top 100K with high RU traffic share.
//   - Use HTTPS on :443 with stable cert chains (cover-handshake works).
//
// Weights approximate Zipf distribution of real browser visit frequency:
// the top entry gets weight 100, rank N gets ~100/N. Picking weighted-random
// from this list matches a real browser's per-SNI distribution far better
// than uniform-random over a 5-element pool.
//
// Config helper: operators can read this list via DefaultRussianCoverSNIs()
// and use it to populate ClientConfig.ServerNames + ServerConfig.MasqueradePool
// (mapping sni -> origin host, here always sni == origin since these are
// real domains we forward to).

type SNIEntry struct {
	SNI    string `json:"sni"`
	Weight int    `json:"weight"`
}

// defaultRussianCoverSNIs is the curated pool. Order = approximate rank.
var defaultRussianCoverSNIs = []SNIEntry{
	{"yandex.ru", 100},
	{"vk.com", 90},
	{"mail.ru", 75},
	{"ok.ru", 65},
	{"rambler.ru", 35},
	{"avito.ru", 50},
	{"ozon.ru", 45},
	{"wildberries.ru", 40},
	{"sberbank.ru", 38},
	{"gosuslugi.ru", 35}, // RKN whitelist core
	{"rutube.ru", 30},
	{"dzen.ru", 28},
	{"market.yandex.ru", 25},
	{"mts.ru", 22},
	{"megafon.ru", 20},
	{"beeline.ru", 18},
	{"tele2.ru", 16},
	{"rt.ru", 15},
	{"pochta.ru", 14},
	{"nalog.gov.ru", 12},
	{"kinopoisk.ru", 22},
	{"hh.ru", 20},
	{"lenta.ru", 18},
	{"ria.ru", 17},
	{"tass.ru", 15},
	{"rg.ru", 13},
	{"kommersant.ru", 12},
	{"vedomosti.ru", 11},
	{"rbc.ru", 14},
	{"mvideo.ru", 10},
	{"eldorado.ru", 9},
	{"dns-shop.ru", 9},
	{"kassir.ru", 7},
	{"afisha.ru", 7},
	{"pikabu.ru", 13},
	{"habr.com", 11},
	{"livejournal.com", 8},
	{"vc.ru", 7},
}

// DefaultRussianCoverSNIs returns a copy of the curated cover-SNI pool with
// approximate Zipf weights. Operators use this to populate
// ClientConfig.ServerNames (list form) and ServerConfig.MasqueradePool
// (sni -> origin map; for these entries origin == sni).
func DefaultRussianCoverSNIs() []SNIEntry {
	out := make([]SNIEntry, len(defaultRussianCoverSNIs))
	copy(out, defaultRussianCoverSNIs)
	return out
}

// DefaultRussianCoverSNINames returns just the SNI names from the pool.
// Convenience wrapper for ClientConfig.ServerNames assignment.
func DefaultRussianCoverSNINames() []string {
	out := make([]string, len(defaultRussianCoverSNIs))
	for i, e := range defaultRussianCoverSNIs {
		out[i] = e.SNI
	}
	return out
}

// DefaultRussianCoverMasqueradePool returns sni -> origin mapping (origin
// equals sni for these direct entries). Convenience wrapper for
// ServerConfig.MasqueradePool assignment.
func DefaultRussianCoverMasqueradePool() map[string]string {
	out := make(map[string]string, len(defaultRussianCoverSNIs))
	for _, e := range defaultRussianCoverSNIs {
		out[e.SNI] = e.SNI
	}
	return out
}

// lookupMasqueradeOrigin resolves a probe SNI against the masquerade
// pool with normalization (review-A P5 + A-RR-1):
//
//  1. Exact match: pool[sni].
//  2. Strip leading "www.": pool[sni[len("www."):]].
//  3. Suffix wildcard: pool keys starting with "*." match when sni ends
//     with the rest of the key (e.g. pool key "*.cdn.example.com"
//     matches probe SNI "static.cdn.example.com").
//
// SNI is case-insensitive per RFC 6066 §3 — a probe with SNI "YANDEX.RU"
// or "Yandex.Ru" must match a pool entry keyed "yandex.ru". A-RR-1
// lowercases the input once before applying all three lookup paths so
// case-permuted probes don't fall through to the default origin (which
// would be exactly the Tell #2 mismatch this codepath is meant to fix).
//
// Pool keys themselves are NOT lowercased at lookup time — the operator
// remains the authority on the canonical key form. Conventionally keys
// are lowercase; if an operator inserts a mixed-case key it will only
// match probes that case-fold to that exact form (vanishingly rare in
// practice).
//
// Returns ("", false) when nothing matches; the caller should then fall
// through to the default MasqueradeDomain origin.
func lookupMasqueradeOrigin(pool map[string]string, sni string) (string, bool) {
	if len(pool) == 0 || sni == "" {
		return "", false
	}
	// A-RR-1: case-fold the probe SNI once before all lookup paths.
	sni = strings.ToLower(sni)
	// 1. Exact match.
	if origin, ok := pool[sni]; ok && origin != "" {
		return origin, true
	}
	// 2. www-stripped match.
	const wwwPrefix = "www."
	if strings.HasPrefix(sni, wwwPrefix) {
		stripped := sni[len(wwwPrefix):]
		if origin, ok := pool[stripped]; ok && origin != "" {
			return origin, true
		}
	}
	// 3. Suffix wildcard match.
	for key, origin := range pool {
		if origin == "" {
			continue
		}
		if !strings.HasPrefix(key, "*.") {
			continue
		}
		// Require the SNI to end with the dot-prefixed remainder so
		// "*.cdn.example.com" matches "x.cdn.example.com" but NOT
		// "evilcdn.example.com" (no dot boundary).
		suffix := key[1:] // ".cdn.example.com"
		if strings.HasSuffix(sni, suffix) && len(sni) > len(suffix) {
			return origin, true
		}
	}
	return "", false
}

// pickWeightedSNI returns a weighted-random pick from the entries.
// Used by Client when ServerNames is empty AND CoverPoolMode=true.
func pickWeightedSNI(entries []SNIEntry) string {
	if len(entries) == 0 {
		return ""
	}
	total := 0
	for _, e := range entries {
		if e.Weight < 0 {
			continue
		}
		total += e.Weight
	}
	if total == 0 {
		return entries[0].SNI
	}
	r := int(coverRandUint64n(uint64(total)))
	cum := 0
	for _, e := range entries {
		cum += e.Weight
		if r < cum {
			return e.SNI
		}
	}
	return entries[len(entries)-1].SNI
}
