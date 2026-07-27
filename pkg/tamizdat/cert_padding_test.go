package tamizdat

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPadCertChain_AddsAtLeastTargetBytes(t *testing.T) {
	// Start with a single 1-byte "leaf" placeholder (we don't need a real cert
	// for size accounting; padCertChain operates on [][]byte).
	leaf := [][]byte{make([]byte, 1024)}
	out, err := padCertChain(leaf, 3000, 3)
	if err != nil {
		t.Fatalf("padCertChain: %v", err)
	}
	if len(out) < len(leaf)+1 {
		t.Errorf("expected at least one padding cert, got chain length %d", len(out))
	}

	// Sum of padding bytes (excluding leaf).
	added := 0
	for _, c := range out[len(leaf):] {
		added += len(c)
	}
	if added < 3000 {
		t.Errorf("padding total %d < target 3000", added)
	}
}

func TestPadCertChain_GeneratesValidX509(t *testing.T) {
	out, err := padCertChain([][]byte{}, 1000, 1)
	if err != nil {
		t.Fatalf("padCertChain: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no padding cert produced")
	}
	// Each padding cert must be parseable as X.509.
	for i, der := range out {
		_, err := x509.ParseCertificate(der)
		if err != nil {
			t.Errorf("padding cert #%d not valid X.509: %v", i, err)
		}
	}
}

func TestPadCertChain_RandomizedSubjects(t *testing.T) {
	// Two padding chains generated separately must not be byte-identical.
	a, err := padCertChain([][]byte{}, 500, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := padCertChain([][]byte{}, 500, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) > 0 && len(b) > 0 && string(a[0]) == string(b[0]) {
		t.Error("two padding cert chains have identical leaf cert bytes — randomization failed")
	}
}

// --- F-1: ServerConfig.DisableCertPadding -----------------------------------

// rawLeafChainSize returns the byte-count of the cert chain a freshly built
// Server holds in s.cachedCert.Certificate. Uses the shared
// generateSelfSignedCert helper from integration_test.go.
func certChainBytes(c [][]byte) int {
	n := 0
	for _, b := range c {
		n += len(b)
	}
	return n
}

func TestCertPaddingDisabledFlagSkipsPadding(t *testing.T) {
	// With DisableCertPadding=true the loaded leaf cert must reach the
	// running Server unchanged (no synthetic CA chain entries appended,
	// total chain bytes equal to the parsed leaf-only size).
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	// Decode raw leaf size for parity check.
	rawSize := 0
	{
		// crude: load the same key-pair the way Server does, count chain.
		rawSrv, err := NewServer(ServerConfig{
			PrivateKey:         priv,
			MasterShortID:      shortID,
			CertPEM:            certPEM,
			KeyPEM:             keyPEM,
			DisableCertPadding: true,
			Handler:            func(context.Context, net.Conn, string) {},
		})
		if err != nil {
			t.Fatalf("NewServer DisableCertPadding=true: %v", err)
		}
		if rawSrv.cachedCert == nil {
			t.Fatal("cachedCert nil with DisableCertPadding=true")
		}
		if got := len(rawSrv.cachedCert.Certificate); got != 1 {
			t.Fatalf("DisableCertPadding=true: chain length = %d, want 1 (leaf only, no padding)", got)
		}
		rawSize = certChainBytes(rawSrv.cachedCert.Certificate)
	}

	// Sanity-check leaf size is in the expected self-signed envelope (~1 KB).
	if rawSize < 200 || rawSize > 4000 {
		t.Fatalf("raw leaf chain size %d outside sanity envelope 200-4000", rawSize)
	}
}

func TestCertPaddingDefaultStillApplies(t *testing.T) {
	// Default (DisableCertPadding zero-value=false) must produce a padded
	// chain: more than 1 cert entry, total bytes well above raw leaf.
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)

	srv, err := NewServer(ServerConfig{
		PrivateKey:    priv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler:       func(context.Context, net.Conn, string) {},
	})
	if err != nil {
		t.Fatalf("NewServer default padding: %v", err)
	}
	if srv.cachedCert == nil {
		t.Fatal("cachedCert nil")
	}
	if got := len(srv.cachedCert.Certificate); got < 2 {
		t.Fatalf("default padding: chain length = %d, want >= 2 (leaf + padding)", got)
	}
	total := certChainBytes(srv.cachedCert.Certificate)
	if total < 3000 {
		t.Fatalf("default padding: chain total %d, want >= 3000 bytes", total)
	}
}

// --- F-4: real defunct-CA Subject/Issuer strings ----------------------------

// matchesCuratedDefunctCA reports whether name carries a CommonName whose
// prefix matches one of the curated defunct-CA pool entries. Padding certs
// suffix the picked CN with 16 random hex chars (for byte-uniqueness across
// two padding chains), so callers compare on prefix not equality.
func matchesCuratedDefunctCA(name pkix.Name) (string, bool) {
	for _, want := range defunctRootCAEntries {
		if strings.HasPrefix(name.CommonName, want.Subject.CommonName) {
			return want.Subject.CommonName, true
		}
	}
	return "", false
}

func TestCertPaddingIssuerNotFabricated(t *testing.T) {
	// The fabricated strings "Internet Trust Services Root R3" /
	// "Edge TLS Intermediate CA <hex>" had zero hits on the public
	// internet, making them a unique fingerprint. Padding must no longer
	// use them; both Subject.CommonName AND Issuer.CommonName (the cert is
	// self-signed, so they coincide) must come from the curated
	// defunct-real-CA pool.
	der, err := generateDummyCACert()
	if err != nil {
		t.Fatalf("generateDummyCACert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	for _, banned := range []string{
		"Internet Trust Services Root R3",
		"Edge TLS Intermediate CA",
		"Internet Trust Services CA",
	} {
		if strings.Contains(cert.Subject.CommonName, banned) ||
			strings.Contains(cert.Issuer.CommonName, banned) {
			t.Fatalf("padding cert still uses fabricated %q DN (review F-4 regression): subject=%q issuer=%q",
				banned, cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}
	if _, ok := matchesCuratedDefunctCA(cert.Subject); !ok {
		t.Fatalf("padding cert Subject.CommonName = %q, not from curated defunct-CA pool", cert.Subject.CommonName)
	}
	if _, ok := matchesCuratedDefunctCA(cert.Issuer); !ok {
		t.Fatalf("padding cert Issuer.CommonName = %q, not from curated defunct-CA pool", cert.Issuer.CommonName)
	}
}

func TestCertPaddingIssuerLooksRealistic(t *testing.T) {
	// The Subject/Issuer CommonName must read like a real WebPKI root:
	// contain "Authority", "CA", or "Root". This is a weak sanity rail
	// against accidentally re-introducing a fabricated string.
	re := regexp.MustCompile(`(?i)(Authority|\bCA\b|Root)`)
	// Sample multiple times to exercise the random pool selection.
	for i := 0; i < 10; i++ {
		der, err := generateDummyCACert()
		if err != nil {
			t.Fatalf("iter %d generateDummyCACert: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("iter %d ParseCertificate: %v", i, err)
		}
		if !re.MatchString(cert.Subject.CommonName) {
			t.Fatalf("iter %d Subject.CommonName %q does not look like a real CA DN", i, cert.Subject.CommonName)
		}
		if !re.MatchString(cert.Issuer.CommonName) {
			t.Fatalf("iter %d Issuer.CommonName %q does not look like a real CA DN", i, cert.Issuer.CommonName)
		}
	}
}

// TestCertPaddingChainSize_HitsTargetBytes (F-4 follow-up): the curated
// defunct-CA pool DN strings are 250-400 B shorter per cert than the
// previous fabricated names, so 3 dummies alone no longer reach the 4200 B
// target the production call site requests (server.go:178). The fix in
// padCertChain treats dummyCount as a MIN cert-floor and targetExtraBytes as
// a real BYTE-floor (loop runs until both are met). This probe asserts the
// invariant holds in 100/100 runs at the production parameters.
func TestCertPaddingChainSize_HitsTargetBytes(t *testing.T) {
	const (
		runs   = 100
		target = 4200
		count  = 3
	)
	for i := 0; i < runs; i++ {
		out, err := padCertChain([][]byte{}, target, count)
		if err != nil {
			t.Fatalf("run %d padCertChain: %v", i, err)
		}
		size := certChainBytes(out)
		if size < target {
			t.Fatalf("run %d: padding chain size = %d, want >= %d (target=%d count=%d)",
				i, size, target, target, count)
		}
		if len(out) < count {
			t.Fatalf("run %d: chain length = %d, want >= %d (count floor)", i, len(out), count)
		}
	}
}

func TestPickDefunctIssuerCoversPool(t *testing.T) {
	// Across many draws, all entries in the pool should be reachable.
	// Probabilistic but loose: 200 draws across N entries gives ~200/N each
	// in expectation, so requiring each to appear at least once is safe.
	seen := make(map[string]bool, len(defunctRootCAEntries))
	for i := 0; i < 200; i++ {
		got := pickDefunctEntry()
		seen[got.Subject.CommonName] = true
	}
	for _, want := range defunctRootCAEntries {
		if !seen[want.Subject.CommonName] {
			t.Errorf("pickDefunctEntry never returned %q in 200 draws", want.Subject.CommonName)
		}
	}
}

// --- F-RR-1: validity dates anchored to real CA timestamps ------------------

// TestCertPaddingValidityMatchesRealCADate (F-RR-1) asserts that any
// generated dummy padding cert's NotBefore/NotAfter matches one of the
// curated real-CA validity periods (within ±1 day tolerance for time-zone
// safety). Previously the code wrote NotBefore=now-1y / NotAfter=now+10y,
// which is provably impossible vs public CCADB records — a censor can
// detect padding by cross-referencing CN against published validity.
func TestCertPaddingValidityMatchesRealCADate(t *testing.T) {
	const tolerance = 24 * time.Hour
	// Sample multiple times so each pool entry is exercised in expectation.
	for i := 0; i < 50; i++ {
		der, err := generateDummyCACert()
		if err != nil {
			t.Fatalf("iter %d generateDummyCACert: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("iter %d ParseCertificate: %v", i, err)
		}

		// Find which curated entry this cert is supposed to mimic by CN
		// prefix (CN gets a 16-hex random suffix appended).
		var matched *defunctCAEntry
		for j := range defunctRootCAEntries {
			e := &defunctRootCAEntries[j]
			if strings.HasPrefix(cert.Subject.CommonName, e.Subject.CommonName) {
				matched = e
				break
			}
		}
		if matched == nil {
			t.Fatalf("iter %d: cert Subject.CommonName %q does not match any curated entry",
				i, cert.Subject.CommonName)
		}

		nbDelta := cert.NotBefore.Sub(matched.NotBefore)
		if nbDelta < 0 {
			nbDelta = -nbDelta
		}
		if nbDelta > tolerance {
			t.Errorf("iter %d (%s): NotBefore = %s, expected ≈ %s (Δ=%s > %s)",
				i, matched.Subject.CommonName, cert.NotBefore, matched.NotBefore, nbDelta, tolerance)
		}

		naDelta := cert.NotAfter.Sub(matched.NotAfter)
		if naDelta < 0 {
			naDelta = -naDelta
		}
		if naDelta > tolerance {
			t.Errorf("iter %d (%s): NotAfter = %s, expected ≈ %s (Δ=%s > %s)",
				i, matched.Subject.CommonName, cert.NotAfter, matched.NotAfter, naDelta, tolerance)
		}
	}
}

// TestCertPaddingValidityNotCurrentDate (F-RR-1 regression guard) asserts
// that a freshly generated padding cert's NotBefore is NOT anchored to
// time.Now(). Earlier code used now-1y; the fix anchors to the historical
// real-CA NotBefore, which for every curated entry is at least 5 years in
// the past. Using a 2-year floor below "now" gives generous slack for any
// future entry additions while still catching a regression to time.Now().
func TestCertPaddingValidityNotCurrentDate(t *testing.T) {
	der, err := generateDummyCACert()
	if err != nil {
		t.Fatalf("generateDummyCACert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	twoYearsAgo := time.Now().Add(-2 * 365 * 24 * time.Hour)
	if cert.NotBefore.After(twoYearsAgo) {
		t.Fatalf("NotBefore = %s is within last 2 years (regression: looks anchored to time.Now); curated entries are all ≥5y old",
			cert.NotBefore)
	}
}
