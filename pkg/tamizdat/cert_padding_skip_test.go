package tamizdat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// expvarSnapshot captures the cert-padding counters for diff testing.
type expvarSnapshot struct {
	applied         int64
	skippedNatural  int64
	skippedDisabled int64
	errors          int64
}

func snapCertPaddingCounters() expvarSnapshot {
	return expvarSnapshot{
		applied:         certPaddingApplied.Value(),
		skippedNatural:  certPaddingSkippedNatural.Value(),
		skippedDisabled: certPaddingSkippedDisabled.Value(),
		errors:          certPaddingErrors.Value(),
	}
}

func (a expvarSnapshot) diff(b expvarSnapshot) expvarSnapshot {
	return expvarSnapshot{
		applied:         b.applied - a.applied,
		skippedNatural:  b.skippedNatural - a.skippedNatural,
		skippedDisabled: b.skippedDisabled - a.skippedDisabled,
		errors:          b.errors - a.errors,
	}
}

// makeNamedSelfSignedCert returns a small self-signed cert (~600-800 bytes
// DER) suitable for the cert-padding skip-test paths. We need a cert with
// CommonName so x509.MarshalECPrivateKey/CreateCertificate succeed without
// extra DNSNames bloat.
func makeNamedSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func newTestServerWithCert(t *testing.T, certPEM, keyPEM []byte, disablePadding bool) *Server {
	t.Helper()
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	s, err := NewServer(ServerConfig{
		PrivateKey:         priv,
		MasterShortID:      shortID,
		CertPEM:            certPEM,
		KeyPEM:             keyPEM,
		DisableCertPadding: disablePadding,
		Handler: func(context.Context, net.Conn, string) {
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// TestCertPadding_AppliedWhenNaturalChainSmall is the F-RR-2 baseline: a
// small self-signed leaf (< 4 KB) gets the dummy-CA padding. Counter
// `tamizdat.cert_padding.applied` increments by exactly 1.
func TestCertPadding_AppliedWhenNaturalChainSmall(t *testing.T) {
	certPEM, keyPEM := makeNamedSelfSignedCert(t, "small.example.com")
	pre := snapCertPaddingCounters()
	s := newTestServerWithCert(t, certPEM, keyPEM, false)
	defer s.Close()
	d := pre.diff(snapCertPaddingCounters())
	if d.applied != 1 {
		t.Fatalf("certPaddingApplied delta = %d, want 1 (snapshot %+v)", d.applied, d)
	}
	// The leaf chain should now have been extended with padding certs.
	if s.cachedCert == nil {
		t.Fatal("cachedCert is nil")
	}
	if len(s.cachedCert.Certificate) < 2 {
		t.Fatalf("padded chain has %d cert(s), want >=2 (leaf + at least one padding)", len(s.cachedCert.Certificate))
	}
}

// TestCertPadding_SkippedWhenDisabled is the F-RR-3 regression guard: a
// caller that sets ServerConfig.DisableCertPadding=true keeps the natural
// chain and bumps the skipped_disabled counter. Used by operators with a
// real LE chain.
func TestCertPadding_SkippedWhenDisabled(t *testing.T) {
	certPEM, keyPEM := makeNamedSelfSignedCert(t, "disable.example.com")
	pre := snapCertPaddingCounters()
	s := newTestServerWithCert(t, certPEM, keyPEM, true)
	defer s.Close()
	d := pre.diff(snapCertPaddingCounters())
	if d.skippedDisabled != 1 {
		t.Fatalf("certPaddingSkippedDisabled delta = %d, want 1 (snapshot %+v)", d.skippedDisabled, d)
	}
	if d.applied != 0 {
		t.Fatalf("certPaddingApplied delta = %d, want 0 when DisableCertPadding=true", d.applied)
	}
	if s.cachedCert == nil {
		t.Fatal("cachedCert is nil")
	}
	if got := len(s.cachedCert.Certificate); got != 1 {
		t.Fatalf("chain length = %d, want exactly 1 (no padding when DisableCertPadding=true)", got)
	}
}

// TestCertPadding_SkippedWhenNaturalChainLarge is the F-RR-2 core: when the
// caller provides a chain that already meets/exceeds the target+margin
// (e.g. real LE with intermediate, or operator-supplied bundle), padding
// is skipped to avoid producing a Frankenstein chain. We synthesize a
// large-enough chain by handing NewServer a multi-cert PEM whose total
// DER size crosses 4200+256 bytes.
func TestCertPadding_SkippedWhenNaturalChainLarge(t *testing.T) {
	// Concatenate one ECDSA leaf with enough RSA-2048 dummy CAs to push the
	// total past 4200+256 = 4456 bytes. Empirically each dummyCA ends up
	// ~700-750 bytes DER, so 7 dummies + leaf = ~5200 bytes (>= threshold).
	leafPEM, keyPEM := makeNamedSelfSignedCert(t, "large.example.com")
	bigPEM := append([]byte(nil), leafPEM...)
	const dummyCount = 7
	for i := 0; i < dummyCount; i++ {
		der, err := generateDummyCACert()
		if err != nil {
			t.Fatalf("generateDummyCACert: %v", err)
		}
		bigPEM = append(bigPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	pre := snapCertPaddingCounters()
	s := newTestServerWithCert(t, bigPEM, keyPEM, false)
	defer s.Close()
	d := pre.diff(snapCertPaddingCounters())
	if d.skippedNatural != 1 {
		t.Fatalf("certPaddingSkippedNatural delta = %d, want 1 (snapshot %+v)", d.skippedNatural, d)
	}
	if d.applied != 0 {
		t.Fatalf("certPaddingApplied delta = %d, want 0 when natural chain already exceeds target", d.applied)
	}
	if s.cachedCert == nil {
		t.Fatal("cachedCert is nil")
	}
	// 1 leaf + 7 dummy CAs = 8 certs, NOT additional padding tacked on.
	if got := len(s.cachedCert.Certificate); got != 1+dummyCount {
		t.Fatalf("chain length = %d, want exactly %d (no extra padding when natural chain already large)", got, 1+dummyCount)
	}
}
