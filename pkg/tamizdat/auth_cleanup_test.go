package tamizdat

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifySessionIDv1_NoProductionCallers locks in C-2 cleanup: the legacy
// slice-allowlist form `VerifySessionIDv1` (deprecated) must not be invoked
// from any non-test .go file in the repo root. Hot-path callers
// (handleConnection) use `VerifySessionIDAny` (which dispatches to
// `VerifySessionIDv2Single` / `VerifySessionIDv1Single`); the slice form is
// retained only for tests that explicitly assert allowlist semantics.
//
// Guard against a regression where a future contributor calls the slice form
// from production code, dragging back the tautological-allowlist API smell
// review-C tell #X flagged.
func TestVerifySessionIDv1_NoProductionCallers(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no *.go files matched in package root")
	}

	fset := token.NewFileSet()
	for _, path := range matches {
		// Skip the definition file itself and any *_test.go.
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if path == "auth.go" {
			// auth.go is the definition site; the function body of
			// `VerifySessionIDv1` calls `verifySessionIDSlice` and
			// references its own name only in the func declaration.
			// We allow that.
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if ident.Name == "VerifySessionIDv1" {
				pos := fset.Position(ident.Pos())
				t.Errorf(
					"%s:%d: production code must not call deprecated VerifySessionIDv1 (slice form). Use VerifySessionIDAny or VerifySessionIDv1Single.",
					path, pos.Line,
				)
			}
			return true
		})
	}
}

// TestVerifySessionIDv1Single_MatchesSliceFormOnSingleton confirms the
// exact-match Single form returns the same accept/reject as the slice form
// when given a single-element allowlist that equals the SessionID's claimed
// shortID — i.e. the tautological hot-path call we replaced was indeed a
// pure simplification and not a behavioural change.
func TestVerifySessionIDv1Single_MatchesSliceFormOnSingleton(t *testing.T) {
	psk, ephPub, shortID := newAuthTriple(t)
	sid, err := BuildSessionIDv1(psk, shortID, ephPub, nil)
	if err != nil {
		t.Fatalf("BuildSessionIDv1: %v", err)
	}

	// Both forms accept on a valid SessionID with the right shortID.
	gotSingle, err := VerifySessionIDv1Single(sid[:], psk, ephPub, shortID)
	if err != nil {
		t.Fatalf("Single err: %v", err)
	}
	verified, gotSlice, err := VerifySessionIDv1(sid[:], psk, ephPub, [][shortIDLen]byte{shortID})
	if err != nil {
		t.Fatalf("Slice err: %v", err)
	}
	if gotSingle != gotSlice {
		t.Fatalf("parity mismatch on accept: single=%v slice=%v", gotSingle, gotSlice)
	}
	if verified != shortID {
		t.Fatal("slice form did not return the verified shortID")
	}

	// Both forms reject on a wrong-PSK case (tag mismatch).
	badPSK := make([]byte, len(psk))
	copy(badPSK, psk)
	badPSK[0] ^= 0xFF
	gotSingle, err = VerifySessionIDv1Single(sid[:], badPSK, ephPub, shortID)
	if err != nil {
		t.Fatalf("Single err on bad PSK: %v", err)
	}
	_, gotSlice, err = VerifySessionIDv1(sid[:], badPSK, ephPub, [][shortIDLen]byte{shortID})
	if err != nil {
		t.Fatalf("Slice err on bad PSK: %v", err)
	}
	if gotSingle != gotSlice {
		t.Fatalf("parity mismatch on bad-PSK reject: single=%v slice=%v", gotSingle, gotSlice)
	}
	if gotSingle {
		t.Fatal("expected reject on bad PSK")
	}
}
