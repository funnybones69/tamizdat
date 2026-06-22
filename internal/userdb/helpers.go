package userdb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// GenerateHex returns 2*n lower-case hex chars of secure random bytes.
func GenerateHex(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("invalid random byte count %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateUserID returns a 16-hex-char (8 random bytes) user identifier.
func GenerateUserID() (string, error) { return GenerateHex(8) }

// GenerateMasterShortID returns a 16-hex-char (8 random bytes) master shortid.
func GenerateMasterShortID() (string, error) { return GenerateHex(8) }

// NormalizeShortIDHex lower-cases + trims a candidate master shortid hex
// string and validates its length / hex character set.
func NormalizeShortIDHex(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 16 {
		return "", fmt.Errorf("shortid must be 16 hex chars")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("shortid must be hex: %w", err)
	}
	return s, nil
}
