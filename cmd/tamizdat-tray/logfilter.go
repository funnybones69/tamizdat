package main

import (
	"regexp"
	"strings"
)

var (
	tamizdatURIPattern = regexp.MustCompile(`tamizdat://[^\s"'<>]+`)
	uriArgPattern      = regexp.MustCompile(`(?i)(-config\s+)[^\s]+`)
	shortIDPattern     = regexp.MustCompile(`(?i)((?:shortid|short-id)=)[0-9a-f]+`)
	pubKeyPattern      = regexp.MustCompile(`(?i)(pubkey=)[0-9a-f]{16,}`)
)

func sanitizeLogLine(line string) string {
	line = tamizdatURIPattern.ReplaceAllString(line, "tamizdat://[redacted]")
	line = uriArgPattern.ReplaceAllString(line, "${1}[redacted]")
	line = shortIDPattern.ReplaceAllString(line, "${1}[redacted]")
	line = pubKeyPattern.ReplaceAllString(line, "${1}[redacted]")
	return line
}

func shouldLogTunLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	lower := strings.ToLower(line)
	for _, marker := range []string{
		"auto-route: default",
		"auto-route: selective",
		"auto-route: assigned",
		"connect failed",
		"route add",
		"route delete",
		"wintun",
		"adapter",
		"dns",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range []string{
		" error",
		"error:",
		"failed",
		"failure",
		"fatal",
		"panic",
		"warn",
		"denied",
		"permission",
		"timeout",
		"timed out",
		"unreachable",
		"refused",
		"reset by peer",
		"no such",
		"cannot",
		"can't",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.HasPrefix(lower, "error") || strings.HasPrefix(lower, "warn")
}
