//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tamizdat-svc is only supported on Windows; cross-compile with GOOS=windows GOARCH=amd64")
	os.Exit(2)
}
