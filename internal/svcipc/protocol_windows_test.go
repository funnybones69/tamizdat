//go:build windows

package svcipc

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestPipeSDDLParsesOnWindows(t *testing.T) {
	if _, err := windows.SecurityDescriptorFromString(PipeSDDL); err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
}
