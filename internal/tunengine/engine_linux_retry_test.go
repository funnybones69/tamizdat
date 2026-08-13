//go:build linux

package tunengine

import (
	"errors"
	"testing"
)

func TestTransientTUNBusyClassification(t *testing.T) {
	if !transientTUNBusy(errors.New("create tun: device or resource busy")) {
		t.Fatal("EBUSY was not classified as transient")
	}
	if transientTUNBusy(errors.New("create tun: permission denied")) {
		t.Fatal("non-EBUSY error was classified as transient")
	}
}
