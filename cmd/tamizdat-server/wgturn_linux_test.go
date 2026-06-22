//go:build linux

package main

import (
	"os"
	"testing"
)

func TestConfigureWGTurnSettingsDoesNotDisableExplicitCLIListenFromArgs(t *testing.T) {
	oldArgs := os.Args
	oldListen := *wgturnListen
	oldPassword := *wgturnPassword
	defer func() {
		os.Args = oldArgs
		*wgturnListen = oldListen
		*wgturnPassword = oldPassword
	}()

	os.Args = []string{"tamizdat-server", "-wgturn-listen", "0.0.0.0:5000", "-wgturn-password", "secret"}
	*wgturnListen = "0.0.0.0:5000"
	*wgturnPassword = "secret"

	configureWGTurnFromSettings(map[string]string{
		"wgturn_enabled":  "0",
		"wgturn_listen":   "",
		"wgturn_password": "",
	}, map[string]bool{})

	if got := *wgturnListen; got != "0.0.0.0:5000" {
		t.Fatalf("wgturn listen after settings override = %q, want CLI value", got)
	}
	if got := *wgturnPassword; got != "secret" {
		t.Fatalf("wgturn password after settings override = %q, want CLI value", got)
	}
}
