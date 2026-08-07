//go:build linux

package localtun

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestNFTConfigMarksTCPAndUDPWithoutAutoMerge(t *testing.T) {
	r := &linuxRouteController{cfg: Config{Interface: "br-lan", BypassPrivate: true}}
	got := r.nftConfig()
	checks := []string{
		`table inet tamizdat_local`,
		`flags interval`,
		`iifname "br-lan" meta l4proto { tcp, udp } meta mark set (meta mark & 0xffffff00) | 0x9d`,
		`10.0.0.0/8`,
		`172.16.0.0/12`,
		`192.168.0.0/16`,
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Fatalf("nft config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "auto-merge") {
		t.Fatalf("nft interval set must not use auto-merge:\n%s", got)
	}
}

func TestNFTConfigCanKeepPublicCGNATEligible(t *testing.T) {
	r := &linuxRouteController{cfg: Config{Interface: "lan0", BypassPrivate: false}}
	got := r.nftConfig()
	for _, absent := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"} {
		if strings.Contains(got, absent) {
			t.Fatalf("nft config unexpectedly bypasses %s:\n%s", absent, got)
		}
	}
}

func TestIsCommandNotFoundIgnoresOnlyObjectENOENT(t *testing.T) {
	objectMissing := &commandError{
		command: "nft list table inet tamizdat_local",
		output:  "Could not process rule: No such file or directory",
		cause:   errors.New("exit status 1"),
	}
	if !isCommandNotFound(objectMissing) {
		t.Fatal("kernel object ENOENT was not recognized")
	}
	binaryMissing := &commandError{
		command: "nft list table inet tamizdat_local",
		output:  "fork/exec nft: no such file or directory",
		cause:   &os.PathError{Op: "fork/exec", Path: "nft", Err: syscall.ENOENT},
	}
	if isCommandNotFound(binaryMissing) {
		t.Fatal("missing nft executable must not be treated as successful cleanup")
	}
	permissionDenied := &commandError{
		command: "nft delete table inet tamizdat_local",
		output:  "Operation not permitted",
		cause:   errors.New("exit status 1"),
	}
	if isCommandNotFound(permissionDenied) {
		t.Fatal("permission failure must not be ignored")
	}
}
