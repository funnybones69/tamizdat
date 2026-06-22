//go:build linux

package wgturn

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	wgIfaceName = "wgturn0"
	wgMTU       = 1280
)

// createTUN creates a userspace WireGuard device with a TUN interface.
// It returns the device and the actual TUN interface name (which may
// differ from the requested name on some kernels).
func createTUN(keys *wgKeys, wgPort int) (*device.Device, string, error) {
	// Clean up any stale interface from a previous run.
	runCmdSilent("ip", "link", "del", wgIfaceName)
	time.Sleep(100 * time.Millisecond)

	tunDev, err := tun.CreateTUN(wgIfaceName, wgMTU)
	if err != nil {
		return nil, "", fmt.Errorf("CreateTUN: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, "", fmt.Errorf("TUN name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[wgturn-wg] ")
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("IpcSet: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("device.Up: %w", err)
	}

	log.Printf("[wgturn] WireGuard device up on port %d, iface %s", wgPort, ifaceName)
	return dev, ifaceName, nil
}

// configureInterface assigns the server IP and brings the TUN interface up.
func configureInterface(ifaceName, serverCIDR string) error {
	for _, cmd := range [][]string{
		{"ip", "addr", "add", serverCIDR, "dev", ifaceName},
		{"ip", "link", "set", "mtu", fmt.Sprintf("%d", wgMTU), "dev", ifaceName},
		{"ip", "link", "set", ifaceName, "up"},
	} {
		out, err := runCmd(cmd[0], cmd[1:]...)
		if err != nil && !strings.Contains(out, "File exists") {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "), out)
		}
	}
	return nil
}

// setupNAT enables ip_forward, BBR congestion control, and configures
// MASQUERADE NAT for the WireGuard subnet using iptables or nftables.
func setupNAT(wgIface, serverCIDR string) error {
	log.Println("[wgturn] configuring NAT...")

	// Enable IP forwarding.
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	// Enable BBR.
	enableBBR()

	extIface := getDefaultInterface()
	log.Printf("[wgturn] external interface: %s", extIface)

	switch {
	case commandExists("iptables"):
		setupIPTablesNAT(wgIface, extIface, serverCIDR)
	case commandExists("nft"):
		setupNftNAT(wgIface, extIface, serverCIDR)
	default:
		log.Println("[wgturn] WARNING: no iptables or nft found, NAT not configured")
	}

	log.Println("[wgturn] NAT configured")
	return nil
}

func setupIPTablesNAT(wgIface, extIface, serverCIDR string) {
	// Remove stale rules.
	for i := 0; i < 5; i++ {
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", serverCIDR, "-o", extIface,
			"-m", "comment", "--comment", "WGTURN_MANAGED",
			"-j", "MASQUERADE").Run()
	}
	exec.Command("iptables", "-t", "nat", "-I", "POSTROUTING", "1",
		"-s", serverCIDR, "-o", extIface,
		"-m", "comment", "--comment", "WGTURN_MANAGED",
		"-j", "MASQUERADE").Run()

	// FORWARD rules.
	for i := 0; i < 5; i++ {
		exec.Command("iptables", "-D", "FORWARD",
			"-i", wgIface, "-m", "comment", "--comment", "WGTURN_MANAGED",
			"-j", "ACCEPT").Run()
		exec.Command("iptables", "-D", "FORWARD",
			"-o", wgIface, "-m", "comment", "--comment", "WGTURN_MANAGED",
			"-j", "ACCEPT").Run()
	}
	exec.Command("iptables", "-A", "FORWARD",
		"-i", wgIface, "-m", "comment", "--comment", "WGTURN_MANAGED",
		"-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD",
		"-o", wgIface, "-m", "comment", "--comment", "WGTURN_MANAGED",
		"-j", "ACCEPT").Run()
}

func setupNftNAT(wgIface, extIface, serverCIDR string) {
	exec.Command("nft", "add", "table", "ip", "wgturn").Run()
	exec.Command("nft", "add", "chain", "ip", "wgturn", "postrouting",
		"{ type nat hook postrouting priority 100; }").Run()
	exec.Command("nft", "add", "rule", "ip", "wgturn", "postrouting",
		"ip", "saddr", serverCIDR, "oifname", extIface, "masquerade").Run()

	exec.Command("nft", "add", "table", "inet", "wgturn").Run()
	exec.Command("nft", "add", "chain", "inet", "wgturn", "forward",
		"{ type filter hook forward priority 0; policy accept; }").Run()
	exec.Command("nft", "add", "rule", "inet", "wgturn", "forward",
		"iifname", wgIface, "accept").Run()
	exec.Command("nft", "add", "rule", "inet", "wgturn", "forward",
		"oifname", wgIface, "accept").Run()
}

// startUAPI starts the WireGuard UAPI control socket listener so
// external tools (wg show, etc.) can inspect the device.
func startUAPI(dev *device.Device, ifaceName string) {
	go func() {
		uapiFile, err := ipc.UAPIOpen(ifaceName)
		if err != nil {
			log.Printf("[wgturn] UAPI open: %v", err)
			return
		}
		uapi, err := ipc.UAPIListen(ifaceName, uapiFile)
		if err != nil {
			log.Printf("[wgturn] UAPI listen: %v", err)
			return
		}
		defer uapi.Close()
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()
}

// enableBBR sets TCP congestion control to BBR and tunes socket buffers.
func enableBBR() {
	out, _ := runCmd("bash", "-c", "sysctl net.ipv4.tcp_congestion_control")
	if strings.Contains(out, "bbr") {
		return
	}
	cmds := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
		{"sysctl", "-w", "net.core.rmem_max=25165824"},
		{"sysctl", "-w", "net.core.wmem_max=25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 25165824"},
	}
	for _, cmd := range cmds {
		runCmd(cmd[0], cmd[1:]...)
	}
}

// --- shell helpers ---

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCmdSilent(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func getDefaultInterface() string {
	out := runCmdSilent("bash", "-c",
		"ip route show default | awk '/default/ {print $5}' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	out = runCmdSilent("bash", "-c",
		"ip -o link show | awk -F': ' '{print $2}' | grep -v -E 'lo|wg|tun|wgturn' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	return "eth0"
}
