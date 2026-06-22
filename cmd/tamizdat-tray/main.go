//go:build windows

// Command tamizdat-tray is a Windows system-tray front-end for the
// tamizdat TUN engine. One static .exe — the TUN engine binary plus the
// Wintun driver are embedded and extracted at first start to
// %LOCALAPPDATA%\Tamizdat-Tray\.
//
// Reads config.uri next to the executable: one tamizdat:// URI per non-empty
// line. With multiple URI lines, the tray shows a Servers submenu and reconnects
// when another server is selected.
// Base menu: Connect/Disconnect, optional Servers, Show Log / Hide Log, Exit.
// The TUN engine itself owns route configuration (--auto-route=true).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
)

func main() {
	hideConsole()

	if !isElevated() {
		if err := relaunchElevated(); err != nil {
			msgBoxf("Tamizdat tray must be run as Administrator (route + netsh).\n\n%v", err)
		}
		return
	}

	workDir := exeDir()
	cfgPath := filepath.Join(workDir, configFileName)
	if _, err := os.Stat(cfgPath); err != nil {
		msgBoxf("%s not found next to the .exe\nlooking at: %s", configFileName, cfgPath)
		return
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		msgBoxf("%s: %v", configFileName, err)
		return
	}

	tunExe, _, err := extractEmbeddedAssets()
	if err != nil {
		msgBoxf("failed to extract bundled TUN engine: %v", err)
		return
	}

	ring := newLogRing(2000)
	logPath := filepath.Join(workDir, "tamizdat-tray.log")
	if f, ferr := openRotatingLogWriter(logPath, trayLogMaxBytes, trayLogMaxBackups); ferr == nil {
		defer f.Close()
		ring.SetFile(f)
	}
	app := newTrayApp(cfg, tunExe, ring)
	systray.Run(app.onReady, app.onExit)
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	procIsUserAdmin   = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
	procMessageBoxW   = user32.NewProc("MessageBoxW")
	procGetConsoleWnd = kernel32.NewProc("GetConsoleWindow")
)

func isElevated() bool {
	r, _, _ := procIsUserAdmin.Call()
	return r != 0
}

func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwd, _ := syscall.UTF16PtrFromString(exeDir())
	r, _, e := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exePtr)),
		0,
		uintptr(unsafe.Pointer(cwd)),
		1,
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecute failed (code=%d): %v", r, e)
	}
	return nil
}

func msgBoxf(format string, args ...any) {
	text, _ := syscall.UTF16PtrFromString(fmt.Sprintf(format, args...))
	caption, _ := syscall.UTF16PtrFromString("Tamizdat tray")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), 0x10)
}

func hideConsole() {
	r, _, _ := procGetConsoleWnd.Call()
	if r != 0 {
		procShowWindow.Call(r, 0)
	}
}
