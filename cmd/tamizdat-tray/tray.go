//go:build windows

package main

import (
	"sync/atomic"

	"github.com/getlantern/systray"
)

type trayApp struct {
	cfg    *Config
	tunExe string
	logr   *logRing
	logwin *logWindow
	child  *Child

	mConnect *systray.MenuItem
	mLog     *systray.MenuItem
	mExit    *systray.MenuItem

	connected atomic.Bool
}

func newTrayApp(cfg *Config, tunExe string, logr *logRing) *trayApp {
	a := &trayApp{cfg: cfg, tunExe: tunExe, logr: logr}
	// Log window: pass a callback so the X close button keeps the tray
	// in sync — clicking [X] hides the window AND flips the menu item
	// back to 'Show Log'.
	a.logwin = newLogWindow(logr, func() { a.refresh() })
	a.child = newChild(tunExe, cfg, logr.Log,
		func() {
			a.connected.Store(false)
			a.refresh()
		},
		func() {
			a.connected.Store(true)
			a.refresh()
		},
	)
	return a
}

func (a *trayApp) onReady() {
	systray.SetTitle("Tamizdat")
	systray.SetTooltip("Tamizdat — starting…")
	systray.SetIcon(embeddedIconOrange)

	a.mConnect = systray.AddMenuItem("Disconnect", "Stop the TUN engine")
	a.mLog = systray.AddMenuItem("Show Log", "Toggle the log window")
	systray.AddSeparator()
	a.mExit = systray.AddMenuItem("Exit", "Quit Tamizdat tray")

	a.logr.Log("=== tamizdat-tray ready ===")
	a.logr.Log("config: %s", a.cfg.String())
	a.logr.Log("tun-engine: %s", a.tunExe)

	go a.menuLoop()

	// Auto-connect on launch — the operator never wants to manually click
	// Connect on every boot. Failure handling is identical to a manual
	// click: child.Start errors are logged and refresh() reverts the
	// button to 'Connect'; ready-timeout watchdog catches stuck child.
	go func() {
		a.logr.Log("auto-connect …")
		if err := a.child.Start(); err != nil {
			a.logr.Log("auto-connect start failed: %v", err)
		}
		a.refresh()
	}()
}

func (a *trayApp) onExit() {
	if a.child.IsRunning() {
		a.child.Stop()
	}
}

func (a *trayApp) menuLoop() {
	for {
		select {
		case <-a.mConnect.ClickedCh:
			if a.child.IsRunning() {
				a.child.Stop()
			} else {
				a.connected.Store(false)
				if err := a.child.Start(); err != nil {
					a.logr.Log("start failed: %v", err)
					continue
				}
			}
			a.refresh()
		case <-a.mLog.ClickedCh:
			if a.logwin.IsVisible() {
				a.logwin.Hide()
			} else {
				a.logwin.Open()
			}
			a.refresh()
		case <-a.mExit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func (a *trayApp) refresh() {
	if a.mConnect == nil {
		return
	}
	if a.child.IsRunning() {
		a.mConnect.SetTitle("Disconnect")
	} else {
		a.mConnect.SetTitle("Connect")
	}
	if a.logwin.IsVisible() {
		a.mLog.SetTitle("Hide Log")
	} else {
		a.mLog.SetTitle("Show Log")
	}
	// 3-state icon: green=fully connected, orange=child running but not
	// yet reported ready (or starting up), red=fully stopped.
	switch {
	case a.child.IsRunning() && a.connected.Load():
		systray.SetIcon(embeddedIconGreen)
		systray.SetTooltip("Tamizdat — connected")
	case a.child.IsRunning():
		systray.SetIcon(embeddedIconOrange)
		systray.SetTooltip("Tamizdat — starting…")
	default:
		systray.SetIcon(embeddedIconRed)
		systray.SetTooltip("Tamizdat — disconnected")
	}
}
