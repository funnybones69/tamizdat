//go:build windows

package main

import (
	"sync"
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
	mServers *systray.MenuItem
	mLog     *systray.MenuItem
	mExit    *systray.MenuItem

	serverItems []*systray.MenuItem
	activeIndex int
	switchMu    sync.Mutex

	connected atomic.Bool
}

func newTrayApp(cfg *Config, tunExe string, logr *logRing) *trayApp {
	a := &trayApp{cfg: cfg, tunExe: tunExe, logr: logr, activeIndex: cfg.ProfileIndex}
	// Log window: pass a callback so the X close button keeps the tray
	// in sync — clicking [X] hides the window AND flips the menu item
	// back to 'Show Log'.
	a.logwin = newLogWindow(logr, func() { a.refresh() })
	a.child = a.makeChild(cfg)
	return a
}

func (a *trayApp) makeChild(cfg *Config) *Child {
	return newChild(a.tunExe, cfg, a.logr.Log,
		func() {
			a.connected.Store(false)
			a.refresh()
		},
		func() {
			a.connected.Store(true)
			a.refresh()
		},
	)
}

func (a *trayApp) onReady() {
	systray.SetTitle("Tamizdat")
	systray.SetTooltip("Tamizdat — starting…")
	systray.SetIcon(embeddedIconOrange)

	a.mConnect = systray.AddMenuItem("Disconnect", "Stop the TUN engine")
	if len(a.cfg.Profiles) > 1 {
		a.mServers = systray.AddMenuItem("Servers", "Select Tamizdat server")
		for i, profile := range a.cfg.Profiles {
			item := a.mServers.AddSubMenuItem(profile.Label, "Switch to "+profile.Label)
			a.serverItems = append(a.serverItems, item)
			go a.serverItemLoop(i, item.ClickedCh)
		}
	}
	a.mLog = systray.AddMenuItem("Show Log", "Toggle the log window")
	systray.AddSeparator()
	a.mExit = systray.AddMenuItem("Exit", "Quit Tamizdat tray")

	a.logr.Log("=== tamizdat-tray ready ===")
	a.logr.Log("config: %s", a.cfg.String())
	a.logr.Log("tun-engine: %s", a.tunExe)
	if len(a.cfg.Profiles) > 1 {
		a.logr.Log("servers: %d, active=%s", len(a.cfg.Profiles), a.activeServerLabel())
	}

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
	if a.child != nil && a.child.IsRunning() {
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

func (a *trayApp) serverItemLoop(index int, clicked <-chan struct{}) {
	for range clicked {
		a.switchServer(index)
	}
}

func (a *trayApp) switchServer(index int) {
	a.switchMu.Lock()
	defer a.switchMu.Unlock()

	if index < 0 || index >= len(a.cfg.Profiles) {
		return
	}
	if index == a.activeIndex {
		a.refresh()
		return
	}

	oldLabel := a.activeServerLabel()
	newCfg := a.cfg.Profiles[index].Config
	wasRunning := a.child != nil && a.child.IsRunning()
	if wasRunning {
		a.child.Stop()
	}

	a.cfg = newCfg
	a.activeIndex = index
	a.child = a.makeChild(newCfg)
	a.connected.Store(false)
	a.logr.Log("server switch: %s -> %s", oldLabel, a.activeServerLabel())
	if err := saveActiveProfile(newCfg.StatePath, newCfg); err != nil {
		a.logr.Log("remember active server failed: %v", err)
	}

	if wasRunning {
		a.logr.Log("reconnect to %s …", a.activeServerLabel())
		if err := a.child.Start(); err != nil {
			a.logr.Log("reconnect failed: %v", err)
		}
	}
	a.refresh()
}

func (a *trayApp) activeServerLabel() string {
	if a.cfg == nil {
		return ""
	}
	if a.activeIndex >= 0 && a.activeIndex < len(a.cfg.Profiles) {
		return a.cfg.Profiles[a.activeIndex].Label
	}
	return a.cfg.Server
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
	for i, item := range a.serverItems {
		if i == a.activeIndex {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
	// 3-state icon: green=fully connected, orange=child running but not
	// yet reported ready (or starting up), red=fully stopped.
	server := a.activeServerLabel()
	switch {
	case a.child.IsRunning() && a.connected.Load():
		systray.SetIcon(embeddedIconGreen)
		systray.SetTooltip("Tamizdat — connected: " + server)
	case a.child.IsRunning():
		systray.SetIcon(embeddedIconOrange)
		systray.SetTooltip("Tamizdat — starting: " + server)
	default:
		systray.SetIcon(embeddedIconRed)
		systray.SetTooltip("Tamizdat — disconnected: " + server)
	}
}
