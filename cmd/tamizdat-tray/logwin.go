//go:build windows

package main

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wsOverlapped       = 0x00000000
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsThickFrame       = 0x00040000
	wsMinimizeBox      = 0x00020000
	wsMaximizeBox      = 0x00010000
	wsOverlappedWindow = wsOverlapped | wsCaption | wsSysMenu | wsThickFrame | wsMinimizeBox | wsMaximizeBox
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsVScroll          = 0x00200000
	wsBorder           = 0x00800000
	esMultiline        = 0x0004
	esAutoVScroll      = 0x0040
	esReadOnly         = 0x0800
	swShow             = 5
	swHide             = 0
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmSize             = 0x0005
	emReplaceSel       = 0x00C2
	emSetSel           = 0x00B1
	emScrollCaret      = 0x00B7
	emSetLimitText     = 0x00C5
	emGetLineCount     = 0x00BA
	emLineIndex        = 0x00BB
	colorWindow        = 5

	// editTextLimit is the maximum number of characters the EDIT control
	// will accept. The Win32 default for a multiline EDIT is ~30,000 which
	// is easily hit in a few minutes of logging. 2 MiB gives comfortable
	// headroom.
	editTextLimit = 2 * 1024 * 1024

	// editTrimThreshold: when the EDIT control exceeds this many lines,
	// the oldest quarter is deleted to keep memory bounded. 8000 lines ≈
	// ~1 MiB of UTF-16 text at ~130 chars/line avg.
	editTrimThreshold = 8000
	editTrimFraction  = 4 // delete 1/N of lines
)

type rect struct {
	Left, Top, Right, Bottom int32
}
type msgStruct struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}
type wndclassex struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

var (
	user32              = syscall.NewLazyDLL("user32.dll")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procRegisterClassEx = user32.NewProc("RegisterClassExW")
	procCreateWindowEx  = user32.NewProc("CreateWindowExW")
	procDefWindowProc   = user32.NewProc("DefWindowProcW")
	procShowWindow      = user32.NewProc("ShowWindow")
	procUpdateWindow    = user32.NewProc("UpdateWindow")
	procGetMessage      = user32.NewProc("GetMessageW")
	procTranslateMsg    = user32.NewProc("TranslateMessage")
	procDispatchMsg     = user32.NewProc("DispatchMessageW")
	procSendMessage     = user32.NewProc("SendMessageW")
	procGetClientRect   = user32.NewProc("GetClientRect")
	procMoveWindow      = user32.NewProc("MoveWindow")
	procLoadCursor      = user32.NewProc("LoadCursorW")
	procPostQuit        = user32.NewProc("PostQuitMessage")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
)

type logWindow struct {
	mu       sync.Mutex
	hwnd     windows.Handle
	hwndEdit windows.Handle
	visible  atomic.Bool
	ready    chan struct{}
	ring     *logRing
	subCh    chan string
	stop     chan struct{}
	// onClose fires when the user dismisses the window via [X] / Alt-F4
	// so the tray can flip the menu label from 'Hide Log' back to
	// 'Show Log' without waiting for the next ClickedCh event.
	onClose func()
}

func newLogWindow(ring *logRing, onClose func()) *logWindow {
	return &logWindow{ring: ring, ready: make(chan struct{}), onClose: onClose}
}

func (w *logWindow) Open() {
	w.mu.Lock()
	if w.hwnd != 0 {
		hwnd := w.hwnd
		w.mu.Unlock()
		procShowWindow.Call(uintptr(hwnd), swShow)
		w.visible.Store(true)
		return
	}
	w.mu.Unlock()

	go w.threadMain()
	<-w.ready
}

func (w *logWindow) Hide() {
	w.mu.Lock()
	hwnd := w.hwnd
	w.mu.Unlock()
	if hwnd != 0 {
		procShowWindow.Call(uintptr(hwnd), swHide)
		w.visible.Store(false)
	}
}

func (w *logWindow) IsVisible() bool { return w.visible.Load() }

func (w *logWindow) threadMain() {
	// Win32 windows have OS-thread affinity: CreateWindowExW + the message
	// loop must run on the same OS thread, otherwise GetMessageW returns
	// nothing for the HWND and the window hangs. LockOSThread pins this
	// goroutine to its OS thread for the rest of its lifetime so the
	// affinity holds.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInstanceRaw, _, _ := procGetModuleHandle.Call(0)
	hInstance := windows.Handle(hInstanceRaw)

	className, _ := syscall.UTF16PtrFromString("TamizdatTrayLog")
	title, _ := syscall.UTF16PtrFromString("Tamizdat — Log")
	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	idcArrow := uintptr(32512)
	hCursor, _, _ := procLoadCursor.Call(0, idcArrow)

	wc := wndclassex{
		Size:       uint32(unsafe.Sizeof(wndclassex{})),
		Style:      0x0003, // CS_HREDRAW | CS_VREDRAW
		WndProc:    syscall.NewCallback(w.wndProc),
		Instance:   hInstance,
		Cursor:     windows.Handle(hCursor),
		Background: windows.Handle(colorWindow + 1),
		ClassName:  className,
	}
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	const useDefault = ^uintptr(0) - (1 << 31) + 1 // CW_USEDEFAULT
	hwnd, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow,
		useDefault, useDefault, 900, 600,
		0, 0, uintptr(hInstance), 0,
	)
	w.mu.Lock()
	w.hwnd = windows.Handle(hwnd)
	w.mu.Unlock()

	hEdit, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(editClass)),
		uintptr(unsafe.Pointer(nilU16())),
		wsChild|wsVisible|wsBorder|wsVScroll|esMultiline|esAutoVScroll|esReadOnly,
		0, 0, 884, 561,
		hwnd, 0, uintptr(hInstance), 0,
	)
	w.mu.Lock()
	w.hwndEdit = windows.Handle(hEdit)
	w.mu.Unlock()

	// Raise the EDIT text limit from the Win32 default (~30k chars) so the
	// control doesn't silently swallow new text after a few minutes of
	// logging.
	procSendMessage.Call(uintptr(hEdit), emSetLimitText, editTextLimit, 0)

	w.replaceAll(w.ring.Snapshot())

	w.subCh = w.ring.Subscribe()
	w.stop = make(chan struct{})
	go w.consumeLog()

	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	w.visible.Store(true)
	close(w.ready)

	var m msgStruct
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (w *logWindow) wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmClose:
		procShowWindow.Call(uintptr(hwnd), swHide)
		w.visible.Store(false)
		if w.onClose != nil {
			// Run async — wndProc must return promptly; refresh() touches
			// tray state on a different OS thread.
			go w.onClose()
		}
		return 0
	case wmDestroy:
		procPostQuit.Call(0)
		return 0
	case wmSize:
		var rc rect
		procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
		w.mu.Lock()
		edit := w.hwndEdit
		w.mu.Unlock()
		if edit != 0 {
			procMoveWindow.Call(uintptr(edit), 0, 0, uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top), 1)
		}
		return 0
	}
	r, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func (w *logWindow) consumeLog() {
	for {
		select {
		case line, ok := <-w.subCh:
			if !ok {
				return
			}
			w.appendLine(line)
		case <-w.stop:
			return
		}
	}
}

func (w *logWindow) replaceAll(s string) {
	w.mu.Lock()
	hEdit := w.hwndEdit
	w.mu.Unlock()
	if hEdit == 0 {
		return
	}
	procSendMessage.Call(uintptr(hEdit), emSetSel, 0, ^uintptr(0))
	ptr, _ := syscall.UTF16PtrFromString(s)
	procSendMessage.Call(uintptr(hEdit), emReplaceSel, 0, uintptr(unsafe.Pointer(ptr)))
	w.scrollEnd()
}

func (w *logWindow) appendLine(line string) {
	w.mu.Lock()
	hEdit := w.hwndEdit
	w.mu.Unlock()
	if hEdit == 0 {
		return
	}
	if !strings.HasSuffix(line, "\r\n") {
		line = line + "\r\n"
	}
	w.trimIfNeeded(hEdit)
	procSendMessage.Call(uintptr(hEdit), emSetSel, ^uintptr(0), ^uintptr(0))
	ptr, _ := syscall.UTF16PtrFromString(line)
	procSendMessage.Call(uintptr(hEdit), emReplaceSel, 0, uintptr(unsafe.Pointer(ptr)))
	w.scrollEnd()
}

// trimIfNeeded deletes the oldest 1/editTrimFraction of lines when the EDIT
// control exceeds editTrimThreshold lines. This keeps memory bounded without
// clearing the entire log.
func (w *logWindow) trimIfNeeded(hEdit windows.Handle) {
	lineCount, _, _ := procSendMessage.Call(uintptr(hEdit), emGetLineCount, 0, 0)
	if int(lineCount) < editTrimThreshold {
		return
	}
	// Delete from char 0 to the start of line (lineCount / editTrimFraction).
	cutLine := int(lineCount) / editTrimFraction
	charIdx, _, _ := procSendMessage.Call(uintptr(hEdit), emLineIndex, uintptr(cutLine), 0)
	procSendMessage.Call(uintptr(hEdit), emSetSel, 0, charIdx)
	empty, _ := syscall.UTF16PtrFromString("")
	procSendMessage.Call(uintptr(hEdit), emReplaceSel, 0, uintptr(unsafe.Pointer(empty)))
}

func (w *logWindow) scrollEnd() {
	w.mu.Lock()
	hEdit := w.hwndEdit
	w.mu.Unlock()
	if hEdit == 0 {
		return
	}
	procSendMessage.Call(uintptr(hEdit), emScrollCaret, 0, 0)
}

func nilU16() *uint16 { var z uint16; return &z }
