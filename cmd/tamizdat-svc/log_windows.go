//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const programDataSDDL = `D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200A9;;;AU)`

func programDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Tamizdat")
	}
	return filepath.Join(os.TempDir(), "Tamizdat")
}
func ensureProgramDataDir() (string, error) {
	return ensureProgramDataDirACL(false)
}

func ensureProgramDataDirForInstall() (string, error) {
	return ensureProgramDataDirACL(true)
}

func ensureProgramDataDirACL(strict bool) (string, error) {
	d := programDataDir()
	if err := os.MkdirAll(d, 0755); err != nil {
		return "", err
	}
	if err := applyProgramDataACL(d); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not apply Tamizdat ProgramData ACL to %s: %v\n", d, err)
		if strict {
			return "", fmt.Errorf("apply Tamizdat ProgramData ACL to %s: %w (run installer as Administrator and verify ACL permissions)", d, err)
		}
	}
	return d, nil
}

func applyProgramDataACL(d string) error {
	sd, err := windows.SecurityDescriptorFromString(programDataSDDL)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

type dailyLogWriter struct {
	mu       sync.Mutex
	file     *os.File
	day, dir string
}

func newDailyLogWriter(dir string) (*dailyLogWriter, error) {
	w := &dailyLogWriter{dir: dir}
	return w, w.rotate(time.Now())
}
func (w *dailyLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if d := time.Now().Format("20060102"); d != w.day {
		if err := w.rotate(time.Now()); err != nil {
			return 0, err
		}
	}
	return w.file.Write(p)
}
func (w *dailyLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
func (w *dailyLogWriter) rotate(now time.Time) error {
	if w.file != nil {
		_ = w.file.Close()
	}
	w.day = now.Format("20060102")
	p := filepath.Join(w.dir, "service.log")
	if st, err := os.Stat(p); err == nil && st.ModTime().Format("20060102") != w.day {
		_ = os.Rename(p, filepath.Join(w.dir, fmt.Sprintf("service-%s.log", st.ModTime().Format("20060102"))))
	}
	m, _ := filepath.Glob(filepath.Join(w.dir, "service-*.log"))
	sort.Strings(m)
	for len(m) > 9 {
		_ = os.Remove(m[0])
		m = m[1:]
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.file = f
	return nil
}
