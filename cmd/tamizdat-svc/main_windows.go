//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/funnybones69/tamizdat/internal/routing"
	"github.com/funnybones69/tamizdat/internal/svcipc"
	"golang.org/x/sys/windows/svc"
)

func main() {
	defer writePanicFile()
	exe, _ := os.Executable()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			fatalIf(installService(exe))
			return
		case "uninstall":
			fatalIf(uninstallService())
			return
		case "start":
			fatalIf(startService())
			return
		case "stop":
			fatalIf(stopService())
			return
		case "debug":
			fatalIf(runConsole())
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: %s [install|uninstall|start|stop|debug]\n", filepath.Base(os.Args[0]))
			os.Exit(2)
		}
	}
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		fatalIf(err)
		return
	}
	if !isSvc {
		fatalIf(runConsole())
		return
	}
	fatalIf(svc.Run(serviceName, &svcHandler{}))
}

func fatalIf(err error) {
	if err != nil {
		log.Printf("fatal: %v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type svcHandler struct{}

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel, cleanup, err := startApp()
	if err != nil {
		log.Printf("start service: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	cleaned := false
	doCleanup := func() {
		if !cleaned {
			cleanup()
			cleaned = true
		}
	}
	defer doCleanup()
	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Pause:
			changes <- svc.Status{State: svc.Paused, Accepts: accepts}
		case svc.Continue:
			changes <- svc.Status{State: svc.Running, Accepts: accepts}
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			<-ctx.Done()
			doCleanup()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

func runConsole() error {
	ctx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	appCtx, cancel, cleanup, err := startApp()
	if err != nil {
		return err
	}
	defer cleanup()
	select {
	case <-ctx.Done():
		cancel()
	case <-appCtx.Done():
	}
	<-appCtx.Done()
	return nil
}

func startApp() (context.Context, context.CancelFunc, func(), error) {
	dir, err := ensureProgramDataDir()
	if err != nil {
		return nil, nil, nil, err
	}
	lw, err := newDailyLogWriter(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	logs := newLogHub()
	log.SetOutput(io.MultiWriter(lw, logs))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	wintunPath, err := svcipc.ExtractWintun()
	if err != nil {
		_ = lw.Close()
		return nil, nil, nil, err
	}
	log.Printf("wintun extracted: %s sha256=%s", wintunPath, svcipc.WintunSHA256)
	ctx, cancel := context.WithCancel(context.Background())
	routing.CleanupOrphanTUNRoutes(ctx, "10.255.0.1", "10.255.0.2")
	rt := newServiceRuntime(newWindowsEngine(wintunPath))
	server := newIPCServer(rt, logs)
	go func() {
		if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("ipc server: %v", err)
			cancel()
		}
	}()
	cleanup := func() {
		cancel()
		_ = server.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer stopCancel()
		_ = rt.Shutdown(stopCtx)
		_ = lw.Close()
	}
	return ctx, cancel, cleanup, nil
}

func writePanicFile() {
	if r := recover(); r != nil {
		dir, _ := ensureProgramDataDir()
		name := filepath.Join(dir, "panic-"+time.Now().Format("20060102-150405")+".txt")
		_ = os.WriteFile(name, append([]byte(fmt.Sprintf("panic: %v\n\n", r)), debug.Stack()...), 0644)
		panic(r)
	}
}
