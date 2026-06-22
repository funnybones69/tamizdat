// routing-probe — tiny SOCKS5 probe for the e2e routing test rig.
//
// Opens a TCP connection to <dst> via the SOCKS5 endpoint on
// 127.0.0.1:1080 (default; -socks overrides), prints one of:
//
//	OK <dst>            — handshake completed, conn opened
//	ERR <error-text>    — failed before or during connect
//
// Built as a fully-static aarch64 binary to live on operator's home router
// (ImmortalWrt / aarch64) where curl + glibc aren't readily available.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 endpoint to probe through")
	timeout := flag.Duration("timeout", 5*time.Second, "dial timeout")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: routing-probe [-socks 127.0.0.1:1080] [-timeout 5s] <host:port>")
		os.Exit(2)
	}
	dst := flag.Arg(0)
	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Println("ERR socks5-init", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dialer.Dial("tcp", dst)
		if conn != nil {
			conn.Close()
		}
		ch <- result{err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			fmt.Println("ERR", r.err)
			os.Exit(1)
		}
		fmt.Println("OK", dst)
	case <-ctx.Done():
		fmt.Println("ERR timeout")
		os.Exit(1)
	}
}
