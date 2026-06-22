// Command tamizdat-node runs a tamizdat proxy node configured by a JSON
// file. Unlike tamizdat-server / tamizdat-client, this binary supports
// multiple inbounds, multiple outbounds, and rule-based routing in the
// style of xray-core / v2ray.
//
// Usage:
//
//	tamizdat-node -config /etc/tamizdat/node.json
//
// See cmd/tamizdat-node/example-config.json for a documented example.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/funnybones69/tamizdat/node"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("--config is required")
	}

	cfg, err := node.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	n, err := node.New(cfg)
	if err != nil {
		log.Fatalf("node: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("tamizdat-node: shutting down")
		cancel()
	}()

	log.Printf("tamizdat-node: started with %d inbounds, %d outbounds, %d rules",
		len(cfg.Inbounds), len(cfg.Outbounds), len(cfg.Routing.Rules))

	if err := n.Start(ctx); err != nil && err != context.Canceled {
		log.Fatalf("node.Start: %v", err)
	}
	_ = n.Close()
}
