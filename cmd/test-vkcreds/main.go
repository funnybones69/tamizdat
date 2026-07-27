package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/funnybones69/tamizdat/internal/vkcreds"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	retries := 3
	if len(os.Args) > 1 && os.Args[1] == "-1" {
		retries = 1
	}

	cfg := &vkcreds.Config{
		AppID:      "6287487",
		AppSecret:  "QbYic1K3lEV5kTGiqlq2",
		UserAgent:  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36",
		DeviceID:   fmt.Sprintf("test-device-%d", time.Now().UnixNano()%100000),
		MaxRetries: retries,
	}

	hash := "x6JP_J-27LeyT158D_yLrpuqeEoLYN_ogPTv16CuJbE"
	log.Printf("Testing VK credential acquisition for hash: %s (retries: %d, device: %s)", hash, retries, cfg.DeviceID)

	start := time.Now()
	creds, err := vkcreds.GetCredentials(ctx, cfg, hash)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("FAILED after %v: %v", elapsed, err)
		os.Exit(1)
	}
	fmt.Printf("SUCCESS in %v:\n  User: %s\n  TurnURLs: %v\n  Lifetime: %d\n", elapsed, creds.User, creds.TurnURLs, creds.Lifetime)
}
