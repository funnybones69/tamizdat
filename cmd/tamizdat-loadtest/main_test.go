package main

import (
	"context"
	"testing"
	"time"
)

func TestSmokeLoadHarness(t *testing.T) {
	cfg := defaultLoadConfig()
	cfg.Concurrency = 5
	cfg.Duration = 5 * time.Second
	cfg.OriginSize = 1024
	cfg.ThinkTimeMin = 10 * time.Millisecond
	cfg.ThinkTimeMax = 20 * time.Millisecond
	cfg.EnableDebug = false
	cfg.ServerListen = "127.0.0.1:0"
	cfg.SocksListen = "127.0.0.1:0"
	cfg.OriginListen = "127.0.0.1:0"
	cfg.DebugListen = "127.0.0.1:0"
	cfg.Out = ""

	report, err := runHarness(context.Background(), cfg)
	if err != nil {
		t.Fatalf("runHarness: %v", err)
	}
	if report.Summary.TotalRequests == 0 {
		t.Fatal("total_requests = 0, want non-zero")
	}
	if report.Summary.SuccessCount == 0 {
		t.Fatalf("success_count = 0, errors = %#v", report.Summary.Errors)
	}
	if report.Summary.SuccessRate <= 0 {
		t.Fatalf("success_rate = %v, want > 0", report.Summary.SuccessRate)
	}
	if len(report.TimeseriesThroughputMbps) == 0 {
		t.Fatal("timeseries throughput is empty")
	}
}

func TestPercentileUsesSpecIndex(t *testing.T) {
	values := []float64{100, 10, 50, 20, 30}
	if got := percentile(values, 95); got != 50 {
		t.Fatalf("p95 = %v, want 50", got)
	}
	if got := percentile(values, 50); got != 30 {
		t.Fatalf("p50 = %v, want 30", got)
	}
}
