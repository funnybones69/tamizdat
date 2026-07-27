package wgturnclient

import (
	"testing"
	"time"
)

func TestNextQuotaRetryDelay(t *testing.T) {
	tests := []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, 5 * time.Second},
		{5 * time.Second, 10 * time.Second},
		{10 * time.Second, 20 * time.Second},
		{30 * time.Second, 60 * time.Second},
		{60 * time.Second, 60 * time.Second},
		{2 * time.Minute, 60 * time.Second},
	}
	for _, tt := range tests {
		if got := nextQuotaRetryDelay(tt.current); got != tt.want {
			t.Fatalf("nextQuotaRetryDelay(%v) = %v, want %v", tt.current, got, tt.want)
		}
	}
}

func TestCredentialCycleSeconds(t *testing.T) {
	for _, tc := range []struct {
		lifetime int
		stagger  int
		want     int
	}{
		{lifetime: 600, stagger: 0, want: 480},
		{lifetime: 600, stagger: 38, want: 518},
		{lifetime: 180, stagger: 20, want: 170},
		{lifetime: 30, stagger: 20, want: 25},
		{lifetime: 0, stagger: 0, want: defaultCycleSecs},
	} {
		if got := credentialCycleSeconds(tc.lifetime, tc.stagger); got != tc.want {
			t.Fatalf("credentialCycleSeconds(%d, %d)=%d want=%d", tc.lifetime, tc.stagger, got, tc.want)
		}
	}
}
