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

func TestRotationSleepDuration(t *testing.T) {
	for _, tc := range []struct {
		lifetime int
		groupID  int
		want     time.Duration
	}{
		{lifetime: 600, groupID: 1, want: 470 * time.Second},
		{lifetime: 600, groupID: 2, want: 460 * time.Second},
		{lifetime: 600, groupID: 99, want: 420 * time.Second},
		{lifetime: 180, groupID: 1, want: 140 * time.Second},
		{lifetime: 30, groupID: 1, want: rotationMinimumInterval},
		{lifetime: 0, groupID: 1, want: (defaultCycleSecs-rotationSafetySeconds)*time.Second - rotationOffsetStep},
	} {
		if got := rotationSleepDuration(tc.lifetime, tc.groupID); got != tc.want {
			t.Fatalf("rotationSleepDuration(%d, %d)=%v want=%v", tc.lifetime, tc.groupID, got, tc.want)
		}
	}
	if got := rotationOffset(999); got != rotationOffsetCap {
		t.Fatalf("rotation offset cap=%v want=%v", got, rotationOffsetCap)
	}
}
