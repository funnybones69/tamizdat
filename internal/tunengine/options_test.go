package tunengine

import (
	"testing"
	"time"
)

type fakeUDPTimeoutSetter struct{ got time.Duration }

func (f *fakeUDPTimeoutSetter) SetUDPTimeout(timeout time.Duration) { f.got = timeout }

func TestSetUDPIdleTimeout(t *testing.T) {
	fake := &fakeUDPTimeoutSetter{}
	setUDPIdleTimeout(fake, 4*time.Minute)
	if fake.got != 4*time.Minute {
		t.Fatalf("UDP timeout = %s, want 4m", fake.got)
	}
	setUDPIdleTimeout(fake, 0)
	if fake.got != 4*time.Minute {
		t.Fatalf("zero timeout changed tun2socks default to %s", fake.got)
	}
}
