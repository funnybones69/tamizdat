package tamizdat

import (
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestParseFragPoCPortPool(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "empty", spec: "  ", want: nil},
		{name: "single", spec: "31510", want: []int{31510}},
		{name: "range", spec: "31510-31512", want: []int{31510, 31511, 31512}},
		{name: "mixed", spec: "31510-31512,31540,31542", want: []int{31510, 31511, 31512, 31540, 31542}},
		{name: "dedup sorted", spec: "31542,31510-31512,31511,31540,31542", want: []int{31510, 31511, 31512, 31540, 31542}},
		{name: "port zero", spec: "0", wantErr: true},
		{name: "port too high", spec: "65536", wantErr: true},
		{name: "range inverted", spec: "31512-31510", wantErr: true},
		{name: "garbage", spec: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFragPoCPortPool(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFragPoCPortPool(%q) expected error, got nil", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFragPoCPortPool(%q): %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseFragPoCPortPool(%q)=%v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestDesiredDynamicPorts(t *testing.T) {
	tests := []struct {
		sessions int
		want     int
	}{
		{sessions: 0, want: 0},
		{sessions: 4, want: 0},
		{sessions: 5, want: 1},
		{sessions: 8, want: 1},
		{sessions: 9, want: 2},
		{sessions: 1000, want: 4},
	}

	for _, tt := range tests {
		if got := desiredDynamicPorts(tt.sessions, 4); got != tt.want {
			t.Fatalf("desiredDynamicPorts(%d, 4)=%d, want %d", tt.sessions, got, tt.want)
		}
	}
}

func TestFragPoCPortManagerLifecycle(t *testing.T) {
	pool := freeTCPPorts(t, 3)
	var sessions int

	m := NewFragPoCPortManager(FragPoCPortConfig{
		Enabled:  true,
		MaxPorts: 3,
		Mode:     "list",
		Pool:     pool,
		BindHost: "127.0.0.1",
		BasePort: 1,
	}, acceptAndDrain, func() int {
		return sessions
	}, func(string, ...any) {})
	defer m.Stop()

	sessions = fragPoCSessionsPerPort*3 + 1
	m.reconcileOnce()
	ports := m.CurrentPorts()
	if len(ports) != 3 {
		t.Fatalf("expected three dynamic ports after one high-load reconcile, got %v", ports)
	}
	for _, port := range ports {
		assertDialSucceeds(t, port)
	}
	opened := append([]int(nil), ports...)

	sessions = 0
	for i := 1; i < fragPoCScaleDownTicks; i++ {
		m.reconcileOnce()
		ports = m.CurrentPorts()
		if !reflect.DeepEqual(ports, opened) {
			t.Fatalf("low hysteresis tick %d should not close ports: got %v, want %v", i, ports, opened)
		}
	}

	m.reconcileOnce()
	ports = m.CurrentPorts()
	if len(ports) != 0 {
		t.Fatalf("expected all dynamic ports closed after low hysteresis ticks, got %v", ports)
	}
	for _, port := range opened {
		assertDialFails(t, port)
	}
}

func freeTCPPorts(t *testing.T, n int) []int {
	t.Helper()

	ports := make([]int, 0, n)
	seen := make(map[int]struct{})
	for len(ports) < n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve free TCP port: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatalf("close reserved TCP port: %v", err)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports
}

func acceptAndDrain(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func assertDialSucceeds(t *testing.T, port int) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("dial dynamic port %d: %v", port, err)
	}
	_ = conn.Close()
}

func assertDialFails(t *testing.T, port int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("dial dynamic port %d still succeeds after close", port)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
