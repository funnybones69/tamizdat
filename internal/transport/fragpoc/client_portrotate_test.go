package fragpoc

import (
	"slices"
	"testing"
	"time"
)

func TestClientPortRotationConfig(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr:      "127.0.0.1:31510",
		DynamicPortPool: []int{31511, 31512, 31511, 31510, 0, 65536, 31513},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	wantPorts := []int{31510, 31511, 31512, 31513}
	if !slices.Equal(client.dialPorts, wantPorts) {
		t.Fatalf("dialPorts = %v, want %v", client.dialPorts, wantPorts)
	}
	if !client.rotationEnabled() {
		t.Fatal("rotationEnabled() = false, want true")
	}

	singlePortClient, err := NewClient(ClientConfig{
		ServerAddr: "127.0.0.1:31510",
	})
	if err != nil {
		t.Fatalf("NewClient empty pool: %v", err)
	}
	defer singlePortClient.Close()

	if singlePortClient.rotationEnabled() {
		t.Fatal("empty-pool rotationEnabled() = true, want false")
	}
	if singlePortClient.dialPorts != nil {
		t.Fatalf("empty-pool dialPorts = %v, want nil", singlePortClient.dialPorts)
	}
}

func TestClientNextDialPortRoundRobin(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr:      "127.0.0.1:31520",
		DynamicPortPool: []int{31521, 31522},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	got := []int{
		client.nextDialPort(),
		client.nextDialPort(),
		client.nextDialPort(),
		client.nextDialPort(),
		client.nextDialPort(),
	}
	want := []int{31520, 31521, 31522, 31520, 31521}
	if !slices.Equal(got, want) {
		t.Fatalf("nextDialPort sequence = %v, want %v", got, want)
	}
}

func TestClientPortCooldownSkipsAndExpires(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr:      "127.0.0.1:31530",
		DynamicPortPool: []int{31531},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if got := client.nextDialPort(); got != 31530 {
		t.Fatalf("first nextDialPort() = %d, want 31530", got)
	}
	client.markPortResult(31531, false)
	if got := client.nextDialPort(); got != 31530 {
		t.Fatalf("cooled nextDialPort() = %d, want base port 31530", got)
	}

	client.portMu.Lock()
	client.portCooldown[31531] = time.Now().Add(-time.Second)
	client.portMu.Unlock()
	if got := client.nextDialPort(); got != 31531 {
		t.Fatalf("expired-cooldown nextDialPort() = %d, want 31531", got)
	}
}

func TestClientBasePortNeverCooled(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ServerAddr:      "127.0.0.1:31540",
		DynamicPortPool: []int{31541},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	client.markPortResult(31540, false)
	client.portMu.Lock()
	_, cooled := client.portCooldown[31540]
	client.portMu.Unlock()
	if cooled {
		t.Fatal("base port was added to portCooldown after failure")
	}

	client.portMu.Lock()
	client.portCooldown[31540] = time.Now().Add(time.Hour)
	client.portMu.Unlock()
	if got := client.nextDialPort(); got != 31540 {
		t.Fatalf("base-port nextDialPort() = %d, want 31540", got)
	}
}
