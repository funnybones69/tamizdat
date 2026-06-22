package node

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

func TestSocksInboundMultiAccountAuthReturnsUsername(t *testing.T) {
	raw, err := json.Marshal(SocksSettings{Accounts: []SocksAccount{
		{Username: "alice", Password: "alice-pass"},
		{Username: "bob", Password: "bob-pass"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSocksInbound("socks", "127.0.0.1:1", raw)
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct {
		user string
		err  error
	}, 1)
	go func() {
		user, err := s.negotiate(server)
		done <- struct {
			user string
			err  error
		}{user: user, err: err}
	}()

	// Client offers USER/PASS auth.
	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if method[0] != 0x05 || method[1] != 0x02 {
		t.Fatalf("method reply = %v, want USER/PASS", method)
	}

	// RFC 1929 auth sub-negotiation for bob.
	msg := []byte{0x01, byte(len("bob"))}
	msg = append(msg, []byte("bob")...)
	msg = append(msg, byte(len("bob-pass")))
	msg = append(msg, []byte("bob-pass")...)
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(client, status); err != nil {
		t.Fatal(err)
	}
	if status[0] != 0x01 || status[1] != 0x00 {
		t.Fatalf("auth status = %v, want success", status)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("negotiate: %v", got.err)
	}
	if got.user != "bob" {
		t.Fatalf("authenticated user = %q, want bob", got.user)
	}
}
