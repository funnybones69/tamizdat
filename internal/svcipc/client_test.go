package svcipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
)

func TestClientConnectOverNetPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		frame, err := ReadFrame(NewFrameReader(serverConn))
		if err != nil {
			t.Errorf("server ReadFrame: %v", err)
			return
		}
		if frame.Type != TypeRequest || frame.Method != MethodConnect {
			t.Errorf("unexpected request: %+v", frame)
			return
		}
		var req ConnectRequest
		if err := json.Unmarshal(frame.Payload, &req); err != nil {
			t.Errorf("unmarshal request: %v", err)
			return
		}
		if req.ConfigURI != "tamizdat://unit" || req.PoolVariant != "v3" {
			t.Errorf("bad ConnectRequest: %+v", req)
			return
		}
		resp := ConnectResponse{ConnectionID: "conn-1", ServerAddr: "example:443", LocalTunIP: "10.255.0.2"}
		payload, _ := json.Marshal(resp)
		if err := WriteFrame(serverConn, Frame{ID: frame.ID, Type: TypeResponse, Method: MethodConnect, Payload: payload}); err != nil {
			t.Errorf("server WriteFrame: %v", err)
		}
	}()

	c := NewClient(clientConn)
	defer c.Close()
	resp, err := c.Connect(context.Background(), ConnectRequest{ConfigURI: "tamizdat://unit", PoolVariant: "v3"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if resp.ConnectionID != "conn-1" || resp.LocalTunIP != "10.255.0.2" {
		t.Fatalf("bad response: %+v", resp)
	}
	<-done
}
