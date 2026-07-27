package svcipc

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	PipeName = `\\.\pipe\tamizdat-svc`
	PipeSDDL = `O:SYD:(A;;0x12019B;;;SY)(A;;0x12019B;;;BA)(A;;0x12019B;;;AU)`

	TypeRequest  = "request"
	TypeResponse = "response"
	TypeEvent    = "event"

	MethodConnect       = "Connect"
	MethodDisconnect    = "Disconnect"
	MethodGetStatus     = "GetStatus"
	MethodGetStats      = "GetStats"
	MethodGetSettings   = "GetSettings"
	MethodSetSettings   = "SetSettings"
	MethodPing          = "Ping"
	MethodSubscribeLogs = "SubscribeLogs"

	EventConnectionStateChanged = "ConnectionStateChanged"
	EventLogLine                = "LogLine"
	EventLogLines               = "LogLines"

	StateDisconnected  = "Disconnected"
	StateConnecting    = "Connecting"
	StateConnected     = "Connected"
	StateDisconnecting = "Disconnecting"
	StateFailed        = "Failed"
)

type Frame struct {
	ID      uint32          `json:"id"`
	Type    string          `json:"type"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type ConnectRequest struct {
	ConfigURI       string   `json:"config_uri"`
	PoolVariant     string   `json:"pool_variant"`
	Debug           bool     `json:"debug"`
	SelectiveRoutes []string `json:"selective_routes,omitempty"`
	BypassRoutes    []string `json:"bypass_routes,omitempty"`
	// RoutingConfigPath is an absolute path to a node JSON config (xray-style
	// inbounds/outbounds/rules). When set, the TUN binary builds a node and
	// passes its dispatcher to tunengine; without it, all TUN flows go through
	// the legacy single-tamizdat-client path (PA TURN 15 routing rules ignored).
	RoutingConfigPath string `json:"routing_config_path,omitempty"`
}

type ConnectResponse struct {
	ConnectionID string `json:"connection_id"`
	ServerAddr   string `json:"server_addr"`
	LocalTunIP   string `json:"local_tun_ip"`
}

type StatusResponse struct {
	State      string `json:"state"`
	ServerAddr string `json:"server_addr,omitempty"`
	Uptime     int64  `json:"uptime"`
	RTT        int64  `json:"rtt"`
}

type StatsResponse struct {
	BytesUp       int64 `json:"bytes_up"`
	BytesDown     int64 `json:"bytes_down"`
	TCPOpenTotal  int64 `json:"tcp_open_total"`
	TCPCloseTotal int64 `json:"tcp_close_total"`
	UDPOpenTotal  int64 `json:"udp_open_total"`
	UDPCloseTotal int64 `json:"udp_close_total"`
	RTTMs         int64 `json:"rtt_ms"`
	LastRTTMs     int64 `json:"last_rtt_ms"`
	Uptime        int64 `json:"uptime"`
}

type Settings struct {
	BypassRoutes []string `json:"bypass_routes,omitempty"`
}

type PingResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time,omitempty"`
}

type SubscribeLogsRequest struct {
	TailFromID uint64 `json:"tail_from_id"`
}

type LogLine struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Source string    `json:"source"`
	Msg    string    `json:"msg"`
}

type ConnectionStateChanged struct {
	NewState string `json:"new_state"`
	Reason   string `json:"reason,omitempty"`
}

func NewFrameReader(r io.Reader) *bufio.Reader {
	if br, ok := r.(*bufio.Reader); ok {
		return br
	}
	return bufio.NewReader(r)
}

func WriteFrame(w io.Writer, f Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(body) > 32<<20 {
		return fmt.Errorf("frame too large: %d bytes", len(body))
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(body)))
	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	return writeFull(w, body)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func ReadFrame(r *bufio.Reader) (Frame, error) {
	hdr, err := r.Peek(4)
	if err != nil {
		return Frame{}, err
	}
	n := binary.LittleEndian.Uint32(hdr)
	if n == 0 || n > 32<<20 {
		return Frame{}, fmt.Errorf("invalid frame length %d", n)
	}
	if _, err := r.Discard(4); err != nil {
		return Frame{}, err
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, err
	}
	return f, nil
}

func MustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
