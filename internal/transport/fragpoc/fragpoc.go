package fragpoc

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	OpOpen     byte = 0x01
	OpUp       byte = 0x02
	OpDown     byte = 0x03
	OpClose    byte = 0x04
	OpPortHint byte = 0x05

	AckOK  byte = 0x00
	AckErr byte = 0xff

	SIDLen          = 12
	ShortIDLen      = 8
	MaxPayload      = 480
	MaxUpPayload    = 640 // UP payload ceiling; client sends randomised <=620-byte chunks
	DownRequestSize = 500
	DefaultWorkers  = 64
	MaxWorkers      = 120
	MaxDownWindow   = 16

	UDPDestinationPrefix = "udp:"

	DefaultConnectTimeout   = 10 * time.Second
	DefaultOperationTimeout = 30 * time.Second
)

var (
	ErrUnsupportedNetwork = errors.New("fragpoc: unsupported network")
	ErrUnsupportedUDP     = errors.New("fragpoc: UDP is not supported")
	ErrAuthFailed         = errors.New("fragpoc: auth failed")
	ErrProtocol           = errors.New("fragpoc: protocol error")
)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func maxPayload(n int) int {
	if n <= 0 || n > MaxPayload {
		return MaxPayload
	}
	return n
}

func workerCount(n int) int {
	if n <= 0 {
		return DefaultWorkers
	}
	if n > MaxWorkers {
		return MaxWorkers
	}
	return n
}

func downWorkerCount(workers int) int {
	if workers <= 1 {
		return 1
	}
	reserve := 1
	switch {
	case workers >= 64:
		reserve = workers / 5
	case workers >= 32:
		reserve = workers / 4
	case workers >= 8:
		reserve = 4
	case workers >= 4:
		reserve = 2
	}
	n := workers - reserve
	if n < 1 {
		return 1
	}
	return n
}

func downWindowCount(workers int, configured int) int {
	if configured <= 0 {
		return 1
	}
	if configured > MaxDownWindow {
		configured = MaxDownWindow
	}
	downWorkers := downWorkerCount(workerCount(workers))
	if configured > downWorkers {
		configured = downWorkers
	}
	if configured < 1 {
		return 1
	}
	return configured
}

func connectTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultConnectTimeout
	}
	return d
}

func operationTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultOperationTimeout
	}
	return d
}

type streamAddr struct {
	network string
	address string
}

func (a streamAddr) Network() string { return a.network }
func (a streamAddr) String() string  { return a.address }
