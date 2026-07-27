package tamizdat

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type closeRecorderRoundTripper struct {
	closed chan time.Time
	once   sync.Once
}

func (r *closeRecorderRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func (r *closeRecorderRoundTripper) Close() error {
	r.once.Do(func() { r.closed <- time.Now() })
	return nil
}

type closeRecorderConn struct {
	net.Conn
	closed chan time.Time
	once   sync.Once
}

func (c *closeRecorderConn) Close() error {
	c.once.Do(func() { c.closed <- time.Now() })
	return c.Conn.Close()
}

func TestH2TransportMarkDrainingOrdersH2BeforeTLSAndWaitsForStreams(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	tlsClosed := make(chan time.Time, 1)
	h2Closed := make(chan time.Time, 1)
	tr := &h2Transport{
		tlsConn:      &closeRecorderConn{Conn: server, closed: tlsClosed},
		h2Roundtrip:  &closeRecorderRoundTripper{closed: h2Closed},
		drainTimeout: 200 * time.Millisecond,
		maxStreams:   10,
	}
	tr.activeStreams.Store(1)

	tr.markDraining()

	var h2Time time.Time
	select {
	case h2Time = <-h2Closed:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("h2 round tripper was not closed promptly")
	}

	select {
	case <-tlsClosed:
		t.Fatal("TLS conn closed while active stream was still present")
	case <-time.After(40 * time.Millisecond):
	}

	tr.activeStreams.Store(0)
	select {
	case tlsTime := <-tlsClosed:
		if tlsTime.Before(h2Time) {
			t.Fatalf("TLS close time %s before H2 close time %s", tlsTime, h2Time)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("TLS conn did not close after active streams drained")
	}
}
