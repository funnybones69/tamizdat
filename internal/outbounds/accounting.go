package outbounds

import "context"

// Recorder is the hook the server-side proxy loop calls after each TCP
// io.Copy half drains (or each UDP datagram lands) to attribute bytes
// to an outbound tag. The server's per-user accounting accumulator
// (userdb.Accounting) satisfies this — but a test can plug in any
// tag→bytes sink.
//
// Semantics from the outbound's POV:
//
//	up   = bytes WE WROTE to the upstream (target ← server)  = client_to_target
//	down = bytes WE READ from the upstream (target → server) = target_to_client
//
// The panel UI shows down as ↓ and up as ↑, matching the user-counter
// orientation in /api/users.
//
// 2026-05-13: dropped the countingConn / countingPacketConn wrappers
// that used to live in this file. They wrapped net.Conn / net.PacketConn
// returned by the dialer, intercepting Read/Write to push byte counts
// into Recorder. The wrap hid the concrete *net.TCPConn / *net.UDPConn
// from downstream code that needed it (iPhone tun2socks UDP relay does
// SyscallConn / SetReadBuffer on the concrete type — see revert commit
// 04d3c94). Accounting now happens at the io.Copy boundary in server.go
// using the byte counts io.Copy returns. The conn itself stays
// untouched, so downstream type-asserts keep working.
type Recorder interface {
	AddOutbound(tag string, up, down int64)
}

type recorderContextKey struct{}

func contextWithRecorder(ctx context.Context, rec Recorder) context.Context {
	if ctx == nil || rec == nil {
		return ctx
	}
	return context.WithValue(ctx, recorderContextKey{}, rec)
}

func recorderFromContext(ctx context.Context) Recorder {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(recorderContextKey{}).(Recorder)
	return rec
}

// SetRecorder wires a Recorder into every leasedDialer the registry
// hands out. Safe to call after Reload — newly-acquired leases use the
// new recorder; in-flight leases keep the recorder they were dialed with.
// Server.go reaches the recorder via leasedDialer.Recorder() to call
// AddOutbound at the io.Copy boundary; the dialer itself never wraps the
// returned conn.
//
// Pass nil to disable accounting (used by tests that exercise the
// dialer without wanting Bytes UPDATEs to land in their throwaway DB).
func (r *Registry) SetRecorder(rec Recorder) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.recorder = rec
	r.mu.Unlock()
}
