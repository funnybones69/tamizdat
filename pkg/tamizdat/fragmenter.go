package tamizdat

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"
)

// Fragmenter implements Geneva-inspired TCP and TLS record fragmentation.
// It wraps a net.Conn and intercepts the first Write (the TLS ClientHello)
// to split it at the SNI field boundary across multiple TCP segments with
// a small randomized delay between them.
type Fragmenter struct {
	conn        net.Conn
	firstWrite  bool
	mu          sync.Mutex
	tcpFragment bool
	minDelay    time.Duration
	maxDelay    time.Duration
	// #7 adaptive Geneva: per-conn picked strategy + server key for bandit reporting.
	strategyName string
	serverAddr   string
}

// NewFragmenter creates a fragmenter that wraps the given connection.
// If tcpFragment is true, the first write (ClientHello) will be split
// across multiple TCP segments using the default strategy.
func NewFragmenter(conn net.Conn, tcpFragment bool) *Fragmenter {
	return NewFragmenterWithStrategy(conn, tcpFragment, "", "")
}

// NewFragmenterWithStrategy is the adaptive-Geneva variant: serverAddr is
// the bandit key (host:port) and strategy is the picked name (empty =
// the bandit picks now). Outcome of the subsequent handshake feeds back
// into the bandit via Fragmenter.ReportOutcome.
func NewFragmenterWithStrategy(conn net.Conn, tcpFragment bool, serverAddr, strategy string) *Fragmenter {
	if strategy == "" && serverAddr != "" {
		strategy = globalGenevaBandit.pick(serverAddr)
	}
	return &Fragmenter{
		conn:         conn,
		firstWrite:   true,
		tcpFragment:  tcpFragment,
		minDelay:     1 * time.Millisecond,
		maxDelay:     20 * time.Millisecond,
		strategyName: strategy,
		serverAddr:   serverAddr,
	}
}

// ReportOutcome reports the success or failure of the handshake that used
// this fragmenter. Called by client.createTransport once it knows whether
// the TLS handshake succeeded.
func (f *Fragmenter) ReportOutcome(won bool) {
	if f.serverAddr == "" || f.strategyName == "" {
		return
	}
	globalGenevaBandit.reportOutcome(f.serverAddr, f.strategyName, won)
}

// UnderlyingTCP returns the wrapped TCP connection, used by transport-level
// quickack flips after TLS handshake completes.
func (f *Fragmenter) UnderlyingTCP() *net.TCPConn {
	if f == nil {
		return nil
	}
	if tc, ok := f.conn.(*net.TCPConn); ok {
		return tc
	}
	return nil
}

// Write implements net.Conn.Write. The first call fragments the ClientHello;
// subsequent calls pass through directly.
func (f *Fragmenter) Write(b []byte) (int, error) {
	f.mu.Lock()
	isFirst := f.firstWrite
	f.firstWrite = false
	f.mu.Unlock()

	if isFirst && f.tcpFragment && len(b) > 50 {
		return f.fragmentClientHello(b)
	}
	return f.conn.Write(b)
}

// fragmentClientHello splits the ClientHello across multiple TCP segments.
// Strategy: find the SNI extension boundary and split there, with an
// additional random split point for robustness.
func (f *Fragmenter) fragmentClientHello(data []byte) (int, error) {
	// MED-8: defensive min-size gate -- skip fragmentation for unrealistic
	// tiny payloads to avoid degenerate split sizes.
	if len(data) < 40 {
		return f.conn.Write(data)
	}

	// #7 adaptive Geneva: if the bandit picked a named strategy, dispatch
	// to it. Otherwise fall through to the legacy SNI-split path below.
	if f.strategyName != "" {
		return f.writeSegments(strategyByName(f.strategyName)(data))
	}
	splitPoint := f.findSNISplitPoint(data)
	if splitPoint <= 0 || splitPoint >= len(data) {
		splitPoint = randomInt(20, len(data)/2)
	}

	// Add a second split point for additional fragmentation
	secondSplit := -1
	if splitPoint+10 < len(data) {
		secondSplit = randomInt(splitPoint+1, len(data))
	}

	totalWritten := 0

	// Fragment 1: up to the split point
	n, err := f.conn.Write(data[:splitPoint])
	totalWritten += n
	if err != nil {
		return totalWritten, err
	}

	// Random delay between fragments (1-20ms)
	f.randomDelay()

	if secondSplit > splitPoint {
		// Fragment 2: split point to second split
		n, err = f.conn.Write(data[splitPoint:secondSplit])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		f.randomDelay()

		// Fragment 3: remainder
		n, err = f.conn.Write(data[secondSplit:])
		totalWritten += n
	} else {
		// Fragment 2: remainder
		n, err = f.conn.Write(data[splitPoint:])
		totalWritten += n
	}

	return totalWritten, err
}

// findSNISplitPoint scans the ClientHello for the SNI extension and returns
// a split point at the beginning of the SNI value (the domain name bytes).
// This forces the DPI to reassemble TCP segments to extract the SNI.

// writeSegments writes a slice of byte segments sequentially with a randomized
// inter-segment delay. Returns total bytes written + first error (if any).
func (f *Fragmenter) writeSegments(segs [][]byte) (int, error) {
	total := 0
	for i, seg := range segs {
		if i > 0 {
			f.randomDelay()
		}
		n, err := f.conn.Write(seg)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (f *Fragmenter) findSNISplitPoint(data []byte) int {
	// Look for the TLS record header
	if len(data) < 5 {
		return -1
	}

	// TLS record: content_type(1) + version(2) + length(2) + fragment
	// We're looking inside the fragment for the ClientHello
	pos := 5 // skip TLS record header

	if pos >= len(data) || data[pos] != 0x01 { // HandshakeTypeClientHello
		return -1
	}
	pos += 4 // skip handshake type(1) + length(3)

	// Skip client_version(2) + random(32)
	pos += 34
	if pos >= len(data) {
		return -1
	}

	// Skip session_id
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return -1
	}

	// Skip cipher_suites
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return -1
	}

	// Skip compression_methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > len(data) {
		return -1
	}

	// Parse extensions to find SNI (type 0x0000)
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	endExts := pos + extensionsLen
	if endExts > len(data) {
		endExts = len(data)
	}

	for pos+4 <= endExts {
		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x0000 { // SNI extension
			// SNI extension body: server_name_list_length(2) + entries
			// Each entry: name_type(1) + name_length(2) + name(var)
			if extLen >= 5 {
				// Split right at the start of the SNI domain name
				sniNameStart := pos + 2 + 1 + 2 // list_len + type + name_len
				if sniNameStart < len(data) {
					// Add random offset within the domain name
					maxOffset := extLen - 5
					if maxOffset > 10 {
						maxOffset = 10
					}
					if maxOffset > 0 {
						return sniNameStart + randomInt(0, maxOffset)
					}
					return sniNameStart
				}
			}
			return pos // fallback: split at start of SNI extension data
		}

		pos += extLen
	}

	return -1
}

// randomDelay sleeps for a random duration between minDelay and maxDelay.
func (f *Fragmenter) randomDelay() {
	d := randomDuration(f.minDelay, f.maxDelay)
	time.Sleep(d)
}

func (f *Fragmenter) Read(b []byte) (int, error)         { return f.conn.Read(b) }
func (f *Fragmenter) Close() error                       { return f.conn.Close() }
func (f *Fragmenter) LocalAddr() net.Addr                { return f.conn.LocalAddr() }
func (f *Fragmenter) RemoteAddr() net.Addr               { return f.conn.RemoteAddr() }
func (f *Fragmenter) SetDeadline(t time.Time) error      { return f.conn.SetDeadline(t) }
func (f *Fragmenter) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *Fragmenter) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }

// randomInt returns a random int in [min, max).
//
// 2026-05-13 perf: this is called O(N) per Write on the data path (record
// fragmentation picks 2-5 split points per H2 DATA frame), so it goes
// through math/rand/v2's top-level Uint64() (concurrent-safe, lock-free,
// per-P state). That removes a per-call getrandom() syscall + math/big.Int
// allocation that pprof showed at ~4% CPU under 50-worker load on ru2. The
// global PRNG is seeded by the runtime from OS entropy — unpredictable to
// an off-host observer, which is the only property we need here (fragment
// sizes are not secret keys).
func randomInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + mrand.IntN(max-min)
}

// randomDuration returns a random duration in [min, max).
func randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + time.Duration(n.Int64())
}
