package tamizdat

import "io"

// Shaper implements traffic shaping for H2/BBCR bytes. BBCR frames are
// encoded first, then FragmentWrite may split those opaque BBCR bytes into
// multiple H2 DATA writes/TLS records. There is deliberately no per-record
// sleep: P0.4 removed jitter because it worsens dMAP-style RTT divergence.
type Shaper struct{}

// NewShaper keeps the old signature for callers/tests, but ignores jitter knobs.
// Jitter and MaxJitterMs were removed from public config and cannot resurrect
// data-path sleeps.
func NewShaper(_ bool, _ int) *Shaper { return &Shaper{} }

// Write directly writes outgoing data without per-record delay. See
// threat-model §2 T4 (updated 2026-04-24): per-record jitter is an anti-pattern
// per the NDSS 2025 dMAP paper's own analysis.
func (s *Shaper) Write(w io.Writer, data []byte) (int, error) {
	return w.Write(data)
}

// FragmentWrite is the P0.1 wiring entry point: if a fragmenter is
// provided, the already-formed payload is split across multiple H2 DATA writes
// (and therefore outer TLS records). With BBCR enabled the layering is:
// application bytes -> BBCR OPEN_STREAM/DATA/FIN/RST frames -> H2 DATA ->
// TLS records. FragmentWrite only shapes the outer TLS/write layer; it never
// parses BBCR frames, changes BBCR chunking, or sleeps on the data path.
func (s *Shaper) FragmentWrite(w io.Writer, fragmenter *RecordFragmenter, data []byte) (int, error) {
	if fragmenter == nil || !fragmenter.enabled {
		return s.Write(w, data)
	}
	fragments := fragmenter.Fragment(data)
	total := 0
	for _, frag := range fragments {
		n, err := s.Write(w, frag)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// RecordFragmenter splits inner TLS records across multiple H2 DATA frames
// to defeat encapsulated TLS detection (USENIX Sec 2024). It also helps
// against #490 byte-counter shaping by keeping individual outer records
// small and irregular.
type RecordFragmenter struct {
	enabled bool
}

// NewRecordFragmenter creates a record-level fragmenter.
func NewRecordFragmenter(enabled bool) *RecordFragmenter {
	return &RecordFragmenter{enabled: enabled}
}

// Enabled reports whether the fragmenter is active.
func (rf *RecordFragmenter) Enabled() bool { return rf.enabled }

// Fragment splits data into multiple chunks with randomized sizes.
// This is used to fragment inner TLS records across H2 DATA frames.
//
// 2026-05-13 perf: the returned slices are SUB-SLICES of data, not heap
// copies. Callers (Shaper.FragmentWrite) immediately hand each slice to a
// Writer and never retain it, so the defensive `make([]byte, n) + copy()`
// the original implementation did was a pure waste — pprof showed 113 MB
// flat-alloc in Fragment() under 50-worker ru2 load and Fragment was on
// the per-Write hot path of every data byte the server forwarded. If any
// future caller needs to retain a fragment past the write, it must clone
// it itself.
func (rf *RecordFragmenter) Fragment(data []byte) [][]byte {
	if !rf.enabled || len(data) < 64 {
		return [][]byte{data}
	}

	numFragments := randomInt(2, 5)
	if numFragments > len(data)/16 {
		numFragments = 2
	}

	fragments := make([][]byte, 0, numFragments)
	remaining := data

	for i := 0; i < numFragments-1 && len(remaining) > 16; i++ {
		avgSize := len(remaining) / (numFragments - i)
		splitSize := randomInt(avgSize/2, avgSize*3/2+1)
		if splitSize > len(remaining)-16 {
			splitSize = len(remaining) - 16
		}
		if splitSize < 1 {
			splitSize = 1
		}

		fragments = append(fragments, remaining[:splitSize:splitSize])
		remaining = remaining[splitSize:]
	}

	if len(remaining) > 0 {
		fragments = append(fragments, remaining)
	}

	return fragments
}
