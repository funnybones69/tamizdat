package tamizdat

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
)

var (
	mathLog = math.Log
	mathCos = math.Cos
	mathPow = math.Pow
)

// Adaptive Geneva-style ClientHello fragmentation strategies + per-server
// multi-armed bandit selection (compass deep-research P1.5).
//
// Background: TSPU enforcement varies per ISP / per city / per time. A single
// hard-coded fragmentation strategy is brittle: what works on Megafon Moscow
// today may fail on MTS Krasnoyarsk tomorrow. Multi-armed-bandit picks the
// strategy that has been winning recently for THIS server and explores
// alternatives 10% of the time.
//
// Strategies are pure functions: given the raw ClientHello bytes, return
// the slice of byte segments that should be sent as separate TCP writes.

// FragmentStrategy is the function signature: takes ClientHello, returns
// segments to write sequentially with small delays between them.
type FragmentStrategy func(data []byte) [][]byte

// fragStrategies is the registered pool. Order matters only in that
// "sni_split" stays first — that's our pre-bandit default.
var fragStrategies = []struct {
	Name string
	Fn   FragmentStrategy
}{
	{"sni_split", stratSNISplit},
	{"first_byte", stratFirstByte},
	{"midpoint", stratMidpoint},
	{"two_thirds", stratTwoThirds},
	{"hdr_then_body", stratHeaderThenBody},
}

// stratSNISplit: split at SNI extension boundary (current default behaviour).
// Falls back to midpoint if SNI not found.
func stratSNISplit(data []byte) [][]byte {
	sp := findSNIOffsetIn(data)
	if sp <= 0 || sp >= len(data) {
		return stratMidpoint(data)
	}
	return [][]byte{data[:sp], data[sp:]}
}

// stratFirstByte: emit byte 0 alone, then rest. Defeats single-byte FSM
// pre-fetch detectors (Geneva paper).
func stratFirstByte(data []byte) [][]byte {
	if len(data) < 2 {
		return [][]byte{data}
	}
	return [][]byte{data[:1], data[1:]}
}

// stratMidpoint: clean halves.
func stratMidpoint(data []byte) [][]byte {
	if len(data) < 2 {
		return [][]byte{data}
	}
	mid := len(data) / 2
	return [][]byte{data[:mid], data[mid:]}
}

// stratTwoThirds: split at 2/3, biased toward later split. Sometimes works
// better when SNI is in the first third.
func stratTwoThirds(data []byte) [][]byte {
	if len(data) < 3 {
		return [][]byte{data}
	}
	sp := len(data) * 2 / 3
	return [][]byte{data[:sp], data[sp:]}
}

// stratHeaderThenBody: split right after TLS record header (5 bytes).
// Lots of stateless detectors match the magic on first segment; missing
// the rest of the handshake disrupts the heuristic.
func stratHeaderThenBody(data []byte) [][]byte {
	if len(data) <= 5 {
		return [][]byte{data}
	}
	return [][]byte{data[:5], data[5:]}
}

// findSNIOffsetIn delegates to the existing SNI finder used by the legacy
// fragmenter -- avoid duplicate parser logic.
func findSNIOffsetIn(data []byte) int {
	// Reuse package-level helper from fragmenter.go
	tmp := &Fragmenter{}
	return tmp.findSNISplitPoint(data)
}

// genevaBandit is a per-server epsilon-greedy multi-armed bandit selecting
// among fragStrategies. State is per-server (host:port) so different
// upstream paths can converge to different best strategies.
type genevaBandit struct {
	mu      sync.Mutex
	stats   map[string]*serverStats // key = server address (host:port)
	epsilon float64                 // exploration rate, default 0.10
}

type serverStats struct {
	// Per-strategy success/failure counts (Wilson-score style would be
	// fancier but straight ratios are fine for our scale).
	wins   map[string]int
	losses map[string]int
}

// globalGenevaBandit is the package-level bandit shared across clients.
// Sharing means insights from one Client transfer to another with the same
// server (typical case: short-lived test runs).
var globalGenevaBandit = &genevaBandit{
	stats:   map[string]*serverStats{},
	epsilon: 0.10,
}

// pick returns the strategy name to use for an outgoing handshake to
// `server`. Thompson Sampling (compass v2 §5.12): for each strategy s with
// wins[s] and losses[s], sample x_s ~ Beta(wins+1, losses+1) and pick
// argmax_s x_s. Naturally balances exploration and exploitation; the
// posterior tightens as evidence accumulates.
//
// Robust against the adversarial-bandit attack where a censor selectively
// blocks a winning arm to force constant re-exploration: with Thompson the
// "exploration probability" is implicit in the posterior variance rather
// than a fixed epsilon, so a censor cannot pin the bandit into the
// equivalent of a high-epsilon mode.
func (b *genevaBandit) pick(server string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.stats[server]
	if !ok {
		st = &serverStats{wins: map[string]int{}, losses: map[string]int{}}
		b.stats[server] = st
	}

	bestName := fragStrategies[0].Name
	if b.epsilon == 0 {
		bestScore := -1.0
		for _, s := range fragStrategies {
			wins := st.wins[s.Name]
			losses := st.losses[s.Name]
			score := float64(wins+1) / float64(wins+losses+2)
			if score > bestScore {
				bestScore = score
				bestName = s.Name
			}
		}
		return bestName
	}

	bestSample := -1.0
	for _, s := range fragStrategies {
		alpha := float64(st.wins[s.Name] + 1)  // +1 prior
		beta := float64(st.losses[s.Name] + 1) // +1 prior
		sample := sampleBeta(alpha, beta)
		if sample > bestSample {
			bestSample = sample
			bestName = s.Name
		}
	}
	return bestName
}

// sampleBeta draws a sample from Beta(alpha, beta) using the standard
// gamma-ratio method: X = G(alpha,1) / (G(alpha,1) + G(beta,1)) where
// G(k,1) is a Gamma random variable. For alpha=beta=1 reduces to Uniform[0,1].
//
// We use Marsaglia-Tsang for Gamma when k >= 1; for k < 1 we use Johnk's
// rejection. Stock crypto/rand drives the underlying entropy so the bandit
// can't be predicted by a censor with a known seed.
func sampleBeta(alpha, beta float64) float64 {
	x := sampleGamma(alpha)
	y := sampleGamma(beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// sampleGamma returns a Gamma(k, 1) sample. Marsaglia-Tsang for k >= 1;
// composition method for k < 1.
func sampleGamma(k float64) float64 {
	if k < 1 {
		// Use the boost trick: G(k) ~ G(k+1) * U^(1/k) where U is uniform.
		return sampleGamma(k+1) * pow(randFloat01OrEpsilon(), 1/k)
	}
	d := k - 1.0/3.0
	c := 1 / sqrt(9*d)
	for {
		x := stdNormal()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := randFloat01()
		if u < 1-0.0331*x*x*x*x {
			return d * v
		}
		// Slower fallback check using the original formula
		if lnf(u) < 0.5*x*x+d*(1-v+lnf(v)) {
			return d * v
		}
	}
}

// stdNormal returns a sample from N(0,1) via Box-Muller.
func stdNormal() float64 {
	u1 := randFloat01OrEpsilon()
	u2 := randFloat01()
	return sqrt(-2*lnf(u1)) * cosF(2*piConst*u2)
}

// randFloat01OrEpsilon returns a value in (0,1] -- excludes zero so log() is safe.
func randFloat01OrEpsilon() float64 {
	x := randFloat01()
	if x == 0 {
		return 1e-12
	}
	return x
}

// Math helpers (don't pull in math/* twice; only what we need).
func sqrt(x float64) float64 {
	// Newton iteration. Rough but sufficient -- bandit need not be perfect.
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 16; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func lnf(x float64) float64 {
	if x <= 0 {
		return -1e18
	}
	// Use math.Log via series. Acceptable precision; we just need monotonic ordering.
	return mathLog(x)
}

func cosF(x float64) float64 {
	return mathCos(x)
}

func pow(x, y float64) float64 {
	return mathPow(x, y)
}

// piConst (math.Pi) at module scope.
const piConst = 3.141592653589793

// reportOutcome records win/loss for a strategy on a server.
func (b *genevaBandit) reportOutcome(server, strategy string, won bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.stats[server]
	if !ok {
		st = &serverStats{wins: map[string]int{}, losses: map[string]int{}}
		b.stats[server] = st
	}
	if won {
		st.wins[strategy]++
	} else {
		st.losses[strategy]++
	}
}

func strategyByName(name string) FragmentStrategy {
	for _, s := range fragStrategies {
		if s.Name == name {
			return s.Fn
		}
	}
	return stratSNISplit // safe fallback
}

func randFloat01() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:])>>1) % n
}
