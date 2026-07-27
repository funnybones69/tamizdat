package tamizdat

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runPcapScriptFixture(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func readPcapFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("agents", "fixtures", "pcap", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func requireScriptPass(t *testing.T, input string, args ...string) string {
	t.Helper()
	out, err := runPcapScriptFixture(t, input, args...)
	if err != nil {
		t.Fatalf("%v failed unexpectedly: %v\n%s", args, err, out)
	}
	if !strings.Contains(out, `"ok": true`) {
		t.Fatalf("%v output missing ok=true: %s", args, out)
	}
	return out
}

func requireScriptFail(t *testing.T, input string, want string, args ...string) string {
	t.Helper()
	out, err := runPcapScriptFixture(t, input, args...)
	if err == nil {
		t.Fatalf("%v succeeded unexpectedly; output:\n%s", args, out)
	}
	if want != "" && !strings.Contains(out, want) {
		t.Fatalf("%v output missing %q:\n%s", args, want, out)
	}
	return out
}

func TestPcapScriptFixtures(t *testing.T) {
	scripts := []string{
		"scripts/pcap_sum_s2c.py",
		"scripts/pcap_syn_rate.py",
		"scripts/check_record_sizes.py",
		"scripts/pcap_cadence_check.py",
	}
	for _, script := range scripts {
		t.Run("help/"+filepath.Base(script), func(t *testing.T) {
			out, err := runPcapScriptFixture(t, "", script, "--help")
			if err != nil {
				t.Fatalf("%s --help failed: %v\n%s", script, err, out)
			}
			if !strings.Contains(strings.ToLower(out), "usage") {
				t.Fatalf("%s --help missing usage:\n%s", script, out)
			}
		})
	}

	t.Run("T1 per-flow S2C cap pass/fail/malformed", func(t *testing.T) {
		requireScriptPass(t, readPcapFixture(t, "tshark-tcp-len.txt"), "scripts/pcap_sum_s2c.py", "--server-ip", "203.0.113.1", "--max-s2c", "12288")
		requireScriptFail(t, readPcapFixture(t, "tshark-tcp-len-overcap.txt"), "violations", "scripts/pcap_sum_s2c.py", "--server-ip", "203.0.113.1", "--max-s2c", "12288")
		requireScriptFail(t, readPcapFixture(t, "tshark-tcp-len-malformed.txt"), "malformed", "scripts/pcap_sum_s2c.py", "--server-ip", "203.0.113.1", "--max-s2c", "12288")
	})

	t.Run("T2 SYN rolling windows pass/fail", func(t *testing.T) {
		requireScriptPass(t, readPcapFixture(t, "tshark-syn-pass.txt"), "scripts/pcap_syn_rate.py", "--window", "60", "--max", "36", "--window", "300", "--max", "165")
		requireScriptFail(t, readPcapFixture(t, "tshark-syn-fail.txt"), "violations", "scripts/pcap_syn_rate.py", "--window", "60", "--max", "36", "--window", "300", "--max", "165")
	})

	t.Run("TLS record sizes max and p95", func(t *testing.T) {
		requireScriptPass(t, readPcapFixture(t, "tls-record-sizes-pass.txt"), "scripts/check_record_sizes.py", "--max", "1500", "--p95-max", "1428")
		requireScriptFail(t, readPcapFixture(t, "tls-record-sizes-fail.txt"), "violations", "scripts/check_record_sizes.py", "--max", "1500", "--p95-max", "1428")
	})

	t.Run("ACK PING REBIND cadence flags metronome", func(t *testing.T) {
		requireScriptPass(t, readPcapFixture(t, "cadence-jitter.txt"), "scripts/pcap_cadence_check.py", "--check", "ack,ping,rebind", "--no-metronome")
		requireScriptFail(t, readPcapFixture(t, "cadence-metronome.txt"), "metronomic", "scripts/pcap_cadence_check.py", "--check", "ack,ping,rebind", "--no-metronome")
	})
}

func TestV2SyntheticLoadL1Stub(t *testing.T) {
	t.Skip("L1 mixed-load pcap soak is a long-running optional harness; unit/integration V2 routing tests cover CI")
}

func TestV2SyntheticLoadL2Stub(t *testing.T) {
	t.Skip("L2 30-minute realtime cycle soak is optional CI; kept as a named stub per Variant 2 spec")
}

func TestV1PcapFixtureAssertions(t *testing.T) {
	t.Run("P1 SYN rate stays within V1 rotation-off envelope", func(t *testing.T) {
		requireScriptPass(t, readPcapFixture(t, "v1-mixed-syns.txt"), "scripts/pcap_syn_rate.py", "--window", "30", "--max", "2")
	})

	// 2026-05-09 cleanup: removed P2 sub-test ("cover bytes stop and record
	// sizes shift during lite") + companion fixture v1-mixed-window-profile.txt.
	// The test verified ShapeLite-era behaviour where the realtime classifier
	// flipped cover traffic off and stretched record sizes. After realtime
	// classifier removal (commit 4a22651 et al.) the live code can no longer
	// produce "lite" windows, so the fixture-based assertion was load-bearing
	// only on the ShapeLite era — irrelevant going forward.
}
