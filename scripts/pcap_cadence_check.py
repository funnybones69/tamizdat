#!/usr/bin/env python3
"""Flag metronomic standalone ACK / PING / REBIND cadence.

Fixture field-text format:
  frame.time_epoch event
where event is ack, ping, or rebind. With --pcap pointing at a binary pcap,
the script invokes tshark and infers event labels from tcp.len/_ws.col.Info.
Output is JSON and contains inter-arrival stats per event type.
"""
import argparse
import json
import math
import os
import statistics
import subprocess
import sys
from collections import defaultdict

EVENTS = {"ack", "ping", "rebind"}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", help="Path to pcap or already-extracted field text. Omit to read field text from stdin.")
    p.add_argument("--check", default="ack,ping,rebind", help="Comma-separated events to check: ack,ping,rebind")
    p.add_argument("--no-metronome", action="store_true", help="Exit nonzero if checked events have too-regular intervals")
    p.add_argument("--min-events", type=int, default=5, help="Minimum events before metronome detection applies")
    p.add_argument("--cv-threshold", type=float, default=0.02, help="Coefficient-of-variation threshold for metronomic intervals")
    p.add_argument("--range-threshold-ms", type=float, default=50.0, help="Also flag when max(interval)-min(interval) is under this many ms")
    return p.parse_args()


def fatal(message):
    print(json.dumps({"ok": False, "error": message}, sort_keys=True, indent=2))
    return 2


def load_text(args):
    if not args.pcap:
        return sys.stdin.read()
    with open(args.pcap, "rb") as fh:
        prefix = fh.read(4)
    pcap_magics = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
    if prefix in pcap_magics:
        cmd = [
            "tshark", "-r", args.pcap, "-T", "fields",
            "-e", "frame.time_epoch", "-e", "tcp.len", "-e", "tcp.flags.ack", "-e", "_ws.col.Info",
        ]
        try:
            return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            raise RuntimeError("tshark is required to read binary pcap files")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("tshark failed: " + exc.output.strip())
    with open(args.pcap, "r", encoding="utf-8") as fh:
        return fh.read()


def infer_event(fields, lineno):
    # Preferred fixture format: timestamp event
    if len(fields) == 2 and fields[1].lower() in EVENTS:
        return fields[1].lower()
    joined = " ".join(fields[1:]).lower()
    if "rebind" in joined:
        return "rebind"
    if "ping" in joined:
        return "ping"
    # tshark-inferred standalone TCP ACK: ts tcp.len tcp.flags.ack info
    if len(fields) >= 3:
        tcp_len = fields[1]
        ack = fields[2].lower()
        if tcp_len in {"0", "0.0"} and ack not in {"", "0", "0x0000", "false"}:
            return "ack"
    raise ValueError(f"malformed line {lineno}: cannot infer event type")


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    idx = max(0, min(len(ordered)-1, math.ceil(q*len(ordered))-1))
    return ordered[idx]


def event_stats(times, min_events, cv_threshold, range_threshold):
    times = sorted(times)
    gaps = [b - a for a, b in zip(times, times[1:])]
    if not gaps:
        return {"count": len(times), "interarrival": {"count": 0}, "metronomic": False}
    mean = statistics.fmean(gaps)
    stdev = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else 0.0
    span = max(gaps) - min(gaps)
    enough = len(times) >= min_events
    metronomic = enough and (cv <= cv_threshold and span <= range_threshold)
    return {
        "count": len(times),
        "interarrival": {
            "count": len(gaps),
            "min": min(gaps),
            "p50": statistics.median(gaps),
            "p95": percentile(gaps, 0.95),
            "max": max(gaps),
            "mean": mean,
            "stdev": stdev,
            "cv": cv,
            "range": span,
        },
        "metronomic": metronomic,
    }


def main():
    args = parse_args()
    checks = [c.strip().lower() for c in args.check.split(",") if c.strip()]
    bad = [c for c in checks if c not in EVENTS]
    if bad:
        return fatal("unknown --check event(s): " + ",".join(bad))
    if args.min_events < 2:
        return fatal("--min-events must be >= 2")
    if args.cv_threshold < 0 or args.range_threshold_ms < 0:
        return fatal("metronome thresholds must be non-negative")
    try:
        text = load_text(args)
    except (OSError, RuntimeError) as exc:
        return fatal(str(exc))
    events = defaultdict(list)
    rows = 0
    try:
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.replace("\t", " ").split()
            if len(fields) < 2:
                raise ValueError(f"malformed line {lineno}: expected timestamp and event fields")
            try:
                ts = float(fields[0])
            except ValueError:
                raise ValueError(f"malformed line {lineno}: timestamp is not numeric: {fields[0]!r}")
            if not math.isfinite(ts):
                raise ValueError(f"malformed line {lineno}: timestamp is not finite")
            try:
                ev = infer_event(fields, lineno)
            except ValueError:
                # Binary-pcap tshark extraction includes SYNs and DATA packets that are
                # not standalone ACK/PING/REBIND cadence events. Ignore those packets
                # while keeping strict fixture parsing for the two-column text form.
                if len(fields) > 2:
                    rows += 1
                    continue
                raise
            if ev in checks:
                events[ev].append(ts)
            rows += 1
    except ValueError as exc:
        return fatal(str(exc))
    if rows == 0:
        return fatal("empty input: no cadence rows found")
    reports = {}
    violations = []
    range_threshold = args.range_threshold_ms / 1000.0
    for ev in checks:
        rep = event_stats(events.get(ev, []), args.min_events, args.cv_threshold, range_threshold)
        reports[ev] = rep
        if args.no_metronome and rep["metronomic"]:
            violations.append({"event": ev, "reason": "metronomic", "stats": rep})
    out = {"ok": not violations, "rows": rows, "events": reports, "violations": violations}
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
