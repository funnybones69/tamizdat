#!/usr/bin/env python3
"""Check SYN open cadence in rolling windows and report inter-arrival stats.

Input is tshark field text with columns:
  frame.time_epoch ip.src ip.dst tcp.dstport
Rows are treated as client->server SYN opens. Counts are aggregated per
(server ip, destination port), matching the P0.5 T2 churn bucket scope.
"""
import argparse
import json
import math
import statistics
import sys
from collections import defaultdict, deque


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--window", action="append", type=float, required=True, help="Rolling window size in seconds; repeatable")
    p.add_argument("--max", dest="maxima", action="append", type=int, required=True, help="Maximum SYN count for the corresponding --window; repeatable")
    return p.parse_args()


def fatal(message):
    print(json.dumps({"ok": False, "error": message}, sort_keys=True, indent=2))
    return 2


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[idx]


def stats(times):
    if len(times) < 2:
        return {"count": len(times), "interarrival": {"count": 0}}
    gaps = [b - a for a, b in zip(times, times[1:])]
    return {
        "count": len(times),
        "interarrival": {
            "count": len(gaps),
            "min": min(gaps),
            "p50": statistics.median(gaps),
            "p95": percentile(gaps, 0.95),
            "max": max(gaps),
        },
    }


def main():
    args = parse_args()
    if len(args.window) != len(args.maxima):
        return fatal("each --window must have a corresponding --max")
    checks = []
    for window, max_count in zip(args.window, args.maxima):
        if window <= 0:
            return fatal("--window must be positive")
        if max_count < 0:
            return fatal("--max must be non-negative")
        checks.append((window, max_count))

    groups = defaultdict(list)
    rows = 0
    try:
        for lineno, raw in enumerate(sys.stdin, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.replace("\t", " ").split()
            if len(fields) != 4:
                raise ValueError(f"malformed line {lineno}: expected 4 fields, got {len(fields)}")
            ts_s, src, dst, dport = fields
            try:
                ts = float(ts_s)
            except ValueError:
                raise ValueError(f"malformed line {lineno}: timestamp is not numeric: {ts_s!r}")
            if not math.isfinite(ts):
                raise ValueError(f"malformed line {lineno}: timestamp is not finite")
            rows += 1
            groups[(dst, dport)].append(ts)
    except ValueError as exc:
        return fatal(str(exc))

    if rows == 0:
        return fatal("empty input: no SYN rows found")

    violations = []
    group_reports = []
    for (dst, dport), times in sorted(groups.items()):
        times.sort()
        report = {"server_ip": dst, "server_port": dport, **stats(times), "windows": []}
        for window, max_count in checks:
            q = deque()
            observed = 0
            observed_start = None
            observed_end = None
            for ts in times:
                q.append(ts)
                while q and ts - q[0] > window:
                    q.popleft()
                if len(q) > observed:
                    observed = len(q)
                    observed_start = q[0]
                    observed_end = ts
            wrep = {"window_seconds": window, "max_allowed": max_count, "max_observed": observed, "start": observed_start, "end": observed_end}
            report["windows"].append(wrep)
            if observed > max_count:
                violations.append({"server_ip": dst, "server_port": dport, **wrep})
        group_reports.append(report)

    out = {"ok": not violations, "rows": rows, "groups": group_reports, "violations": violations}
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
