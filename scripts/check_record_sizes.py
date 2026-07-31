#!/usr/bin/env python3
"""Verify TLS record length max and p95 thresholds from tshark field text.

Input is one or more tls.record.length values per line. Values may be separated
by whitespace, tabs, semicolons, or commas, matching common tshark repeated-field output.
"""
import argparse
import json
import math
import re
import sys


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--max", dest="max_len", type=int, required=True, help="Maximum allowed TLS record length")
    p.add_argument("--p95-max", type=int, required=True, help="Maximum allowed nearest-rank p95 TLS record length")
    return p.parse_args()


def fatal(message):
    print(json.dumps({"ok": False, "error": message}, sort_keys=True, indent=2))
    return 2


def nearest_rank(values, q):
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[idx]


def main():
    args = parse_args()
    if args.max_len < 0 or args.p95_max < 0:
        return fatal("thresholds must be non-negative")
    values = []
    try:
        for lineno, raw in enumerate(sys.stdin, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            for token in re.split(r"[\s,;]+", line):
                if not token:
                    continue
                try:
                    n = int(token, 10)
                except ValueError:
                    raise ValueError(f"malformed line {lineno}: TLS record length is not an integer: {token!r}")
                if n < 0:
                    raise ValueError(f"malformed line {lineno}: TLS record length is negative")
                values.append(n)
    except ValueError as exc:
        return fatal(str(exc))
    if not values:
        return fatal("empty input: no TLS record lengths found")
    max_seen = max(values)
    p95 = nearest_rank(values, 0.95)
    violations = []
    if max_seen > args.max_len:
        violations.append({"metric": "max", "observed": max_seen, "allowed": args.max_len})
    if p95 > args.p95_max:
        violations.append({"metric": "p95", "observed": p95, "allowed": args.p95_max})
    out = {"ok": not violations, "count": len(values), "max": max_seen, "max_allowed": args.max_len, "p95": p95, "p95_allowed": args.p95_max, "violations": violations}
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
