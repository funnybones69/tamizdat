#!/usr/bin/env python3
"""Sum pcap-visible cumulative server-to-client tcp.len bytes per outer TCP flow.

Input is tshark field text with columns:
  ip.src tcp.srcport ip.dst tcp.dstport tcp.len
Blank lines and # comments are ignored. Output is JSON.
"""
import argparse
import json
import sys
from collections import defaultdict


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server-ip", required=True, help="Server IP; only rows with ip.src equal to this value count as S2C")
    p.add_argument("--max-s2c", type=int, required=True, help="Maximum cumulative S2C tcp.len bytes per outer TCP flow")
    return p.parse_args()


def fatal(message, line=None):
    payload = {"ok": False, "error": message}
    if line is not None:
        payload["line"] = line
    print(json.dumps(payload, sort_keys=True, indent=2))
    return 2


def parse_len(token, lineno):
    try:
        n = int(token, 10)
    except ValueError:
        raise ValueError(f"malformed line {lineno}: tcp.len is not an integer: {token!r}")
    if n < 0:
        raise ValueError(f"malformed line {lineno}: tcp.len is negative")
    return n


def main():
    args = parse_args()
    if args.max_s2c < 0:
        return fatal("--max-s2c must be non-negative")
    flows = defaultdict(int)
    rows = 0
    try:
        for lineno, raw in enumerate(sys.stdin, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.replace("\t", " ").split()
            if len(fields) != 5:
                raise ValueError(f"malformed line {lineno}: expected 5 fields, got {len(fields)}")
            src, sport, dst, dport, length = fields
            tcp_len = parse_len(length, lineno)
            rows += 1
            if src == args.server_ip and tcp_len > 0:
                flow = {"server_ip": src, "server_port": sport, "client_ip": dst, "client_port": dport}
                key = (src, sport, dst, dport)
                flows[key] += tcp_len
    except ValueError as exc:
        return fatal(str(exc))

    if rows == 0:
        return fatal("empty input: no tcp.len rows found")

    flow_reports = []
    for (src, sport, dst, dport), total in sorted(flows.items()):
        flow_reports.append({
            "server_ip": src,
            "server_port": sport,
            "client_ip": dst,
            "client_port": dport,
            "s2c_bytes": total,
        })
    max_s2c = max((f["s2c_bytes"] for f in flow_reports), default=0)
    violations = [f for f in flow_reports if f["s2c_bytes"] > args.max_s2c]
    out = {
        "ok": not violations,
        "rows": rows,
        "max_s2c": max_s2c,
        "max_s2c_allowed": args.max_s2c,
        "flows": flow_reports,
        "violations": violations,
    }
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
