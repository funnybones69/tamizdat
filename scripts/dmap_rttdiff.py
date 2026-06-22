#!/usr/bin/env python3
"""Estimate dMAP-style TRTT/ARTT and RTTdiff from localhost packet timing.

Input field format (--format fields):
  frame.time_epoch ip.src ip.dst tcp.srcport tcp.dstport tcp.len tcp.flags
Binary pcap input invokes tshark to extract the same fields.
TRTT is approximated as SYN -> SYN/ACK median per TCP flow. ARTT is approximated
as client payload -> next server payload median on the same flow. This is a
numerical comparison helper, not a new threat-model clause.
"""
import argparse
import json
import math
import statistics
import subprocess
import sys
from collections import defaultdict

SYN = 0x02
ACK = 0x10


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", help="binary pcap to analyze; if omitted, read field text from stdin")
    p.add_argument("--format", choices=["fields"], default="fields")
    p.add_argument("--label", default="sample")
    return p.parse_args()


def fatal(message):
    print(json.dumps({"ok": False, "error": message}, sort_keys=True, indent=2))
    return 2


def median(vals):
    return statistics.median(vals) if vals else None


def load_text(path):
    if not path:
        return sys.stdin.read()
    cmd = ["tshark", "-r", path, "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len", "-e", "tcp.flags"]
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise RuntimeError("tshark is required for --pcap")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("tshark failed: " + exc.output.strip())


def parse_flags(s):
    if not s:
        return 0
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return 0


def main():
    args = parse_args()
    try:
        text = load_text(args.pcap)
    except RuntimeError as exc:
        return fatal(str(exc))
    rows = []
    try:
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            f = line.replace("\t", " ").split()
            if len(f) != 7:
                raise ValueError(f"line {lineno}: expected 7 fields, got {len(f)}")
            ts = float(f[0]); src=f[1]; dst=f[2]; sport=f[3]; dport=f[4]; tcp_len=int(f[5] or 0); flags=parse_flags(f[6])
            if not math.isfinite(ts):
                raise ValueError(f"line {lineno}: non-finite timestamp")
            rows.append((ts, src, dst, sport, dport, tcp_len, flags))
    except ValueError as exc:
        return fatal(str(exc))
    if not rows:
        return fatal("empty input")
    rows.sort()

    client_for_flow = {}
    syn_times = {}
    trtt = []
    for ts, src, dst, sport, dport, tcp_len, flags in rows:
        if flags & SYN and not (flags & ACK):
            key = (src, sport, dst, dport)
            syn_times[key] = ts
            client_for_flow[(src, sport, dst, dport)] = (src, sport)
            client_for_flow[(dst, dport, src, sport)] = (src, sport)
        elif flags & SYN and flags & ACK:
            rev = (dst, dport, src, sport)
            if rev in syn_times:
                trtt.append(max(0.0, ts - syn_times[rev]))

    by_flow = defaultdict(list)
    for row in rows:
        ts, src, dst, sport, dport, tcp_len, flags = row
        canon = tuple(sorted([(src, sport), (dst, dport)]))
        by_flow[canon].append(row)

    artt = []
    for packets in by_flow.values():
        client = None
        for ts, src, dst, sport, dport, tcp_len, flags in packets:
            if flags & SYN and not (flags & ACK):
                client = (src, sport)
                break
        if client is None:
            continue
        for i, row in enumerate(packets):
            ts, src, dst, sport, dport, tcp_len, flags = row
            if tcp_len <= 0 or (src, sport) != client:
                continue
            for nxt in packets[i+1:]:
                nts, nsrc, ndst, nsport, ndport, nlen, nfl = nxt
                if nlen > 0 and (nsrc, nsport) != client:
                    artt.append(max(0.0, nts - ts))
                    break

    trtt_s = median(trtt)
    artt_s = median(artt)
    if trtt_s is None or artt_s is None:
        return fatal(f"insufficient timing pairs: trtt_pairs={len(trtt)} artt_pairs={len(artt)}")
    out = {
        "ok": True,
        "label": args.label,
        "rows": len(rows),
        "trtt_pairs": len(trtt),
        "artt_pairs": len(artt),
        "trtt_ms": trtt_s * 1000.0,
        "artt_ms": artt_s * 1000.0,
        "rttdiff_ms": (artt_s - trtt_s) * 1000.0,
        "note": "TRTT=SYN/SYNACK median, ARTT=client-payload to next server-payload median; numerical localhost helper only",
    }
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
