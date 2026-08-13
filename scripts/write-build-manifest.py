#!/usr/bin/env python3
"""Write the deployment manifest that binds binaries and panel to one build."""

import argparse
import hashlib
import json
import os
from pathlib import Path


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(path):
    p = Path(path)
    return {"name": p.name, "size": p.stat().st_size, "sha256": sha256(p)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--client")
    parser.add_argument("--goos", default=os.environ.get("GOOS", "linux"))
    parser.add_argument("--goarch", default=os.environ.get("GOARCH", "unknown"))
    args = parser.parse_args()

    required = ["TAMIZDAT_VERSION", "TAMIZDAT_BUILD_ID", "TAMIZDAT_COMMIT", "TAMIZDAT_BUILD_TIME"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        parser.error("missing build environment: " + ", ".join(missing))

    artifacts = {"server": artifact(args.server), "panel": artifact(args.panel)}
    if args.client:
        artifacts["client"] = artifact(args.client)
    data = {
        "schema": 1,
        "version": os.environ["TAMIZDAT_VERSION"],
        "build_id": os.environ["TAMIZDAT_BUILD_ID"],
        "commit": os.environ["TAMIZDAT_COMMIT"],
        "build_time": os.environ["TAMIZDAT_BUILD_TIME"],
        "target": {"goos": args.goos, "goarch": args.goarch},
        "artifacts": artifacts,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
