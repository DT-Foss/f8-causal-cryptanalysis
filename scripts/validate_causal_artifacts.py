#!/usr/bin/env python3
"""Fail-closed validation of every repository-local .causal artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path("research/results"))
    args = parser.parse_args()
    paths = sorted(args.root.rglob("*.causal"))
    if not paths:
        raise SystemExit(f"no .causal files found below {args.root}")
    rows = []
    for path in paths:
        reader = CryptoCausalReader(path)
        triplets = reader.triplets()
        if not triplets:
            raise SystemExit(f"empty causal graph: {path}")
        if not reader.verify_provenance():
            raise SystemExit(f"invalid inferred-edge provenance: {path}")
        rows.append({
            "path": str(path),
            "experiment": reader.graph["experiment"],
            "triplets": len(triplets),
            "parameters": len(reader.graph.get("parameters", {})),
        })
    print(json.dumps({"validated": len(rows), "artifacts": rows}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
