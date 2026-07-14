#!/usr/bin/env python3
"""Fail-closed validation of every repository-local .causal artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from arx_carry_leak._dotcausal import io as dotcausal_io
from arx_carry_leak.crypto_causal import CryptoCausalReader


def _validate_legacy(path: Path) -> dict[str, object]:
    reader = CryptoCausalReader(path)
    triplets = reader.triplets()
    if not triplets:
        raise ValueError(f"empty legacy Causal graph: {path}")
    if not reader.verify_provenance():
        raise ValueError(f"invalid inferred-edge provenance: {path}")
    return {
        "path": str(path),
        "format": "crypto-causal-v3",
        "experiment": reader.graph["experiment"],
        "triplets": len(triplets),
        "parameters": len(reader.graph.get("parameters", {})),
        "integrity": "graph-sha256-and-inferred-provenance",
    }


def _validate_dotcausal(path: Path) -> dict[str, object]:
    encoded = path.read_bytes()
    if len(encoded) < 96:
        raise ValueError(f"truncated dotcausal artifact: {path}")
    stored_crc = encoded[20:28]
    content = encoded[96:]
    xxhash_crc = struct.pack("<Q", dotcausal_io.xxhash.xxh64(content).intdigest())
    md5_crc = hashlib.md5(content).digest()[:8]
    if stored_crc == xxhash_crc:
        has_xxhash = True
        integrity = "xxhash64"
    elif stored_crc == md5_crc:
        has_xxhash = False
        integrity = "md5-fallback"
    else:
        raise ValueError(f"dotcausal content checksum differs: {path}")

    original = dotcausal_io.HAS_XXHASH
    dotcausal_io.HAS_XXHASH = has_xxhash
    try:
        reader = dotcausal_io.CausalReader(str(path), verify_integrity=True)
    finally:
        dotcausal_io.HAS_XXHASH = original
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    if not all_rows:
        raise ValueError(f"empty dotcausal graph: {path}")
    return {
        "path": str(path),
        "format": "dotcausal-v1",
        "api_id": reader.api_id,
        "version": reader.version,
        "explicit_triplets": len(explicit),
        "inferred_triplets": len(all_rows) - len(explicit),
        "triplets": len(all_rows),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity": integrity,
    }


def validate(path: Path) -> dict[str, object]:
    header = path.read_bytes()[:8]
    if header == b"CAUSAL\x03\x00":
        return _validate_legacy(path)
    if header == b"CAUSAL\x00\x01":
        return _validate_dotcausal(path)
    raise ValueError(f"unsupported Causal header {header!r}: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path("research/results"))
    args = parser.parse_args()
    paths = sorted(args.root.rglob("*.causal"))
    if not paths:
        raise SystemExit(f"no .causal files found below {args.root}")
    rows = []
    for path in paths:
        rows.append(validate(path))
    print(json.dumps({"validated": len(rows), "artifacts": rows}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
