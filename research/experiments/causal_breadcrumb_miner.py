#!/usr/bin/env python3
"""Mine reader-validated causal graphs into auditable next-run hypotheses."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any

from arx_carry_leak._dotcausal import io as dotcausal_io
from arx_carry_leak.crypto_causal import CryptoCausalReader

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOP_TOKENS = {
    "output", "differential", "entropy", "repairing", "vs", "chosen", "propagation",
    "quantized", "information", "change", "rate", "screen", "fixed", "random", "global",
    "field", "code", "length", "gain", "family", "round", "bit", "position", "same",
}


def _tokens(value: str) -> set[str]:
    return set(TOKEN_RE.findall(value.lower()))


def _family(trigger: str) -> str:
    return trigger.split(":", 1)[0]


def _read_causal(path: Path) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Read either repository Causal encoding through its native Reader."""

    encoded = path.read_bytes()
    header = encoded[:8]
    if header == b"CAUSAL\x03\x00":
        reader = CryptoCausalReader(path)
        if not reader.verify_provenance():
            raise ValueError(f"invalid provenance: {path}")
        graph = {
            "experiment": str(reader.graph["experiment"]),
            "graph_sha256": reader.graph_sha256,
            "format": "crypto-causal-v3",
        }
        return graph, [dict(row) for row in reader.triplets(include_inferred=False)]

    if header != b"CAUSAL\x00\x01" or len(encoded) < 96:
        raise ValueError(f"unsupported or truncated Causal artifact: {path}")

    stored_crc = encoded[20:28]
    content = encoded[96:]
    md5_crc = hashlib.md5(content).digest()[:8]
    xxhash_crc = (
        struct.pack("<Q", dotcausal_io.xxhash.xxh64(content).intdigest())
        if dotcausal_io.HAS_XXHASH
        else None
    )
    if stored_crc == md5_crc:
        has_xxhash = False
    elif xxhash_crc is not None and stored_crc == xxhash_crc:
        has_xxhash = True
    else:
        raise ValueError(f"dotcausal content checksum differs: {path}")

    original = dotcausal_io.HAS_XXHASH
    dotcausal_io.HAS_XXHASH = has_xxhash
    try:
        reader = dotcausal_io.CausalReader(str(path), verify_integrity=True)
    finally:
        dotcausal_io.HAS_XXHASH = original
    graph = {
        "experiment": f"dotcausal:{reader.api_id}",
        "graph_sha256": hashlib.sha256(encoded).hexdigest(),
        "format": "dotcausal-v1",
    }
    return graph, [dict(row) for row in reader.get_all_triplets(include_inferred=False)]


def mine(root: Path) -> dict[str, Any]:
    edges: list[dict[str, Any]] = []
    graphs = []
    for path in sorted(root.rglob("*.causal")):
        graph, triplets = _read_causal(path)
        graphs.append({"path": str(path), **graph})
        for edge in triplets:
            row = dict(edge)
            row["artifact"] = str(path)
            row["family"] = _family(edge["trigger"])
            row["positive"] = edge["confidence"] >= 0.9
            edges.append(row)

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        by_family[edge["family"]].append(edge)

    family_hypotheses = []
    for family, rows in sorted(by_family.items()):
        mechanisms = sorted({row["mechanism"] for row in rows})
        outcomes = sorted({row["outcome"] for row in rows})
        positive = [row for row in rows if row["positive"]]
        if len(mechanisms) < 2:
            continue
        for left in mechanisms:
            for right in mechanisms:
                if left >= right:
                    continue
                evidence = [row for row in positive if row["mechanism"] in (left, right)]
                artifact_mechanisms: dict[str, set[str]] = defaultdict(set)
                for row in positive:
                    artifact_mechanisms[row["artifact"]].add(row["mechanism"])
                joint_artifacts = sorted(
                    artifact for artifact, mechanisms_seen in artifact_mechanisms.items()
                    if left in mechanisms_seen and right in mechanisms_seen
                )
                family_hypotheses.append({
                    "kind": "same_target_mechanism_composition",
                    "family": family,
                    "first_mechanism": left,
                    "second_mechanism": right,
                    "observed_outcomes": outcomes,
                    "positive_edge_count": len(evidence),
                    "status": "already_jointly_observed" if joint_artifacts else "unrun_composition",
                    "joint_artifacts": joint_artifacts,
                    "reason": "same trigger family has independently positive mechanisms that have not been jointly tested",
                })

    cross_hypotheses = []
    seen_bridges: set[tuple[str, str, tuple[str, ...]]] = set()
    positive = [edge for edge in edges if edge["positive"]]
    for index, left in enumerate(positive):
        left_tokens = _tokens(left["outcome"])
        for right in positive[index + 1 :]:
            if left["family"] == right["family"]:
                continue
            if left["mechanism"] == right["mechanism"]:
                continue
            overlap = sorted((left_tokens & (_tokens(right["mechanism"]) | _tokens(right["outcome"]))) - STOP_TOKENS)
            if not overlap:
                continue
            bridge_key = (left["mechanism"], right["mechanism"], tuple(overlap))
            if bridge_key in seen_bridges:
                continue
            seen_bridges.add(bridge_key)
            score = len(overlap) * min(left["confidence"], right["confidence"])
            cross_hypotheses.append({
                "kind": "cross_family_token_bridge",
                "left": {"artifact": left["artifact"], "trigger": left["trigger"], "mechanism": left["mechanism"], "outcome": left["outcome"]},
                "right": {"artifact": right["artifact"], "trigger": right["trigger"], "mechanism": right["mechanism"], "outcome": right["outcome"]},
                "shared_tokens": overlap,
                "score": score,
                "status": "hypothesis_only",
            })
    cross_hypotheses.sort(key=lambda row: (-row["score"], row["shared_tokens"]))
    return {
        "schema": "causal-breadcrumb-miner-v1",
        "graphs": graphs,
        "edge_count": len(edges),
        "positive_edge_count": sum(edge["positive"] for edge in edges),
        "family_mechanism_compositions": family_hypotheses,
        "cross_family_bridges": cross_hypotheses[:500],
        "interpretation": "Hypotheses are planning artifacts; only a subsequent experiment may promote them to evidence triplets.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("research/results/v1"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = mine(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "graphs": len(payload["graphs"]), "edges": payload["edge_count"], "family_hypotheses": len(payload["family_mechanism_compositions"]), "cross_bridges": len(payload["cross_family_bridges"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
