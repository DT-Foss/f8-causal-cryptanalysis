#!/usr/bin/env python3
"""Screen chosen plaintext-bit differences across genuine AES-128 prefixes."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import (
    aes_inverse_linear_layer,
    aes_inverse_shift_rows,
    aes_prefix_batch,
    exact_sign_flip_test,
)
from arx_carry_leak.crypto_causal import CryptoCausalBuilder
from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.differential import repairing_analysis


METRICS = (
    "entropy_deficit_sum",
    "maximum_byte_entropy_deficit",
    "mean_bit_bias_chi2",
    "maximum_bit_bias_chi2",
    "maximum_absolute_bit_probability_bias",
)


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": values,
        "mean": float(array.mean()),
        "sample_sd_ddof1": float(array.std(ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(array.min()),
        "maximum": float(array.max()),
    }


def _bh_adjust(rows: list[dict[str, Any]], key: str, output_key: str | None = None) -> None:
    order = sorted(range(len(rows)), key=lambda index: rows[index][key])
    running = 1.0
    for rank in range(len(order), 0, -1):
        index = order[rank - 1]
        running = min(running, rows[index][key] * len(rows) / rank)
        rows[index][output_key or f"{key}_bh_q"] = float(running)


def _unique_plaintexts(rng: np.random.Generator, count: int) -> np.ndarray:
    """Generate unique AES blocks without silently reducing the requested N."""
    chunks: list[np.ndarray] = []
    have = 0
    seen: set[bytes] = set()
    while have < count:
        batch = rng.integers(0, 256, size=(count - have, 16), dtype=np.uint8)
        keep = []
        for row in batch:
            token = row.tobytes()
            if token not in seen:
                seen.add(token)
                keep.append(row.copy())
        if keep:
            chunk = np.stack(keep)
            chunks.append(chunk)
            have += len(chunk)
    return np.concatenate(chunks, axis=0)[:count]


def run_screen(args: argparse.Namespace) -> list[dict[str, Any]]:
    records: dict[tuple[int, int, str], list[dict[str, Any]]] = {
        (rounds, bit, representation): []
        for rounds in args.rounds
        for bit in args.bits
        for representation in args.representations
    }
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed ^ 0xAE5)
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        plaintexts = _unique_plaintexts(rng, args.pairs)
        for rounds in args.rounds:
            print(f"aes screen seed={seed} rounds={rounds}", flush=True)
            first = aes_prefix_batch(key, plaintexts, rounds)
            for bit in args.bits:
                paired_plaintexts = plaintexts.copy()
                paired_plaintexts[:, bit // 8] ^= np.uint8(1 << (bit % 8))
                second = aes_prefix_batch(key, paired_plaintexts, rounds)
                for representation in args.representations:
                    if representation == "identity":
                        represented_first, represented_second = first, second
                    elif representation == "inverse-linear":
                        represented_first = aes_inverse_linear_layer(first)
                        represented_second = aes_inverse_linear_layer(second)
                    elif representation == "peel-final-linear":
                        transform = aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer
                        represented_first = transform(first)
                        represented_second = transform(second)
                    else:
                        raise ValueError(f"unknown representation: {representation}")
                    analysis = repairing_analysis(
                        represented_first,
                        represented_second,
                        routes=args.routes,
                        seed=seed ^ (rounds << 16) ^ bit ^ (0x1A2B if representation != "identity" else 0),
                    )
                    analysis["seed"] = seed
                    records[rounds, bit, representation].append(analysis)

    results: list[dict[str, Any]] = []
    for rounds in args.rounds:
        for bit in args.bits:
            for representation in args.representations:
                rows = records[rounds, bit, representation]
                metrics: dict[str, Any] = {}
                for metric in METRICS:
                    differences = [row["effects"][metric]["difference"] for row in rows]
                    metrics[metric] = {
                        "effect": _summary(differences),
                        "actual": _summary([row["actual"][metric] for row in rows]),
                        "route_z": _summary([row["effects"][metric]["route_z"] for row in rows]),
                        "exact_sign_flip": exact_sign_flip_test(differences),
                    }
                results.append({
                    "rounds": rounds,
                    "plaintext_bit": bit,
                    "representation": representation,
                    "metrics": metrics,
                })

    for metric in METRICS:
        key = f"{metric}_p"
        for row in results:
            row[key] = row["metrics"][metric]["exact_sign_flip"]["two_sided_p"]
        _bh_adjust(results, key)
        for rounds in args.rounds:
            for representation in args.representations:
                family = [
                    row
                    for row in results
                    if row["rounds"] == rounds and row["representation"] == representation
                ]
                _bh_adjust(family, key, f"{key}_family_bh_q")
    return results


def _causal(results: list[dict[str, Any]], parameters: dict[str, Any], output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="aes_bit_round_frontier_screen", parameters=parameters)
    for row in results:
        entropy_row = row["metrics"]["entropy_deficit_sum"]
        builder.add_triplet(
            edge_id=f"aes-r{row['rounds']}-bit{row['plaintext_bit']}-{row['representation']}",
            trigger=f"aes_r{row['rounds']}:plaintext_xor_bit_{row['plaintext_bit']}",
            mechanism="chosen_plaintext_difference_propagation",
            outcome=f"{row['representation']}_output_differential_entropy_vs_repairing",
            confidence=1.0 - float(entropy_row["exact_sign_flip"]["two_sided_p"]),
            evidence_kind="discovery_screen_paired_keys",
            source=str(output.with_suffix(".json")),
            attrs={"effect_mean": entropy_row["effect"]["mean"], "screen_only": True},
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=[1, 2, 3, 4, 10])
    parser.add_argument("--bits", type=int, nargs="+", default=list(range(128)))
    parser.add_argument(
        "--representations",
        choices=("identity", "inverse-linear", "peel-final-linear"),
        nargs="+",
        default=["identity"],
    )
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--seed-base", type=int, default=85001)
    parser.add_argument(
        "--status",
        default="discovery screen; candidates require frozen independent holdout",
    )
    args = parser.parse_args()
    if any(not 1 <= rounds <= 10 for rounds in args.rounds):
        parser.error("rounds must be in [1, 10]")
    if any(not 0 <= bit < 128 for bit in args.bits):
        parser.error("bits must be in [0, 127]")

    parameters = {
        "rounds": args.rounds,
        "bits": args.bits,
        "representations": args.representations,
        "pairs_per_seed": args.pairs,
        "seeds": args.seeds,
        "repairing_routes": args.routes,
        "seed_base": args.seed_base,
        "aes_semantics": "genuine AES-128 prefix; MixColumns in prefix rounds 1-9",
        "null": "same outputs with independently permuted second rows",
        "status": args.status,
    }
    results = run_screen(args)
    payload = {
        "schema": "aes-bit-round-frontier-v1",
        "parameters": parameters,
        "results": results,
        "environment": {"python": sys.version, "numpy": np.__version__, "platform": platform.platform()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode()
    args.output.write_bytes(encoded + b"\n")
    causal_path = args.output.with_suffix(".causal")
    causal_meta = _causal(results, parameters, causal_path)
    causal_reader = CryptoCausalReader(causal_path)
    causal_triplets = causal_reader.triplets()
    if len(causal_triplets) != causal_meta["triplets"] or not causal_reader.verify_provenance():
        raise RuntimeError("causal round-trip validation failed after writing the artifact")
    causal_meta["reader_roundtrip"] = {
        "triplets": len(causal_triplets),
        "provenance_valid": True,
        "graph_sha256": causal_reader.graph_sha256,
        "file_sha256": causal_reader.file_sha256,
    }
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(encoded + b"\n").hexdigest(),
        "causal": causal_meta,
        "rows": len(results),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
