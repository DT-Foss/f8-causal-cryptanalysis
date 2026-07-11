#!/usr/bin/env python3
"""Turn paired AES prefix outputs themselves into stable reversible .causal graphs."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import platform
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import aes_inverse_linear_layer, aes_inverse_shift_rows, aes_prefix_batch
from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.output_causal import derive_edges, evaluate_holdout, reverse_rank, save_output_graph


def _sign_flip(values: list[float]) -> float:
    values_array = np.asarray(values, dtype=float)
    observed = float(values_array.mean())
    null = np.asarray([np.mean(values_array * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(values_array))])
    return float(min(1.0, 2 * min(np.mean(null >= observed), np.mean(null <= observed))))


def _represent(first: np.ndarray, second: np.ndarray, rounds: int, representation: str) -> tuple[np.ndarray, np.ndarray]:
    if representation == "identity":
        return first, second
    if representation == "peel-final-linear":
        transform = aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer
        return transform(first), transform(second)
    raise ValueError(f"unknown representation {representation}")


def _aggregate(seed_edges: list[list[dict[str, Any]]], *, consensus: int) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, int, int, int], list[dict[str, Any]]] = defaultdict(list)
    for edges in seed_edges:
        for edge in edges:
            grouped[(edge["source_byte"], edge["source_bin"], edge["outcome_byte"], edge["outcome_bin"])].append(edge)
    result = []
    for key, rows in grouped.items():
        if len(rows) < consensus:
            continue
        excess = [float(row["excess_count"]) for row in rows]
        p = _sign_flip(excess)
        result.append({
            "source_byte": key[0], "source_bin": key[1], "outcome_byte": key[2], "outcome_bin": key[3],
            "observed_count": int(round(np.mean([row["observed_count"] for row in rows]))),
            "control_mean_count": float(np.mean([row["control_mean_count"] for row in rows])),
            "control_sd_count": float(np.mean([row["control_sd_count"] for row in rows])),
            "excess_count": float(np.mean(excess)),
            "route_z": float(np.mean([row["route_z"] for row in rows])),
            "empirical_upper_p": p / 2.0,
            "conditional_probability": float(np.mean([row["conditional_probability"] for row in rows])),
            "marginal_probability": float(np.mean([row["marginal_probability"] for row in rows])),
            "lift": float(np.mean([row["lift"] for row in rows])),
            "supporting_seeds": len(rows),
            "exact_sign_flip_p": p,
        })
    return sorted(result, key=lambda row: (-row["supporting_seeds"], -row["route_z"], -row["excess_count"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, nargs="+", default=[3, 4, 10])
    parser.add_argument("--representations", nargs="+", choices=["identity", "peel-final-linear"], default=["identity", "peel-final-linear"])
    parser.add_argument("--bits", type=int, nargs="+", default=[0, 31, 64, 127])
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--bins", type=int, default=16)
    parser.add_argument("--max-edges", type=int, default=128)
    parser.add_argument("--train-seeds", type=int, default=0, help="first N keys build graph; remaining keys are reverse-query holdout")
    parser.add_argument("--seed-base", type=int, default=685001)
    args = parser.parse_args()
    if any(rounds not in range(1, 11) for rounds in args.rounds) or any(bit not in range(128) for bit in args.bits):
        raise ValueError("rounds must be [1,10] and bits [0,127]")
    if args.train_seeds < 0 or args.train_seeds >= args.seeds:
        if args.train_seeds:
            raise ValueError("train-seeds must be between 1 and seeds-1")
    buffers: dict[tuple[int, str, int], dict[str, list[Any]]] = {
        (rounds, representation, bit): {"source": [], "delta": [], "edges": []}
        for rounds in args.rounds for representation in args.representations for bit in args.bits
    }
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed)
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        plaintexts = rng.integers(0, 256, size=(args.pairs, 16), dtype=np.uint8)
        for rounds in args.rounds:
            print(f"aes direct-output causal seed={seed} rounds={rounds}", flush=True)
            first = aes_prefix_batch(key, plaintexts, rounds)
            for bit in args.bits:
                paired_plaintexts = plaintexts.copy()
                paired_plaintexts[:, bit // 8] ^= np.uint8(1 << (bit % 8))
                second = aes_prefix_batch(key, paired_plaintexts, rounds)
                for representation in args.representations:
                    source, paired = _represent(first, second, rounds, representation)
                    delta = source ^ paired
                    record = buffers[rounds, representation, bit]
                    # The graph is built from observed differential output
                    # nodes themselves.  This avoids assuming that a random-
                    # looking base-output byte is the causal parent.
                    record["source"].append(delta)
                    record["delta"].append(delta)
                    record["edges"].append(derive_edges(source, delta, bins=args.bins, routes=args.routes, seed=seed ^ (rounds << 16) ^ bit, max_edges=args.max_edges))
    args.causal_dir.mkdir(parents=True, exist_ok=True)
    result_rows = []
    for (rounds, representation, bit), record in buffers.items():
        train_count = args.train_seeds or args.seeds
        source = np.concatenate(record["source"][:train_count])
        delta = np.concatenate(record["delta"][:train_count])
        # Causal compression is performed on all observed output rows.  The
        # seedwise lists are retained for a later disjoint-key holdout rather
        # than used as a brittle exact-bin intersection.
        edges = derive_edges(source, delta, bins=args.bins, routes=args.routes, seed=args.seed_base ^ rounds ^ bit, max_edges=args.max_edges, exclude_diagonal=True)
        condition = f"aes-r{rounds}-{representation}-bit{bit}"
        causal_path = args.causal_dir / f"{condition}.causal"
        stats = save_output_graph(str(causal_path), experiment="aes_output_causal_codec", condition=condition, parameters={"rounds": rounds, "representation": representation, "input_bit": bit, "bins": args.bins, "train_seeds": train_count, "pairs_per_seed": args.pairs, "repair_routes": args.routes}, source=source, outcome=delta, edges=edges)
        reader = CryptoCausalReader(causal_path)
        reverse = reverse_rank(reader, condition=condition, observed_delta=delta[0], bins=args.bins)[:8]
        holdout = []
        for heldout_index, (heldout_source, heldout_delta) in enumerate(zip(record["source"][train_count:], record["delta"][train_count:], strict=True)):
            holdout.append(evaluate_holdout(reader, condition=condition, source=heldout_source, outcome=heldout_delta, bins=args.bins, routes=args.routes, seed=args.seed_base ^ rounds ^ bit ^ heldout_index))
        holdout_summary = None
        if holdout:
            holdout_summary = {
                "keys": len(holdout),
                "mean_edge_excess_count": float(np.mean([row["mean_edge_excess_count"] for row in holdout])),
                "reverse_coverage": float(np.mean([row["reverse_coverage"] for row in holdout])),
                "reverse_top1_hit_rate": float(np.mean([row["reverse_top1_hit_rate"] for row in holdout])),
                "reverse_marginal_baseline_rate": float(np.mean([row["reverse_marginal_baseline_rate"] for row in holdout])),
                "reverse_lift_over_marginal": float(np.mean([row["reverse_lift_over_marginal"] for row in holdout])),
                "edge_excess_sign_flip_p": _sign_flip([row["mean_edge_excess_count"] for row in holdout]),
            }
        result_rows.append({"rounds": rounds, "representation": representation, "input_bit": bit, "causal_path": str(causal_path), "causal": stats, "candidate_edges_per_seed": [len(rows) for rows in record["edges"]], "causal_compressed_edges": len(edges), "edge_summaries": edges[:16], "reverse_query_for_first_delta": reverse, "holdout": holdout_summary})
    payload = {"schema": "aes-direct-output-causal-v1", "parameters": {key: value for key, value in vars(args).items() if key not in {"output", "causal_dir"}}, "environment": {"python": sys.version, "numpy": np.__version__, "platform": platform.platform()}, "results": result_rows, "scope": "direct observed-output causal compression and reverse output-node ranking; not key recovery or a full-AES security claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.write_bytes(encoded)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "conditions": len(result_rows), "causal_compressed_edges": sum(row["causal_compressed_edges"] for row in result_rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
