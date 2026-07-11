#!/usr/bin/env python3
"""Intervene on ChaCha counter traversal while holding key and rounds fixed."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from pathlib import Path
from typing import Any

import matplotlib
import numpy as np
from scipy.stats import spearmanr

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from arx_carry_leak.atlas import (
    chacha_counter_blocks,
    exact_sign_flip_test,
    mutual_information_matrix,
    positional_entropy,
)
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


TRAVERSALS = (
    "binary",
    "binary_reverse_order",
    "binary_shuffled",
    "gray",
    "stride3",
    "stride257",
    "bit_reversed32",
    "xorshift32",
)


def _bit_reverse32(values: np.ndarray) -> np.ndarray:
    result = values.astype(np.uint32, copy=True)
    result = ((result >> 1) & 0x55555555) | ((result & 0x55555555) << 1)
    result = ((result >> 2) & 0x33333333) | ((result & 0x33333333) << 2)
    result = ((result >> 4) & 0x0F0F0F0F) | ((result & 0x0F0F0F0F) << 4)
    result = ((result >> 8) & 0x00FF00FF) | ((result & 0x00FF00FF) << 8)
    return ((result >> 16) | (result << 16)).astype(np.uint32)


def _xorshift32(count: int, seed: int) -> np.ndarray:
    state = np.uint32(seed or 1)
    output = np.empty(count, dtype=np.uint32)
    for index in range(count):
        state ^= state << np.uint32(13)
        state ^= state >> np.uint32(17)
        state ^= state << np.uint32(5)
        output[index] = state
    return output


def _traversal(name: str, count: int, seed: int) -> np.ndarray:
    base = np.arange(count, dtype=np.uint32)
    if name == "binary":
        return base
    if name == "binary_reverse_order":
        return base[::-1].copy()
    if name == "binary_shuffled":
        return np.random.default_rng(seed ^ 0x51A7F1E).permutation(base)
    if name == "gray":
        return base ^ (base >> np.uint32(1))
    if name == "stride3":
        return (base * np.uint32(3) + np.uint32(0xA5A5A5A5)).astype(np.uint32)
    if name == "stride257":
        return (base * np.uint32(257) + np.uint32(0xA5A5A5A5)).astype(np.uint32)
    if name == "bit_reversed32":
        return _bit_reverse32(base)
    if name == "xorshift32":
        return _xorshift32(count, seed ^ 0x9E3779B9)
    raise ValueError(f"unknown traversal {name}")


def _paired_control(
    source: np.ndarray, paired_next: np.ndarray, *, shift: int, routes: int, seed: int
) -> dict[str, Any]:
    observed = mutual_information_matrix(source, source ^ paired_next, shift=shift)
    rng = np.random.default_rng(seed)
    controls = np.stack(
        [
            mutual_information_matrix(source, source ^ paired_next[rng.permutation(len(paired_next))], shift=shift)
            for _ in range(routes)
        ]
    )
    control_mean = controls.mean(axis=0)
    excess = observed - control_mean
    return {
        "observed": observed,
        "control_mean": control_mean,
        "excess": excess,
        "observed_mean": float(observed.mean()),
        "control_mean_scalar": float(control_mean.mean()),
        "excess_mean": float(excess.mean()),
        "excess_l2": float(np.linalg.norm(excess)),
    }


def _counter_diagnostics(counters: np.ndarray, shift: int) -> dict[str, Any]:
    byte_rows = counters.astype("<u4", copy=False).view(np.uint8).reshape(-1, 4)
    xor_delta = counters[:-1] ^ counters[1:]
    hamming = np.unpackbits(xor_delta.astype("<u4", copy=False).view(np.uint8).reshape(-1, 4), axis=1).sum(axis=1)
    input_matrix = mutual_information_matrix(byte_rows[:-1], byte_rows[:-1] ^ byte_rows[1:], shift=shift)
    entropy = positional_entropy(byte_rows)
    return {
        "unique_counters": int(len(np.unique(counters))),
        "counter_multiset_sha256": hashlib.sha256(np.sort(counters).tobytes()).hexdigest(),
        "ordered_counter_sha256": hashlib.sha256(counters.tobytes()).hexdigest(),
        "mean_xor_hamming_distance": float(hamming.mean()),
        "minimum_xor_hamming_distance": int(hamming.min()),
        "maximum_xor_hamming_distance": int(hamming.max()),
        "byte_entropy": [float(value) for value in entropy],
        "input_transition_mean_mi": float(input_matrix.mean()),
        "input_transition_maximum_mi": float(input_matrix.max()),
        "input_transition_matrix": input_matrix,
    }


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, dict[str, np.ndarray]]]:
    raw: dict[str, list[dict[str, Any]]] = {name: [] for name in args.traversals}
    binary_within: dict[int, np.ndarray] = {}
    execution_order = ["binary", *[name for name in args.traversals if name != "binary"]]
    for seed_index in range(args.seeds):
        seed = 42 + 1009 * seed_index
        for name in execution_order:
            counters = _traversal(name, args.operations, seed)
            blocks = chacha_counter_blocks(counters, args.rounds, seed)
            first, second = blocks[:, :32], blocks[:, 32:]
            between = _paired_control(
                second[:-1],
                first[1:],
                shift=args.shift,
                routes=args.routes,
                seed=seed ^ 0xB37E3E ^ sum(name.encode()),
            )
            within = mutual_information_matrix(first, first ^ second, shift=args.shift)
            diagnostics = _counter_diagnostics(counters, args.shift)
            if name == "binary":
                binary_within[seed] = within
            invariant = None
            if name in {"binary_reverse_order", "binary_shuffled"}:
                invariant = float(np.max(np.abs(within - binary_within[seed])))
            raw[name].append(
                {
                    "seed": seed,
                    "between": between,
                    "within": within,
                    "within_vs_binary_max_abs": invariant,
                    "counter": diagnostics,
                }
            )
    results = []
    matrices: dict[str, dict[str, np.ndarray]] = {}
    binary_effects = [record["between"]["excess_mean"] for record in raw["binary"]]
    for name in args.traversals:
        records = raw[name]
        effects = [record["between"]["excess_mean"] for record in records]
        excess = np.mean([record["between"]["excess"] for record in records], axis=0)
        within = np.mean([record["within"] for record in records], axis=0)
        input_matrix = np.mean([record["counter"]["input_transition_matrix"] for record in records], axis=0)
        maximum = np.unravel_index(int(np.argmax(excess)), excess.shape)
        minimum = np.unravel_index(int(np.argmin(excess)), excess.shape)
        result = {
            "traversal": name,
            "between_block_excess_mean": _summary(effects),
            "between_block_paired_exact_test": exact_sign_flip_test(effects),
            "paired_difference_vs_binary": exact_sign_flip_test(
                list(np.asarray(effects) - np.asarray(binary_effects))
            ),
            "between_block_excess_l2": _summary(
                [record["between"]["excess_l2"] for record in records]
            ),
            "mean_excess_maximum": float(excess[maximum]),
            "mean_excess_maximum_edge": [int(value) for value in maximum],
            "mean_excess_minimum": float(excess[minimum]),
            "mean_excess_minimum_edge": [int(value) for value in minimum],
            "mean_between_block_excess_matrix": [[float(value) for value in row] for row in excess],
            "mean_within_block_matrix": [[float(value) for value in row] for row in within],
            "mean_input_transition_matrix": [[float(value) for value in row] for row in input_matrix],
            "counter_diagnostics": {
                "unique_counters": [record["counter"]["unique_counters"] for record in records],
                "multiset_sha256": [record["counter"]["counter_multiset_sha256"] for record in records],
                "ordered_sha256": [record["counter"]["ordered_counter_sha256"] for record in records],
                "mean_xor_hamming_distance": _summary(
                    [record["counter"]["mean_xor_hamming_distance"] for record in records]
                ),
                "input_transition_mean_mi": _summary(
                    [record["counter"]["input_transition_mean_mi"] for record in records]
                ),
                "input_transition_maximum_mi": _summary(
                    [record["counter"]["input_transition_maximum_mi"] for record in records]
                ),
                "mean_byte_entropy": [
                    float(value)
                    for value in np.mean([record["counter"]["byte_entropy"] for record in records], axis=0)
                ],
            },
            "within_same_multiset_invariance_max_abs": (
                max(record["within_vs_binary_max_abs"] for record in records)
                if name in {"binary_reverse_order", "binary_shuffled"}
                else None
            ),
            "per_seed_scalars": [
                {
                    "seed": record["seed"],
                    "between_observed_mean": record["between"]["observed_mean"],
                    "between_control_mean": record["between"]["control_mean_scalar"],
                    "between_excess_mean": record["between"]["excess_mean"],
                    "between_excess_l2": record["between"]["excess_l2"],
                    "mean_xor_hamming_distance": record["counter"]["mean_xor_hamming_distance"],
                    "input_transition_mean_mi": record["counter"]["input_transition_mean_mi"],
                }
                for record in records
            ],
        }
        results.append(result)
        matrices[name] = {"output": excess, "input": input_matrix}
    input_values = [result["counter_diagnostics"]["input_transition_mean_mi"]["mean"] for result in results]
    output_values = [result["between_block_excess_mean"]["mean"] for result in results]
    correlation = spearmanr(input_values, output_values)
    for result in results:
        result["across_traversal_context"] = {
            "input_output_spearman_rho": float(correlation.statistic),
            "input_output_spearman_p": float(correlation.pvalue),
            "n_traversals": len(results),
        }
    return results, matrices


def _plot(results: list[dict[str, Any]], matrices: dict[str, dict[str, np.ndarray]], output: Path) -> None:
    figure, axes = plt.subplots(len(results), 2, figsize=(9.5, 3.2 * len(results)), squeeze=False)
    output_limit = max(float(np.max(np.abs(value["output"]))) for value in matrices.values())
    input_limit = max(float(np.max(value["input"])) for value in matrices.values())
    for row, result in enumerate(results):
        name = result["traversal"]
        out_image = axes[row, 0].imshow(
            matrices[name]["output"], cmap="coolwarm", vmin=-output_limit, vmax=output_limit
        )
        in_image = axes[row, 1].imshow(matrices[name]["input"], cmap="viridis", vmin=0, vmax=input_limit)
        axes[row, 0].set_title(f"{name}: ChaCha between-block excess")
        axes[row, 1].set_title(f"{name}: counter transition MI")
        for axis in axes[row]:
            axis.set_xlabel("delta byte j")
            axis.set_ylabel("source byte i")
        figure.colorbar(out_image, ax=axes[row, 0], shrink=0.7)
        figure.colorbar(in_image, ax=axes[row, 1], shrink=0.7)
    figure.suptitle("ChaCha counter-traversal intervention")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=160, bbox_inches="tight", metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_counter_traversal_suite", parameters=parameters)
    for result in results:
        test = result["between_block_paired_exact_test"]
        builder.add_triplet(
            edge_id=f"{result['traversal']}-between-block",
            trigger=f"chacha_r{parameters['rounds']}:{result['traversal']}:counter_sequence",
            mechanism="determines_next_block_counter_geometry",
            outcome="between_block_conditional_information_vs_repairing",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="paired_exact_sign_flip_across_keys",
            source=source,
            attrs={**test, "mean_excess": result["between_block_excess_mean"]["mean"]},
        )
    shuffled = next(result for result in results if result["traversal"] == "binary_shuffled")
    comparison = shuffled["paired_difference_vs_binary"]
    builder.add_triplet(
        edge_id="binary-order-shuffle-intervention",
        trigger="do(binary_counter_order=random_permutation_same_multiset)",
        mechanism="destroys_successor_geometry_while_preserving_counter_multiset",
        outcome="change_in_chacha_between_block_information",
        confidence=1.0 - float(comparison["two_sided_p"]),
        evidence_kind="paired_order_intervention",
        source=source,
        attrs={
            **comparison,
            "binary_mean": results[0]["between_block_excess_mean"]["mean"],
            "shuffled_mean": shuffled["between_block_excess_mean"]["mean"],
            "within_multiset_invariance": shuffled["within_same_multiset_invariance_max_abs"],
        },
    )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--operations", type=int, default=10000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--traversals", nargs="*", default=list(TRAVERSALS))
    args = parser.parse_args()
    if args.rounds < 1 or args.operations < 1000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("rounds >= 1, operations >= 1000, seeds >= 3 and routes >= 3 required")
    unknown = sorted(set(args.traversals) - set(TRAVERSALS))
    if unknown:
        raise ValueError(f"unknown traversals: {', '.join(unknown)}")
    if "binary" not in args.traversals or "binary_shuffled" not in args.traversals:
        raise ValueError("binary and binary_shuffled are required controls")
    parameters = {
        "rounds": args.rounds,
        "operations": args.operations,
        "seeds": args.seeds,
        "routes": args.routes,
        "shift": args.shift,
        "traversals": args.traversals,
    }
    results, matrices = _run(args)
    _plot(results, matrices, args.figure)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_counter_traversal_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": (
            "This chosen-input intervention isolates how public counter traversal controls an early-round "
            "known-key output relation. It is not a claim about standard ChaCha20 keystream security."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(results, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    print(f"wrote {args.figure}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
