#!/usr/bin/env python3
"""Conditional code gain under an involution-preserving ChaCha null."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import platform
import sys
from pathlib import Path
from typing import Any

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test, mutual_information_matrix
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


def _load_matching() -> Any:
    path = Path(__file__).with_name("chacha_involution_fair_null_suite.py")
    spec = importlib.util.spec_from_file_location("chacha_matching_for_conditional", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load matching helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _analyse(
    outputs: np.ndarray,
    *,
    counter_bit: int,
    shift: int,
    routes: int,
    seed: int,
    matching: Any,
) -> dict[str, Any]:
    factual_mapping = np.arange(len(outputs), dtype=np.int64) ^ (1 << counter_bit)
    factual = mutual_information_matrix(outputs, outputs ^ outputs[factual_mapping], shift=shift)
    rng = np.random.default_rng(seed)
    controls = []
    for _ in range(routes):
        mapping = matching._perfect_matching(len(outputs), rng)
        controls.append(mutual_information_matrix(outputs, outputs ^ outputs[mapping], shift=shift))
    control_mean = np.mean(controls, axis=0)
    effect = factual - control_mean
    maximum = np.unravel_index(int(np.argmax(effect)), effect.shape)
    minimum = np.unravel_index(int(np.argmin(effect)), effect.shape)
    return {
        "factual_mean": float(factual.mean()),
        "control_mean": float(control_mean.mean()),
        "mean_effect": float(effect.mean()),
        "l2_effect": float(np.linalg.norm(effect)),
        "maximum_effect": float(effect[maximum]),
        "maximum_edge": [int(value) for value in maximum],
        "minimum_effect": float(effect[minimum]),
        "minimum_edge": [int(value) for value in minimum],
        "effect_matrix": effect,
    }


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace, matching: Any) -> tuple[list[dict[str, Any]], dict[tuple[int, int], np.ndarray]]:
    configs = [(rounds, bits) for rounds in args.rounds for bits in args.active_bits]
    raw = {config: [] for config in configs}
    for seed_index in range(args.seeds):
        key_seed = args.seed_base + 1009 * seed_index
        for rounds, bits in configs:
            coset_rows = []
            for coset in range(args.cosets):
                counters = matching._coset_counters(bits, key_seed ^ (coset * 0x9E3779B1))
                outputs = chacha_counter_blocks(counters, rounds, key_seed)
                analysis = _analyse(
                    outputs,
                    counter_bit=args.counter_bit,
                    shift=args.shift,
                    routes=args.routes,
                    seed=key_seed ^ (rounds << 20) ^ (bits << 12) ^ coset,
                    matching=matching,
                )
                coset_rows.append(analysis)
            raw[rounds, bits].append(
                {
                    "key_seed": key_seed,
                    "mean_effect": float(np.mean([row["mean_effect"] for row in coset_rows])),
                    "mean_l2_effect": float(np.mean([row["l2_effect"] for row in coset_rows])),
                    "mean_maximum_effect": float(np.mean([row["maximum_effect"] for row in coset_rows])),
                    "effect_matrix": np.mean([row["effect_matrix"] for row in coset_rows], axis=0),
                    "cosets": [
                        {key: row[key] for key in (
                            "factual_mean",
                            "control_mean",
                            "mean_effect",
                            "l2_effect",
                            "maximum_effect",
                            "maximum_edge",
                            "minimum_effect",
                            "minimum_edge",
                        )}
                        for row in coset_rows
                    ],
                }
            )
        print(f"conditional-code key={key_seed}", flush=True)
    results = []
    matrices = {}
    for rounds, bits in configs:
        records = raw[rounds, bits]
        mean_effects = [row["mean_effect"] for row in records]
        l2 = [row["mean_l2_effect"] for row in records]
        maxima = [row["mean_maximum_effect"] for row in records]
        matrix = np.mean([row["effect_matrix"] for row in records], axis=0)
        maximum = np.unravel_index(int(np.argmax(matrix)), matrix.shape)
        matrices[rounds, bits] = matrix
        results.append(
            {
                "rounds": rounds,
                "active_low_bits": bits,
                "mean_conditional_code_gain_effect": _summary(mean_effects),
                "mean_effect_exact_test": exact_sign_flip_test(mean_effects),
                "l2_effect": _summary(l2),
                "maximum_edge_effect": _summary(maxima),
                "aggregate_maximum_effect": float(matrix[maximum]),
                "aggregate_maximum_edge": [int(value) for value in maximum],
                "aggregate_effect_matrix": [[float(value) for value in row] for row in matrix],
                "keys": [
                    {key: row[key] for key in (
                        "key_seed", "mean_effect", "mean_l2_effect", "mean_maximum_effect", "cosets"
                    )}
                    for row in records
                ],
            }
        )
    return results, matrices


def _plot(results: list[dict[str, Any]], matrices: dict[tuple[int, int], np.ndarray], output: Path) -> None:
    columns = len(sorted({row["active_low_bits"] for row in results}))
    rows_count = len(sorted({row["rounds"] for row in results}))
    figure, axes = plt.subplots(rows_count, columns, figsize=(4 * columns, 3.6 * rows_count), squeeze=False, layout="constrained")
    rounds_values = sorted({row["rounds"] for row in results})
    bits_values = sorted({row["active_low_bits"] for row in results})
    limit = max(float(np.max(np.abs(matrix))) for matrix in matrices.values())
    for row_index, rounds in enumerate(rounds_values):
        for column_index, bits in enumerate(bits_values):
            axis = axes[row_index, column_index]
            image = axis.imshow(matrices[rounds, bits], cmap="coolwarm", vmin=-limit, vmax=limit)
            axis.set_title(f"R{rounds}, k={bits}")
            axis.set_xlabel("delta byte")
            axis.set_ylabel("source byte")
    figure.colorbar(image, ax=list(axes.ravel()), shrink=0.6, label="conditional MI excess (bits)")
    figure.suptitle("Involution-fair conditional code-gain matrices")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=160, metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_involution_conditional_code_suite", parameters=parameters)
    for row in results:
        test = row["mean_effect_exact_test"]
        builder.add_triplet(
            edge_id=f"r{row['rounds']}-k{row['active_low_bits']}",
            trigger=f"chacha_r{row['rounds']}:factual_xor_matching",
            mechanism="source_conditioned_ideal_code_for_output_differential",
            outcome=f"k{row['active_low_bits']}_gain_vs_random_involution",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="involution_fair_conditional_information",
            source=source,
            attrs={
                **test,
                "effect_mean": row["mean_conditional_code_gain_effect"]["mean"],
                "aggregate_maximum_effect": row["aggregate_maximum_effect"],
                "aggregate_maximum_edge": row["aggregate_maximum_edge"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", nargs="*", type=int, default=[4, 5, 20])
    parser.add_argument("--active-bits", nargs="*", type=int, default=[8, 10, 12])
    parser.add_argument("--counter-bit", type=int, default=0)
    parser.add_argument("--cosets", type=int, default=2)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--seed-base", type=int, default=160000)
    args = parser.parse_args()
    if args.cosets < 1 or args.seeds < 3 or args.routes < 3:
        raise ValueError("cosets >=1, seeds >=3 and routes >=3 required")
    if any(bits < 2 or bits > 14 for bits in args.active_bits):
        raise ValueError("active bits must be in [2, 14]")
    if any(args.counter_bit >= bits for bits in args.active_bits):
        raise ValueError("counter bit must lie inside every subspace")
    args.rounds = sorted(set(args.rounds))
    args.active_bits = sorted(set(args.active_bits))
    matching = _load_matching()
    parameters = {
        "rounds": args.rounds,
        "active_bits": args.active_bits,
        "counter_bit": args.counter_bit,
        "cosets": args.cosets,
        "seeds": args.seeds,
        "routes": args.routes,
        "shift": args.shift,
        "seed_base": args.seed_base,
        "formula": "I(C(c)_i; (C(c)_j XOR C(pair(c))_j))",
        "null": "random fixed-point-free perfect matching on identical output multiset",
    }
    results, matrices = _run(args, matching)
    _plot(results, matrices, args.figure)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_involution_conditional_code_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": "Conditional ideal code gain with matching structure and output multiset held fixed.",
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
