#!/usr/bin/env python3
"""Decompose early-round atlas effects by packing and operation boundary."""

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

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from arx_carry_leak.atlas import (
    aes_counter_blocks,
    chacha_counter_blocks,
    exact_sign_flip_test,
    mutual_information_matrix,
)
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


TARGETS = {
    "chacha_r1": ("chacha", 1),
    "chacha_r2": ("chacha", 2),
    "chacha_r3": ("chacha", 3),
    "aes_r1": ("aes", 1),
    "aes_r2": ("aes", 2),
}


def _chacha_blocks(count: int, rounds: int, seed: int) -> np.ndarray:
    return chacha_counter_blocks(np.arange(count, dtype=np.uint32), rounds, seed)


def _phase_pairs(family: str, rounds: int, operations: int, seed: int) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    if family == "chacha":
        blocks = _chacha_blocks(operations, rounds, seed)
        first, second = blocks[:, :32], blocks[:, 32:]
        rows = blocks.reshape(-1, 32)
        return {
            "pooled_alternating_rows": (rows[:-1], rows[1:]),
            "within_block_first_to_second": (first, second),
            "between_blocks_second_to_next_first": (second[:-1], first[1:]),
        }
    blocks = aes_counter_blocks(operations * 2, rounds, seed)
    even, odd = blocks[0::2], blocks[1::2]
    rows = np.concatenate([even, odd], axis=1)
    return {
        "pooled_packed_rows_stride2": (rows[:-1], rows[1:]),
        "within_row_even_to_odd": (even, odd),
        "between_rows_odd_to_next_even": (odd[:-1], even[1:]),
        "even_lane_stride2": (even[:-1], even[1:]),
        "odd_lane_stride2": (odd[:-1], odd[1:]),
    }


def _paired_control(
    source: np.ndarray, paired_next: np.ndarray, *, shift: int, routes: int, seed: int
) -> dict[str, Any]:
    if source.shape != paired_next.shape:
        raise ValueError("phase pairs must have equal shape")
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
        "excess_maximum": float(excess.max()),
        "excess_minimum": float(excess.min()),
        "positive_edges": int(np.count_nonzero(excess > 0)),
        "negative_edges": int(np.count_nonzero(excess < 0)),
    }


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _target_run(name: str, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    family, rounds = TARGETS[name]
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for seed_index in range(args.seeds):
        seed = 42 + 1009 * seed_index
        for phase, (source, paired_next) in _phase_pairs(family, rounds, args.operations, seed).items():
            analysis = _paired_control(
                source,
                paired_next,
                shift=args.shift,
                routes=args.routes,
                seed=seed ^ 0xB0A7D ^ sum(phase.encode()),
            )
            analysis["seed"] = seed
            analysis["pairs"] = len(source)
            by_phase.setdefault(phase, []).append(analysis)
    phases = []
    matrices = {}
    for phase, records in by_phase.items():
        differences = [record["excess_mean"] for record in records]
        mean_matrix = np.mean([record["excess"] for record in records], axis=0)
        maximum_index = np.unravel_index(int(np.argmax(mean_matrix)), mean_matrix.shape)
        minimum_index = np.unravel_index(int(np.argmin(mean_matrix)), mean_matrix.shape)
        matrices[phase] = mean_matrix
        phases.append(
            {
                "phase": phase,
                "matrix_shape": list(mean_matrix.shape),
                "pairs_per_seed": records[0]["pairs"],
                "observed_mean": _summary([record["observed_mean"] for record in records]),
                "repairing_control_mean": _summary(
                    [record["control_mean_scalar"] for record in records]
                ),
                "excess_mean": _summary(differences),
                "paired_exact_test": exact_sign_flip_test(differences),
                "excess_l2": _summary([record["excess_l2"] for record in records]),
                "mean_excess_maximum": float(mean_matrix[maximum_index]),
                "mean_excess_maximum_edge": [int(value) for value in maximum_index],
                "mean_excess_minimum": float(mean_matrix[minimum_index]),
                "mean_excess_minimum_edge": [int(value) for value in minimum_index],
                "mean_positive_edges": float(np.mean([record["positive_edges"] for record in records])),
                "mean_negative_edges": float(np.mean([record["negative_edges"] for record in records])),
                "mean_excess_matrix": [[float(value) for value in row] for row in mean_matrix],
                "per_seed_scalars": [
                    {
                        key: record[key]
                        for key in (
                            "seed",
                            "pairs",
                            "observed_mean",
                            "control_mean_scalar",
                            "excess_mean",
                            "excess_l2",
                            "excess_maximum",
                            "excess_minimum",
                            "positive_edges",
                            "negative_edges",
                        )
                    }
                    for record in records
                ],
            }
        )
    return {"target": name, "family": family, "rounds": rounds, "phases": phases}, matrices


def _plot(results: list[dict[str, Any]], matrices: dict[str, dict[str, np.ndarray]], output: Path) -> None:
    panels = [(result["target"], phase["phase"]) for result in results for phase in result["phases"]]
    columns = 4
    rows = math.ceil(len(panels) / columns)
    figure, axes = plt.subplots(rows, columns, figsize=(4.1 * columns, 3.7 * rows), squeeze=False)
    limits = {
        target: max(float(np.max(np.abs(matrix))) for matrix in target_matrices.values())
        for target, target_matrices in matrices.items()
    }
    for axis, (target, phase) in zip(axes.ravel(), panels, strict=False):
        matrix = matrices[target][phase]
        image = axis.imshow(matrix, cmap="coolwarm", vmin=-limits[target], vmax=limits[target])
        axis.set_title(f"{target}\n{phase}", fontsize=9)
        axis.set_xlabel("delta byte j")
        axis.set_ylabel("source byte i")
        figure.colorbar(image, ax=axis, shrink=0.65)
    for axis in axes.ravel()[len(panels) :]:
        axis.axis("off")
    figure.suptitle("Packing and operation-boundary information decomposition")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=160, bbox_inches="tight", metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="output_boundary_intervention_suite", parameters=parameters)
    for result in results:
        for phase in result["phases"]:
            test = phase["paired_exact_test"]
            builder.add_triplet(
                edge_id=f"{result['target']}-{phase['phase']}",
                trigger=f"{result['target']}:{phase['phase']}:factual_pairing",
                mechanism="preserves_output_packing_or_operation_boundary",
                outcome="quantized_delta_information_vs_global_repairing",
                confidence=1.0 - float(test["two_sided_p"]),
                evidence_kind="paired_exact_sign_flip_across_keys",
                source=source,
                attrs={
                    **test,
                    "mean_excess": phase["excess_mean"]["mean"],
                    "mean_l2": phase["excess_l2"]["mean"],
                    "scope": "output boundary intervention; not an internal-round security claim",
                },
            )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--targets", nargs="*", default=list(TARGETS))
    args = parser.parse_args()
    if args.operations < 1000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("operations >= 1000, seeds >= 3 and routes >= 3 required")
    unknown = sorted(set(args.targets) - set(TARGETS))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    parameters = {
        "operations": args.operations,
        "seeds": args.seeds,
        "routes": args.routes,
        "shift": args.shift,
        "targets": args.targets,
    }
    results = []
    matrices = {}
    for target in args.targets:
        print(f"boundary decomposition: {target}", flush=True)
        result, target_matrices = _target_run(target, args)
        results.append(result)
        matrices[target] = target_matrices
    _plot(results, matrices, args.figure)
    payload = {
        "schema_version": 1,
        "experiment": "output_boundary_intervention_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
            "matplotlib": matplotlib.__version__,
        },
        "definitions": {
            "phase_statistic": "I(source_i >> shift; ((source_j XOR paired_next_j) >> shift))",
            "repairing_control": "globally permute paired_next while preserving source and paired_next row multisets",
            "excess": "factual phase heatmap minus mean repairing-control heatmap",
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": (
            "The suite determines which public-output packing/boundary phase carries an atlas effect. "
            "It does not identify an internal cipher mechanism without a subsequent state/input intervention."
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
