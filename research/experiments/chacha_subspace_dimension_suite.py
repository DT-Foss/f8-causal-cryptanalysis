#!/usr/bin/env python3
"""Map ChaCha chosen-difference strength versus counter-subspace dimension."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path
from typing import Any

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


def _load_helpers() -> Any:
    path = Path(__file__).with_name("chacha_r4_counter_domain_suite.py")
    spec = importlib.util.spec_from_file_location("chacha_domain_helpers_for_dimension", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load counter-domain helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _unique_values(bits: int, count: int, rng: np.random.Generator) -> np.ndarray:
    space = 1 << bits
    if count > space:
        raise ValueError(f"cannot draw {count} unique values from {bits}-bit subspace")
    if bits <= 20:
        return rng.choice(space, size=count, replace=False).astype(np.uint32)
    values: list[int] = []
    seen: set[int] = set()
    mask = (1 << bits) - 1
    while len(values) < count:
        batch = rng.integers(0, 2**32, size=count - len(values), dtype=np.uint32)
        for value in batch:
            integer = int(value) & mask
            if integer not in seen:
                seen.add(integer)
                values.append(integer)
    return np.asarray(values, dtype=np.uint32)


def _subspace(orientation: str, bits: int, count: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed ^ (bits << 8) ^ sum(orientation.encode()))
    values = _unique_values(bits, count, rng)
    if bits == 32:
        return values
    if orientation == "low":
        fixed_high = rng.integers(0, 1 << (32 - bits), dtype=np.uint32) << np.uint32(bits)
        return fixed_high | values
    if orientation == "high":
        fixed_low = rng.integers(0, 1 << (32 - bits), dtype=np.uint32)
        return fixed_low | (values << np.uint32(32 - bits))
    raise ValueError(f"unknown orientation {orientation}")


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace, helpers: Any) -> list[dict[str, Any]]:
    configs = [(orientation, bits) for orientation in args.orientations for bits in args.active_bits]
    raw = {config: [] for config in configs}
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        for orientation, bits in configs:
            counters = _subspace(orientation, bits, args.pairs, seed)
            first = chacha_counter_blocks(counters, args.rounds, seed)
            second = chacha_counter_blocks(
                counters ^ np.uint32(1 << args.counter_bit), args.rounds, seed
            )
            analysis = helpers._analyse(
                first, second, args.routes, seed ^ (bits << 16) ^ sum(orientation.encode())
            )
            analysis["seed"] = seed
            analysis["counter_profile"] = helpers._counter_profile(counters)
            raw[orientation, bits].append(analysis)
        print(f"subspace-dimension seed={seed}", flush=True)
    full = {
        orientation: [
            row["effects"]["entropy_deficit_sum"]["difference"]
            for row in raw[orientation, max(args.active_bits)]
        ]
        for orientation in args.orientations
    }
    results = []
    for orientation, bits in configs:
        records = raw[orientation, bits]
        entropy = [row["effects"]["entropy_deficit_sum"]["difference"] for row in records]
        bit_bias = [row["effects"]["mean_bit_bias_chi2"]["difference"] for row in records]
        results.append(
            {
                "orientation": orientation,
                "active_bits": bits,
                "entropy_effect": _summary(entropy),
                "entropy_exact_test": exact_sign_flip_test(entropy),
                "entropy_difference_vs_max_dimension": exact_sign_flip_test(
                    list(np.asarray(entropy) - np.asarray(full[orientation]))
                ),
                "mean_bit_bias_effect": _summary(bit_bias),
                "mean_bit_bias_exact_test": exact_sign_flip_test(bit_bias),
                "active_counter_bits": [
                    row["counter_profile"]["active_bits_entropy_gt_0_1"] for row in records
                ],
                "unique_counters": [row["counter_profile"]["unique"] for row in records],
                "per_seed": [
                    {
                        "seed": row["seed"],
                        "entropy_effect": row["effects"]["entropy_deficit_sum"]["difference"],
                        "entropy_route_z": row["effects"]["entropy_deficit_sum"]["route_z"],
                        "mean_bit_bias_effect": row["effects"]["mean_bit_bias_chi2"]["difference"],
                    }
                    for row in records
                ],
            }
        )
    return results


def _plot(results: list[dict[str, Any]], output: Path, rounds: int) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(12, 4.8), layout="constrained")
    for orientation in sorted({row["orientation"] for row in results}):
        rows = sorted(
            [row for row in results if row["orientation"] == orientation],
            key=lambda row: row["active_bits"],
        )
        x = [row["active_bits"] for row in rows]
        entropy = [row["entropy_effect"]["mean"] for row in rows]
        entropy_sd = [row["entropy_effect"]["sample_sd_ddof1"] for row in rows]
        bias = [row["mean_bit_bias_effect"]["mean"] for row in rows]
        bias_sd = [row["mean_bit_bias_effect"]["sample_sd_ddof1"] for row in rows]
        axes[0].errorbar(x, entropy, yerr=entropy_sd, marker="o", label=orientation)
        axes[1].errorbar(x, bias, yerr=bias_sd, marker="o", label=orientation)
    axes[0].set_title(f"ChaCha R{rounds} differential entropy vs subspace dimension")
    axes[1].set_title(f"ChaCha R{rounds} bit bias vs subspace dimension")
    for axis in axes:
        axis.set_xlabel("active counter bits")
        axis.axhline(0, color="black", linewidth=0.8)
        axis.grid(alpha=0.25)
        axis.legend()
    axes[0].set_ylabel("entropy deficit excess")
    axes[1].set_ylabel("mean bit chi-square excess")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=170, metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_subspace_dimension_suite", parameters=parameters)
    for row in results:
        test = row["entropy_exact_test"]
        builder.add_triplet(
            edge_id=f"{row['orientation']}-{row['active_bits']}",
            trigger=f"do(counter_subspace={row['orientation']}_{row['active_bits']}bit)",
            mechanism="changes_chosen_input_dimension_and_bit_location",
            outcome=f"r{parameters['rounds']}_differential_entropy",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="subspace_dimension_intervention",
            source=source,
            attrs={
                **test,
                "effect_mean": row["entropy_effect"]["mean"],
                "vs_max_dimension": row["entropy_difference_vs_max_dimension"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--counter-bit", type=int, default=0)
    parser.add_argument("--pairs", type=int, default=16000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=80000)
    parser.add_argument("--active-bits", nargs="*", type=int, default=[14, 16, 18, 20, 22, 24, 26, 28, 30, 32])
    parser.add_argument("--orientations", nargs="*", default=["low", "high"])
    args = parser.parse_args()
    if args.pairs < 64 or args.seeds < 3 or args.routes < 3:
        raise ValueError("pairs >= 64, seeds >= 3 and routes >= 3 required")
    if any(bits < 1 or bits > 32 for bits in args.active_bits):
        raise ValueError("active bits must be in [1, 32]")
    if set(args.orientations) - {"low", "high"}:
        raise ValueError("orientations must be low/high")
    args.active_bits = sorted(set(args.active_bits))
    if max(args.active_bits) != 32:
        raise ValueError("32-bit maximum-dimension control is required")
    helpers = _load_helpers()
    parameters = {
        "rounds": args.rounds,
        "counter_bit": args.counter_bit,
        "pairs": args.pairs,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "active_bits": args.active_bits,
        "orientations": args.orientations,
        "sampling": "unique values uniformly sampled without replacement inside each affine subspace",
    }
    results = _run(args, helpers)
    _plot(results, args.figure, args.rounds)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_subspace_dimension_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": "Reduced-round chosen-subspace dimension map with disjoint key schedule.",
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
