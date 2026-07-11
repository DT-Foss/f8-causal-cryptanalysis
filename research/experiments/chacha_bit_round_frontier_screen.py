#!/usr/bin/env python3
"""Discovery screen for all ChaCha counter bits across a round frontier."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import zlib
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


METRICS = (
    "entropy_deficit_sum",
    "mean_reduced_byte_chi2",
    "mean_bit_bias_chi2",
    "mean_adjacent_quantized_mi",
    "maximum_adjacent_quantized_mi",
    "zlib_savings",
)


def _entropy(values: np.ndarray, bins: int) -> float:
    counts = np.bincount(values, minlength=bins)
    probabilities = counts[counts > 0] / len(values)
    return -float(np.sum(probabilities * np.log2(probabilities)))


def _mi(first: np.ndarray, second: np.ndarray, bins: int) -> float:
    counts = np.bincount(
        first.astype(np.int64) * bins + second,
        minlength=bins * bins,
    ).reshape(bins, bins)
    joint = counts / counts.sum()
    independent = joint.sum(axis=1, keepdims=True) @ joint.sum(axis=0, keepdims=True)
    valid = joint > 0
    return float(np.sum(joint[valid] * np.log2(joint[valid] / independent[valid])))


def _metrics(difference: np.ndarray, shift: int, *, skip_zlib: bool = False) -> dict[str, float]:
    n = len(difference)
    entropy_deficit = 0.0
    byte_chi2 = []
    expected_byte = n / 256.0
    for position in range(64):
        column = difference[:, position]
        entropy_deficit += 8.0 - _entropy(column, 256)
        counts = np.bincount(column, minlength=256)
        byte_chi2.append(float(np.sum((counts - expected_byte) ** 2 / expected_byte) / 255.0))
    bits = np.unpackbits(difference, axis=1)
    ones = bits.sum(axis=0)
    bit_chi2 = ((ones - n / 2.0) ** 2 / (n / 2.0)) * 2.0
    quantized = difference >> shift
    bins = 2 ** (8 - shift)
    adjacent = [_mi(quantized[:, index], quantized[:, index + 1], bins) for index in range(63)]
    if skip_zlib:
        zlib_savings = 0.0
    else:
        raw = difference.tobytes()
        compressed = zlib.compress(raw, level=9)
        zlib_savings = 1.0 - len(compressed) / len(raw)
    return {
        "entropy_deficit_sum": entropy_deficit,
        "mean_reduced_byte_chi2": float(np.mean(byte_chi2)),
        "mean_bit_bias_chi2": float(np.mean(bit_chi2)),
        "mean_adjacent_quantized_mi": float(np.mean(adjacent)),
        "maximum_adjacent_quantized_mi": float(np.max(adjacent)),
        "zlib_savings": zlib_savings,
    }


def _analyse_pair(
    first: np.ndarray,
    second: np.ndarray,
    *,
    shift: int,
    routes: int,
    seed: int,
    skip_zlib: bool = False,
) -> dict[str, Any]:
    actual = _metrics(first ^ second, shift, skip_zlib=skip_zlib)
    rng = np.random.default_rng(seed)
    controls = [
        _metrics(first ^ second[rng.permutation(len(second))], shift, skip_zlib=skip_zlib)
        for _ in range(routes)
    ]
    result: dict[str, Any] = {"actual": actual, "controls": controls, "effects": {}}
    for metric in METRICS:
        values = np.asarray([control[metric] for control in controls])
        control_sd = float(values.std(ddof=1))
        difference_value = float(actual[metric] - values.mean())
        result["effects"][metric] = {
            "difference": difference_value,
            "control_mean": float(values.mean()),
            "control_sd_ddof1": control_sd,
            "control_degenerate": control_sd <= 1e-12,
            "route_z": 0.0 if control_sd <= 1e-12 else difference_value / control_sd,
        }
    return result


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _bh_adjust(rows: list[dict[str, Any]], key: str) -> None:
    order = sorted(range(len(rows)), key=lambda index: rows[index][key])
    adjusted = 1.0
    for reverse_rank, index in enumerate(reversed(order), start=1):
        rank = len(rows) - reverse_rank + 1
        adjusted = min(adjusted, rows[index][key] * len(rows) / rank)
        rows[index][f"{key}_bh_q"] = float(adjusted)


def _run(args: argparse.Namespace) -> list[dict[str, Any]]:
    raw: dict[tuple[int, int], list[dict[str, Any]]] = {
        (rounds, bit): [] for rounds in args.rounds for bit in args.bits
    }
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed ^ 0xD1FF)
        values: list[int] = []
        seen: set[int] = set()
        while len(values) < args.pairs:
            batch = rng.integers(0, 2**32, size=args.pairs - len(values), dtype=np.uint32)
            for value in batch:
                integer = int(value)
                if integer not in seen:
                    seen.add(integer)
                    values.append(integer)
        counters = np.asarray(values, dtype=np.uint32)
        for rounds in args.rounds:
            print(f"screen seed={seed} rounds={rounds}", flush=True)
            first = chacha_counter_blocks(counters, rounds, seed)
            for bit in args.bits:
                paired = chacha_counter_blocks(counters ^ np.uint32(1 << bit), rounds, seed)
                analysis = _analyse_pair(
                    first,
                    paired,
                    shift=args.shift,
                    routes=args.routes,
                    seed=seed ^ (rounds << 16) ^ bit,
                    skip_zlib=args.skip_zlib,
                )
                analysis["seed"] = seed
                raw[rounds, bit].append(analysis)
    results = []
    for rounds in args.rounds:
        for bit in args.bits:
            records = raw[rounds, bit]
            metrics = {}
            maximum_abs_route_z = 0.0
            for metric in METRICS:
                differences = [record["effects"][metric]["difference"] for record in records]
                route_z = [record["effects"][metric]["route_z"] for record in records]
                test = exact_sign_flip_test(differences)
                metrics[metric] = {
                    "effect": _summary(differences),
                    "actual": _summary([record["actual"][metric] for record in records]),
                    "route_z": _summary(route_z),
                    "exact_sign_flip": test,
                }
                maximum_abs_route_z = max(maximum_abs_route_z, abs(float(np.mean(route_z))))
            results.append(
                {
                    "rounds": rounds,
                    "counter_bit": bit,
                    "metrics": metrics,
                    "maximum_absolute_mean_route_z": maximum_abs_route_z,
                    "all_entropy_effects_positive": all(
                        record["effects"]["entropy_deficit_sum"]["difference"] > 0 for record in records
                    ),
                }
            )
    for metric in METRICS:
        key = f"{metric}_p"
        for row in results:
            row[key] = row["metrics"][metric]["exact_sign_flip"]["two_sided_p"]
        _bh_adjust(results, key)
    return results


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_bit_round_frontier_screen", parameters=parameters)
    for row in results:
        entropy = row["metrics"]["entropy_deficit_sum"]
        builder.add_triplet(
            edge_id=f"r{row['rounds']}-bit{row['counter_bit']}",
            trigger=f"chacha_r{row['rounds']}:counter_xor_bit_{row['counter_bit']}",
            mechanism="chosen_counter_difference_propagation",
            outcome="output_differential_entropy_vs_repairing",
            confidence=1.0 - float(entropy["exact_sign_flip"]["two_sided_p"]),
            evidence_kind="discovery_screen_paired_keys",
            source=source,
            attrs={
                "effect_mean": entropy["effect"]["mean"],
                "route_z_mean": entropy["route_z"]["mean"],
                "screen_only": True,
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--seed-base", type=int, default=42)
    parser.add_argument(
        "--skip-zlib",
        action="store_true",
        help="record zlib as a disabled degenerate metric after a prior no-gain gate",
    )
    parser.add_argument("--rounds", nargs="*", type=int, default=list(range(2, 9)))
    parser.add_argument("--bits", nargs="*", type=int, default=list(range(32)))
    args = parser.parse_args()
    if args.pairs < 1000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("pairs >= 1000, seeds >= 3 and routes >= 3 required")
    if any(rounds < 1 or rounds > 20 for rounds in args.rounds):
        raise ValueError("rounds must be in [1, 20]")
    if any(bit < 0 or bit > 31 for bit in args.bits):
        raise ValueError("bits must be in [0, 31]")
    args.rounds = list(dict.fromkeys(args.rounds))
    args.bits = list(dict.fromkeys(args.bits))
    parameters = {
        "pairs": args.pairs,
        "seeds": args.seeds,
        "routes": args.routes,
        "shift": args.shift,
        "rounds": args.rounds,
        "counter_bits": args.bits,
        "seed_base": args.seed_base,
        "zlib_enabled": not args.skip_zlib,
        "base_counter_distribution": "uniform uint32 without collision per seed",
    }
    results = _run(args)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_bit_round_frontier_screen",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "metrics": list(METRICS),
        "results": results,
        "scope_note": (
            "This is a discovery screen. Configurations require an independent 10-seed confirmation before "
            "interpretation. It measures a chosen-input reduced-round differential, not standard ChaCha20 security."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(results, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
