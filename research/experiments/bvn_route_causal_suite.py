#!/usr/bin/env python3
"""Balanced BvN-route causal controls for F8 and CASI.

The route ensemble preserves every observed row exactly.  For F8 it destroys
only the true R-to-R+1 block pairing; for CASI it destroys only row order.
This is an intervention/control experiment, not a cipher transformation and
not a cryptanalytic attack.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.ciphers import FULL_ROUNDS, get_generator
from arx_carry_leak.f8 import _chi_square
from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score
from arx_carry_leak.nano_ciphers import NANO_CIPHER_REGISTRY


def _f8_rate(first: np.ndarray, second: np.ndarray, shift: int, alpha: float) -> float:
    n_bins = 2 ** (8 - shift)
    difference = first ^ second
    source = first >> shift
    delta = difference >> shift
    significant = 0
    tested = 0
    for source_position in range(first.shape[1]):
        for target_position in range(first.shape[1]):
            flat = source[:, source_position].astype(np.int64) * n_bins + delta[:, target_position]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            _, p_value = result
            tested += 1
            significant += p_value < alpha
    return significant / max(tested, 1)


def _operational_casi(rows: np.ndarray, baseline_seed: int) -> float:
    standard = compute_casi_score(rows, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(rows, baseline_seed=baseline_seed)
    return float(max(standard["casi"], amplified["casi"]))


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": [float(value) for value in array],
        "mean": float(np.mean(array)),
        "sample_sd_ddof1": float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(np.min(array)),
        "maximum": float(np.max(array)),
    }


def _aggregate_route_test(
    actual: list[float], route_null_by_seed: list[list[float]], seed: int
) -> dict[str, Any]:
    """Paired randomization distribution of the cross-seed mean null rate."""
    rng = np.random.default_rng(seed)
    null = np.asarray(route_null_by_seed, dtype=float)
    draws = 20_000
    route_indices = rng.integers(null.shape[1], size=(draws, null.shape[0]))
    selected = null[np.arange(null.shape[0])[None, :], route_indices]
    null_means = np.mean(selected, axis=1)
    actual_mean = float(np.mean(actual))
    return {
        "actual_mean": actual_mean,
        "route_null_mean": float(np.mean(null_means)),
        "route_null_sd": float(np.std(null_means, ddof=1)),
        "resamples": draws,
        "empirical_upper_tail_p": float((1 + np.sum(null_means >= actual_mean)) / (1 + draws)),
        "empirical_lower_tail_p": float((1 + np.sum(null_means <= actual_mean)) / (1 + draws)),
        "empirical_two_sided_p": float(
            min(
                1.0,
                2
                * min(
                    (1 + np.sum(null_means >= actual_mean)) / (1 + draws),
                    (1 + np.sum(null_means <= actual_mean)) / (1 + draws),
                ),
            )
        ),
    }


def _f8_target(target: str, config: dict[str, Any]) -> dict[str, Any]:
    generator = get_generator(target)
    full_rounds = FULL_ROUNDS[target]
    seeds = int(config["n_seeds"])
    routes_per_seed = int(config["routes_per_seed"])
    actual_rates, null_rates, null_by_seed, per_seed = [], [], [], []
    for seed_index in range(seeds):
        seed = 42 + seed_index * 1000
        raw_r, block_bytes, _ = generator(int(config["n_blocks"]), full_rounds, seed)
        raw_r1, next_block_bytes, _ = generator(int(config["n_blocks"]), full_rounds + 1, seed)
        if block_bytes != next_block_bytes:
            raise RuntimeError("round pair changed block size")
        first = np.frombuffer(raw_r, dtype=np.uint8).reshape(-1, block_bytes)
        second = np.frombuffer(raw_r1, dtype=np.uint8).reshape(-1, block_bytes)
        actual = _f8_rate(first, second, int(config["shift"]), float(config["alpha"]))
        routes = route_ensemble(len(second), routes_per_seed, 0xB0A000 + seed)
        route_check = verify_routes(routes)
        route_values = [_f8_rate(first, second[route], int(config["shift"]), float(config["alpha"])) for route in routes]
        actual_rates.append(actual)
        null_rates.extend(route_values)
        null_by_seed.append(route_values)
        per_seed.append(
            {
                "seed": seed,
                "actual_rate": actual,
                "route_null": _summary(route_values),
                "empirical_upper_tail_p": (1 + sum(value >= actual for value in route_values)) / (1 + len(route_values)),
                "route_check": route_check,
            }
        )
    return {
        "target": target,
        "full_rounds": full_rounds,
        "actual": _summary(actual_rates),
        "route_null_pooled": _summary(null_rates),
        "causal_gap_actual_minus_route_null": float(np.mean(actual_rates) - np.mean(null_rates)),
        "aggregate_route_randomization_test": _aggregate_route_test(
            actual_rates, null_by_seed, 0xCA05E + full_rounds
        ),
        "per_seed": per_seed,
    }


def _casi_target(config: dict[str, Any]) -> dict[str, Any]:
    target = str(config["target"])
    raw = NANO_CIPHER_REGISTRY[target]["gen"](int(config["samples"]), int(config["rounds"]), seed=42)
    rows = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 32).copy()
    actual = _operational_casi(rows, 0xCA510)
    routes = route_ensemble(len(rows), int(config["routes"]), 0xCA510)
    null_values = [_operational_casi(rows[route], 0xCA510) for route in routes]
    return {
        "target": target,
        "rounds": int(config["rounds"]),
        "rows": int(len(rows)),
        "actual_operational_casi": actual,
        "route_order_null": _summary(null_values),
        "actual_minus_route_null_mean": float(actual - np.mean(null_values)),
        "route_check": verify_routes(routes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    f8_results = []
    for target in config["f8"]["targets"]:
        print(f"F8 route causal control: {target}", flush=True)
        f8_results.append(_f8_target(str(target), config["f8"]))
    print("CASI route-order control", flush=True)
    casi_result = _casi_target(config["casi"])
    payload = {
        "schema_version": 1,
        "experiment": "bvn_route_causal_suite",
        "parameters": config,
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": np.__version__},
        "f8": f8_results,
        "casi": casi_result,
        "scope_note": (
            "Route nulls preserve output rows exactly and break only selected pairing/order relations. "
            "F8 remains a known-key cross-round distinguisher; no row in this result is key recovery or a PQC security break."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
