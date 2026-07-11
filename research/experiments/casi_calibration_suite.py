#!/usr/bin/env python3
"""Calibrate CASI null behavior, baseline sensitivity, and order dependence."""

from __future__ import annotations

import argparse
import json
import math
import platform
import sys
import zlib
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats

from arx_carry_leak.live_casi_v091.core import (
    DEEP_BASELINE_FLOOR,
    compute_amplified_score,
    compute_casi_score,
    strategy_compression,
)
from arx_carry_leak.nano_ciphers import NANO_CIPHER_REGISTRY


def _score(keys: np.ndarray, baseline_seed: int) -> dict[str, float]:
    standard = compute_casi_score(keys, baseline_seed=baseline_seed)
    amplified = compute_amplified_score(keys, baseline_seed=baseline_seed)
    return {
        "casi_standard_max": float(standard["casi"]),
        "casi_classic": float(standard["casi_classic"]),
        "casi_deep": float(standard["casi_deep"]),
        "casi_amplified": float(amplified["casi_amplified"]),
        "casi_operational_max": float(max(standard["casi"], amplified["casi"])),
        "signal_classic": float(standard["signal_classic"]),
        "signal_deep": float(standard["signal_deep"]),
        "baseline_classic": float(standard["baseline_classic"]),
        "baseline_deep_raw": float(standard["baseline_deep"]),
    }


def _describe(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": [float(value) for value in array],
        "mean": float(np.mean(array)),
        "sample_sd_ddof1": float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(np.min(array)),
        "maximum": float(np.max(array)),
        "count_above_1_5": int(np.sum(array > 1.5)),
        "count_above_2_0": int(np.sum(array > 2.0)),
    }


def _compression_record(keys: np.ndarray) -> dict[str, float]:
    raw = keys.tobytes()
    compressed = zlib.compress(raw, level=1)
    return {
        "raw_bytes": len(raw),
        "compressed_bytes": len(compressed),
        "compression_ratio": len(compressed) / len(raw),
        "strategy_compression_count": float(strategy_compression(keys)),
    }


def _cipher_keys(target: str, samples: int, rounds: int, seed: int = 42) -> np.ndarray:
    raw = NANO_CIPHER_REGISTRY[target]["gen"](samples, rounds, seed=seed)
    return np.frombuffer(raw, dtype=np.uint8).reshape(-1, 32).copy()


def _null_calibration(samples: int, seeds: int) -> dict:
    records = []
    for seed in range(seeds):
        rng = np.random.default_rng(100000 + seed)
        keys = rng.integers(0, 256, size=(samples, 32), dtype=np.uint8)
        records.append({"seed": seed, **_score(keys, 0xBA5E)})
    operational = [record["casi_operational_max"] for record in records]
    return {"records": records, "operational_summary": _describe(operational)}


def _baseline_sensitivity(keys: np.ndarray, seeds: int) -> dict:
    records = []
    for index in range(seeds):
        baseline_seed = 20000 + index * 97
        records.append({"baseline_seed": baseline_seed, **_score(keys, baseline_seed)})
    operational = [record["casi_operational_max"] for record in records]
    deep_baselines = [record["baseline_deep_raw"] for record in records]
    return {
        "records": records,
        "operational_summary": _describe(operational),
        "deep_baseline_summary": _describe(deep_baselines),
        "deep_baseline_floor": DEEP_BASELINE_FLOOR,
    }


def _permutation_sensitivity(keys: np.ndarray, permutations: int) -> dict:
    records = []
    rng = np.random.default_rng(314159)
    original = _score(keys, 0xBA5E)
    original_compression = _compression_record(keys)
    for index in range(permutations):
        permuted = keys[rng.permutation(len(keys))]
        records.append(
            {
                "permutation": index,
                **_score(permuted, 0xBA5E),
                **_compression_record(permuted),
            }
        )
    operational = [record["casi_operational_max"] for record in records]
    return {
        "original": {**original, **original_compression},
        "permuted_records": records,
        "permuted_operational_summary": _describe(operational),
        "original_minus_permuted_mean": original["casi_operational_max"]
        - float(np.mean(operational)),
    }


def _round_compression_alignment(target: str, samples: int, rounds: list[int]) -> dict:
    records = []
    for round_count in rounds:
        keys = _cipher_keys(target, samples, round_count)
        records.append(
            {
                "round": round_count,
                **_score(keys, 0xBA5E),
                **_compression_record(keys),
            }
        )
    casi = [record["casi_operational_max"] for record in records]
    ratios = [record["compression_ratio"] for record in records]
    spearman = stats.spearmanr(casi, ratios)
    return {
        "records": records,
        "spearman_casi_vs_compression_ratio": float(spearman.statistic),
        "spearman_p": float(spearman.pvalue),
        "compression_in_compute_casi_score": False,
    }


def _controlled_faults(samples: int) -> dict:
    rng = np.random.default_rng(271828)
    baseline = rng.integers(0, 256, size=(samples, 32), dtype=np.uint8)
    cases: dict[str, np.ndarray] = {"random": baseline}

    stuck_bit = baseline.copy()
    stuck_bit[:, 0] &= np.uint8(0x7F)
    cases["byte0_msb_stuck_zero"] = stuck_bit

    repeated_one_percent = baseline.copy()
    repeated_one_percent[: max(1, samples // 100)] = baseline[0]
    cases["one_percent_repeated_rows"] = repeated_one_percent

    periodic = baseline.copy()
    periodic[::16] = periodic[0]
    cases["every_16th_row_repeated"] = periodic

    records = []
    for name, keys in cases.items():
        records.append({"case": name, **_score(keys, 0xBA5E), **_compression_record(keys)})
    return {"records": records}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())["casi"]
    samples = int(config["n_samples"])
    target = str(config["target"])
    reduced_round = int(config["reduced_round"])
    full_round = int(NANO_CIPHER_REGISTRY[target]["full"])
    reduced_keys = _cipher_keys(target, samples, reduced_round)

    print("CASI null calibration", flush=True)
    null_calibration = _null_calibration(samples, int(config["null_seeds"]))
    print("CASI baseline-seed sensitivity", flush=True)
    baseline_sensitivity = _baseline_sensitivity(
        reduced_keys, int(config["baseline_seeds"])
    )
    print("CASI row-permutation sensitivity", flush=True)
    permutation_sensitivity = _permutation_sensitivity(
        reduced_keys, int(config["permutations"])
    )
    print("CASI/compression alignment", flush=True)
    round_alignment = _round_compression_alignment(
        target,
        samples,
        sorted({1, 2, reduced_round, min(reduced_round + 3, full_round), full_round}),
    )
    print("CASI controlled faults", flush=True)
    controlled_faults = _controlled_faults(samples)

    findings = [
        {
            "id": "NR-CASI-01",
            "finding": "Empirical random-input false-positive behavior is directly calibrated across independent data seeds.",
            "evidence": "null_calibration",
        },
        {
            "id": "NR-CASI-02",
            "finding": "CASI variability induced solely by the fixed random baseline seed is quantified.",
            "evidence": "baseline_sensitivity",
        },
        {
            "id": "NR-CASI-03",
            "finding": "Row-order sensitivity is quantified on an unchanged ciphertext multiset.",
            "evidence": "permutation_sensitivity",
        },
        {
            "id": "NR-CASI-04",
            "finding": "The operational CASI score is compared directly with actual zlib compressibility across rounds.",
            "evidence": "round_compression_alignment",
        },
        {
            "id": "NR-CASI-05",
            "finding": "Detection behavior is measured for three controlled output faults and a matched random baseline.",
            "evidence": "controlled_faults",
        },
    ]
    payload = {
        "schema_version": 1,
        "experiment": "casi_calibration_suite",
        "parameters": config,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "null_calibration": null_calibration,
        "baseline_sensitivity": baseline_sensitivity,
        "permutation_sensitivity": permutation_sensitivity,
        "round_compression_alignment": round_alignment,
        "controlled_faults": controlled_faults,
        "candidate_findings": findings,
        "scope_note": (
            "Calibration describes this implementation and parameterization; a score below a "
            "threshold is not a proof of cryptographic security."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
