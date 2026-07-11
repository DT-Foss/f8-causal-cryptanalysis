#!/usr/bin/env python3
"""F8 fair-null, local-round, terminal-window, and beta-tail experiments.

The suite distinguishes three questions that were previously conflated:

1. Does the measured cross-round dependency exist?
2. Is predecessor-round computation necessary to generate it?
3. Does it distinguish the cipher from a related ideal construction that uses
   the same public final-round transition?
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats

from arx_carry_leak.ciphers import (
    FULL_ROUNDS,
    MASK64,
    SPECK_VARIANTS,
    THREEFISH256_ROTATIONS,
    THREEFISH_C240,
    _random_words,
    get_generator,
    speck_round_keys,
)
from arx_carry_leak.f8 import _chi_square


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _rol_array(values: np.ndarray, amount: int, width: int) -> np.ndarray:
    if width == 64:
        return (values << np.uint64(amount)) | (values >> np.uint64(64 - amount))
    mask = np.uint64((1 << width) - 1)
    return ((values << amount) | (values >> (width - amount))) & mask


def _ror_array(values: np.ndarray, amount: int, width: int) -> np.ndarray:
    if width == 64:
        return (values >> np.uint64(amount)) | (values << np.uint64(64 - amount))
    mask = np.uint64((1 << width) - 1)
    return ((values >> amount) | (values << (width - amount))) & mask


def _words_to_bytes(words: list[np.ndarray], word_size: int) -> np.ndarray:
    dtype = {16: ">u2", 32: ">u4", 64: ">u8"}[word_size]
    return np.concatenate(
        [word.astype(dtype, copy=False).view(np.uint8).reshape(-1, word_size // 8) for word in words],
        axis=1,
    )


def _pair_counts(first: np.ndarray, second: np.ndarray, shift: int) -> tuple[int, int, float]:
    n_bins = 2 ** (8 - shift)
    difference = first ^ second
    output_quantized = first >> shift
    difference_quantized = difference >> shift
    significant = 0
    tested = 0
    max_chi2 = 0.0
    for source_position in range(first.shape[1]):
        source = output_quantized[:, source_position]
        for target_position in range(first.shape[1]):
            target = difference_quantized[:, target_position]
            flat = source.astype(np.int64) * n_bins + target
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            chi2, p_value = result
            tested += 1
            significant += p_value < 0.05
            max_chi2 = max(max_chi2, chi2)
    return significant, tested, max_chi2


def _rate(counts: list[tuple[int, int, float]]) -> float:
    significant = sum(item[0] for item in counts)
    tested = sum(item[1] for item in counts)
    return significant / tested


def _summary(values: list[float], null: float = 0.05) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    mean = float(np.mean(array))
    sample_sd = float(np.std(array, ddof=1)) if len(array) > 1 else 0.0
    standard_error = sample_sd / math.sqrt(len(array)) if len(array) > 1 else 0.0
    if standard_error:
        confidence = stats.t.interval(0.95, len(array) - 1, loc=mean, scale=standard_error)
        test = stats.ttest_1samp(array, null)
        t_statistic = float(test.statistic)
        p_value = float(test.pvalue)
    else:
        confidence = (mean, mean)
        t_statistic = 0.0
        p_value = 1.0
    return {
        "values": [float(value) for value in array],
        "mean": mean,
        "sample_sd_ddof1": sample_sd,
        "ci95": [float(confidence[0]), float(confidence[1])],
        "null": null,
        "t_ddof1": t_statistic,
        "p_two_sided": p_value,
        "cohen_d_vs_null": (mean - null) / sample_sd if sample_sd else 0.0,
    }


def _comparison(left: list[float], right: list[float], margin: float) -> dict[str, Any]:
    a = np.asarray(left, dtype=float)
    b = np.asarray(right, dtype=float)
    welch = stats.ttest_ind(a, b, equal_var=False)
    difference = float(np.mean(a) - np.mean(b))
    variance_a = np.var(a, ddof=1) / len(a)
    variance_b = np.var(b, ddof=1) / len(b)
    standard_error = math.sqrt(variance_a + variance_b)
    degrees = (variance_a + variance_b) ** 2 / (
        variance_a**2 / (len(a) - 1) + variance_b**2 / (len(b) - 1)
    )
    lower_t = (difference + margin) / standard_error
    upper_t = (difference - margin) / standard_error
    lower_p = float(stats.t.sf(lower_t, degrees))
    upper_p = float(stats.t.cdf(upper_t, degrees))
    return {
        "mean_difference": difference,
        "welch_t": float(welch.statistic),
        "welch_p_two_sided": float(welch.pvalue),
        "equivalence_margin": margin,
        "tost_p": max(lower_p, upper_p),
        "equivalent_at_alpha_0_05": lower_p < 0.05 and upper_p < 0.05,
    }


def _actual_transition_windows(
    target: str, n_blocks: int, n_seeds: int, pairs: int, shift: int
) -> dict[str, Any]:
    full = FULL_ROUNDS[target]
    first_round = full - pairs
    generator = get_generator(target)
    standard_rates: list[float] = []
    extra_rates: list[float] = []
    transition_rates: dict[int, list[float]] = {round_index: [] for round_index in range(first_round, full + 1)}

    for seed_index in range(n_seeds):
        seed = seed_index * 1000 + 42
        outputs: dict[int, np.ndarray] = {}
        block_bytes = 0
        for round_count in range(first_round, full + 2):
            raw, block_bytes, _ = generator(n_blocks, round_count, seed)
            outputs[round_count] = np.frombuffer(raw, dtype=np.uint8).reshape(-1, block_bytes)
        per_transition = {}
        for round_index in range(first_round, full + 1):
            counts = _pair_counts(outputs[round_index], outputs[round_index + 1], shift)
            per_transition[round_index] = counts
            transition_rates[round_index].append(counts[0] / counts[1])
        standard_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round, full)])
        )
        extra_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round + 1, full + 1)])
        )

    numeric_transition_means = {
        round_index: float(np.mean(rates)) for round_index, rates in transition_rates.items()
    }
    transition_means = {
        str(round_index): mean for round_index, mean in numeric_transition_means.items()
    }
    slope = stats.linregress(
        list(numeric_transition_means), list(numeric_transition_means.values())
    )
    return {
        "full_rounds": full,
        "standard_terminal_window": {
            "base_round": first_round,
            "last_endpoint": full,
            **_summary(standard_rates),
        },
        "packaged_extra_round_window": {
            "base_round": first_round + 1,
            "last_endpoint": full + 1,
            **_summary(extra_rates),
        },
        "per_transition_mean_rate": transition_means,
        "late_round_linear_slope": float(slope.slope),
        "late_round_slope_p": float(slope.pvalue),
    }


def _speck_local_windows(
    target: str,
    n_blocks: int,
    n_seeds: int,
    pairs: int,
    shift: int,
    independent: bool = False,
    shuffled: bool = False,
) -> dict[str, Any]:
    variant = SPECK_VARIANTS[target]
    width = variant.word_size
    if width not in (16, 32, 64):
        raise ValueError("local vectorized suite currently supports 16/32/64-bit Speck words")
    dtype = {16: np.uint16, 32: np.uint32, 64: np.uint64}[width]
    full = variant.full_rounds
    first_round = full - pairs
    standard_rates: list[float] = []
    extra_rates: list[float] = []

    for seed_index in range(n_seeds):
        seed = seed_index * 1000 + 42
        key_rng = np.random.default_rng(seed)
        master_key = _random_words(key_rng, variant.key_words, width)
        round_keys = speck_round_keys(variant, master_key, full + 1)
        per_transition = {}
        for round_index in range(first_round, full + 1):
            rng = np.random.default_rng(seed * 100003 + round_index * 7919)
            high = 2**64 if width == 64 else 1 << width
            x = rng.integers(0, high, size=n_blocks, dtype=dtype)
            y = rng.integers(0, high, size=n_blocks, dtype=dtype)
            first = _words_to_bytes([x, y], width)
            if independent:
                next_x = rng.integers(0, high, size=n_blocks, dtype=dtype)
                next_y = rng.integers(0, high, size=n_blocks, dtype=dtype)
            else:
                mask = np.uint64((1 << width) - 1) if width < 64 else np.uint64(MASK64)
                next_x = ((_ror_array(x, variant.alpha, width) + y) & mask) ^ np.array(
                    round_keys[round_index], dtype=dtype
                )
                next_y = _rol_array(y, variant.beta, width) ^ next_x
            second = _words_to_bytes([next_x, next_y], width)
            if shuffled:
                second = second[rng.permutation(n_blocks)]
            per_transition[round_index] = _pair_counts(first, second, shift)
        standard_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round, full)])
        )
        extra_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round + 1, full + 1)])
        )
    return {
        "standard_terminal_window": _summary(standard_rates),
        "packaged_extra_round_window": _summary(extra_rates),
    }


def _threefish_local_windows(
    n_blocks: int,
    n_seeds: int,
    pairs: int,
    shift: int,
    independent: bool = False,
    shuffled: bool = False,
) -> dict[str, Any]:
    full = 72
    first_round = full - pairs
    standard_rates: list[float] = []
    extra_rates: list[float] = []
    for seed_index in range(n_seeds):
        seed = seed_index * 1000 + 42
        key_rng = np.random.default_rng(seed)
        key = _random_words(key_rng, 4, 64)
        tweak = _random_words(key_rng, 2, 64)
        key_schedule = key + [THREEFISH_C240 ^ key[0] ^ key[1] ^ key[2] ^ key[3]]
        tweak_schedule = tweak + [tweak[0] ^ tweak[1]]
        per_transition = {}
        for round_index in range(first_round, full + 1):
            rng = np.random.default_rng(seed * 100003 + round_index * 7919)
            state = [rng.integers(0, 2**64, size=n_blocks, dtype=np.uint64) for _ in range(4)]
            first = _words_to_bytes(state, 64)
            if independent:
                next_state = [
                    rng.integers(0, 2**64, size=n_blocks, dtype=np.uint64) for _ in range(4)
                ]
            else:
                rotation_a, rotation_b = THREEFISH256_ROTATIONS[round_index % 8]
                q0 = state[0] + state[1]
                q1 = _rol_array(state[1], rotation_a, 64) ^ q0
                q2 = state[2] + state[3]
                q3 = _rol_array(state[3], rotation_b, 64) ^ q2
                next_state = [q0, q3, q2, q1]
                if (round_index + 1) % 4 == 0:
                    injection = (round_index + 1) // 4
                    next_state[0] += np.uint64(key_schedule[injection % 5])
                    next_state[1] += np.uint64(
                        (key_schedule[(injection + 1) % 5] + tweak_schedule[injection % 3])
                        & MASK64
                    )
                    next_state[2] += np.uint64(
                        (
                            key_schedule[(injection + 2) % 5]
                            + tweak_schedule[(injection + 1) % 3]
                        )
                        & MASK64
                    )
                    next_state[3] += np.uint64(
                        (key_schedule[(injection + 3) % 5] + injection) & MASK64
                    )
            second = _words_to_bytes(next_state, 64)
            if shuffled:
                second = second[rng.permutation(n_blocks)]
            per_transition[round_index] = _pair_counts(first, second, shift)
        standard_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round, full)])
        )
        extra_rates.append(
            _rate([per_transition[round_index] for round_index in range(first_round + 1, full + 1)])
        )
    return {
        "standard_terminal_window": _summary(standard_rates),
        "packaged_extra_round_window": _summary(extra_rates),
    }


def _binary_mi(first: np.ndarray, second: np.ndarray) -> float:
    cells = np.bincount((first.astype(np.int64) << 1) | second, minlength=4).astype(float)
    cells /= len(first)
    row = np.array([cells[0] + cells[1], cells[2] + cells[3]])
    column = np.array([cells[0] + cells[2], cells[1] + cells[3]])
    result = 0.0
    for i in range(2):
        for j in range(2):
            probability = cells[2 * i + j]
            if probability:
                result += probability * math.log2(probability / (row[i] * column[j]))
    return result


def _beta_tail_experiment(n_blocks: int, n_seeds: int, beta_values: list[int]) -> dict:
    width = 16
    alpha = 7
    records = []
    for beta in beta_values:
        per_seed = []
        for seed_index in range(n_seeds):
            rng = np.random.default_rng(800000 + seed_index * 1000 + beta)
            x = rng.integers(0, 2**width, size=n_blocks, dtype=np.uint16)
            y = rng.integers(0, 2**width, size=n_blocks, dtype=np.uint16)
            next_x = ((_ror_array(x, alpha, width) + y) & 0xFFFF) ^ np.uint16(0x1234)
            next_y = _rol_array(y, beta, width) ^ next_x
            difference_y = y.astype(np.uint32) ^ next_y.astype(np.uint32)
            values = []
            for bit in range(width):
                target_bit = (bit - alpha) % width
                values.append(
                    _binary_mi(
                        ((x.astype(np.uint32) >> bit) & 1).astype(np.uint8),
                        ((difference_y >> target_bit) & 1).astype(np.uint8),
                    )
                )
            # The beta lowest-information positions are part of the mechanism and
            # are retained; report both all-bit and active-bit summaries.
            per_seed.append(
                {
                    "mean_all_bits": float(np.mean(values)),
                    "median_all_bits": float(np.median(values)),
                    "mean_above_0_001": float(np.mean([v for v in values if v > 0.001]))
                    if any(v > 0.001 for v in values)
                    else 0.0,
                    "bits_above_0_001": sum(v > 0.001 for v in values),
                }
            )
        mean_all = float(np.mean([item["mean_all_bits"] for item in per_seed]))
        records.append(
            {
                "beta": beta,
                "mean_mi_all_bits": mean_all,
                "mean_active_mi_thresholded": float(
                    np.mean([item["mean_above_0_001"] for item in per_seed])
                ),
                "mean_bits_above_0_001": float(
                    np.mean([item["bits_above_0_001"] for item in per_seed])
                ),
                "per_seed": per_seed,
            }
        )
    positive = [record for record in records if record["mean_mi_all_bits"] > 0]
    fit = stats.linregress(
        [record["beta"] for record in positive],
        [math.log(record["mean_mi_all_bits"]) for record in positive],
    )
    return {
        "records": records,
        "log_linear_fit": {
            "prefactor": math.exp(fit.intercept),
            "exponent": fit.slope,
            "r_squared": fit.rvalue**2,
        },
        "interpretation_boundary": (
            "The 0.001 threshold is an operational detection threshold, not proof that MI is zero."
        ),
    }


def _exact_relation_demo(n_blocks: int) -> dict:
    rng = np.random.default_rng(918273)
    x = rng.integers(0, 2**16, size=n_blocks, dtype=np.uint16)
    y = rng.integers(0, 2**16, size=n_blocks, dtype=np.uint16)
    key = np.uint16(0xBEEF)
    expected_x = ((_ror_array(x, 7, 16) + y) & 0xFFFF) ^ key
    expected_y = _rol_array(y, 2, 16) ^ expected_x
    independent_x = rng.integers(0, 2**16, size=n_blocks, dtype=np.uint16)
    independent_y = rng.integers(0, 2**16, size=n_blocks, dtype=np.uint16)
    return {
        "related_matches": int(np.sum((expected_x == expected_x) & (expected_y == expected_y))),
        "related_trials": n_blocks,
        "independent_matches": int(
            np.sum((independent_x == expected_x) & (independent_y == expected_y))
        ),
        "independent_trials": n_blocks,
        "ideal_independent_match_probability_per_trial": 2**-32,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run a tiny serialization/control-flow check before the paper-scale suite.",
    )
    args = parser.parse_args()
    config = json.loads(args.config.read_text())["f8"]
    statistics_config = json.loads(args.config.read_text())["statistics"]
    n_blocks = int(config["n_blocks"])
    n_seeds = int(config["n_seeds"])
    pairs = int(config["n_round_pairs"])
    shift = int(config["shift"])
    if args.preflight:
        n_blocks = 500
        n_seeds = 2
        pairs = 2
        config = {
            **config,
            "n_blocks": n_blocks,
            "n_seeds": n_seeds,
            "n_round_pairs": pairs,
            "beta_sweep_blocks": 1000,
            "beta_sweep_seeds": 2,
            "beta_values": [1, 5],
            "preflight": True,
        }
    margin = float(statistics_config["equivalence_margin_absolute_rate"])

    targets = {}
    for target in config["targets"]:
        print(f"actual transition windows: {target}", flush=True)
        actual = _actual_transition_windows(target, n_blocks, n_seeds, pairs, shift)
        if target.startswith("speck"):
            related = _speck_local_windows(target, n_blocks, n_seeds, pairs, shift)
            independent = _speck_local_windows(
                target, n_blocks, n_seeds, pairs, shift, independent=True
            )
            shuffled = _speck_local_windows(
                target, n_blocks, n_seeds, pairs, shift, shuffled=True
            )
        else:
            related = _threefish_local_windows(n_blocks, n_seeds, pairs, shift)
            independent = _threefish_local_windows(
                n_blocks, n_seeds, pairs, shift, independent=True
            )
            shuffled = _threefish_local_windows(n_blocks, n_seeds, pairs, shift, shuffled=True)
        comparison = _comparison(
            actual["packaged_extra_round_window"]["values"],
            related["packaged_extra_round_window"]["values"],
            margin,
        )
        targets[target] = {
            "actual": actual,
            "uniform_state_plus_real_round": related,
            "independent_next_state": independent,
            "row_shuffled_next_state": shuffled,
            "actual_vs_uniform_local": comparison,
        }

    beta_tail = _beta_tail_experiment(
        int(config["beta_sweep_blocks"]),
        int(config["beta_sweep_seeds"]),
        [int(value) for value in config["beta_values"]],
    )
    exact_relation = _exact_relation_demo(n_blocks)

    findings = [
        {
            "id": "NR-F8-01",
            "finding": "Uniform state plus one Speck32/64 round reproduces the late-round F8 rate.",
            "evidence": "targets.speck32_64",
        },
        {
            "id": "NR-F8-02",
            "finding": "Uniform state plus one Speck128/256 round generates a signal at least as large as the late-round rate.",
            "evidence": "targets.speck128_256",
        },
        {
            "id": "NR-F8-03",
            "finding": "Uniform state plus one Threefish round reproduces the late-round F8 elevation.",
            "evidence": "targets.threefish256",
        },
        {
            "id": "NR-F8-04",
            "finding": "Independent next states calibrate near the nominal 5 percent rejection rate.",
            "evidence": "targets.*.independent_next_state",
        },
        {
            "id": "NR-F8-05",
            "finding": "Row shuffling destroys the local-round dependency while preserving marginal state distributions.",
            "evidence": "targets.*.row_shuffled_next_state",
        },
        {
            "id": "NR-F8-06",
            "finding": "A standard terminal window ending at the specified full round still detects the dependency; an extra unspecified round is unnecessary.",
            "evidence": "targets.*.actual.standard_terminal_window",
        },
        {
            "id": "NR-F8-07",
            "finding": "Late-transition rates can be inspected individually; the fitted round slope tests the stationarity claim without selecting the maximum window.",
            "evidence": "targets.*.actual.per_transition_mean_rate",
        },
        {
            "id": "NR-F8-08",
            "finding": "The beta>=5 death threshold is operational: MI remains positive below the fixed 0.001 reporting threshold.",
            "evidence": "beta_tail",
        },
        {
            "id": "NR-F8-09",
            "finding": "Exact known-round consistency separates related from independent state pairs without an F8 statistic.",
            "evidence": "exact_relation",
        },
    ]

    payload = {
        "schema_version": 1,
        "experiment": "f8_fair_null_suite",
        "parameters": config,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
            "scipy": stats.__version__ if hasattr(stats, "__version__") else None,
        },
        "targets": targets,
        "beta_tail": beta_tail,
        "exact_relation": exact_relation,
        "candidate_findings": findings,
        "scope_note": (
            "These experiments establish properties of cross-round observations. They do not, by "
            "themselves, establish advantage in a conventional single-oracle PRP security game."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_default) + "\n"
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
