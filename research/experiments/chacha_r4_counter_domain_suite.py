#!/usr/bin/env python3
"""Counter-domain interventions for the historical ChaCha R4 differential."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


DOMAINS = (
    "low_range",
    "low_range_shuffled",
    "random_offset_range",
    "gray_low_range",
    "bit_reversed_low_range",
    "affine_full_range",
    "fixed_high16_random_low16",
    "fixed_low16_random_high16",
    "fixed_high8_random_low24",
    "fixed_low8_random_high24",
    "uniform_u32",
)


def _bit_reverse32(values: np.ndarray) -> np.ndarray:
    result = values.astype(np.uint32, copy=True)
    result = ((result >> 1) & 0x55555555) | ((result & 0x55555555) << 1)
    result = ((result >> 2) & 0x33333333) | ((result & 0x33333333) << 2)
    result = ((result >> 4) & 0x0F0F0F0F) | ((result & 0x0F0F0F0F) << 4)
    result = ((result >> 8) & 0x00FF00FF) | ((result & 0x00FF00FF) << 8)
    return ((result >> 16) | (result << 16)).astype(np.uint32)


def _domain(name: str, count: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed ^ 0xD04A1)
    base = np.arange(count, dtype=np.uint32)
    if name == "low_range":
        return base
    if name == "low_range_shuffled":
        return rng.permutation(base)
    if name == "random_offset_range":
        offset = rng.integers(0, 2**32, dtype=np.uint32)
        return (base + offset).astype(np.uint32)
    if name == "gray_low_range":
        return base ^ (base >> np.uint32(1))
    if name == "bit_reversed_low_range":
        return _bit_reverse32(base)
    if name == "affine_full_range":
        offset = rng.integers(0, 2**32, dtype=np.uint32)
        return (base * np.uint32(0x9E3779B1) + offset).astype(np.uint32)
    if name == "fixed_high16_random_low16":
        high = rng.integers(0, 2**16, dtype=np.uint32) << np.uint32(16)
        return high | rng.integers(0, 2**16, size=count, dtype=np.uint32)
    if name == "fixed_low16_random_high16":
        low = rng.integers(0, 2**16, dtype=np.uint32)
        return low | (rng.integers(0, 2**16, size=count, dtype=np.uint32) << np.uint32(16))
    if name == "fixed_high8_random_low24":
        high = rng.integers(0, 2**8, dtype=np.uint32) << np.uint32(24)
        return high | rng.integers(0, 2**24, size=count, dtype=np.uint32)
    if name == "fixed_low8_random_high24":
        low = rng.integers(0, 2**8, dtype=np.uint32)
        return low | (rng.integers(0, 2**24, size=count, dtype=np.uint32) << np.uint32(8))
    if name == "uniform_u32":
        return rng.integers(0, 2**32, size=count, dtype=np.uint32)
    raise ValueError(f"unknown domain {name}")


def _counter_profile(counters: np.ndarray) -> dict[str, Any]:
    bits = np.unpackbits(counters.astype("<u4", copy=False).view(np.uint8).reshape(-1, 4), axis=1, bitorder="little")
    probabilities = bits.mean(axis=0)
    entropy = []
    for probability in probabilities:
        if probability in (0.0, 1.0):
            entropy.append(0.0)
        else:
            entropy.append(float(-probability * np.log2(probability) - (1 - probability) * np.log2(1 - probability)))
    return {
        "unique": int(len(np.unique(counters))),
        "ordered_sha256": hashlib.sha256(counters.tobytes()).hexdigest(),
        "multiset_sha256": hashlib.sha256(np.sort(counters).tobytes()).hexdigest(),
        "bit_one_probability": [float(value) for value in probabilities],
        "bit_entropy": entropy,
        "active_bits_entropy_gt_0_1": int(np.count_nonzero(np.asarray(entropy) > 0.1)),
    }


def _profile(difference: np.ndarray) -> dict[str, Any]:
    n = len(difference)
    byte_deficit = np.empty(64)
    for position in range(64):
        counts = np.bincount(difference[:, position], minlength=256)
        probability = counts[counts > 0] / n
        byte_deficit[position] = 8.0 + float(np.sum(probability * np.log2(probability)))
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    ones = bits.sum(axis=0)
    bit_probability = ones / n
    bit_chi2 = ((ones - n / 2.0) ** 2 / (n / 2.0)) * 2.0
    return {
        "entropy_deficit_sum": float(byte_deficit.sum()),
        "mean_bit_bias_chi2": float(bit_chi2.mean()),
        "maximum_bit_bias_chi2": float(bit_chi2.max()),
        "byte_entropy_deficit": byte_deficit,
        "bit_one_probability": bit_probability,
        "bit_bias_chi2": bit_chi2,
    }


def _analyse(first: np.ndarray, second: np.ndarray, routes: int, seed: int) -> dict[str, Any]:
    actual = _profile(first ^ second)
    rng = np.random.default_rng(seed)
    controls = [_profile(first ^ second[rng.permutation(len(second))]) for _ in range(routes)]
    result: dict[str, Any] = {"actual": actual, "effects": {}}
    for metric in ("entropy_deficit_sum", "mean_bit_bias_chi2", "maximum_bit_bias_chi2"):
        null = np.asarray([control[metric] for control in controls])
        result["effects"][metric] = {
            "difference": float(actual[metric] - null.mean()),
            "control_mean": float(null.mean()),
            "control_sd_ddof1": float(null.std(ddof=1)),
            "route_z": float((actual[metric] - null.mean()) / max(null.std(ddof=1), 1e-15)),
        }
    result["byte_entropy_excess"] = actual["byte_entropy_deficit"] - np.mean(
        [control["byte_entropy_deficit"] for control in controls], axis=0
    )
    result["bit_chi2_excess"] = actual["bit_bias_chi2"] - np.mean(
        [control["bit_bias_chi2"] for control in controls], axis=0
    )
    return result


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace) -> list[dict[str, Any]]:
    raw = {name: [] for name in args.domains}
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        for name in args.domains:
            counters = _domain(name, args.pairs, seed)
            first = chacha_counter_blocks(counters, args.rounds, seed)
            second = chacha_counter_blocks(
                counters ^ np.uint32(1 << args.counter_bit), args.rounds, seed
            )
            analysis = _analyse(first, second, args.routes, seed ^ sum(name.encode()))
            analysis["seed"] = seed
            analysis["counter_profile"] = _counter_profile(counters)
            raw[name].append(analysis)
        print(f"counter-domain seed={seed}", flush=True)
    uniform_entropy = [
        row["effects"]["entropy_deficit_sum"]["difference"] for row in raw["uniform_u32"]
    ]
    results = []
    for name in args.domains:
        records = raw[name]
        entropy = [row["effects"]["entropy_deficit_sum"]["difference"] for row in records]
        bit_bias = [row["effects"]["mean_bit_bias_chi2"]["difference"] for row in records]
        max_bias = [row["effects"]["maximum_bit_bias_chi2"]["difference"] for row in records]
        byte_profile = np.mean([row["byte_entropy_excess"] for row in records], axis=0)
        bit_profile = np.mean([row["bit_chi2_excess"] for row in records], axis=0)
        top = np.argsort(bit_profile)[::-1][:16]
        results.append(
            {
                "domain": name,
                "entropy_effect": _summary(entropy),
                "entropy_exact_test": exact_sign_flip_test(entropy),
                "entropy_difference_vs_uniform": exact_sign_flip_test(
                    list(np.asarray(entropy) - np.asarray(uniform_entropy))
                ),
                "mean_bit_bias_effect": _summary(bit_bias),
                "mean_bit_bias_exact_test": exact_sign_flip_test(bit_bias),
                "maximum_bit_bias_effect": _summary(max_bias),
                "mean_byte_entropy_excess": [float(value) for value in byte_profile],
                "mean_bit_chi2_excess": [float(value) for value in bit_profile],
                "top_output_bits": [
                    {
                        "flat_bit": int(bit),
                        "word": int(bit // 32),
                        "bit_in_word": int(bit % 32),
                        "chi2_excess": float(bit_profile[bit]),
                        "one_probability": float(
                            np.mean([row["actual"]["bit_one_probability"][bit] for row in records])
                        ),
                    }
                    for bit in top
                ],
                "counter_profiles": [row["counter_profile"] for row in records],
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


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_r4_counter_domain_suite", parameters=parameters)
    for result in results:
        test = result["entropy_exact_test"]
        builder.add_triplet(
            edge_id=result["domain"],
            trigger=f"do(counter_domain={result['domain']})",
            mechanism="conditions_base_counter_subspace",
            outcome="r4_chosen_difference_entropy_vs_repairing",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="counter_domain_intervention",
            source=source,
            attrs={
                **test,
                "effect_mean": result["entropy_effect"]["mean"],
                "vs_uniform": result["entropy_difference_vs_uniform"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--counter-bit", type=int, default=0)
    parser.add_argument("--pairs", type=int, default=30000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=70000)
    parser.add_argument("--domains", nargs="*", default=list(DOMAINS))
    args = parser.parse_args()
    if args.pairs < 1000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("pairs >= 1000, seeds >= 3 and routes >= 3 required")
    unknown = sorted(set(args.domains) - set(DOMAINS))
    if unknown:
        raise ValueError(f"unknown domains: {', '.join(unknown)}")
    if "uniform_u32" not in args.domains:
        raise ValueError("uniform_u32 control is required")
    parameters = {
        "rounds": args.rounds,
        "counter_bit": args.counter_bit,
        "pairs": args.pairs,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "domains": args.domains,
    }
    results = _run(args)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_r4_counter_domain_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "scope_note": (
            "Chosen-input reduced-round domain intervention. It distinguishes base-counter subspace effects "
            "from a domain-independent differential and is not a statement about standard ChaCha20."
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
