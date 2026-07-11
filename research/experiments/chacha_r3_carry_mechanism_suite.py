#!/usr/bin/env python3
"""Carry and feed-forward interventions for the confirmed ChaCha R3 frontier."""

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

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


VARIANTS = (
    "standard",
    "no_feedforward",
    "xor_feedforward",
    "carryfree_round0",
    "carryfree_round1",
    "carryfree_round2",
    "carryfree_all_core",
)


def _chacha_intervened(
    counters: np.ndarray,
    *,
    rounds: int,
    seed: int,
    carryfree_rounds: frozenset[int] = frozenset(),
    feedforward: str = "add",
) -> np.ndarray:
    values = np.asarray(counters, dtype=np.uint32)
    rng = np.random.RandomState(seed)
    key = rng.bytes(32)
    nonce = rng.bytes(12)
    state = np.zeros((len(values), 16), dtype=np.uint32)
    state[:, :4] = np.asarray([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
    state[:, 4:12] = np.frombuffer(key, dtype="<u4")
    state[:, 12] = values
    state[:, 13:16] = np.frombuffer(nonce, dtype="<u4")
    initial = state.copy()

    def rotate_left(value: np.ndarray, bits: int) -> np.ndarray:
        return ((value << np.uint32(bits)) | (value >> np.uint32(32 - bits))).astype(np.uint32)

    def combine(left: np.ndarray, right: np.ndarray, carryfree: bool) -> np.ndarray:
        return left ^ right if carryfree else left + right

    def quarter_round(a: int, b: int, c: int, d: int, carryfree: bool) -> None:
        state[:, a] = combine(state[:, a], state[:, b], carryfree)
        state[:, d] = rotate_left(state[:, d] ^ state[:, a], 16)
        state[:, c] = combine(state[:, c], state[:, d], carryfree)
        state[:, b] = rotate_left(state[:, b] ^ state[:, c], 12)
        state[:, a] = combine(state[:, a], state[:, b], carryfree)
        state[:, d] = rotate_left(state[:, d] ^ state[:, a], 8)
        state[:, c] = combine(state[:, c], state[:, d], carryfree)
        state[:, b] = rotate_left(state[:, b] ^ state[:, c], 7)

    for round_index in range(rounds):
        carryfree = round_index in carryfree_rounds
        if round_index % 2 == 0:
            quarter_round(0, 4, 8, 12, carryfree)
            quarter_round(1, 5, 9, 13, carryfree)
            quarter_round(2, 6, 10, 14, carryfree)
            quarter_round(3, 7, 11, 15, carryfree)
        else:
            quarter_round(0, 5, 10, 15, carryfree)
            quarter_round(1, 6, 11, 12, carryfree)
            quarter_round(2, 7, 8, 13, carryfree)
            quarter_round(3, 4, 9, 14, carryfree)
    if feedforward == "add":
        state = state + initial
    elif feedforward == "xor":
        state ^= initial
    elif feedforward != "none":
        raise ValueError(f"unknown feedforward mode {feedforward}")
    return state.astype("<u4", copy=False).view(np.uint8).reshape(len(values), 64).copy()


def _variant_output(name: str, counters: np.ndarray, rounds: int, seed: int) -> np.ndarray:
    if name == "standard":
        return _chacha_intervened(counters, rounds=rounds, seed=seed)
    if name == "no_feedforward":
        return _chacha_intervened(counters, rounds=rounds, seed=seed, feedforward="none")
    if name == "xor_feedforward":
        return _chacha_intervened(counters, rounds=rounds, seed=seed, feedforward="xor")
    if name.startswith("carryfree_round"):
        round_index = int(name.removeprefix("carryfree_round"))
        return _chacha_intervened(
            counters, rounds=rounds, seed=seed, carryfree_rounds=frozenset({round_index})
        )
    if name == "carryfree_all_core":
        return _chacha_intervened(
            counters, rounds=rounds, seed=seed, carryfree_rounds=frozenset(range(rounds))
        )
    raise ValueError(f"unknown variant {name}")


def _profile(difference: np.ndarray) -> dict[str, Any]:
    n = len(difference)
    entropy_deficit = np.empty(64, dtype=float)
    for position in range(64):
        counts = np.bincount(difference[:, position], minlength=256)
        probability = counts[counts > 0] / n
        entropy_deficit[position] = 8.0 + float(np.sum(probability * np.log2(probability)))
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    ones = bits.sum(axis=0)
    probabilities = ones / n
    chi2 = ((ones - n / 2.0) ** 2 / (n / 2.0)) * 2.0
    return {
        "entropy_deficit_sum": float(entropy_deficit.sum()),
        "mean_bit_bias_chi2": float(chi2.mean()),
        "maximum_bit_bias_chi2": float(chi2.max()),
        "entropy_deficit_by_byte": entropy_deficit,
        "bit_one_probability": probabilities,
        "bit_bias_chi2": chi2,
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
    entropy_null = np.mean([control["entropy_deficit_by_byte"] for control in controls], axis=0)
    bit_null = np.mean([control["bit_bias_chi2"] for control in controls], axis=0)
    result["entropy_excess_by_byte"] = actual["entropy_deficit_by_byte"] - entropy_null
    result["bit_chi2_excess"] = actual["bit_bias_chi2"] - bit_null
    return result


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, dict[str, np.ndarray]]]:
    raw = {name: [] for name in args.variants}
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed ^ 0xCA227)
        counters = rng.integers(0, 2**32, size=args.pairs, dtype=np.uint32)
        paired_counters = counters ^ np.uint32(1 << args.counter_bit)
        for name in args.variants:
            first = _variant_output(name, counters, args.rounds, seed)
            second = _variant_output(name, paired_counters, args.rounds, seed)
            analysis = _analyse(first, second, args.routes, seed ^ sum(name.encode()))
            analysis["seed"] = seed
            raw[name].append(analysis)
    standard_entropy = [row["effects"]["entropy_deficit_sum"]["difference"] for row in raw["standard"]]
    results = []
    matrices = {}
    for name in args.variants:
        records = raw[name]
        entropy = [row["effects"]["entropy_deficit_sum"]["difference"] for row in records]
        bit_bias = [row["effects"]["mean_bit_bias_chi2"]["difference"] for row in records]
        max_bias = [row["effects"]["maximum_bit_bias_chi2"]["difference"] for row in records]
        entropy_profile = np.mean([row["entropy_excess_by_byte"] for row in records], axis=0)
        bit_profile = np.mean([row["bit_chi2_excess"] for row in records], axis=0)
        bit_probability = np.mean(
            [row["actual"]["bit_one_probability"] for row in records], axis=0
        )
        top_bits = np.argsort(bit_profile)[::-1][:16]
        result = {
            "variant": name,
            "entropy_effect": _summary(entropy),
            "entropy_exact_test": exact_sign_flip_test(entropy),
            "entropy_difference_vs_standard": exact_sign_flip_test(
                list(np.asarray(entropy) - np.asarray(standard_entropy))
            ),
            "mean_bit_bias_effect": _summary(bit_bias),
            "mean_bit_bias_exact_test": exact_sign_flip_test(bit_bias),
            "maximum_bit_bias_effect": _summary(max_bias),
            "mean_entropy_excess_by_byte": [float(value) for value in entropy_profile],
            "mean_bit_chi2_excess": [float(value) for value in bit_profile],
            "mean_actual_bit_one_probability": [float(value) for value in bit_probability],
            "top_output_bits": [
                {
                    "flat_bit": int(bit),
                    "word": int(bit // 32),
                    "bit_in_word": int(bit % 32),
                    "chi2_excess": float(bit_profile[bit]),
                    "one_probability": float(bit_probability[bit]),
                }
                for bit in top_bits
            ],
            "per_seed": [
                {
                    "seed": row["seed"],
                    "entropy_effect": row["effects"]["entropy_deficit_sum"]["difference"],
                    "entropy_route_z": row["effects"]["entropy_deficit_sum"]["route_z"],
                    "mean_bit_bias_effect": row["effects"]["mean_bit_bias_chi2"]["difference"],
                    "mean_bit_bias_route_z": row["effects"]["mean_bit_bias_chi2"]["route_z"],
                }
                for row in records
            ],
        }
        results.append(result)
        matrices[name] = {"entropy": entropy_profile, "bit": bit_profile}
    return results, matrices


def _plot(results: list[dict[str, Any]], matrices: dict[str, dict[str, np.ndarray]], output: Path) -> None:
    figure, axes = plt.subplots(len(results), 2, figsize=(12, 2.8 * len(results)), squeeze=False, layout="constrained")
    for row, result in enumerate(results):
        name = result["variant"]
        entropy_limit = max(float(np.max(np.abs(matrices[name]["entropy"]))), 1e-12)
        bit_limit = max(float(np.max(np.abs(matrices[name]["bit"]))), 1e-12)
        axes[row, 0].bar(np.arange(64), matrices[name]["entropy"])
        axes[row, 0].set_ylim(-entropy_limit * 1.05, entropy_limit * 1.05)
        axes[row, 0].set_title(f"{name}: entropy excess by output byte")
        image = axes[row, 1].imshow(
            matrices[name]["bit"].reshape(16, 32),
            cmap="coolwarm",
            vmin=-bit_limit,
            vmax=bit_limit,
            aspect="auto",
        )
        axes[row, 1].set_title(f"{name}: bit-bias chi-square excess")
        axes[row, 1].set_xlabel("bit in word")
        axes[row, 1].set_ylabel("state word")
        figure.colorbar(image, ax=axes[row, 1], shrink=0.75)
    figure.suptitle("ChaCha R3 bit15 carry/feed-forward mechanism interventions")
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=160, metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_r3_carry_mechanism_suite", parameters=parameters)
    for result in results:
        test = result["entropy_exact_test"]
        builder.add_triplet(
            edge_id=f"{result['variant']}-differential",
            trigger=f"do(chacha_r{parameters['rounds']}={result['variant']})",
            mechanism="changes_modular_addition_or_feedforward_layer",
            outcome="bit15_differential_entropy_vs_repairing",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="paired_mechanism_intervention",
            source=source,
            attrs={
                **test,
                "effect_mean": result["entropy_effect"]["mean"],
                "vs_standard": result["entropy_difference_vs_standard"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--counter-bit", type=int, default=15)
    parser.add_argument("--pairs", type=int, default=20000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=40000)
    parser.add_argument("--variants", nargs="*", default=list(VARIANTS))
    args = parser.parse_args()
    if args.pairs < 1000 or args.seeds < 3 or args.routes < 3:
        raise ValueError("pairs >= 1000, seeds >= 3 and routes >= 3 required")
    unknown = sorted(set(args.variants) - set(VARIANTS))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    if "standard" not in args.variants:
        raise ValueError("standard control is required")
    parameters = {
        "rounds": args.rounds,
        "counter_bit": args.counter_bit,
        "pairs": args.pairs,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "variants": args.variants,
        "base_counter_distribution": "uniform uint32",
    }
    results, matrices = _run(args)
    _plot(results, matrices, args.figure)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_r3_carry_mechanism_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": (
            "The suite intervenes on reduced-round arithmetic to locate the confirmed R3 differential mechanism. "
            "Carry-free variants are counterfactual algorithms, not claims about standard ChaCha20."
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
