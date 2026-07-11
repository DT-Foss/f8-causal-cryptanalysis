#!/usr/bin/env python3
"""Fair perfect-matching null for closed ChaCha counter subspaces."""

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


def _load_profile() -> Any:
    path = Path(__file__).with_name("chacha_r4_counter_domain_suite.py")
    spec = importlib.util.spec_from_file_location("chacha_domain_profile_for_matching", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load differential profile helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _perfect_matching(size: int, rng: np.random.Generator) -> np.ndarray:
    if size % 2:
        raise ValueError("perfect matching requires even size")
    order = rng.permutation(size)
    mapping = np.empty(size, dtype=np.int64)
    left, right = order[0::2], order[1::2]
    mapping[left] = right
    mapping[right] = left
    return mapping


def _coset_counters(active_bits: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed ^ (active_bits << 12))
    values = np.arange(1 << active_bits, dtype=np.uint32)
    if active_bits == 32:
        raise ValueError("full 32-bit coset cannot be enumerated")
    fixed_high = rng.integers(0, 1 << (32 - active_bits), dtype=np.uint32) << np.uint32(active_bits)
    return fixed_high | values


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _analyse_outputs(
    outputs: np.ndarray,
    *,
    counter_bit: int,
    routes: int,
    seed: int,
    profile_module: Any,
) -> dict[str, Any]:
    factual_mapping = np.arange(len(outputs), dtype=np.int64) ^ (1 << counter_bit)
    factual = profile_module._profile(outputs ^ outputs[factual_mapping])
    rng = np.random.default_rng(seed)
    controls = []
    route_checks = []
    for _ in range(routes):
        mapping = _perfect_matching(len(outputs), rng)
        controls.append(profile_module._profile(outputs ^ outputs[mapping]))
        route_checks.append(
            {
                "involution": bool(np.array_equal(mapping[mapping], np.arange(len(mapping)))),
                "fixed_points": int(np.count_nonzero(mapping == np.arange(len(mapping)))),
                "bijective": bool(np.array_equal(np.sort(mapping), np.arange(len(mapping)))),
            }
        )
    result: dict[str, Any] = {"factual": factual, "effects": {}, "route_checks": route_checks}
    for metric in ("entropy_deficit_sum", "mean_bit_bias_chi2", "maximum_bit_bias_chi2"):
        null = np.asarray([control[metric] for control in controls])
        result["effects"][metric] = {
            "difference": float(factual[metric] - null.mean()),
            "control_mean": float(null.mean()),
            "control_sd_ddof1": float(null.std(ddof=1)),
            "route_z": float((factual[metric] - null.mean()) / max(null.std(ddof=1), 1e-15)),
        }
    return result


def _run(args: argparse.Namespace, profile_module: Any) -> list[dict[str, Any]]:
    configs = [(rounds, bits) for rounds in args.rounds for bits in args.active_bits]
    raw = {config: [] for config in configs}
    for seed_index in range(args.seeds):
        key_seed = args.seed_base + 1009 * seed_index
        for rounds, bits in configs:
            cosets = []
            for coset in range(args.cosets):
                counters = _coset_counters(bits, key_seed ^ (coset * 0x9E3779B1))
                outputs = chacha_counter_blocks(counters, rounds, key_seed)
                analysis = _analyse_outputs(
                    outputs,
                    counter_bit=args.counter_bit,
                    routes=args.routes,
                    seed=key_seed ^ (rounds << 20) ^ (bits << 12) ^ coset,
                    profile_module=profile_module,
                )
                if not all(
                    row["involution"] and row["bijective"] and row["fixed_points"] == 0
                    for row in analysis["route_checks"]
                ):
                    raise RuntimeError("matching null invariant failed")
                cosets.append(
                    {
                        "coset": coset,
                        "counter_sha256": hashlib.sha256(counters.tobytes()).hexdigest(),
                        "entropy_effect": analysis["effects"]["entropy_deficit_sum"]["difference"],
                        "entropy_route_z": analysis["effects"]["entropy_deficit_sum"]["route_z"],
                        "mean_bit_bias_effect": analysis["effects"]["mean_bit_bias_chi2"]["difference"],
                    }
                )
            raw[rounds, bits].append(
                {
                    "key_seed": key_seed,
                    "cosets": cosets,
                    "mean_entropy_effect": float(np.mean([row["entropy_effect"] for row in cosets])),
                    "mean_entropy_route_z": float(np.mean([row["entropy_route_z"] for row in cosets])),
                    "mean_bit_bias_effect": float(np.mean([row["mean_bit_bias_effect"] for row in cosets])),
                }
            )
        print(f"fair-matching key={key_seed}", flush=True)
    results = []
    for rounds, bits in configs:
        records = raw[rounds, bits]
        entropy = [row["mean_entropy_effect"] for row in records]
        bit_bias = [row["mean_bit_bias_effect"] for row in records]
        results.append(
            {
                "rounds": rounds,
                "active_low_bits": bits,
                "counter_values_per_coset": 1 << bits,
                "cosets_per_key": args.cosets,
                "entropy_effect": _summary(entropy),
                "entropy_exact_test": exact_sign_flip_test(entropy),
                "mean_entropy_route_z": float(np.mean([row["mean_entropy_route_z"] for row in records])),
                "mean_bit_bias_effect": _summary(bit_bias),
                "mean_bit_bias_exact_test": exact_sign_flip_test(bit_bias),
                "keys": records,
            }
        )
    return results


def _plot(results: list[dict[str, Any]], output: Path) -> None:
    figure, axis = plt.subplots(figsize=(8, 5.5), layout="constrained")
    for rounds in sorted({row["rounds"] for row in results}):
        rows = sorted([row for row in results if row["rounds"] == rounds], key=lambda row: row["active_low_bits"])
        axis.errorbar(
            [row["active_low_bits"] for row in rows],
            [row["entropy_effect"]["mean"] for row in rows],
            yerr=[row["entropy_effect"]["sample_sd_ddof1"] for row in rows],
            marker="o",
            label=f"R{rounds}",
        )
    axis.axhline(0, color="black", linewidth=0.8)
    axis.set_xlabel("active low counter bits (complete coset)")
    axis.set_ylabel("entropy excess over fair random perfect matching")
    axis.set_title("ChaCha chosen-difference under involution-preserving null")
    axis.grid(alpha=0.25)
    axis.legend(ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=170, metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_involution_fair_null_suite", parameters=parameters)
    for row in results:
        test = row["entropy_exact_test"]
        builder.add_triplet(
            edge_id=f"r{row['rounds']}-k{row['active_low_bits']}",
            trigger=f"chacha_r{row['rounds']}:xor_bit{parameters['counter_bit']}_matching",
            mechanism="compared_with_fixed_point_free_involution_on_same_output_multiset",
            outcome=f"k{row['active_low_bits']}_coset_differential_entropy",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="involution_preserving_fair_null",
            source=source,
            attrs={
                **test,
                "effect_mean": row["entropy_effect"]["mean"],
                "mean_route_z": row["mean_entropy_route_z"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", nargs="*", type=int, default=[4, 5, 6, 7, 8, 20])
    parser.add_argument("--active-bits", nargs="*", type=int, default=[8, 10, 12, 14])
    parser.add_argument("--counter-bit", type=int, default=0)
    parser.add_argument("--cosets", type=int, default=4)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=150000)
    args = parser.parse_args()
    if args.cosets < 1 or args.seeds < 3 or args.routes < 3:
        raise ValueError("cosets >=1, seeds >=3 and routes >=3 required")
    if any(bits < 2 or bits > 16 for bits in args.active_bits):
        raise ValueError("enumerated active bits must be in [2, 16]")
    if any(args.counter_bit >= bits for bits in args.active_bits):
        raise ValueError("counter difference bit must lie inside every closed subspace")
    args.rounds = sorted(set(args.rounds))
    args.active_bits = sorted(set(args.active_bits))
    profile_module = _load_profile()
    parameters = {
        "rounds": args.rounds,
        "active_bits": args.active_bits,
        "counter_bit": args.counter_bit,
        "cosets": args.cosets,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "null": "random fixed-point-free perfect matching; bijective involution on identical output multiset",
    }
    results = _run(args, profile_module)
    _plot(results, args.figure)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_involution_fair_null_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": "Corrects arbitrary repairing for differentials that are perfect matchings on a closed input subspace.",
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
