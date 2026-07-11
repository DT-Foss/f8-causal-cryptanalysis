#!/usr/bin/env python3
"""Multi-coset confirmation of ChaCha chosen-subspace frontiers."""

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


def _load(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _run(args: argparse.Namespace, dimension: Any, domain: Any) -> list[dict[str, Any]]:
    configs = [(orientation, bits) for orientation in args.orientations for bits in args.active_bits]
    key_results = {config: [] for config in configs}
    for seed_index in range(args.seeds):
        key_seed = args.seed_base + 1009 * seed_index
        for orientation, bits in configs:
            sample_count = min(args.samples_per_coset, 1 << bits)
            coset_records = []
            for coset in range(args.cosets):
                domain_seed = key_seed ^ (coset * 0x9E3779B1) ^ (bits << 12)
                counters = dimension._subspace(orientation, bits, sample_count, domain_seed)
                first = chacha_counter_blocks(counters, args.rounds, key_seed)
                second = chacha_counter_blocks(
                    counters ^ np.uint32(1 << args.counter_bit), args.rounds, key_seed
                )
                analysis = domain._analyse(
                    first,
                    second,
                    args.routes,
                    key_seed ^ (coset << 16) ^ bits ^ sum(orientation.encode()),
                )
                coset_records.append(
                    {
                        "coset": coset,
                        "samples": sample_count,
                        "counter_multiset_sha256": hashlib.sha256(np.sort(counters).tobytes()).hexdigest(),
                        "entropy_effect": analysis["effects"]["entropy_deficit_sum"]["difference"],
                        "entropy_route_z": analysis["effects"]["entropy_deficit_sum"]["route_z"],
                        "mean_bit_bias_effect": analysis["effects"]["mean_bit_bias_chi2"]["difference"],
                    }
                )
            key_results[orientation, bits].append(
                {
                    "key_seed": key_seed,
                    "cosets": coset_records,
                    "mean_entropy_effect": float(np.mean([row["entropy_effect"] for row in coset_records])),
                    "mean_entropy_route_z": float(np.mean([row["entropy_route_z"] for row in coset_records])),
                    "mean_bit_bias_effect": float(np.mean([row["mean_bit_bias_effect"] for row in coset_records])),
                }
            )
        print(f"multi-coset key={key_seed}", flush=True)
    results = []
    for orientation, bits in configs:
        records = key_results[orientation, bits]
        entropy = [row["mean_entropy_effect"] for row in records]
        bit_bias = [row["mean_bit_bias_effect"] for row in records]
        results.append(
            {
                "orientation": orientation,
                "active_bits": bits,
                "samples_per_coset": min(args.samples_per_coset, 1 << bits),
                "cosets_per_key": args.cosets,
                "entropy_effect_across_keys": _summary(entropy),
                "entropy_exact_test_across_keys": exact_sign_flip_test(entropy),
                "bit_bias_effect_across_keys": _summary(bit_bias),
                "bit_bias_exact_test_across_keys": exact_sign_flip_test(bit_bias),
                "mean_route_z_across_cosets_and_keys": float(
                    np.mean([row["mean_entropy_route_z"] for row in records])
                ),
                "keys": records,
            }
        )
    return results


def _plot(results: list[dict[str, Any]], output: Path, rounds: int) -> None:
    figure, axis = plt.subplots(figsize=(7.5, 5), layout="constrained")
    for orientation in sorted({row["orientation"] for row in results}):
        rows = sorted(
            [row for row in results if row["orientation"] == orientation],
            key=lambda row: row["active_bits"],
        )
        axis.errorbar(
            [row["active_bits"] for row in rows],
            [row["entropy_effect_across_keys"]["mean"] for row in rows],
            yerr=[row["entropy_effect_across_keys"]["sample_sd_ddof1"] for row in rows],
            marker="o",
            label=orientation,
        )
    axis.axhline(0, color="black", linewidth=0.8)
    axis.set_xlabel("active counter bits per coset")
    axis.set_ylabel("mean entropy-deficit excess")
    axis.set_title(f"ChaCha R{rounds} multi-coset subspace confirmation")
    axis.grid(alpha=0.25)
    axis.legend()
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=170, metadata={"Creator": "arx-carry-leak"})
    plt.close(figure)


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_subspace_multicoset_suite", parameters=parameters)
    for row in results:
        test = row["entropy_exact_test_across_keys"]
        builder.add_triplet(
            edge_id=f"{row['orientation']}-{row['active_bits']}",
            trigger=f"do(multiple_{row['orientation']}_{row['active_bits']}bit_cosets)",
            mechanism="averages_within_coset_repairing_effect_over_independent_cosets",
            outcome=f"r{parameters['rounds']}_chosen_difference_entropy",
            confidence=1.0 - float(test["two_sided_p"]),
            evidence_kind="multi_coset_multi_key_confirmation",
            source=source,
            attrs={
                **test,
                "effect_mean": row["entropy_effect_across_keys"]["mean"],
                "mean_route_z": row["mean_route_z_across_cosets_and_keys"],
            },
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--counter-bit", type=int, default=0)
    parser.add_argument("--active-bits", nargs="*", type=int, default=[8, 10, 12, 14, 32])
    parser.add_argument("--orientations", nargs="*", default=["low", "high"])
    parser.add_argument("--samples-per-coset", type=int, default=512)
    parser.add_argument("--cosets", type=int, default=16)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=8)
    parser.add_argument("--seed-base", type=int, default=130000)
    args = parser.parse_args()
    if args.samples_per_coset < 64 or args.cosets < 2 or args.seeds < 3 or args.routes < 3:
        raise ValueError("samples >=64, cosets >=2, seeds >=3 and routes >=3 required")
    if set(args.orientations) - {"low", "high"}:
        raise ValueError("orientations must be low/high")
    args.active_bits = sorted(set(args.active_bits))
    dimension = _load("chacha_dimension_for_multicoset", "chacha_subspace_dimension_suite.py")
    domain = _load("chacha_domain_for_multicoset", "chacha_r4_counter_domain_suite.py")
    parameters = {
        "rounds": args.rounds,
        "counter_bit": args.counter_bit,
        "active_bits": args.active_bits,
        "orientations": args.orientations,
        "samples_per_coset": args.samples_per_coset,
        "cosets": args.cosets,
        "seeds": args.seeds,
        "routes": args.routes,
        "seed_base": args.seed_base,
        "pairing_control": "independent global repairing within each coset",
    }
    results = _run(args, dimension, domain)
    _plot(results, args.figure, args.rounds)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_subspace_multicoset_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "results": results,
        "figure": str(args.figure),
        "scope_note": "Each effect is first estimated within a fixed-dimension coset, then averaged across cosets and tested across keys.",
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
