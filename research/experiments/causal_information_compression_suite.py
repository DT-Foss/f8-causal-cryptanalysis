#!/usr/bin/env python3
"""Conditional code-length interpretation of cross-round F8 dependence.

For every byte-position pair, the quantized delta can be encoded either with
an unconditional model or a model conditioned on the quantized source byte.
The ideal code-length gain is exactly

    G_ij = H(Delta_j) - H(Delta_j | X_i) = I(X_i ; Delta_j).

Balanced BvN re-pairing estimates the finite-sample coding gain under broken
round pairing. Carry-free counterfactuals identify whether that gain is
mediated by modular addition.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.ciphers import FULL_ROUNDS, SPECK_VARIANTS, get_generator
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


def _load_interventions() -> Any:
    path = Path(__file__).with_name("causal_carry_intervention_suite.py")
    spec = importlib.util.spec_from_file_location("causal_carry_interventions_for_mi", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load carry intervention helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _mutual_information_matrix(first: np.ndarray, second: np.ndarray, shift: int) -> np.ndarray:
    if first.shape != second.shape:
        raise ValueError("paired matrices must have the same shape")
    bins = 2 ** (8 - shift)
    source = first >> shift
    delta = (first ^ second) >> shift
    matrix = np.zeros((first.shape[1], first.shape[1]), dtype=float)
    for i in range(first.shape[1]):
        for j in range(first.shape[1]):
            counts = np.bincount(
                source[:, i].astype(np.int64) * bins + delta[:, j],
                minlength=bins * bins,
            ).reshape(bins, bins)
            joint = counts / counts.sum()
            source_probability = joint.sum(axis=1, keepdims=True)
            delta_probability = joint.sum(axis=0, keepdims=True)
            independent = source_probability @ delta_probability
            valid = joint > 0
            matrix[i, j] = np.sum(joint[valid] * np.log2(joint[valid] / independent[valid]))
    return matrix


def _matrix_summary(matrix: np.ndarray) -> dict[str, Any]:
    maximum_index = np.unravel_index(int(np.argmax(matrix)), matrix.shape)
    return {
        "mean_gain_bits_per_symbol": float(np.mean(matrix)),
        "sum_gain_bits_per_symbol_across_edges": float(np.sum(matrix)),
        "maximum_gain_bits_per_symbol": float(np.max(matrix)),
        "maximum_edge": [int(maximum_index[0]), int(maximum_index[1])],
        "matrix": [[float(value) for value in row] for row in matrix],
    }


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "values": values,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _paired_test(first: list[float], second: list[float]) -> dict[str, float | int]:
    differences = np.asarray(first) - np.asarray(second)
    observed = float(np.mean(differences))
    null = np.asarray(
        [np.mean(differences * signs) for signs in itertools.product((-1.0, 1.0), repeat=len(differences))]
    )
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "mean_difference_bits_per_symbol": observed,
        "seed_pairs": len(differences),
        "exact_assignments": len(null),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def _target_run(target: str, args: argparse.Namespace, interventions: Any) -> dict[str, Any]:
    generator = get_generator(target)
    round_index = FULL_ROUNDS[target]
    actual_means = []
    actual_maxima = []
    route_means_by_seed = []
    carry_free_means = []
    carry_free_maxima = []
    per_seed = []
    for seed_index in range(args.seeds):
        seed = 42 + 1000 * seed_index
        raw, block_bytes, _ = generator(args.blocks, round_index, seed)
        raw_next, next_block_bytes, _ = generator(args.blocks, round_index + 1, seed)
        if block_bytes != next_block_bytes:
            raise RuntimeError("block width changed")
        first = np.frombuffer(raw, dtype=np.uint8).reshape(-1, block_bytes)
        second = np.frombuffer(raw_next, dtype=np.uint8).reshape(-1, block_bytes)
        actual_matrix = _mutual_information_matrix(first, second, args.shift)
        actual_summary = _matrix_summary(actual_matrix)
        actual_means.append(actual_summary["mean_gain_bits_per_symbol"])
        actual_maxima.append(actual_summary["maximum_gain_bits_per_symbol"])
        routes = route_ensemble(len(second), args.routes, 0xC0DE + seed)
        route_check = verify_routes(routes)
        route_summaries = [
            _matrix_summary(_mutual_information_matrix(first, second[route], args.shift))
            for route in routes
        ]
        route_means = [summary["mean_gain_bits_per_symbol"] for summary in route_summaries]
        route_means_by_seed.append(route_means)
        record: dict[str, Any] = {
            "seed": seed,
            "actual": actual_summary,
            "route_null_mean_gain": _summary(route_means),
            "route_check": route_check,
        }
        if target in SPECK_VARIANTS:
            counterfactual, transition_check = interventions._speck_counterfactual(
                target, first, second, round_index, seed
            )
        elif target == "threefish256":
            counterfactual, transition_check = interventions._threefish_counterfactual(
                first, second, round_index, seed
            )
        else:
            counterfactual = None
            transition_check = {"not_applicable": "no modular addition"}
        record["transition_check"] = transition_check
        if counterfactual is not None:
            carry_free_summary = _matrix_summary(
                _mutual_information_matrix(first, counterfactual, args.shift)
            )
            carry_free_means.append(carry_free_summary["mean_gain_bits_per_symbol"])
            carry_free_maxima.append(carry_free_summary["maximum_gain_bits_per_symbol"])
            record["carry_free"] = carry_free_summary
        per_seed.append(record)
    route_seed_means = [float(np.mean(values)) for values in route_means_by_seed]
    result: dict[str, Any] = {
        "target": target,
        "full_round_transition": [round_index, round_index + 1],
        "actual_mean_gain": _summary(actual_means),
        "actual_maximum_edge_gain": _summary(actual_maxima),
        "bvn_route_mean_gain": _summary(route_seed_means),
        "paired_actual_vs_bvn": _paired_test(actual_means, route_seed_means),
        "per_seed": per_seed,
    }
    if carry_free_means:
        result.update(
            {
                "carry_free_mean_gain": _summary(carry_free_means),
                "carry_free_maximum_edge_gain": _summary(carry_free_maxima),
                "paired_actual_vs_carry_free": _paired_test(actual_means, carry_free_means),
            }
        )
    return result


def _graph(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="causal_information_compression_suite", parameters=parameters)
    for result in results:
        target = result["target"]
        paired = result["paired_actual_vs_bvn"]
        builder.add_triplet(
            edge_id=f"{target}-conditional-code-gain",
            trigger=f"{target}:quantized_source_byte",
            mechanism="conditions_ideal_code_for_cross_round_delta",
            outcome="reduced_code_length_vs_bvn_repairing",
            confidence=1.0 - float(paired["upper_tail_p"]),
            evidence_kind="paired_bvn_conditional_code_test",
            source=source,
            attrs={
                **paired,
                "actual_mean": result["actual_mean_gain"]["mean"],
                "bvn_mean": result["bvn_route_mean_gain"]["mean"],
                "actual_maximum_edge_mean": result["actual_maximum_edge_gain"]["mean"],
            },
        )
        if "carry_free_mean_gain" in result:
            ablation = result["paired_actual_vs_carry_free"]
            builder.add_triplet(
                edge_id=f"{target}-conditional-code-carry-ablation",
                trigger=f"{target}:modular_addition_enabled",
                mechanism="do(carry=0)_changes_conditional_code_gain",
                outcome="cross_round_information_compression",
                confidence=1.0 - float(ablation["two_sided_p"]),
                evidence_kind="paired_mechanism_intervention",
                source=source,
                attrs={
                    **ablation,
                    "actual_mean": result["actual_mean_gain"]["mean"],
                    "carry_free_mean": result["carry_free_mean_gain"]["mean"],
                    "carry_free_maximum_edge_mean": result[
                        "carry_free_maximum_edge_gain"
                    ]["mean"],
                },
            )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=10_000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--targets", nargs="*", default=list(FULL_ROUNDS))
    args = parser.parse_args()
    if args.blocks < 1000 or args.seeds < 2 or args.routes < 4:
        raise ValueError("blocks >= 1000, seeds >= 2, routes >= 4 required")
    unknown = sorted(set(args.targets) - set(FULL_ROUNDS))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    parameters = {
        "blocks": args.blocks,
        "seeds": args.seeds,
        "routes": args.routes,
        "shift": args.shift,
        "targets": args.targets,
    }
    interventions = _load_interventions()
    results = []
    for target in args.targets:
        print(f"causal conditional code-length sweep: {target}", flush=True)
        results.append(_target_run(target, args, interventions))
    payload = {
        "schema_version": 1,
        "experiment": "causal_information_compression_suite",
        "parameters": parameters,
        "environment": {"python": sys.version.split()[0], "numpy": np.__version__, "platform": platform.platform()},
        "formulae": {
            "gain": "G_ij = H(Delta_j) - H(Delta_j | X_i) = I(X_i; Delta_j)",
            "source": "X_i = output_R_byte_i >> shift",
            "delta": "Delta_j = (output_R_byte_j XOR output_R+1_byte_j) >> shift",
        },
        "results": results,
        "scope_note": (
            "Ideal conditional code-length measurement under known pairing. It is an information-theoretic "
            "interpretation of F8, not key recovery or a generic compressor attack."
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
