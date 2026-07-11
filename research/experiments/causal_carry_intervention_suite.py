#!/usr/bin/env python3
"""Mechanism-specific ``do(carry=0)`` interventions for full-round F8.

For Speck and Threefish, the factual transition keeps modular addition while
the counterfactual transition replaces only additions with XOR. Rotations,
word layout, key/tweak material, input states, round index, and pairing remain
fixed. SIMON is the no-addition negative control. Balanced BvN routes supply a
separate pairing null.

This is a known-state/known-key mechanism experiment. It is not key recovery
and it does not claim a black-box intervention on an unknown primitive.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import itertools
import json
import operator
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.ciphers import (
    FULL_ROUNDS,
    MASK64,
    SPECK_VARIANTS,
    THREEFISH256_ROTATIONS,
    THREEFISH_C240,
    _random_words,
    _rol,
    _ror,
    get_generator,
    speck_round_keys,
)
from arx_carry_leak.crypto_causal import CryptoCausalBuilder
from arx_carry_leak.f8 import _chi_square


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": [float(value) for value in array],
        "mean": float(np.mean(array)),
        "sample_sd_ddof1": float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(np.min(array)),
        "maximum": float(np.max(array)),
    }


def _f8_rate(first: np.ndarray, second: np.ndarray, shift: int, alpha: float) -> float:
    if first.shape != second.shape:
        raise ValueError("paired matrices must have the same shape")
    n_bins = 2 ** (8 - shift)
    difference = first ^ second
    source = first >> shift
    delta = difference >> shift
    significant = tested = 0
    for source_position in range(first.shape[1]):
        for target_position in range(first.shape[1]):
            flat = source[:, source_position].astype(np.int64) * n_bins + delta[:, target_position]
            table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
            result = _chi_square(table.astype(float), len(first))
            if result is None:
                continue
            tested += 1
            significant += result[1] < alpha
    return significant / max(tested, 1)


def _paired_sign_flip_test(actual: list[float], counterfactual: list[float]) -> dict[str, float | int]:
    """Exact paired randomization test over independent seeds."""
    differences = np.asarray(actual, dtype=float) - np.asarray(counterfactual, dtype=float)
    observed = float(np.mean(differences))
    null = np.asarray(
        [np.mean(differences * np.asarray(signs)) for signs in itertools.product((-1.0, 1.0), repeat=len(differences))]
    )
    upper = float(np.mean(null >= observed))
    lower = float(np.mean(null <= observed))
    return {
        "actual_minus_counterfactual_mean": observed,
        "seed_pairs": len(differences),
        "exact_null_assignments": len(null),
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def _aggregate_route_test(actual: list[float], null_by_seed: list[list[float]], seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    null = np.asarray(null_by_seed, dtype=float)
    draws = 20_000
    indices = rng.integers(null.shape[1], size=(draws, null.shape[0]))
    selected = null[np.arange(null.shape[0])[None, :], indices]
    means = np.mean(selected, axis=1)
    observed = float(np.mean(actual))
    upper = float((1 + np.sum(means >= observed)) / (1 + draws))
    lower = float((1 + np.sum(means <= observed)) / (1 + draws))
    return {
        "actual_mean": observed,
        "route_null_mean": float(np.mean(means)),
        "route_null_sd": float(np.std(means, ddof=1)),
        "resamples": draws,
        "upper_tail_p": upper,
        "lower_tail_p": lower,
        "two_sided_p": min(1.0, 2.0 * min(upper, lower)),
    }


def _words_from_rows(rows: np.ndarray, word_bytes: int) -> list[list[int]]:
    raw = memoryview(rows).cast("B")
    block_bytes = rows.shape[1]
    return [
        [
            int.from_bytes(raw[offset + index * word_bytes : offset + (index + 1) * word_bytes], "big")
            for index in range(block_bytes // word_bytes)
        ]
        for offset in range(0, len(raw), block_bytes)
    ]


def _rows_from_words(words: list[list[int]], word_bytes: int) -> np.ndarray:
    block_bytes = len(words[0]) * word_bytes
    raw = bytearray(len(words) * block_bytes)
    for row_index, row in enumerate(words):
        offset = row_index * block_bytes
        for word_index, word in enumerate(row):
            start = offset + word_index * word_bytes
            raw[start : start + word_bytes] = word.to_bytes(word_bytes, "big")
    return np.frombuffer(bytes(raw), dtype=np.uint8).reshape(-1, block_bytes)


def _speck_counterfactual(
    target: str, first: np.ndarray, actual_second: np.ndarray, round_index: int, seed: int
) -> tuple[np.ndarray, dict[str, int | bool]]:
    variant = SPECK_VARIANTS[target]
    rng = np.random.default_rng(seed)
    master_key = _random_words(rng, variant.key_words, variant.word_size)
    round_key = speck_round_keys(variant, master_key, round_index + 1)[round_index]
    mask = (1 << variant.word_size) - 1
    factual_words: list[list[int]] = []
    counterfactual_words: list[list[int]] = []
    residual_words: list[list[int]] = []
    for x, y in _words_from_rows(first, variant.word_size // 8):
        rotated = _ror(x, variant.alpha, variant.word_size)
        addition = (rotated + y) & mask
        carry_free = rotated ^ y
        factual_x = addition ^ round_key
        factual_y = _rol(y, variant.beta, variant.word_size) ^ factual_x
        counterfactual_x = carry_free ^ round_key
        counterfactual_y = _rol(y, variant.beta, variant.word_size) ^ counterfactual_x
        carry_effect = addition ^ carry_free
        factual_words.append([factual_x & mask, factual_y & mask])
        counterfactual_words.append([counterfactual_x & mask, counterfactual_y & mask])
        residual_words.append([carry_effect, carry_effect])
    factual = _rows_from_words(factual_words, variant.word_size // 8)
    counterfactual = _rows_from_words(counterfactual_words, variant.word_size // 8)
    expected_residual = _rows_from_words(residual_words, variant.word_size // 8)
    return counterfactual, {
        "factual_transition_rows_verified": int(np.sum(np.all(factual == actual_second, axis=1))),
        "carry_identity_rows_verified": int(
            np.sum(np.all((actual_second ^ counterfactual) == expected_residual, axis=1))
        ),
        "rows": len(first),
        "all_factual_transitions_verified": bool(np.array_equal(factual, actual_second)),
        "all_carry_identities_verified": bool(np.array_equal(actual_second ^ counterfactual, expected_residual)),
    }


def _threefish_schedule(seed: int) -> tuple[list[int], list[int]]:
    rng = np.random.default_rng(seed)
    key = _random_words(rng, 4, 64)
    tweak = _random_words(rng, 2, 64)
    key_schedule = list(key)
    parity = THREEFISH_C240
    for word in key_schedule:
        parity ^= word
    key_schedule.append(parity)
    return key_schedule, [tweak[0], tweak[1], tweak[0] ^ tweak[1]]


def _threefish_transition(
    state: list[int], round_index: int, key_schedule: list[int], tweak_schedule: list[int], *, carry_free: bool
) -> list[int]:
    combine = (
        (lambda *values: functools.reduce(operator.xor, values, 0))
        if carry_free
        else (lambda *values: sum(values))
    )
    rotation_a, rotation_b = THREEFISH256_ROTATIONS[round_index % 8]
    mixed0 = combine(state[0], state[1]) & MASK64
    mixed1 = _rol(state[1], rotation_a, 64) ^ mixed0
    mixed2 = combine(state[2], state[3]) & MASK64
    mixed3 = _rol(state[3], rotation_b, 64) ^ mixed2
    result = [mixed0, mixed3, mixed2, mixed1]
    if (round_index + 1) % 4 == 0:
        subkey = (round_index + 1) // 4
        result[0] = combine(result[0], key_schedule[subkey % 5]) & MASK64
        result[1] = combine(
            result[1], key_schedule[(subkey + 1) % 5], tweak_schedule[subkey % 3]
        ) & MASK64
        result[2] = combine(
            result[2], key_schedule[(subkey + 2) % 5], tweak_schedule[(subkey + 1) % 3]
        ) & MASK64
        result[3] = combine(result[3], key_schedule[(subkey + 3) % 5], subkey) & MASK64
    return result


def _threefish_counterfactual(
    first: np.ndarray, actual_second: np.ndarray, round_index: int, seed: int
) -> tuple[np.ndarray, dict[str, int | bool]]:
    key_schedule, tweak_schedule = _threefish_schedule(seed)
    factual = []
    counterfactual = []
    affine_neighbor_identity_rows = 0
    for state in _words_from_rows(first, 8):
        factual.append(_threefish_transition(state, round_index, key_schedule, tweak_schedule, carry_free=False))
        carry_free_state = _threefish_transition(
            state, round_index, key_schedule, tweak_schedule, carry_free=True
        )
        counterfactual.append(carry_free_state)
        constant0 = constant2 = 0
        if (round_index + 1) % 4 == 0:
            subkey = (round_index + 1) // 4
            constant0 = key_schedule[subkey % 5]
            constant2 = (
                key_schedule[(subkey + 2) % 5] ^ tweak_schedule[(subkey + 1) % 3]
            )
        lane0_identity = (state[0] ^ carry_free_state[0]) == (state[1] ^ constant0)
        lane2_identity = (state[2] ^ carry_free_state[2]) == (state[3] ^ constant2)
        affine_neighbor_identity_rows += int(lane0_identity and lane2_identity)
    factual_rows = _rows_from_words(factual, 8)
    counterfactual_rows = _rows_from_words(counterfactual, 8)
    return counterfactual_rows, {
        "factual_transition_rows_verified": int(np.sum(np.all(factual_rows == actual_second, axis=1))),
        "rows": len(first),
        "all_factual_transitions_verified": bool(np.array_equal(factual_rows, actual_second)),
        "affine_neighbor_identity_rows_verified": affine_neighbor_identity_rows,
        "all_affine_neighbor_identities_verified": affine_neighbor_identity_rows == len(first),
    }


def _target_run(target: str, args: argparse.Namespace) -> dict[str, Any]:
    full_rounds = FULL_ROUNDS[target]
    base_round = full_rounds - args.round_pairs + 1
    generator = get_generator(target)
    actual_seed_rates: list[float] = []
    counterfactual_seed_rates: list[float] = []
    residual_seed_rates: list[float] = []
    route_null_by_seed: list[list[float]] = []
    per_seed = []
    for seed_index in range(args.seeds):
        seed = 42 + 1000 * seed_index
        cache: dict[int, np.ndarray] = {}
        block_bytes = None
        for round_index in range(base_round, full_rounds + 2):
            raw, current_block_bytes, _ = generator(args.blocks, round_index, seed)
            block_bytes = current_block_bytes
            cache[round_index] = np.frombuffer(raw, dtype=np.uint8).reshape(-1, current_block_bytes)
        actual_round_rates = []
        counterfactual_round_rates = []
        residual_round_rates = []
        transition_checks = []
        routed_rounds: list[list[float]] = [[] for _ in range(args.routes)]
        for round_index in range(base_round, full_rounds + 1):
            first = cache[round_index]
            second = cache[round_index + 1]
            actual_round_rates.append(_f8_rate(first, second, args.shift, args.alpha))
            routes = route_ensemble(len(second), args.routes, 0xB0A000 + seed + round_index)
            route_check = verify_routes(routes)
            if route_check != {"all_bijective": True, "forbidden_alignments": 0}:
                raise RuntimeError(f"{target}: invalid route ensemble")
            for route_index, route in enumerate(routes):
                routed_rounds[route_index].append(_f8_rate(first, second[route], args.shift, args.alpha))
            if target in SPECK_VARIANTS:
                counterfactual, check = _speck_counterfactual(target, first, second, round_index, seed)
            elif target == "threefish256":
                counterfactual, check = _threefish_counterfactual(first, second, round_index, seed)
            else:
                transition_checks.append({"round": round_index, "not_applicable": "no modular addition"})
                continue
            transition_checks.append({"round": round_index, **check})
            counterfactual_round_rates.append(_f8_rate(first, counterfactual, args.shift, args.alpha))
            residual_round_rates.append(_f8_rate(first, second ^ counterfactual, args.shift, args.alpha))
        actual_rate = float(np.mean(actual_round_rates))
        route_values = [float(np.mean(values)) for values in routed_rounds]
        actual_seed_rates.append(actual_rate)
        route_null_by_seed.append(route_values)
        record: dict[str, Any] = {
            "seed": seed,
            "block_bytes": block_bytes,
            "actual_round_rates": actual_round_rates,
            "actual_rate": actual_rate,
            "route_null": _summary(route_values),
            "transition_checks": transition_checks,
        }
        if counterfactual_round_rates:
            counterfactual_rate = float(np.mean(counterfactual_round_rates))
            residual_rate = float(np.mean(residual_round_rates))
            counterfactual_seed_rates.append(counterfactual_rate)
            residual_seed_rates.append(residual_rate)
            record.update(
                {
                    "carry_free_round_rates": counterfactual_round_rates,
                    "carry_free_rate": counterfactual_rate,
                    "carry_residual_round_rates": residual_round_rates,
                    "carry_residual_rate": residual_rate,
                }
            )
        per_seed.append(record)
    result: dict[str, Any] = {
        "target": target,
        "full_rounds": full_rounds,
        "base_round": base_round,
        "actual": _summary(actual_seed_rates),
        "bvn_route_null": {
            "per_seed": [_summary(values) for values in route_null_by_seed],
            "aggregate_test": _aggregate_route_test(actual_seed_rates, route_null_by_seed, 0xCA05E + full_rounds),
        },
        "per_seed": per_seed,
    }
    if counterfactual_seed_rates:
        result.update(
            {
                "carry_free_counterfactual": _summary(counterfactual_seed_rates),
                "carry_residual": _summary(residual_seed_rates),
                "paired_carry_ablation_test": _paired_sign_flip_test(
                    actual_seed_rates, counterfactual_seed_rates
                ),
                "all_factual_transition_gates_passed": all(
                    check.get("all_factual_transitions_verified", False)
                    for record in per_seed
                    for check in record["transition_checks"]
                ),
            }
        )
        if target in SPECK_VARIANTS:
            result["all_speck_carry_identity_gates_passed"] = all(
                check.get("all_carry_identities_verified", False)
                for record in per_seed
                for check in record["transition_checks"]
            )
        elif target == "threefish256":
            result["all_threefish_affine_neighbor_identity_gates_passed"] = all(
                check.get("all_affine_neighbor_identities_verified", False)
                for record in per_seed
                for check in record["transition_checks"]
            )
    return result


def _build_causal(results: list[dict[str, Any]], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="causal_carry_intervention_suite", parameters=parameters)
    for result in results:
        target = result["target"]
        route = result["bvn_route_null"]["aggregate_test"]
        builder.add_triplet(
            edge_id=f"{target}-pairing-control",
            trigger=f"{target}:true_round_pairing",
            mechanism="tested_against_balanced_bvn_repairing",
            outcome="cross_round_f8_rate",
            confidence=1.0 - float(route["upper_tail_p"]),
            evidence_kind="paired_randomization",
            source=source,
            attrs=route,
        )
        if "carry_free_counterfactual" not in result:
            builder.add_triplet(
                edge_id=f"{target}-no-addition-control",
                trigger=target,
                mechanism="contains_no_modular_addition",
                outcome="carry_ablation_not_applicable",
                confidence=1.0,
                evidence_kind="algorithmic_control",
                source=source,
            )
            continue
        ablation = result["paired_carry_ablation_test"]
        builder.add_triplet(
            edge_id=f"{target}-carry-ablation",
            trigger=f"{target}:modular_addition_enabled",
            mechanism="do(carry=0)_with_other_round_components_fixed",
            outcome="cross_round_f8_rate_change",
            confidence=1.0 - float(ablation["upper_tail_p"]),
            evidence_kind="mechanism_intervention",
            source=source,
            attrs={
                **ablation,
                "actual_mean": result["actual"]["mean"],
                "carry_free_mean": result["carry_free_counterfactual"]["mean"],
                "carry_residual_mean": result["carry_residual"]["mean"],
            },
        )
        if target in SPECK_VARIANTS:
            builder.add_triplet(
                edge_id=f"{target}-carry-identity",
                trigger=f"{target}:factual_next_xor_carry_free_next",
                mechanism="equals_propagated_addition_carry_mask",
                outcome="both_output_words",
                confidence=1.0,
                evidence_kind="algebraic_identity_verified_over_all_rows",
                source=source,
                attrs={"all_rows_verified": result["all_speck_carry_identity_gates_passed"]},
            )
        elif target == "threefish256":
            builder.add_triplet(
                edge_id="threefish256-affine-neighbor-identity",
                trigger="threefish256:carry_free_round_delta",
                mechanism="equals_neighbor_word_xor_fixed_round_constant",
                outcome="word_lanes_0_and_2",
                confidence=1.0,
                evidence_kind="algebraic_identity_verified_over_all_rows",
                source=source,
                attrs={
                    "all_rows_verified": result[
                        "all_threefish_affine_neighbor_identity_gates_passed"
                    ],
                    "identity": [
                        "delta_word0 = old_word1 XOR round_constant0",
                        "delta_word2 = old_word3 XOR round_constant2",
                    ],
                },
            )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=10_000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--round-pairs", type=int, default=1)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--shift", type=int, default=5)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--targets", nargs="*", default=list(FULL_ROUNDS))
    args = parser.parse_args()
    if args.blocks < 1000 or args.seeds < 2 or args.round_pairs < 1 or args.routes < 4:
        raise ValueError("blocks >= 1000, seeds >= 2, round-pairs >= 1, routes >= 4 required")
    unknown = sorted(set(args.targets) - set(FULL_ROUNDS))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    if any(args.round_pairs > FULL_ROUNDS[target] for target in args.targets):
        raise ValueError("round-pairs exceeds a target's full round count")
    parameters = {
        "blocks": args.blocks,
        "seeds": args.seeds,
        "round_pairs": args.round_pairs,
        "routes": args.routes,
        "shift": args.shift,
        "alpha": args.alpha,
        "targets": args.targets,
    }
    results = []
    for target in args.targets:
        print(f"causal carry intervention: {target}", flush=True)
        results.append(_target_run(target, args))
    payload = {
        "schema_version": 1,
        "experiment": "causal_carry_intervention_suite",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "platform": platform.platform(),
        },
        "formulae": {
            "speck_factual": "x'=(ROR(x)+y) XOR k; y'=ROL(y) XOR x'",
            "speck_do_carry_zero": "x_cf=(ROR(x) XOR y) XOR k; y_cf=ROL(y) XOR x_cf",
            "speck_identity": "factual_next XOR counterfactual_next = (sum XOR xor) repeated in both words",
            "interpretation": "only modular-addition carry is intervened on; all other transition inputs/components are fixed",
        },
        "results": results,
        "scope_note": (
            "Known-state/known-key mechanism intervention. A low ablation p-value attributes this F8 statistic "
            "to modular-addition carry under the tested transition model; it is not key recovery or a PQC break."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source_hash = hashlib.sha256(args.output.read_bytes()).hexdigest()
    graph_stats = _build_causal(results, parameters, f"sha256:{source_hash}", args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({graph_stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
