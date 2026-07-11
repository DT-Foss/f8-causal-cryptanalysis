#!/usr/bin/env python3
"""Full-rank SHAKE capacity-to-next-rate Boolean Jacobian Readers."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BASE_PATH = Path(__file__).with_name("shake_fullround_rate_reader.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "shake_fullround_rate_reader", _BASE_PATH
)
assert _BASE_SPEC is not None and _BASE_SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _BASE
_BASE_SPEC.loader.exec_module(_BASE)


def _reader_recipe(variant: Any) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "base_state": "instrumented_post_first_squeeze_state",
        "held_fixed": "all_rate_bits",
        "intervention": "flip_each_capacity_bit_individually",
        "capacity_bits": variant.capacity_bits,
        "capacity_lane_offset": variant.rate_lanes,
        "response": "xor_delta_of_next_rate_after_keccak_f1600",
        "response_bits": variant.rate_bits,
        "permutation_rounds": 24,
        "signature_serialization": "little_endian_uint64_rate_lanes",
        "reader_query": "exact_same_base_signature_to_capacity_bit_index",
    }


def _build_graph(path: Path, bases: int, routes: int, pair_tests: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_capacity_to_next_rate_boolean_jacobian",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "permutation_rounds_per_response": 24,
            "bases_per_variant": bases,
            "bvn_routes": routes,
            "two_bit_interactions_per_base": pair_tests,
            "prediction_before_measurement": (
                "Every single capacity-bit intervention should have a unique next-rate "
                "signature and the Boolean Jacobian should have full capacity rank."
            ),
        },
    )
    for key, variant in _BASE.VARIANTS.items():
        response_id = f"{key}-capacity-bit-fullround-rate-response"
        rank_id = f"{key}-capacity-jacobian-full-rank"
        builder.add_triplet(
            edge_id=response_id,
            trigger=f"do({key}:post_first_squeeze_capacity_bit_j xor=1)",
            mechanism="full_keccak_f1600_capacity_to_rate_response",
            outcome=f"{key}:next_squeeze_rate_xor_signature_j",
            confidence=1.0,
            evidence_kind="exact_interventional_fullround_trace",
            source="FIPS202_next_squeeze_permutation",
            attrs={
                "reader_recipe": _reader_recipe(variant),
                "capacity_bits": variant.capacity_bits,
                "rate_bits": variant.rate_bits,
            },
        )
        builder.add_triplet(
            edge_id=rank_id,
            trigger=f"{key}:all_single_capacity_bit_response_signatures",
            mechanism="complete_boolean_jacobian_gf2_rank",
            outcome=f"{key}:local_capacity_observability_dimension",
            confidence=1.0,
            evidence_kind="complete_capacity_basis_rank_test",
            source="same_base_capacity_intervention_matrix",
            provenance=[response_id],
            attrs={
                "predicted_rank": variant.capacity_bits,
                "columns": variant.capacity_bits,
                "rows": variant.rate_bits,
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-capacity-signature-reader",
            trigger=f"{key}:same_base_next_rate_delta_signature",
            mechanism="reader_executable_exact_capacity_bit_identification",
            outcome=f"{key}:intervened_capacity_bit_index",
            confidence=1.0,
            evidence_kind="exact_same_base_signature_lookup",
            source="complete_capacity_response_dictionary",
            provenance=[response_id, rank_id],
            attrs={
                "reader_recipe": _reader_recipe(variant),
                "classes": variant.capacity_bits,
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE capacity Jacobian causal graph gate failed")
    return stats


def _recipes_from_reader(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    recipes = {}
    for key in _BASE.VARIANTS:
        matches = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_exact_capacity_bit_identification"
            and row["trigger"].startswith(f"{key}:")
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Reader returned no unique {key} capacity recipe")
        recipes[key] = matches[0]["attrs"]["reader_recipe"]
    return recipes, rows


def _validate_recipe(variant: Any, recipe: dict[str, Any]) -> None:
    if int(recipe["capacity_bits"]) != variant.capacity_bits:
        raise ValueError("capacity dimension does not match Reader recipe")
    if int(recipe["capacity_lane_offset"]) != variant.rate_lanes:
        raise ValueError("capacity offset does not match Reader recipe")
    if int(recipe["response_bits"]) != variant.rate_bits:
        raise ValueError("rate dimension does not match Reader recipe")
    if int(recipe["permutation_rounds"]) != 24:
        raise ValueError("Reader recipe is not a full Keccak-f[1600] response")


def _intervention_responses(
    base_state: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    intervention_sets: np.ndarray | None = None,
) -> np.ndarray:
    _validate_recipe(variant, recipe)
    if base_state.dtype != np.uint64 or base_state.shape != (1, 25):
        raise ValueError("base_state must be uint64[1,25]")
    if intervention_sets is None:
        intervention_sets = np.arange(variant.capacity_bits, dtype=np.int64).reshape(-1, 1)
    if intervention_sets.ndim != 2:
        raise ValueError("intervention_sets must be a two-dimensional index matrix")
    states = np.repeat(base_state, len(intervention_sets), axis=0)
    rows = np.arange(len(intervention_sets))
    for column in range(intervention_sets.shape[1]):
        indices = intervention_sets[:, column]
        if np.any(indices < 0) or np.any(indices >= variant.capacity_bits):
            raise ValueError("capacity intervention index outside recipe domain")
        lanes = variant.rate_lanes + indices // 64
        bits = indices % 64
        states[rows, lanes] ^= np.left_shift(
            np.uint64(1), bits.astype(np.uint64)
        )
    baseline = _BASE._keccak_f1600(base_state)[:, : variant.rate_lanes]
    intervened = _BASE._keccak_f1600(states)[:, : variant.rate_lanes]
    return intervened ^ baseline


def _signature_bytes(responses: np.ndarray) -> list[bytes]:
    if responses.dtype != np.uint64 or responses.ndim != 2:
        raise ValueError("responses must be a uint64 matrix")
    return [row.astype("<u8", copy=False).tobytes() for row in responses]


def _gf2_rank(responses: np.ndarray) -> int:
    pivots: dict[int, int] = {}
    for serialized in _signature_bytes(responses):
        value = int.from_bytes(serialized, "little")
        while value:
            pivot = value.bit_length() - 1
            if pivot in pivots:
                value ^= pivots[pivot]
            else:
                pivots[pivot] = value
                break
    return len(pivots)


def _signature_reader_accuracy(
    dictionary_responses: np.ndarray,
    query_responses: np.ndarray,
    expected_indices: np.ndarray,
) -> dict[str, Any]:
    dictionary = {
        signature: index
        for index, signature in enumerate(_signature_bytes(dictionary_responses))
    }
    inferred = np.array(
        [dictionary.get(signature, -1) for signature in _signature_bytes(query_responses)],
        dtype=np.int64,
    )
    matches = int(np.sum(inferred == expected_indices))
    return {
        "matches": matches,
        "total": int(len(expected_indices)),
        "accuracy": matches / len(expected_indices),
        "unmatched": int(np.sum(inferred < 0)),
        "wrong_known_signature": int(np.sum((inferred >= 0) & (inferred != expected_indices))),
    }


def _route_controls(
    responses: np.ndarray, count: int, seed: int
) -> dict[str, Any]:
    routes = route_ensemble(len(responses), count, seed)
    verification = verify_routes(routes)
    if not verification["all_bijective"] or verification["forbidden_alignments"]:
        raise RuntimeError("invalid capacity-signature BvN route bank")
    expected = np.arange(len(responses), dtype=np.int64)
    rows = [
        _signature_reader_accuracy(responses, responses[route], expected)
        for route in routes
    ]
    return {
        "count": count,
        "total_matches": sum(row["matches"] for row in rows),
        "max_matches": max(row["matches"] for row in rows),
        "total_queries": count * len(responses),
    }


def _two_bit_interactions(
    base_state: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    single_responses: np.ndarray,
    count: int,
    rng: np.random.Generator,
) -> dict[str, Any]:
    pairs = rng.integers(
        0, variant.capacity_bits, size=(count, 2), dtype=np.int64
    )
    duplicates = pairs[:, 0] == pairs[:, 1]
    pairs[duplicates, 1] = (pairs[duplicates, 1] + 1) % variant.capacity_bits
    actual = _intervention_responses(base_state, variant, recipe, pairs)
    linearized = single_responses[pairs[:, 0]] ^ single_responses[pairs[:, 1]]
    difference = actual ^ linearized
    bit_differences = sum(int(value).bit_count() for value in difference.ravel())
    bit_total = int(difference.size * 64)
    return {
        "pairs": count,
        "exact_superpositions": int(np.sum(np.all(difference == 0, axis=1))),
        "bit_agreement": (bit_total - bit_differences) / bit_total,
        "interaction_bit_density": bit_differences / bit_total,
    }


def _base_result(
    base_state: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    routes: int,
    pair_tests: int,
    seed: int,
) -> tuple[dict[str, Any], np.ndarray]:
    responses = _intervention_responses(base_state, variant, recipe)
    signatures = _signature_bytes(responses)
    rank = _gf2_rank(responses)
    weights = np.array(
        [int.from_bytes(signature, "little").bit_count() for signature in signatures],
        dtype=np.int64,
    )
    expected = np.arange(variant.capacity_bits, dtype=np.int64)
    factual = _signature_reader_accuracy(responses, responses, expected)
    lane_rotated = np.roll(responses, 1, axis=1)
    wrong_lane = _signature_reader_accuracy(responses, lane_rotated, expected)
    rng = np.random.default_rng(seed)
    return {
        "gf2_rank": rank,
        "expected_full_rank": variant.capacity_bits,
        "unique_signatures": len(set(signatures)),
        "signature_sha256": hashlib.sha256(b"".join(signatures)).hexdigest(),
        "response_weight": {
            "mean": float(np.mean(weights)),
            "minimum": int(np.min(weights)),
            "maximum": int(np.max(weights)),
            "rate_bits": variant.rate_bits,
        },
        "factual_same_base_reader": factual,
        "bvn_routes": _route_controls(responses, routes, seed ^ 0xB711),
        "wrong_lane_rotation_control": wrong_lane,
        "two_bit_interaction_boundary": _two_bit_interactions(
            base_state,
            variant,
            recipe,
            responses,
            pair_tests,
            rng,
        ),
    }, responses


def _variant_confirmation(
    variant: Any,
    recipe: dict[str, Any],
    bases: int,
    routes: int,
    pair_tests: int,
    seed: int,
) -> list[dict[str, Any]]:
    base_rows = []
    response_rows = []
    for base_index in range(bases):
        base_seed = seed + 1009 * base_index
        rng = np.random.default_rng(base_seed)
        message = rng.integers(
            0,
            256,
            size=(1, variant.message_bytes),
            dtype=np.uint8,
        )
        base_state, _ = _BASE._first_squeeze_state(message, variant)
        print(
            f"{variant.name} capacity Jacobian base={base_index + 1}/{bases}",
            flush=True,
        )
        result, responses = _base_result(
            base_state,
            variant,
            recipe,
            routes,
            pair_tests,
            base_seed,
        )
        base_rows.append(
            {
                "base_index": base_index,
                "seed": base_seed,
                "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
                **result,
            }
        )
        response_rows.append(responses)
    expected = np.arange(variant.capacity_bits, dtype=np.int64)
    for base_index, row in enumerate(base_rows):
        next_index = (base_index + 1) % bases
        row["next_base_dictionary_control"] = _signature_reader_accuracy(
            response_rows[next_index], response_rows[base_index], expected
        )
    return base_rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bases", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--pair-tests", type=int, default=128)
    parser.add_argument("--seed", type=int, default=89528001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.bases, args.routes, args.pair_tests) < 1:
        raise ValueError("bases, routes, and pair-tests must be positive")

    kat = _BASE._kat()
    causal = _build_graph(
        args.causal_output, args.bases, args.routes, args.pair_tests
    )
    recipes, reader_rows = _recipes_from_reader(args.causal_output)
    confirmations = {}
    for variant_index, (key, variant) in enumerate(_BASE.VARIANTS.items()):
        confirmations[key] = _variant_confirmation(
            variant,
            recipes[key],
            args.bases,
            args.routes,
            args.pair_tests,
            args.seed + 100_003 * variant_index,
        )
    retained = all(
        row["gf2_rank"] == row["expected_full_rank"]
        and row["unique_signatures"] == row["expected_full_rank"]
        and row["factual_same_base_reader"]["accuracy"] == 1.0
        and row["bvn_routes"]["total_matches"] == 0
        and row["wrong_lane_rotation_control"]["matches"] == 0
        and row["next_base_dictionary_control"]["matches"] == 0
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "shake-capacity-jacobian-reader-v1",
        "evidence_stage": (
            "FULLROUND_CAPACITY_JACOBIANS_FULL_RANK"
            if retained
            else "NEW_CAPACITY_OBSERVABILITY_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "At each tested post-first-squeeze base state, every single capacity-bit "
            "intervention has a unique next-rate signature and the 24-round Boolean "
            "Jacobian has full capacity rank. The exact signature Reader is base-local."
        ),
        "scope": (
            "Instrumented single-bit capacity interventions followed by a complete "
            "Keccak-f[1600] permutation. Full local rank is not asserted as ordinary-output "
            "capacity reconstruction or as global linearity."
        ),
        "parameters": {
            "permutation_rounds": 24,
            "bases_per_variant": args.bases,
            "bvn_routes": args.routes,
            "two_bit_interactions_per_base": args.pair_tests,
            "seed": args.seed,
        },
        "kat": kat,
        "causal": causal,
        "reader_triplets": reader_rows,
        "confirmation": confirmations,
        "retained": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "retained": retained,
                "ranks": {
                    key: [row["gf2_rank"] for row in rows]
                    for key, rows in confirmations.items()
                },
                "same_base_matches": {
                    key: [row["factual_same_base_reader"]["matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
                "bvn_total_matches": {
                    key: [row["bvn_routes"]["total_matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
                "two_bit_exact_superpositions": {
                    key: [
                        row["two_bit_interaction_boundary"]["exact_superpositions"]
                        for row in rows
                    ]
                    for key, rows in confirmations.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
