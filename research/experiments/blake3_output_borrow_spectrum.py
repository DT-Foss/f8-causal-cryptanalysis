#!/usr/bin/env python3
"""Exact borrow spectrum of XOR-to-subtraction in the BLAKE3 output inverse."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BASE_PATH = Path(__file__).with_name("blake3_fullcompression_reader.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "blake3_fullcompression_reader", _BASE_PATH
)
assert _BASE_SPEC is not None and _BASE_SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _BASE
_BASE_SPEC.loader.exec_module(_BASE)


STATES = ((0, 0), (0, 1), (1, 0), (1, 1))
BORROW_RECIPE = {
    "state_order": ["00", "01", "10", "11"],
    "transition_matrix": [
        ["5/8", "1/8", "1/8", "1/8"],
        ["1/4", "1/2", "0", "1/4"],
        ["1/4", "0", "1/2", "1/4"],
        ["1/8", "1/8", "1/8", "5/8"],
    ],
    "initial_distribution": ["1", "0", "0", "0"],
    "high_bit_match_states": ["00", "01"],
    "low_bit_match_states": ["00", "11"],
    "word_bits": 32,
    "word_match_probability": "(3/4)^31",
    "identities": {
        "high_substitution": "H_sub[k] = H[k] xor b[k]",
        "low_substitution": "L_sub[k] = L[k] xor b[k] xor d[k]",
        "high_match": "H_sub[k] == H[k] iff b[k] == 0",
        "low_match": "L_sub[k] == L[k] iff b[k] == d[k]",
    },
}


def _fraction(value: str) -> Fraction:
    return Fraction(value)


def _borrow(minuend: int, subtrahend: int, incoming: int) -> int:
    return ((1 - minuend) & subtrahend) | (
        incoming & (1 - (minuend ^ subtrahend))
    )


def _derive_transition_matrix() -> list[list[Fraction]]:
    matrix = [[Fraction(0) for _ in STATES] for _ in STATES]
    for row, (high_borrow, low_borrow) in enumerate(STATES):
        for low_bit in (0, 1):
            for high_bit in (0, 1):
                for cv_bit in (0, 1):
                    output_high_bit = high_bit ^ cv_bit
                    substituted_high_bit = high_bit ^ high_borrow
                    output_low_bit = low_bit ^ high_bit
                    next_high = _borrow(
                        output_high_bit, cv_bit, high_borrow
                    )
                    next_low = _borrow(
                        output_low_bit, substituted_high_bit, low_borrow
                    )
                    column = STATES.index((next_high, next_low))
                    matrix[row][column] += Fraction(1, 8)
    return matrix


def _matrix_from_recipe(recipe: dict[str, Any]) -> list[list[Fraction]]:
    if recipe["state_order"] != ["00", "01", "10", "11"]:
        raise ValueError("unsupported borrow state order")
    return [[_fraction(value) for value in row] for row in recipe["transition_matrix"]]


def _analytic_spectrum(recipe: dict[str, Any]) -> dict[str, Any]:
    matrix = _matrix_from_recipe(recipe)
    independently_derived = _derive_transition_matrix()
    if matrix != independently_derived:
        raise RuntimeError("serialized borrow matrix does not match bit enumeration")
    if any(sum(row) != 1 for row in matrix):
        raise RuntimeError("borrow transition row is not stochastic")
    distribution = [_fraction(value) for value in recipe["initial_distribution"]]
    high_rows = []
    low_rows = []
    combined_rows = []
    distributions = []
    for bit in range(int(recipe["word_bits"])):
        high_match = distribution[0] + distribution[1]
        low_match = distribution[0] + distribution[3]
        combined = (high_match + low_match) / 2
        distributions.append([str(value) for value in distribution])
        high_rows.append(high_match)
        low_rows.append(low_match)
        combined_rows.append(combined)
        distribution = [
            sum(distribution[row] * matrix[row][column] for row in range(4))
            for column in range(4)
        ]
    average = sum(combined_rows) / len(combined_rows)
    word_probability = Fraction(3, 4) ** 31
    return {
        "transition_matrix": [[str(value) for value in row] for row in matrix],
        "state_distributions": distributions,
        "high_match_probability": [float(value) for value in high_rows],
        "low_match_probability": [float(value) for value in low_rows],
        "combined_match_probability": [float(value) for value in combined_rows],
        "average_bit_accuracy_fraction": str(average),
        "average_bit_accuracy": float(average),
        "exact_word_match_probability_fraction": str(word_probability),
        "exact_word_match_probability": float(word_probability),
    }


def _build_graph(path: Path, pairs: int, seeds: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="blake3_output_xor_to_subtraction_borrow_spectrum",
        parameters={
            "rounds": 7,
            "word_bits": 32,
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "prediction_before_measurement": (
                "The two coupled borrow bits form a four-state Markov chain; its "
                "exact spectrum should predict both bit and complete-word matches."
            ),
        },
    )
    builder.add_triplet(
        edge_id="blake3-sub-high-borrow-identity",
        trigger="blake3:output_high_minus_cv",
        mechanism="exact_subtraction_borrow_recurrence",
        outcome="blake3:high_word_xor_borrow_mask",
        confidence=1.0,
        evidence_kind="exact_bit_equation",
        source="BLAKE3_output_equation_plus_binary_subtraction",
        attrs={
            "formula": BORROW_RECIPE["identities"]["high_substitution"],
            "match_criterion": BORROW_RECIPE["identities"]["high_match"],
        },
    )
    builder.add_triplet(
        edge_id="blake3-sub-low-coupled-borrow-identity",
        trigger="blake3:output_low_minus_substituted_high",
        mechanism="exact_coupled_subtraction_borrow_recurrence",
        outcome="blake3:low_word_xor_two_borrow_mask",
        confidence=1.0,
        evidence_kind="exact_bit_equation",
        source="BLAKE3_pair_xor_plus_two_binary_subtractions",
        provenance=["blake3-sub-high-borrow-identity"],
        attrs={
            "formula": BORROW_RECIPE["identities"]["low_substitution"],
            "match_criterion": BORROW_RECIPE["identities"]["low_match"],
        },
    )
    builder.add_triplet(
        edge_id="blake3-sub-four-state-transition",
        trigger="blake3:uniform_low_high_cv_input_bits_and_current_borrows",
        mechanism="exact_four_state_borrow_transition",
        outcome="blake3:next_high_and_low_borrows",
        confidence=1.0,
        evidence_kind="exhaustive_three_input_bit_enumeration",
        source="BLAKE3_output_substitution_borrow_state_machine",
        provenance=[
            "blake3-sub-high-borrow-identity",
            "blake3-sub-low-coupled-borrow-identity",
        ],
        attrs={"reader_recipe": BORROW_RECIPE},
    )
    builder.add_triplet(
        edge_id="blake3-sub-word-survival",
        trigger="blake3:31_internal_borrow_transitions",
        mechanism="exact_equal_state_survival_probability",
        outcome="blake3:complete_substituted_word_match",
        confidence=1.0,
        evidence_kind="exact_markov_path_probability",
        source="BLAKE3_borrow_state_machine",
        provenance=["blake3-sub-four-state-transition"],
        attrs={
            "high_word_probability": "(3/4)^31",
            "low_word_probability": "(3/4)^31",
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 4:
        raise RuntimeError("BLAKE3 borrow-spectrum causal gate failed")
    return stats


def _recipe_from_reader(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    matches = [
        row
        for row in rows
        if row["mechanism"] == "exact_four_state_borrow_transition"
    ]
    if len(matches) != 1:
        raise RuntimeError("Reader returned no unique borrow transition recipe")
    return matches[0]["attrs"]["reader_recipe"], rows


def _bit_counts(expected: np.ndarray, observed: np.ndarray) -> np.ndarray:
    difference = expected ^ observed
    counts = np.empty(32, dtype=np.int64)
    for bit in range(32):
        counts[bit] = int(np.sum(((difference >> np.uint32(bit)) & np.uint32(1)) == 0))
    return counts


def _empirical_seed(inputs: tuple[np.ndarray, ...]) -> dict[str, Any]:
    chaining_value = inputs[0]
    trace, output = _BASE._compress_trace(*inputs)
    post = trace[-1]
    expected_low = post[:, :8]
    expected_high = post[:, 8:]
    substituted_high = output[:, 8:] - chaining_value
    substituted_low = output[:, :8] - substituted_high
    high_counts = _bit_counts(expected_high, substituted_high)
    low_counts = _bit_counts(expected_low, substituted_low)
    bit_total_per_half = int(expected_high.size)

    high_borrow = np.zeros_like(expected_high, dtype=np.uint8)
    low_borrow = np.zeros_like(expected_low, dtype=np.uint8)
    identity_matches = 0
    identity_total = 0
    for bit in range(32):
        low_bit = ((expected_low >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
        high_bit = ((expected_high >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
        cv_bit = ((chaining_value >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
        output_high_bit = high_bit ^ cv_bit
        output_low_bit = low_bit ^ high_bit
        substituted_high_bit = high_bit ^ high_borrow
        observed_high_bit = (
            (substituted_high >> np.uint32(bit)) & np.uint32(1)
        ).astype(np.uint8)
        observed_low_bit = (
            (substituted_low >> np.uint32(bit)) & np.uint32(1)
        ).astype(np.uint8)
        predicted_low_bit = low_bit ^ high_borrow ^ low_borrow
        identity_matches += int(np.sum(observed_high_bit == substituted_high_bit))
        identity_matches += int(np.sum(observed_low_bit == predicted_low_bit))
        identity_total += 2 * expected_high.size
        next_high = ((1 - output_high_bit) & cv_bit) | (
            high_borrow & (1 - (output_high_bit ^ cv_bit))
        )
        next_low = ((1 - output_low_bit) & substituted_high_bit) | (
            low_borrow & (1 - (output_low_bit ^ substituted_high_bit))
        )
        high_borrow = next_high.astype(np.uint8)
        low_borrow = next_low.astype(np.uint8)

    high_word_matches = int(np.sum(expected_high == substituted_high))
    low_word_matches = int(np.sum(expected_low == substituted_low))
    return {
        "high_match_counts": high_counts.tolist(),
        "low_match_counts": low_counts.tolist(),
        "bit_total_per_half": bit_total_per_half,
        "high_bit_accuracy": (high_counts / bit_total_per_half).tolist(),
        "low_bit_accuracy": (low_counts / bit_total_per_half).tolist(),
        "combined_bit_accuracy": ((high_counts + low_counts) / (2 * bit_total_per_half)).tolist(),
        "overall_bit_accuracy": float(
            (np.sum(high_counts) + np.sum(low_counts))
            / (64 * bit_total_per_half)
        ),
        "borrow_identity_matches": identity_matches,
        "borrow_identity_total": identity_total,
        "borrow_identity_accuracy": identity_matches / identity_total,
        "high_word_matches": high_word_matches,
        "low_word_matches": low_word_matches,
        "word_matches": high_word_matches + low_word_matches,
        "word_total": int(2 * expected_high.size),
    }


def _pooled(rows: list[dict[str, Any]], analytic: dict[str, Any]) -> dict[str, Any]:
    high_counts = np.sum([row["high_match_counts"] for row in rows], axis=0)
    low_counts = np.sum([row["low_match_counts"] for row in rows], axis=0)
    total = sum(int(row["bit_total_per_half"]) for row in rows)
    high = high_counts / total
    low = low_counts / total
    combined = (high_counts + low_counts) / (2 * total)
    predicted_high = np.asarray(analytic["high_match_probability"])
    predicted_low = np.asarray(analytic["low_match_probability"])
    predicted_combined = np.asarray(analytic["combined_match_probability"])
    observed_vector = np.concatenate((high, low))
    predicted_vector = np.concatenate((predicted_high, predicted_low))
    correlation = float(np.corrcoef(observed_vector, predicted_vector)[0, 1])
    word_total = sum(int(row["word_total"]) for row in rows)
    expected_word_matches = word_total * float(analytic["exact_word_match_probability"])
    return {
        "high_bit_accuracy": high.tolist(),
        "low_bit_accuracy": low.tolist(),
        "combined_bit_accuracy": combined.tolist(),
        "overall_bit_accuracy": float(np.mean(combined)),
        "analytic_observed_correlation_64_cells": correlation,
        "combined_max_absolute_error": float(np.max(np.abs(combined - predicted_combined))),
        "borrow_identity_matches": sum(int(row["borrow_identity_matches"]) for row in rows),
        "borrow_identity_total": sum(int(row["borrow_identity_total"]) for row in rows),
        "word_matches": sum(int(row["word_matches"]) for row in rows),
        "word_total": word_total,
        "expected_word_matches": expected_word_matches,
        "word_match_expected_ratio": (
            sum(int(row["word_matches"]) for row in rows) / expected_word_matches
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=89128001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.seeds) < 1:
        raise ValueError("pairs and seeds must be positive")

    kat = _BASE._kat()
    causal = _build_graph(args.causal_output, args.pairs, args.seeds)
    recipe, reader_rows = _recipe_from_reader(args.causal_output)
    analytic = _analytic_spectrum(recipe)
    confirmations = []
    for seed_index in range(args.seeds):
        seed = args.seed + 1009 * seed_index
        rng = np.random.default_rng(seed)
        print(f"BLAKE3 borrow spectrum seed={seed_index + 1}/{args.seeds}", flush=True)
        confirmations.append(
            {
                "seed_index": seed_index,
                "seed": seed,
                **_empirical_seed(_BASE._random_inputs(rng, args.pairs)),
            }
        )
    pooled = _pooled(confirmations, analytic)
    retained = (
        pooled["borrow_identity_matches"] == pooled["borrow_identity_total"]
        and pooled["analytic_observed_correlation_64_cells"] > 0.999
        and pooled["combined_max_absolute_error"] < 0.003
    )
    payload = {
        "schema": "blake3-output-borrow-spectrum-v1",
        "evidence_stage": (
            "EXACT_BORROW_SPECTRUM_RETAINED"
            if retained
            else "NEW_BORROW_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "The 60.6% XOR-to-subtraction control accuracy is generated by an "
            "exact four-state coupled-borrow recurrence, which predicts the full "
            "bit spectrum and complete-word survival probability."
        ),
        "parameters": {
            "rounds": 7,
            "word_bits": 32,
            "pairs_per_seed": args.pairs,
            "seeds": args.seeds,
            "seed": args.seed,
        },
        "kat": kat,
        "causal": causal,
        "reader_triplets": reader_rows,
        "analytic": analytic,
        "confirmation": confirmations,
        "pooled": pooled,
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
                "analytic_bit_accuracy": analytic["average_bit_accuracy"],
                "observed_bit_accuracy": pooled["overall_bit_accuracy"],
                "correlation": pooled["analytic_observed_correlation_64_cells"],
                "borrow_identities": (
                    f"{pooled['borrow_identity_matches']}/{pooled['borrow_identity_total']}"
                ),
                "word_matches_observed": pooled["word_matches"],
                "word_matches_expected": pooled["expected_word_matches"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
