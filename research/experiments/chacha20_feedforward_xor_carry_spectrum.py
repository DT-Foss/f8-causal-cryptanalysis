#!/usr/bin/env python3
"""Exact carry spectrum of XOR peeling at the ChaCha20 feed-forward endpoint."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BASE_PATH = Path(__file__).with_name("chacha20_fullround_feedforward_reader.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "chacha20_fullround_feedforward_reader", _BASE_PATH
)
assert _BASE_SPEC is not None and _BASE_SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _BASE
_BASE_SPEC.loader.exec_module(_BASE)


CARRY_RECIPE = {
    "word_bits": 32,
    "initial_carry_probability": 0.0,
    "bit_match_probability": "1-p_k",
    "conditional_updates": {
        "addend_bit_0": "p_(k+1)=p_k/2",
        "addend_bit_1": "p_(k+1)=(1+p_k)/2",
    },
    "exact_bit_identity": "xor_peeled[k] = core[k] xor carry[k]",
    "exact_match_criterion": "xor_peeled[k] == core[k] iff carry[k] == 0",
    "conditional_word_match_probability": (
        "2^(-popcount(initial_word & 0x7fffffff))"
    ),
}


def _build_graph(path: Path, pairs: int, seeds: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_feedforward_xor_peeling_carry_spectrum",
        parameters={
            "rounds": 20,
            "word_bits": 32,
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "prediction_before_measurement": (
                "XOR peeling differs from exact subtraction only by the incoming "
                "feed-forward carry; conditioning on each actual initial word should "
                "predict the complete 16x32 spectrum."
            ),
        },
    )
    builder.add_triplet(
        edge_id="chacha20-xor-peel-carry-identity",
        trigger="chacha20:core_plus_initial_feedforward_then_xor_initial",
        mechanism="exact_feedforward_carry_mask",
        outcome="chacha20:core_xor_incoming_carry_per_bit",
        confidence=1.0,
        evidence_kind="exact_binary_addition_equation",
        source="ChaCha20_feedforward_addition",
        attrs={
            "identity": CARRY_RECIPE["exact_bit_identity"],
            "match_criterion": CARRY_RECIPE["exact_match_criterion"],
        },
    )
    builder.add_triplet(
        edge_id="chacha20-xor-peel-conditional-spectrum",
        trigger="chacha20:initial_word_bit_pattern",
        mechanism="reader_executable_conditional_carry_recurrence",
        outcome="chacha20:per_lane_per_bit_xor_peeling_accuracy",
        confidence=1.0,
        evidence_kind="exact_conditional_carry_model",
        source="ChaCha20_feedforward_addend_conditioning",
        provenance=["chacha20-xor-peel-carry-identity"],
        attrs={"reader_recipe": CARRY_RECIPE},
    )
    builder.add_triplet(
        edge_id="chacha20-xor-peel-word-survival",
        trigger="chacha20:initial_word_low31_popcount",
        mechanism="exact_no_carry_path_probability",
        outcome="chacha20:complete_xor_peeled_word_match",
        confidence=1.0,
        evidence_kind="exact_conditional_path_probability",
        source="ChaCha20_feedforward_carry_recurrence",
        provenance=["chacha20-xor-peel-conditional-spectrum"],
        attrs={
            "formula": CARRY_RECIPE["conditional_word_match_probability"],
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("ChaCha20 carry-spectrum causal gate failed")
    return stats


def _recipe_from_reader(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    matches = [
        row
        for row in rows
        if row["mechanism"] == "reader_executable_conditional_carry_recurrence"
    ]
    if len(matches) != 1:
        raise RuntimeError("Reader returned no unique ChaCha20 carry recipe")
    return matches[0]["attrs"]["reader_recipe"], rows


def _conditional_prediction(
    initial: np.ndarray, recipe: dict[str, Any]
) -> tuple[np.ndarray, float]:
    if initial.dtype != np.uint32 or initial.ndim != 2 or initial.shape[1] != 16:
        raise ValueError("initial must be uint32[N,16]")
    if int(recipe["word_bits"]) != 32:
        raise ValueError("unsupported ChaCha carry word width")
    carry_probability = np.full(
        initial.shape,
        float(recipe["initial_carry_probability"]),
        dtype=np.float64,
    )
    predicted = np.empty((16, 32), dtype=np.float64)
    for bit in range(32):
        predicted[:, bit] = np.mean(1.0 - carry_probability, axis=0)
        addend_bit = (
            (initial >> np.uint32(bit)) & np.uint32(1)
        ).astype(np.float64)
        carry_probability = 0.5 * carry_probability + 0.5 * addend_bit
    low31_popcounts = np.fromiter(
        (
            int(value & np.uint32(0x7FFFFFFF)).bit_count()
            for value in initial.ravel()
        ),
        dtype=np.int16,
        count=initial.size,
    )
    expected_word_matches = float(np.sum(2.0 ** (-low31_popcounts)))
    return predicted, expected_word_matches


def _empirical_seed(
    inputs: tuple[np.ndarray, np.ndarray, np.ndarray],
    recipe: dict[str, Any],
) -> dict[str, Any]:
    initial, core, output = _BASE._block_trace(*inputs, rounds=20)
    xor_peeled = output ^ initial
    difference = xor_peeled ^ core
    observed_counts = np.empty((16, 32), dtype=np.int64)
    carry = np.zeros_like(initial, dtype=np.uint8)
    identity_matches = 0
    identity_total = 0
    for bit in range(32):
        observed_counts[:, bit] = np.sum(
            ((difference >> np.uint32(bit)) & np.uint32(1)) == 0,
            axis=0,
        )
        core_bit = ((core >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
        addend_bit = (
            (initial >> np.uint32(bit)) & np.uint32(1)
        ).astype(np.uint8)
        output_bit = ((output >> np.uint32(bit)) & np.uint32(1)).astype(np.uint8)
        peeled_bit = (
            (xor_peeled >> np.uint32(bit)) & np.uint32(1)
        ).astype(np.uint8)
        predicted_output_bit = core_bit ^ addend_bit ^ carry
        predicted_peeled_bit = core_bit ^ carry
        identity_matches += int(np.sum(output_bit == predicted_output_bit))
        identity_matches += int(np.sum(peeled_bit == predicted_peeled_bit))
        identity_total += 2 * initial.size
        carry = (
            (core_bit & addend_bit)
            | (carry & (core_bit ^ addend_bit))
        ).astype(np.uint8)
    predicted, expected_word_matches = _conditional_prediction(initial, recipe)
    word_matches = int(np.sum(xor_peeled == core))
    return {
        "observed_match_counts": observed_counts.tolist(),
        "predicted_accuracy": predicted.tolist(),
        "rows": len(initial),
        "observed_accuracy": (observed_counts / len(initial)).tolist(),
        "overall_observed_bit_accuracy": float(np.mean(observed_counts / len(initial))),
        "overall_predicted_bit_accuracy": float(np.mean(predicted)),
        "carry_identity_matches": identity_matches,
        "carry_identity_total": identity_total,
        "carry_identity_accuracy": identity_matches / identity_total,
        "word_matches": word_matches,
        "word_total": int(initial.size),
        "expected_word_matches": expected_word_matches,
    }


def _pooled(rows: list[dict[str, Any]]) -> dict[str, Any]:
    observed_counts = np.sum([row["observed_match_counts"] for row in rows], axis=0)
    predicted_weighted = np.sum(
        [np.asarray(row["predicted_accuracy"]) * int(row["rows"]) for row in rows],
        axis=0,
    )
    total_rows = sum(int(row["rows"]) for row in rows)
    observed = observed_counts / total_rows
    predicted = predicted_weighted / total_rows
    wrong_lane_prediction = np.roll(predicted, 1, axis=0)
    correlation = float(np.corrcoef(observed.ravel(), predicted.ravel())[0, 1])
    wrong_lane_correlation = float(
        np.corrcoef(observed.ravel(), wrong_lane_prediction.ravel())[0, 1]
    )
    rmse = float(np.sqrt(np.mean((observed - predicted) ** 2)))
    wrong_lane_rmse = float(
        np.sqrt(np.mean((observed - wrong_lane_prediction) ** 2))
    )
    expected_word_matches = sum(float(row["expected_word_matches"]) for row in rows)
    word_matches = sum(int(row["word_matches"]) for row in rows)
    return {
        "observed_accuracy": observed.tolist(),
        "predicted_accuracy": predicted.tolist(),
        "overall_observed_bit_accuracy": float(np.mean(observed)),
        "overall_predicted_bit_accuracy": float(np.mean(predicted)),
        "analytic_observed_correlation_512_cells": correlation,
        "wrong_lane_prediction_correlation": wrong_lane_correlation,
        "rmse": rmse,
        "wrong_lane_prediction_rmse": wrong_lane_rmse,
        "maximum_absolute_error": float(np.max(np.abs(observed - predicted))),
        "carry_identity_matches": sum(int(row["carry_identity_matches"]) for row in rows),
        "carry_identity_total": sum(int(row["carry_identity_total"]) for row in rows),
        "word_matches": word_matches,
        "word_total": sum(int(row["word_total"]) for row in rows),
        "expected_word_matches": expected_word_matches,
        "word_match_expected_ratio": word_matches / expected_word_matches,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=89328001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.seeds) < 1:
        raise ValueError("pairs and seeds must be positive")

    kat = _BASE._kat()
    causal = _build_graph(args.causal_output, args.pairs, args.seeds)
    recipe, reader_rows = _recipe_from_reader(args.causal_output)
    confirmations = []
    for seed_index in range(args.seeds):
        seed = args.seed + 1009 * seed_index
        rng = np.random.default_rng(seed)
        print(f"ChaCha20 XOR-peeling carry seed={seed_index + 1}/{args.seeds}", flush=True)
        confirmations.append(
            {
                "seed_index": seed_index,
                "seed": seed,
                **_empirical_seed(_BASE._fixed_key_inputs(rng, args.pairs), recipe),
            }
        )
    pooled = _pooled(confirmations)
    retained = (
        pooled["carry_identity_matches"] == pooled["carry_identity_total"]
        and pooled["analytic_observed_correlation_512_cells"] > 0.999
        and pooled["rmse"] < 0.004
        and pooled["wrong_lane_prediction_correlation"] < 0.8
    )
    payload = {
        "schema": "chacha20-feedforward-xor-carry-spectrum-v1",
        "evidence_stage": (
            "FULLROUND_CONDITIONAL_CARRY_SPECTRUM_RETAINED"
            if retained
            else "NEW_CARRY_REPRESENTATION_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "XOR peeling of the ChaCha20 feed-forward output equals the round-20 "
            "core masked by the exact incoming-carry field. Conditioning on each "
            "initial word predicts the complete 16x32 accuracy spectrum and whole-word survival."
        ),
        "parameters": {
            "rounds": 20,
            "word_bits": 32,
            "pairs_per_seed": args.pairs,
            "seeds": args.seeds,
            "seed": args.seed,
        },
        "kat": kat,
        "causal": causal,
        "reader_triplets": reader_rows,
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
                "observed_bit_accuracy": pooled["overall_observed_bit_accuracy"],
                "predicted_bit_accuracy": pooled["overall_predicted_bit_accuracy"],
                "correlation": pooled["analytic_observed_correlation_512_cells"],
                "wrong_lane_correlation": pooled["wrong_lane_prediction_correlation"],
                "carry_identities": (
                    f"{pooled['carry_identity_matches']}/{pooled['carry_identity_total']}"
                ),
                "word_matches_observed": pooled["word_matches"],
                "word_matches_expected": pooled["expected_word_matches"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
