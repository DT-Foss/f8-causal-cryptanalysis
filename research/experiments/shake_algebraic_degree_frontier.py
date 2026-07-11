#!/usr/bin/env python3
"""Exact ANF degree and density frontier across full-round SHAKE traces."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_AFFINE_PATH = Path(__file__).with_name("shake_affine_hull_frontier.py")
_AFFINE_SPEC = importlib.util.spec_from_file_location(
    "shake_affine_hull_frontier_anf_base", _AFFINE_PATH
)
assert _AFFINE_SPEC is not None and _AFFINE_SPEC.loader is not None
_AFFINE = importlib.util.module_from_spec(_AFFINE_SPEC)
sys.modules[_AFFINE_SPEC.name] = _AFFINE
_AFFINE_SPEC.loader.exec_module(_AFFINE)

_PREFIX = _AFFINE._PREFIX
_BITSLICED = _AFFINE._BITSLICED
_BASE = _AFFINE._BASE
_WINDOW = _AFFINE._WINDOW
OUTPUT_COORDINATES = 128


def _candidate_output_bits(planes: np.ndarray) -> np.ndarray:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("candidate state must be uint64[P,25,64]")
    coordinate_words = np.ascontiguousarray(planes[:, :2, :]).reshape(
        len(planes), OUTPUT_COORDINATES
    )
    byte_view = coordinate_words.view(np.uint8).reshape(
        len(planes), OUTPUT_COORDINATES, 8
    )
    return np.unpackbits(byte_view, axis=2, bitorder="little").transpose(
        0, 2, 1
    ).reshape(len(planes) * 64, OUTPUT_COORDINATES)


def _mobius_transform(truth_table: np.ndarray) -> np.ndarray:
    if truth_table.dtype != np.uint8 and truth_table.dtype != np.bool_:
        raise ValueError("truth table must be Boolean/uint8")
    if truth_table.ndim != 2:
        raise ValueError("truth table must have shape [assignments,coordinates]")
    assignments = len(truth_table)
    window_bits = assignments.bit_length() - 1
    if assignments != 1 << window_bits:
        raise ValueError("truth table assignment count must be a power of two")
    coefficients = truth_table.astype(np.uint8, copy=True)
    for variable in range(window_bits):
        step = 1 << variable
        blocks = coefficients.reshape(-1, step * 2, coefficients.shape[1])
        blocks[:, step:, :] ^= blocks[:, :step, :]
    return coefficients


def _anf_statistics(planes: np.ndarray, window_bits: int) -> dict[str, Any]:
    truth_table = _candidate_output_bits(planes)
    if len(truth_table) != 1 << window_bits:
        raise ValueError("candidate truth table does not match window width")
    coefficients = _mobius_transform(truth_table)
    monomial_weights = np.fromiter(
        (index.bit_count() for index in range(1 << window_bits)),
        dtype=np.uint8,
        count=1 << window_bits,
    )
    degree_by_coordinate = np.max(
        np.where(coefficients != 0, monomial_weights[:, None], 0), axis=0
    )
    monomial_count_by_coordinate = np.sum(coefficients, axis=0, dtype=np.int64)
    zero_polynomials = int(np.count_nonzero(monomial_count_by_coordinate == 0))
    degree_values, degree_counts = np.unique(degree_by_coordinate, return_counts=True)
    random_mean = (1 << window_bits) / 2.0
    random_coordinate_sd = math.sqrt((1 << window_bits) / 4.0)
    random_mean_sd = random_coordinate_sd / math.sqrt(OUTPUT_COORDINATES)
    full_degree_count = int(np.count_nonzero(degree_by_coordinate == window_bits))
    return {
        "window_bits": window_bits,
        "assignments": 1 << window_bits,
        "output_coordinates": OUTPUT_COORDINATES,
        "zero_polynomials": zero_polynomials,
        "maximum_degree": int(np.max(degree_by_coordinate)),
        "degree_histogram": {
            str(int(degree)): int(count)
            for degree, count in zip(degree_values, degree_counts, strict=True)
        },
        "degree_by_coordinate": [int(value) for value in degree_by_coordinate],
        "full_degree_coordinate_count": full_degree_count,
        "random_expected_full_degree_coordinates": OUTPUT_COORDINATES / 2.0,
        "full_degree_count_z": (
            (full_degree_count - OUTPUT_COORDINATES / 2.0)
            / math.sqrt(OUTPUT_COORDINATES / 4.0)
        ),
        "monomial_count_by_coordinate": [
            int(value) for value in monomial_count_by_coordinate
        ],
        "mean_monomials": float(np.mean(monomial_count_by_coordinate)),
        "standard_deviation_monomials": float(
            np.std(monomial_count_by_coordinate)
        ),
        "random_expected_mean_monomials": random_mean,
        "random_expected_coordinate_sd": random_coordinate_sd,
        "mean_monomial_count_z": (
            float(np.mean(monomial_count_by_coordinate)) - random_mean
        )
        / random_mean_sd,
        "coefficient_density": float(np.mean(coefficients)),
        "truth_table_one_density": float(np.mean(truth_table)),
        "anf_sha256": hashlib.sha256(coefficients.tobytes()).hexdigest(),
    }


def _mobius_gate() -> dict[str, Any]:
    assignments = np.arange(8, dtype=np.uint8)
    x0 = assignments & 1
    x1 = (assignments >> 1) & 1
    x2 = (assignments >> 2) & 1
    truth = np.column_stack(
        [
            np.ones(8, dtype=np.uint8),
            x0,
            x0 & x1,
            (x0 & x1 & x2) ^ x2,
        ]
    )
    coefficients = _mobius_transform(truth)
    weights = np.array([index.bit_count() for index in range(8)], dtype=np.uint8)
    degrees = np.max(np.where(coefficients, weights[:, None], 0), axis=0)
    expected = [0, 1, 2, 3]
    if degrees.tolist() != expected:
        raise RuntimeError("ANF Mobius gate failed")
    return {
        "functions": 4,
        "assignments": 8,
        "expected_degrees": expected,
        "observed_degrees": degrees.tolist(),
        "exact_match": True,
    }


def _build_graph(path: Path, window_bits: int, observed_rounds: list[int]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_algebraic_degree_frontier",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "output_coordinates": OUTPUT_COORDINATES,
            "observed_rounds": observed_rounds,
            "prediction_before_measurement": (
                "Exact Mobius transforms should localize the round at which the "
                "restricted SHAKE coordinate functions reach full algebraic degree "
                "and random-like coefficient density."
            ),
        },
    )
    for key in _BASE.VARIANTS:
        truth_id = f"{key}-anf-truth-space"
        builder.add_triplet(
            edge_id=truth_id,
            trigger=f"{key}:complete_{window_bits}_coordinate_truth_space",
            mechanism="exact_round_indexed_first_128_rate_truth_tables",
            outcome=f"{key}:boolean_coordinate_functions",
            confidence=1.0,
            evidence_kind="all_2^k_assignments",
            source="bit_sliced_keccak_round_trace",
            attrs={"rounds": observed_rounds},
        )
        builder.add_triplet(
            edge_id=f"{key}-anf-reader",
            trigger=f"{key}:boolean_coordinate_functions",
            mechanism="reader_exact_fast_mobius_transform",
            outcome=f"{key}:degree_and_monomial_density_frontier",
            confidence=1.0,
            evidence_kind="complete_algebraic_normal_form",
            source="GF2_subset_transform",
            provenance=[truth_id],
            attrs={
                "reader_recipe": {
                    "operation": "in_place_GF2_Mobius_transform",
                    "variable_order": "capacity_window_little_endian",
                    "output_coordinates": OUTPUT_COORDINATES,
                    "statistics": [
                        "degree_histogram",
                        "monomial_density",
                        "random_baseline_z",
                    ],
                }
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 4:
        raise RuntimeError("SHAKE ANF causal graph gate failed")
    return stats


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    observed_rounds: list[int],
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    positions = _WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xB175
    )
    template = _WINDOW._clear_window(base_state, variant, positions)
    state = _BITSLICED._candidate_planes(
        _BITSLICED._template_planes(template),
        variant,
        positions,
        np.arange(1 << (window_bits - 6), dtype=np.uint64),
    )
    observations = []
    for round_number in range(25):
        if round_number in observed_rounds:
            observations.append(
                {"round": round_number, **_anf_statistics(state, window_bits)}
            )
        if round_number < 24:
            state = _PREFIX._keccak_round_bitsliced(state, round_number)
    return {
        "seed": seed,
        "variant": variant.name,
        "window_bits": window_bits,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
        "observations": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--rounds", default="0,1,2,3,4,5,6,8,12,24")
    parser.add_argument("--seed", type=int, default=89784001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if args.window_bits < 6 or args.window_bits > 18:
        raise ValueError("algebraic frontier window must be in 6..18")
    rounds = _AFFINE._parse_int_list(args.rounds, 0, 24)
    if 24 not in rounds:
        raise ValueError("observed rounds must include 24")
    mobius_gate = _mobius_gate()
    conversion_gate = _AFFINE._conversion_gate(args.seed ^ 0xAFF128)
    round_gate = _PREFIX._round_composition_gate(args.seed ^ 0x24F1600)
    causal = _build_graph(args.causal_output, args.window_bits, rounds)
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        print(f"{variant.name} algebraic degree frontier", flush=True)
        trials.append(
            _trial(
                variant,
                args.window_bits,
                args.seed + 100_003 * variant_index,
                rounds,
            )
        )
    fullround = {
        row["variant"]: next(
            observation for observation in row["observations"] if observation["round"] == 24
        )
        for row in trials
    }
    payload = {
        "schema": "shake-algebraic-degree-frontier-v1",
        "evidence_stage": "FULLROUND_ALGEBRAIC_SATURATION_FRONTIER_MAPPED",
        "result": (
            "Complete ANFs localize the round at which restricted SHAKE rate "
            "coordinates attain full degree and random-like monomial density."
        ),
        "scope": (
            "Known-complement capacity window; exact ANFs of the first 128 rate "
            "coordinates over every assignment."
        ),
        "parameters": {
            "window_bits": args.window_bits,
            "output_coordinates": OUTPUT_COORDINATES,
            "observed_rounds": rounds,
            "seed": args.seed,
        },
        "mobius_gate": mobius_gate,
        "conversion_gate": conversion_gate,
        "round_composition_gate": round_gate,
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trials": trials,
        "fullround": fullround,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "frontier": {
                    row["variant"]: {
                        str(observation["round"]): {
                            "maximum_degree": observation["maximum_degree"],
                            "full_degree_coordinates": observation[
                                "full_degree_coordinate_count"
                            ],
                            "mean_monomials": observation["mean_monomials"],
                        }
                        for observation in row["observations"]
                    }
                    for row in trials
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
