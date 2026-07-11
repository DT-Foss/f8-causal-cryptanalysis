#!/usr/bin/env python3
"""Exact Boolean-intervention influence frontier for SHAKE state windows."""
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


_ANF_PATH = Path(__file__).with_name("shake_algebraic_degree_frontier.py")
_ANF_SPEC = importlib.util.spec_from_file_location(
    "shake_algebraic_degree_frontier_influence_base", _ANF_PATH
)
assert _ANF_SPEC is not None and _ANF_SPEC.loader is not None
_ANF = importlib.util.module_from_spec(_ANF_SPEC)
sys.modules[_ANF_SPEC.name] = _ANF
_ANF_SPEC.loader.exec_module(_ANF)

_BASE = _ANF._BASE
_BITSLICED = _ANF._BITSLICED
_PREFIX = _ANF._PREFIX
_WINDOW = _ANF._WINDOW
STATE_COORDINATES = 1600


def _lane_truth_table(lane_planes: np.ndarray) -> np.ndarray:
    if lane_planes.dtype != np.uint64 or lane_planes.ndim != 2:
        raise ValueError("lane planes must be uint64[packs,64]")
    assignments = len(lane_planes) * 64
    if assignments < 2 or assignments & (assignments - 1):
        raise ValueError("candidate count must be a power of two")
    byte_view = np.ascontiguousarray(lane_planes).view(np.uint8).reshape(
        len(lane_planes), 64, 8
    )
    return np.unpackbits(byte_view, axis=2, bitorder="little").transpose(
        0, 2, 1
    ).reshape(assignments, 64)


def _influence_counts(truth_table: np.ndarray) -> np.ndarray:
    if truth_table.dtype not in (np.dtype(np.uint8), np.dtype(np.bool_)):
        raise ValueError("truth table must be Boolean/uint8")
    if truth_table.ndim != 2:
        raise ValueError("truth table must have shape [assignments,coordinates]")
    assignments = len(truth_table)
    window_bits = assignments.bit_length() - 1
    if assignments != 1 << window_bits:
        raise ValueError("truth table assignment count must be a power of two")
    counts = np.zeros((window_bits, truth_table.shape[1]), dtype=np.uint32)
    for variable in range(window_bits):
        step = 1 << variable
        blocks = truth_table.reshape(-1, 2 * step, truth_table.shape[1])
        counts[variable] = np.count_nonzero(
            blocks[:, :step] != blocks[:, step:], axis=(0, 1)
        )
    return counts


def _influence_gate() -> dict[str, Any]:
    assignments = np.arange(8, dtype=np.uint8)
    x0 = assignments & 1
    x1 = (assignments >> 1) & 1
    truth = np.column_stack(
        [
            np.zeros(8, dtype=np.uint8),
            x0,
            x0 ^ x1,
            x0 & x1,
        ]
    )
    observed = _influence_counts(truth).tolist()
    expected = [
        [0, 4, 4, 2],
        [0, 0, 4, 2],
        [0, 0, 0, 0],
    ]
    if observed != expected:
        raise RuntimeError("Boolean influence gate failed")
    return {
        "functions": ["zero", "x0", "x0_xor_x1", "x0_and_x1"],
        "paired_assignments_per_variable": 4,
        "expected_counts": expected,
        "observed_counts": observed,
        "exact_match": True,
    }


def _cell(counts: np.ndarray, flat_index: int) -> dict[str, int]:
    variable, coordinate = np.unravel_index(flat_index, counts.shape)
    return {
        "window_variable": int(variable),
        "state_coordinate": int(coordinate),
        "lane": int(coordinate // 64),
        "bit": int(coordinate % 64),
        "paired_changes": int(counts[variable, coordinate]),
    }


def _state_influence_statistics(
    planes: np.ndarray, window_bits: int
) -> dict[str, Any]:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("candidate state must be uint64[packs,25,64]")
    if len(planes) * 64 != 1 << window_bits:
        raise ValueError("candidate state does not match window width")
    counts = np.zeros((window_bits, STATE_COORDINATES), dtype=np.uint32)
    for lane in range(25):
        counts[:, lane * 64 : (lane + 1) * 64] = _influence_counts(
            _lane_truth_table(planes[:, lane, :])
        )
    paired_assignments = 1 << (window_bits - 1)
    nonzero = counts != 0
    support = np.sum(nonzero, axis=0, dtype=np.int16)
    influences = counts.astype(np.float64) / paired_assignments
    nonzero_values = influences[nonzero]
    support_values, support_counts = np.unique(support, return_counts=True)
    minimum_flat = int(np.argmin(np.where(nonzero, counts, paired_assignments + 1)))
    maximum_flat = int(np.argmax(counts))
    quantiles = np.quantile(nonzero_values, [0.0, 0.25, 0.5, 0.75, 1.0])
    return {
        "window_bits": window_bits,
        "assignments": 1 << window_bits,
        "paired_assignments_per_cell": paired_assignments,
        "state_coordinates": STATE_COORDINATES,
        "intervention_cells": int(counts.size),
        "nonzero_intervention_cells": int(np.count_nonzero(nonzero)),
        "zero_intervention_cells": int(counts.size - np.count_nonzero(nonzero)),
        "fully_coupled_coordinates": int(np.count_nonzero(support == window_bits)),
        "coordinate_support_histogram": {
            str(int(value)): int(count)
            for value, count in zip(support_values, support_counts, strict=True)
        },
        "minimum_nonzero_cell": _cell(counts, minimum_flat),
        "maximum_cell": _cell(counts, maximum_flat),
        "nonzero_influence_quantiles": {
            key: float(value)
            for key, value in zip(
                ("minimum", "q25", "median", "q75", "maximum"),
                quantiles,
                strict=True,
            )
        },
        "mean_influence_all_cells": float(np.mean(influences)),
        "mean_influence_nonzero_cells": float(np.mean(nonzero_values)),
        "mean_absolute_deviation_from_half_all_cells": float(
            np.mean(np.abs(influences - 0.5))
        ),
        "maximum_absolute_deviation_from_half": float(
            np.max(np.abs(influences - 0.5))
        ),
        "cells_within_0_02_of_half": int(
            np.count_nonzero(np.abs(influences - 0.5) <= 0.02)
        ),
        "per_variable": [
            {
                "window_variable": variable,
                "affected_coordinates": int(np.count_nonzero(nonzero[variable])),
                "mean_influence": float(np.mean(influences[variable])),
                "minimum_influence": float(np.min(influences[variable])),
                "maximum_influence": float(np.max(influences[variable])),
            }
            for variable in range(window_bits)
        ],
        "influence_count_matrix_sha256": hashlib.sha256(
            counts.astype("<u4", copy=False).tobytes()
        ).hexdigest(),
        "coordinate_support_sha256": hashlib.sha256(
            support.astype("<u2", copy=False).tobytes()
        ).hexdigest(),
    }


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
        variant.capacity_bits, window_bits, seed ^ 0x1F1E2D3C
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
                {
                    "round": round_number,
                    **_state_influence_statistics(state, window_bits),
                }
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


def _aggregate(trials: list[dict[str, Any]], rounds: list[int]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for variant in sorted({row["variant"] for row in trials}):
        variant_trials = [row for row in trials if row["variant"] == variant]
        per_round = {}
        for round_number in rounds:
            observations = [
                next(item for item in row["observations"] if item["round"] == round_number)
                for row in variant_trials
            ]
            coupled = [item["fully_coupled_coordinates"] for item in observations]
            nonzero = [item["nonzero_intervention_cells"] for item in observations]
            deviations = [
                item["maximum_absolute_deviation_from_half"] for item in observations
            ]
            per_round[str(round_number)] = {
                "trials": len(observations),
                "fully_coupled_coordinates_min": min(coupled),
                "fully_coupled_coordinates_max": max(coupled),
                "nonzero_intervention_cells_min": min(nonzero),
                "nonzero_intervention_cells_max": max(nonzero),
                "maximum_absolute_deviation_from_half_max": max(deviations),
                "all_to_all_in_every_trial": all(
                    value == STATE_COORDINATES for value in coupled
                ),
            }
        result[variant] = per_round
    return result


def _build_graph(
    path: Path, window_bits: int, observed_rounds: list[int], seeds: int
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_boolean_influence_frontier",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "observed_rounds": observed_rounds,
            "seeds_per_variant": seeds,
            "state_coordinates": STATE_COORDINATES,
            "prediction_before_measurement": (
                "The sparse R3 ANFs may already connect nearly every window "
                "coordinate to every state coordinate, with complete balanced "
                "Boolean intervention influence appearing by R4 or R5."
            ),
        },
    )
    for key in _BASE.VARIANTS:
        truth_id = f"{key}-complete-window-state-traces"
        matrix_id = f"{key}-boolean-intervention-matrices"
        builder.add_triplet(
            edge_id=truth_id,
            trigger=f"{key}:complete_{window_bits}_coordinate_truth_spaces",
            mechanism="exact_round_indexed_full_state_truth_tables",
            outcome=f"{key}:all_1600_boolean_coordinate_functions",
            confidence=1.0,
            evidence_kind="all_2^k_assignments",
            source="bit_sliced_keccak_round_trace",
            attrs={"rounds": observed_rounds, "seeds": seeds},
        )
        builder.add_triplet(
            edge_id=matrix_id,
            trigger=f"{key}:all_boolean_coordinate_functions",
            mechanism="reader_pair_every_assignment_under_each_single_bit_intervention",
            outcome=f"{key}:exact_window_to_state_influence_matrices",
            confidence=1.0,
            evidence_kind="complete_boolean_derivatives",
            source="GF2_single_coordinate_interventions",
            provenance=[truth_id],
            attrs={
                "reader_recipe": {
                    "operation": "pair_x_with_x_xor_basis_vector",
                    "paired_assignments_per_cell": 1 << (window_bits - 1),
                    "cells_per_observation": window_bits * STATE_COORDINATES,
                }
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-coupling-frontier",
            trigger=f"{key}:exact_window_to_state_influence_matrices",
            mechanism="reader_count_nonzero_support_and_influence_balance",
            outcome=f"{key}:all_to_all_coupling_round_frontier",
            confidence=1.0,
            evidence_kind="complete_matrix_support_and_counts",
            source="serialized_influence_matrix_hashes",
            provenance=[matrix_id],
            attrs={
                "statistics": [
                    "fully_coupled_coordinates",
                    "support_histogram",
                    "influence_quantiles",
                    "deviation_from_half",
                ]
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE Boolean influence causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--rounds", default="0,1,2,3,4,5,24")
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--seed", type=int, default=89795001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if args.window_bits < 6 or args.window_bits > 18:
        raise ValueError("Boolean influence window must be in 6..18")
    if args.seeds < 1:
        raise ValueError("seed count must be positive")
    rounds = _ANF._AFFINE._parse_int_list(args.rounds, 0, 24)
    if 24 not in rounds:
        raise ValueError("observed rounds must include 24")
    influence_gate = _influence_gate()
    conversion_gate = _ANF._AFFINE._conversion_gate(args.seed ^ 0x1F128)
    round_gate = _PREFIX._round_composition_gate(args.seed ^ 0x24F1600)
    causal = _build_graph(args.causal_output, args.window_bits, rounds, args.seeds)
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        for seed_index in range(args.seeds):
            seed = args.seed + 100_003 * variant_index + 1009 * seed_index
            print(
                f"{variant.name} Boolean influence frontier seed={seed}", flush=True
            )
            trials.append(_trial(variant, args.window_bits, seed, rounds))
    aggregate = _aggregate(trials, rounds)
    first_all_to_all = {
        variant: min(
            int(round_number)
            for round_number, row in per_round.items()
            if row["all_to_all_in_every_trial"]
        )
        for variant, per_round in aggregate.items()
    }
    payload = {
        "schema": "shake-boolean-influence-frontier-v1",
        "evidence_stage": "FULLROUND_BOOLEAN_INTERVENTION_COUPLING_FRONTIER_MAPPED",
        "result": (
            "Complete Boolean derivatives map the first all-to-all window-to-state "
            f"coupling round as {first_all_to_all}."
        ),
        "scope": (
            "Known-complement capacity windows; every single-coordinate intervention "
            "is paired over the complete assignment truth space for all 1,600 state bits."
        ),
        "parameters": {
            "window_bits": args.window_bits,
            "observed_rounds": rounds,
            "seeds_per_variant": args.seeds,
            "seed": args.seed,
            "state_coordinates": STATE_COORDINATES,
        },
        "influence_gate": influence_gate,
        "conversion_gate": conversion_gate,
        "round_composition_gate": round_gate,
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "first_all_to_all_round": first_all_to_all,
        "aggregate": aggregate,
        "trials": trials,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "first_all_to_all_round": first_all_to_all,
                "aggregate": aggregate,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
