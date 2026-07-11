#!/usr/bin/env python3
"""Exact prefix-observability frontier across all 24 Keccak rounds."""
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


_BITSLICED_PATH = Path(__file__).with_name("shake_bitsliced_window_solver.py")
_BITSLICED_SPEC = importlib.util.spec_from_file_location(
    "shake_bitsliced_window_solver_prefix_base", _BITSLICED_PATH
)
assert _BITSLICED_SPEC is not None and _BITSLICED_SPEC.loader is not None
_BITSLICED = importlib.util.module_from_spec(_BITSLICED_SPEC)
sys.modules[_BITSLICED_SPEC.name] = _BITSLICED
_BITSLICED_SPEC.loader.exec_module(_BITSLICED)

_BASE = _BITSLICED._BASE
_WINDOW = _BITSLICED._WINDOW


def _keccak_round_bitsliced(planes: np.ndarray, round_index: int) -> np.ndarray:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("bit-sliced state must be uint64[P,25,64]")
    if round_index < 0 or round_index >= 24:
        raise ValueError("Keccak round index must be in 0..23")
    state = planes.copy()
    grid = state.reshape(len(state), 5, 5, 64)
    columns = np.bitwise_xor.reduce(grid, axis=1)
    theta = np.roll(columns, 1, axis=1) ^ np.roll(
        np.roll(columns, -1, axis=1), 1, axis=2
    )
    grid ^= theta[:, None, :, :]

    rotated = np.empty_like(state)
    for x in range(5):
        for y in range(5):
            new_x = y
            new_y = (2 * x + 3 * y) % 5
            rotated[:, new_x + 5 * new_y] = np.roll(
                state[:, x + 5 * y],
                int(_BASE.ROTATION_OFFSETS[x, y]),
                axis=1,
            )
    rows = rotated.reshape(len(state), 5, 5, 64)
    state = (
        rows ^ ((~np.roll(rows, -1, axis=2)) & np.roll(rows, -2, axis=2))
    ).reshape(len(state), 25, 64)
    state[:, 0] ^= _BITSLICED.ROUND_CONSTANT_PLANES[round_index]
    return state


def _round_composition_gate(seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    scalar = rng.integers(0, 1 << 64, size=(64, 25), dtype=np.uint64)
    planes = _BITSLICED._scalar_to_bitsliced(scalar)
    traced = planes
    for round_index in range(24):
        traced = _keccak_round_bitsliced(traced, round_index)
    direct = _BITSLICED._keccak_f1600_bitsliced(planes)
    expected = _BASE._keccak_f1600(scalar)
    observed = _BITSLICED._bitsliced_to_scalar(traced, 64)
    if not np.array_equal(traced, direct) or not np.array_equal(observed, expected):
        raise RuntimeError("round-composed bit-sliced Keccak gate failed")
    return {
        "states": 64,
        "state_bits_checked": 102_400,
        "rounds": 24,
        "exact_direct_bitslice_match": True,
        "exact_scalar_match": True,
        "output_sha256": hashlib.sha256(observed.astype("<u8").tobytes()).hexdigest(),
    }


def _prefix_mask(prefix_bits: int, actual_assignment: int) -> np.uint64:
    if prefix_bits < 0 or prefix_bits > 6:
        raise ValueError("in-pack prefix width must be in 0..6")
    mask = 0
    expected = actual_assignment & ((1 << prefix_bits) - 1)
    for candidate in range(64):
        if (candidate & ((1 << prefix_bits) - 1)) == expected:
            mask |= 1 << candidate
    return np.uint64(mask)


def _prefix_constant_counts(
    planes: np.ndarray,
    actual_assignment: int,
    prefix_bits: int,
    lane_count: int,
) -> dict[str, int]:
    if prefix_bits < 0:
        raise ValueError("prefix width must be nonnegative")
    pack_count = len(planes)
    window_bits = int(round(math.log2(pack_count * 64)))
    if (1 << window_bits) != pack_count * 64 or prefix_bits > window_bits:
        raise ValueError("candidate packs must represent an exact power-of-two window")
    selected = planes[:, :lane_count, :].reshape(pack_count, lane_count * 64)
    if prefix_bits < 6:
        mask = _prefix_mask(prefix_bits, actual_assignment)
        any_one = np.any((selected & mask) != 0, axis=0)
        any_zero = np.any(((~selected) & mask) != 0, axis=0)
    else:
        fixed_pack_bits = prefix_bits - 6
        pack_pattern = (actual_assignment >> 6) & ((1 << fixed_pack_bits) - 1)
        stride = 1 << fixed_pack_bits
        pack_indices = np.arange(pack_pattern, pack_count, stride, dtype=np.int64)
        candidate_bit = actual_assignment & 63
        values = (
            (selected[pack_indices] >> np.uint64(candidate_bit)) & np.uint64(1)
        )
        any_one = np.any(values != 0, axis=0)
        any_zero = np.any(values == 0, axis=0)
    variable = int(np.count_nonzero(any_one & any_zero))
    coordinate_count = lane_count * 64
    return {
        "prefix_bits": prefix_bits,
        "remaining_bits": window_bits - prefix_bits,
        "remaining_assignments": 1 << (window_bits - prefix_bits),
        "constant_coordinates": coordinate_count - variable,
        "variable_coordinates": variable,
        "coordinate_count": coordinate_count,
    }


def _target_prefix_matches(
    planes: np.ndarray,
    target: np.ndarray,
    constrained_bits: int,
) -> int:
    if constrained_bits < 0 or constrained_bits > target.shape[1] * 64:
        raise ValueError("target prefix width is outside supplied lanes")
    masks = np.full(len(planes), np.uint64(0xFFFFFFFFFFFFFFFF), dtype=np.uint64)
    for coordinate in range(constrained_bits):
        lane = coordinate // 64
        bit = coordinate % 64
        plane = planes[:, lane, bit]
        masks &= plane if ((int(target[0, lane]) >> bit) & 1) else ~plane
    return sum(int(value).bit_count() for value in masks)


def _random_constant_expectation(coordinate_count: int, remaining: int) -> float:
    if remaining == 0:
        return float(coordinate_count)
    assignments = 1 << remaining
    exponent = 1 - assignments
    if exponent < -1074:
        return 0.0
    return coordinate_count * math.exp2(exponent)


def _build_graph(path: Path, window_bits: int, observed_rounds: list[int]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_prefix_observability_frontier",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "observed_rounds": observed_rounds,
            "permutation_rounds": 24,
            "prediction_before_measurement": (
                "Exact prefix conditioning should reveal the round at which no "
                "rate coordinate remains fixed until only a few window coordinates remain."
            ),
        },
    )
    for key, variant in _BASE.VARIANTS.items():
        truth_id = f"{key}-complete-window-truth-space"
        builder.add_triplet(
            edge_id=truth_id,
            trigger=f"{key}:{window_bits}_capacity_window_coordinates",
            mechanism="exact_candidate_axis_truth_space_through_each_keccak_round",
            outcome=f"{key}:round_indexed_state_coordinate_functions",
            confidence=1.0,
            evidence_kind="complete_2^k_assignment_evaluation",
            source="bit_sliced_round_composition",
            attrs={"assignments": 1 << window_bits, "rounds": observed_rounds},
        )
        builder.add_triplet(
            edge_id=f"{key}-prefix-observability-reader",
            trigger=f"{key}:actual_prefix_conditioned_truth_space",
            mechanism="reader_exact_constant_coordinate_count",
            outcome=f"{key}:round_by_prefix_observability_frontier",
            confidence=1.0,
            evidence_kind="all_remaining_assignments_checked",
            source="constant_and_variable_coordinate_partition",
            provenance=[truth_id],
            attrs={
                "reader_recipe": {
                    "known": "rate_capacity_complement_and_actual_prefix",
                    "variable": "remaining_window_suffix",
                    "operation": "count_coordinates_constant_over_all_suffix_assignments",
                    "rate_lanes": variant.rate_lanes,
                    "capacity_bits": variant.capacity_bits,
                }
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 4:
        raise RuntimeError("SHAKE prefix frontier causal graph gate failed")
    return stats


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    observed_rounds: list[int],
) -> dict[str, Any]:
    problem = _BITSLICED._WINDOW._window_positions
    rng = np.random.default_rng(seed)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    positions = problem(variant.capacity_bits, window_bits, seed ^ 0xB175)
    template = _WINDOW._clear_window(base_state, variant, positions)
    actual = _WINDOW._extract_window(base_state, variant, positions)
    pack_count = 1 << (window_bits - 6)
    template_planes = _BITSLICED._template_planes(template)
    state = _BITSLICED._candidate_planes(
        template_planes,
        variant,
        positions,
        np.arange(pack_count, dtype=np.uint64),
    )
    prefix_widths = list(range(window_bits + 1))
    filter_widths = [
        width
        for width in (1, 2, 4, 8, 16, 32, 64, 128)
        if width <= variant.rate_lanes * 64
    ]
    target_by_round: dict[int, np.ndarray] = {0: base_state[:, : variant.rate_lanes]}
    scalar_trace = base_state.copy()
    for round_index in range(24):
        scalar_planes = _BITSLICED._scalar_to_bitsliced(scalar_trace)
        scalar_planes = _keccak_round_bitsliced(scalar_planes, round_index)
        scalar_trace = _BITSLICED._bitsliced_to_scalar(scalar_planes, 1)
        target_by_round[round_index + 1] = scalar_trace[:, : variant.rate_lanes]

    rows = []
    for round_number in range(25):
        if round_number in observed_rounds:
            rate_frontier = [
                {
                    **_prefix_constant_counts(
                        state, actual, prefix_bits, variant.rate_lanes
                    ),
                    "random_expected_constant_coordinates": _random_constant_expectation(
                        variant.rate_lanes * 64, window_bits - prefix_bits
                    ),
                }
                for prefix_bits in prefix_widths
            ]
            full_frontier = [
                _prefix_constant_counts(state, actual, prefix_bits, 25)
                for prefix_bits in prefix_widths
            ]
            target_matches = {
                str(width): _target_prefix_matches(
                    state, target_by_round[round_number], width
                )
                for width in filter_widths
            }
            rows.append(
                {
                    "round": round_number,
                    "rate_prefix_frontier": rate_frontier,
                    "full_state_prefix_frontier": full_frontier,
                    "actual_target_prefix_matches": target_matches,
                }
            )
        if round_number < 24:
            state = _keccak_round_bitsliced(state, round_number)
    return {
        "seed": seed,
        "variant": variant.name,
        "window_bits": window_bits,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "actual_assignment": actual,
        "candidate_count": 1 << window_bits,
        "packed_state_count": pack_count,
        "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
        "observations": rows,
    }


def _parse_rounds(value: str) -> list[int]:
    try:
        rounds = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise ValueError("rounds must be comma-separated integers") from error
    if not rounds or len(set(rounds)) != len(rounds) or any(r < 0 or r > 24 for r in rounds):
        raise ValueError("rounds must be unique values in 0..24")
    return rounds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--rounds", default="0,1,2,3,4,6,12,24")
    parser.add_argument("--seed", type=int, default=89762001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if args.window_bits < 6 or args.window_bits > 20:
        raise ValueError("prefix frontier window must be in 6..20")
    rounds = _parse_rounds(args.rounds)
    if 24 not in rounds:
        raise ValueError("observed rounds must include the full-round endpoint 24")
    gate = _round_composition_gate(args.seed ^ 0x24F1600)
    causal = _build_graph(args.causal_output, args.window_bits, rounds)
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        print(f"{variant.name} prefix observability frontier", flush=True)
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
        "schema": "shake-prefix-observability-frontier-v1",
        "evidence_stage": "FULLROUND_PREFIX_OBSERVABILITY_FRONTIER_MAPPED",
        "result": (
            "Complete truth-space conditioning localizes the round and remaining-window "
            "width at which exact fixed rate coordinates cease to support early filtering."
        ),
        "scope": (
            "Known-complement capacity window; exact all-suffix coordinate constancy "
            "under the actual assignment prefix, compared with a random-function baseline."
        ),
        "parameters": {
            "window_bits": args.window_bits,
            "observed_rounds": rounds,
            "seed": args.seed,
        },
        "round_composition_gate": gate,
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
                "fullround_constant_rate_coordinates": {
                    variant: {
                        str(row["prefix_bits"]): row["constant_coordinates"]
                        for row in observation["rate_prefix_frontier"]
                    }
                    for variant, observation in fullround.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
