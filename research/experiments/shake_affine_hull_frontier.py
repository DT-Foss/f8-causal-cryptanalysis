#!/usr/bin/env python3
"""Exact affine-hull frontier for full-round SHAKE window branches."""
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


_PREFIX_PATH = Path(__file__).with_name("shake_prefix_observability_frontier.py")
_PREFIX_SPEC = importlib.util.spec_from_file_location(
    "shake_prefix_observability_frontier_affine_base", _PREFIX_PATH
)
assert _PREFIX_SPEC is not None and _PREFIX_SPEC.loader is not None
_PREFIX = importlib.util.module_from_spec(_PREFIX_SPEC)
sys.modules[_PREFIX_SPEC.name] = _PREFIX
_PREFIX_SPEC.loader.exec_module(_PREFIX)

_BITSLICED = _PREFIX._BITSLICED
_BASE = _PREFIX._BASE
_WINDOW = _PREFIX._WINDOW
OUTPUT_COORDINATES = 128


def _candidate_output_integers(planes: np.ndarray) -> list[int]:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("candidate state must be uint64[P,25,64]")
    coordinate_words = np.ascontiguousarray(planes[:, :2, :]).reshape(
        len(planes), OUTPUT_COORDINATES
    )
    byte_view = coordinate_words.view(np.uint8).reshape(
        len(planes), OUTPUT_COORDINATES, 8
    )
    candidate_bits = np.unpackbits(byte_view, axis=2, bitorder="little")
    candidate_bits = candidate_bits.transpose(0, 2, 1).reshape(
        len(planes) * 64, OUTPUT_COORDINATES
    )
    packed = np.packbits(candidate_bits, axis=1, bitorder="little")
    return [int.from_bytes(row.tobytes(), "little") for row in packed]


def _insert_basis(basis: dict[int, int], value: int) -> bool:
    reduced = value
    while reduced:
        pivot = reduced.bit_length() - 1
        existing = basis.get(pivot)
        if existing is None:
            basis[pivot] = reduced
            return True
        reduced ^= existing
    return False


def _affine_basis(values: list[int]) -> tuple[int, dict[int, int]]:
    if not values:
        raise ValueError("affine hull requires at least one point")
    origin = values[0]
    basis: dict[int, int] = {}
    for value in values[1:]:
        _insert_basis(basis, value ^ origin)
        if len(basis) == OUTPUT_COORDINATES:
            break
    return origin, basis


def _reduce_basis(basis: dict[int, int], value: int) -> int:
    reduced = value
    while reduced:
        pivot = reduced.bit_length() - 1
        existing = basis.get(pivot)
        if existing is None:
            return reduced
        reduced ^= existing
    return 0


def _in_affine_hull(origin: int, basis: dict[int, int], value: int) -> bool:
    return _reduce_basis(basis, value ^ origin) == 0


def _prefix_affine_frontier(
    values: list[int], actual_assignment: int, window_bits: int
) -> list[dict[str, Any]]:
    rows = []
    for prefix_bits in range(window_bits + 1):
        prefix_count = 1 << prefix_bits
        actual_prefix = actual_assignment & (prefix_count - 1)
        branch = values[actual_prefix::prefix_count]
        origin, basis = _affine_basis(branch)
        rank = len(basis)
        maximum_random_like_rank = min(OUTPUT_COORDINATES, len(branch) - 1)
        rows.append(
            {
                "prefix_bits": prefix_bits,
                "remaining_bits": window_bits - prefix_bits,
                "branch_assignments": len(branch),
                "affine_rank": rank,
                "affine_relations": OUTPUT_COORDINATES - rank,
                "maximum_random_like_rank": maximum_random_like_rank,
                "rank_deficit_from_random_maximum": maximum_random_like_rank - rank,
                "target_in_actual_branch_hull": _in_affine_hull(
                    origin, basis, values[actual_assignment]
                ),
            }
        )
    return rows


def _branch_membership_frontier(
    values: list[int], actual_assignment: int, window_bits: int, prefix_widths: list[int]
) -> list[dict[str, Any]]:
    target = values[actual_assignment]
    rows = []
    for prefix_bits in prefix_widths:
        prefix_count = 1 << prefix_bits
        survivors = []
        rank_counts: dict[int, int] = {}
        ranks_by_prefix = []
        for prefix in range(prefix_count):
            branch = values[prefix::prefix_count]
            origin, basis = _affine_basis(branch)
            rank = len(basis)
            ranks_by_prefix.append(rank)
            rank_counts[rank] = rank_counts.get(rank, 0) + 1
            if _in_affine_hull(origin, basis, target):
                survivors.append(prefix)
        actual_prefix = actual_assignment & (prefix_count - 1)
        random_expected_false_survivors = sum(
            math.exp2(rank - OUTPUT_COORDINATES)
            for prefix, rank in enumerate(ranks_by_prefix)
            if prefix != actual_prefix
        )
        rows.append(
            {
                "prefix_bits": prefix_bits,
                "remaining_bits": window_bits - prefix_bits,
                "branches": prefix_count,
                "assignments_per_branch": 1 << (window_bits - prefix_bits),
                "surviving_prefixes": survivors,
                "survivor_count": len(survivors),
                "false_survivor_count": len(survivors) - 1,
                "random_target_expected_false_survivors": random_expected_false_survivors,
                "actual_prefix": actual_prefix,
                "actual_prefix_retained": actual_prefix in survivors,
                "rank_histogram": {
                    str(rank): count for rank, count in sorted(rank_counts.items())
                },
            }
        )
    return rows


def _conversion_gate(seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    states = rng.integers(0, 1 << 64, size=(64, 25), dtype=np.uint64)
    planes = _BITSLICED._scalar_to_bitsliced(states)
    observed = _candidate_output_integers(planes)
    expected = [int(row[0]) | (int(row[1]) << 64) for row in states]
    if observed != expected:
        raise RuntimeError("affine output coordinate conversion gate failed")
    return {
        "states": 64,
        "coordinates_per_state": OUTPUT_COORDINATES,
        "coordinate_values_checked": 64 * OUTPUT_COORDINATES,
        "exact_match": True,
        "output_sha256": hashlib.sha256(
            b"".join(value.to_bytes(16, "little") for value in observed)
        ).hexdigest(),
    }


def _build_graph(
    path: Path,
    window_bits: int,
    observed_rounds: list[int],
    branch_prefix_widths: list[int],
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_affine_hull_frontier",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "output_coordinates": OUTPUT_COORDINATES,
            "observed_rounds": observed_rounds,
            "branch_prefix_widths": branch_prefix_widths,
            "prediction_before_measurement": (
                "Joint affine relations may persist after every individual rate "
                "coordinate has become variable; their exact rank frontier should "
                "localize any useful branch-membership transition."
            ),
        },
    )
    for key in _BASE.VARIANTS:
        truth_id = f"{key}-affine-truth-space"
        builder.add_triplet(
            edge_id=truth_id,
            trigger=f"{key}:complete_{window_bits}_coordinate_truth_space",
            mechanism="exact_first_128_rate_coordinate_functions",
            outcome=f"{key}:round_indexed_128_bit_candidate_outputs",
            confidence=1.0,
            evidence_kind="all_2^k_assignments",
            source="bit_sliced_keccak_round_trace",
            attrs={"rounds": observed_rounds},
        )
        builder.add_triplet(
            edge_id=f"{key}-affine-hull-reader",
            trigger=f"{key}:prefix_partitioned_candidate_outputs",
            mechanism="reader_exact_gf2_affine_hull_membership",
            outcome=f"{key}:prefix_rank_and_target_membership_frontier",
            confidence=1.0,
            evidence_kind="complete_branch_gaussian_elimination",
            source="128_coordinate_integer_basis",
            provenance=[truth_id],
            attrs={
                "reader_recipe": {
                    "operation": "center_branch_outputs_then_GF2_basis_and_membership",
                    "output_coordinates": OUTPUT_COORDINATES,
                    "prefix_widths": branch_prefix_widths,
                    "known": "rate_capacity_complement_and_observed_target",
                }
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 4:
        raise RuntimeError("SHAKE affine hull causal graph gate failed")
    return stats


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    observed_rounds: list[int],
    branch_prefix_widths: list[int],
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    message = rng.integers(0, 256, size=(1, variant.message_bytes), dtype=np.uint8)
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    positions = _WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xB175
    )
    template = _WINDOW._clear_window(base_state, variant, positions)
    actual = _WINDOW._extract_window(base_state, variant, positions)
    pack_count = 1 << (window_bits - 6)
    state = _BITSLICED._candidate_planes(
        _BITSLICED._template_planes(template),
        variant,
        positions,
        np.arange(pack_count, dtype=np.uint64),
    )
    observations = []
    for round_number in range(25):
        if round_number in observed_rounds:
            values = _candidate_output_integers(state)
            row = {
                "round": round_number,
                "actual_prefix_affine_frontier": _prefix_affine_frontier(
                    values, actual, window_bits
                ),
            }
            if round_number == 24:
                row["all_branch_target_membership"] = _branch_membership_frontier(
                    values, actual, window_bits, branch_prefix_widths
                )
            observations.append(row)
        if round_number < 24:
            state = _PREFIX._keccak_round_bitsliced(state, round_number)
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
        "observations": observations,
    }


def _parse_int_list(value: str, minimum: int, maximum: int) -> list[int]:
    try:
        values = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise ValueError("expected comma-separated integers") from error
    if (
        not values
        or len(set(values)) != len(values)
        or any(item < minimum or item > maximum for item in values)
    ):
        raise ValueError(f"values must be unique integers in {minimum}..{maximum}")
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--rounds", default="0,1,2,3,4,6,12,24")
    parser.add_argument("--branch-prefix-widths", default="8,9,10,11,12")
    parser.add_argument("--seed", type=int, default=89773001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if args.window_bits < 6 or args.window_bits > 18:
        raise ValueError("affine frontier window must be in 6..18")
    rounds = _parse_int_list(args.rounds, 0, 24)
    if 24 not in rounds:
        raise ValueError("observed rounds must include 24")
    branch_prefix_widths = _parse_int_list(
        args.branch_prefix_widths, 0, args.window_bits
    )
    conversion_gate = _conversion_gate(args.seed ^ 0xAFF128)
    round_gate = _PREFIX._round_composition_gate(args.seed ^ 0x24F1600)
    causal = _build_graph(
        args.causal_output, args.window_bits, rounds, branch_prefix_widths
    )
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for variant_index, variant in enumerate(_BASE.VARIANTS.values()):
        print(f"{variant.name} affine hull frontier", flush=True)
        trials.append(
            _trial(
                variant,
                args.window_bits,
                args.seed + 100_003 * variant_index,
                rounds,
                branch_prefix_widths,
            )
        )
    fullround = {
        row["variant"]: next(
            observation for observation in row["observations"] if observation["round"] == 24
        )
        for row in trials
    }
    payload = {
        "schema": "shake-affine-hull-frontier-v1",
        "evidence_stage": "FULLROUND_AFFINE_HULL_FRONTIER_MAPPED",
        "result": (
            "Exact 128-coordinate affine hulls localize the prefix width at which "
            "joint relations begin rejecting complete-window branches."
        ),
        "scope": (
            "Known-complement capacity window and first 128 rate coordinates; "
            "complete truth-space branch partitions with exact GF(2) membership."
        ),
        "parameters": {
            "window_bits": args.window_bits,
            "output_coordinates": OUTPUT_COORDINATES,
            "observed_rounds": rounds,
            "branch_prefix_widths": branch_prefix_widths,
            "seed": args.seed,
        },
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
                "fullround_branch_survivors": {
                    variant: {
                        str(row["prefix_bits"]): row["survivor_count"]
                        for row in observation["all_branch_target_membership"]
                    }
                    for variant, observation in fullround.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
