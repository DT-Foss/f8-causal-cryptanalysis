#!/usr/bin/env python3
"""Machine-word bit-sliced SHAKE state-window consistency solver."""
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


_BASE_PATH = Path(__file__).with_name("shake_fullround_rate_reader.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "shake_fullround_rate_reader", _BASE_PATH
)
assert _BASE_SPEC is not None and _BASE_SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _BASE
_BASE_SPEC.loader.exec_module(_BASE)

_WINDOW_PATH = Path(__file__).with_name("shake_capacity_window_inference.py")
_WINDOW_SPEC = importlib.util.spec_from_file_location(
    "shake_capacity_window_inference", _WINDOW_PATH
)
assert _WINDOW_SPEC is not None and _WINDOW_SPEC.loader is not None
_WINDOW = importlib.util.module_from_spec(_WINDOW_SPEC)
sys.modules[_WINDOW_SPEC.name] = _WINDOW
_WINDOW_SPEC.loader.exec_module(_WINDOW)


ALL_ONES = np.uint64(0xFFFFFFFFFFFFFFFF)
LOW_CANDIDATE_PATTERNS = np.array(
    [
        sum(((candidate >> bit) & 1) << candidate for candidate in range(64))
        for bit in range(6)
    ],
    dtype=np.uint64,
)
ROUND_CONSTANT_PLANES = np.zeros((24, 64), dtype=np.uint64)
for _round_index, _round_constant in enumerate(_BASE.ROUND_CONSTANTS):
    for _bit in range(64):
        if (int(_round_constant) >> _bit) & 1:
            ROUND_CONSTANT_PLANES[_round_index, _bit] = ALL_ONES


def _reader_recipe(variant: Any) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "representation": "candidate_axis_bitsliced_into_uint64",
        "candidates_per_machine_word": 64,
        "state_planes": [25, 64],
        "known": "rate_and_capacity_complement",
        "variable": "declared_capacity_window",
        "operation": "bitsliced_keccak_f1600_then_exact_next_rate_filter",
        "permutation_rounds": 24,
        "rate_lanes": variant.rate_lanes,
        "capacity_bits": variant.capacity_bits,
        "capacity_lane_offset": variant.rate_lanes,
        "filter_lanes": 2,
    }


def _build_graph(path: Path, window_bits: list[int], pack_batch: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_bitsliced_capacity_window_solver",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "pack_batch": pack_batch,
            "candidates_per_machine_word": 64,
            "prediction_before_measurement": (
                "Keccak's Boolean operations should evaluate 64 window assignments "
                "per uint64 while preserving exact full-round output equality."
            ),
        },
    )
    for key, variant in _BASE.VARIANTS.items():
        pack_id = f"{key}-candidate-axis-bit-pack"
        permutation_id = f"{key}-bitsliced-keccak-fullround"
        builder.add_triplet(
            edge_id=pack_id,
            trigger=f"{key}:64_capacity_window_assignments",
            mechanism="exact_candidate_axis_bit_slicing",
            outcome=f"{key}:1600_uint64_candidate_bit_planes",
            confidence=1.0,
            evidence_kind="exact_lossless_representation_transform",
            source="candidate_axis_transposition",
            attrs={
                "candidates_per_word": 64,
                "low_candidate_patterns": [
                    f"{int(value):016x}" for value in LOW_CANDIDATE_PATTERNS
                ],
            },
        )
        builder.add_triplet(
            edge_id=permutation_id,
            trigger=f"{key}:bitsliced_state_planes",
            mechanism="exact_bitsliced_keccak_f1600_24_rounds",
            outcome=f"{key}:bitsliced_next_state_planes",
            confidence=1.0,
            evidence_kind="64_state_cross_implementation_gate",
            source="FIPS202_Boolean_operations_transposed_over_candidate_axis",
            provenance=[pack_id],
            attrs={"reader_recipe": _reader_recipe(variant)},
        )
        builder.add_triplet(
            edge_id=f"{key}-bitsliced-window-reader",
            trigger=f"{key}:observed_next_rate_plus_bitsliced_candidates",
            mechanism="reader_executable_bitsliced_exact_consistency_filter",
            outcome=f"{key}:consistent_capacity_window_assignment",
            confidence=1.0,
            evidence_kind="exact_fullround_output_equality",
            source="two_rate_lane_filter_then_complete_rate_confirmation",
            provenance=[pack_id, permutation_id],
            attrs={
                "reader_recipe": _reader_recipe(variant),
                "window_sizes": window_bits,
                "packed_evaluations": {
                    str(bits): math.ceil((1 << bits) / 64)
                    for bits in window_bits
                },
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE bit-sliced causal graph gate failed")
    return stats


def _recipes_from_reader(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    recipes = {}
    for key in _BASE.VARIANTS:
        matches = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_bitsliced_exact_consistency_filter"
            and row["trigger"].startswith(f"{key}:")
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Reader returned no unique {key} bit-sliced recipe")
        recipes[key] = matches[0]["attrs"]["reader_recipe"]
    return recipes, rows


def _scalar_to_bitsliced(states: np.ndarray) -> np.ndarray:
    if states.dtype != np.uint64 or states.ndim != 2 or states.shape[1] != 25:
        raise ValueError("states must be uint64[N,25]")
    if len(states) < 1 or len(states) > 64:
        raise ValueError("scalar-to-bitsliced gate accepts 1..64 states")
    planes = np.zeros((1, 25, 64), dtype=np.uint64)
    for lane in range(25):
        for bit in range(64):
            values = (states[:, lane] >> np.uint64(bit)) & np.uint64(1)
            packed = np.uint64(0)
            for candidate, value in enumerate(values):
                packed |= np.uint64(int(value)) << np.uint64(candidate)
            planes[0, lane, bit] = packed
    return planes


def _bitsliced_to_scalar(planes: np.ndarray, count: int) -> np.ndarray:
    if planes.dtype != np.uint64 or planes.shape != (1, 25, 64):
        raise ValueError("gate planes must be uint64[1,25,64]")
    if count < 1 or count > 64:
        raise ValueError("scalar count must be in 1..64")
    states = np.zeros((count, 25), dtype=np.uint64)
    for lane in range(25):
        for bit in range(64):
            packed = int(planes[0, lane, bit])
            for candidate in range(count):
                states[candidate, lane] |= (
                    np.uint64((packed >> candidate) & 1) << np.uint64(bit)
                )
    return states


def _keccak_f1600_bitsliced(planes: np.ndarray) -> np.ndarray:
    if planes.dtype != np.uint64 or planes.ndim != 3 or planes.shape[1:] != (25, 64):
        raise ValueError("bit-sliced state must be uint64[P,25,64]")
    state = planes.copy()
    for round_index in range(24):
        grid = state.reshape(len(state), 5, 5, 64)  # candidate packs, y, x, lane bit
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
            rows
            ^ ((~np.roll(rows, -1, axis=2)) & np.roll(rows, -2, axis=2))
        ).reshape(len(state), 25, 64)
        state[:, 0] ^= ROUND_CONSTANT_PLANES[round_index]
    return state


def _cross_implementation_gate(seed: int = 89728001) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    states = rng.integers(0, 1 << 64, size=(64, 25), dtype=np.uint64)
    expected = _BASE._keccak_f1600(states)
    observed = _bitsliced_to_scalar(
        _keccak_f1600_bitsliced(_scalar_to_bitsliced(states)), 64
    )
    if not np.array_equal(observed, expected):
        raise RuntimeError("bit-sliced Keccak cross-implementation gate failed")
    return {
        "states": 64,
        "state_bits_checked": 64 * 1600,
        "exact_match": True,
        "input_sha256": hashlib.sha256(
            states.astype("<u8", copy=False).tobytes()
        ).hexdigest(),
        "output_sha256": hashlib.sha256(
            observed.astype("<u8", copy=False).tobytes()
        ).hexdigest(),
    }


def _template_planes(template: np.ndarray) -> np.ndarray:
    if template.dtype != np.uint64 or template.shape != (1, 25):
        raise ValueError("template must be uint64[1,25]")
    planes = np.zeros((1, 25, 64), dtype=np.uint64)
    for lane in range(25):
        value = int(template[0, lane])
        for bit in range(64):
            if (value >> bit) & 1:
                planes[0, lane, bit] = ALL_ONES
    return planes


def _candidate_planes(
    template_planes: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    pack_indices: np.ndarray,
) -> np.ndarray:
    planes = np.repeat(template_planes, len(pack_indices), axis=0)
    for candidate_bit, position in enumerate(positions):
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        if candidate_bit < 6:
            planes[:, lane, bit] = LOW_CANDIDATE_PATTERNS[candidate_bit]
        else:
            planes[:, lane, bit] = np.where(
                (
                    (pack_indices >> np.uint64(candidate_bit - 6))
                    & np.uint64(1)
                )
                != 0,
                ALL_ONES,
                np.uint64(0),
            )
    return planes


def _match_masks(
    output_planes: np.ndarray,
    target_rate: np.ndarray,
    filter_lanes: int,
) -> np.ndarray:
    masks = np.full(len(output_planes), ALL_ONES, dtype=np.uint64)
    for lane in range(filter_lanes):
        target = int(target_rate[0, lane])
        for bit in range(64):
            plane = output_planes[:, lane, bit]
            masks &= plane if ((target >> bit) & 1) else ~plane
    return masks


def _indices_from_masks(
    masks: np.ndarray,
    first_pack: int,
    candidate_count: int,
) -> list[int]:
    matches = []
    for local_pack, packed_mask in enumerate(masks):
        value = int(packed_mask)
        while value:
            low_bit = value & -value
            candidate_bit = low_bit.bit_length() - 1
            candidate = (first_pack + local_pack) * 64 + candidate_bit
            if candidate < candidate_count:
                matches.append(candidate)
            value ^= low_bit
    return matches


def _confirm_candidates(
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    candidates: list[int],
    target_rate: np.ndarray,
) -> list[int]:
    if not candidates:
        return []
    candidate_array = np.asarray(candidates, dtype=np.uint64)
    states = _WINDOW._inject_candidates(
        template, variant, positions, candidate_array
    )
    output = _BASE._keccak_f1600(states)[:, : variant.rate_lanes]
    return [
        candidate
        for candidate, matches in zip(
            candidates,
            np.all(output == target_rate, axis=1),
            strict=True,
        )
        if matches
    ]


def _solve_window(
    base_state: np.ndarray,
    wrong_state: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    positions: np.ndarray,
    pack_batch: int,
) -> dict[str, Any]:
    if int(recipe["permutation_rounds"]) != 24:
        raise ValueError("bit-sliced recipe is not full-round")
    if int(recipe["candidates_per_machine_word"]) != 64:
        raise ValueError("unsupported candidate pack width")
    window_bits = len(positions)
    candidate_count = 1 << window_bits
    pack_count = math.ceil(candidate_count / 64)
    template = _WINDOW._clear_window(base_state, variant, positions)
    packed_template = _template_planes(template)
    target = _BASE._keccak_f1600(base_state)[:, : variant.rate_lanes]
    wrong_target = _BASE._keccak_f1600(wrong_state)[:, : variant.rate_lanes]
    filter_lanes = int(recipe["filter_lanes"])
    factual_filtered = []
    wrong_filtered = []
    for first_pack in range(0, pack_count, pack_batch):
        last_pack = min(first_pack + pack_batch, pack_count)
        pack_indices = np.arange(first_pack, last_pack, dtype=np.uint64)
        input_planes = _candidate_planes(
            packed_template, variant, positions, pack_indices
        )
        output_planes = _keccak_f1600_bitsliced(input_planes)
        factual_filtered.extend(
            _indices_from_masks(
                _match_masks(output_planes, target, filter_lanes),
                first_pack,
                candidate_count,
            )
        )
        wrong_filtered.extend(
            _indices_from_masks(
                _match_masks(output_planes, wrong_target, filter_lanes),
                first_pack,
                candidate_count,
            )
        )
    factual_full = _confirm_candidates(
        template, variant, positions, factual_filtered, target
    )
    wrong_full = _confirm_candidates(
        template, variant, positions, wrong_filtered, wrong_target
    )
    actual = _WINDOW._extract_window(base_state, variant, positions)
    return {
        "window_bits": window_bits,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "actual_assignment": actual,
        "candidate_count": candidate_count,
        "candidates_per_machine_word": 64,
        "packed_state_count": pack_count,
        "pack_batch": pack_batch,
        "pack_batch_count": math.ceil(pack_count / pack_batch),
        "filter_lanes": filter_lanes,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "wrong_target_filter_matches": wrong_filtered,
        "wrong_target_full_matches": wrong_full,
        "unique_exact_consistency": factual_full == [actual],
        "wrong_target_rejected": len(wrong_full) == 0,
        "packed_evaluation_reduction_factor": candidate_count / pack_count,
    }


def _trial(
    variant: Any,
    recipe: dict[str, Any],
    window_bits: int,
    pack_batch: int,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    wrong_message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    base_state, _ = _BASE._first_squeeze_state(message, variant)
    wrong_state, _ = _BASE._first_squeeze_state(wrong_message, variant)
    positions = _WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xB175
    )
    return {
        "seed": seed,
        "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
        **_solve_window(
            base_state,
            wrong_state,
            variant,
            recipe,
            positions,
            pack_batch,
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="20,24")
    parser.add_argument("--pack-batch", type=int, default=256)
    parser.add_argument("--seed", type=int, default=89728001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    windows = _WINDOW._parse_windows(args.window_bits)
    if args.pack_batch < 1:
        raise ValueError("pack-batch must be positive")

    kat = _BASE._kat()
    bitslice_gate = _cross_implementation_gate(args.seed ^ 0x641600)
    causal = _build_graph(args.causal_output, windows, args.pack_batch)
    recipes, reader_rows = _recipes_from_reader(args.causal_output)
    confirmations = {}
    for variant_index, (key, variant) in enumerate(_BASE.VARIANTS.items()):
        rows = []
        for window_index, bits in enumerate(windows):
            seed = args.seed + 100_003 * variant_index + 1009 * window_index
            print(f"{variant.name} bit-sliced consistency bits={bits}", flush=True)
            rows.append(
                _trial(variant, recipes[key], bits, args.pack_batch, seed)
            )
        confirmations[key] = rows
    retained = all(
        row["unique_exact_consistency"]
        and row["wrong_target_rejected"]
        and row["packed_evaluation_reduction_factor"] == 64.0
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "shake-bitsliced-window-solver-v1",
        "evidence_stage": (
            "BIT_SLICED_FULLROUND_WINDOW_CONSISTENCY_RETAINED"
            if retained
            else "NEW_BIT_SLICED_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "Candidate-axis bit slicing evaluates 64 state-window assignments per "
            "uint64 and uniquely determines every tested 20-/24-bit assignment by "
            "exact next-rate consistency after 24 Keccak rounds."
        ),
        "scope": (
            "Known-complement state-window consistency benchmark. Bit slicing reduces "
            "machine-word full-state evaluations by 64 while total candidate count remains 2^k."
        ),
        "parameters": {
            "permutation_rounds": 24,
            "window_bits": windows,
            "pack_batch": args.pack_batch,
            "seed": args.seed,
        },
        "kat": kat,
        "bitslice_cross_implementation_gate": bitslice_gate,
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
                "bitslice_gate_bits": bitslice_gate["state_bits_checked"],
                "consistent_assignments": {
                    key: {
                        str(row["window_bits"]): row["factual_full_matches"]
                        for row in rows
                    }
                    for key, rows in confirmations.items()
                },
                "candidate_counts": {
                    str(bits): 1 << bits for bits in windows
                },
                "packed_state_counts": {
                    str(bits): math.ceil((1 << bits) / 64)
                    for bits in windows
                },
                "wrong_target_matches": {
                    key: [len(row["wrong_target_full_matches"]) for row in rows]
                    for key, rows in confirmations.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
