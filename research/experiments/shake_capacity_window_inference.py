#!/usr/bin/env python3
"""Exact SHAKE capacity-window inference from consecutive squeeze states."""
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


def _reader_recipe(variant: Any) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "known": [
            "complete_post_first_squeeze_rate",
            "capacity_complement_outside_declared_window",
            "complete_next_squeeze_rate",
        ],
        "unknown": "declared_contiguous_capacity_window",
        "operation": "enumerate_window_then_keccak_f1600_then_exact_rate_match",
        "permutation_rounds": 24,
        "capacity_bits": variant.capacity_bits,
        "capacity_lane_offset": variant.rate_lanes,
        "rate_lanes": variant.rate_lanes,
        "first_filter_lanes": 2,
        "full_confirmation_lanes": variant.rate_lanes,
        "candidate_order": "ascending_unsigned",
    }


def _build_graph(path: Path, window_bits: list[int], batch_size: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_capacity_window_exact_inference",
        parameters={
            "variants": list(_BASE.VARIANTS),
            "window_bits": window_bits,
            "batch_size": batch_size,
            "permutation_rounds_per_candidate": 24,
            "prediction_before_measurement": (
                "With the capacity complement fixed, exact enumeration should recover "
                "a unique window assignment from the next complete rate block; work "
                "should scale as 2^window_bits."
            ),
        },
    )
    for key, variant in _BASE.VARIANTS.items():
        builder.add_triplet(
            edge_id=f"{key}-capacity-window-forward-constraint",
            trigger=f"{key}:first_rate_plus_capacity_complement_plus_window_candidate",
            mechanism="full_keccak_f1600_candidate_evaluation",
            outcome=f"{key}:predicted_next_complete_rate",
            confidence=1.0,
            evidence_kind="exact_fullround_forward_equation",
            source="FIPS202_consecutive_squeeze_permutation",
            attrs={"reader_recipe": _reader_recipe(variant)},
        )
        builder.add_triplet(
            edge_id=f"{key}-capacity-window-reader",
            trigger=f"{key}:observed_next_rate_and_known_capacity_complement",
            mechanism="reader_executable_exact_capacity_window_enumeration",
            outcome=f"{key}:recovered_capacity_window_assignment",
            confidence=1.0,
            evidence_kind="exact_fullround_reverse_query",
            source="complete_candidate_rate_equality",
            provenance=[f"{key}-capacity-window-forward-constraint"],
            attrs={
                "reader_recipe": _reader_recipe(variant),
                "window_sizes": window_bits,
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-capacity-window-scaling",
            trigger=f"{key}:capacity_window_width_k",
            mechanism="exact_enumeration_search_space",
            outcome=f"{key}:2^k_candidate_evaluations",
            confidence=1.0,
            evidence_kind="exact_algorithmic_complexity",
            source="capacity_window_enumeration",
            provenance=[f"{key}-capacity-window-reader"],
            attrs={
                "candidate_counts": {str(bits): 1 << bits for bits in window_bits},
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 6:
        raise RuntimeError("SHAKE capacity-window causal graph gate failed")
    return stats


def _recipes_from_reader(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    recipes = {}
    for key in _BASE.VARIANTS:
        matches = [
            row
            for row in rows
            if row["mechanism"] == "reader_executable_exact_capacity_window_enumeration"
            and row["trigger"].startswith(f"{key}:")
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Reader returned no unique {key} window recipe")
        recipes[key] = matches[0]["attrs"]["reader_recipe"]
    return recipes, rows


def _validate_recipe(variant: Any, recipe: dict[str, Any]) -> None:
    if int(recipe["permutation_rounds"]) != 24:
        raise ValueError("window Reader must execute full Keccak-f[1600]")
    if int(recipe["capacity_bits"]) != variant.capacity_bits:
        raise ValueError("capacity dimension differs from Reader recipe")
    if int(recipe["capacity_lane_offset"]) != variant.rate_lanes:
        raise ValueError("capacity lane offset differs from Reader recipe")
    if int(recipe["rate_lanes"]) != variant.rate_lanes:
        raise ValueError("rate dimension differs from Reader recipe")


def _window_positions(capacity_bits: int, window_bits: int, seed: int) -> np.ndarray:
    if window_bits < 1 or window_bits > capacity_bits:
        raise ValueError("window width outside capacity")
    rng = np.random.default_rng(seed)
    start = int(rng.integers(0, capacity_bits - window_bits + 1))
    return np.arange(start, start + window_bits, dtype=np.int64)


def _extract_window(state: np.ndarray, variant: Any, positions: np.ndarray) -> int:
    value = 0
    for candidate_bit, position in enumerate(positions):
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        value |= ((int(state[0, lane]) >> bit) & 1) << candidate_bit
    return value


def _clear_window(
    state: np.ndarray, variant: Any, positions: np.ndarray
) -> np.ndarray:
    template = state.copy()
    for position in positions:
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        template[0, lane] &= ~(np.uint64(1) << np.uint64(bit))
    return template


def _inject_candidates(
    template: np.ndarray,
    variant: Any,
    positions: np.ndarray,
    candidates: np.ndarray,
) -> np.ndarray:
    states = np.repeat(template, len(candidates), axis=0)
    for candidate_bit, position in enumerate(positions):
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        states[:, lane] |= (
            ((candidates >> np.uint64(candidate_bit)) & np.uint64(1))
            << np.uint64(bit)
        )
    return states


def _infer_window(
    base_state: np.ndarray,
    target_next_rate: np.ndarray,
    wrong_next_rate: np.ndarray,
    variant: Any,
    recipe: dict[str, Any],
    positions: np.ndarray,
    batch_size: int,
) -> dict[str, Any]:
    _validate_recipe(variant, recipe)
    window_bits = len(positions)
    candidate_count = 1 << window_bits
    template = _clear_window(base_state, variant, positions)
    filter_lanes = int(recipe["first_filter_lanes"])
    factual_filter_matches = []
    wrong_filter_matches = []
    factual_full_matches = []
    wrong_full_matches = []
    for start in range(0, candidate_count, batch_size):
        stop = min(start + batch_size, candidate_count)
        candidates = np.arange(start, stop, dtype=np.uint64)
        states = _inject_candidates(template, variant, positions, candidates)
        predicted = _BASE._keccak_f1600(states)[:, : variant.rate_lanes]
        factual_mask = np.all(
            predicted[:, :filter_lanes] == target_next_rate[:, :filter_lanes],
            axis=1,
        )
        wrong_mask = np.all(
            predicted[:, :filter_lanes] == wrong_next_rate[:, :filter_lanes],
            axis=1,
        )
        factual_candidates = candidates[factual_mask]
        wrong_candidates = candidates[wrong_mask]
        factual_filter_matches.extend(int(value) for value in factual_candidates)
        wrong_filter_matches.extend(int(value) for value in wrong_candidates)
        if len(factual_candidates):
            factual_predictions = predicted[factual_mask]
            factual_full_matches.extend(
                int(candidate)
                for candidate, match in zip(
                    factual_candidates,
                    np.all(factual_predictions == target_next_rate, axis=1),
                    strict=True,
                )
                if match
            )
        if len(wrong_candidates):
            wrong_predictions = predicted[wrong_mask]
            wrong_full_matches.extend(
                int(candidate)
                for candidate, match in zip(
                    wrong_candidates,
                    np.all(wrong_predictions == wrong_next_rate, axis=1),
                    strict=True,
                )
                if match
            )
    actual = _extract_window(base_state, variant, positions)
    return {
        "window_bits": window_bits,
        "window_start_capacity_bit": int(positions[0]),
        "window_stop_capacity_bit_exclusive": int(positions[-1] + 1),
        "actual_assignment": actual,
        "candidate_count": candidate_count,
        "batch_size": batch_size,
        "batch_count": math.ceil(candidate_count / batch_size),
        "first_filter_lanes": filter_lanes,
        "factual_filter_matches": factual_filter_matches,
        "factual_full_matches": factual_full_matches,
        "wrong_target_filter_matches": wrong_filter_matches,
        "wrong_target_full_matches": wrong_full_matches,
        "unique_exact_recovery": factual_full_matches == [actual],
        "wrong_target_rejected": len(wrong_full_matches) == 0,
    }


def _trial(
    variant: Any,
    recipe: dict[str, Any],
    window_bits: int,
    batch_size: int,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    message = rng.integers(
        0,
        256,
        size=(1, variant.message_bytes),
        dtype=np.uint8,
    )
    wrong_message = rng.integers(
        0,
        256,
        size=(1, variant.message_bytes),
        dtype=np.uint8,
    )
    base_state, first_rate = _BASE._first_squeeze_state(message, variant)
    wrong_state, _ = _BASE._first_squeeze_state(wrong_message, variant)
    target_next_rate = _BASE._keccak_f1600(base_state)[:, : variant.rate_lanes]
    wrong_next_rate = _BASE._keccak_f1600(wrong_state)[:, : variant.rate_lanes]
    positions = _window_positions(variant.capacity_bits, window_bits, seed ^ 0xC411)
    result = _infer_window(
        base_state,
        target_next_rate,
        wrong_next_rate,
        variant,
        recipe,
        positions,
        batch_size,
    )
    return {
        "seed": seed,
        "message_sha256": hashlib.sha256(message.tobytes()).hexdigest(),
        "first_rate_sha256": hashlib.sha256(first_rate.tobytes()).hexdigest(),
        "target_next_rate_sha256": hashlib.sha256(
            target_next_rate.astype("<u8", copy=False).tobytes()
        ).hexdigest(),
        **result,
    }


def _parse_windows(value: str) -> list[int]:
    windows = sorted({int(token) for token in value.split(",") if token.strip()})
    if not windows or any(bits < 1 or bits > 24 for bits in windows):
        raise ValueError("window sizes must be a comma list in 1..24")
    return windows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="8,12,16,20")
    parser.add_argument("--batch-size", type=int, default=32768)
    parser.add_argument("--seed", type=int, default=89628001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    windows = _parse_windows(args.window_bits)
    if args.batch_size < 1:
        raise ValueError("batch-size must be positive")

    kat = _BASE._kat()
    causal = _build_graph(args.causal_output, windows, args.batch_size)
    recipes, reader_rows = _recipes_from_reader(args.causal_output)
    confirmations = {}
    for variant_index, (key, variant) in enumerate(_BASE.VARIANTS.items()):
        rows = []
        for window_index, bits in enumerate(windows):
            seed = args.seed + 100_003 * variant_index + 1009 * window_index
            print(f"{variant.name} capacity-window inference bits={bits}", flush=True)
            rows.append(
                _trial(variant, recipes[key], bits, args.batch_size, seed)
            )
        confirmations[key] = rows
    retained = all(
        row["unique_exact_recovery"] and row["wrong_target_rejected"]
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "shake-capacity-window-inference-v1",
        "evidence_stage": (
            "CAPACITY_WINDOW_EXACT_INFERENCE_RETAINED"
            if retained
            else "NEW_CAPACITY_INFERENCE_FRONTIER_IDENTIFIED"
        ),
        "result": (
            "Given the complete first-squeeze state except for a declared capacity "
            "window and the complete next rate block, the Reader uniquely recovers "
            "every tested window assignment by exact full-round enumeration."
        ),
        "scope": (
            "Known-capacity-complement window inference. Candidate work is exactly "
            "2^k and does not constitute full 256-/512-bit capacity reconstruction."
        ),
        "parameters": {
            "permutation_rounds": 24,
            "window_bits": windows,
            "batch_size": args.batch_size,
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
                "recoveries": {
                    key: {
                        str(row["window_bits"]): row["factual_full_matches"]
                        for row in rows
                    }
                    for key, rows in confirmations.items()
                },
                "candidate_counts": {
                    str(bits): 1 << bits for bits in windows
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
