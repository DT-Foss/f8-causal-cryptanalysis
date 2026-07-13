#!/usr/bin/env python3
"""A215: R1--R20 contrast-key Mobius, carry, and public-output atlas."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.boolean_mobius import (
    local_mobius_coefficients,
    local_truth_table,
    nearest_center_indices,
    subset_masks,
)
from arx_carry_leak.chacha_trace import trace_chacha20_batch_words
from arx_carry_leak.contrast_views import (
    canonical_casi_tiles,
    codec_length_profile,
    f8_intervention_transition,
)
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader, ExactRule


ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
PROTOCOL_PATH = RESEARCH / "configs/chacha20_round20_key_contrast_mobius_atlas_v1.json"
PROTOCOL_SHA256 = "22f8d8b703575d19fb8ecfd5543b925f39d8f36693cc30748fb65f4d4941bd04"
CHALLENGE_PATH = (
    RESEARCH
    / "pilots/chacha20_round20_partition_v1/phase2_split18_10s/config.json"
)
R20_RESULT_PATH = RESEARCH / "results/v1/chacha20_round20_global_incremental_transfer_v1.json"
R20_RESULT_SHA256 = "a5be062ebce29cbc864ef926c55a1f9dbaadd69c9edcc54aed43552304f8e3f0"
WIDTH8_RESULT_PATH = RESEARCH / "results/v1/chacha20_key_contrast_mobius_width8_preflight_v1.json"
WIDTH8_RESULT_SHA256 = "3d09b44bb5e797fcb075210f584b1afa9f5cb50a0f8e44fffa3d262245fb1f00"

ATTEMPT_ID = "A215-CHACHA20-KEY-CONTRAST-MOBIUS-V1"
SCHEMA = "chacha20-round20-key-contrast-mobius-atlas-v1"
PREREVEAL_SCHEMA = "chacha20-round20-key-contrast-mobius-atlas-prereveal-v1"
CENTERS = (0x00000, 0xFFFFF, 0x55555, 0xAAAAA)
CENTER_NAMES = ("zero", "one", "alternating_01", "alternating_10")
MASKS = subset_masks(20, 3)
ORDERS = (1, 2, 3)
ROUND_COUNT = 20
BLOCK_COUNT = 8
HOLDOUT_COUNT = 1024
RANK_CHALLENGE_COUNT = 16
POPCOUNT = np.asarray([value.bit_count() for value in range(256)], dtype=np.uint8)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    )


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(),
    )


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL_PATH) != PROTOCOL_SHA256:
        raise RuntimeError("A215 protocol hash differs")
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    design = protocol.get("contrast_design", {})
    validation = protocol.get("validation", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-key-contrast-mobius-atlas-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or design.get("intervention_orders") != [0, 1, 2, 3]
        or design.get("total_center_labeled_traces") != 5404
        or [int(row["value_hex"], 16) for row in design.get("centers_in_fixed_order", [])]
        != list(CENTERS)
        or validation.get("holdout_count") != HOLDOUT_COUNT
        or validation.get("complete_rank_challenge_count") != RANK_CHALLENGE_COUNT
        or validation.get("target_value_available_only_after_protocol_and_target_free_prereveal_artifact_are_hashed")
        is not True
    ):
        raise RuntimeError("A215 protocol identity gate failed")
    return protocol


def _load_public_challenge(protocol: dict[str, Any]) -> dict[str, Any]:
    public = json.loads(CHALLENGE_PATH.read_bytes())["public_challenge"]
    expected = protocol["anchors"]["public_challenge"]["canonical_sha256"]
    if _canonical_sha256(public) != expected:
        raise RuntimeError("A215 public challenge hash differs")
    if (
        public["rounds"] != ROUND_COUNT
        or public["block_count"] != BLOCK_COUNT
        or public["unknown_key_word0_low_bits"] != 20
    ):
        raise RuntimeError("A215 public challenge semantic gate failed")
    return public


def _training_ledger() -> tuple[np.ndarray, list[dict[str, Any]]]:
    keys: list[int] = []
    rows: list[dict[str, Any]] = []
    for center_index, (center_name, center) in enumerate(zip(CENTER_NAMES, CENTERS, strict=True)):
        for subset_index, mask in enumerate(MASKS):
            low20 = center ^ mask
            keys.append(low20)
            rows.append(
                {
                    "center_index": center_index,
                    "center": center_name,
                    "center_hex": f"0x{center:05x}",
                    "subset_index": subset_index,
                    "subset_mask": mask,
                    "subset_mask_hex": f"0x{mask:05x}",
                    "order": mask.bit_count(),
                    "low20": low20,
                    "low20_hex": f"0x{low20:05x}",
                }
            )
    if len(keys) != 5404 or len(set(keys)) != len(keys):
        raise RuntimeError("A215 contrast Hamming balls must be disjoint and complete")
    return np.asarray(keys, dtype=np.uint32), rows


def _shake_holdouts(excluded: set[int]) -> np.ndarray:
    label = b"A215:ChaCha20:R20:key-contrast-mobius:key-disjoint-holdout:v1"
    output: list[int] = []
    seen = set(excluded)
    batch = 0
    while len(output) < HOLDOUT_COUNT:
        raw = hashlib.shake_256(label + batch.to_bytes(4, "little")).digest(3072)
        batch += 1
        for offset in range(0, len(raw), 3):
            value = int.from_bytes(raw[offset : offset + 3], "little") & 0xFFFFF
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
            if len(output) == HOLDOUT_COUNT:
                break
    return np.asarray(output, dtype=np.uint32)


def _key_words(low20: np.ndarray, public: dict[str, Any]) -> np.ndarray:
    keys = np.empty((len(low20), 8), dtype=np.uint32)
    keys[:, 0] = np.uint32(public["known_key_word0_upper12"]) | low20
    keys[:, 1:] = np.asarray(public["known_key_words_1_through_7"], dtype=np.uint32)
    return keys


def _round_outputs(batch: Any, *, carry_free: bool) -> np.ndarray:
    initial = batch.core_round_states[:, :, 0, :]
    if carry_free:
        outputs = batch.core_round_states ^ initial[:, :, None, :]
    else:
        outputs = batch.core_round_states + initial[:, :, None, :]
    return np.transpose(outputs, (0, 2, 1, 3)).copy()


def _trace_bank(
    training: np.ndarray, holdouts: np.ndarray, public: dict[str, Any]
) -> dict[str, Any]:
    low20 = np.concatenate((training, holdouts))
    keys = _key_words(low20, public)
    counters = (
        np.uint32(public["counter_start"])
        + np.arange(BLOCK_COUNT, dtype=np.uint32)
    ).astype(np.uint32)
    nonce = np.asarray(public["nonce_words"], dtype=np.uint32)
    factual = trace_chacha20_batch_words(
        key_words=keys,
        counters=counters,
        nonce_words=nonce,
        rounds=ROUND_COUNT,
        mode="factual",
        selected_trace_blocks=[0],
        chunk_size=256,
    )
    carry_free = trace_chacha20_batch_words(
        key_words=keys,
        counters=counters,
        nonce_words=nonce,
        rounds=ROUND_COUNT,
        mode="carry_free",
        selected_trace_blocks=[0],
        chunk_size=256,
    )
    if (
        not np.array_equal(factual.block_states, _round_outputs(factual, carry_free=False)[:, -1])
        or not np.array_equal(
            carry_free.block_states, _round_outputs(carry_free, carry_free=True)[:, -1]
        )
    ):
        raise RuntimeError("A215 batch feed-forward gate failed")
    return {
        "low20": low20,
        "factual_core": np.transpose(factual.core_round_states, (0, 2, 1, 3)).copy(),
        "factual_output": _round_outputs(factual, carry_free=False),
        "carry_free_core": np.transpose(
            carry_free.core_round_states, (0, 2, 1, 3)
        ).copy(),
        "carry_free_output": _round_outputs(carry_free, carry_free=True),
        "carry_out": factual.selected_block(0).carry_out_masks.copy(),
        "carry_in": factual.selected_block(0).carry_in_masks.copy(),
        "addition_operands": factual.selected_block(0).addition_operands.copy(),
        "modular_sums": factual.selected_block(0).modular_sums.copy(),
        "xor_values": factual.selected_block(0).xor_values.copy(),
        "rotated_values": factual.selected_block(0).rotated_values.copy(),
    }


def _coefficient_bank(trace: dict[str, Any]) -> dict[str, np.ndarray]:
    training_count = len(CENTERS) * len(MASKS)
    outputs = {
        "factual_core": np.empty((4, len(MASKS), 21, 16), dtype=np.uint32),
        "factual_output": np.empty((4, len(MASKS), 21, 8, 16), dtype=np.uint32),
        "carry_free_core": np.empty((4, len(MASKS), 21, 16), dtype=np.uint32),
        "carry_free_output": np.empty((4, len(MASKS), 21, 8, 16), dtype=np.uint32),
        "carry_out": np.empty((4, len(MASKS), 20, 4, 4), dtype=np.uint32),
        "carry_in": np.empty((4, len(MASKS), 20, 4, 4), dtype=np.uint32),
    }
    for center_index in range(4):
        rows = slice(center_index * len(MASKS), (center_index + 1) * len(MASKS))
        outputs["factual_core"][center_index] = local_mobius_coefficients(
            trace["factual_core"][rows, :, 0, :],
            MASKS,
            width=20,
            maximum_order=3,
        )
        outputs["factual_output"][center_index] = local_mobius_coefficients(
            trace["factual_output"][rows], MASKS, width=20, maximum_order=3
        )
        outputs["carry_free_core"][center_index] = local_mobius_coefficients(
            trace["carry_free_core"][rows, :, 0, :],
            MASKS,
            width=20,
            maximum_order=3,
        )
        outputs["carry_free_output"][center_index] = local_mobius_coefficients(
            trace["carry_free_output"][rows], MASKS, width=20, maximum_order=3
        )
        for name in ("carry_out", "carry_in"):
            outputs[name][center_index] = local_mobius_coefficients(
                trace[name][rows], MASKS, width=20, maximum_order=3
            )
    if training_count != 5404:
        raise RuntimeError("A215 training count gate failed")
    return outputs


def _array_manifest(values: np.ndarray) -> dict[str, Any]:
    contiguous = np.ascontiguousarray(values)
    return {
        "shape": list(contiguous.shape),
        "dtype": contiguous.dtype.str,
        "bytes": contiguous.nbytes,
        "sha256": _sha256(contiguous.tobytes(order="C")),
    }


def _trace_manifest(trace: dict[str, Any]) -> dict[str, Any]:
    names = (
        "low20",
        "factual_core",
        "factual_output",
        "carry_free_core",
        "carry_free_output",
        "carry_out",
        "carry_in",
        "addition_operands",
        "modular_sums",
        "xor_values",
        "rotated_values",
    )
    manifest = {name: _array_manifest(trace[name]) for name in names}
    manifest["combined_sha256"] = _canonical_sha256(manifest)
    return manifest


def _active_bits(values: np.ndarray) -> int:
    return int(np.sum(POPCOUNT[values.view(np.uint8)], dtype=np.uint64))


def _degree_profiles(coefficients: np.ndarray, *, payload_bits: int) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    for degree in range(4):
        rows = [index for index, mask in enumerate(MASKS) if mask.bit_count() == degree]
        active = _active_bits(coefficients[:, rows])
        total = int(coefficients.shape[0] * len(rows) * payload_bits)
        profiles.append(
            {
                "degree": degree,
                "coefficient_count_per_center": len(rows),
                "active_bits": active,
                "total_bits": total,
                "density": active / total,
            }
        )
    return profiles


def _round_degree_atlas(coefficients: dict[str, np.ndarray]) -> dict[str, Any]:
    result: dict[str, Any] = {"factual_output": [], "factual_core": [], "carry": []}
    for round_index in range(21):
        result["factual_output"].append(
            {
                "round": round_index,
                "degrees": _degree_profiles(
                    coefficients["factual_output"][:, :, round_index], payload_bits=4096
                ),
            }
        )
        result["factual_core"].append(
            {
                "round": round_index,
                "degrees": _degree_profiles(
                    coefficients["factual_core"][:, :, round_index], payload_bits=512
                ),
            }
        )
    for round_index in range(20):
        combined = np.concatenate(
            (
                coefficients["carry_in"][:, :, round_index],
                coefficients["carry_out"][:, :, round_index],
            ),
            axis=-1,
        )
        result["carry"].append(
            {
                "round": round_index + 1,
                "degrees": _degree_profiles(combined, payload_bits=1024),
            }
        )
    carry_free_high = sum(
        _active_bits(coefficients[name][:, [index for index, mask in enumerate(MASKS) if mask.bit_count() >= 2]])
        for name in ("carry_free_core", "carry_free_output")
    )
    result["carry_free_degree_2_or_3_active_bits"] = carry_free_high
    if carry_free_high != 0:
        raise RuntimeError("A215 carry-free control is not affine")
    return result


def _feature_views(
    trace: dict[str, Any], coefficients: dict[str, np.ndarray]
) -> dict[str, Any]:
    selected_rounds = (1, 2, 3, 4, 6, 8, 10, 12, 16, 20)
    casi = []
    f8 = []
    for center_index, center_name in enumerate(CENTER_NAMES):
        rows = slice(center_index * len(MASKS), (center_index + 1) * len(MASKS))
        for round_index in selected_rounds:
            core = np.ascontiguousarray(
                trace["factual_core"][rows, round_index, 0]
            ).view(np.uint8).reshape(len(MASKS), 64)
            casi.append(
                {
                    "center": center_name,
                    "round": round_index,
                    **canonical_casi_tiles(
                        core,
                        baseline_seed=0xA215000 + 100 * center_index + round_index,
                    ),
                }
            )
        for round_index in range(20):
            first = np.ascontiguousarray(
                trace["factual_core"][rows, round_index, 0]
            ).view(np.uint8).reshape(len(MASKS), 64)
            second = np.ascontiguousarray(
                trace["factual_core"][rows, round_index + 1, 0]
            ).view(np.uint8).reshape(len(MASKS), 64)
            f8.append(
                {
                    "center": center_name,
                    "round_pair": [round_index, round_index + 1],
                    **f8_intervention_transition(first, second, shift=5, alpha=0.05),
                }
            )

    nonlinear_rows = [
        index for index, mask in enumerate(MASKS) if mask.bit_count() >= 2
    ]
    derivative_rows = [
        index for index, mask in enumerate(MASKS) if mask.bit_count() >= 1
    ]
    streams = {
        "canonical_Mobius_coefficient_bitplanes": np.ascontiguousarray(
            coefficients["factual_output"][:, :, 20]
        ).tobytes(),
        "round_stacked_derivatives": np.ascontiguousarray(
            coefficients["factual_core"][:, derivative_rows]
        ).tobytes(),
        "carry_masks": np.ascontiguousarray(
            np.stack((coefficients["carry_in"], coefficients["carry_out"]), axis=-1)
        ).tobytes(),
        "nonlinear_residuals": np.ascontiguousarray(
            coefficients["factual_output"][:, nonlinear_rows, 20]
        ).tobytes(),
    }
    codec = {
        name: codec_length_profile(
            raw,
            permutation_seed=0xA215C00 + index,
            coordinate_bytes=4,
        )
        for index, (name, raw) in enumerate(streams.items())
    }
    return {
        "CASI_canonical_32byte_tiles": casi,
        "F8_adjacent_round_intervention_profiles": f8,
        "six_codec_profiles": codec,
    }


def _predict_orders(
    coefficients: np.ndarray, holdouts: np.ndarray, center: int
) -> dict[int, np.ndarray]:
    delta = holdouts ^ np.uint32(center)
    prediction = np.zeros((len(holdouts), *coefficients.shape[1:]), dtype=np.uint32)
    outputs: dict[int, np.ndarray] = {}
    for degree in range(4):
        for row, mask in enumerate(MASKS):
            if mask.bit_count() != degree:
                continue
            selected = (delta & np.uint32(mask)) == np.uint32(mask)
            if np.any(selected):
                prediction[selected] ^= coefficients[row]
        if degree in ORDERS:
            outputs[degree] = prediction.copy()
    return outputs


def _accuracy_rows(predicted: np.ndarray, actual: np.ndarray) -> list[dict[str, Any]]:
    if predicted.shape != actual.shape or predicted.ndim != 4:
        raise ValueError("A215 validation arrays must have shape (keys, rounds, blocks, words)")
    rows = []
    for round_index in range(predicted.shape[1]):
        difference = predicted[:, round_index] ^ actual[:, round_index]
        error_bits = _active_bits(difference)
        total_bits = int(difference.shape[0] * difference.shape[1] * difference.shape[2] * 32)
        word_exact = difference == 0
        block_exact = np.all(word_exact, axis=2)
        key_exact = np.all(block_exact, axis=1)
        rows.append(
            {
                "round": round_index,
                "bit_accuracy": 1.0 - error_bits / total_bits,
                "error_bits": error_bits,
                "total_bits": total_bits,
                "exact_words": int(np.count_nonzero(word_exact)),
                "total_words": int(word_exact.size),
                "exact_blocks": int(np.count_nonzero(block_exact)),
                "total_blocks": int(block_exact.size),
                "exact_keys_all_8_blocks": int(np.count_nonzero(key_exact)),
            }
        )
    return rows


def _majority_four_with_nearest_tie(
    values: np.ndarray, nearest: np.ndarray
) -> np.ndarray:
    if values.shape[0] != 4:
        raise ValueError("A215 majority requires four center predictions")
    a, b, c, d = values
    at_least_two = (a & b) | (a & c) | (a & d) | (b & c) | (b & d) | (c & d)
    at_least_three = (a & b & c) | (a & b & d) | (a & c & d) | (b & c & d)
    nearest_values = values[nearest, np.arange(values.shape[1])]
    tie = at_least_two & ~at_least_three
    return at_least_three | (tie & nearest_values)


def _validation_atlas(
    coefficients: dict[str, np.ndarray],
    trace: dict[str, Any],
    holdouts: np.ndarray,
) -> tuple[dict[str, Any], np.ndarray]:
    start = 4 * len(MASKS)
    actual = trace["factual_output"][start:]
    actual_carry_free = trace["carry_free_output"][start:]
    predictions = np.empty((4, 3, len(holdouts), 21, 8, 16), dtype=np.uint32)
    carry_free_predictions = np.empty((4, len(holdouts), 21, 8, 16), dtype=np.uint32)
    per_center: list[dict[str, Any]] = []
    for center_index, center in enumerate(CENTERS):
        predicted = _predict_orders(coefficients["factual_output"][center_index], holdouts, center)
        for order_index, order in enumerate(ORDERS):
            predictions[center_index, order_index] = predicted[order]
            per_center.append(
                {
                    "center": CENTER_NAMES[center_index],
                    "order": order,
                    "rounds": _accuracy_rows(predicted[order], actual),
                }
            )
        carry_free = _predict_orders(
            coefficients["carry_free_output"][center_index], holdouts, center
        )[1]
        carry_free_predictions[center_index] = carry_free

    nearest = nearest_center_indices(holdouts, CENTERS, width=20)
    nearest_rows = []
    majority_rows = []
    wrong_rows = []
    best_rows = []
    for order_index, order in enumerate(ORDERS):
        nearest_prediction = predictions[nearest, order_index, np.arange(len(holdouts))]
        wrong_prediction = predictions[(nearest + 1) % 4, order_index, np.arange(len(holdouts))]
        majority = _majority_four_with_nearest_tie(predictions[:, order_index], nearest)
        distances = np.empty((4, len(holdouts), 21), dtype=np.uint16)
        for center_index in range(4):
            difference = predictions[center_index, order_index] ^ actual
            distances[center_index] = np.sum(
                POPCOUNT[difference.view(np.uint8)].reshape(len(holdouts), 21, -1),
                axis=2,
                dtype=np.uint16,
            )
        best_center = np.argmin(distances, axis=0)
        best = np.empty_like(actual)
        for round_index in range(21):
            best[:, round_index] = predictions[
                best_center[:, round_index],
                order_index,
                np.arange(len(holdouts)),
                round_index,
            ]
        nearest_rows.append({"order": order, "rounds": _accuracy_rows(nearest_prediction, actual)})
        wrong_rows.append({"order": order, "rounds": _accuracy_rows(wrong_prediction, actual)})
        majority_rows.append({"order": order, "rounds": _accuracy_rows(majority, actual)})
        best_rows.append({"order": order, "rounds": _accuracy_rows(best, actual)})

    carry_free_nearest = carry_free_predictions[nearest, np.arange(len(holdouts))]
    carry_free_rows = _accuracy_rows(carry_free_nearest, actual_carry_free)
    if any(row["bit_accuracy"] != 1.0 for row in carry_free_rows):
        raise RuntimeError("A215 carry-free first-order holdout prediction is not exact")
    return (
        {
            "per_center": per_center,
            "nearest_center": nearest_rows,
            "majority_four_nearest_tie": majority_rows,
            "wrong_center_rotation": wrong_rows,
            "minimum_output_distance_four_centers": best_rows,
            "carry_free_nearest_order1": carry_free_rows,
            "nearest_center_counts": {
                CENTER_NAMES[index]: int(np.count_nonzero(nearest == index)) for index in range(4)
            },
        },
        predictions,
    )


def _rank_from_distances(distances: np.ndarray, candidate: int) -> int:
    target = int(distances[candidate])
    indices = np.arange(len(distances), dtype=np.uint32)
    return 1 + int(np.count_nonzero(distances < target)) + int(
        np.count_nonzero((distances == target) & (indices < candidate))
    )


def _distance_rows(table: np.ndarray, targets: np.ndarray, *, chunk_size: int = 8192) -> np.ndarray:
    if table.dtype != np.uint32 or targets.dtype != np.uint32:
        raise TypeError("A215 rank tables must use uint32")
    distances = np.empty((len(targets), len(table)), dtype=np.uint16)
    for first in range(0, len(table), chunk_size):
        last = min(first + chunk_size, len(table))
        difference = table[None, first:last] ^ targets[:, None]
        distances[:, first:last] = np.sum(
            POPCOUNT[difference.view(np.uint8)].reshape(len(targets), last - first, -1),
            axis=2,
            dtype=np.uint16,
        )
    return distances


def _global_center_table(local: np.ndarray, center: int) -> np.ndarray:
    candidates = np.arange(1 << 20, dtype=np.uint32)
    return local[candidates ^ np.uint32(center)]


def _rank_models_for_order(
    coefficients: np.ndarray,
    order: int,
    target_outputs: np.ndarray,
    target_keys: np.ndarray,
    null_keys: np.ndarray | None = None,
) -> dict[str, Any]:
    candidate_count = 1 << 20
    candidate_values = np.arange(candidate_count, dtype=np.uint32)
    nearest = nearest_center_indices(candidate_values, CENTERS, width=20)
    with tempfile.TemporaryDirectory(prefix=f"a215-order{order}-") as directory:
        paths = [Path(directory) / f"center-{index}.npy" for index in range(4)]
        for center_index, center in enumerate(CENTERS):
            local = local_truth_table(
                coefficients[center_index], MASKS, width=20, maximum_order=order
            )
            global_table = _global_center_table(local, center)
            np.save(paths[center_index], global_table, allow_pickle=False)
            del local, global_table
        center_tables = [np.load(path, mmap_mode="r") for path in paths]
        nearest_distances = np.empty((len(target_outputs), candidate_count), dtype=np.uint16)
        minimum_distances = np.full_like(nearest_distances, np.iinfo(np.uint16).max)
        majority_distances = np.empty_like(nearest_distances)
        for first in range(0, candidate_count, 8192):
            last = min(first + 8192, candidate_count)
            stacked = np.stack([table[first:last] for table in center_tables])
            local_nearest = nearest[first:last]
            nearest_table = stacked[local_nearest, np.arange(last - first)]
            majority_table = _majority_four_with_nearest_tie(stacked, local_nearest)
            nearest_distances[:, first:last] = _distance_rows(nearest_table, target_outputs)
            majority_distances[:, first:last] = _distance_rows(majority_table, target_outputs)
            for center_index in range(4):
                current = _distance_rows(stacked[center_index], target_outputs)
                minimum_distances[:, first:last] = np.minimum(
                    minimum_distances[:, first:last], current
                )
        models = {
            "nearest_center": nearest_distances,
            "majority_four_nearest_tie": majority_distances,
            "minimum_output_distance_four_centers": minimum_distances,
        }
        result: dict[str, Any] = {"order": order, "models": {}}
        for name, distances in models.items():
            ranks = [
                    _rank_from_distances(distances[index], int(target_keys[index]))
                    for index in range(len(target_keys))
                ]
            model: dict[str, Any] = {
                "ranks": ranks,
                "true_key_distances": [
                    int(distances[index, int(target_keys[index])])
                    for index in range(len(target_keys))
                ],
                "distance_rows_sha256": _sha256(distances.tobytes(order="C")),
            }
            if null_keys is not None:
                if null_keys.ndim != 2 or null_keys.shape[1] != len(target_keys):
                    raise ValueError("A215 null-key bank shape differs from rank challenges")
                null_ranks = [
                    [
                        _rank_from_distances(distances[index], int(null_keys[permutation, index]))
                        for index in range(len(target_keys))
                    ]
                    for permutation in range(len(null_keys))
                ]
                observed_median = float(np.median(ranks))
                null_medians = [float(np.median(row)) for row in null_ranks]
                model["key_label_null"] = {
                    "permutations": len(null_ranks),
                    "null_ranks": null_ranks,
                    "observed_median_rank": observed_median,
                    "null_median_ranks": null_medians,
                    "minimum_null_median_rank": min(null_medians),
                    "maximum_null_median_rank": max(null_medians),
                    "beats_all_null_medians": observed_median < min(null_medians),
                }
            result["models"][name] = model
        return result


def _validation_rank_atlas(
    coefficients: dict[str, np.ndarray], trace: dict[str, Any], holdouts: np.ndarray
) -> tuple[list[dict[str, Any]], np.ndarray]:
    actual_r20 = trace["factual_output"][4 * len(MASKS) :, 20]
    targets = actual_r20[:RANK_CHALLENGE_COUNT]
    keys = holdouts[:RANK_CHALLENGE_COUNT]
    rng = np.random.default_rng(0xA215)
    null_keys = np.stack(
        [rng.permutation(holdouts)[:RANK_CHALLENGE_COUNT] for _ in range(64)]
    ).astype(np.uint32)
    return [
        _rank_models_for_order(
            coefficients["factual_output"][:, :, 20],
            order,
            targets,
            keys,
            null_keys,
        )
        for order in ORDERS
    ], null_keys


def _label_nulls(
    rank_atlas: list[dict[str, Any]], null_keys: np.ndarray
) -> dict[str, Any]:
    summaries = []
    for order_row in rank_atlas:
        for name, model in order_row["models"].items():
            null = model["key_label_null"]
            summaries.append(
                {
                    "order": order_row["order"],
                    "model": name,
                    "observed_median_rank": null["observed_median_rank"],
                    "minimum_null_median_rank": null["minimum_null_median_rank"],
                    "maximum_null_median_rank": null["maximum_null_median_rank"],
                    "beats_all_null_medians": null["beats_all_null_medians"],
                }
            )
    return {
        "permutations": len(null_keys),
        "challenge_count": RANK_CHALLENGE_COUNT,
        "label_bank_uint32_le_sha256": _sha256(null_keys.astype("<u4").tobytes()),
        "model_summaries": summaries,
    }


def _save_measurements(
    output: Path,
    *,
    training: np.ndarray,
    holdouts: np.ndarray,
    coefficients: dict[str, np.ndarray],
) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("wb") as stream:
        np.savez(
            stream,
            training_low20=training,
            holdout_low20=holdouts,
            masks=np.asarray(MASKS, dtype=np.uint32),
            centers=np.asarray(CENTERS, dtype=np.uint32),
            **coefficients,
        )
    temporary.replace(output)
    return {
        "path": str(output),
        "bytes": output.stat().st_size,
        "sha256": _file_sha256(output),
    }


def _postseal_target_low20() -> tuple[int, dict[str, Any]]:
    if _file_sha256(R20_RESULT_PATH) != R20_RESULT_SHA256:
        raise RuntimeError("A215 R20 retained-result hash differs")
    retained = json.loads(R20_RESULT_PATH.read_bytes())
    confirmations = retained.get("confirmations", [])
    values = {
        int(row["recovered_unknown_low20"])
        for row in confirmations
        if row.get("all_blocks_match") is True
    }
    if values != {0xE4934}:
        raise RuntimeError("A215 postseal R20 target reveal differs")
    return values.pop(), {
        "source_result_sha256": R20_RESULT_SHA256,
        "independent_confirmed_modes": len(confirmations),
        "target_reveal_after_prereveal": True,
    }


def _public_target_words(public: dict[str, Any]) -> np.ndarray:
    return np.asarray(public["target_words"], dtype=np.uint32)


def _target_rank_atlas(
    coefficients: dict[str, np.ndarray], public: dict[str, Any], target_low20: int
) -> list[dict[str, Any]]:
    target = _public_target_words(public)[None, ...]
    key = np.asarray([target_low20], dtype=np.uint32)
    return [
        _rank_models_for_order(coefficients["factual_output"][:, :, 20], order, target, key)
        for order in ORDERS
    ]


def _best_validation_model(validation_ranks: list[dict[str, Any]]) -> tuple[int, str, dict[str, Any]]:
    candidates = []
    for order_row in validation_ranks:
        for name, model in order_row["models"].items():
            ranks = np.asarray(model["ranks"], dtype=np.int64)
            candidates.append(
                (
                    float(np.median(ranks)),
                    int(order_row["order"]),
                    name,
                    {
                        "median_rank": float(np.median(ranks)),
                        "mean_rank": float(np.mean(ranks)),
                        "top1024": int(np.count_nonzero(ranks <= 1024)),
                        "ranks": ranks.tolist(),
                        "beats_all_key_label_nulls": bool(
                            model["key_label_null"]["beats_all_null_medians"]
                        ),
                        "minimum_null_median_rank": float(
                            model["key_label_null"]["minimum_null_median_rank"]
                        ),
                    },
                )
            )
    _, order, name, summary = min(candidates, key=lambda row: (row[0], row[1], row[2]))
    return order, name, summary


def _evidence_stage(
    validation_choice: tuple[int, str, dict[str, Any]], target_ranks: list[dict[str, Any]]
) -> str:
    order, name, validation = validation_choice
    target_row = next(row for row in target_ranks if row["order"] == order)
    target_rank = int(target_row["models"][name]["ranks"][0])
    validation_transfer = validation["beats_all_key_label_nulls"]
    if validation_transfer and target_rank <= 1024:
        return "FULLROUND_OUTPUT_SURROGATE_RECOVERY_SIGNAL"
    if validation_transfer:
        return "FULLROUND_OUTPUT_SURROGATE_ENRICHMENT"
    return "R3_RAW_OUTPUT_DEGREE_SATURATION_AND_R20_LOW_ORDER_REPRESENTATION_BOUNDARY"


def _causal_graph(payload: dict[str, Any], output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_key_contrast_mobius_atlas",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": PROTOCOL_SHA256,
            "prereveal_sha256": payload["prereveal_sha256"],
            "target_key_available_before_prereveal": False,
        },
    )
    builder.add_rule(
        ExactRule(
            name="contrast_to_public_output_rank",
            first="constructs_exact_local_Mobius_derivatives",
            second="scores_complete_public_output_candidate_domain",
            conclusion="tests_fullround_output_surrogate_transfer",
        )
    )
    builder.add_triplet(
        edge_id="a215-contrast-bank",
        trigger="A215:four_low_entropy_centers_plus_all_order3_interventions",
        mechanism="constructs_exact_local_Mobius_derivatives",
        outcome="A215:target_free_coefficients_and_holdout_models",
        confidence=1.0,
        evidence_kind="complete_frozen_intervention_bank",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        attrs={
            "center_labeled_traces": 5404,
            "holdouts": HOLDOUT_COUNT,
            "measurement_sha256": payload["measurement_artifact"]["sha256"],
        },
    )
    builder.add_triplet(
        edge_id="a215-carry-localization",
        trigger="A215:exact_factual_and_carry_free_round_traces",
        mechanism="localizes_degree_growth_to_modular_carry",
        outcome="A215:roundwise_degree_and_carry_frontier",
        confidence=1.0,
        evidence_kind="exact_operation_intervention",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        attrs={
            "carry_free_high_degree_active_bits": payload["prereveal"]["degree_atlas"][
                "carry_free_degree_2_or_3_active_bits"
            ]
        },
    )
    builder.add_triplet(
        edge_id="a215-public-rank",
        trigger="A215:target_free_coefficients_and_holdout_models",
        mechanism="scores_complete_public_output_candidate_domain",
        outcome=f"A215:{payload['evidence_stage']}",
        confidence=1.0,
        evidence_kind="postseal_complete_domain_surrogate_ranking",
        source=f"measurement:sha256:{payload['measurement_sha256']}",
        provenance=["a215-contrast-bank"],
        attrs={
            "selected_validation_model": payload["selected_validation_model"],
            "target_ranks": payload["target_ranks"],
        },
    )
    builder.infer_exact_closure(max_hops=4)
    stats = builder.save(output)
    reader = CryptoCausalReader(output)
    if not reader.verify_provenance() or reader.graph_sha256 != stats["graph_sha256"]:
        raise RuntimeError("A215 Causal Reader gate failed")
    return {**stats, "reader_verified": True}


def _report(payload: dict[str, Any], output: Path) -> None:
    selected = payload["selected_validation_model"]
    target_rank = payload["target_ranks"]["selected_model_rank"]
    rounds = {
        row["round"]: row
        for row in next(
            row
            for row in payload["prereveal"]["validation"]["nearest_center"]
            if row["order"] == 3
        )["rounds"]
    }
    lines = [
        "# ChaCha20 R1--R20 key-contrast Mobius atlas (A215)",
        "",
        f"**Evidence stage:** `{payload['evidence_stage']}`",
        "",
        "A215 turns the four low-entropy key patterns into exact intervention centers, "
        "measures every first-, second-, and third-order derivative, and evaluates the "
        "frozen surrogates on 1,024 key-disjoint holdouts before opening the retained "
        "R20 target. The public-output rank never uses a candidate ChaCha evaluation.",
        "",
        "## Round frontier",
        "",
        "| Round | Nearest-center order-3 bit accuracy |",
        "|---:|---:|",
    ]
    for round_index in (0, 1, 2, 3, 4, 8, 12, 16, 20):
        lines.append(f"| {round_index} | {rounds[round_index]['bit_accuracy']:.9f} |")
    lines.extend(
        [
            "",
            "## Complete-domain public-output rank",
            "",
            f"- Validation-selected model: order `{selected['order']}`, `{selected['model']}`",
            f"- Validation median rank: `{selected['summary']['median_rank']:,.1f}` / 1,048,576",
            f"- Public R20 target rank: `{target_rank:,}` / 1,048,576",
            f"- Target low20 (postseal confirmation): `0x{payload['target_reveal']['target_low20']:05x}`",
            "",
            "## Mechanism",
            "",
            "The carry-free XOR control remains exactly affine through R20. Any observed "
            "higher-order coefficient in the factual path is therefore localized to modular "
            "carry generation and its propagation, not to rotation, XOR, layout, or serialization.",
            "",
            f"- Protocol SHA-256: `{PROTOCOL_SHA256}`",
            f"- Prereveal SHA-256: `{payload['prereveal_sha256']}`",
            f"- Measurement artifact SHA-256: `{payload['measurement_artifact']['sha256']}`",
            f"- Causal graph SHA-256: `{payload['causal_artifact']['graph_sha256']}`",
        ]
    )
    _atomic_write(output, ("\n".join(lines) + "\n").encode())


def run(
    *,
    prereveal_output: Path,
    measurement_output: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
) -> dict[str, Any]:
    protocol = _load_protocol()
    public = _load_public_challenge(protocol)
    training, ledger = _training_ledger()
    holdouts = _shake_holdouts(set(int(value) for value in training))
    trace = _trace_bank(training, holdouts, public)
    trace_manifest = _trace_manifest(trace)
    coefficients = _coefficient_bank(trace)
    degree_atlas = _round_degree_atlas(coefficients)
    feature_views = _feature_views(trace, coefficients)
    validation, _predictions = _validation_atlas(coefficients, trace, holdouts)
    measurement = _save_measurements(
        measurement_output,
        training=training,
        holdouts=holdouts,
        coefficients=coefficients,
    )
    validation_ranks, null_keys = _validation_rank_atlas(coefficients, trace, holdouts)
    nulls = _label_nulls(validation_ranks, null_keys)
    width8 = json.loads(WIDTH8_RESULT_PATH.read_bytes())
    if _file_sha256(WIDTH8_RESULT_PATH) != WIDTH8_RESULT_SHA256:
        raise RuntimeError("A215 width8 calibration hash differs")
    prereveal = {
        "schema": PREREVEAL_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "target_key_available": False,
        "target_ciphertext_used_for_model_selection": False,
        "training_key_count": len(training),
        "training_ledger_sha256": _canonical_sha256(ledger),
        "training_low20_uint32_le_sha256": _sha256(training.astype("<u4").tobytes()),
        "holdout_key_count": len(holdouts),
        "holdout_low20_uint32_le_sha256": _sha256(holdouts.astype("<u4").tobytes()),
        "rank_challenge_keys_uint32_le_sha256": _sha256(
            holdouts[:RANK_CHALLENGE_COUNT].astype("<u4").tobytes()
        ),
        "measurement_artifact": measurement,
        "trace_manifest": trace_manifest,
        "degree_atlas": degree_atlas,
        "feature_views": feature_views,
        "validation": validation,
        "validation_complete_domain_ranks": validation_ranks,
        "key_label_null": nulls,
        "width8_calibration": {
            "result_sha256": WIDTH8_RESULT_SHA256,
            "measurement_sha256": width8["measurement_sha256"],
            "evidence_stage": width8["evidence_stage"],
        },
        "all_model_rules_and_target_free_metrics_sealed": True,
    }
    _atomic_json(prereveal_output, prereveal)
    prereveal_sha256 = _file_sha256(prereveal_output)
    if json.loads(prereveal_output.read_bytes()) != prereveal:
        raise RuntimeError("A215 prereveal atomic readback differs")

    target_low20, reveal = _postseal_target_low20()
    if target_low20 in set(int(value) for value in training):
        raise RuntimeError("A215 target collided with a training key")
    target_ranks = _target_rank_atlas(coefficients, public, target_low20)
    selection = _best_validation_model(validation_ranks)
    selected_order, selected_name, selected_summary = selection
    selected_target = next(row for row in target_ranks if row["order"] == selected_order)[
        "models"
    ][selected_name]
    stage = _evidence_stage(selection, target_ranks)
    measurement_payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "prereveal_sha256": prereveal_sha256,
        "prereveal": prereveal,
        "measurement_artifact": measurement,
        "target_reveal": {
            **reveal,
            "target_low20": target_low20,
            "target_low20_hex": f"0x{target_low20:05x}",
            "minimum_center_distance": min((target_low20 ^ center).bit_count() for center in CENTERS),
        },
        "selected_validation_model": {
            "order": selected_order,
            "model": selected_name,
            "summary": selected_summary,
        },
        "target_rank_models": target_ranks,
        "target_ranks": {
            "selected_model_rank": int(selected_target["ranks"][0]),
            "selected_model_distance": int(selected_target["true_key_distances"][0]),
        },
        "evidence_stage": stage,
    }
    measurement_sha256 = _canonical_sha256(measurement_payload)
    payload = {**measurement_payload, "measurement_sha256": measurement_sha256}
    payload["causal_artifact"] = _causal_graph(payload, causal_output)
    _atomic_json(output, payload)
    _report(payload, report_output)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prereveal-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_prereveal.json",
    )
    parser.add_argument(
        "--measurement-output",
        type=Path,
        default=RESEARCH
        / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1.json",
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=RESEARCH / "results/v1/chacha20_round20_key_contrast_mobius_atlas_v1.causal",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=RESEARCH / "reports/CAUSAL_CHACHA20_ROUND20_KEY_CONTRAST_MOBIUS_ATLAS_V1.md",
    )
    args = parser.parse_args()
    payload = run(
        prereveal_output=args.prereveal_output,
        measurement_output=args.measurement_output,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "measurement_sha256": payload["measurement_sha256"],
                "evidence_stage": payload["evidence_stage"],
                "target_rank": payload["target_ranks"]["selected_model_rank"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
