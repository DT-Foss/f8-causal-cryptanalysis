"""Deterministic multiview features for exact CNF propagation clouds."""

from __future__ import annotations

import bz2
import functools
import lzma
import math
import zlib
from collections.abc import Callable

import brotli
import lz4.frame
import numpy as np
import zstandard

from .exact_cnf import ExactCNF, PropagationState


_ZSTD = zstandard.ZstdCompressor(level=9)
_CODECS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("zlib9", lambda raw: zlib.compress(raw, level=9)),
    ("bz2_9", lambda raw: bz2.compress(raw, compresslevel=9)),
    ("lzma6", lambda raw: lzma.compress(raw, preset=6)),
    ("zstd9", _ZSTD.compress),
    (
        "lz4_9",
        lambda raw: lz4.frame.compress(
            raw, compression_level=9, block_linked=True, content_checksum=True
        ),
    ),
    ("brotli9", lambda raw: brotli.compress(raw, quality=9)),
)

F1_NAMES = (
    "f1_new_assigned_variables",
    "f1_new_satisfied_clauses",
    "f1_residual_unsatisfied_binary_clauses",
    "f1_residual_unsatisfied_ternary_clauses",
)
F2_NAMES = (
    "f2_assigned_variable_id_mean",
    "f2_assigned_variable_id_sd",
    "f2_assigned_id_gap_mean",
    "f2_assigned_id_gap_sd",
    "f2_assigned_mask_run_count",
    "f2_assigned_mask_lag1_autocorrelation",
)
F3_NAMES = tuple(
    name
    for codec, _ in _CODECS
    for name in (f"f3_{codec}_bytes", f"f3_{codec}_delta_vs_zero_mask")
)
F4_NAMES = (
    "f4_byte_entropy",
    "f4_byte_frequency_reduced_chi_square",
    "f4_nibble_adjacent_mutual_information",
    "f4_spectral_low_frequency_energy_fraction",
)
FEATURE_NAMES = F1_NAMES + F2_NAMES + F3_NAMES + F4_NAMES


def _payload(mask: np.ndarray) -> bytes:
    packed = np.packbits(mask.astype(np.uint8, copy=False), bitorder="little").tobytes()
    return b"A214MASK\x00" + len(mask).to_bytes(4, "little") + b"LEBIT\x00" + packed


@functools.lru_cache(maxsize=32)
def _zero_code_lengths(variable_count: int) -> tuple[int, ...]:
    raw = _payload(np.zeros(variable_count, dtype=np.bool_))
    return tuple(len(compress(raw)) for _, compress in _CODECS)


def _entropy(values: np.ndarray) -> float:
    counts = np.bincount(values, minlength=256)
    positive = counts[counts > 0].astype(np.float64)
    probabilities = positive / positive.sum()
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _nibble_mi(values: np.ndarray) -> float:
    nibbles = np.empty(2 * len(values), dtype=np.uint8)
    nibbles[0::2] = values >> 4
    nibbles[1::2] = values & 0x0F
    if len(nibbles) < 2:
        return 0.0
    joint = np.bincount(
        nibbles[:-1].astype(np.int64) * 16 + nibbles[1:], minlength=256
    ).reshape(16, 16)
    probability = joint / joint.sum()
    expected = probability.sum(axis=1, keepdims=True) @ probability.sum(
        axis=0, keepdims=True
    )
    valid = probability > 0
    return float(
        np.sum(probability[valid] * np.log2(probability[valid] / expected[valid]))
    )


def extract_propagation_features(
    cnf: ExactCNF,
    base: PropagationState,
    probe: PropagationState,
) -> dict[str, float]:
    """Extract all frozen A214 feature families from one non-conflicting probe."""
    if base.conflicted or probe.conflicted:
        raise ValueError("propagation features require non-conflicting states")
    if len(base.assignment) != cnf.variable_count + 1 or len(probe.assignment) != len(
        base.assignment
    ):
        raise ValueError("propagation state shape differs from CNF")
    new_mask = (probe.assignment[1:] != 0) & (base.assignment[1:] == 0)
    assigned_ids = np.flatnonzero(new_mask).astype(np.float64) + 1.0
    gaps = np.diff(assigned_ids)
    centered = new_mask.astype(np.float64) - float(np.mean(new_mask))
    denominator = float(np.dot(centered, centered))
    lag1 = (
        float(np.dot(centered[:-1], centered[1:]) / denominator)
        if denominator > 0 and len(centered) > 1
        else 0.0
    )
    padded = np.pad(new_mask.astype(np.int8), (1, 0))
    runs = int(np.count_nonzero((padded[1:] == 1) & (padded[:-1] == 0)))
    unsatisfied = ~probe.satisfied
    remaining = probe.remaining

    raw = _payload(new_mask)
    packed = np.packbits(
        new_mask.astype(np.uint8, copy=False), bitorder="little"
    ).astype(np.uint8, copy=False)
    zero_lengths = _zero_code_lengths(cnf.variable_count)
    code_lengths = [len(compress(raw)) for _, compress in _CODECS]
    counts = np.bincount(packed, minlength=256).astype(np.float64)
    expected = len(packed) / 256.0
    reduced_chi = (
        float(np.sum((counts - expected) ** 2 / expected) / 255.0)
        if expected > 0
        else 0.0
    )
    centered_bytes = packed.astype(np.float64) - float(np.mean(packed))
    spectrum = np.abs(np.fft.rfft(centered_bytes)) ** 2
    total_energy = float(np.sum(spectrum[1:]))
    low_end = max(2, 1 + len(spectrum) // 16)
    low_fraction = (
        float(np.sum(spectrum[1:low_end]) / total_energy) if total_energy > 0 else 0.0
    )

    result: dict[str, float] = {
        "f1_new_assigned_variables": float(len(assigned_ids)),
        "f1_new_satisfied_clauses": float(
            np.count_nonzero(probe.satisfied & ~base.satisfied)
        ),
        "f1_residual_unsatisfied_binary_clauses": float(
            np.count_nonzero(unsatisfied & (remaining == 2))
        ),
        "f1_residual_unsatisfied_ternary_clauses": float(
            np.count_nonzero(unsatisfied & (remaining == 3))
        ),
        "f2_assigned_variable_id_mean": float(np.mean(assigned_ids))
        if len(assigned_ids)
        else 0.0,
        "f2_assigned_variable_id_sd": float(np.std(assigned_ids))
        if len(assigned_ids)
        else 0.0,
        "f2_assigned_id_gap_mean": float(np.mean(gaps)) if len(gaps) else 0.0,
        "f2_assigned_id_gap_sd": float(np.std(gaps)) if len(gaps) else 0.0,
        "f2_assigned_mask_run_count": float(runs),
        "f2_assigned_mask_lag1_autocorrelation": lag1,
    }
    for (codec, _), length, zero_length in zip(
        _CODECS, code_lengths, zero_lengths, strict=True
    ):
        result[f"f3_{codec}_bytes"] = float(length)
        result[f"f3_{codec}_delta_vs_zero_mask"] = float(length - zero_length)
    result.update(
        {
            "f4_byte_entropy": _entropy(packed),
            "f4_byte_frequency_reduced_chi_square": reduced_chi,
            "f4_nibble_adjacent_mutual_information": _nibble_mi(packed),
            "f4_spectral_low_frequency_energy_fraction": low_fraction,
        }
    )
    if tuple(result) != FEATURE_NAMES or not all(math.isfinite(value) for value in result.values()):
        raise RuntimeError("A214 propagation feature schema or finiteness gate failed")
    return result
