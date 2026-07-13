"""Deterministic F8, CASI-tile, and codec views for intervention atlases."""

from __future__ import annotations

import bz2
import hashlib
import lzma
import zlib
from collections.abc import Callable
from typing import Any

import brotli
import lz4.frame
import numpy as np
import zstandard

from .f8 import _chi_square
from .live_casi_v091 import compute_casi_score


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


def codec_length_profile(
    raw: bytes,
    *,
    permutation_seed: int,
    coordinate_bytes: int = 4,
) -> dict[str, Any]:
    """Measure six code lengths beside a coordinate-permuted control."""
    if not raw:
        raise ValueError("raw codec payload must not be empty")
    if coordinate_bytes < 1 or len(raw) % coordinate_bytes:
        raise ValueError("coordinate_bytes must divide the payload length")
    coordinates = np.frombuffer(raw, dtype=np.uint8).reshape(-1, coordinate_bytes)
    order = np.random.default_rng(permutation_seed).permutation(len(coordinates))
    permuted = np.ascontiguousarray(coordinates[order]).tobytes()
    rows = []
    for name, compress in _CODECS:
        actual = len(compress(raw))
        control = len(compress(permuted))
        rows.append(
            {
                "codec": name,
                "actual_bytes": actual,
                "permuted_control_bytes": control,
                "actual_minus_control_bytes": actual - control,
                "actual_ratio": actual / len(raw),
                "control_ratio": control / len(raw),
            }
        )
    return {
        "raw_bytes": len(raw),
        "coordinate_bytes": coordinate_bytes,
        "coordinate_count": len(coordinates),
        "permutation_seed": permutation_seed,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "permuted_sha256": hashlib.sha256(permuted).hexdigest(),
        "codecs": rows,
    }


def canonical_casi_tiles(
    values: np.ndarray,
    *,
    baseline_seed: int,
) -> dict[str, Any]:
    """Apply CASI independently to canonical consecutive 32-byte tiles."""
    array = np.asarray(values)
    if array.dtype != np.uint8 or array.ndim != 2:
        raise ValueError("CASI values must be a two-dimensional uint8 matrix")
    if array.shape[0] < 100 or array.shape[1] < 32 or array.shape[1] % 32:
        raise ValueError("CASI values need at least 100 rows and a 32-byte tiled width")
    tiles = []
    for tile_index, first in enumerate(range(0, array.shape[1], 32)):
        score = compute_casi_score(
            np.ascontiguousarray(array[:, first : first + 32]),
            baseline_seed=baseline_seed + tile_index,
        )
        tiles.append(
            {
                "tile_index": tile_index,
                "byte_start": first,
                "byte_end_exclusive": first + 32,
                **score,
            }
        )
    return {
        "rows": len(array),
        "bytes_per_row": array.shape[1],
        "tile_count": len(tiles),
        "tiles": tiles,
        "maximum_casi": max(float(row["casi"]) for row in tiles),
        "mean_casi": float(np.mean([row["casi"] for row in tiles])),
    }


def f8_intervention_transition(
    first: np.ndarray,
    second: np.ndarray,
    *,
    shift: int = 5,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Apply the published F8 table test to aligned intervention rows."""
    left = np.asarray(first)
    right = np.asarray(second)
    if (
        left.dtype != np.uint8
        or right.dtype != np.uint8
        or left.ndim != 2
        or left.shape != right.shape
        or len(left) < 1
    ):
        raise ValueError("F8 inputs must be equal non-empty uint8 matrices")
    if not 1 <= shift <= 7 or not 0 < alpha < 1:
        raise ValueError("invalid F8 quantization or alpha")
    bins = 1 << (8 - shift)
    source = left >> shift
    delta = (left ^ right) >> shift
    significant = tested = 0
    maximum_chi2 = 0.0
    for source_position in range(left.shape[1]):
        for target_position in range(left.shape[1]):
            flat = source[:, source_position].astype(np.int64) * bins + delta[:, target_position]
            table = np.bincount(flat, minlength=bins * bins).reshape(bins, bins)
            result = _chi_square(table.astype(float), len(left))
            if result is None:
                continue
            chi2, p_value = result
            tested += 1
            maximum_chi2 = max(maximum_chi2, chi2)
            significant += int(p_value < alpha)
    return {
        "rows": len(left),
        "bytes_per_row": left.shape[1],
        "shift": shift,
        "alpha": alpha,
        "significant_pairs": significant,
        "tested_pairs": tested,
        "significant_rate": significant / max(tested, 1),
        "maximum_chi2": maximum_chi2,
    }


__all__ = [
    "canonical_casi_tiles",
    "codec_length_profile",
    "f8_intervention_transition",
]
