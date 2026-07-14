"""Fixed local operators on complete 8-bit candidate score fields."""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np

CANDIDATE_BITS = 8
CANDIDATE_COUNT = 1 << CANDIDATE_BITS


def _score_vector(scores: Sequence[float] | np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CANDIDATE_COUNT,) or not np.isfinite(values).all():
        raise ValueError("candidate score field must contain 256 finite values")
    return values


def neighbor_matrix(scores: Sequence[float] | np.ndarray) -> np.ndarray:
    """Return scores of each candidate's eight Hamming-distance-one neighbors."""

    values = _score_vector(scores)
    candidates = np.arange(CANDIDATE_COUNT, dtype=np.int64)
    return np.stack(
        [values[np.bitwise_xor(candidates, 1 << bit)] for bit in range(CANDIDATE_BITS)],
        axis=1,
    )


def local_pairwise_residual(scores: Sequence[float] | np.ndarray) -> np.ndarray:
    """Apply the normalized hypercube Laplacian: score minus neighbor mean."""

    values = _score_vector(scores)
    return values - neighbor_matrix(values).mean(axis=1)


def paired_margins(
    scores: Sequence[float] | np.ndarray, candidate: int
) -> np.ndarray:
    """Return the eight directed score margins from candidate to its neighbors."""

    values = _score_vector(scores)
    if not isinstance(candidate, int) or isinstance(candidate, bool) or not 0 <= candidate < 256:
        raise ValueError("candidate must be an integer in 0...255")
    return np.asarray(
        [values[candidate] - values[candidate ^ (1 << bit)] for bit in range(8)],
        dtype=np.float64,
    )


def descending_midrank(scores: Sequence[float] | np.ndarray, candidate: int) -> float:
    """One-based descending midrank with exact tie handling."""

    values = _score_vector(scores)
    if not isinstance(candidate, int) or isinstance(candidate, bool) or not 0 <= candidate < 256:
        raise ValueError("candidate must be an integer in 0...255")
    target = float(values[candidate])
    return float(
        1
        + np.count_nonzero(values > target)
        + 0.5 * (np.count_nonzero(values == target) - 1)
    )


def mean_log2_rank(ranks: Sequence[float]) -> float:
    values = [float(rank) for rank in ranks]
    if not values or any(not math.isfinite(rank) or rank < 1.0 for rank in values):
        raise ValueError("ranks must be finite and at least one")
    return sum(math.log2(rank) for rank in values) / len(values)
