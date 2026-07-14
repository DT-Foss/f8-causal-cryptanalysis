from __future__ import annotations

import numpy as np
import pytest

from arx_carry_leak.score_hypercube import (
    descending_midrank,
    local_pairwise_residual,
    mean_log2_rank,
    neighbor_matrix,
    paired_margins,
)


def test_neighbors_are_exact_hamming_one_transitions() -> None:
    scores = np.arange(256, dtype=np.float64)
    neighbors = neighbor_matrix(scores)
    assert neighbors.shape == (256, 8)
    assert neighbors[0].tolist() == [1, 2, 4, 8, 16, 32, 64, 128]
    assert neighbors[173].tolist() == [172, 175, 169, 165, 189, 141, 237, 45]


def test_local_residual_removes_constant_and_is_zero_sum() -> None:
    constant = np.full(256, 7.0)
    assert np.array_equal(local_pairwise_residual(constant), np.zeros(256))
    scores = np.arange(256, dtype=np.float64) ** 2
    residual = local_pairwise_residual(scores)
    assert abs(float(residual.sum())) < 1e-10
    assert np.allclose(residual, scores - neighbor_matrix(scores).mean(axis=1))


def test_pairwise_margins_and_midrank() -> None:
    scores = np.arange(256, dtype=np.float64)
    assert paired_margins(scores, 0).tolist() == [-1, -2, -4, -8, -16, -32, -64, -128]
    assert descending_midrank(scores, 255) == 1.0
    tied = np.zeros(256)
    assert descending_midrank(tied, 0) == 128.5
    assert mean_log2_rank([1, 2, 4, 8]) == 1.5


@pytest.mark.parametrize("bad", [np.zeros(255), np.zeros(257), np.full(256, np.nan)])
def test_invalid_score_geometry_is_rejected(bad: np.ndarray) -> None:
    with pytest.raises(ValueError, match="256 finite"):
        local_pairwise_residual(bad)
