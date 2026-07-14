from __future__ import annotations

import numpy as np
import pytest

from arx_carry_leak.fresh_candidate_nonlinear import fit_diagonal_gaussian_poe
from arx_carry_leak.fresh_candidate_reader import FEATURE_NAMES, CandidateFeatureTable


def _table(label: str, true_prefix: int, shift: float) -> CandidateFeatureTable:
    candidates = np.arange(256, dtype=np.float64)
    signs = np.where((np.arange(256) & 1) == 0, -1.0, 1.0)
    matrix = np.empty((256, len(FEATURE_NAMES)), dtype=np.float64)
    for column in range(len(FEATURE_NAMES)):
        scale = 2.0 + 0.01 * (column % 7)
        matrix[:, column] = signs * scale + 0.001 * candidates + shift
    # The positive class sits in the middle of the symmetric wrong-key cloud;
    # a one-sided linear score cannot represent this relation.
    matrix[true_prefix] = shift
    return CandidateFeatureTable(
        label=label,
        true_prefix=true_prefix,
        candidates=tuple(range(256)),
        feature_names=FEATURE_NAMES,
        matrix=matrix,
    )


def test_nonlinear_poe_ranks_band_center_first() -> None:
    training = [_table(f"train_{index}", 17 + index, 0.02 * index) for index in range(8)]
    model = fit_diagonal_gaussian_poe(
        training,
        positive_variance_shrinkage=0.5,
        expert_log_ratio_cap=1.0,
    )
    holdout = _table("holdout", 211, 0.07)
    scores = model.scores(holdout.matrix)
    assert int(np.argmax(scores)) == holdout.true_prefix
    assert model.positive_count == 8
    assert model.negative_count == 8 * 255


def test_nonlinear_poe_is_deterministic_and_coordinate_free() -> None:
    tables = [_table(f"train_{index}", 31 + index, 0.01 * index) for index in range(4)]
    first = fit_diagonal_gaussian_poe(
        tables,
        positive_variance_shrinkage=0.5,
        expert_log_ratio_cap=2.0,
    )
    second = fit_diagonal_gaussian_poe(
        tables,
        positive_variance_shrinkage=0.5,
        expert_log_ratio_cap=2.0,
    )
    assert first.as_dict() == second.as_dict()
    assert all("candidate" not in name for name in first.feature_names)


@pytest.mark.parametrize(
    ("shrinkage", "cap"),
    [(-0.1, 1.0), (1.0, 1.0), (0.5, 0.0), (0.5, float("inf"))],
)
def test_nonlinear_poe_rejects_invalid_hyperparameters(
    shrinkage: float, cap: float
) -> None:
    with pytest.raises(ValueError):
        fit_diagonal_gaussian_poe(
            [_table("a", 1, 0.0), _table("b", 2, 0.1)],
            positive_variance_shrinkage=shrinkage,
            expert_log_ratio_cap=cap,
        )
