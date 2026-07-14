"""Prefix-blind nonlinear Product-of-Experts for fresh candidate trajectories."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from arx_carry_leak.fresh_candidate_reader import (
    FEATURE_NAMES,
    CandidateFeatureTable,
    concatenate_training,
)


@dataclass(frozen=True)
class DiagonalGaussianPoE:
    """Clipped diagonal Gaussian log-likelihood-ratio ensemble.

    Every feature is an expert.  The correct-candidate class may occupy a band
    rather than one side of a hyperplane, so each expert contributes a
    quadratic Gaussian log-likelihood ratio.  Per-expert clipping prevents a
    single low-support positive variance estimate from dominating the product.
    """

    feature_names: tuple[str, ...]
    positive_means: tuple[float, ...]
    negative_means: tuple[float, ...]
    positive_variances: tuple[float, ...]
    negative_variances: tuple[float, ...]
    positive_variance_shrinkage: float
    expert_log_ratio_cap: float
    positive_count: int
    negative_count: int

    def scores(self, matrix: np.ndarray) -> np.ndarray:
        values = np.asarray(matrix, dtype=np.float64)
        if (
            values.ndim != 2
            or values.shape[1] != len(self.feature_names)
            or not np.isfinite(values).all()
        ):
            raise ValueError("nonlinear PoE feature matrix differs")
        positive_means = np.asarray(self.positive_means)
        negative_means = np.asarray(self.negative_means)
        positive_variances = np.asarray(self.positive_variances)
        negative_variances = np.asarray(self.negative_variances)
        log_ratio = -0.5 * (
            np.log(positive_variances / negative_variances)
            + np.square(values - positive_means) / positive_variances
            - np.square(values - negative_means) / negative_variances
        )
        np.clip(
            log_ratio,
            -self.expert_log_ratio_cap,
            self.expert_log_ratio_cap,
            out=log_ratio,
        )
        result = log_ratio.mean(axis=1)
        if not np.isfinite(result).all():
            raise RuntimeError("nonlinear PoE produced non-finite scores")
        return result

    def as_dict(self) -> dict[str, object]:
        return {
            "model": "clipped_diagonal_gaussian_product_of_experts",
            "feature_names": list(self.feature_names),
            "positive_means": list(self.positive_means),
            "negative_means": list(self.negative_means),
            "positive_variances": list(self.positive_variances),
            "negative_variances": list(self.negative_variances),
            "positive_variance_shrinkage": self.positive_variance_shrinkage,
            "expert_log_ratio_cap": self.expert_log_ratio_cap,
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
        }


def fit_diagonal_gaussian_poe(
    tables: Sequence[CandidateFeatureTable],
    *,
    positive_variance_shrinkage: float,
    expert_log_ratio_cap: float,
) -> DiagonalGaussianPoE:
    """Fit a deterministic nonlinear reader without candidate coordinates."""
    if (
        not 0.0 <= positive_variance_shrinkage < 1.0
        or not np.isfinite(positive_variance_shrinkage)
        or expert_log_ratio_cap <= 0.0
        or not np.isfinite(expert_log_ratio_cap)
    ):
        raise ValueError("nonlinear PoE hyperparameters are invalid")
    matrix, labels = concatenate_training(tables)
    positive = labels == 1
    negative = ~positive
    positive_count = int(np.count_nonzero(positive))
    negative_count = int(np.count_nonzero(negative))
    if positive_count < 2 or negative_count < 2:
        raise ValueError("nonlinear PoE needs both classes with repeated support")
    positive_values = matrix[positive]
    negative_values = matrix[negative]
    positive_means = positive_values.mean(axis=0)
    negative_means = negative_values.mean(axis=0)
    positive_variances = positive_values.var(axis=0)
    negative_variances = negative_values.var(axis=0)
    pooled_variances = (
        positive_count * positive_variances + negative_count * negative_variances
    ) / (positive_count + negative_count)
    floor = np.maximum(1e-8, pooled_variances * 1e-6)
    positive_variances = (
        (1.0 - positive_variance_shrinkage) * positive_variances
        + positive_variance_shrinkage * pooled_variances
    )
    positive_variances = np.maximum(positive_variances, floor)
    negative_variances = np.maximum(negative_variances, floor)
    arrays = (
        positive_means,
        negative_means,
        positive_variances,
        negative_variances,
    )
    if any(array.shape != (len(FEATURE_NAMES),) for array in arrays) or not all(
        np.isfinite(array).all() for array in arrays
    ):
        raise RuntimeError("nonlinear PoE fit produced invalid parameters")
    return DiagonalGaussianPoE(
        feature_names=FEATURE_NAMES,
        positive_means=tuple(float(value) for value in positive_means),
        negative_means=tuple(float(value) for value in negative_means),
        positive_variances=tuple(float(value) for value in positive_variances),
        negative_variances=tuple(float(value) for value in negative_variances),
        positive_variance_shrinkage=float(positive_variance_shrinkage),
        expert_log_ratio_cap=float(expert_log_ratio_cap),
        positive_count=positive_count,
        negative_count=negative_count,
    )
