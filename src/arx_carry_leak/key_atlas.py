"""Deterministic ridge-logistic and factor-table utilities for key atlases."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize


@dataclass(frozen=True)
class RidgeLogisticModel:
    feature_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    intercept: float
    coefficients: tuple[float, ...]
    ridge_lambda: float
    optimizer_iterations: int
    optimizer_gradient_norm: float

    def logits(self, matrix: np.ndarray) -> np.ndarray:
        values = np.asarray(matrix, dtype=np.float64)
        if values.ndim != 2 or values.shape[1] != len(self.feature_names):
            raise ValueError("feature matrix shape differs from fitted model")
        means = np.asarray(self.means)
        scales = np.asarray(self.scales)
        coefficients = np.asarray(self.coefficients)
        standardized = (values - means) / scales
        return self.intercept + np.einsum("ij,j->i", standardized, coefficients, optimize=False)

    def as_dict(self) -> dict[str, object]:
        return {
            "feature_names": list(self.feature_names),
            "means": list(self.means),
            "scales": list(self.scales),
            "intercept": self.intercept,
            "coefficients": list(self.coefficients),
            "ridge_lambda": self.ridge_lambda,
            "optimizer_iterations": self.optimizer_iterations,
            "optimizer_gradient_norm": self.optimizer_gradient_norm,
        }


def fit_ridge_logistic(
    matrix: np.ndarray,
    labels: np.ndarray,
    *,
    feature_names: Sequence[str],
    ridge_lambda: float,
) -> RidgeLogisticModel:
    """Fit a class-balanced deterministic ridge-logistic model with L-BFGS."""
    values = np.asarray(matrix, dtype=np.float64)
    targets = np.asarray(labels, dtype=np.float64)
    if (
        values.ndim != 2
        or targets.shape != (len(values),)
        or values.shape[1] != len(feature_names)
        or not np.isfinite(values).all()
        or not set(np.unique(targets)).issubset({0.0, 1.0})
        or len(np.unique(targets)) != 2
        or ridge_lambda <= 0
    ):
        raise ValueError("invalid ridge-logistic training data")
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    near_constant = scales <= np.maximum(1e-10, np.abs(means) * 1e-10)
    scales[near_constant] = 1.0
    standardized = (values - means) / scales
    standardized[:, near_constant] = 0.0
    if not np.isfinite(standardized).all():
        raise RuntimeError("ridge-logistic standardization produced non-finite values")
    positive = targets == 1
    negative = ~positive
    weights = np.empty(len(targets), dtype=np.float64)
    weights[positive] = 0.5 / np.count_nonzero(positive)
    weights[negative] = 0.5 / np.count_nonzero(negative)

    def objective(parameters: np.ndarray) -> tuple[float, np.ndarray]:
        intercept = parameters[0]
        coefficients = parameters[1:]
        logits = intercept + np.einsum("ij,j->i", standardized, coefficients, optimize=False)
        if not np.isfinite(logits).all():
            return float("inf"), np.zeros_like(parameters)
        loss = np.sum(weights * (np.logaddexp(0.0, logits) - targets * logits))
        loss += (
            0.5
            * ridge_lambda
            * float(np.einsum("i,i->", coefficients, coefficients, optimize=False))
        )
        residual = weights * (1.0 / (1.0 + np.exp(-np.clip(logits, -40, 40))) - targets)
        gradient = np.concatenate(
            (
                [float(np.sum(residual))],
                np.einsum("ij,i->j", standardized, residual, optimize=False)
                + ridge_lambda * coefficients,
            )
        )
        return float(loss), gradient

    initial = np.zeros(values.shape[1] + 1, dtype=np.float64)
    result = minimize(
        objective,
        initial,
        method="L-BFGS-B",
        jac=True,
        bounds=[(-50.0, 50.0)] * len(initial),
        options={"ftol": 1e-13, "gtol": 1e-9, "maxiter": 2000, "maxls": 50},
    )
    if not result.success or not np.isfinite(result.x).all():
        raise RuntimeError(f"ridge-logistic optimizer failed: {result.message}")
    result.x[1:][near_constant] = 0.0
    _, gradient = objective(result.x)
    return RidgeLogisticModel(
        feature_names=tuple(feature_names),
        means=tuple(float(value) for value in means),
        scales=tuple(float(value) for value in scales),
        intercept=float(result.x[0]),
        coefficients=tuple(float(value) for value in result.x[1:]),
        ridge_lambda=float(ridge_lambda),
        optimizer_iterations=int(result.nit),
        optimizer_gradient_norm=float(np.linalg.norm(gradient)),
    )


def candidate_scores(
    unary_logits: np.ndarray,
    pair_logits: np.ndarray,
    *,
    width: int = 20,
) -> np.ndarray:
    """Sum unary and upper-triangular pair factors for all ``2**width`` keys."""
    unary = np.asarray(unary_logits, dtype=np.float64)
    pairs = np.asarray(pair_logits, dtype=np.float64)
    if unary.shape != (width, 2) or pairs.shape != (width, width, 2, 2):
        raise ValueError("factor table shape differs from key width")
    candidates = np.arange(1 << width, dtype=np.uint32)
    bits = [((candidates >> bit) & 1).astype(np.uint8) for bit in range(width)]
    scores = np.zeros(len(candidates), dtype=np.float64)
    for bit in range(width):
        scores += unary[bit, bits[bit]]
    for first in range(width):
        for second in range(first + 1, width):
            scores += pairs[first, second, bits[first], bits[second]]
    return scores


def exact_rank(scores: np.ndarray, candidate: int) -> int:
    """One-based descending rank with ascending-candidate tie breaking."""
    values = np.asarray(scores, dtype=np.float64)
    if candidate < 0 or candidate >= len(values):
        raise ValueError("candidate outside score domain")
    target = values[candidate]
    candidates = np.arange(len(values), dtype=np.int64)
    return (
        1
        + int(np.count_nonzero(values > target))
        + int(np.count_nonzero((values == target) & (candidates < candidate)))
    )


def candidate_order(scores: np.ndarray) -> np.ndarray:
    """Descending score order with ascending-candidate tie breaking."""
    values = np.asarray(scores, dtype=np.float64)
    candidates = np.arange(len(values), dtype=np.uint32)
    return np.lexsort((candidates, -values)).astype(np.uint32, copy=False)
