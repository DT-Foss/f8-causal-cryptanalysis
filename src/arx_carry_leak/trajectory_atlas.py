"""Deterministic feature views and linear readouts for retained solver trajectories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.stats import rankdata

from arx_carry_leak.key_atlas import fit_ridge_logistic

CHANNEL_NAMES = (
    "conflicts",
    "decisions",
    "search_propagations",
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
)
OPERATOR_NAMES = ("numeric", "reflected_gray8")
FEATURE_FAMILY_ORDER = ("F1_local", "F2_cross", "F3_cube", "F4_path", "F5_all")
READOUT_ORDER = ("ridge_logistic", "gram_wiener_fisher")


@dataclass(frozen=True)
class FeatureView:
    names: tuple[str, ...]
    matrix: np.ndarray


@dataclass(frozen=True)
class LinearReadout:
    """A standardized linear cell-scoring operator."""

    kind: str
    feature_family: str
    feature_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    intercept: float
    coefficients: tuple[float, ...]
    ridge_lambda: float
    diagnostics: Mapping[str, Any]

    def scores(self, matrix: np.ndarray) -> np.ndarray:
        values = np.asarray(matrix, dtype=np.float64)
        if values.ndim != 2 or values.shape[1] != len(self.feature_names):
            raise ValueError("trajectory feature matrix differs from fitted readout")
        standardized = (values - np.asarray(self.means)) / np.asarray(self.scales)
        return self.intercept + np.einsum(
            "ij,j->i",
            standardized,
            np.asarray(self.coefficients),
            optimize=False,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "feature_family": self.feature_family,
            "feature_names": list(self.feature_names),
            "means": list(self.means),
            "scales": list(self.scales),
            "intercept": self.intercept,
            "coefficients": list(self.coefficients),
            "ridge_lambda": self.ridge_lambda,
            "diagnostics": dict(self.diagnostics),
        }


def readout_from_dict(value: Mapping[str, Any]) -> LinearReadout:
    return LinearReadout(
        kind=str(value["kind"]),
        feature_family=str(value["feature_family"]),
        feature_names=tuple(str(name) for name in value["feature_names"]),
        means=tuple(float(item) for item in value["means"]),
        scales=tuple(float(item) for item in value["scales"]),
        intercept=float(value["intercept"]),
        coefficients=tuple(float(item) for item in value["coefficients"]),
        ridge_lambda=float(value["ridge_lambda"]),
        diagnostics=dict(value["diagnostics"]),
    )


def _signed_log1p(values: np.ndarray) -> np.ndarray:
    return np.sign(values) * np.log1p(np.abs(values))


def _zscore(values: np.ndarray) -> np.ndarray:
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    threshold = np.maximum(1e-12, np.abs(means) * 1e-12)
    constant = scales <= threshold
    safe_scales = scales.copy()
    safe_scales[constant] = 1.0
    result = (values - means) / safe_scales
    result[:, constant] = 0.0
    return result


def _centered_ranks(values: np.ndarray) -> np.ndarray:
    result = np.empty_like(values, dtype=np.float64)
    denominator = max(1, len(values) - 1)
    for column in range(values.shape[1]):
        ranks = rankdata(values[:, column], method="average")
        result[:, column] = 2.0 * (ranks - 1.0) / denominator - 1.0
    return result


def _aligned_rows(trajectory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = trajectory.get("rows")
    if not isinstance(rows, list) or len(rows) != 256:
        raise ValueError("trajectory must contain 256 rows")
    by_prefix: dict[int, Mapping[str, Any]] = {}
    for row in rows:
        prefix = row.get("prefix8")
        if (
            not isinstance(prefix, str)
            or len(prefix) != 8
            or set(prefix) - {"0", "1"}
            or int(prefix, 2) in by_prefix
        ):
            raise ValueError("trajectory prefix cover is malformed")
        by_prefix[int(prefix, 2)] = row
    if set(by_prefix) != set(range(256)):
        raise ValueError("trajectory prefix cover is incomplete")
    return [by_prefix[prefix] for prefix in range(256)]


def _channel_matrix(trajectory: Mapping[str, Any]) -> np.ndarray:
    rows = _aligned_rows(trajectory)
    matrix = np.empty((256, len(CHANNEL_NAMES)), dtype=np.float64)
    for index, row in enumerate(rows):
        metrics = row.get("metrics_delta")
        if not isinstance(metrics, list) or len(metrics) != 3:
            raise ValueError("trajectory metric delta is malformed")
        raw = [
            metrics[0],
            metrics[1],
            metrics[2],
            row.get("active_variables_delta"),
            row.get("irredundant_clauses_delta"),
            row.get("redundant_clauses_delta"),
        ]
        if any(not isinstance(value, int) for value in raw):
            raise ValueError("trajectory feature channel is not integral")
        if any(value < 0 for value in raw[:3]):
            raise ValueError("trajectory search-work delta is negative")
        matrix[index, :3] = np.log1p(raw[:3])
        matrix[index, 3:] = _signed_log1p(np.asarray(raw[3:], dtype=np.float64))
    if not np.isfinite(matrix).all():
        raise ValueError("trajectory transform produced a non-finite value")
    return matrix


def _operator_positions(trajectory: Mapping[str, Any]) -> tuple[np.ndarray, np.ndarray]:
    rows = trajectory.get("rows")
    if not isinstance(rows, list) or len(rows) != 256:
        raise ValueError("trajectory order is malformed")
    order = np.asarray([int(row["prefix8"], 2) for row in rows], dtype=np.int64)
    if set(order.tolist()) != set(range(256)):
        raise ValueError("trajectory order is not a complete prefix permutation")
    position = np.empty(256, dtype=np.int64)
    position[order] = np.arange(256)
    return order, position


def _hypercube_residual(matrix: np.ndarray) -> np.ndarray:
    result = np.empty_like(matrix)
    for prefix in range(256):
        neighbors = [prefix ^ (1 << bit) for bit in range(8)]
        result[prefix] = matrix[prefix] - matrix[neighbors].mean(axis=0)
    return result


def _path_gradients(
    matrix: np.ndarray, trajectory: Mapping[str, Any]
) -> tuple[np.ndarray, np.ndarray]:
    order, position = _operator_positions(trajectory)
    predecessor = order[(position - 1) % 256]
    successor = order[(position + 1) % 256]
    return matrix - matrix[predecessor], matrix - matrix[successor]


def extract_feature_views(
    trajectories: Mapping[str, Mapping[str, Any]],
) -> dict[str, FeatureView]:
    """Create the five predeclared A218 feature families for one challenge."""
    if set(trajectories) != set(OPERATOR_NAMES):
        raise ValueError("A218 requires exactly Numeric and reflected-Gray8 trajectories")

    local_parts: list[np.ndarray] = []
    local_names: list[str] = []
    operator_views: dict[str, dict[str, np.ndarray]] = {}
    for operator in OPERATOR_NAMES:
        transformed = _channel_matrix(trajectories[operator])
        operator_views[operator] = {
            "z": _zscore(transformed),
            "rank": _centered_ranks(transformed),
        }
        for view in ("z", "rank"):
            local_parts.append(operator_views[operator][view])
            local_names.extend(f"{operator}.{view}.{channel}" for channel in CHANNEL_NAMES)
    local = np.column_stack(local_parts)

    cross_parts: list[np.ndarray] = []
    cross_names: list[str] = []
    root2 = np.sqrt(2.0)
    for view in ("z", "rank"):
        numeric = operator_views["numeric"][view]
        gray = operator_views["reflected_gray8"][view]
        cross_parts.extend(((numeric + gray) / root2, (numeric - gray) / root2))
        for channel in CHANNEL_NAMES:
            cross_names.append(f"cross.{view}.sum.{channel}")
        for channel in CHANNEL_NAMES:
            cross_names.append(f"cross.{view}.difference.{channel}")
    cross = np.column_stack(cross_parts)

    cube = _hypercube_residual(local)
    cube_names = [f"cube_h1.{name}" for name in local_names]

    path_parts: list[np.ndarray] = []
    path_names: list[str] = []
    column = 0
    for operator in OPERATOR_NAMES:
        width = 2 * len(CHANNEL_NAMES)
        operator_local = local[:, column : column + width]
        column += width
        predecessor, successor = _path_gradients(operator_local, trajectories[operator])
        path_parts.extend((predecessor, successor))
        operator_local_names = [
            f"{operator}.{view}.{channel}" for view in ("z", "rank") for channel in CHANNEL_NAMES
        ]
        path_names.extend(f"path_predecessor.{name}" for name in operator_local_names)
        path_names.extend(f"path_successor.{name}" for name in operator_local_names)
    path = np.column_stack(path_parts)

    components = {
        "local": (local, local_names),
        "cross": (cross, cross_names),
        "cube": (cube, cube_names),
        "path": (path, path_names),
    }
    layouts = {
        "F1_local": ("local",),
        "F2_cross": ("local", "cross"),
        "F3_cube": ("local", "cross", "cube"),
        "F4_path": ("local", "cross", "path"),
        "F5_all": ("local", "cross", "cube", "path"),
    }
    result: dict[str, FeatureView] = {}
    for family in FEATURE_FAMILY_ORDER:
        selected = layouts[family]
        matrix = np.column_stack([components[name][0] for name in selected])
        names = tuple(feature for name in selected for feature in components[name][1])
        if matrix.shape != (256, len(names)) or not np.isfinite(matrix).all():
            raise RuntimeError(f"A218 feature family {family} is malformed")
        result[family] = FeatureView(names=names, matrix=matrix)
    return result


def _standardization(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    constant = scales <= np.maximum(1e-10, np.abs(means) * 1e-10)
    scales[constant] = 1.0
    standardized = (values - means) / scales
    standardized[:, constant] = 0.0
    return standardized, means, scales


def fit_linear_readout(
    matrix: np.ndarray,
    labels: np.ndarray,
    *,
    kind: str,
    feature_family: str,
    feature_names: Sequence[str],
    ridge_lambda: float,
) -> LinearReadout:
    values = np.asarray(matrix, dtype=np.float64)
    targets = np.asarray(labels, dtype=np.uint8)
    if (
        kind not in READOUT_ORDER
        or feature_family not in FEATURE_FAMILY_ORDER
        or values.ndim != 2
        or values.shape[1] != len(feature_names)
        or targets.shape != (len(values),)
        or set(np.unique(targets)) != {0, 1}
        or ridge_lambda <= 0
        or not np.isfinite(values).all()
    ):
        raise ValueError("invalid A218 readout training data")

    if kind == "ridge_logistic":
        fitted = fit_ridge_logistic(
            values,
            targets,
            feature_names=feature_names,
            ridge_lambda=ridge_lambda,
        )
        return LinearReadout(
            kind=kind,
            feature_family=feature_family,
            feature_names=tuple(feature_names),
            means=fitted.means,
            scales=fitted.scales,
            intercept=fitted.intercept,
            coefficients=fitted.coefficients,
            ridge_lambda=ridge_lambda,
            diagnostics={
                "optimizer_iterations": fitted.optimizer_iterations,
                "optimizer_gradient_norm": fitted.optimizer_gradient_norm,
            },
        )

    standardized, means, scales = _standardization(values)
    positive = standardized[targets == 1]
    negative = standardized[targets == 0]
    if len(positive) < 2 or len(negative) < 2:
        raise ValueError("Gram/Wiener readout requires at least two rows per class")
    positive_mean = positive.mean(axis=0)
    negative_mean = negative.mean(axis=0)
    positive_centered = positive - positive_mean
    negative_centered = negative - negative_mean
    positive_covariance = np.einsum(
        "ni,nj->ij", positive_centered, positive_centered, optimize=False
    ) / (len(positive) - 1)
    negative_covariance = np.einsum(
        "ni,nj->ij", negative_centered, negative_centered, optimize=False
    ) / (len(negative) - 1)
    covariance = 0.5 * (positive_covariance + negative_covariance)
    system = covariance + ridge_lambda * np.eye(values.shape[1])
    contrast = positive_mean - negative_mean
    coefficients = np.linalg.solve(system, contrast)
    intercept = -0.5 * float(
        np.einsum("i,i->", positive_mean + negative_mean, coefficients, optimize=False)
    )
    residual = np.einsum("ij,j->i", system, coefficients, optimize=False) - contrast
    condition = float(np.linalg.cond(system))
    if not np.isfinite(coefficients).all() or not np.isfinite(condition):
        raise RuntimeError("Gram/Wiener readout is non-finite")
    return LinearReadout(
        kind=kind,
        feature_family=feature_family,
        feature_names=tuple(feature_names),
        means=tuple(float(value) for value in means),
        scales=tuple(float(value) for value in scales),
        intercept=intercept,
        coefficients=tuple(float(value) for value in coefficients),
        ridge_lambda=ridge_lambda,
        diagnostics={
            "linear_system_condition_number": condition,
            "linear_system_residual_l2": float(np.linalg.norm(residual)),
            "positive_rows": len(positive),
            "negative_rows": len(negative),
        },
    )


def exact_rank(scores: np.ndarray, target_prefix: int) -> int:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or target_prefix < 0 or target_prefix >= 256:
        raise ValueError("invalid A218 prefix-rank input")
    target = values[target_prefix]
    prefixes = np.arange(256)
    return (
        1
        + int(np.count_nonzero(values > target))
        + int(np.count_nonzero((values == target) & (prefixes < target_prefix)))
    )


def cell_order(scores: np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise ValueError("invalid A218 cell scores")
    prefixes = np.arange(256, dtype=np.uint16)
    return np.lexsort((prefixes, -values)).astype(np.uint16, copy=False)


def rank_metrics(ranks: Sequence[int]) -> dict[str, Any]:
    values = np.asarray(ranks, dtype=np.int64)
    if values.ndim != 1 or len(values) == 0 or np.any((values < 1) | (values > 256)):
        raise ValueError("invalid A218 rank collection")
    return {
        "ranks": [int(value) for value in values],
        "mean_log2_rank": float(np.mean(np.log2(values))),
        "median_rank": float(np.median(values)),
        "mean_rank": float(np.mean(values)),
        "hit_at_1": int(np.count_nonzero(values <= 1)),
        "hit_at_8": int(np.count_nonzero(values <= 8)),
        "hit_at_16": int(np.count_nonzero(values <= 16)),
        "hit_at_32": int(np.count_nonzero(values <= 32)),
        "hit_at_64": int(np.count_nonzero(values <= 64)),
        "mean_reciprocal_rank": float(np.mean(1.0 / values)),
    }
