"""Translation-equivariant feature tables for fresh-state candidate solvers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

HORIZONS = (1, 2, 4, 8)
METRICS = ("conflicts", "decisions", "search_propagations")
ORBIT_TRANSFORMS = ("raw_z", "xor_laplacian", "xor_gradient_l2", "xor_gradient_maxabs")


@dataclass(frozen=True)
class CandidateFeatureTable:
    label: str
    true_prefix: int
    candidates: tuple[int, ...]
    feature_names: tuple[str, ...]
    matrix: np.ndarray

    def labels(self) -> np.ndarray:
        result = np.zeros(256, dtype=np.uint8)
        result[self.true_prefix] = 1
        return result


def _signed_log1p(values: np.ndarray) -> np.ndarray:
    return np.sign(values) * np.log1p(np.abs(values))


def _base_feature_names() -> tuple[str, ...]:
    names: list[str] = []
    for horizon in HORIZONS:
        names.extend(f"h{horizon}_cumulative_{metric}" for metric in METRICS)
        names.extend(f"h{horizon}_stage_{metric}" for metric in METRICS)
        names.extend(
            (
                f"h{horizon}_active_variables_delta",
                f"h{horizon}_irredundant_clauses_delta",
                f"h{horizon}_redundant_clauses_delta",
            )
        )
    return tuple(names)


BASE_FEATURE_NAMES = _base_feature_names()
FEATURE_NAMES = tuple(
    f"{name}__{transform}" for name in BASE_FEATURE_NAMES for transform in ORBIT_TRANSFORMS
)


def _stage_rows(measurement: Mapping[str, Any]) -> dict[tuple[int, int], Mapping[str, Any]]:
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in measurement["run"]["stages"]
    }
    expected = {(candidate, horizon) for candidate in range(256) for horizon in HORIZONS}
    if set(rows) != expected:
        missing = sorted(expected - set(rows))[:8]
        raise ValueError(f"fresh candidate feature table is incomplete: {missing}")
    return rows


def _base_matrix(measurement: Mapping[str, Any]) -> np.ndarray:
    rows = _stage_rows(measurement)
    matrix = np.empty((256, len(BASE_FEATURE_NAMES)), dtype=np.float64)
    for candidate in range(256):
        values: list[float] = []
        for horizon in HORIZONS:
            row = rows[(candidate, horizon)]
            if row.get("metric_names") != list(METRICS):
                raise ValueError("fresh candidate metric order differs")
            values.extend(float(value) for value in row["metrics_cell_cumulative_delta"])
            values.extend(float(value) for value in row["metrics_stage_delta"])
            values.extend(
                (
                    float(row["active_variables_delta"]),
                    float(row["irredundant_clauses_delta"]),
                    float(row["redundant_clauses_delta"]),
                )
            )
        matrix[candidate] = values
    transformed = _signed_log1p(matrix)
    means = transformed.mean(axis=0)
    scales = transformed.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    scales[constant] = 1.0
    standardized = (transformed - means) / scales
    standardized[:, constant] = 0.0
    if not np.isfinite(standardized).all():
        raise RuntimeError("fresh candidate feature standardization is non-finite")
    return standardized


def _orbit_matrix(standardized: np.ndarray) -> np.ndarray:
    if standardized.shape != (256, len(BASE_FEATURE_NAMES)):
        raise ValueError("fresh candidate base feature shape differs")
    neighbors = np.stack(
        [standardized[np.arange(256, dtype=np.uint16) ^ (1 << bit)] for bit in range(8)],
        axis=1,
    )
    differences = standardized[:, None, :] - neighbors
    laplacian = differences.mean(axis=1)
    gradient_l2 = np.sqrt(np.mean(np.square(differences), axis=1))
    gradient_maxabs = np.max(np.abs(differences), axis=1)
    # Interleave transforms per base channel to match FEATURE_NAMES.
    result = np.stack(
        (standardized, laplacian, gradient_l2, gradient_maxabs), axis=2
    ).reshape(256, -1)
    if result.shape != (256, len(FEATURE_NAMES)) or not np.isfinite(result).all():
        raise RuntimeError("fresh candidate orbit feature construction failed")
    return result


def build_feature_table(measurement: Mapping[str, Any]) -> CandidateFeatureTable:
    design = measurement.get("known_key_design", {})
    true_prefix = design.get("prefix8")
    label = measurement.get("label")
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
    ):
        raise ValueError("fresh candidate measurement label is invalid")
    return CandidateFeatureTable(
        label=label,
        true_prefix=true_prefix,
        candidates=tuple(range(256)),
        feature_names=FEATURE_NAMES,
        matrix=_orbit_matrix(_base_matrix(measurement)),
    )


def concatenate_training(
    tables: Sequence[CandidateFeatureTable],
) -> tuple[np.ndarray, np.ndarray]:
    values = list(tables)
    if not values or any(table.feature_names != FEATURE_NAMES for table in values):
        raise ValueError("fresh candidate training tables differ")
    return (
        np.concatenate([table.matrix for table in values], axis=0),
        np.concatenate([table.labels() for table in values], axis=0),
    )


def descending_midrank(scores: np.ndarray, candidate: int) -> float:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all() or not 0 <= candidate < 256:
        raise ValueError("fresh candidate score vector is invalid")
    target = values[candidate]
    return float(
        1
        + np.count_nonzero(values > target)
        + 0.5 * (np.count_nonzero(values == target) - 1)
    )
