"""Scale-free solver event-shape reader for complete candidate covers."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from arx_carry_leak.key_atlas import RidgeLogisticModel, fit_ridge_logistic

HORIZONS = (1, 2, 4, 8)
METRICS = ("conflicts", "decisions", "search_propagations")
CHANNELS = (
    "conflicts",
    "decisions",
    "search_propagations",
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
    "learned_clause_accepted_stage",
    "learned_clause_offered_stage",
    "learned_clause_rejected_large_stage",
    "learned_literal_count_stage",
    "learned_clause_length_mean",
    "learned_clause_length_std",
    "learned_clause_length_max",
)
RATIO_PAIRS = (
    ("decisions", "conflicts"),
    ("search_propagations", "decisions"),
    ("learned_clause_accepted_stage", "conflicts"),
    ("learned_literal_count_stage", "learned_clause_accepted_stage"),
)
ORBIT_TRANSFORMS = (
    "raw_z",
    "xor_laplacian",
    "xor_gradient_l2",
    "xor_gradient_maxabs",
)
PREFIX_PATTERN = re.compile(r"_p(\d{2})_")


def _base_feature_names() -> tuple[str, ...]:
    names = []
    for channel in CHANNELS:
        names.extend(f"{channel}__profile_h{horizon}" for horizon in HORIZONS)
        names.extend(
            f"{channel}__first_difference_{left}_{right}"
            for left, right in zip(HORIZONS, HORIZONS[1:], strict=False)
        )
        names.extend(
            f"{channel}__second_difference_{left}_{middle}_{right}"
            for left, middle, right in zip(
                HORIZONS, HORIZONS[1:], HORIZONS[2:], strict=False
            )
        )
    for numerator, denominator in RATIO_PAIRS:
        names.extend(
            f"ratio_{numerator}_versus_{denominator}__h{horizon}"
            for horizon in HORIZONS
        )
    return tuple(names)


BASE_FEATURE_NAMES = _base_feature_names()
FEATURE_NAMES = tuple(
    f"{name}__{transform}"
    for name in BASE_FEATURE_NAMES
    for transform in ORBIT_TRANSFORMS
)


@dataclass(frozen=True)
class TrajectoryShapeTable:
    label: str
    true_prefix: int
    feature_names: tuple[str, ...]
    matrix: np.ndarray

    def labels(self) -> np.ndarray:
        result = np.zeros(256, dtype=np.uint8)
        result[self.true_prefix] = 1
        return result


def _prefix_index(label: str) -> int:
    match = PREFIX_PATTERN.search(label)
    if match is None:
        raise ValueError(f"trajectory-shape label lacks prefix index: {label}")
    return int(match.group(1))


def _stage_rows(measurement: Mapping[str, Any]) -> dict[tuple[int, int], Mapping[str, Any]]:
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in measurement.get("run", {}).get("stages", [])
    }
    expected = {
        (candidate, horizon)
        for candidate in range(256)
        for horizon in HORIZONS
    }
    if set(rows) != expected:
        raise ValueError("trajectory-shape stage cover differs")
    return rows


def _channel_value(row: Mapping[str, Any], channel: str) -> float:
    if row.get("metric_names") != list(METRICS):
        raise ValueError("trajectory-shape metric order differs")
    if channel in METRICS:
        return float(row["metrics_stage_delta"][METRICS.index(channel)])
    if channel == "learned_clause_length_mean":
        lengths = np.asarray(row["learned_clause_lengths_stage"], dtype=np.float64)
        return float(lengths.mean()) if len(lengths) else 0.0
    if channel == "learned_clause_length_std":
        lengths = np.asarray(row["learned_clause_lengths_stage"], dtype=np.float64)
        return float(lengths.std()) if len(lengths) else 0.0
    if channel == "learned_clause_length_max":
        lengths = row["learned_clause_lengths_stage"]
        return float(max(lengths)) if lengths else 0.0
    return float(row[channel])


def _shape_vector(channel_values: Mapping[str, np.ndarray]) -> np.ndarray:
    values = []
    profiles: dict[str, np.ndarray] = {}
    for channel in CHANNELS:
        raw = np.asarray(channel_values[channel], dtype=np.float64)
        scale = float(np.abs(raw).sum())
        profile = raw / scale if scale > 0.0 else np.zeros(4, dtype=np.float64)
        profiles[channel] = profile
        first = np.diff(profile)
        second = np.diff(profile, n=2)
        values.extend(profile)
        values.extend(first)
        values.extend(second)
    for numerator, denominator in RATIO_PAIRS:
        left = np.asarray(channel_values[numerator], dtype=np.float64)
        right = np.asarray(channel_values[denominator], dtype=np.float64)
        scale = np.abs(left) + np.abs(right)
        ratio = np.divide(
            left - right,
            scale,
            out=np.zeros_like(left),
            where=scale > 0.0,
        )
        values.extend(ratio)
    result = np.asarray(values, dtype=np.float64)
    if result.shape != (len(BASE_FEATURE_NAMES),) or not np.isfinite(result).all():
        raise RuntimeError("trajectory-shape feature vector differs")
    return result


def _orbit_matrix(base: np.ndarray) -> np.ndarray:
    if base.shape != (256, len(BASE_FEATURE_NAMES)):
        raise ValueError("trajectory-shape base matrix differs")
    means = base.mean(axis=0)
    scales = base.std(axis=0)
    constant = scales <= np.maximum(1e-12, np.abs(means) * 1e-12)
    scales[constant] = 1.0
    standardized = (base - means) / scales
    standardized[:, constant] = 0.0
    neighbors = np.stack(
        [
            standardized[np.arange(256, dtype=np.uint16) ^ (1 << bit)]
            for bit in range(8)
        ],
        axis=1,
    )
    differences = standardized[:, None, :] - neighbors
    result = np.stack(
        (
            standardized,
            differences.mean(axis=1),
            np.sqrt(np.mean(np.square(differences), axis=1)),
            np.max(np.abs(differences), axis=1),
        ),
        axis=2,
    ).reshape(256, -1)
    if result.shape != (256, len(FEATURE_NAMES)) or not np.isfinite(result).all():
        raise RuntimeError("trajectory-shape orbit construction failed")
    return result


def build_trajectory_shape_table(measurement: Mapping[str, Any]) -> TrajectoryShapeTable:
    design = measurement.get("known_key_design", {})
    label = measurement.get("label")
    true_prefix = design.get("prefix8") if isinstance(design, Mapping) else None
    run = measurement.get("run", {})
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
        or run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
    ):
        raise ValueError("trajectory-shape measurement identity differs")
    rows = _stage_rows(measurement)
    base = np.empty((256, len(BASE_FEATURE_NAMES)), dtype=np.float64)
    for candidate in range(256):
        channel_values = {
            channel: np.asarray(
                [
                    _channel_value(rows[(candidate, horizon)], channel)
                    for horizon in HORIZONS
                ],
                dtype=np.float64,
            )
            for channel in CHANNELS
        }
        base[candidate] = _shape_vector(channel_values)
    return TrajectoryShapeTable(
        label=label,
        true_prefix=true_prefix,
        feature_names=FEATURE_NAMES,
        matrix=_orbit_matrix(base),
    )


def concatenate_training(
    tables: Sequence[TrajectoryShapeTable],
) -> tuple[np.ndarray, np.ndarray]:
    values = list(tables)
    if not values or any(table.feature_names != FEATURE_NAMES for table in values):
        raise ValueError("trajectory-shape training tables differ")
    return (
        np.concatenate([table.matrix for table in values], axis=0),
        np.concatenate([table.labels() for table in values], axis=0),
    )


def _fit(
    tables: Sequence[TrajectoryShapeTable], ridge_lambda: float
) -> RidgeLogisticModel:
    matrix, labels = concatenate_training(tables)
    return fit_ridge_logistic(
        matrix,
        labels,
        feature_names=FEATURE_NAMES,
        ridge_lambda=ridge_lambda,
    )


def _descending_midrank(scores: np.ndarray, candidate: int) -> float:
    target = float(scores[candidate])
    return float(
        1
        + np.count_nonzero(scores > target)
        + 0.5 * (np.count_nonzero(scores == target) - 1)
    )


def _score_tables(
    model: RidgeLogisticModel, tables: Sequence[TrajectoryShapeTable]
) -> list[dict[str, Any]]:
    result = []
    for table in tables:
        scores = model.logits(table.matrix)
        result.append(
            {
                "label": table.label,
                "prefix_index": _prefix_index(table.label),
                "true_prefix": table.true_prefix,
                "midrank": _descending_midrank(scores, table.true_prefix),
                "scores": scores.tolist(),
            }
        )
    return result


def _mean_log2(rows: Sequence[Mapping[str, Any]]) -> float:
    return sum(math.log2(float(row["midrank"])) for row in rows) / len(rows)


def _select_lambda(
    training: Sequence[TrajectoryShapeTable], lambdas: Sequence[float]
) -> tuple[float, list[dict[str, Any]]]:
    groups = sorted({_prefix_index(table.label) for table in training})
    ledger = []
    for ridge_lambda in lambdas:
        rows = []
        for test_group in groups:
            inner_train = [
                table
                for table in training
                if _prefix_index(table.label) != test_group
            ]
            inner_test = [
                table
                for table in training
                if _prefix_index(table.label) == test_group
            ]
            rows.extend(_score_tables(_fit(inner_train, ridge_lambda), inner_test))
        ledger.append(
            {
                "ridge_lambda": float(ridge_lambda),
                "inner_holdout_mean_log2_rank": _mean_log2(rows),
                "inner_holdout_ranks": [
                    {
                        key: row[key]
                        for key in ("label", "prefix_index", "true_prefix", "midrank")
                    }
                    for row in rows
                ],
            }
        )
    selected = min(
        ledger,
        key=lambda row: (
            row["inner_holdout_mean_log2_rank"],
            -row["ridge_lambda"],
        ),
    )
    return float(selected["ridge_lambda"]), ledger


def nested_trajectory_shape_evaluate(
    tables: Sequence[TrajectoryShapeTable],
    *,
    ridge_lambdas: Sequence[float],
) -> dict[str, Any]:
    groups = sorted({_prefix_index(table.label) for table in tables})
    if len(tables) != 20 or groups != [0, 1, 2, 3, 4]:
        raise ValueError("trajectory-shape outer fold geometry differs")
    folds = []
    all_rows = []
    for outer_group in groups:
        training = [
            table for table in tables if _prefix_index(table.label) != outer_group
        ]
        testing = [
            table for table in tables if _prefix_index(table.label) == outer_group
        ]
        selected_lambda, inner_ledger = _select_lambda(training, ridge_lambdas)
        model = _fit(training, selected_lambda)
        scored = _score_tables(model, testing)
        model_dict = model.as_dict()
        folds.append(
            {
                "outer_prefix_index": outer_group,
                "outer_true_prefix": testing[0].true_prefix,
                "selected_ridge_lambda": selected_lambda,
                "inner_selection": inner_ledger,
                "model": model_dict,
                "model_sha256": hashlib.sha256(
                    _canonical_bytes(model_dict)
                ).hexdigest(),
                "test_rows": scored,
                "test_mean_log2_rank": _mean_log2(scored),
            }
        )
        all_rows.extend(scored)
    observed = _mean_log2(all_rows)
    shifted = []
    for xor_offset in range(256):
        ranks = [
            _descending_midrank(
                np.asarray(row["scores"], dtype=np.float64),
                int(row["true_prefix"]) ^ xor_offset,
            )
            for row in all_rows
        ]
        shifted.append(sum(math.log2(rank) for rank in ranks) / len(ranks))
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    return {
        "outer_folds": folds,
        "outer_holdout_rows": all_rows,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "outer_prefix_folds_with_positive_bit_gain": sum(
            uniform - fold["test_mean_log2_rank"] > 0.0 for fold in folds
        ),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": sum(
            value <= observed + 1e-15 for value in shifted
        )
        / 256.0,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def _canonical_bytes(value: Any) -> bytes:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
