"""Continuous matched-contrast reader for ChaCha20 learned-clause flow.

A261 established that discretizing operation-flow counts into token identities
loses transfer.  This module preserves the signed continuous magnitude of every
target-blind typed counter.  Each feature is centered and scaled inside one
complete 256-candidate key cover; supervised weights are then learned only from
training prefix groups and evaluated on an entirely unseen prefix group.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from arx_carry_leak.chacha20_operation_flow import (
    NearestOperationTaps,
    OperationFlowGraph,
    _candidate_flow_counters,
)

VIEWS = ("linear_l1", "log1p_l1", "sqrt_l1")
PREFIX_PATTERN = re.compile(r"_p(\d{2})_")


def _prefix_index(label: str) -> int:
    match = PREFIX_PATTERN.search(label)
    if match is None:
        raise ValueError(f"continuous-flow label lacks prefix index: {label}")
    return int(match.group(1))


def _descending_midrank(scores: np.ndarray, target: int) -> float:
    value = float(scores[target])
    better = int(np.count_nonzero(scores > value))
    tied = int(np.count_nonzero(scores == value))
    return 1.0 + better + 0.5 * (tied - 1)


def _mean_log2(rows: Sequence[Mapping[str, Any]]) -> float:
    if not rows:
        raise ValueError("continuous-flow rank rows are empty")
    return sum(math.log2(float(row["midrank"])) for row in rows) / len(rows)


@dataclass
class ContinuousFlowTable:
    label: str
    true_prefix: int
    feature_counts: Mapping[str, np.ndarray]
    _view_cache: dict[str, dict[str, np.ndarray]] = field(
        default_factory=dict, init=False, repr=False
    )

    def transformed(self, view: str) -> Mapping[str, np.ndarray]:
        if view not in VIEWS:
            raise ValueError(f"unsupported continuous-flow view: {view}")
        cached = self._view_cache.get(view)
        if cached is not None:
            return cached
        result: dict[str, np.ndarray] = {}
        for feature, raw in self.feature_counts.items():
            values = raw.astype(np.float64)
            if view == "log1p_l1":
                values = np.log1p(values)
            elif view == "sqrt_l1":
                values = np.sqrt(values)
            center = float(np.median(values))
            residual = values - center
            scale = float(np.mean(np.abs(residual)))
            if not math.isfinite(scale) or scale <= 0.0:
                continue
            result[feature] = np.clip(residual / scale, -8.0, 8.0).astype(
                np.float32
            )
        self._view_cache[view] = result
        return result


@dataclass(frozen=True)
class ContinuousFlowModel:
    view: str
    maximum_features: int
    ridge: float
    feature_weights: tuple[tuple[str, float], ...]
    training_key_count: int
    training_prefix_groups: tuple[int, ...]
    eligible_feature_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "view": self.view,
            "maximum_features": self.maximum_features,
            "ridge": self.ridge,
            "feature_weights": [
                {"feature": feature, "weight": weight}
                for feature, weight in self.feature_weights
            ],
            "training_key_count": self.training_key_count,
            "training_prefix_groups": list(self.training_prefix_groups),
            "eligible_feature_count": self.eligible_feature_count,
        }


def build_continuous_flow_table(
    measurement: Mapping[str, Any],
    nearest: NearestOperationTaps,
    graph: OperationFlowGraph,
    *,
    minimum_nonzero_candidates: int = 4,
) -> tuple[ContinuousFlowTable, dict[str, Any]]:
    """Retain varying raw typed counters without consulting the true label."""

    design = measurement.get("known_key_design", {})
    label = measurement.get("label")
    true_prefix = design.get("prefix8") if isinstance(design, Mapping) else None
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
        or minimum_nonzero_candidates < 1
    ):
        raise ValueError("continuous-flow measurement identity differs")
    counters, counter_manifest = _candidate_flow_counters(measurement, nearest, graph)
    features = sorted({feature for counter in counters for feature in counter})
    retained: dict[str, np.ndarray] = {}
    ledger = []
    for feature in features:
        values = np.fromiter(
            (counter.get(feature, 0) for counter in counters),
            dtype=np.int32,
            count=256,
        )
        nonzero = int(np.count_nonzero(values))
        if nonzero < minimum_nonzero_candidates or int(values.min()) == int(values.max()):
            continue
        retained[feature] = values
        ledger.append(
            {
                "feature": feature,
                "nonzero_candidates": nonzero,
                "unique_counts": int(np.unique(values).size),
                "counts_int32le_sha256": hashlib.sha256(values.tobytes()).hexdigest(),
            }
        )
    if not retained:
        raise RuntimeError("continuous-flow table retained no varying features")
    table = ContinuousFlowTable(
        label=label,
        true_prefix=true_prefix,
        feature_counts=retained,
    )
    return table, {
        "counter_manifest": counter_manifest,
        "raw_feature_count": len(features),
        "retained_varying_feature_count": len(retained),
        "minimum_nonzero_candidates": minimum_nonzero_candidates,
        "feature_ledger_sha256": hashlib.sha256(
            json_bytes(ledger)
        ).hexdigest(),
        "true_prefix_used_during_counter_or_feature_retention": False,
    }


def _feature_rows(
    training: Sequence[ContinuousFlowTable],
    *,
    view: str,
    minimum_training_keys: int,
    minimum_training_groups: int,
    minimum_group_sign_fraction: float,
) -> list[dict[str, Any]]:
    support = Counter(
        feature
        for table in training
        for feature in table.transformed(view)
    )
    rows = []
    for feature in sorted(support):
        if support[feature] < minimum_training_keys:
            continue
        grouped: defaultdict[int, list[float]] = defaultdict(list)
        key_contrasts = []
        for table in training:
            values = table.transformed(view).get(feature)
            if values is None:
                continue
            target = int(table.true_prefix)
            true_value = float(values[target])
            wrong_mean = (float(values.sum()) - true_value) / 255.0
            contrast = true_value - wrong_mean
            grouped[_prefix_index(table.label)].append(contrast)
            key_contrasts.append(contrast)
        group_means = [
            float(np.mean(grouped[group]))
            for group in sorted(grouped)
            if grouped[group]
        ]
        if len(group_means) < minimum_training_groups:
            continue
        positive = sum(value > 0.0 for value in group_means)
        negative = sum(value < 0.0 for value in group_means)
        sign_fraction = max(positive, negative) / len(group_means)
        if sign_fraction + 1e-15 < minimum_group_sign_fraction:
            continue
        mean_effect = float(np.mean(group_means))
        if mean_effect == 0.0:
            continue
        group_scale = float(np.std(group_means, ddof=0))
        rows.append(
            {
                "feature": feature,
                "support_keys": len(key_contrasts),
                "support_groups": len(group_means),
                "group_sign_fraction": sign_fraction,
                "mean_group_effect": mean_effect,
                "group_effect_scale": group_scale,
            }
        )
    return rows


def fit_continuous_flow_model(
    training: Sequence[ContinuousFlowTable],
    *,
    view: str,
    maximum_features: int,
    ridge: float,
    minimum_training_keys: int = 8,
    minimum_training_groups: int = 2,
    minimum_group_sign_fraction: float = 2.0 / 3.0,
) -> ContinuousFlowModel:
    if (
        view not in VIEWS
        or maximum_features < 1
        or ridge <= 0.0
        or len(training) < minimum_training_keys
    ):
        raise ValueError("continuous-flow model contract differs")
    rows = _feature_rows(
        training,
        view=view,
        minimum_training_keys=minimum_training_keys,
        minimum_training_groups=minimum_training_groups,
        minimum_group_sign_fraction=minimum_group_sign_fraction,
    )
    for row in rows:
        row["weight"] = row["mean_group_effect"] / (
            row["group_effect_scale"] + float(ridge)
        )
    rows.sort(key=lambda row: (-abs(row["weight"]), row["feature"]))
    selected = rows[:maximum_features]
    return ContinuousFlowModel(
        view=view,
        maximum_features=maximum_features,
        ridge=float(ridge),
        feature_weights=tuple(
            (str(row["feature"]), float(row["weight"])) for row in selected
        ),
        training_key_count=len(training),
        training_prefix_groups=tuple(
            sorted({_prefix_index(table.label) for table in training})
        ),
        eligible_feature_count=len(rows),
    )


def score_continuous_flow_table(
    model: ContinuousFlowModel,
    table: ContinuousFlowTable,
) -> dict[str, Any]:
    scores = np.zeros(256, dtype=np.float64)
    available = 0
    weight_mass = 0.0
    transformed = table.transformed(model.view)
    for feature, weight in model.feature_weights:
        values = transformed.get(feature)
        if values is None:
            continue
        scores += weight * values
        weight_mass += abs(weight)
        available += 1
    if weight_mass > 0.0:
        scores /= weight_mass
    return {
        "label": table.label,
        "prefix_index": _prefix_index(table.label),
        "true_prefix": table.true_prefix,
        "midrank": _descending_midrank(scores, table.true_prefix),
        "available_model_features": available,
        "model_feature_count": len(model.feature_weights),
        "scores": scores.tolist(),
    }


def _select_operator(
    training: Sequence[ContinuousFlowTable],
    *,
    views: Sequence[str],
    maximum_features_grid: Sequence[int],
    ridge_grid: Sequence[float],
) -> tuple[str, int, float, list[dict[str, Any]]]:
    groups = sorted({_prefix_index(table.label) for table in training})
    if len(groups) < 2:
        raise ValueError("continuous-flow inner selection requires multiple groups")
    ledger = []
    for view in views:
        for maximum_features in maximum_features_grid:
            for ridge in ridge_grid:
                rows = []
                retained_counts = []
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
                    model = fit_continuous_flow_model(
                        inner_train,
                        view=view,
                        maximum_features=int(maximum_features),
                        ridge=float(ridge),
                    )
                    rows.extend(
                        score_continuous_flow_table(model, table)
                        for table in inner_test
                    )
                    retained_counts.append(len(model.feature_weights))
                ledger.append(
                    {
                        "view": view,
                        "maximum_features": int(maximum_features),
                        "ridge": float(ridge),
                        "inner_holdout_mean_log2_rank": _mean_log2(rows),
                        "inner_retained_feature_counts": retained_counts,
                        "inner_holdout_ranks": [
                            {
                                key: row[key]
                                for key in (
                                    "label",
                                    "prefix_index",
                                    "true_prefix",
                                    "midrank",
                                )
                            }
                            for row in rows
                        ],
                    }
                )
    selected = min(
        ledger,
        key=lambda row: (
            row["inner_holdout_mean_log2_rank"],
            row["maximum_features"],
            -row["ridge"],
            row["view"],
        ),
    )
    return (
        str(selected["view"]),
        int(selected["maximum_features"]),
        float(selected["ridge"]),
        ledger,
    )


def nested_continuous_flow_evaluate(
    tables: Sequence[ContinuousFlowTable],
    *,
    views: Sequence[str] = VIEWS,
    maximum_features_grid: Sequence[int] = (16, 64, 256),
    ridge_grid: Sequence[float] = (0.25, 1.0, 4.0),
) -> dict[str, Any]:
    groups = sorted({_prefix_index(table.label) for table in tables})
    if len(tables) != 20 or groups != [0, 1, 2, 3, 4]:
        raise ValueError("continuous-flow outer fold geometry differs")
    folds = []
    all_rows = []
    for outer_group in groups:
        training = [
            table for table in tables if _prefix_index(table.label) != outer_group
        ]
        testing = [
            table for table in tables if _prefix_index(table.label) == outer_group
        ]
        view, maximum_features, ridge, inner_ledger = _select_operator(
            training,
            views=views,
            maximum_features_grid=maximum_features_grid,
            ridge_grid=ridge_grid,
        )
        model = fit_continuous_flow_model(
            training,
            view=view,
            maximum_features=maximum_features,
            ridge=ridge,
        )
        scored = [score_continuous_flow_table(model, table) for table in testing]
        fold = {
            "outer_prefix_index": outer_group,
            "outer_true_prefix": testing[0].true_prefix,
            "selected_view": view,
            "selected_maximum_features": maximum_features,
            "selected_ridge": ridge,
            "inner_selection": inner_ledger,
            "model": model.as_dict(),
            "model_sha256": hashlib.sha256(json_bytes(model.as_dict())).hexdigest(),
            "test_rows": scored,
            "test_mean_log2_rank": _mean_log2(scored),
        }
        folds.append(fold)
        all_rows.extend(scored)
    observed = _mean_log2(all_rows)
    shifted = []
    for xor_offset in range(256):
        ranks = []
        for row in all_rows:
            scores = np.asarray(row["scores"], dtype=np.float64)
            ranks.append(
                _descending_midrank(scores, int(row["true_prefix"]) ^ xor_offset)
            )
        shifted.append(sum(math.log2(rank) for rank in ranks) / len(ranks))
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    exact_p = sum(value <= observed + 1e-15 for value in shifted) / 256.0
    return {
        "outer_folds": folds,
        "outer_holdout_rows": all_rows,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "outer_prefix_folds_with_positive_bit_gain": sum(
            uniform - fold["test_mean_log2_rank"] > 0 for fold in folds
        ),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": exact_p,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def continuous_table_sha256(table: ContinuousFlowTable) -> str:
    digest = hashlib.sha256()
    digest.update(table.label.encode())
    digest.update(table.true_prefix.to_bytes(1, "little"))
    for feature in sorted(table.feature_counts):
        encoded = feature.encode()
        digest.update(len(encoded).to_bytes(4, "little"))
        digest.update(encoded)
        digest.update(np.asarray(table.feature_counts[feature], dtype="<i4").tobytes())
    return digest.hexdigest()


def json_bytes(value: Any) -> bytes:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
