"""Typed feature extraction for exact CaDiCaL proof-antecedent statistics."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

HORIZONS = (1, 2, 4, 8)
PARTITIONS = ("all", "redundant", "irredundant")
COUNTERS = (
    "events",
    "witness_events",
    "direct_assumption_touch_events",
    "ancestry_assumption_touch_events",
    "direct_assumption_same_literals",
    "direct_assumption_opposite_literals",
    "parent_assumption_ancestry_edges",
    "recurrent_clause_events",
)
MASKS = (
    "direct_assumption_position_union",
    "ancestry_assumption_position_union",
)
MOMENTS = (
    "clause_size",
    "antecedent_count",
    "proof_depth",
    "original_parent_count",
    "derived_parent_count",
    "missing_parent_count",
    "parent_clause_size",
    "parent_depth",
)
PARENT_REUSE = (
    "references",
    "unique_parents",
    "reused_references",
    "maximum_parent_use",
    "entropy_bits",
    "normalized_entropy",
)
LIFECYCLE = (
    "proof_derived_count_stage",
    "proof_antecedent_count_stage",
    "proof_deletions_stage",
    "proof_demotions_stage",
    "proof_weakenings_stage",
    "proof_strengthenings_stage",
    "proof_finalizations_stage",
    "learned_clause_offered_stage",
    "learned_clause_accepted_stage",
    "learned_clause_rejected_large_stage",
    "learned_literal_count_stage",
)


def _finite(value: Any, label: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite proof feature: {label}")
    return result


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _moment_features(moment: Mapping[str, Any], prefix: str) -> dict[str, float]:
    count = _finite(moment["count"], f"{prefix}.count")
    total = _finite(moment["sum"], f"{prefix}.sum")
    squares = _finite(moment["sum_squares"], f"{prefix}.sum_squares")
    maximum = _finite(moment["maximum"], f"{prefix}.maximum")
    mean = _ratio(total, count)
    variance = max(0.0, _ratio(squares, count) - mean * mean)
    return {
        f"{prefix}::count": count,
        f"{prefix}::sum": total,
        f"{prefix}::mean": mean,
        f"{prefix}::std": math.sqrt(variance),
        f"{prefix}::maximum": maximum,
    }


def stage_feature_map(row: Mapping[str, Any]) -> dict[str, float]:
    statistics = row["proof_antecedent_statistics"]
    result: dict[str, float] = {}
    for partition in PARTITIONS:
        aggregate = statistics[partition]
        for key in COUNTERS:
            result[f"{partition}::{key}"] = _finite(
                aggregate[key], f"{partition}.{key}"
            )
        for key in MASKS:
            mask = int(aggregate[key])
            if not 0 <= mask <= 255:
                raise ValueError("proof assumption mask exceeds eight positions")
            result[f"{partition}::{key}::popcount"] = float(mask.bit_count())
            for position in range(8):
                result[f"{partition}::{key}::position{position}"] = float(
                    (mask >> position) & 1
                )
        for key in MOMENTS:
            result.update(_moment_features(aggregate[key], f"{partition}::{key}"))
    for family in ("all", "redundant"):
        reuse = statistics[f"parent_reuse_{family}"]
        for key in PARENT_REUSE:
            result[f"parent_reuse_{family}::{key}"] = _finite(
                reuse[key], f"parent_reuse_{family}.{key}"
            )
    for key in LIFECYCLE:
        result[f"lifecycle::{key}"] = _finite(row[key], key)

    all_events = result["all::events"]
    redundant_events = result["redundant::events"]
    redundant_antecedents = result["redundant::antecedent_count::sum"]
    direct_literals = (
        result["redundant::direct_assumption_same_literals"]
        + result["redundant::direct_assumption_opposite_literals"]
    )
    result.update(
        {
            "ratio::redundant_event_fraction": _ratio(redundant_events, all_events),
            "ratio::redundant_direct_touch_fraction": _ratio(
                result["redundant::direct_assumption_touch_events"], redundant_events
            ),
            "ratio::redundant_ancestry_touch_fraction": _ratio(
                result["redundant::ancestry_assumption_touch_events"],
                redundant_events,
            ),
            "ratio::redundant_opposition_fraction": _ratio(
                result["redundant::direct_assumption_opposite_literals"],
                direct_literals,
            ),
            "ratio::redundant_original_parent_fraction": _ratio(
                result["redundant::original_parent_count::sum"],
                redundant_antecedents,
            ),
            "ratio::redundant_derived_parent_fraction": _ratio(
                result["redundant::derived_parent_count::sum"],
                redundant_antecedents,
            ),
            "ratio::redundant_parent_ancestry_fraction": _ratio(
                result["redundant::parent_assumption_ancestry_edges"],
                redundant_antecedents,
            ),
            "ratio::redundant_recurrence_fraction": _ratio(
                result["redundant::recurrent_clause_events"], redundant_events
            ),
            "ratio::parent_reuse_all_fraction": _ratio(
                result["parent_reuse_all::reused_references"],
                result["parent_reuse_all::references"],
            ),
            "ratio::parent_reuse_redundant_fraction": _ratio(
                result["parent_reuse_redundant::reused_references"],
                result["parent_reuse_redundant::references"],
            ),
        }
    )
    return result


def _primary_temporal_feature(name: str) -> bool:
    if name in {
        "all::events",
        "redundant::events",
        "irredundant::events",
        "redundant::direct_assumption_touch_events",
        "redundant::ancestry_assumption_touch_events",
        "redundant::direct_assumption_same_literals",
        "redundant::direct_assumption_opposite_literals",
        "redundant::parent_assumption_ancestry_edges",
        "redundant::recurrent_clause_events",
    }:
        return True
    if name.startswith("redundant::") and name.endswith(("::mean", "::maximum")):
        return any(
            f"::{moment}::" in name
            for moment in ("clause_size", "antecedent_count", "proof_depth")
        )
    if name.startswith(("parent_reuse_all::", "parent_reuse_redundant::")):
        return name.endswith(
            ("normalized_entropy", "maximum_parent_use", "reused_references")
        )
    if name.startswith("ratio::"):
        return True
    return False


def extract_proof_feature_matrix(
    measurement: Mapping[str, Any],
) -> tuple[np.ndarray, tuple[str, ...]]:
    run = measurement.get("run", measurement)
    if (
        run.get("proof_antecedent_identity_complete") is not True
        or run.get("proof_missing_antecedent_total") != 0
        or len(run.get("cells", [])) != 256
    ):
        raise ValueError("complete proof-antecedent measurement required")
    rows: dict[tuple[int, int], Mapping[str, Any]] = {}
    for row in run.get("stages", []):
        key = (int(row["cell_index"]), int(row["horizon"]))
        if key in rows:
            raise ValueError("duplicate proof cell/horizon")
        rows[key] = row
    if set(rows) != {(cell, horizon) for cell in range(256) for horizon in HORIZONS}:
        raise ValueError("proof cell/horizon cover differs")

    feature_rows: list[dict[str, float]] = []
    names: tuple[str, ...] | None = None
    for cell in range(256):
        by_horizon = {
            horizon: stage_feature_map(rows[(cell, horizon)]) for horizon in HORIZONS
        }
        combined: dict[str, float] = {}
        for horizon in HORIZONS:
            for name, value in by_horizon[horizon].items():
                combined[f"h{horizon}::{name}"] = value
        primary = sorted(name for name in by_horizon[1] if _primary_temporal_feature(name))
        for name in primary:
            values = [by_horizon[horizon][name] for horizon in HORIZONS]
            combined[f"temporal::sum::{name}"] = float(sum(values))
            combined[f"temporal::h8_minus_h1::{name}"] = float(values[-1] - values[0])
            combined[f"temporal::maximum::{name}"] = float(max(values))
        current_names = tuple(sorted(combined))
        if names is None:
            names = current_names
        elif current_names != names:
            raise RuntimeError("proof feature ledger differs across cells")
        feature_rows.append(combined)
    if names is None:
        raise RuntimeError("empty proof feature ledger")
    matrix = np.asarray(
        [[row[name] for name in names] for row in feature_rows], dtype=np.float64
    )
    if matrix.shape != (256, len(names)) or not np.isfinite(matrix).all():
        raise RuntimeError("proof feature matrix differs")
    return matrix, names


def target_normalize(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.ndim != 2 or values.shape[0] != 256 or not np.isfinite(values).all():
        raise ValueError("proof target-normalization matrix differs")
    center = np.median(values, axis=0)
    scale = np.median(np.abs(values - center), axis=0)
    fallback = values.std(axis=0)
    scale = np.where(scale > 0.0, scale, np.where(fallback > 0.0, fallback, 1.0))
    return (values - center) / scale


def exact_directional_rank_fields(
    normalized: np.ndarray,
    baseline_ranks: Sequence[int],
) -> tuple[np.ndarray, tuple[str, ...]]:
    values = np.asarray(normalized, dtype=np.float64)
    baseline = np.asarray(baseline_ranks, dtype=np.int64)
    if (
        values.ndim != 2
        or values.shape[0] != 256
        or baseline.shape != (256,)
        or set(baseline.tolist()) != set(range(1, 257))
        or not np.isfinite(values).all()
    ):
        raise ValueError("proof directional-rank input differs")
    fields: list[np.ndarray] = []
    names: list[str] = []
    cell = np.arange(256, dtype=np.int64)
    exact = np.arange(1, 257, dtype=np.int16)
    for feature in range(values.shape[1]):
        column = values[:, feature]
        for direction, primary in (
            ("ascending", column),
            ("descending", -column),
            ("absolute", -np.abs(column)),
        ):
            order = np.lexsort((cell, baseline, primary))
            ranks = np.empty(256, dtype=np.int16)
            ranks[order] = exact
            fields.append(ranks)
            names.append(f"feature{feature:04d}::{direction}")
    return np.stack(fields), tuple(names)


def directional_feature_names(base_names: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        f"{name}::{direction}"
        for name in base_names
        for direction in ("ascending", "descending", "absolute")
    )
