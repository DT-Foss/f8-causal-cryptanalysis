"""Exact additive decompositions of frozen trajectory-shape readers."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from arx_carry_leak.score_hypercube import descending_midrank, mean_log2_rank


def feature_source_and_transform(feature_name: str) -> tuple[str, str]:
    """Return the semantic source and final orbit transform of a feature."""

    if not isinstance(feature_name, str) or "__" not in feature_name:
        raise ValueError("trajectory feature name differs")
    base, transform = feature_name.rsplit("__", 1)
    source = base.split("__", 1)[0]
    if not source or not transform:
        raise ValueError("trajectory feature source or transform differs")
    return source, transform


def signed_semantic_groups(
    feature_names: Sequence[str], coefficients: Sequence[float]
) -> dict[str, tuple[int, ...]]:
    """Partition nonzero coefficients by semantic source and coefficient sign."""

    names = tuple(feature_names)
    values = np.asarray(coefficients, dtype=np.float64)
    if values.shape != (len(names),) or not np.isfinite(values).all():
        raise ValueError("trajectory coefficient geometry differs")
    groups: dict[str, list[int]] = {}
    for index, (name, coefficient) in enumerate(zip(names, values, strict=True)):
        source, _ = feature_source_and_transform(name)
        if coefficient == 0.0:
            continue
        sign = "positive" if coefficient > 0.0 else "negative"
        groups.setdefault(f"{source}::coefficient_{sign}", []).append(index)
    result = {name: tuple(indices) for name, indices in sorted(groups.items())}
    covered = [index for indices in result.values() for index in indices]
    expected = [index for index, value in enumerate(values) if value != 0.0]
    if sorted(covered) != expected or len(covered) != len(set(covered)):
        raise RuntimeError("signed semantic groups do not partition coefficients")
    return result


def standardized_contributions(
    matrix: np.ndarray,
    *,
    means: Sequence[float],
    scales: Sequence[float],
    coefficients: Sequence[float],
) -> np.ndarray:
    """Return one additive logit contribution per row and frozen feature."""

    values = np.asarray(matrix, dtype=np.float64)
    center = np.asarray(means, dtype=np.float64)
    scale = np.asarray(scales, dtype=np.float64)
    coefficient = np.asarray(coefficients, dtype=np.float64)
    width = len(coefficient)
    if (
        values.ndim != 2
        or values.shape[1] != width
        or center.shape != (width,)
        or scale.shape != (width,)
        or not np.isfinite(values).all()
        or not np.isfinite(center).all()
        or not np.isfinite(scale).all()
        or not np.isfinite(coefficient).all()
        or np.any(scale <= 0.0)
    ):
        raise ValueError("trajectory contribution input differs")
    result = ((values - center) / scale) * coefficient
    if not np.isfinite(result).all():
        raise RuntimeError("trajectory contribution matrix is non-finite")
    return result


def grouped_scores(
    contributions: np.ndarray, groups: Mapping[str, Sequence[int]]
) -> dict[str, np.ndarray]:
    """Sum frozen additive contributions for every predefined group."""

    values = np.asarray(contributions, dtype=np.float64)
    if values.ndim != 2 or not np.isfinite(values).all() or not groups:
        raise ValueError("trajectory contribution groups differ")
    result: dict[str, np.ndarray] = {}
    for name, raw_indices in groups.items():
        indices = np.asarray(tuple(raw_indices), dtype=np.int64)
        if (
            not name
            or indices.ndim != 1
            or len(indices) == 0
            or np.any(indices < 0)
            or np.any(indices >= values.shape[1])
            or len(np.unique(indices)) != len(indices)
        ):
            raise ValueError(f"invalid trajectory contribution group: {name}")
        result[name] = values[:, indices].sum(axis=1)
    return result


def score_view_statistics(
    score_fields: Sequence[np.ndarray],
    *,
    true_prefixes: Sequence[int],
    prefix_indices: Sequence[int],
) -> dict[str, Any]:
    """Evaluate one frozen score view with all shared-XOR label controls."""

    fields = [np.asarray(field, dtype=np.float64) for field in score_fields]
    truths = [int(value) for value in true_prefixes]
    groups = [int(value) for value in prefix_indices]
    if (
        len(fields) != 20
        or len(truths) != 20
        or len(groups) != 20
        or any(field.shape != (256,) or not np.isfinite(field).all() for field in fields)
        or any(value not in range(256) for value in truths)
        or sorted(set(groups)) != list(range(5))
        or any(groups.count(value) != 4 for value in range(5))
    ):
        raise ValueError("score-view evaluation geometry differs")
    ranks = [
        descending_midrank(field, truth)
        for field, truth in zip(fields, truths, strict=True)
    ]
    observed = mean_log2_rank(ranks)
    shifted = [
        mean_log2_rank(
            [
                descending_midrank(field, truth ^ offset)
                for field, truth in zip(fields, truths, strict=True)
            ]
        )
        for offset in range(256)
    ]
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    prefix_rows = []
    for group in range(5):
        group_ranks = [
            rank for rank, value in zip(ranks, groups, strict=True) if value == group
        ]
        group_mean = mean_log2_rank(group_ranks)
        prefix_rows.append(
            {
                "prefix_index": group,
                "ranks": group_ranks,
                "mean_log2_rank": group_mean,
                "bit_gain": uniform - group_mean,
            }
        )
    return {
        "ranks": ranks,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "positive_prefix_groups": sum(row["bit_gain"] > 0.0 for row in prefix_rows),
        "prefix_groups": prefix_rows,
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": sum(value <= observed + 1e-15 for value in shifted)
        / 256.0,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def familywise_best_gain(
    evaluations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Exact max-statistic control over a frozen family of score views."""

    if not evaluations:
        raise ValueError("empty score-view family")
    names = sorted(evaluations)
    gains: dict[str, list[float]] = {}
    for name in names:
        row = evaluations[name]
        shifted = row.get("shared_xor_offset_mean_log2_ranks")
        uniform = row.get("uniform_mean_log2_rank_reference")
        if (
            not isinstance(shifted, Sequence)
            or len(shifted) != 256
            or not isinstance(uniform, (int, float))
        ):
            raise ValueError(f"score-view control geometry differs: {name}")
        values = [float(uniform) - float(value) for value in shifted]
        if not np.isfinite(values).all():
            raise ValueError(f"score-view controls are non-finite: {name}")
        gains[name] = values
    observed_name = max(names, key=lambda name: (gains[name][0], name))
    observed = gains[observed_name][0]
    max_by_offset = [max(gains[name][offset] for name in names) for offset in range(256)]
    return {
        "view_count": len(names),
        "best_observed_view": observed_name,
        "best_observed_bit_gain": observed,
        "max_bit_gain_by_shared_xor_offset": max_by_offset,
        "exact_familywise_shared_xor_p": sum(
            value >= observed - 1e-15 for value in max_by_offset
        )
        / 256.0,
        "best_null_offset": max(range(256), key=max_by_offset.__getitem__),
        "observed_offset": 0,
    }
