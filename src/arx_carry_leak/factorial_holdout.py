"""Frozen-reader scoring and exact holdout inference for A220.

This module contains no file or solver access.  It consumes already verified
holdout measurements, applies exactly the serialized A220 Reader, and evaluates
the four factorial panels plus the complete 5! primary cluster-label null.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from arx_carry_leak.factorial_trajectory import (
    ATOMIC_BUNDLE_ORDER,
    DUAL_BUNDLE_ORDER,
    CandidateIdentity,
    dual_schedule_score_matrix,
    evaluate_score_matrix,
    exact_lower_tail_p,
    extract_pair_feature_views,
    readout_from_dict,
    score_readout_views,
)

HOLDOUT_PANEL_ORDER = (
    "fit_by_confirm",
    "select_by_confirm",
    "confirm_by_fit",
    "confirm_by_confirm",
)
HOLDOUT_PANEL_COUNTS = {
    "fit_by_confirm": 32,
    "select_by_confirm": 20,
    "confirm_by_fit": 20,
    "confirm_by_confirm": 20,
}
PRIMARY_PANEL = "confirm_by_confirm"
PRIMARY_CLUSTER_COUNT = 5
PRIMARY_SUFFIX_REPLICATES = 4
PRIMARY_EXACT_PERMUTATIONS = math.factorial(PRIMARY_CLUSTER_COUNT)
UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 = 6.578110496969589
PRIMARY_P_THRESHOLD = 0.05

GEOMETRY_OPERATOR_PAIRS = {
    "numeric": ("numeric_forward", "numeric_reverse_same_anchor"),
    "reflected_gray8": (
        "reflected_gray8_forward",
        "reflected_gray8_reverse_same_anchor",
    ),
    "formula_gray8": ("formula_gray8_forward", "formula_gray8_reverse_same_anchor"),
}
SCHEDULE_ORDER = ("staged_retained_resolve", "one_shot")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _float64_sha256(values: np.ndarray) -> str:
    array = np.ascontiguousarray(np.asarray(values, dtype="<f8"))
    return hashlib.sha256(array.tobytes()).hexdigest()


def holdout_panel_name(row: Mapping[str, Any]) -> str:
    prefix_split = row.get("prefix_split")
    suffix_split = row.get("suffix_split")
    panel = f"{prefix_split}_by_{suffix_split}"
    if panel not in HOLDOUT_PANEL_ORDER:
        raise ValueError(f"A220 row is not in a frozen holdout panel: {panel}")
    return panel


def selected_bundle_run_ids(bundle_id: str) -> tuple[str, ...]:
    """Return the exact two or four fresh-process run IDs for a frozen bundle."""
    if bundle_id in ATOMIC_BUNDLE_ORDER:
        geometry, schedule = bundle_id.split("__", 1)
        schedules = (schedule,)
    elif bundle_id in DUAL_BUNDLE_ORDER:
        geometry = bundle_id.removesuffix("__dual_schedule")
        schedules = SCHEDULE_ORDER
    else:
        raise ValueError("A220 selected bundle is outside the frozen grid")
    forward, reverse = GEOMETRY_OPERATOR_PAIRS[geometry]
    return tuple(
        f"{operator}__{schedule}"
        for schedule in schedules
        for operator in (forward, reverse)
    )


def _selected_reader_identity(selected_reader: Mapping[str, Any]) -> CandidateIdentity:
    expected_fields = {
        "selected_identity",
        "selected_metrics",
        "selected_score_sha256",
        "selected_constituent_readouts",
        "candidate_grid_sha256",
    }
    if not isinstance(selected_reader, Mapping) or set(selected_reader) != expected_fields:
        raise ValueError("A220 selected Reader schema differs")
    raw = selected_reader["selected_identity"]
    if not isinstance(raw, Mapping):
        raise ValueError("A220 selected Reader identity is not an object")
    try:
        identity = CandidateIdentity(
            bundle_id=str(raw["bundle_id"]),
            feature_family=str(raw["feature_family"]),
            readout_kind=str(raw["readout_kind"]),
            ridge_lambda=float(raw["ridge_lambda"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("A220 selected Reader identity differs") from error
    if raw != identity.as_dict():
        raise ValueError("A220 selected Reader run count or identity differs")
    if (
        not isinstance(selected_reader["selected_score_sha256"], str)
        or len(selected_reader["selected_score_sha256"]) != 64
        or not isinstance(selected_reader["candidate_grid_sha256"], str)
        or len(selected_reader["candidate_grid_sha256"]) != 64
    ):
        raise ValueError("A220 selected Reader digest differs")
    return identity


def _constituent_bundle_ids(identity: CandidateIdentity) -> tuple[str, ...]:
    if identity.bundle_id in ATOMIC_BUNDLE_ORDER:
        return (identity.bundle_id,)
    geometry = identity.bundle_id.removesuffix("__dual_schedule")
    return tuple(f"{geometry}__{schedule}" for schedule in SCHEDULE_ORDER)


def _pair_view(
    runs: Mapping[str, Any], *, bundle_id: str, feature_family: str
) -> Any:
    geometry, schedule = bundle_id.split("__", 1)
    forward, reverse = GEOMETRY_OPERATOR_PAIRS[geometry]
    forward_id = f"{forward}__{schedule}"
    reverse_id = f"{reverse}__{schedule}"
    # A dual-schedule payload legitimately contains the other schedule's pair
    # as well.  The caller already gates the complete 2/4-run cover; here we
    # require the exact constituent pair needed for this feature view.
    if not {forward_id, reverse_id}.issubset(runs):
        raise ValueError("A220 holdout scientific-run set differs from the selected bundle")
    try:
        return extract_pair_feature_views(runs[forward_id], runs[reverse_id])[feature_family]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("A220 holdout trajectory feature extraction failed") from error


def score_verified_holdout(
    selected_reader: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    payloads: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Apply one frozen Reader to exactly 92 verified holdout payloads."""
    identity = _selected_reader_identity(selected_reader)
    if len(rows) != 92 or len(payloads) != 92:
        raise ValueError("A220 holdout scoring requires exactly 92 keys")
    panels = [holdout_panel_name(row) for row in rows]
    if Counter(panels) != HOLDOUT_PANEL_COUNTS:
        raise ValueError("A220 holdout panel counts differ")
    labels = [str(row.get("label")) for row in rows]
    if len(set(labels)) != 92:
        raise ValueError("A220 holdout labels are not unique")
    targets = []
    run_maps = []
    expected_run_ids = set(selected_bundle_run_ids(identity.bundle_id))
    for row, payload in zip(rows, payloads, strict=True):
        if (
            not isinstance(payload, Mapping)
            or payload.get("key_factorial_identity") != dict(row)
            or not isinstance(payload.get("scientific_runs"), Mapping)
            or set(payload["scientific_runs"]) != expected_run_ids
        ):
            raise ValueError("A220 holdout payload order or selected-run cover differs")
        prefix = row.get("prefix8")
        if not isinstance(prefix, int) or isinstance(prefix, bool) or not 0 <= prefix < 256:
            raise ValueError("A220 holdout target prefix differs")
        targets.append(prefix)
        run_maps.append(payload["scientific_runs"])

    raw_readouts = selected_reader["selected_constituent_readouts"]
    constituents = _constituent_bundle_ids(identity)
    if not isinstance(raw_readouts, Mapping) or set(raw_readouts) != set(constituents):
        raise ValueError("A220 selected constituent Reader set differs")
    constituent_scores = {}
    for bundle_id in constituents:
        readout = readout_from_dict(raw_readouts[bundle_id])
        if (
            readout.feature_family != identity.feature_family
            or readout.kind != identity.readout_kind
            or readout.ridge_lambda != identity.ridge_lambda
        ):
            raise ValueError("A220 constituent Reader identity differs")
        views = [
            _pair_view(runs, bundle_id=bundle_id, feature_family=identity.feature_family)
            for runs in run_maps
        ]
        constituent_scores[bundle_id] = score_readout_views(readout, views)

    if identity.bundle_id in ATOMIC_BUNDLE_ORDER:
        scores = constituent_scores[identity.bundle_id]
    else:
        scores = dual_schedule_score_matrix(
            constituent_scores[constituents[0]], constituent_scores[constituents[1]]
        )
    if scores.shape != (92, 256) or not np.isfinite(scores).all():
        raise RuntimeError("A220 holdout score matrix is malformed")
    overall = evaluate_score_matrix(scores, targets)
    per_key = []
    for index, (row, score, rank) in enumerate(
        zip(rows, scores, overall["ranks"], strict=True)
    ):
        target = targets[index]
        per_key.append(
            {
                "key_label": row["label"],
                "panel": panels[index],
                "prefix_split": row["prefix_split"],
                "prefix_index": row["prefix_index"],
                "suffix_split": row["suffix_split"],
                "suffix_index": row["suffix_index"],
                "true_prefix8": target,
                "true_prefix_rank": rank,
                "true_prefix_score": float(score[target]),
                "score_vector_float64_le_sha256": _float64_sha256(score),
            }
        )
    return {
        "selected_identity": identity.as_dict(),
        "selected_run_ids": list(selected_bundle_run_ids(identity.bundle_id)),
        "constituent_bundle_ids": list(constituents),
        "row_label_order_sha256": _canonical_sha256(labels),
        "score_matrix_float64_le_sha256": _float64_sha256(scores),
        "target_prefix_order_sha256": _canonical_sha256(targets),
        "overall_metrics": overall,
        "per_key": per_key,
        "_score_matrix": scores,
    }


def _primary_exact_null(
    rows: Sequence[Mapping[str, Any]], scores: np.ndarray
) -> dict[str, Any]:
    primary_indices = [
        index for index, row in enumerate(rows) if holdout_panel_name(row) == PRIMARY_PANEL
    ]
    if len(primary_indices) != PRIMARY_CLUSTER_COUNT * PRIMARY_SUFFIX_REPLICATES:
        raise ValueError("A220 primary holdout panel size differs")
    primary_rows = [rows[index] for index in primary_indices]
    primary_scores = scores[primary_indices]
    cluster_indices = sorted({int(row["prefix_index"]) for row in primary_rows})
    if cluster_indices != list(range(PRIMARY_CLUSTER_COUNT)):
        raise ValueError("A220 primary prefix cluster indices differ")
    cluster_prefixes = []
    for cluster in cluster_indices:
        members = [row for row in primary_rows if int(row["prefix_index"]) == cluster]
        prefixes = {int(row["prefix8"]) for row in members}
        suffixes = {int(row["suffix_index"]) for row in members}
        if len(members) != PRIMARY_SUFFIX_REPLICATES or len(prefixes) != 1 or suffixes != set(
            range(PRIMARY_SUFFIX_REPLICATES)
        ):
            raise ValueError("A220 primary cluster replication differs")
        cluster_prefixes.append(next(iter(prefixes)))

    observed_targets = [int(row["prefix8"]) for row in primary_rows]
    observed_metrics = evaluate_score_matrix(primary_scores, observed_targets)
    records = []
    for permutation_index, permutation in enumerate(
        itertools.permutations(range(PRIMARY_CLUSTER_COUNT))
    ):
        targets = [
            cluster_prefixes[permutation[int(row["prefix_index"])]] for row in primary_rows
        ]
        metrics = evaluate_score_matrix(primary_scores, targets)
        records.append(
            {
                "permutation_index": permutation_index,
                "cluster_permutation": list(permutation),
                "target_prefix_order_sha256": _canonical_sha256(targets),
                "mean_log2_rank": metrics["mean_log2_rank"],
            }
        )
    statistics = [record["mean_log2_rank"] for record in records]
    p_value = exact_lower_tail_p(
        observed_metrics["mean_log2_rank"],
        statistics,
        expected_count=PRIMARY_EXACT_PERMUTATIONS,
    )
    identity_records = [
        record
        for record in records
        if record["cluster_permutation"] == list(range(PRIMARY_CLUSTER_COUNT))
    ]
    if (
        len(records) != PRIMARY_EXACT_PERMUTATIONS
        or len(identity_records) != 1
        or identity_records[0]["mean_log2_rank"] != observed_metrics["mean_log2_rank"]
    ):
        raise RuntimeError("A220 exact primary null identity differs")
    retained = (
        p_value <= PRIMARY_P_THRESHOLD
        and observed_metrics["mean_log2_rank"] < UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
    )
    bit_gain = UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 - observed_metrics["mean_log2_rank"]
    return {
        "panel": PRIMARY_PANEL,
        "prefix_clusters": PRIMARY_CLUSTER_COUNT,
        "suffix_replicates_per_cluster": PRIMARY_SUFFIX_REPLICATES,
        "observed_metrics": observed_metrics,
        "uniform_random_rank_expected_mean_log2": UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2,
        "observed_bit_gain_over_uniform_mean_log2": bit_gain,
        "geometric_rank_concentration_factor": float(2.0**bit_gain),
        "permutation_records": records,
        "permutation_statistics_sha256": _canonical_sha256(statistics),
        "exact_lower_tail_p": p_value,
        "retention_threshold": PRIMARY_P_THRESHOLD,
        "retained": retained,
    }


def evaluate_verified_holdout(
    selected_reader: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    payloads: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Score all holdout keys and perform the frozen panel/null analysis."""
    scored = score_verified_holdout(selected_reader, rows, payloads)
    scores = scored.pop("_score_matrix")
    panel_metrics = {}
    for panel in HOLDOUT_PANEL_ORDER:
        indices = [
            index for index, row in enumerate(rows) if holdout_panel_name(row) == panel
        ]
        if len(indices) != HOLDOUT_PANEL_COUNTS[panel]:
            raise ValueError(f"A220 {panel} panel size differs")
        panel_metrics[panel] = evaluate_score_matrix(
            scores[indices], [int(rows[index]["prefix8"]) for index in indices]
        )
    primary = _primary_exact_null(rows, scores)
    evidence_stage = (
        "FULLROUND_R20_FACTORIAL_TRAJECTORY_HOLDOUT_TRANSFER"
        if primary["retained"]
        else "FULLROUND_R20_FACTORIAL_TRAJECTORY_PROBE_SPECIFIC_BOUNDARY"
    )
    result = {
        **scored,
        "panel_metrics": panel_metrics,
        "primary_exact_cluster_null": primary,
        "evidence_stage": evidence_stage,
    }
    result["evaluation_sha256"] = _canonical_sha256(result)
    return result
