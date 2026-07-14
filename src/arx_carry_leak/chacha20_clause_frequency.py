"""Continuous exact-frequency coordinates for shallow R20 learned clauses.

The A251 reader reduced every learned variable, pair, and clause identity to a
binary present/absent token.  This module retains the multiplicity with which
the same exact identity recurs across learned clauses and horizons.  The eight
candidate-assumption variables are projected out before any coordinate is
formed, exactly as in A251.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from arx_carry_leak.chacha20_continuous_flow import ContinuousFlowTable

HORIZONS = (1, 2, 4, 8)
PAIR_MAXIMUM_CLAUSE_SIZE = 16
FEATURE_FAMILIES = (
    "stage_signed_variable",
    "stage_unsigned_variable",
    "stage_clause",
    "stage_pair",
    "stage_clause_length",
    "all_signed_variable",
    "all_unsigned_variable",
    "all_clause",
    "all_pair",
    "all_clause_length",
)


def _clause_digest(clause: Sequence[int]) -> str:
    values = np.asarray(tuple(int(value) for value in clause), dtype="<i4")
    raw = len(values).to_bytes(2, "little") + values.tobytes()
    return hashlib.sha256(raw).hexdigest()


def _increment_clause_features(
    counter: Counter[str], horizon: int, clause: Sequence[int]
) -> None:
    values = tuple(int(value) for value in clause)
    digest = _clause_digest(values)
    counter[f"stage_clause|h{horizon}|{digest}"] += 1
    counter[f"all_clause|{digest}"] += 1
    counter[f"stage_clause_length|h{horizon}|{len(values)}"] += 1
    counter[f"all_clause_length|{len(values)}"] += 1
    for literal in values:
        counter[f"stage_signed_variable|h{horizon}|{literal}"] += 1
        counter[f"stage_unsigned_variable|h{horizon}|{abs(literal)}"] += 1
        counter[f"all_signed_variable|{literal}"] += 1
        counter[f"all_unsigned_variable|{abs(literal)}"] += 1
    if len(values) <= PAIR_MAXIMUM_CLAUSE_SIZE:
        for first in range(len(values)):
            for second in range(first + 1, len(values)):
                left, right = values[first], values[second]
                counter[f"stage_pair|h{horizon}|{left}|{right}"] += 1
                counter[f"all_pair|{left}|{right}"] += 1


def build_clause_frequency_table(
    measurement: Mapping[str, Any],
    *,
    minimum_nonzero_candidates: int = 4,
) -> tuple[ContinuousFlowTable, dict[str, Any]]:
    """Build target-blind exact frequency coordinates for one 256-cover."""

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
        or minimum_nonzero_candidates < 1
    ):
        raise ValueError("clause-frequency measurement identity differs")
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in run.get("stages", [])
    }
    expected = {
        (candidate, horizon)
        for candidate in range(256)
        for horizon in HORIZONS
    }
    if set(rows) != expected:
        raise ValueError("clause-frequency stage cover differs")
    assumption_variable_sets = {
        frozenset(abs(int(literal)) for literal in row.get("assumptions", []))
        for row in rows.values()
    }
    if (
        len(assumption_variable_sets) != 1
        or len(next(iter(assumption_variable_sets), frozenset())) != 8
    ):
        raise ValueError("clause-frequency assumption-variable set differs")
    assumption_variables = next(iter(assumption_variable_sets))
    counters: list[Counter[str]] = []
    accepted_clause_count = 0
    projected_empty_clause_count = 0
    projected_literal_count = 0
    for candidate in range(256):
        counter: Counter[str] = Counter()
        for horizon in HORIZONS:
            clauses = rows[(candidate, horizon)].get("learned_clauses_stage")
            if not isinstance(clauses, list):
                raise ValueError("clause-frequency learned-clause payload differs")
            for clause in clauses:
                accepted_clause_count += 1
                projected = tuple(
                    int(literal)
                    for literal in clause
                    if abs(int(literal)) not in assumption_variables
                )
                if not projected:
                    projected_empty_clause_count += 1
                    continue
                projected_literal_count += len(projected)
                _increment_clause_features(counter, horizon, projected)
        counters.append(counter)
    support = Counter(
        feature
        for counter in counters
        for feature, count in counter.items()
        if count > 0
    )
    retained: dict[str, np.ndarray] = {}
    family_counts: Counter[str] = Counter()
    ledger = []
    for feature in sorted(support):
        nonzero = int(support[feature])
        if nonzero < minimum_nonzero_candidates:
            continue
        values = np.fromiter(
            (counter.get(feature, 0) for counter in counters),
            dtype=np.int32,
            count=256,
        )
        if int(values.min()) == int(values.max()):
            continue
        retained[feature] = values
        family = feature.split("|", 1)[0]
        if family not in FEATURE_FAMILIES:
            raise RuntimeError("clause-frequency feature family differs")
        family_counts[family] += 1
        ledger.append(
            {
                "feature": feature,
                "nonzero_candidates": nonzero,
                "unique_counts": int(np.unique(values).size),
                "maximum_count": int(values.max()),
                "counts_int32le_sha256": hashlib.sha256(values.tobytes()).hexdigest(),
            }
        )
    if not retained:
        raise RuntimeError("clause-frequency table retained no varying features")
    return (
        ContinuousFlowTable(
            label=label,
            true_prefix=true_prefix,
            feature_counts=retained,
        ),
        {
            "raw_feature_count": len(support),
            "retained_varying_feature_count": len(retained),
            "minimum_nonzero_candidates": minimum_nonzero_candidates,
            "retained_feature_families": dict(sorted(family_counts.items())),
            "accepted_clause_count": accepted_clause_count,
            "projected_empty_clause_count": projected_empty_clause_count,
            "projected_literal_count": projected_literal_count,
            "feature_ledger_sha256": hashlib.sha256(
                _canonical_bytes(ledger)
            ).hexdigest(),
            "assumption_variable_count": len(assumption_variables),
            "assumption_variables_projected_before_counting": True,
            "true_prefix_used_during_frequency_or_feature_retention": False,
        },
    )


def _canonical_bytes(value: Any) -> bytes:
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
