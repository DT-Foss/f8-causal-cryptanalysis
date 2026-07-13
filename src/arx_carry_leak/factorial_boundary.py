"""Prospective mechanistic routing for an A220 factorial holdout boundary.

The router contains no file, solver, label, or model access.  It converts the
four pre-frozen holdout panels plus the Reader's selection-panel reference into
the exact two-factor contrasts that identify prefix novelty, suffix novelty,
and their interaction.  It is useful only after the registered A220 evaluation
has been finalized; it never changes that evaluation or its retention rule.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any

PANEL_ORDER = (
    "fit_by_confirm",
    "select_by_confirm",
    "confirm_by_fit",
    "confirm_by_confirm",
)
UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2 = 6.578110496969589

# Exact ties prefer the most mechanistically specific contrast.
DRIVER_PRIORITY = (
    "prefix_suffix_interaction",
    "prefix_novelty_main_effect",
    "suffix_novelty_main_effect",
    "fit_to_selection_shift",
    "absolute_primary_capacity_gap",
)

NEXT_PROBE = {
    "prefix_suffix_interaction": {
        "probe": "eight_block_cross_schedule_tensor_reader",
        "mechanism": (
            "combine the frozen direction/schedule channels across all eight public "
            "counter blocks before applying a low-rank interaction readout"
        ),
    },
    "prefix_novelty_main_effect": {
        "probe": "xor_translation_equivariant_prefix_reader",
        "mechanism": (
            "replace absolute prefix coordinates by XOR-orbit aligned local, cube, and "
            "path residuals while preserving the frozen solver measurements"
        ),
    },
    "suffix_novelty_main_effect": {
        "probe": "eight_block_counter_ensemble_reader",
        "mechanism": (
            "average target-independent trajectory evidence across the eight public "
            "counter blocks to suppress within-prefix suffix-landscape dependence"
        ),
    },
    "fit_to_selection_shift": {
        "probe": "cluster_balanced_operator_ensemble",
        "mechanism": (
            "combine diverse frozen operators with equal prefix-cluster weight instead "
            "of selecting a single minimum on the selection panel"
        ),
    },
    "absolute_primary_capacity_gap": {
        "probe": "multi_block_joint_cnf_trajectory",
        "mechanism": (
            "increase public observation by constraining multiple ChaCha20 blocks in one "
            "shared-key formula before extracting the same three trajectory channels"
        ),
    },
    "cluster_stability": {
        "probe": "prefix_orbit_averaged_reader",
        "mechanism": (
            "enforce prefix-orbit equivariance so a favorable mean cannot depend on a "
            "small subset of the five independent confirmation prefix clusters"
        ),
    },
    "prospective_target": {
        "probe": "separately_committed_label_free_target_order",
        "mechanism": (
            "reuse the retained Reader byte-for-byte on a newly committed target and "
            "freeze its complete 256-prefix order before ranked recovery"
        ),
    },
}


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _finite(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        raise ValueError(f"A220 factorial boundary {label} is not finite")
    return float(value)


def localize_factorial_boundary(
    *,
    selection_mean_log2_rank: float,
    panel_mean_log2_ranks: Mapping[str, float],
    primary_retained: bool,
) -> dict[str, Any]:
    """Return exact factorial contrasts and a deterministic next mechanism.

    Lower mean-log2 rank is better.  Positive effects therefore measure a loss
    under the named novelty.  No significance claim is introduced here: the
    registered exact null remains the sole A220 retention decision.
    """

    if not isinstance(primary_retained, bool):
        raise ValueError("A220 factorial boundary retention flag is not Boolean")
    if not isinstance(panel_mean_log2_ranks, Mapping) or set(panel_mean_log2_ranks) != set(
        PANEL_ORDER
    ):
        raise ValueError("A220 factorial boundary panel set differs")
    selection = _finite(selection_mean_log2_rank, "selection reference")
    panels = {panel: _finite(panel_mean_log2_ranks[panel], panel) for panel in PANEL_ORDER}
    fit_confirm = panels["fit_by_confirm"]
    select_confirm = panels["select_by_confirm"]
    confirm_fit = panels["confirm_by_fit"]
    confirm_confirm = panels["confirm_by_confirm"]

    prefix_at_fit_suffix = confirm_fit - selection
    prefix_at_confirm_suffix = confirm_confirm - select_confirm
    suffix_at_select_prefix = select_confirm - selection
    suffix_at_confirm_prefix = confirm_confirm - confirm_fit
    prefix_main = 0.5 * (prefix_at_fit_suffix + prefix_at_confirm_suffix)
    suffix_main = 0.5 * (suffix_at_select_prefix + suffix_at_confirm_prefix)
    interaction = confirm_confirm - confirm_fit - select_confirm + selection
    fit_to_selection = select_confirm - fit_confirm
    absolute_gap = confirm_confirm - UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2

    effects = {
        "prefix_novelty_at_fit_suffix": prefix_at_fit_suffix,
        "prefix_novelty_at_confirm_suffix": prefix_at_confirm_suffix,
        "prefix_novelty_main_effect": prefix_main,
        "suffix_novelty_at_select_prefix": suffix_at_select_prefix,
        "suffix_novelty_at_confirm_prefix": suffix_at_confirm_prefix,
        "suffix_novelty_main_effect": suffix_main,
        "prefix_suffix_interaction": interaction,
        "fit_to_selection_shift": fit_to_selection,
        "absolute_primary_capacity_gap": absolute_gap,
    }
    if not all(math.isfinite(value) for value in effects.values()):
        raise RuntimeError("A220 factorial boundary contrast is non-finite")
    positive_penalties = {name: max(0.0, effects[name]) for name in DRIVER_PRIORITY}
    driver_order = sorted(
        DRIVER_PRIORITY,
        key=lambda name: (-positive_penalties[name], DRIVER_PRIORITY.index(name)),
    )

    if primary_retained:
        status = "RETAINED_RESULT"
        primary_condition = "REGISTERED_FACTORIAL_TRANSFER_RETAINED"
        driver = "prospective_target"
    else:
        status = "NEW_BOUNDARY"
        primary_condition = (
            "CONCENTRATION_WITHOUT_CLUSTER_RETENTION"
            if confirm_confirm < UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2
            else "PRIMARY_CONFIRMATION_PANEL_AT_OR_ABOVE_UNIFORM_REFERENCE"
        )
        driver = (
            driver_order[0] if positive_penalties[driver_order[0]] > 0.0 else "cluster_stability"
        )

    result = {
        "schema": "chacha20-round20-factorial-boundary-localization-v1",
        "evidence_status": status,
        "registered_retention_rule_changed": False,
        "significance_claim_added": False,
        "selection_reference_mean_log2_rank": selection,
        "panel_mean_log2_ranks": panels,
        "uniform_random_rank_expected_mean_log2": (UNIFORM_RANDOM_RANK_EXPECTED_MEAN_LOG2),
        "primary_condition": primary_condition,
        "factorial_effects_mean_log2_rank": effects,
        "positive_penalty_components": positive_penalties,
        "driver_order": driver_order,
        "selected_driver": driver,
        "next_probe": NEXT_PROBE[driver],
    }
    result["localization_sha256"] = _canonical_sha256(result)
    return result
