from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path

import pytest

from arx_carry_leak.factorial_boundary import (
    DRIVER_PRIORITY,
    NEXT_PROBE,
    PANEL_ORDER,
    localize_factorial_boundary,
)

ROOT = Path(__file__).parents[1]
PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_boundary_router_v1.json"


def _panels(**updates: float) -> dict[str, float]:
    result = {
        "fit_by_confirm": 4.0,
        "select_by_confirm": 4.0,
        "confirm_by_fit": 4.0,
        "confirm_by_confirm": 4.0,
    }
    result.update(updates)
    return result


def test_retained_result_routes_to_separate_prospective_target() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=4.0,
        panel_mean_log2_ranks=_panels(),
        primary_retained=True,
    )
    assert result["evidence_status"] == "RETAINED_RESULT"
    assert result["selected_driver"] == "prospective_target"
    assert result["next_probe"]["probe"] == "separately_committed_label_free_target_order"
    assert result["registered_retention_rule_changed"] is False


def test_prefix_novelty_is_localized_from_both_suffix_levels() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=3.0,
        panel_mean_log2_ranks=_panels(
            fit_by_confirm=3.0,
            select_by_confirm=3.0,
            confirm_by_fit=6.0,
            confirm_by_confirm=6.0,
        ),
        primary_retained=False,
    )
    effects = result["factorial_effects_mean_log2_rank"]
    assert effects["prefix_novelty_main_effect"] == 3.0
    assert effects["suffix_novelty_main_effect"] == 0.0
    assert effects["prefix_suffix_interaction"] == 0.0
    assert result["selected_driver"] == "prefix_novelty_main_effect"
    assert result["next_probe"]["probe"] == "xor_translation_equivariant_prefix_reader"


def test_suffix_novelty_routes_to_eight_block_ensemble() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=2.0,
        panel_mean_log2_ranks=_panels(
            fit_by_confirm=5.0,
            select_by_confirm=5.0,
            confirm_by_fit=2.0,
            confirm_by_confirm=5.0,
        ),
        primary_retained=False,
    )
    assert result["factorial_effects_mean_log2_rank"]["suffix_novelty_main_effect"] == 3.0
    assert result["selected_driver"] == "suffix_novelty_main_effect"
    assert result["next_probe"]["probe"] == "eight_block_counter_ensemble_reader"


def test_positive_interaction_has_deterministic_tie_priority() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=0.0,
        panel_mean_log2_ranks=_panels(
            fit_by_confirm=0.0,
            select_by_confirm=0.0,
            confirm_by_fit=1.0,
            confirm_by_confirm=3.0,
        ),
        primary_retained=False,
    )
    effects = result["factorial_effects_mean_log2_rank"]
    assert effects["prefix_suffix_interaction"] == 2.0
    assert effects["prefix_novelty_main_effect"] == 2.0
    assert result["selected_driver"] == "prefix_suffix_interaction"
    assert result["next_probe"]["probe"] == "eight_block_cross_schedule_tensor_reader"


def test_additive_main_effect_tie_prefers_prefix_before_suffix() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=0.0,
        panel_mean_log2_ranks=_panels(
            fit_by_confirm=0.0,
            select_by_confirm=2.0,
            confirm_by_fit=2.0,
            confirm_by_confirm=4.0,
        ),
        primary_retained=False,
    )
    effects = result["factorial_effects_mean_log2_rank"]
    assert effects["prefix_suffix_interaction"] == 0.0
    assert effects["prefix_novelty_main_effect"] == 2.0
    assert effects["suffix_novelty_main_effect"] == 2.0
    assert result["selected_driver"] == "prefix_novelty_main_effect"


def test_no_positive_penalty_becomes_cluster_stability_boundary() -> None:
    result = localize_factorial_boundary(
        selection_mean_log2_rank=5.0,
        panel_mean_log2_ranks=_panels(
            fit_by_confirm=5.0,
            select_by_confirm=4.5,
            confirm_by_fit=4.5,
            confirm_by_confirm=4.0,
        ),
        primary_retained=False,
    )
    assert max(result["positive_penalty_components"].values()) == 0.0
    assert result["selected_driver"] == "cluster_stability"
    assert result["primary_condition"] == "CONCENTRATION_WITHOUT_CLUSTER_RETENTION"


def test_factorial_identity_and_effect_equations_are_exact() -> None:
    selection = 1.25
    panels = _panels(
        fit_by_confirm=2.5,
        select_by_confirm=3.0,
        confirm_by_fit=4.25,
        confirm_by_confirm=6.5,
    )
    result = localize_factorial_boundary(
        selection_mean_log2_rank=selection,
        panel_mean_log2_ranks=panels,
        primary_retained=False,
    )
    effects = result["factorial_effects_mean_log2_rank"]
    assert effects["prefix_novelty_at_fit_suffix"] == 3.0
    assert effects["prefix_novelty_at_confirm_suffix"] == 3.5
    assert effects["suffix_novelty_at_select_prefix"] == 1.75
    assert effects["suffix_novelty_at_confirm_prefix"] == 2.25
    assert effects["prefix_novelty_main_effect"] == 3.25
    assert effects["suffix_novelty_main_effect"] == 2.0
    assert effects["prefix_suffix_interaction"] == 0.5


def test_interaction_identity_holds_across_finite_factorial_tuples() -> None:
    values = (-2.5, 0.0, 1.25, 7.0)
    for selection in values:
        for select_confirm in values:
            for confirm_fit in values:
                for confirm_confirm in values:
                    result = localize_factorial_boundary(
                        selection_mean_log2_rank=selection,
                        panel_mean_log2_ranks=_panels(
                            fit_by_confirm=0.5,
                            select_by_confirm=select_confirm,
                            confirm_by_fit=confirm_fit,
                            confirm_by_confirm=confirm_confirm,
                        ),
                        primary_retained=False,
                    )
                    effects = result["factorial_effects_mean_log2_rank"]
                    interaction = effects["prefix_suffix_interaction"]
                    assert math.isclose(
                        interaction,
                        effects["prefix_novelty_at_confirm_suffix"]
                        - effects["prefix_novelty_at_fit_suffix"],
                        rel_tol=0.0,
                        abs_tol=1e-12,
                    )
                    assert math.isclose(
                        interaction,
                        effects["suffix_novelty_at_confirm_prefix"]
                        - effects["suffix_novelty_at_select_prefix"],
                        rel_tol=0.0,
                        abs_tol=1e-12,
                    )


@pytest.mark.parametrize(
    ("selection", "panels", "retained"),
    [
        (math.nan, _panels(), False),
        (1.0, {**_panels(), "extra": 1.0}, False),
        (1.0, {name: math.inf for name in PANEL_ORDER}, False),
        (1.0, _panels(), 1),
    ],
)
def test_invalid_inputs_are_rejected(selection, panels, retained) -> None:
    with pytest.raises(ValueError):
        localize_factorial_boundary(
            selection_mean_log2_rank=selection,
            panel_mean_log2_ranks=panels,
            primary_retained=retained,
        )


def test_output_digest_changes_with_every_mechanistic_input() -> None:
    base = localize_factorial_boundary(
        selection_mean_log2_rank=4.0,
        panel_mean_log2_ranks=_panels(),
        primary_retained=False,
    )
    changed = localize_factorial_boundary(
        selection_mean_log2_rank=4.0,
        panel_mean_log2_ranks={**copy.deepcopy(_panels()), "confirm_by_confirm": 4.1},
        primary_retained=False,
    )
    assert base["localization_sha256"] != changed["localization_sha256"]


def test_preoutcome_router_protocol_binds_code_equations_and_routes() -> None:
    protocol = json.loads(PROTOCOL.read_bytes())
    source = ROOT / protocol["anchors"]["router_source_path"]
    assert protocol["schema"] == "chacha20-round20-factorial-boundary-router-protocol-v1"
    assert protocol["attempt_id"] == "A220B"
    assert protocol["protocol_state"].endswith("holdout_outcome")
    assert (
        hashlib.sha256(source.read_bytes()).hexdigest()
        == protocol["anchors"]["router_source_sha256"]
    )
    assert protocol["permitted_inputs"]["holdout_panels"] == list(PANEL_ORDER)
    assert protocol["driver_priority_on_exact_ties"] == list(DRIVER_PRIORITY)
    assert protocol["routing"]["retained"] == NEXT_PROBE["prospective_target"]["probe"]
    assert protocol["information_boundary"] == {
        "A220_holdout_measurements_opened_before_freeze": False,
        "A220_holdout_outcome_opened_before_freeze": False,
        "raw_trajectory_or_target_label_input_permitted": False,
        "retention_rule_threshold_or_reader_change_permitted": False,
        "router_adds_a_significance_claim": False,
        "router_purpose": ("mechanistic localization and deterministic next-probe selection only"),
    }
