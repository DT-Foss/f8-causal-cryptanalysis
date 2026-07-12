from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_structural_portfolio.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_structural_portfolio_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "420dc4f30c6bea9da848a4ffe08bcca4b424ff0dbdd7b39b4a0a18f35122cc19"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a207_protocol_runner_and_anchor_chain_are_exact(analysis: dict[str, Any]) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    gates = analysis["anchor_gates"]
    assert gates["A206_result_sha256"] == MODULE.A206_SHA256
    assert gates["A206_causal_provenance_verified"] is True
    assert gates["A206_complete_64_unknown_boundary_retained"] is True
    assert gates["order_archive_sha256"] == MODULE.ORDER_ARCHIVE_SHA256
    assert gates["order_metadata_sha256"] == MODULE.ORDER_METADATA_SHA256
    assert gates["order_causal_provenance_verified"] is True
    assert gates["order_archive_12_exact_permutations_retained"] is True


def test_a207_complete_remaining_portfolio_is_frozen_without_reexecution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    portfolio = protocol["complete_calibrated_portfolio"]
    assert portfolio["candidate_order"] == list(MODULE._ARCHIVE.CANDIDATE_ORDER)
    assert portfolio["remaining_candidate_order"] == list(MODULE.REMAINING_CANDIDATES)
    assert len(MODULE.REMAINING_CANDIDATES) == 11
    assert "bidirectional_min_distance" not in MODULE.REMAINING_CANDIDATES
    assert portfolio["A206_completed_candidate"] == "bidirectional_min_distance"
    assert portfolio["A206_completed_modes"] == ["default", "reverse"]
    assert portfolio["A206_completed_cell_mode_count"] == 64
    assert portfolio["A206_reexecution_permitted"] is False
    assert portfolio["solver_mode_by_remaining_candidate"] == {
        candidate: MODULE._ARCHIVE.CALIBRATED_MODES[candidate]
        for candidate in MODULE.REMAINING_CANDIDATES
    }
    assert portfolio["volatile_calibration_time_used_for_selection"] is False


def test_a207_exact_352_plus_64_execution_plan_is_frozen(analysis: dict[str, Any]) -> None:
    plan = analysis["protocol"]["execution_plan"]
    assert plan["remaining_candidate_count"] == 11
    assert plan["prefix_cells_per_candidate"] == 32
    assert plan["new_cell_mode_count"] == 352
    assert plan["combined_with_A206_cell_mode_count"] == 416
    assert plan["solver_time_limit_seconds_per_cell"] == 10
    assert plan["external_timeout_seconds_per_cell"] == 13
    assert plan["max_parallel_workers"] == 4
    assert plan["inverse_restore_prefix_endpoints_per_candidate"] == ["00000", "11111"]
    assert plan["early_stop_permitted"] is False


def test_a207_information_boundary_is_explicit(analysis: dict[str, Any]) -> None:
    boundary = analysis["protocol"]["information_boundary"]
    assert boundary["A205_and_A206_outcomes_known_before_freeze"] is True
    assert boundary["A207_order_archive_created_before_any_A207_remaining_portfolio_solver_outcome"]
    assert boundary["any_A207_remaining_portfolio_solver_outcome_known_before_freeze"] is False
    assert boundary["round10_unknown_assignment_in_protocol_source_or_order_archive"] is False
    assert boundary["round10_unknown_assignment_available_to_runner_before_execution"] is False
    assert (
        boundary["unrelated_A188_known_positive_model_used_in_A207_order_transform_or_solver_input"]
        is False
    )
    assert boundary["A206_candidate_reexecution_permitted"] is False
    assert boundary["early_stop_permitted"] is False


def test_a207_archive_rows_and_calibrated_modes_align(analysis: dict[str, Any]) -> None:
    protocol = analysis["protocol"]
    metadata = analysis["order_metadata"]
    manifest = metadata["candidate_manifest"]
    indices = protocol["complete_calibrated_portfolio"]["archive_row_indices"]
    assert indices == {
        candidate: index for index, candidate in enumerate(MODULE._ARCHIVE.CANDIDATE_ORDER)
    }
    for candidate in MODULE.REMAINING_CANDIDATES:
        row = manifest[indices[candidate]]
        assert row["candidate"] == candidate
        assert (
            row["calibrated_solver_mode"]
            == protocol["complete_calibrated_portfolio"]["solver_mode_by_remaining_candidate"][
                candidate
            ]
        )
    assert (
        metadata["information_boundary"][
            "any_A207_remaining_portfolio_solver_outcome_known_before_archive_derivation"
        ]
        is False
    )


def test_a207_comparison_logic_keeps_unknown_distinct_from_unsat(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    observations = [
        {
            "variant": f"{candidate}__cse_prefix_{prefix}__{protocol['complete_calibrated_portfolio']['solver_mode_by_remaining_candidate'][candidate]}",
            "candidate": candidate,
            "prefix": prefix,
            "status": "unknown",
        }
        for candidate in MODULE.REMAINING_CANDIDATES
        for prefix in MODULE.PREFIXES
    ]
    comparison = MODULE._compare(
        protocol=protocol,
        observations=observations,
        confirmations=[],
        a206=analysis["a206_result"],
    )
    assert comparison["new_cell_mode_count"] == 352
    assert comparison["new_status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 352,
        "invalid": 0,
    }
    assert comparison["combined_calibrated_portfolio_cell_mode_count"] == 416
    assert comparison["confirmed_recovery_retained"] is False
    assert comparison["single_candidate_complete_domain_resolution_retained"] is False
    assert comparison["portfolio_complete_domain_resolution_retained"] is False
    assert comparison["portfolio_unsat_prefixes"] == []


def test_a207_progress_map_retains_missing_metrics_instead_of_aborting(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    observations = [
        {
            "variant": f"{candidate}__cse_prefix_{prefix}",
            "candidate": candidate,
            "solver_mode": protocol["complete_calibrated_portfolio"][
                "solver_mode_by_remaining_candidate"
            ][candidate],
            "prefix": prefix,
            "metrics": {},
        }
        for candidate in MODULE.REMAINING_CANDIDATES
        for prefix in MODULE.PREFIXES
    ]
    progress = MODULE._progress_map(observations, analysis["a206_result"])
    assert len(progress["cell_rows"]) == 352
    assert len(progress["candidate_summaries"]) == 11
    for summary in progress["candidate_summaries"]:
        for metric in summary["metrics"].values():
            assert metric["candidate_total"] is None
            assert metric["candidate_metric_observation_count"] == 0
            assert metric["candidate_metric_missing_count"] == 32
            assert metric["total_ratio"] is None


def test_a207_portfolio_resolution_rejects_a_sat_unsat_prefix_contradiction(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    observations = [
        {
            "variant": f"{candidate}__cse_prefix_{prefix}",
            "candidate": candidate,
            "prefix": prefix,
            "status": "unknown",
        }
        for candidate in MODULE.REMAINING_CANDIDATES
        for prefix in MODULE.PREFIXES
    ]
    observations[0]["status"] = "sat"
    observations[32]["status"] = "unsat"
    confirmations = [
        {
            "variant": observations[0]["variant"],
            "prefix": "00000",
            "combined_assignment": 123,
            "recovered_unknown_low20": 123,
        }
    ]
    comparison = MODULE._compare(
        protocol=protocol,
        observations=observations,
        confirmations=confirmations,
        a206=analysis["a206_result"],
    )
    assert comparison["portfolio_contradictory_sat_unsat_prefixes"] == ["00000"]
    assert comparison["portfolio_complete_domain_resolution_retained"] is False


def test_a207_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A207"
    assert raw.endswith(b"\n")
