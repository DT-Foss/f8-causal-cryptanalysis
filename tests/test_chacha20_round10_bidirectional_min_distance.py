from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_bidirectional_min_distance.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_bidirectional_min_distance_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "a53a983dfb0ebd88fa1e9b7d6f05786d7de078161003b9bb1d61e0d5fd889d15"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "c2d4b703c463d5cdd2c95f22d9a5627c0cf0157e8929df5090ef2e9fe8e02c25"
CAUSAL_SHA256 = "15d06d3058e8843146366ae84056de66e4c724714e2166ef6ac2d5fdfd3b6046"
CAUSAL_GRAPH_SHA256 = "5c4877af9b0c83fd63a7abb6619d76eb656e74ed29ec3aaf145bb9bb21316e1f"
SELECTION_SHA256 = "1d86870405e818bb11adb42e57e480802535444529d4e09ab1d106a283be70da"
SOURCE_EXPORTS_SHA256 = "c59025b3ffcc1923072015cd58ef02a23731d5e1c633755eb91229d6e09a76fe"
GRAPH_SHA256 = "b5812bb01eb1e2ca035a931b42d40db3cc04fd331b33b20a1a1377563037e627"
STRUCTURAL_DIAGNOSTICS_SHA256 = "9d9a95401a979b915c370cbbbb905f606f7f1d683160435070868c58d63c7162"
TRANSFORM_MANIFEST_SHA256 = "ace479de29cf0d893b643d81f20845ad9fe2925b6945bfdaa9241fc8452edd74"
EXECUTION_SHA256 = "f08f591f4ab97266e0eb92c576048f9da5bf2ae7a970d97a7a4b0c039e2fef8b"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "39b7e4f18230e9ee35ec6e109bc322150f07b648557bb209449033ec0e672ca3"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a206_protocol_runner_and_anchor_chain_are_exact(analysis: dict[str, Any]) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert analysis["anchor_gates"] == {
        "A204_result_sha256": MODULE.A204_SHA256,
        "A204_causal_sha256": MODULE.A204_CAUSAL_SHA256,
        "A204_causal_graph_sha256": MODULE.A204_CAUSAL_GRAPH_SHA256,
        "A204_causal_provenance_verified": True,
        "A205_r2_result_sha256": MODULE.A205_SHA256,
        "A205_r2_causal_sha256": MODULE.A205_CAUSAL_SHA256,
        "A205_r2_causal_graph_sha256": MODULE.A205_CAUSAL_GRAPH_SHA256,
        "A205_r2_causal_provenance_verified": True,
        "A204_complete_round10_cover_all_unknown_retained": True,
        "A205_r2_unique_robust_both_mode_candidate_retained": True,
        "A205_r2_boundary_metadata_correction_retained": True,
    }
    assert analysis["solver_execution_started"] is False
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False


def test_a206_unique_robust_pilot_and_full_execution_are_frozen(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    selection = protocol["selection"]
    assert selection["selected_candidate"] == "bidirectional_min_distance"
    assert selection["robust_both_mode_candidates"] == ["bidirectional_min_distance"]
    assert (
        len(selection["calibration_candidates_with_at_least_one_confirmed_noncontrol_SAT_mode"])
        == 12
    )
    assert selection["selection_time_data_used"] is False
    assert selection["complete_A205_transfer_portfolio_deferred_not_cancelled"] is True
    assert protocol["round10_source"]["prefix_order"] == list(MODULE.PREFIXES)
    assert protocol["solver_modes"] == [
        {"name": "default", "arguments": []},
        {"name": "reverse", "arguments": ["--reverse=true"]},
    ]
    plan = protocol["execution_plan"]
    assert plan["cell_mode_count"] == 64
    assert plan["solver_time_limit_seconds_per_cell_mode"] == 10
    assert plan["external_timeout_seconds_per_cell_mode"] == 13
    assert plan["max_parallel_workers"] == 4
    assert plan["early_stop_permitted"] is False


def test_a206_round10_information_boundary_is_explicit(analysis: dict[str, Any]) -> None:
    boundary = analysis["protocol"]["information_boundary"]
    assert boundary["A205_calibration_outcomes_known_before_freeze"] is True
    assert (
        boundary[
            "A205_candidate_selected_after_calibration_by_the_predeclared_robust_both_mode_criterion"
        ]
        is True
    )
    assert boundary["any_A206_round10_solver_outcome_known_before_freeze"] is False
    assert boundary["round10_unknown_assignment_in_protocol_or_source"] is False
    assert boundary["round10_unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["unrelated_A188_known_positive_model_present_only_in_A205_anchor"] is True
    assert (
        boundary["unrelated_A188_known_positive_model_used_in_A206_order_or_solver_input"] is False
    )
    assert boundary["early_stop_permitted"] is False


def test_a206_representative_order_and_transformed_mapping_are_frozen(
    analysis: dict[str, Any],
) -> None:
    structural = analysis["protocol"]["structural_order"]
    graph = analysis["protocol"]["representative_graph_preflight"]
    assert structural["order_sha256"] == (
        "c019beaea6888a5db16c3805922752c273aacd5a70498df1119edb21535db8d3"
    )
    assert structural["old_to_new_sha256"] == (
        "8568c89883908e5eadead20533c700c4a6a37d7ac9968de5ea939f66f2012702"
    )
    assert structural["transformed_free_k0_bit_one_literal_mapping"] == [
        12,
        11,
        13,
        14,
        15,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
    ]
    assert graph["variable_count"] == 232191
    assert graph["clause_count"] == 734180
    assert graph["connected_components"] == 2
    assert graph["isolated_vertices"] == 1
    assert graph["undirected_edges"] == 636276


def test_a206_comparison_logic_separates_recovery_both_mode_and_complete_resolution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    observations = []
    for prefix in MODULE.PREFIXES:
        for mode in ("default", "reverse"):
            if prefix == "00000":
                status = "sat"
            elif mode == "default":
                status = "unsat"
            else:
                status = "unknown"
            observations.append(
                {
                    "variant": f"cse_prefix_{prefix}__bidirectional_min_distance__{mode}",
                    "prefix": prefix,
                    "solver_mode": mode,
                    "status": status,
                }
            )
    confirmations = [
        {
            "variant": f"cse_prefix_00000__bidirectional_min_distance__{mode}",
            "prefix": "00000",
            "solver_mode": mode,
            "combined_assignment": 123,
            "recovered_unknown_low20": 123,
        }
        for mode in ("default", "reverse")
    ]
    comparison = MODULE._compare(protocol, {"observations": observations}, confirmations)
    assert comparison["status_counts"] == {
        "sat": 2,
        "unsat": 31,
        "unknown": 31,
        "invalid": 0,
    }
    assert comparison["confirmed_partial_recovery_retained"] is True
    assert comparison["both_mode_transfer_retained"] is True
    assert comparison["complete_domain_resolution_modes"] == ["default"]
    assert comparison["complete_domain_resolution_retained"] is True


def test_a206_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A206"
    assert raw.endswith(b"\n")


def test_a206_retained_artifact_and_subhashes_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["attempt_id"] == "A206"
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["evidence_stage"] == (
        "ROUND10_STRUCTURAL_ORDER_COMPLETE_TRANSFER_BOUNDARY_RETAINED"
    )
    assert payload["selection_sha256"] == SELECTION_SHA256
    assert payload["source_exports_sha256"] == SOURCE_EXPORTS_SHA256
    assert payload["graph_sha256"] == GRAPH_SHA256
    assert payload["structural_order_sha256"] == (
        "c019beaea6888a5db16c3805922752c273aacd5a70498df1119edb21535db8d3"
    )
    assert payload["structural_diagnostics_sha256"] == STRUCTURAL_DIAGNOSTICS_SHA256
    assert payload["transform_manifest_sha256"] == TRANSFORM_MANIFEST_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a206_retained_source_graph_order_and_transforms_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    sources = payload["source_exports"]
    assert len(sources) == 32
    assert len({row["sha256"] for row in sources}) == 32
    assert {row["normalized_sha256"] for row in sources} == {
        "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
    }
    assert len(payload["structural_order"]) == 232191
    assert MODULE._canonical_sha256(payload["graph"]) == GRAPH_SHA256
    diagnostics = payload["structural_diagnostics"]
    assert diagnostics["candidate"] == "bidirectional_min_distance"
    assert diagnostics["key_source_count"] == 15
    assert diagnostics["unit_source_count"] == 6919
    assert diagnostics["transformed_free_k0_bit_one_literal_mapping"] == [
        12,
        11,
        13,
        14,
        15,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
    ]
    transforms = payload["transform_manifest"]
    assert len(transforms) == 32
    assert len({row["transformed_cnf_sha256"] for row in transforms}) == 32
    assert {row["transformed_normalized_sha256"] for row in transforms} == {
        "65809b9b8bf1698195ec6b82b395f49242ec7ea6997c0966ccfaa8d69ae44bca"
    }
    assert all(row["inverse_byte_identical"] is True for row in transforms)
    assert MODULE._canonical_sha256(transforms) == TRANSFORM_MANIFEST_SHA256


def test_a206_retained_complete_64_cell_mode_boundary_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    execution = payload["execution"]
    observations = execution["observations"]
    assert len(observations) == 64
    assert len(execution["wave_observations"]) == 16
    assert [row["variant"] for row in observations] == execution["variant_order"]
    assert all(row["status"] == "unknown" for row in observations)
    assert all(row["status_line"] is None for row in observations)
    assert all(row["internal_timeout_marker"] is True for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["witness_assignment_count"] == 0 for row in observations)
    assert all(row["model"] is None for row in observations)
    assert all(
        set(row["metrics"]) == {"conflicts", "decisions", "propagations", "restarts"}
        for row in observations
    )
    assert sum(row["volatile_seconds"] for row in observations) == 644.0202014148235
    assert execution["complete_cell_mode_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["round10_unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256

    assert payload["confirmations"] == []
    comparison = payload["comparisons"]
    assert comparison["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 64,
        "invalid": 0,
    }
    assert comparison["per_mode_status_counts"] == {
        "default": {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0},
        "reverse": {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0},
    }
    assert comparison["confirmed_partial_recovery_retained"] is False
    assert comparison["both_mode_transfer_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False
    assert comparison["complete_predeclared_execution"] is True
    assert MODULE._canonical_sha256(comparison) == COMPARISON_SHA256


def test_a206_native_reader_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a206-round10-cover-anchor",
        "chacha20-a206-robust-order-selection",
        "chacha20-a206-primal-graph-order",
        "chacha20-a206-bijective-transform",
        "chacha20-a206-complete-cell-mode-execution",
        "chacha20-a206-independent-confirmation",
        "chacha20-a206-transfer-result",
    ]
    assert len(rows) == 7
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )
