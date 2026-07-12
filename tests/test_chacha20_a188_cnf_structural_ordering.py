from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_a188_cnf_structural_ordering.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_a188_cnf_structural_ordering_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "605310ffeb5836f609ad3ca9a5079b56479fe299ed8fafb39ff54d7859c642df"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "b3c76fca5a9ffabf3bd2c2bf812c8ef66b9be56bc7f9936a9525fd5e8d3c7f7f"
CAUSAL_SHA256 = "d17ed98433e70ecfafd75ce895372aa7f150cb2b178c853697ee8406f0582f80"
CAUSAL_GRAPH_SHA256 = "8dddd0764910b940627c65e2b21b2e4e0e367db388d481954e70c3213c56fec0"
SOURCE_EXPORT_SHA256 = "0d40648ef1899ce4a2aa80558ab2ec5d230ee8cfa8951e926ed8537bb8d30754"
GRAPH_SHA256 = "57e7280e33fa4a39c66f7f3643edae61892c8348e1c520ac728a15d1b3897c21"
CANDIDATE_DIAGNOSTICS_SHA256 = "671f3ba37bd59dcb2c588413ffc457f62a3bfff1627a57840bb93938a0944662"
TRANSFORM_PLAN_SHA256 = "81c957f7db4181817bad6bd23b455e96ba63e4150634024649c5ef34da91c082"
EXECUTION_SHA256 = "28ca16c1d0fc5b3a4375803c613dd1a0cdeaf6e6a659b1ab61b97671444a398b"
CONFIRMATION_SHA256 = "6d68ffe6030f8625f5034a1ab546bd2145618f0c7873b53141a405144c100c1a"
COMPARISON_SHA256 = "60b1363e815ae5248a314dd1b35af8a2437f0f85535da39123603c72c045e1f3"
METADATA_CORRECTION_SHA256 = "8cb488ed94f17944ca8e3b64b06085f4e6bd98e1f6c0f48eaee9fdede86f5a37"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a205_protocol_runner_and_source_anchors_are_exact(analysis: dict[str, Any]) -> None:
    protocol = analysis["protocol"]
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A204_r3_and_formula_atlas_transfer_design_before_any_A205_"
        "structural_solver_execution"
    )
    assert analysis["anchor_gates"]["A204_full_calibration_mapping_and_round10_boundary_retained"]
    assert analysis["anchor_gates"]["formula_atlas_2411_entries_113_pages_retained"]
    assert MODULE._sha256(analysis["a188_formula"].encode()) == (
        "004bbb7ef6ab6ab19898dface90ad7bee953e5a9ca5a3134fab41ac275bae590"
    )
    assert analysis["a188_public_challenge"]["unknown_assignment_included"] is False
    assert analysis["a188_public_challenge"]["unknown_key_word0_included"] is False
    assert analysis["solver_execution_started"] is False


def test_a205_complete_candidate_mode_matrix_is_frozen_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    candidates = protocol["candidates"]
    assert len(candidates) == 23
    assert len({row["name"] for row in candidates}) == 23
    assert protocol["candidate_order"] == [row["name"] for row in candidates]
    assert protocol["solver_modes"] == [
        {"name": "default", "arguments": []},
        {"name": "reverse", "arguments": ["--reverse=true"]},
    ]
    assert protocol["execution_plan"]["total_variant_count"] == 46
    boundary = protocol["information_boundary"]
    assert boundary["any_new_A205_structural_candidate_outcome_known_before_freeze"] is False
    assert boundary["known_positive_model_in_protocol"] is True
    assert boundary["known_positive_model_available_to_runner_before_execution"] is True
    assert boundary["model_used_only_for_post_witness_confirmation"] is True
    assert boundary["model_not_used_in_order_construction_or_solver_input"] is True
    assert boundary["early_stop_permitted"] is False


def test_a205_small_cnf_parser_graph_and_bfs_are_exact() -> None:
    raw = b"p cnf 4 4\n1 -2 0\n2 3 0\n-3 4 0\n-4 0\n"
    parsed = MODULE._parse_cnf(raw)
    assert parsed["variable_count"] == 4
    assert parsed["clause_count"] == 4
    assert parsed["length_counts"] == {1: 1, 2: 3}
    assert parsed["component_count"] == 1
    assert parsed["graph"].nnz // 2 == 3
    assert parsed["units"].tolist() == [4]
    assert MODULE._multi_source_bfs(parsed["graph"], parsed["units"]).tolist() == [3, 2, 1, 0]


def test_a205_reindex_and_inverse_restore_are_byte_exact() -> None:
    raw = b"p cnf 4 3\n1 -2 0\n2 3 -4 0\n-1 4 0\n"
    order = np.array([3, 1, 4, 2], dtype=np.int64)
    mapping = MODULE._old_to_new(order)
    inverse = np.zeros_like(mapping)
    inverse[mapping[1:]] = np.arange(1, len(mapping), dtype=np.int64)
    transformed = MODULE._reindex_cnf(raw, mapping)
    restored = MODULE._reindex_cnf(transformed, inverse)
    assert transformed != raw
    assert restored == raw
    assert MODULE._sha256(restored) == MODULE._sha256(raw)


def test_a205_alternating_orders_is_bijective_and_deterministic() -> None:
    first = np.array([1, 2, 3, 4, 5], dtype=np.int64)
    second = np.array([5, 4, 3, 2, 1], dtype=np.int64)
    combined = MODULE._alternate_orders(first, second)
    assert combined.tolist() == [1, 5, 2, 4, 3]
    assert sorted(combined.tolist()) == [1, 2, 3, 4, 5]


def test_a205_retained_source_graph_and_candidate_orders_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A205"
    assert payload["evidence_stage"] == "A188_CNF_ROBUST_STRUCTURAL_ORDERING_OUTLIER_RETAINED"
    assert payload["source_export_sha256"] == SOURCE_EXPORT_SHA256
    assert payload["graph_sha256"] == GRAPH_SHA256
    assert payload["candidate_diagnostics_sha256"] == CANDIDATE_DIAGNOSTICS_SHA256
    assert payload["transform_plan_sha256"] == TRANSFORM_PLAN_SHA256
    graph = payload["graph"]
    assert graph["variable_count"] == 96859
    assert graph["clause_count"] == 310088
    assert graph["undirected_edges"] == 264534
    assert graph["connected_components"] == 1
    assert graph["isolated_vertices"] == 0
    assert graph["unit_clause_variable_count"] == 6642
    diagnostics = payload["candidate_diagnostics"]
    assert len(diagnostics["candidate_order_sha256"]) == 23
    assert len(set(diagnostics["candidate_order_sha256"].values())) == 23
    assert diagnostics["key_source_count"] == 40
    assert diagnostics["unit_source_count"] == 6642
    assert diagnostics["key_distance_max"] == 9
    assert diagnostics["unit_distance_max"] == 7
    assert diagnostics["fiedler_eigenvalues"] == [
        -1.2263177088264413e-16,
        0.004648327669233628,
    ]
    assert diagnostics["fiedler_residual"] == 4.407140333482364e-08


def test_a205_retained_all_23_reindexings_are_byte_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    plan = payload["transform_plan"]
    assert [row["candidate"] for row in plan] == payload["protocol_gate"]["candidate_order"]
    assert len(plan) == 23
    assert len({row["order_sha256"] for row in plan}) == 23
    assert len({row["cnf_sha256"] for row in plan}) == 23
    assert all(row["inverse_byte_identical"] is True for row in plan)
    assert all(
        row["inverse_restored_sha256"]
        == "a49e7ec1ea7135b760d732855fe05b91ac85c56cf786e0777bb9a2188d6a3216"
        for row in plan
    )
    assert MODULE._canonical_sha256(plan) == TRANSFORM_PLAN_SHA256


def test_a205_retained_complete_46_variant_execution_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    execution = payload["execution"]
    observations = execution["observations"]
    assert len(observations) == 46
    assert [row["variant"] for row in observations] == execution["variant_order"]
    assert sum(row["status"] == "sat" for row in observations) == 16
    assert sum(row["status"] == "unknown" for row in observations) == 30
    assert all(row["status"] in {"sat", "unknown"} for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(
        set(row["metrics"]) == {"conflicts", "decisions", "propagations", "restarts"}
        for row in observations
    )
    assert all(
        (row["status_line"] == "s SATISFIABLE" and row["returncode"] == 10)
        if row["status"] == "sat"
        else (
            row["status_line"] is None
            and row["returncode"] == 0
            and row["internal_timeout_marker"] is True
        )
        for row in observations
    )
    assert sum(row["volatile_seconds"] for row in observations) == 210.8208139189519
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 16
    assert execution["known_positive_model_available_to_runner_before_execution"] is True
    assert execution["model_used_only_for_post_witness_confirmation"] is True
    assert execution["model_not_used_in_order_construction_or_solver_input"] is True
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256


def test_a205_all_16_models_and_structural_outliers_are_confirmed() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    confirmations = payload["confirmations"]
    assert len(confirmations) == 16
    assert all(row["combined_assignment"] == 357645702403 for row in confirmations)
    assert all(row["key_word0"] == 1163416835 for row in confirmations)
    assert all(row["key_word1_low_value"] == 83 for row in confirmations)
    assert all(row["all_blocks_match"] is True for row in confirmations)
    assert all(row["control_first_block_match"] is False for row in confirmations)
    assert all(row["output_bits_checked"] == 4096 for row in confirmations)
    assert MODULE._canonical_sha256(confirmations) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons["status_counts"] == {"sat": 16, "unsat": 0, "unknown": 30, "invalid": 0}
    assert comparisons["primary_prediction_retained"] is True
    assert comparisons["robust_prediction_retained"] is True
    assert comparisons["robust_both_mode_structural_candidates"] == ["bidirectional_min_distance"]
    assert comparisons["structural_outlier_candidates"] == [
        "occurrence_degree_ascending",
        "adjacency_degree_ascending",
        "adjacency_degree_descending",
        "occurrence_span_ascending",
        "output_unit_bfs_near",
        "output_unit_bfs_far",
        "bidirectional_min_distance",
        "signed_key_minus_output_ascending",
        "signed_key_minus_output_descending",
        "output_layer_parity_interleave",
        "fiedler_ascending",
        "fiedler_center_out",
    ]
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256

    correction = payload["metadata_correction"]
    assert correction["solver_observations_reused_without_rerun"] is True
    assert correction["solver_observations_changed"] is False
    assert correction["confirmations_changed"] is False
    assert correction["comparisons_changed"] is False
    assert correction["known_positive_model_used_only_after_a_SAT_witness_was_returned"]
    assert correction["known_positive_model_not_used_in_order_construction_or_solver_input"]
    assert MODULE._canonical_sha256(correction) == METADATA_CORRECTION_SHA256
    assert payload["metadata_correction_sha256"] == METADATA_CORRECTION_SHA256


def test_a205_native_reader_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a205-formula-atlas-transfer",
        "chacha20-a205-a204-exact-cnf-anchor",
        "chacha20-a205-primal-graph",
        "chacha20-a205-structural-orders",
        "chacha20-a205-bijective-reindex",
        "chacha20-a205-complete-calibration",
        "chacha20-a205-confirmed-outliers",
        "chacha20-a205-boundary-metadata-correction",
    ]
    assert len(rows) == 8
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
        [ids[6]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )
