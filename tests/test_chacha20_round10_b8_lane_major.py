from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_b8_lane_major.py"
SPEC = importlib.util.spec_from_file_location("chacha20_round10_b8_lane_major_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "37bf927443ab16e312f841f2bfec65e51cc102edbc949dd51ab9604bdf2dc40f"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "65fb21c0aec9cfe1b599b3c2c73ed9a2e34f0640899db3b31099b3c6d1d37d35"
CAUSAL_SHA256 = "a8bfda40ac3220da210fe36847f5c71e9b2e79bed5aeac13c691d89488667c22"
CAUSAL_GRAPH_SHA256 = "7044f6294734f91991d050f5d09e21500591f5ed0d61f0261ac278dc4dee3152"
EXECUTION_SHA256 = "109765c5051fbefd4f4b01a14f07f337305f117f85291b0ccfdd6bdf164a8d36"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "309f6187993e760621b26f6f9ee835e1337a41f2840f0771055fcd41974e5532"
LANE_STATS_SHA256 = "e11363ab90e940148842912f3139bf136b6c7eb9441e58df980b2b057e50e846"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a203_protocol_runner_calibration_and_boundary_anchors_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A188_basis_calibration_and_A202_boundary_before_any_A203_solver_execution"
    )
    assert protocol["basis_calibration"]["identity_lane_major"]["status_at_A188_5000ms"] == ("sat")
    assert protocol["basis_calibration"]["adjacent_xor"]["status_at_A188_5000ms"] == "unknown"
    assert protocol["basis_calibration"]["zeta_cnot"]["status_at_A188_5000ms"] == "unknown"
    assert analysis["anchor_gates"]["A188_b8_calibration_recovery_retained"] is True
    assert analysis["anchor_gates"]["A202_preprocessor_canonicalized_CSE_boundary_retained"] is True
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert analysis["solver_execution_started"] is False


def test_a203_lane_major_reorders_only_the_same_midstate_equalities(
    analysis: dict[str, Any],
) -> None:
    assert analysis["lane_stats"] == {
        "base_bytes": 148714,
        "base_sha256": MODULE.LANE_BASE_SHA256,
        "definition_count": 2364,
        "key_constraint_count": 2,
        "midstate_equality_count": 128,
        "definition_block_order": [7, 6, 5, 4, 3, 2, 1, 0],
        "assertion_order": "lane_major_then_block_ascending_0_through_7",
        "midstate_equality_multiset_preserved": True,
    }
    preprocess = analysis["preprocess_gate"]
    assert preprocess["same_preprocessed_size"] is True
    assert preprocess["distinct_preprocessed_formula"] is True
    assert preprocess["rows"] == [
        {
            "label": "baseline",
            "input_bytes": 148758,
            "preprocessed_bytes": 231733,
            "preprocessed_lines": 2927,
            "preprocessed_sha256": MODULE.BASELINE_PREPROCESSED_SHA256,
        },
        {
            "label": "lane_major",
            "input_bytes": 148758,
            "preprocessed_bytes": 231733,
            "preprocessed_lines": 2927,
            "preprocessed_sha256": MODULE.LANE_PREPROCESSED_SHA256,
        },
    ]


def test_a203_complete_lane_major_cover_and_formula_plan_are_byte_stable(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._canonical_sha256(analysis["execution_plan"]) == MODULE.EXECUTION_PLAN_SHA256
    assert MODULE._canonical_sha256(list(MODULE.VARIANTS)) == MODULE.VARIANT_ORDER_SHA256
    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(formula_plan) == MODULE.FORMULA_PLAN_SHA256
    assert MODULE._canonical_sha256([row["sha256"] for row in formula_plan]) == (
        MODULE.FORMULA_HASH_LIST_SHA256
    )
    assert len(formula_plan) == 32
    assert [row["prefix"] for row in formula_plan] == list(MODULE.PREFIXES)
    assert sum(row["candidate_count"] for row in formula_plan) == 1 << 20
    for row in formula_plan:
        formula = analysis["formulas"][row["variant"]]
        assert row["candidate_count"] == 1 << 15
        assert row["definition_count"] == 2364
        assert row["output_equality_count"] == 128
        assert row["bytes"] == len(formula.encode()) == 148758
        assert row["sha256"] == MODULE._sha256(formula.encode())
        assert len(formula.splitlines()) == 2509
        assert sum(line.startswith("(define-fun g") for line in formula.splitlines()) == 2364
        assert sum(line.startswith("(assert") for line in formula.splitlines()) == 131
        assert formula.count("(check-sat)") == 1
        assert "(set-option :timeout " not in formula


def test_a203_all_lane_major_formulas_parse_without_solving(
    analysis: dict[str, Any],
) -> None:
    for variant in MODULE.VARIANTS:
        result = subprocess.run(
            ["bitwuzla", "--lang", "smt2", "--parse-only"],
            input=analysis["formulas"][variant],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout == ""
        assert result.stderr == ""


def test_a203_retained_complete_lane_major_execution_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A203"
    assert payload["evidence_stage"] == "ROUND10_LANE_MAJOR_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    assert payload["lane_stats_sha256"] == LANE_STATS_SHA256
    assert payload["execution_plan_sha256"] == MODULE.EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == MODULE.FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    waves = execution["wave_observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["status"] for row in observations] == ["unknown"] * 32
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["model"] is None for row in observations)
    assert len(waves) == 8
    for wave_index, wave in enumerate(waves):
        group = observations[wave_index * 4 : wave_index * 4 + 4]
        assert wave["wave_index"] == wave_index
        assert wave["variants"] == [row["variant"] for row in group]
        assert wave["statuses"] == ["unknown"] * 4
        assert wave["maximum_volatile_seconds"] == max(row["volatile_seconds"] for row in group)
    assert sum(row["volatile_seconds"] for row in observations) == 320.58543653879315
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low20_assignments"] == []
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a203_retained_comparison_is_the_exact_lane_order_boundary() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    comparisons = payload["comparisons"]
    assert comparisons == {
        "original_domain_candidate_count": 1 << 20,
        "complete_domain_candidate_count": 1 << 20,
        "partition_complete_and_disjoint_by_construction": True,
        "A202_baseline_reexecuted": False,
        "A202_block_major_10s_status": "all_unknown",
        "same_128_midstate_equality_multiset": True,
        "distinct_preprocessed_formula": True,
        "status_counts": {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0},
        "resolved_sat_plus_unsat_cell_count": 0,
        "confirmed_variants": [],
        "fully_confirmed_unknown_low20_assignments": [],
        "primary_prediction_retained": False,
        "secondary_prediction_retained": False,
        "statuses": {variant: "unknown" for variant in MODULE.VARIANTS},
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a203_solver_identity_and_native_reader_chain_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert payload["solver_identity"] == {
        "executable_sha256": "9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a",
        "mode": "bitblast",
        "path": "/opt/homebrew/bin/bitwuzla",
        "sat_backend": "cadical",
        "version": "0.9.1",
    }
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a203-a188-calibration",
        "chacha20-a203-a202-canonicalization-boundary",
        "chacha20-a203-lane-major-equality-order",
        "chacha20-a203-complete-lane-prefix-cover",
        "chacha20-a203-independent-confirmation",
        "chacha20-a203-prospective-lane-result",
    ]
    assert len(rows) == 6
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )
