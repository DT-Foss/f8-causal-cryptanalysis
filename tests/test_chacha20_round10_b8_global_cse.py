from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_b8_global_cse.py"
SPEC = importlib.util.spec_from_file_location("chacha20_round10_b8_global_cse_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "751761bdb4b583e422eb2091d24ab7268408e379f607eee4d7c89f0d2b8db063"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "4fbfc950984d3cb8eee85ba5532217cab2edae43e7ed8444ff2363259d3e990b"
CAUSAL_SHA256 = "fb2dd421e7a6ff89c668f908d6760a53a91728f2ce5881cde8188bff10522ac3"
CAUSAL_GRAPH_SHA256 = "42f702cccf79f2abf0b65fd29c6b271ab6b71c9ec3d959f16abf6da2cc947e2d"
CSE_PAYLOAD_SHA256 = "2ff7187ce177a67ed6c58326f282e074b2b5b2e64943871b58340a9de1601fe3"
EXECUTION_SHA256 = "6b8f470b34b47ddbc7a0d7358b85243e5a15bda4eb0dcb05802eea4820511e6b"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "6e17015ec51f7caacfbcc046a7bb73c2779bc7adfb7938f328b9a395b155d5f2"
PREPROCESSED_SHA256 = "532479d8427f02b6fa1304f9acc95c7f6806c53130d561fb438c5d61ef851bd9"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a202_protocol_runner_and_three_anchor_chain_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A200_A201_and_global_CSE_derivation_before_any_A202_solver_execution"
    )
    assert protocol["information_boundary"] == {
        "A202_solver_outcomes_used_before_protocol_freeze": False,
        "cell_order_budget_or_CSE_rule_changed_after_any_A202_outcome": False,
        "early_stop_permitted": False,
        "original_A198_cells_reexecuted": False,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_assignment_in_protocol_or_source": False,
    }
    assert analysis["anchor_gates"]["A198_A200_complete_partition_boundaries_zero_models"] is True
    assert analysis["anchor_gates"]["A201_shared_public_operator_structure_retained"] is True
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert analysis["solver_execution_started"] is False


def test_a202_global_hash_cons_reduces_only_exact_duplicate_expressions(
    analysis: dict[str, Any],
) -> None:
    stats = analysis["cse_stats"]
    assert stats == {
        "original_base_bytes": 177158,
        "original_base_sha256": MODULE.ORIGINAL_BASE_SHA256,
        "original_definition_count": 2560,
        "cse_base_bytes": 148714,
        "cse_base_sha256": MODULE.CSE_BASE_SHA256,
        "cse_definition_count": 2364,
        "reused_definition_occurrences": 196,
        "byte_reduction": 28444,
        "byte_reduction_fraction": 0.160557242687,
        "per_block": [
            {"block_index": 7, "new_definitions": 320, "reused_definitions": 0},
            *[
                {"block_index": block, "new_definitions": 292, "reused_definitions": 28}
                for block in range(6, -1, -1)
            ],
        ],
        "semantic_rule": (
            "reuse_only_byte_identical_expressions_after_exact_local_to_global_DAG_name_substitution"
        ),
    }
    assert MODULE._canonical_sha256(stats["per_block"]) == MODULE.CSE_STATS_SHA256
    assert stats["original_definition_count"] - stats["cse_definition_count"] == 196
    assert sum(row["reused_definitions"] for row in stats["per_block"]) == 196


def test_a202_complete_cse_prefix_cover_and_formula_plan_are_byte_stable(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(plan) == MODULE.EXECUTION_PLAN_SHA256
    assert MODULE._canonical_sha256(list(MODULE.VARIANTS)) == MODULE.VARIANT_ORDER_SHA256
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
        assert row["cse_definition_count"] == 2364
        assert row["reused_definition_occurrences"] == 196
        assert row["bytes"] == len(formula.encode()) == 148758
        assert row["sha256"] == MODULE._sha256(formula.encode())
        assert len(formula.splitlines()) == 2509
        assert sum(line.startswith("(define-fun g") for line in formula.splitlines()) == 2364
        assert sum(line.startswith("(assert") for line in formula.splitlines()) == 131
        assert formula.count("(check-sat)") == 1
        assert "(set-option :timeout " not in formula


def test_a202_all_32_cse_formulas_parse_without_solving(
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


def test_a202_original_and_cse_inputs_preprocess_to_the_same_solver_formula(
    analysis: dict[str, Any],
) -> None:
    original_analysis = MODULE._A198.analyze(RESULTS)
    original = original_analysis["formulas"]["b8_t10000_prefix_00000"]
    cse = analysis["formulas"]["cse_prefix_00000"]
    outputs = []
    for formula in (original, cse):
        result = subprocess.run(
            ["bitwuzla", "--lang", "smt2", "--pp-only", "--print-formula"],
            input=formula,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stderr == ""
        outputs.append(result.stdout)
    assert len(original.encode()) == 177202
    assert len(cse.encode()) == 148758
    assert outputs[0] == outputs[1]
    assert len(outputs[0].encode()) == 231733
    assert len(outputs[0].splitlines()) == 2927
    assert sum(line.startswith("(assert") for line in outputs[0].splitlines()) == 130
    assert sum(line.startswith("(define-fun") for line in outputs[0].splitlines()) == 0
    assert hashlib.sha256(outputs[0].encode()).hexdigest() == PREPROCESSED_SHA256


def test_a202_retained_complete_cse_execution_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A202"
    assert payload["evidence_stage"] == "ROUND10_GLOBAL_CSE_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    assert payload["cse_stats_sha256"] == CSE_PAYLOAD_SHA256
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
    assert sum(row["volatile_seconds"] for row in observations) == 320.5861444566399
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


def test_a202_retained_comparison_is_the_exact_global_cse_boundary() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    comparisons = payload["comparisons"]
    assert comparisons == {
        "original_domain_candidate_count": 1 << 20,
        "complete_domain_candidate_count": 1 << 20,
        "partition_complete_and_disjoint_by_construction": True,
        "original_A198_prefix_cover_reexecuted": False,
        "original_A198_10s_prefix_status": "all_unknown",
        "original_definition_count": 2560,
        "cse_definition_count": 2364,
        "reused_definition_occurrences": 196,
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


def test_a202_solver_identity_and_native_reader_chain_are_exact() -> None:
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
        "chacha20-a202-a198-a200-boundary",
        "chacha20-a202-a201-shared-operator-structure",
        "chacha20-a202-global-expression-hash-cons",
        "chacha20-a202-complete-cse-prefix-cover",
        "chacha20-a202-independent-model-confirmation",
        "chacha20-a202-prospective-cse-result",
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
