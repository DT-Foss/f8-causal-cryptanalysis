from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = (
    ROOT / "research" / "experiments" / "chacha20_bitwuzla_round10_b8_partition_transfer.py"
)
SPEC = importlib.util.spec_from_file_location("chacha20_round10_b8_a198", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
RESULTS = ROOT / "research" / "results" / "v1"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME

RUNNER_SHA256 = "0409dacb97274a062be93a53b1b8c0eba8f28ba95fae9460daa82b0efee73847"
RESULT_SHA256 = "693367464ab488c49d386c1d011e8c45e7fb094cceeb37352934dde121773373"
CAUSAL_SHA256 = "b7c4e1302594e266c7958057221fb4101fb5ef5ee284792d6ca93e43386dd514"
CAUSAL_GRAPH_SHA256 = "3895d60a4020f72b60630544ae88bcbaf9e659986eb2f28999291eb7350e2ba9"
FORMULA_PLAN_SHA256 = "24373bd8cb5fbd76f3fa88c028b44827ff6167511f59e1565ec53f0276295040"
EXECUTION_SHA256 = "120d8d220d916c4bacbd32ce387752cbb45ecc68d00434f3681675d31e185745"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "a420ddf3d23e9b4ce6d56186261a679229f740bf9d33978471dfda9d5148cbda"


def _analysis() -> dict:
    return MODULE.analyze(RESULTS)


def test_frozen_protocol_and_anchor_chain() -> None:
    analysis = _analysis()
    assert (
        MODULE._file_sha256(ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME)
        == MODULE.PROTOCOL_SHA256
    )
    assert MODULE._canonical_sha256(analysis["execution_plan"]) == MODULE.EXECUTION_PLAN_SHA256
    assert MODULE._canonical_sha256(list(MODULE.VARIANTS)) == MODULE.VARIANT_ORDER_SHA256
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert analysis["anchor_gates"]["mechanism_and_boundary_anchors_retained"] is True
    assert analysis["anchor_gates"]["formula_atlas_reaudit_sha256"] == MODULE.ATLAS_AUDIT_SHA256


def test_two_complete_disjoint_domain_covers() -> None:
    plan = _analysis()["formula_plan"]
    assert len(plan) == 64
    for budget in MODULE.BUDGETS_MS:
        rows = [row for row in plan if row["budget_milliseconds"] == budget]
        assert len(rows) == 32
        assert [row["prefix"] for row in rows] == list(MODULE.PREFIXES)
        assert sum(row["candidate_count"] for row in rows) == 1 << 20
        assert {tuple(row["fixed_key_coordinates"]) for row in rows} == {(19, 18, 17, 16, 15)}
        assert {tuple(row["free_key_coordinates"]) for row in rows} == {tuple(reversed(range(15)))}
    assert [row["sha256"] for row in plan[:32]] == [row["sha256"] for row in plan[32:]]
    assert [row["bytes"] for row in plan[:32]] == [row["bytes"] for row in plan[32:]]


def test_each_formula_is_full_b8_and_budget_invariant() -> None:
    analysis = _analysis()
    first = analysis["formulas"]["b8_t10000_prefix_00000"]
    second = analysis["formulas"]["b8_t30000_prefix_00000"]
    assert first == second
    lines = first.splitlines()
    assert len(lines) == 2_705
    assert sum(line.startswith("(define-fun b") for line in lines) == 2_560
    assert sum(line.startswith("(assert") for line in lines) == 131
    assert first.count("(check-sat)") == 1
    assert first.count("((_ extract 19 15) k0)") == 1
    for block_index in range(8):
        assert first.count(f"(define-fun b{block_index}_") == 320
    assert "(set-option :timeout " not in first


def test_analyze_only_plan_is_byte_stable() -> None:
    analysis = _analysis()
    expected = json.loads((ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME).read_bytes())
    assert expected["execution_plan_sha256"] == MODULE._canonical_sha256(analysis["execution_plan"])
    assert MODULE._canonical_sha256(analysis["formula_plan"]) == (
        "24373bd8cb5fbd76f3fa88c028b44827ff6167511f59e1565ec53f0276295040"
    )
    assert analysis["solver_execution_started"] is False


def test_a198_retained_result_and_complete_execution_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A198"
    assert payload["evidence_stage"] == "ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    assert payload["execution_plan_sha256"] == MODULE.EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    waves = execution["wave_observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert len(observations) == 64
    assert len(waves) == 16
    assert [row["status"] for row in observations] == ["unknown"] * 64
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["model"] is None for row in observations)
    assert all(row["candidate_count"] == 1 << 15 for row in observations)
    assert all(row["shared_key_block_count"] == 8 for row in observations)
    assert all(row["target_output_bits"] == 4096 for row in observations)
    for wave_index, wave in enumerate(waves):
        group = observations[wave_index * 4 : wave_index * 4 + 4]
        assert wave["wave_index"] == wave_index
        assert wave["variants"] == [row["variant"] for row in group]
        assert wave["statuses"] == ["unknown"] * 4
        assert wave["maximum_volatile_seconds"] == max(row["volatile_seconds"] for row in group)
    assert sum(row["volatile_seconds"] for row in observations) == 1281.069384752307
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low20_assignments"] == []
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a198_two_budget_boundary_comparison_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    observations = payload["execution"]["observations"]
    comparisons = payload["comparisons"]
    assert comparisons["original_domain_candidate_count"] == 1 << 20
    assert comparisons["complete_domain_covered_once_per_budget"] is True
    assert comparisons["partition_complete_and_disjoint_by_construction"] is True
    assert comparisons["same_formula_bytes_across_budgets"] is True
    assert comparisons["shared_key_block_count"] == 8
    assert comparisons["target_output_bits_per_cell"] == 4096
    assert comparisons["fully_confirmed_unknown_low20_assignments"] == []
    assert comparisons["primary_30000ms_prediction_retained"] is False
    assert comparisons["secondary_10000ms_prediction_retained"] is False
    for offset, budget in enumerate(MODULE.BUDGETS_MS):
        rows = observations[offset * 32 : (offset + 1) * 32]
        result = comparisons["budget_results"][str(budget)]
        assert [row["budget_milliseconds"] for row in rows] == [budget] * 32
        assert result["complete_domain_candidate_count"] == 1 << 20
        assert result["complete_partition_executed"] is True
        assert result["confirmed_variants"] == []
        assert result["fully_confirmed_unknown_low20_assignments"] == []
        assert result["prediction_retained"] is False
        assert result["statuses"] == {
            variant: "unknown" for variant in MODULE.VARIANTS[offset * 32 : (offset + 1) * 32]
        }
    assert [row["formula_sha256"] for row in observations[:32]] == [
        row["formula_sha256"] for row in observations[32:]
    ]
    assert [row["formula_bytes"] for row in observations[:32]] == [
        row["formula_bytes"] for row in observations[32:]
    ]
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a198_solver_identity_and_causal_reader_chain_are_exact() -> None:
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
    ids = [
        "chacha20-a198-a187-a188-stacking-mechanism",
        "chacha20-a198-a197-round10-refinement-boundary",
        "chacha20-a198-still-secret-round10-challenge",
        "chacha20-a198-b8-two-budget-complete-partitions",
        "chacha20-a198-complete-wave-execution",
        "chacha20-a198-independent-eight-block-confirmation",
        "chacha20-a198-prospective-depth-transfer",
    ]
    by_id = {row["edge_id"]: row for row in rows}
    assert len(rows) == 7
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[1:-1], ids[2:], strict=True)
    )
