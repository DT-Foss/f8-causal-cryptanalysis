from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "chacha20_bitwuzla_round10_split9_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round10_split9_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ROOT = Path(__file__).parents[1]
RESULTS_DIR = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / "chacha20_bitwuzla_round10_split9_transfer_v1.json"
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_split9_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_split9_transfer_v1.causal"
A195_RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"

RUNNER_SHA256 = "a8378c8c768c90d66234d68922d55cff5775d3779034754504e3172badacbf95"
RESULT_SHA256 = "722a2e0d6c697d47189f157b9878d723dc05e264f328c2386ef9189458b33eaa"
CAUSAL_SHA256 = "959467bf76271f8fec6d738cd698ccfc51e1c8eb10275455150dd33a2e9bbd5d"
CAUSAL_GRAPH_SHA256 = "9d1909f592c522e0841ff0d9bb79c14011213e7e69715ccab302e9225899eb54"
A195_CAUSAL_GRAPH_SHA256 = "552018924f0fdb83e82ed507aa6301440d1c46dba8e4ea992406905c73e80f01"
EXECUTION_PLAN_SHA256 = "10f4afe1a653f71c4306320615921b3ec831caed3cf118bae2ba5e845d5d4e72"
FORMULA_PLAN_SHA256 = "f86439777fea0ec534d98b2ea7013ec101fcb557c5b9fd70a2f2432534023347"
EXECUTION_SHA256 = "9cb9dfeeb6d1ae7db402e2d2bb29df84b98fea18dacb8b9d71dc9e794cd4face"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "93103e23f6941ea06faf3b09aa07d811e9b611e5556729734ebc71aef3178f04"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a196_frozen_protocol_runner_and_a195_anchor_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_complete_A195_boundary_before_any_A196_solver_execution"
    )
    assert protocol["anchors"]["A195"] == {
        "artifact": "research/results/v1/chacha20_bitwuzla_round10_width20_partition_transfer_v1.json",
        "sha256": MODULE.A195_SHA256,
        "causal_artifact": "research/results/v1/chacha20_bitwuzla_round10_width20_partition_transfer_v1.causal",
        "causal_sha256": MODULE.A195_CAUSAL_SHA256,
        "causal_graph_sha256": A195_CAUSAL_GRAPH_SHA256,
        "rounds": 10,
        "unknown_key_bits": 20,
        "cut": "split8",
        "partition_cells": 32,
        "complete_variant_plan": True,
        "returned_model_count": 0,
        "all_cell_statuses": "unknown",
    }
    assert analysis["anchor_gates"] == {
        "A195_result_sha256": MODULE.A195_SHA256,
        "A195_causal_sha256": MODULE.A195_CAUSAL_SHA256,
        "A195_causal_graph_sha256": A195_CAUSAL_GRAPH_SHA256,
        "A195_causal_provenance_verified": True,
        "A195_complete_split8_boundary_retained": True,
    }
    boundary = protocol["information_boundary"]
    assert boundary == {
        "A195_solver_outcomes_used_only_to_select_the_predeclared_alternative_cut": True,
        "A195_revealed_no_model_or_correct_prefix": True,
        "unknown_assignment_in_protocol_or_source": False,
        "unknown_assignment_available_to_runner_before_execution": False,
        "A196_solver_outcomes_used_before_protocol_freeze": False,
        "cell_order_cut_or_budget_changed_after_any_A196_outcome": False,
        "early_stop_permitted": False,
    }
    reuse = protocol["challenge_reuse_boundary"]
    assert reuse["public_challenge_reused_byte_for_byte_from_A195"] is True
    assert reuse["unknown_assignment_recovered_during_A195"] is False
    assert reuse["correct_prefix_known_before_A196_execution"] is False
    assert reuse["A195_returned_model_count"] == 0
    assert analysis["solver_execution_started"] is False


def test_a196_reuses_the_exact_still_secret_a195_public_challenge(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    a195 = json.loads(A195_RESULT_PATH.read_bytes())
    assert challenge == a195["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 10
    assert challenge["block_count"] == 8
    assert challenge["unknown_assignment_bits"] == 20
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_low_value_included"] is False

    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "40044d942ad2dc135f1228bde509731f9d1416f0c1a9bb38de851db1f95af53d"
    )
    assert int(words[0]) & ~MODULE.LOW_MASK == challenge["known_key_word0_upper12"]
    assert int(words[1]) == challenge["known_key_word1"]
    assert [int(value) for value in words[2:8]] == challenge["known_key_words_2_through_7"]
    assert int(words[8]) == challenge["counter_start"]
    assert [int(value) for value in words[9:12]] == challenge["nonce_words"]
    for target, expected in zip(
        challenge["target_words"], challenge["target_block_sha256"], strict=True
    ):
        assert hashlib.sha256(np.array(target, dtype="<u4").tobytes()).hexdigest() == expected
    assert (
        hashlib.sha256(
            np.array(challenge["control_target_words"], dtype="<u4").tobytes()
        ).hexdigest()
        == "371b6b0aac44efe9552551ac05246b4334e42bb87e9deee0bc9ccbb3e4c1b669"
    )


def test_a196_split9_partition_structurally_covers_complete_2pow20_domain(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 10
    assert plan["unknown_key_bits"] == 20
    assert plan["known_key_bits"] == 236
    assert plan["partition_cell_count"] == 32
    assert plan["partition_cell_free_bits"] == 15
    assert plan["partition_fixed_bits"] == 5
    assert plan["partition_prefix_order"] == [f"{value:05b}" for value in range(32)]
    assert plan["formula_representation"] == (
        "portable_SMTLIB2_round10_split9_b1_complete_5bit_prefix_partition"
    )
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    retained = json.loads(RESULT_PATH.read_bytes())["formula_plan"]
    formula_plan = analysis["formula_plan"]
    assert formula_plan == retained
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert len(formula_plan) == 32
    assert sum(row["candidate_count"] for row in formula_plan) == 1 << 20
    assert [row["prefix"] for row in formula_plan] == [f"{value:05b}" for value in range(32)]
    for index, row in enumerate(formula_plan):
        variant = MODULE.VARIANTS[index]
        formula = analysis["formulas"][variant]
        assert row["variant"] == variant
        assert row["candidate_count"] == 1 << 15
        assert row["fixed_key_coordinates"] == [19, 18, 17, 16, 15]
        assert row["free_key_coordinates"] == list(reversed(range(15)))
        assert row["portable_smtlib2"] is True
        assert len(formula.encode()) == row["bytes"] == 23_069
        assert hashlib.sha256(formula.encode()).hexdigest() == row["sha256"]
        assert formula.count("(check-sat)") == 1
        assert f"(assert (= ((_ extract 19 15) k0) #b{index:05b}))" in formula
        assert "(assert (= lo8 #xab))" in formula
        assert "(assert (= ((_ extract 31 20) k0) #xcb3))" in formula


def test_a196_and_a195_are_status_equivalent_complete_cut_boundaries(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    a195 = json.loads(A195_RESULT_PATH.read_bytes())
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A196"
    assert payload["evidence_stage"] == "ROUND10_SPLIT9_CUT_BOUNDARY_RETAINED"
    assert payload["public_challenge"] == a195["public_challenge"]
    assert payload["public_challenge_sha256"] == a195["public_challenge_sha256"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["prefix"] for row in observations] == [f"{value:05b}" for value in range(32)]
    assert [row["status"] for row in observations] == ["unknown"] * 32
    assert all(row["candidate_count"] == 1 << 15 for row in observations)
    assert all(row["free_bits"] == 15 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["model"] is None for row in observations)
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low20_assignments"] == []
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    assert payload["comparisons"] == a195["comparisons"]
    assert MODULE._canonical_sha256(payload["comparisons"]) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256
    assert payload["comparisons"]["prospective_prediction_retained"] is False
    assert payload["comparisons"]["partition_complete_and_disjoint_by_construction"] is True


def test_a196_solver_provenance_and_causal_chain_are_exact() -> None:
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
        "chacha20-a195-round10-split8-boundary-anchor",
        "chacha20-a196-still-secret-round10-challenge",
        "chacha20-a196-complete-split9-prefix-partition",
        "chacha20-a196-complete-cell-execution",
        "chacha20-a196-independent-model-confirmation",
        "chacha20-a196-prospective-cut-transfer",
    ]
    by_id = {row["edge_id"]: row for row in rows}
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
