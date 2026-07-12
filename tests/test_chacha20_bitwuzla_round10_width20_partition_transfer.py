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
    / "chacha20_bitwuzla_round10_width20_partition_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round10_width20_partition_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ROOT = Path(__file__).parents[1]
RESULTS_DIR = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = (
    ROOT / "research" / "configs" / "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width20_partition_transfer_v1.causal"

RUNNER_SHA256 = "7739cfad67ada249a31f4673c230a870d1722e41cf8138a20d4fb269ad22cd6f"
RESULT_SHA256 = "8d8fc41df65d98af3eb7a0e117b2255c07e465cc16638f67ebe7df39dcc7e107"
CAUSAL_SHA256 = "e0ed05f35b405f558797b2eb66d218cb70a0e4c9778dd9312376a05c2d2ae9a5"
CAUSAL_GRAPH_SHA256 = "552018924f0fdb83e82ed507aa6301440d1c46dba8e4ea992406905c73e80f01"
EXECUTION_PLAN_SHA256 = "533be9fdcd0700544f37e02f01767ffcaf2011f1814cc635c49043dac4d826b5"
FORMULA_PLAN_SHA256 = "7bcea5cd3ebf73c775db9d890fbfa385af216fdb171c670a65c920aef79427fc"
EXECUTION_SHA256 = "35e2646e7fe2eafb396251a8e0832820b9ac0f665bd030bc2e0eb133f6f3e550"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "93103e23f6941ea06faf3b09aa07d811e9b611e5556729734ebc71aef3178f04"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a195_frozen_protocol_runner_and_a194_anchor_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A195_solver_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A194"]["sha256"] == MODULE.A194_SHA256
    assert protocol["anchors"]["A194"]["causal_sha256"] == MODULE.A194_CAUSAL_SHA256
    assert protocol["prospective_prediction"] == {
        "claim_type": "prospective_assignment_free_complete_partition_round_depth_transfer",
        "frozen_before_solver_execution": True,
        "prediction": (
            "the_complete_thirty_two_cell_split8_partition_returns_at_least_one_fresh_round10_20bit_assignment_within_10000ms_per_cell"
        ),
        "success_rule": (
            "all_thirty_two_cells_executed_in_frozen_order_at_least_one_model_independent_512bit_confirmation_and_control_rejection"
        ),
    }
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert (
        boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    )
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A195_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["cell_order_cut_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a195_public_challenge_derivation_and_targets_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 10
    assert challenge["block_count"] == 8
    assert challenge["unknown_assignment_bits"] == 20
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_low_value_included"] is False
    assert challenge["known_key_word0_upper12"] & ((1 << 20) - 1) == 0

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
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert (
        hashlib.sha256(control.tobytes()).hexdigest() == (challenge["control_target_block_sha256"])
    )


def test_a195_split8_partition_structurally_covers_complete_2pow20_domain(
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
        "portable_SMTLIB2_round10_split8_b1_complete_5bit_prefix_partition"
    )
    assert plan["variants"] == list(MODULE.VARIANTS)
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
    assert set(range(32)) == {MODULE._prefix_value(variant) for variant in MODULE.VARIANTS}


def test_a195_complete_execution_is_a_fresh_instance_cut_transfer_boundary(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A195"
    assert payload["evidence_stage"] == ("ROUND10_WIDTH20_COMPLETE_PARTITION_BOUNDARY_RETAINED")
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
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

    comparisons = payload["comparisons"]
    assert comparisons == {
        "complete_domain_candidate_count": 1 << 20,
        "confirmed_variants": [],
        "fully_confirmed_unknown_low20_assignments": [],
        "original_domain_candidate_count": 1 << 20,
        "partition_complete_and_disjoint_by_construction": True,
        "prospective_prediction_retained": False,
        "statuses": {f"prefix_{value:05b}": "unknown" for value in range(32)},
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a195_solver_provenance_and_causal_chain_are_exact() -> None:
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
        "chacha20-a194-round9-width20-partition-recovery-anchor",
        "chacha20-a195-fresh-round10-width20-challenge",
        "chacha20-a195-complete-split8-prefix-partition",
        "chacha20-a195-complete-cell-execution",
        "chacha20-a195-independent-model-confirmation",
        "chacha20-a195-prospective-depth-transfer",
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
