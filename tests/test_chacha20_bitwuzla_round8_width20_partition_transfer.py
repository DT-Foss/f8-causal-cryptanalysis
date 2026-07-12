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
    / "chacha20_bitwuzla_round8_width20_partition_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round8_width20_partition_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ROOT = Path(__file__).parents[1]
RESULTS_DIR = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = (
    ROOT
    / "research"
    / "configs"
    / "chacha20_bitwuzla_round8_width20_partition_transfer_v1.json"
)
RESULT_PATH = (
    RESULTS_DIR / "chacha20_bitwuzla_round8_width20_partition_transfer_v1.json"
)
CAUSAL_PATH = (
    RESULTS_DIR / "chacha20_bitwuzla_round8_width20_partition_transfer_v1.causal"
)

RUNNER_SHA256 = "081975613398a08e998559840bf93dfb3c56b42317f00f1061177fee0bdba636"
RESULT_SHA256 = "b4d146be64030e08ca6e7ce2e626acfa52ba8a4e6003ec5e605760b295053fae"
CAUSAL_SHA256 = "b8e6dfb148e1250c073b244ba6cecc23ecbe0c477c8021d0a2491af708c4971e"
CAUSAL_GRAPH_SHA256 = (
    "b97bed32cfac5d1313f1b0ed600edc3a66a67a38b521891da97792c2d1133274"
)
EXECUTION_PLAN_SHA256 = (
    "33ba0ca665a86e4740d438cf7f92b6b65701a6b07b0c633275b78d4dfff6cb11"
)
FORMULA_PLAN_SHA256 = (
    "a4eb18ce062378a43ad6260e1ce4c0ae2a5f8bf44aaac2ef7bcb233f852c9a98"
)
EXECUTION_SHA256 = "c3a44f6d5e45440e8a307e45dc14e4e9ae8833790751d6a22ff4abb6834c66b1"
CONFIRMATION_SHA256 = (
    "4baba285d9c0e8b85ba395360d4a0d93d28249e9093b92682ecd191ff1442641"
)
COMPARISON_SHA256 = (
    "298f63ff4fc97459bf6513315d446d34c2feec4489a833505660ad4b59bd6188"
)

RECOVERED_LOW20 = 369_674
RECOVERED_WORD0 = 681_944_074
RECOVERED_WORD1_LOW = 117
RECOVERED_COMBINED = 503_193_117_706
RECOVERED_MODEL = {
    "combined_assignment": RECOVERED_COMBINED,
    "key_word0": RECOVERED_WORD0,
    "key_word1_low_value": RECOVERED_WORD1_LOW,
    "recovered_unknown_low20": RECOVERED_LOW20,
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a193_frozen_protocol_runner_and_a192_depth_anchor_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A193_solver_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A192"]["sha256"] == MODULE.A192_SHA256
    assert protocol["anchors"]["A192"]["causal_sha256"] == MODULE.A192_CAUSAL_SHA256
    assert protocol["prospective_prediction"] == {
        "claim_type": "prospective_assignment_free_complete_partition_round_depth_transfer",
        "frozen_before_solver_execution": True,
        "prediction": (
            "the_complete_thirty_two_cell_split7_partition_returns_at_least_one_fresh_round8_20bit_assignment_within_10000ms_per_cell"
        ),
        "success_rule": (
            "all_thirty_two_cells_executed_in_frozen_order_at_least_one_model_independent_512bit_confirmation_and_control_rejection"
        ),
    }
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A193_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["cell_order_cut_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a193_public_challenge_derivation_and_literal_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 8
    assert challenge["block_count"] == 8
    assert challenge["unknown_assignment_bits"] == 20
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_low_value_included"] is False
    assert challenge["known_key_word0_upper12"] & ((1 << 20) - 1) == 0

    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "f94269fc107ae1acdeb9688b860fcaeebe01f093ea4c856cfede4296f9e8dbfd"
    )
    assert int(words[0]) & ~MODULE.LOW_MASK == challenge["known_key_word0_upper12"]
    assert int(words[1]) == challenge["known_key_word1"]
    assert [int(value) for value in words[2:8]] == challenge[
        "known_key_words_2_through_7"
    ]
    assert int(words[8]) == challenge["counter_start"]
    assert [int(value) for value in words[9:12]] == challenge["nonce_words"]
    for target, expected in zip(
        challenge["target_words"], challenge["target_block_sha256"], strict=True
    ):
        assert hashlib.sha256(np.array(target, dtype="<u4").tobytes()).hexdigest() == expected
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert hashlib.sha256(control.tobytes()).hexdigest() == (
        challenge["control_target_block_sha256"]
    )

    spellings = (
        str(RECOVERED_LOW20),
        str(RECOVERED_WORD0),
        str(RECOVERED_COMBINED),
        "5a40a",
        "28a5a40a",
        "7528a5a40a",
    )
    for path in (PROTOCOL_PATH, MODULE_PATH):
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in spellings)


def test_a193_split7_partition_structurally_covers_complete_2pow20_domain(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 8
    assert plan["unknown_key_bits"] == 20
    assert plan["known_key_bits"] == 236
    assert plan["partition_cell_count"] == 32
    assert plan["partition_cell_free_bits"] == 15
    assert plan["partition_fixed_bits"] == 5
    assert plan["partition_prefix_order"] == [f"{value:05b}" for value in range(32)]
    assert plan["formula_representation"] == (
        "portable_SMTLIB2_round8_split7_b1_complete_5bit_prefix_partition"
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
    assert [row["prefix"] for row in formula_plan] == [
        f"{value:05b}" for value in range(32)
    ]
    for index, row in enumerate(formula_plan):
        variant = MODULE.VARIANTS[index]
        formula = analysis["formulas"][variant]
        assert row["variant"] == variant
        assert row["candidate_count"] == 1 << 15
        assert row["fixed_key_coordinates"] == [19, 18, 17, 16, 15]
        assert row["free_key_coordinates"] == list(reversed(range(15)))
        assert row["portable_smtlib2"] is True
        assert len(formula.encode()) == row["bytes"] == 18_829
        assert hashlib.sha256(formula.encode()).hexdigest() == row["sha256"]
        assert formula.count("(check-sat)") == 1
        assert f"(assert (= ((_ extract 19 15) k0) #b{index:05b}))" in formula
        assert "(assert (= lo8 #x75))" in formula
        assert "(assert (= ((_ extract 31 20) k0) #x28a))" in formula
    assert set(range(32)) == {
        MODULE._prefix_value(variant) for variant in MODULE.VARIANTS
    }


def test_a193_complete_execution_retains_recovery_but_not_uniqueness_adjudication(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A193"
    assert payload["evidence_stage"] == (
        "PROSPECTIVE_ROUND8_WIDTH20_COMPLETE_PARTITION_RECOVERY_RETAINED"
    )
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["prefix"] for row in observations] == [
        f"{value:05b}" for value in range(32)
    ]
    statuses = [row["status"] for row in observations]
    assert statuses == ["unknown"] * 11 + ["sat"] + ["unknown"] * 20
    assert "unsat" not in statuses
    assert statuses.count("unknown") == 31
    assert all(row["candidate_count"] == 1 << 15 for row in observations)
    assert all(row["free_bits"] == 15 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert observations[11]["model"] == RECOVERED_MODEL
    assert all(row["model"] is None for index, row in enumerate(observations) if index != 11)
    assert RECOVERED_LOW20 >> 15 == 0b01011
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 1
    assert execution["fully_confirmed_unknown_assignment_count"] == 1
    assert execution["fully_confirmed_unknown_low20_assignments"] == [RECOVERED_LOW20]
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons["complete_domain_candidate_count"] == 1 << 20
    assert comparisons["original_domain_candidate_count"] == 1 << 20
    assert comparisons["partition_complete_and_disjoint_by_construction"] is True
    assert comparisons["confirmed_variants"] == ["prefix_01011"]
    assert comparisons["fully_confirmed_unknown_low20_assignments"] == [
        RECOVERED_LOW20
    ]
    assert comparisons["prospective_prediction_retained"] is True
    assert list(comparisons["statuses"].values()).count("unknown") == 31
    assert list(comparisons["statuses"].values()).count("sat") == 1
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a193_model_has_independent_512_bit_confirmation_and_rejects_control(
    analysis: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    expected = {
        "variant": "prefix_01011",
        "prefix": "01011",
        **MODULE._confirm_model(analysis["public_challenge"], RECOVERED_MODEL),
    }
    assert payload["confirmations"] == [expected]
    assert expected["known_key_constraints_match"] is True
    assert expected["block_count_checked"] == 1
    assert expected["block_matches"] == [True]
    assert expected["all_blocks_match"] is True
    assert expected["output_bits_checked"] == 512
    assert expected["candidate_block_sha256"] == [
        analysis["public_challenge"]["target_block_sha256"][0]
    ]
    assert expected["control_first_block_match"] is False
    assert format(RECOVERED_LOW20, "05x") == "5a40a"
    assert format(RECOVERED_WORD0, "08x") == "28a5a40a"
    assert format(RECOVERED_COMBINED, "010x") == "7528a5a40a"
    assert MODULE._canonical_sha256([expected]) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a193_solver_provenance_and_causal_chain_are_exact() -> None:
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
        "chacha20-a192-round7-width20-partition-recovery-anchor",
        "chacha20-a193-fresh-round8-width20-challenge",
        "chacha20-a193-complete-split7-prefix-partition",
        "chacha20-a193-complete-cell-execution",
        "chacha20-a193-independent-model-confirmation",
        "chacha20-a193-prospective-depth-transfer",
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
