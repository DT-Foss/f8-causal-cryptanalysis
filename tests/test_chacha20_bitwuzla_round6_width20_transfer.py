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
    / "chacha20_bitwuzla_round6_width20_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round6_width20_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
PROTOCOL_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "configs"
    / "chacha20_bitwuzla_round6_width20_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round6_width20_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round6_width20_transfer_v1.causal"

RUNNER_SHA256 = "8636ad0aa9fff62a7ee6bfa31d3d40fa6ba0244db3ce4f792884a83f13bad8c6"
PUBLIC_CHALLENGE_SHA256 = (
    "c9a75c6f80b07baa31768146a6b5f3549723da56d8bd16b07d74d255dac19d39"
)
RESULT_SHA256 = "e57294c1aabf29f2e8fff87b9b06f0ed1ab0d8392cc9ea79f4f97745904e6b70"
CAUSAL_SHA256 = "bebcd7805592cd28805e7226c1efa216696544539605693dc197b88a70e44a37"
CAUSAL_GRAPH_SHA256 = (
    "1a5cd713921ecbfd79bc649a1f4bd30aaad440074bb88374a7ce28c68581ffc9"
)
EXECUTION_PLAN_SHA256 = (
    "3aeba8db2d59e89def52b9104348800f82973a86d0f538bf7fbb6a5e482e51d7"
)
FORMULA_PLAN_SHA256 = (
    "8471323ecb3da7ea4149504383b7d2d16641e705a425c7b945f5bd7af479f798"
)
EXECUTION_SHA256 = "a2d5780c5850288c635169281831f97d8c136e38d600365fb8c320ebc1f6d8b1"
CONFIRMATION_SHA256 = (
    "ee89fcf1cb3ac46b62834af579b3306faff594fff879d47537e9a1a15dfccabd"
)
COMPARISON_SHA256 = (
    "78515deb3ff87577a169b4ce508a8049e3ec36c40b46b1743b33d285f9b83928"
)

RECOVERED_LOW20 = 457_328
RECOVERED_WORD0 = 3_522_624_112
RECOVERED_WORD1_LOW = 30
RECOVERED_COMBINED = 132_371_642_992
RECOVERED_MODEL = {
    "combined_assignment": RECOVERED_COMBINED,
    "key_word0": RECOVERED_WORD0,
    "key_word1_low_value": RECOVERED_WORD1_LOW,
    "recovered_unknown_low20": RECOVERED_LOW20,
}

VARIANTS = [
    "bitwuzla_bitblast_b1",
    "bitwuzla_bitblast_b2",
    "bitwuzla_bitblast_b4",
    "bitwuzla_bitblast_b8",
    "bitwuzla_preprop_b8",
    "bitwuzla_prop_b8",
    "z3_bitblast_b8",
    "boolector_fun_b8",
]
STATUSES = ["sat", "unknown", "unknown", "sat", "sat", "unknown", "invalid", "unknown"]
FORMULA_IDENTITY = {
    "bitwuzla_bitblast_b1": (14_545, "df68f35bf6ede07faf8f40ce391dcf637e66d1579850dda54a12f109561a5699"),
    "bitwuzla_bitblast_b2": (28_084, "dfe2584c25cef0ad4f68f9eafc149d1c8e44497b49ff0c3c57019a142868f085"),
    "bitwuzla_bitblast_b4": (55_162, "b158737bb1cad45dbd5cc2fac1f9aa54cee156c7ba8b27bdc2efa12d3b7c8dec"),
    "bitwuzla_bitblast_b8": (109_318, "bf097bac9b8f7b51e1b305ed3f00fe23730c52abf7473b58f65990141bbcb9fb"),
    "bitwuzla_preprop_b8": (109_318, "bf097bac9b8f7b51e1b305ed3f00fe23730c52abf7473b58f65990141bbcb9fb"),
    "bitwuzla_prop_b8": (109_318, "bf097bac9b8f7b51e1b305ed3f00fe23730c52abf7473b58f65990141bbcb9fb"),
    "z3_bitblast_b8": (109_318, "bf097bac9b8f7b51e1b305ed3f00fe23730c52abf7473b58f65990141bbcb9fb"),
    "boolector_fun_b8": (109_318, "bf097bac9b8f7b51e1b305ed3f00fe23730c52abf7473b58f65990141bbcb9fb"),
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a189_protocol_freshness_anchor_and_prediction_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A189_solver_execution"
    assert protocol["public_challenge_sha256"] == PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A188"]["sha256"] == MODULE.A188_SHA256
    assert protocol["anchors"]["A188"]["causal_sha256"] == MODULE.A188_CAUSAL_SHA256
    prediction = protocol["prospective_prediction"]
    assert prediction["claim_type"] == (
        "prospective_round6_depth_width_partial_key_recovery_transfer"
    )
    assert prediction["prediction"] == (
        "Bitwuzla_bitblast_cadical_b8_returns_the_fresh_round6_20_bit_assignment_within_30000ms"
    )
    assert prediction["frozen_before_solver_execution"] is True
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A189_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a189_public_challenge_derivation_and_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 6
    assert challenge["block_count"] == 8
    assert challenge["counter_schedule"] == "base_plus_block_index_mod_2^32"
    assert challenge["unknown_assignment_bits"] == 20
    assert challenge["unknown_key_word0_low_bits"] == 20
    assert challenge["unknown_key_word0_low_value_included"] is False
    assert challenge["known_key_word0_upper12"] & 0x000FFFFF == 0

    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "b33cf231cc7ea6c9f6b26f2af3c38fc4d5bda4f570d11bc6c3fc31781d27722a"
    )
    assert int(words[0]) & 0xFFF00000 == challenge["known_key_word0_upper12"]
    assert int(words[1]) == challenge["known_key_word1"]
    assert [int(value) for value in words[2:8]] == challenge["known_key_words_2_through_7"]
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
    assert challenge["control_target_words"][0] == challenge["target_words"][0][0] ^ 1
    assert challenge["control_target_words"][1:] == challenge["target_words"][0][1:]

    secret_spellings = (
        str(RECOVERED_LOW20),
        str(RECOVERED_WORD0),
        str(RECOVERED_COMBINED),
        "6fa70",
        "d1f6fa70",
        "1ed1f6fa70",
    )
    for path in (PROTOCOL_PATH, MODULE_PATH):
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in secret_spellings)


def test_a189_reconstructs_all_eight_portable_formulas_without_engines(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 6
    assert plan["unknown_key_bits"] == 20
    assert plan["known_key_bits"] == 236
    assert plan["variants"] == VARIANTS
    assert plan["variant_execution_order"] == VARIANTS
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert [row["variant"] for row in formula_plan] == VARIANTS
    for row in formula_plan:
        formula = analysis["formulas"][row["variant"]]
        expected_bytes, expected_sha = FORMULA_IDENTITY[row["variant"]]
        assert len(formula.encode()) == expected_bytes == row["bytes"]
        assert hashlib.sha256(formula.encode()).hexdigest() == expected_sha == row["sha256"]
        assert row["logical_unknown_key_bits"] == 20
        assert row["portable_smtlib2"] is True
        assert formula.count("(check-sat)") == 1
        assert formula.endswith("(check-sat)\n(get-value (k0 lo8))\n")
        assert "(set-option :timeout" not in formula
        assert "(assert (= lo8 #x1e))" in formula
        assert "(assert (= ((_ extract 31 20) k0) #xd1f))" in formula
        lowered = formula.lower()
        assert "6fa70" not in lowered
        assert "d1f6fa70" not in lowered


def test_a189_complete_execution_models_and_z3_parser_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A189"
    assert payload["evidence_stage"] == (
        "PROSPECTIVE_BITWUZLA_ROUND6_20BIT_RECOVERY_TRANSFER_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A188_result_sha256"] == MODULE.A188_SHA256
    assert payload["anchor_gates"]["A188_causal_sha256"] == MODULE.A188_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == VARIANTS
    assert [row["variant"] for row in observations] == VARIANTS
    assert [row["status"] for row in observations] == STATUSES
    assert all(row["externally_timed_out"] is False for row in observations)
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 3
    assert execution["fully_confirmed_unknown_assignment_count"] == 1
    assert execution["fully_confirmed_unknown_low20_assignments"] == [RECOVERED_LOW20]
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == payload["execution_sha256"] == EXECUTION_SHA256

    for index in (0, 3, 4):
        assert observations[index]["model"] == RECOVERED_MODEL
        assert observations[index]["status"] == "sat"
    assert observations[0]["volatile_seconds"] == 3.0447999159805477
    assert observations[3]["volatile_seconds"] == 19.674508791882545
    assert observations[4]["volatile_seconds"] == 22.287194792181253
    assert all(observations[index]["model"] is None for index in (1, 2, 5, 6, 7))
    assert format(RECOVERED_LOW20, "05x") == "6fa70"
    assert format(RECOVERED_WORD0, "08x") == "d1f6fa70"
    assert format(RECOVERED_COMBINED, "010x") == "1ed1f6fa70"

    z3_row = observations[6]
    assert z3_row["status"] == "invalid"
    assert z3_row["returncode"] == 0
    assert z3_row["statistics"] == {"rlimit-count": 20_698_099}
    assert z3_row["stdout_sha256"] == (
        "102e893de2f8c54d4c0f3b6d798c04c03c619a73ce1612e5e57133825d9d327a"
    )


def test_a189_models_confirm_b1_and_two_independent_b8_views(
    analysis: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    expected_confirmations = [
        {
            "variant": variant,
            **MODULE._confirm_model(analysis["public_challenge"], blocks, RECOVERED_MODEL),
        }
        for variant, blocks in (
            ("bitwuzla_bitblast_b1", 1),
            ("bitwuzla_bitblast_b8", 8),
            ("bitwuzla_preprop_b8", 8),
        )
    ]
    assert payload["confirmations"] == expected_confirmations
    assert expected_confirmations[0]["output_bits_checked"] == 512
    assert expected_confirmations[0]["block_matches"] == [True]
    for confirmation in expected_confirmations[1:]:
        assert confirmation["output_bits_checked"] == 4_096
        assert confirmation["block_matches"] == [True] * 8
    assert all(row["all_blocks_match"] is True for row in expected_confirmations)
    assert all(row["known_key_constraints_match"] is True for row in expected_confirmations)
    assert all(row["control_first_block_match"] is False for row in expected_confirmations)
    assert expected_confirmations[1]["candidate_block_sha256"] == analysis[
        "public_challenge"
    ]["target_block_sha256"]
    assert expected_confirmations[2]["candidate_block_sha256"] == analysis[
        "public_challenge"
    ]["target_block_sha256"]
    assert MODULE._canonical_sha256(expected_confirmations) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons == {
        "fully_confirmed_unknown_low20_assignments": [RECOVERED_LOW20],
        "predicted_variant": "bitwuzla_bitblast_b8",
        "predicted_variant_confirmed": True,
        "prospective_prediction_retained": True,
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a189_solver_dependency_identities_and_causal_chain_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert payload["solver_identities"] == {
        "bitwuzla": {
            "executable_sha256": "9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a",
            "path": "/opt/homebrew/bin/bitwuzla",
            "version": "0.9.1",
        },
        "boolector": {
            "executable_sha256": "ad08034940a968ab4641fd885c75a98220685443240224500b6de0ab23f11edb",
            "path": "/opt/homebrew/bin/boolector",
            "version": "3.2.4",
        },
        "z3": {
            "executable_sha256": "ae6c8df33db9c9ae9a80b6044e77cd66529a141d8b25f0620f1e89b409594f48",
            "path": "/opt/homebrew/bin/z3",
            "version": "4.15.4",
        },
    }

    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    ids = [
        "chacha20-a188-round5-b8-recovery-anchor",
        "chacha20-a189-fresh-round6-width20-challenge",
        "chacha20-a189-round6-split5-formula-family",
        "chacha20-a189-complete-engine-block-frontier",
        "chacha20-a189-independent-round6-confirmation",
        "chacha20-a189-prospective-depth-width-transfer",
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
