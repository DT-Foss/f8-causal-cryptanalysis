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
    / "chacha20_bitwuzla_round5_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round5_transfer_tested",
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
    / "chacha20_bitwuzla_round5_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round5_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round5_transfer_v1.causal"

RUNNER_SHA256 = "6d5517361c3399419352cf0d4b481e051841e0bf1b85745b2bac6e2963eb3df5"
PUBLIC_CHALLENGE_SHA256 = (
    "231ca751d07fefffbd54ce0715d8bc35f7a6d444df0f5c6f482b5b407e69ff9c"
)
RESULT_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
CAUSAL_SHA256 = "a717e615cfc005fe985a24059f7e6bedcd8008c460b274bb313f6ddfc53e7c78"
CAUSAL_GRAPH_SHA256 = (
    "4db3b36f5a6b6c89d14905c861e6bb91035b5f5a9843af3345baf142dee294eb"
)
EXECUTION_PLAN_SHA256 = (
    "f19a7653d73ee4bc2f66bba609766c3d5a7c037bcb009ed69d839378ebb5e0cf"
)
FORMULA_PLAN_SHA256 = (
    "ef6b1485e607c44e1895d80c0d8f81c8c3ffd6a3976d8e6577c40926fe8f408b"
)
EXECUTION_SHA256 = "a340a50456ce9f0fbf7e80abebf5cfd85ebb34bce99bc8632afbeaeea23dcffb"
CONFIRMATION_SHA256 = (
    "fbc625b84b07f0e0b241da42e5773073123309b297ff92075cffe87e84abf2dc"
)
COMPARISON_SHA256 = (
    "c0af73824da47d80d8ca9b16ec4dda937113fcf831d200c2a8f7d76d12afd8e3"
)

RECOVERED_COMBINED = 357_645_702_403
RECOVERED_WORD0 = 1_163_416_835
RECOVERED_LOW_VALUE = 83
RECOVERED_MODEL = {
    "combined_assignment": RECOVERED_COMBINED,
    "key_word0": RECOVERED_WORD0,
    "key_word1_low_value": RECOVERED_LOW_VALUE,
}

VARIANTS = [
    "bitwuzla_bitblast_b1",
    "bitwuzla_bitblast_b2",
    "bitwuzla_bitblast_b4",
    "bitwuzla_bitblast_b8",
    "bitwuzla_preprop_b4",
    "bitwuzla_prop_b4",
    "z3_bitblast_b4",
    "boolector_fun_b4",
]
STATUSES = ["unknown", "unknown", "unknown", "sat", "unknown", "unknown", "invalid", "unknown"]
FORMULA_IDENTITY = {
    "bitwuzla_bitblast_b1": (12_361, "b9174703c57ecd7dbbfb42f43f475c2b1b6d07d70622e5611be890eb3281748a"),
    "bitwuzla_bitblast_b2": (23_780, "c145e87c596d79fe3bed63e5c805740fffbc65263856a9c2d141dd0666b03b4d"),
    "bitwuzla_bitblast_b4": (46_618, "edf3d3cabda04fc470f9482fbcdcfffa327dc4718fddfb97b61d7a40219bfae1"),
    "bitwuzla_bitblast_b8": (92_294, "004bbb7ef6ab6ab19898dface90ad7bee953e5a9ca5a3134fab41ac275bae590"),
    "bitwuzla_preprop_b4": (46_618, "edf3d3cabda04fc470f9482fbcdcfffa327dc4718fddfb97b61d7a40219bfae1"),
    "bitwuzla_prop_b4": (46_618, "edf3d3cabda04fc470f9482fbcdcfffa327dc4718fddfb97b61d7a40219bfae1"),
    "z3_bitblast_b4": (46_618, "edf3d3cabda04fc470f9482fbcdcfffa327dc4718fddfb97b61d7a40219bfae1"),
    "boolector_fun_b4": (46_618, "edf3d3cabda04fc470f9482fbcdcfffa327dc4718fddfb97b61d7a40219bfae1"),
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a188_protocol_freshness_portfolio_and_solver_identities(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A188_solver_execution"
    assert protocol["public_challenge_sha256"] == PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A187"]["sha256"] == MODULE.A187_SHA256
    assert protocol["anchors"]["A187"]["causal_sha256"] == MODULE.A187_CAUSAL_SHA256
    prediction = protocol["prospective_prediction"]
    assert prediction["claim_type"] == "prospective_cross_engine_partial_key_recovery_transfer"
    assert prediction["frozen_before_solver_execution"] is True
    assert prediction["prediction"] == (
        "both_Bitwuzla_bitblast_cadical_b4_and_preprop_cadical_b4_return_the_same_fresh_40_bit_assignment_within_5000ms"
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A188_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert protocol["solver_binaries"] == {
        "bitwuzla": {
            "executable_sha256": "9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a",
            "path_at_freeze": "/opt/homebrew/bin/bitwuzla",
            "sat_backend": "cadical",
            "version": "0.9.1",
        },
        "boolector": {
            "executable_sha256": "ad08034940a968ab4641fd885c75a98220685443240224500b6de0ab23f11edb",
            "path_at_freeze": "/opt/homebrew/bin/boolector",
            "version": "3.2.4",
        },
        "z3": {
            "executable_sha256": "ae6c8df33db9c9ae9a80b6044e77cd66529a141d8b25f0620f1e89b409594f48",
            "path_at_freeze": "/opt/homebrew/bin/z3",
            "version": "4.15.4",
        },
    }
    assert analysis["solver_execution_started"] is False


def test_a188_public_challenge_derivation_and_literal_secret_boundary(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 5
    assert challenge["block_count"] == 8
    assert challenge["counter_schedule"] == "base_plus_block_index_mod_2^32"
    assert challenge["unknown_assignment_bits"] == 40
    assert challenge["unknown_key_word0_bits"] == 32
    assert challenge["unknown_key_word1_low_bits"] == 8
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_included"] is False
    assert challenge["unknown_key_word1_low_value_included"] is False
    assert challenge["known_key_word1_upper24"] & 0xFF == 0

    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(44)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "7f11a25515a8451c0c1cff9602121a84ce463592f334e42a36d2dc291e56300e"
    )
    assert int(words[0]) & 0xFFFFFF00 == challenge["known_key_word1_upper24"]
    assert [int(value) for value in words[1:7]] == challenge["known_key_words_2_through_7"]
    assert int(words[7]) == challenge["counter_start"]
    assert [int(value) for value in words[8:11]] == challenge["nonce_words"]

    for target, expected in zip(
        challenge["target_words"], challenge["target_block_sha256"], strict=True
    ):
        raw = np.array(target, dtype="<u4").tobytes()
        assert hashlib.sha256(raw).hexdigest() == expected
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert hashlib.sha256(control.tobytes()).hexdigest() == (
        challenge["control_target_block_sha256"]
    )

    secret_spellings = (
        str(RECOVERED_COMBINED),
        str(RECOVERED_WORD0),
        "5345585503",
        "45585503",
    )
    for path in (PROTOCOL_PATH, MODULE_PATH):
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in secret_spellings)


def test_a188_reconstructs_complete_portable_formula_portfolio_without_engines(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["variants"] == VARIANTS
    assert plan["variant_execution_order"] == VARIANTS
    assert plan["solver_time_limit_milliseconds_per_variant"] == 5_000
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
        assert row["portable_smtlib2"] is True
        assert formula.count("(check-sat)") == 1
        assert formula.endswith("(check-sat)\n(get-value (k0 lo8))\n")
        assert "(set-option :timeout" not in formula
        assert "(set-option :rlimit" not in formula
        assert "(declare-fun lo8 () (_ BitVec 8))" in formula
        assert "(declare-fun k0 () (_ BitVec 32))" in formula
        lowered = formula.lower()
        assert "5345585503" not in lowered
        assert "45585503" not in lowered


def test_a188_stored_evidence_stage_status_vector_and_parser_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A188"
    assert payload["evidence_stage"] == "CROSS_ENGINE_ROUND5_RECOVERY_BOUNDARY_RETAINED"
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A187_result_sha256"] == MODULE.A187_SHA256
    assert payload["anchor_gates"]["A187_causal_sha256"] == MODULE.A187_CAUSAL_SHA256
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
    assert execution["returned_model_count"] == 1
    assert execution["fully_confirmed_assignment_count"] == 1
    assert execution["fully_confirmed_assignments"] == [RECOVERED_COMBINED]
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == payload["execution_sha256"] == EXECUTION_SHA256

    bitwuzla_b8 = observations[3]
    assert bitwuzla_b8["variant"] == "bitwuzla_bitblast_b8"
    assert bitwuzla_b8["status"] == "sat"
    assert bitwuzla_b8["model"] == RECOVERED_MODEL
    assert bitwuzla_b8["volatile_seconds"] == 4.856995374895632
    assert bitwuzla_b8["stdout_sha256"] == (
        "ac67390cfb0ea340f91cf57c9c04270157309646cba01f447d2a6b5263e43800"
    )
    assert format(RECOVERED_COMBINED, "010x") == "5345585503"
    assert format(RECOVERED_WORD0, "08x") == "45585503"
    assert format(RECOVERED_LOW_VALUE, "02x") == "53"

    z3_row = observations[6]
    assert z3_row["variant"] == "z3_bitblast_b4"
    assert z3_row["status"] == "invalid"
    assert z3_row["returncode"] == 0
    assert z3_row["model"] is None
    assert z3_row["statistics"] == {"rlimit-count": 55_402_653}
    assert z3_row["stdout_sha256"] == (
        "c1633c5a41eeb3842f6e0ad51772b115ca1524ac2ca6d1245e8da8509318a41c"
    )


def test_a188_b8_model_confirms_all_4096_bits_and_rejects_control(
    analysis: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    confirmation = {
        "variant": "bitwuzla_bitblast_b8",
        **MODULE._A187._confirm_model(
            analysis["public_challenge"],
            8,
            RECOVERED_MODEL,
        ),
    }
    assert payload["confirmations"] == [confirmation]
    assert confirmation["all_blocks_match"] is True
    assert confirmation["block_matches"] == [True] * 8
    assert confirmation["block_count_checked"] == 8
    assert confirmation["output_bits_checked"] == 4_096
    assert confirmation["control_first_block_match"] is False
    assert confirmation["candidate_block_sha256"] == analysis["public_challenge"][
        "target_block_sha256"
    ]
    assert MODULE._canonical_sha256([confirmation]) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons == {
        "fully_confirmed_assignments": [RECOVERED_COMBINED],
        "predicted_assignments_identical": False,
        "predicted_variants": ["bitwuzla_bitblast_b4", "bitwuzla_preprop_b4"],
        "predicted_variants_confirmed": [],
        "prospective_prediction_retained": False,
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a188_causal_reader_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    ids = [
        "chacha20-a187-prospective-stacking-anchor",
        "chacha20-a188-fresh-cross-engine-challenge",
        "chacha20-a188-portable-smtlib-formula-family",
        "chacha20-a188-complete-engine-portfolio",
        "chacha20-a188-independent-multiblock-confirmation",
        "chacha20-a188-prospective-engine-transfer",
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
