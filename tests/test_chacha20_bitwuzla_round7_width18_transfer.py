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
    / "chacha20_bitwuzla_round7_width18_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round7_width18_transfer_tested",
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
    / "chacha20_bitwuzla_round7_width18_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round7_width18_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round7_width18_transfer_v1.causal"

RUNNER_SHA256 = "fb7ec319302a6dd7708411aced69c115a572311f625480f9a20400d8bfd21e69"
RESULT_SHA256 = "f1cdad782a7ed82e893517eb2bffc1973640652bd59bcdc6a76a8ce060659220"
CAUSAL_SHA256 = "bb400fa62b338833dd7b06e98ea34840da1926315624f2d024ea80220af472f6"
CAUSAL_GRAPH_SHA256 = (
    "eca84970c765a5c9f017d98018835009b34a52150bfdfc3f9430de9789bd782a"
)
EXECUTION_PLAN_SHA256 = (
    "e1bfd7baf65802a210b5a4b917da376d329767d509ddf22ae59477006549532f"
)
FORMULA_PLAN_SHA256 = (
    "93b1fdd8d8288c5735106ef229a31e7761f2ff2f93168d1cf976ba2db76be696"
)
EXECUTION_SHA256 = "e5f3bbc7b02eefcc979ee89222cf31ab8fc29c026a881f27c30358aaa789f77f"
CONFIRMATION_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
COMPARISON_SHA256 = (
    "8ac3ee3d91549efafd804d69c1cd3bd837a0ff6be3d12a5ff7a9eb83d5b866a8"
)

FORMULA_IDENTITY = {
    "bitwuzla_bitblast_split6_b1": (
        16_676,
        "b7d54b70faadf3500753df87e80aef702955964654dc5ce2d48fff0505af8226",
    ),
    "bitwuzla_bitblast_split6_b2": (
        32_335,
        "264094156cf719d507b393de26e1fe5ea07ec2637ddc55a3324ff7771d02f735",
    ),
    "bitwuzla_bitblast_split6_b4": (
        63_653,
        "992de86fba00a4930182e4038345879e67c6fa7bdfd028fc15c6c04de95c534c",
    ),
    "bitwuzla_bitblast_split6_b8": (
        126_289,
        "5a61b805be1e4e372c2ff9134ea6eab34be298ca5ba6ac341326927d67c9e6d3",
    ),
    "bitwuzla_preprop_split6_b1": (
        16_676,
        "b7d54b70faadf3500753df87e80aef702955964654dc5ce2d48fff0505af8226",
    ),
    "bitwuzla_prop_split6_b1": (
        16_676,
        "b7d54b70faadf3500753df87e80aef702955964654dc5ce2d48fff0505af8226",
    ),
    "bitwuzla_bitblast_split5_b1": (
        16_676,
        "c3e3fa270b7eb5ef466795314293c8cf390c3b8ea09eca0b3534daa5bebceb0d",
    ),
    "z3_bitblast_split6_b1": (
        16_676,
        "b7d54b70faadf3500753df87e80aef702955964654dc5ce2d48fff0505af8226",
    ),
    "boolector_fun_split6_b1": (
        16_676,
        "b7d54b70faadf3500753df87e80aef702955964654dc5ce2d48fff0505af8226",
    ),
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a190_frozen_protocol_runner_and_anchor_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A190_solver_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A189"]["sha256"] == MODULE.A189_SHA256
    assert protocol["anchors"]["A189"]["causal_sha256"] == MODULE.A189_CAUSAL_SHA256
    assert protocol["prospective_prediction"] == {
        "claim_type": "prospective_round7_depth_width_partial_key_recovery_transfer",
        "frozen_before_solver_execution": True,
        "prediction": (
            "Bitwuzla_bitblast_cadical_split6_b1_returns_the_fresh_round7_18_bit_assignment_within_30000ms"
        ),
        "success_rule": (
            "complete_nine_variant_execution_predicted_model_independent_512_bit_confirmation_and_control_rejection"
        ),
    }
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A190_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a190_public_challenge_derivation_and_targets_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 7
    assert challenge["block_count"] == 8
    assert challenge["unknown_assignment_bits"] == 18
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_low_value_included"] is False
    assert challenge["known_key_word0_upper14"] & ((1 << 18) - 1) == 0

    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "1eb8af8aa31fe3964cb150c59683d56418c5924136d7be46b06224ff28036461"
    )
    assert int(words[0]) & ~MODULE.LOW_MASK == challenge["known_key_word0_upper14"]
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
    assert challenge["control_target_words"][0] == challenge["target_words"][0][0] ^ 1
    assert challenge["control_target_words"][1:] == challenge["target_words"][0][1:]


def test_a190_reconstructs_all_nine_portable_formulas_without_engines(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 7
    assert plan["unknown_key_bits"] == 18
    assert plan["known_key_bits"] == 238
    assert plan["variants"] == list(MODULE.VARIANTS)
    assert plan["variant_execution_order"] == list(MODULE.VARIANTS)
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert [row["variant"] for row in formula_plan] == list(MODULE.VARIANTS)
    for row in formula_plan:
        formula = analysis["formulas"][row["variant"]]
        expected_bytes, expected_sha = FORMULA_IDENTITY[row["variant"]]
        assert len(formula.encode()) == expected_bytes == row["bytes"]
        assert hashlib.sha256(formula.encode()).hexdigest() == expected_sha == row["sha256"]
        assert row["logical_unknown_key_bits"] == 18
        assert row["portable_smtlib2"] is True
        assert formula.count("(check-sat)") == 1
        assert formula.endswith("(check-sat)\n(get-value (k0 lo8))\n")
        assert "(set-option :timeout" not in formula
        assert "(assert (= lo8 #xea))" in formula
        assert "(assert (= ((_ extract 31 18) k0) #b10100000011010))" in formula


def test_a190_complete_open_portfolio_and_parser_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A190"
    assert payload["evidence_stage"] == "ROUND7_WIDTH18_RECOVERY_BOUNDARY_RETAINED"
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["status"] for row in observations] == [
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "invalid",
        "unknown",
    ]
    assert all(row["model"] is None for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low18_assignments"] == []
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    z3_row = observations[7]
    assert z3_row["variant"] == "z3_bitblast_split6_b1"
    assert z3_row["status"] == "invalid"
    assert z3_row["returncode"] == 0
    assert z3_row["statistics"] == {"rlimit-count": 93_468_752}
    assert z3_row["stdout_sha256"] == (
        "464c8d38d12f61d0137849192f8144d212f3c266662370735028b8563ea28a2c"
    )

    comparisons = payload["comparisons"]
    assert comparisons["predicted_variant"] == "bitwuzla_bitblast_split6_b1"
    assert comparisons["predicted_variant_confirmed"] is False
    assert comparisons["prospective_prediction_retained"] is False
    assert comparisons["fully_confirmed_unknown_low18_assignments"] == []
    assert comparisons["confirmed_variants"] == []
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a190_solver_provenance_and_causal_chain_are_exact() -> None:
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
        "chacha20-a189-round6-width20-recovery-anchor",
        "chacha20-a190-fresh-round7-width18-challenge",
        "chacha20-a190-round7-cut-block-formula-family",
        "chacha20-a190-complete-solver-portfolio",
        "chacha20-a190-independent-round7-confirmation",
        "chacha20-a190-prospective-depth-width-transfer",
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
