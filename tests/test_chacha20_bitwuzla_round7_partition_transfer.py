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
    / "chacha20_bitwuzla_round7_partition_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round7_partition_transfer_tested",
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
    / "chacha20_bitwuzla_round7_partition_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round7_partition_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round7_partition_transfer_v1.causal"

RUNNER_SHA256 = "841a10feaf6a84b6db69da426cf01349aee959c4834f1f202bb711cf94a80b74"
RESULT_SHA256 = "11911962fa7cdfaa3c1b996e2f45ccbbc3584948612ef98d88b3719099c31172"
CAUSAL_SHA256 = "c9197fe27adc0fafd5352f3b506c1533e9992f428504b24cfa87de347a39ac9a"
CAUSAL_GRAPH_SHA256 = (
    "4d4a8685bba61d4e373bd829f6a94c6006f3d04eb0901ac81a695caf4059f01e"
)
EXECUTION_PLAN_SHA256 = (
    "5b9357f11d6281c4eb65344cbd1244b7294156b2be8c05d1b5ac7ec21188a700"
)
FORMULA_PLAN_SHA256 = (
    "8efc964ec069077adebad39a2ae9e9384962c25c70b795bc4d73072c22aa51a7"
)
EXECUTION_SHA256 = "5e9acef4fda6ee5436193d889a6fcd49c6b4ca7c5204a2c9080e11054bf85840"
CONFIRMATION_SHA256 = (
    "8d1c10412b305e8d6667797abed6249df8705f416649bc0d72c8d675717a7912"
)
COMPARISON_SHA256 = (
    "21effa88461bcf944e5913dd50f1f97a1330ad2520e5fc42ecd62064b9da7976"
)

RECOVERED_LOW18 = 249_937
RECOVERED_WORD0 = 2_893_795_409
RECOVERED_WORD1_LOW = 121
RECOVERED_COMBINED = 522_584_838_225
RECOVERED_MODEL = {
    "combined_assignment": RECOVERED_COMBINED,
    "key_word0": RECOVERED_WORD0,
    "key_word1_low_value": RECOVERED_WORD1_LOW,
    "recovered_unknown_low18": RECOVERED_LOW18,
}

FORMULA_HASHES = [
    "d4c89312a950228b65a618ab11f858dab2a3ed8c2dbe5a07af8b9164288b31be",
    "1d1ad3062373cd2ec5914d366bdd6647d630617cdf2c876235cc90a4407474ba",
    "26d798bb800594324990e762c77a7728289deacc2279fbca0ce133d70003e4dc",
    "b1290f24ef8fe4101ebcce12cc410f53cdca4068c3aee293a681d3c8035bfcb7",
    "72bb032f997ae8583042d0761666c81cb7b066f204454c279d58207859466aca",
    "be1e1b44c80c572d00b2e3bb92f7e5aedf561f0396d72ce78e77d2bde7bb89c6",
    "5dd2bd8cc206d9d353a407217f5ae54b2109be35b296bdc9b64f0962c0872f95",
    "faf3e64bc828b68fe9e5da47afad9b149de5c1430624ae17f653743f222a0232",
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a191_frozen_protocol_runner_and_a190_anchor_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A191_solver_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A190"]["sha256"] == MODULE.A190_SHA256
    assert protocol["anchors"]["A190"]["causal_sha256"] == MODULE.A190_CAUSAL_SHA256
    assert protocol["prospective_prediction"] == {
        "claim_type": "prospective_assignment_free_complete_partition_partial_key_recovery_transfer",
        "frozen_before_solver_execution": True,
        "prediction": (
            "the_complete_eight_cell_split6_partition_returns_at_least_one_fresh_round7_18bit_assignment_within_10000ms_per_cell"
        ),
        "success_rule": (
            "all_eight_cells_executed_in_frozen_order_at_least_one_model_independent_512bit_confirmation_and_control_rejection"
        ),
    }
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A191_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["cell_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a191_public_challenge_derivation_and_literal_secret_absence_are_exact(
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
        "da324c9149b2477cb366dbd4a0e04b55fce2235ff838957185d510c3cd6d2cbb"
    )
    assert int(words[0]) & ~MODULE._A190.LOW_MASK == challenge[
        "known_key_word0_upper14"
    ]
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
        str(RECOVERED_LOW18),
        str(RECOVERED_WORD0),
        str(RECOVERED_COMBINED),
        "3d051",
        "ac7bd051",
        "79ac7bd051",
    )
    for path in (PROTOCOL_PATH, MODULE_PATH):
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in spellings)


def test_a191_partition_is_complete_disjoint_and_preserves_the_full_domain(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 7
    assert plan["unknown_key_bits"] == 18
    assert plan["known_key_bits"] == 238
    assert plan["partition_cell_count"] == 8
    assert plan["partition_cell_free_bits"] == 15
    assert plan["partition_fixed_bits"] == 3
    assert plan["partition_prefix_order"] == [f"{value:03b}" for value in range(8)]
    assert plan["variants"] == list(MODULE.VARIANTS)
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert len(formula_plan) == 8
    assert sum(row["candidate_count"] for row in formula_plan) == 1 << 18
    assert [row["prefix"] for row in formula_plan] == [
        f"{value:03b}" for value in range(8)
    ]
    for index, row in enumerate(formula_plan):
        variant = MODULE.VARIANTS[index]
        formula = analysis["formulas"][variant]
        assert row["variant"] == variant
        assert row["candidate_count"] == 1 << 15
        assert row["fixed_key_coordinates"] == [17, 16, 15]
        assert row["free_key_coordinates"] == list(reversed(range(15)))
        assert row["portable_smtlib2"] is True
        assert len(formula.encode()) == row["bytes"] == 16_718
        assert hashlib.sha256(formula.encode()).hexdigest() == row["sha256"] == FORMULA_HASHES[index]
        assert formula.count("(check-sat)") == 1
        assert f"(assert (= ((_ extract 17 15) k0) #b{index:03b}))" in formula
        for other in range(8):
            if other != index:
                assert f"((_ extract 17 15) k0) #b{other:03b}" not in formula
    assert set(range(8)) == {MODULE._prefix_value(variant) for variant in MODULE.VARIANTS}


def test_a191_complete_execution_closes_all_eight_cells_and_recovers_one_model(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A191"
    assert payload["evidence_stage"] == (
        "PROSPECTIVE_ROUND7_WIDTH18_COMPLETE_PARTITION_RECOVERY_RETAINED"
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
        f"{value:03b}" for value in range(8)
    ]
    assert [row["status"] for row in observations] == ["unsat"] * 7 + ["sat"]
    assert all(row["candidate_count"] == 1 << 15 for row in observations)
    assert all(row["free_bits"] == 15 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["model"] is None for row in observations[:7])
    assert observations[7]["model"] == RECOVERED_MODEL
    assert RECOVERED_LOW18 >> 15 == 0b111
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 1
    assert execution["fully_confirmed_unknown_assignment_count"] == 1
    assert execution["fully_confirmed_unknown_low18_assignments"] == [RECOVERED_LOW18]
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons == {
        "complete_domain_candidate_count": 1 << 18,
        "confirmed_variants": ["prefix_111"],
        "fully_confirmed_unknown_low18_assignments": [RECOVERED_LOW18],
        "original_domain_candidate_count": 1 << 18,
        "partition_complete_and_disjoint_by_construction": True,
        "prospective_prediction_retained": True,
        "statuses": {
            **{f"prefix_{value:03b}": "unsat" for value in range(7)},
            "prefix_111": "sat",
        },
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a191_model_has_independent_512_bit_confirmation_and_rejects_control(
    analysis: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    expected = {
        "variant": "prefix_111",
        "prefix": "111",
        **MODULE._A190._confirm_model(
            analysis["public_challenge"], 1, RECOVERED_MODEL
        ),
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
    assert format(RECOVERED_LOW18, "05x") == "3d051"
    assert format(RECOVERED_WORD0, "08x") == "ac7bd051"
    assert format(RECOVERED_COMBINED, "010x") == "79ac7bd051"
    assert MODULE._canonical_sha256([expected]) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a191_solver_provenance_and_causal_chain_are_exact() -> None:
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
        "chacha20-a190-monolithic-round7-boundary-anchor",
        "chacha20-a191-fresh-round7-width18-challenge",
        "chacha20-a191-complete-prefix-partition",
        "chacha20-a191-complete-cell-execution",
        "chacha20-a191-independent-model-confirmation",
        "chacha20-a191-prospective-partition-transfer",
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
