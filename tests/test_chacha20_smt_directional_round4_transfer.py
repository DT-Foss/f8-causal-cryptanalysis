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
    / "chacha20_smt_directional_round4_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_smt_directional_round4_transfer_tested",
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
    / "chacha20_smt_directional_round4_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_smt_directional_round4_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_smt_directional_round4_transfer_v1.causal"
RESULT_SHA256 = "d87aefa46f4b85a71ab9fd2199401975075beb0fedf1545b9dc63842126c31e0"
CAUSAL_SHA256 = "ea490a5ea59838faacddfc11ca80390e6cb87ff35943eb1e294cd1006f1e77ac"
CAUSAL_GRAPH_SHA256 = (
    "43f5b6a267de0fcd272136d46f84442697c2186b98bbb59dccaf74f9bba77824"
)
EXECUTION_PLAN_SHA256 = (
    "3160f3c45617a04b99530a9d139b1eb00501a8e0f4485c3e021669c809d87a8f"
)
FORMULA_PLAN_SHA256 = (
    "fe884dd4396c2672221b16e4d4d37c032c9446d89eb84a2c4dde5777be04d08d"
)
EXECUTION_SHA256 = "3afe54a447dcef54d48d3c99f2c0c7d25a648c21e4621366134f3dcd2e82e04d"
CONFIRMATION_SHA256 = (
    "31c8585ed6cfe56b05556bbea0474802acb0eac946b2fb169d43482c204566f0"
)
RECOVERED_COMBINED = 150_577_278_509
RECOVERED_WORD0 = 253_423_149
RECOVERED_LOW_VALUE = 35
VARIANTS = ["forward", "inverse", "split1", "split2", "split3"]
FORMULA_PLAN = [
    {
        "variant": "forward",
        "sha256": "432a117edc7996c2e99e0717d2fdc830ca53c38bb41ec57085884a46deda77e1",
        "bytes": 8_865,
    },
    {
        "variant": "inverse",
        "sha256": "f464ddd82ef51f9ac71a19d73314cb2c3b4822cb70b4e12cd2bf05d2b4e5f340",
        "bytes": 9_138,
    },
    {
        "variant": "split1",
        "sha256": "a3af7431ad1687fc7000a131df3e397b597e6092ae4bca998979c16908e6e0e3",
        "bytes": 9_170,
    },
    {
        "variant": "split2",
        "sha256": "6104e272345919ca5fb1d138e19c0ef37eb6ebdee3b81af87a276ade0fe33983",
        "bytes": 9_169,
    },
    {
        "variant": "split3",
        "sha256": "6ce8fb1a329d157aec74434ffd4395ce80d1da762bfdeec25593b520baabb784",
        "bytes": 9_169,
    },
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_fresh_round4_challenge_and_fixed_plan(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "4132728bfd1a5ed6865d38e6adfa6ed2cc9e1e75073ec0960201d4076d323fa1"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A185_solver_execution"
    assert protocol["anchors"]["A184"]["sha256"] == MODULE.A184_SHA256
    assert protocol["anchors"]["A184"]["causal_sha256"] == MODULE.A184_CAUSAL_SHA256
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "prospective_causal_direction_transfer"
    )
    assert protocol["prospective_prediction"]["frozen_before_solver_execution"] is True
    assert protocol["discovery_basis"]["selection_rule"] == (
        "transfer_all_three_sat_directions_plus_forward_control_to_a_fresh_round4_challenge"
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A185_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_public_challenge_derivation_and_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_RELATION_SHA256
    assert challenge["rounds"] == 4
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
        "04f9b57b70db9574c05e35830b5362d0ab433eec1eb16b400923f6dc76f0160a"
    )
    assert int(words[0]) & 0xFFFFFF00 == challenge["known_key_word1_upper24"]
    assert [int(value) for value in words[1:7]] == challenge["known_key_words_2_through_7"]
    assert int(words[7]) == challenge["counter"]
    assert [int(value) for value in words[8:11]] == challenge["nonce_words"]

    target = np.array(challenge["target_words"], dtype="<u4")
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert hashlib.sha256(target.tobytes()).hexdigest() == challenge["target_block_sha256"]
    assert hashlib.sha256(control.tobytes()).hexdigest() == (
        challenge["control_target_block_sha256"]
    )
    assert challenge["control_target_words"][0] == challenge["target_words"][0] ^ 1
    assert challenge["control_target_words"][1:] == challenge["target_words"][1:]

    secret_spellings = (
        str(RECOVERED_COMBINED),
        str(RECOVERED_WORD0),
        "230f1aee2d",
        "0f1aee2d",
    )
    for path in (PROTOCOL_PATH, MODULE_PATH):
        lowered = path.read_text().lower()
        assert all(spelling not in lowered for spelling in secret_spellings)


def test_runner_builds_exact_frozen_five_view_formula_plan_without_solver(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 4
    assert plan["unknown_key_bits"] == 40
    assert plan["known_key_bits"] == 216
    assert plan["target_output_bits"] == 512
    assert plan["variants"] == VARIANTS
    assert plan["variant_execution_order"] == VARIANTS
    assert plan["timeout_milliseconds_per_variant"] == 30_000
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False
    assert plan["unknown_assignment_available_to_runner_before_execution"] is False

    formulas = {
        variant: MODULE._formula(variant, analysis["public_challenge"], 30_000)
        for variant in VARIANTS
    }
    observed_plan = [
        {
            "variant": variant,
            "sha256": hashlib.sha256(formulas[variant].encode()).hexdigest(),
            "bytes": len(formulas[variant].encode()),
        }
        for variant in VARIANTS
    ]
    assert observed_plan == FORMULA_PLAN
    assert MODULE._canonical_sha256(observed_plan) == FORMULA_PLAN_SHA256
    for formula in formulas.values():
        assert formula.count("(check-sat)") == 1
        assert formula.endswith("(check-sat)\n(get-value (k0 lo8))\n")
        assert "(set-option :timeout 30000)" in formula
        assert "(declare-fun k0 () (_ BitVec 32))" in formula
        assert "(declare-fun lo8 () (_ BitVec 8))" in formula
        lowered = formula.lower()
        assert "230f1aee2d" not in lowered
        assert "0f1aee2d" not in lowered


def test_retained_a185_execution_is_exact_and_hash_pinned(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A185"
    assert payload["evidence_stage"] == (
        "PROSPECTIVE_CAUSAL_DIRECTION_TRANSFER_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A184_result_sha256"] == MODULE.A184_SHA256
    assert payload["anchor_gates"]["A184_causal_sha256"] == MODULE.A184_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["public_challenge_sha256"] == MODULE.PUBLIC_RELATION_SHA256
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan"] == FORMULA_PLAN
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == VARIANTS
    assert [row["variant"] for row in observations] == VARIANTS
    assert [row["status"] for row in observations] == [
        "unknown",
        "unknown",
        "sat",
        "sat",
        "unknown",
    ]
    assert all(row["externally_timed_out"] is False for row in observations)
    assert [row["formula_sha256"] for row in observations] == [
        row["sha256"] for row in FORMULA_PLAN
    ]
    assert observations[0]["model"] is None
    assert observations[1]["model"] is None
    assert observations[4]["model"] is None
    expected_model = {
        "combined_assignment": RECOVERED_COMBINED,
        "key_word0": RECOVERED_WORD0,
        "key_word1_low_value": RECOVERED_LOW_VALUE,
    }
    assert observations[2]["model"] == expected_model
    assert observations[3]["model"] == expected_model
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["confirmed_assignment_count"] == 1
    assert execution["confirmed_assignments"] == [RECOVERED_COMBINED]
    assert execution["confirmed_directional_variants"] == ["split1", "split2"]
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert all(
        volatile not in row
        for row in observations
        for volatile in ("wallclock_seconds", "elapsed_seconds", "duration_seconds")
    )
    assert format(RECOVERED_COMBINED, "010x") == "230f1aee2d"
    assert format(RECOVERED_WORD0, "08x") == "0f1aee2d"


def test_split_models_independently_confirm_all_512_target_bits(
    analysis: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    expected_model = {
        "combined_assignment": RECOVERED_COMBINED,
        "key_word0": RECOVERED_WORD0,
        "key_word1_low_value": RECOVERED_LOW_VALUE,
    }
    confirmations = [
        {
            "variant": variant,
            **MODULE._confirm(analysis["public_challenge"], expected_model),
        }
        for variant in ("split1", "split2")
    ]
    assert confirmations == payload["confirmations"]
    assert [row["variant"] for row in confirmations] == ["split1", "split2"]
    assert all(row["complete_block_match"] is True for row in confirmations)
    assert all(row["output_bits_checked"] == 512 for row in confirmations)
    assert all(
        row["candidate_block_sha256"]
        == "0f577a89f5049326db0f8494f97d6e51db03315354efbb98732458a132cde154"
        for row in confirmations
    )
    assert MODULE._canonical_sha256(confirmations) == CONFIRMATION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_retained_a185_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a184-width40-fullround-anchor",
        "chacha20-a185-fresh-round4-challenge",
        "chacha20-a185-five-causal-formula-views",
        "chacha20-a185-complete-directional-execution",
        "chacha20-a185-independent-directional-transfer",
    ]
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )
