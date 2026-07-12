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
    / "chacha20_smt_directional_round5_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_smt_directional_round5_transfer_tested",
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
    / "chacha20_smt_directional_round5_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_smt_directional_round5_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_smt_directional_round5_transfer_v1.causal"
RUNNER_SHA256 = "4796799d7d0b3224e5d291cdb8f93a14a2a9860082fa248bb3ee64eb2eb27a9c"
RESULT_SHA256 = "c47722b6110bfdac9b4688454235339cdb7f297011b1e6c7f959a0c947e4a953"
CAUSAL_SHA256 = "043f2b52fd13ca8298f713e374edd1aaa720c7748daf0a4b6c39453b32dff62a"
CAUSAL_GRAPH_SHA256 = (
    "41afa2b30a1eec3d2a96719ce919e802a63d83fd904e6752663acb97e7f02ab8"
)
EXECUTION_PLAN_SHA256 = (
    "8cdf3acf3400f8157f198ca6e6c2474b666214cb5d4cc527b1f513f56bc4aaa6"
)
FORMULA_PLAN_SHA256 = (
    "527f2ad85ff45bbb01c81a1d21169b430cf3b9cf33a304f43d5e25dcbaa18a39"
)
EXECUTION_SHA256 = "359e561926016b3dc3bdd12043c718e65b4a9aab37caa36ed3834c7c773964b5"
EMPTY_CONFIRMATION_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
VARIANTS = ["forward", "inverse", "split1", "split2", "split3", "split4"]
FORMULA_PLAN = [
    {
        "variant": "forward",
        "sha256": "a7a126526b7b9057140b93f3d0d76abdcef18da75c68f511ab748ef6d1759425",
        "bytes": 10_697,
    },
    {
        "variant": "inverse",
        "sha256": "ffb6d50d8c8bd0a8c4e32cc362c80555e06606fc7703781af9ccaef65cca965b",
        "bytes": 10_970,
    },
    {
        "variant": "split1",
        "sha256": "c94d7ed88246f513f0959e3daf9ea63086d7e7885648e10b44132a21ba27131b",
        "bytes": 11_002,
    },
    {
        "variant": "split2",
        "sha256": "7f283e14684112e374277b23e7251a2bc15b81d9e359b52e66996bf6c5319696",
        "bytes": 11_001,
    },
    {
        "variant": "split3",
        "sha256": "488669f69e1a97014c06860164ecde3000e5dccc463fd4edaf1a57b7ef0d19d5",
        "bytes": 11_001,
    },
    {
        "variant": "split4",
        "sha256": "0a81b5b4cc506e6673fd0aaff8c4f97d649e5ab0093fe6a4a86ea7a5aecb201a",
        "bytes": 10_997,
    },
]
STATISTICS = {
    "forward": {
        "rlimit-count": 277_184_707,
        "sat-conflicts": 148_831,
        "sat-decisions": 277_384,
        "sat-propagations-2ary": 47_863_530,
        "sat-propagations-nary": 236_079_471,
        "sat-restarts": 25_538,
    },
    "inverse": {
        "rlimit-count": 293_423_035,
        "sat-conflicts": 213_393,
        "sat-decisions": 339_134,
        "sat-propagations-2ary": 62_342_265,
        "sat-propagations-nary": 247_886_684,
        "sat-restarts": 18_085,
    },
    "split1": {
        "rlimit-count": 289_219_054,
        "sat-conflicts": 321_871,
        "sat-decisions": 478_512,
        "sat-propagations-2ary": 62_405_354,
        "sat-propagations-nary": 241_814_902,
        "sat-restarts": 29_776,
    },
    "split2": {
        "rlimit-count": 246_217_947,
        "sat-conflicts": 384_814,
        "sat-decisions": 523_857,
        "sat-propagations-2ary": 59_782_844,
        "sat-propagations-nary": 202_787_782,
        "sat-restarts": 24_321,
    },
    "split3": {
        "rlimit-count": 256_839_505,
        "sat-conflicts": 352_108,
        "sat-decisions": 622_087,
        "sat-propagations-2ary": 41_617_794,
        "sat-propagations-nary": 231_588_109,
        "sat-restarts": 30_375,
    },
    "split4": {
        "rlimit-count": 285_053_744,
        "sat-conflicts": 176_623,
        "sat-decisions": 322_736,
        "sat-propagations-2ary": 48_303_987,
        "sat-propagations-nary": 250_504_206,
        "sat-restarts": 32_833,
    },
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_fresh_round5_challenge_and_six_view_plan(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert MODULE.PROTOCOL_SHA256 == (
        "67c27032eab51ac443dcb5446eca3fe46b1c42dd60a02fb13d2d7c0b97e3c6fe"
    )
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A186_solver_execution"
    assert protocol["anchors"]["A185"]["sha256"] == MODULE.A185_SHA256
    assert protocol["anchors"]["A185"]["causal_sha256"] == MODULE.A185_CAUSAL_SHA256
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "prospective_round_depth_causal_direction_transfer"
    )
    assert protocol["prospective_prediction"]["frozen_before_solver_execution"] is True
    assert protocol["discovery_basis"]["selection_rule"] == (
        "transfer_both_prospectively_confirmed_early_splits_and_map_every_round5_cut_with_forward_and_inverse_controls"
    )
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A186_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_public_challenge_derivation_and_secret_absence_are_exact(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["rounds"] == 5
    assert challenge["unknown_assignment_bits"] == 40
    assert challenge["unknown_key_word0_bits"] == 32
    assert challenge["unknown_key_word1_low_bits"] == 8
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_included"] is False
    assert challenge["unknown_key_word1_low_value_included"] is False
    assert challenge["known_key_word1_upper24"] & 0xFF == 0
    forbidden_fields = {
        "unknown_assignment",
        "unknown_key_word0",
        "unknown_key_word1_low_value",
        "secret",
        "ground_truth",
    }
    assert forbidden_fields.isdisjoint(challenge)

    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(44)
    words = np.frombuffer(derived, dtype="<u4")
    assert hashlib.sha256(derived).hexdigest() == (
        "66e2279235428a619bb591c98a489e938492ba9fda0c7510e6c5b6f5f71695c3"
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

    source = MODULE_PATH.read_text().lower()
    assert "import secrets" not in source
    assert "os.urandom" not in source
    assert "token_bytes" not in source
    assert "ground_truth" not in source


def test_runner_builds_exact_frozen_six_view_formula_plan_without_solver(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 5
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


def test_retained_a186_status_and_statistics_vector_is_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A186"
    assert payload["evidence_stage"] == "ROUND5_DIRECTIONAL_SOLVER_BOUNDARY_RETAINED"
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A185_result_sha256"] == MODULE.A185_SHA256
    assert payload["anchor_gates"]["A185_causal_sha256"] == MODULE.A185_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan"] == FORMULA_PLAN
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == VARIANTS
    assert [row["variant"] for row in observations] == VARIANTS
    assert [row["status"] for row in observations] == ["unknown"] * 6
    assert [row["statistics"] for row in observations] == [
        STATISTICS[variant] for variant in VARIANTS
    ]
    assert [row["formula_sha256"] for row in observations] == [
        row["sha256"] for row in FORMULA_PLAN
    ]
    assert [row["formula_bytes"] for row in observations] == [
        row["bytes"] for row in FORMULA_PLAN
    ]
    assert all(row["returncode"] == 1 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["model"] is None for row in observations)
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["confirmed_assignment_count"] == 0
    assert execution["confirmed_assignments"] == []
    assert execution["confirmed_variants"] == []
    assert execution["predicted_variants"] == ["split1", "split2"]
    assert execution["predicted_variants_confirmed"] == []
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256


def test_retained_a186_has_no_assignment_or_confirmation() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == EMPTY_CONFIRMATION_SHA256
    assert MODULE._canonical_sha256([]) == EMPTY_CONFIRMATION_SHA256
    assert payload["execution"]["confirmed_assignments"] == []
    assert all(
        row["model"] is None for row in payload["execution"]["observations"]
    )


def test_retained_a186_causal_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a185-direction-transfer-anchor",
        "chacha20-a186-fresh-round5-challenge",
        "chacha20-a186-six-causal-formula-views",
        "chacha20-a186-complete-directional-execution",
        "chacha20-a186-independent-round-depth-transfer",
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
