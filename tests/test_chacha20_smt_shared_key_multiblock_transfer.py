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
    / "chacha20_smt_shared_key_multiblock_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_smt_shared_key_multiblock_transfer_tested",
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
    / "chacha20_smt_shared_key_multiblock_transfer_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_smt_shared_key_multiblock_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_smt_shared_key_multiblock_transfer_v1.causal"

RUNNER_SHA256 = "34a6c01f14b26d78f17c15f096d0dba9f2f2911c12e08194080dea58d81e8335"
RESULT_SHA256 = "ec00786b9e778b3914cc2594919da11b763cfffa72f71fa110c2c90dc8e9e3e3"
CAUSAL_SHA256 = "6c3eda1c3f84cac90bf04e63267728cd88581f73f85fe18e971e72caa67fd68d"
CAUSAL_GRAPH_SHA256 = (
    "3d4a769c40a1be6ff8b697bbd73b42b7ee89b840a2494d9e71907415d1542d50"
)
EXECUTION_PLAN_SHA256 = (
    "0df1a9768f16a21339b53dd1c33303b23149c0af942577757329ce00da6d711d"
)
FORMULA_PLAN_SHA256 = (
    "46c0e4e0576d5fe000b81b6391d476d79a300a5bad3809a58d833553286b494b"
)
EXECUTION_SHA256 = "7d3da2a1f7255bbfbdc4b95dd8e39af18f12b226aab8ab02c4201d1e4efde430"
CONFIRMATION_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
COMPARISON_SHA256 = (
    "fe2758dcc62bc3aff1c78d69cf80d5aba72a52b36e56396da5ead91bbaa49300"
)

FORMULA_IDENTITY = {
    "split4_full_b1": (12_465, "aad139ea2f49321d85233234dc0b176d0706c4a3da35bd8c3a98bb0b2ef8178a"),
    "split4_full_b2": (23_884, "90958bbdfb018b4ab761a6fcc5e73c7bc4b84b8af91e74cc31d912b1f2fead07"),
    "split4_full_b4": (46_722, "14040a57a5ebe1daeace507a48510e0f6edaaaf34a5256bef675c2525f4f1259"),
    "split4_full_b8": (92_398, "5d1d1e50b7dd9e721fa85a079ff615188e6a15d0e8880872143648b599791e17"),
    "split4_sparse512_b2": (23_420, "54b31294b1a07fe227fd2ea2eb834da5fe705ee1d0bec59fce02666eb0fed4e7"),
    "split4_sparse512_b4": (45_330, "e1d2e0933f4e45d9740f4500d11582ce736468d989d55e07b9bc146fc6189794"),
    "split4_sparse512_b8": (89_150, "b33d6e2b8eb4f877b3837e15a7a221b7a9cf4ee95867c7dba9b9259e7cf7fc9a"),
    "forward_delta_b2": (23_100, "594338c0a808976049ccdcbe0c90a83da7bef0a4e40cb489a7f7b84d5c8302ab"),
    "forward_delta_b4": (46_536, "948dfd9e5dfe8c46c4bcedab240479cf51e2d4abd9ec87a7466405234fd1b5b4"),
    "forward_delta_b8": (93_408, "fd303ac5cb23e5498dc6e8fb20fa71424c5b4ec975aea355738423e208de2eee"),
}

STATISTICS = {
    "split4_full_b1": {
        "rlimit-count": 10_000_534,
        "sat-conflicts": 29_385,
        "sat-decisions": 35_285,
        "sat-propagations-2ary": 3_082_948,
        "sat-propagations-nary": 7_410_764,
        "sat-restarts": 2_717,
    },
    "split4_full_b2": {
        "rlimit-count": 10_001_014,
        "sat-conflicts": 1_514,
        "sat-decisions": 3_028,
        "sat-propagations-2ary": 2_963_771,
        "sat-propagations-nary": 6_611_011,
        "sat-restarts": 125,
    },
    "split4_full_b4": {
        "rlimit-count": 10_001_974,
        "sat-conflicts": 575,
        "sat-decisions": 1_417,
        "sat-propagations-2ary": 2_997_368,
        "sat-propagations-nary": 5_679_663,
        "sat-restarts": 42,
    },
    "split4_full_b8": {
        "rlimit-count": 10_003_894,
        "sat-conflicts": 389,
        "sat-decisions": 1_686,
        "sat-propagations-2ary": 2_765_656,
        "sat-propagations-nary": 4_313_189,
        "sat-restarts": 77,
    },
    "split4_sparse512_b2": {
        "rlimit-count": 10_001_014,
        "sat-conflicts": 25_267,
        "sat-decisions": 28_987,
        "sat-propagations-2ary": 3_358_773,
        "sat-propagations-nary": 7_191_469,
        "sat-restarts": 4_376,
    },
    "split4_sparse512_b4": {
        "rlimit-count": 10_001_974,
        "sat-conflicts": 3_096,
        "sat-decisions": 7_600,
        "sat-propagations-2ary": 2_324_555,
        "sat-propagations-nary": 7_419_649,
        "sat-restarts": 381,
    },
    "split4_sparse512_b8": {
        "rlimit-count": 10_003_894,
        "sat-conflicts": 4_276,
        "sat-decisions": 9_185,
        "sat-propagations-2ary": 2_408_096,
        "sat-propagations-nary": 7_050_475,
        "sat-restarts": 722,
    },
    "forward_delta_b2": {
        "rlimit-count": 10_001_014,
        "sat-conflicts": 5_785,
        "sat-decisions": 16_155,
        "sat-propagations-2ary": 2_589_628,
        "sat-propagations-nary": 6_696_591,
        "sat-restarts": 841,
    },
    "forward_delta_b4": {
        "rlimit-count": 10_001_974,
        "sat-conflicts": 8_152,
        "sat-decisions": 13_793,
        "sat-propagations-2ary": 2_703_874,
        "sat-propagations-nary": 5_330_149,
        "sat-restarts": 1_384,
    },
    "forward_delta_b8": {
        "rlimit-count": 10_003_894,
        "sat-conflicts": 548,
        "sat-decisions": 9_796,
        "sat-propagations-2ary": 2_033_340,
        "sat-propagations-nary": 2_608_075,
        "sat-restarts": 72,
    },
}


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a187_protocol_and_fresh_eight_block_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == "frozen_before_any_A187_solver_execution"
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A186"]["sha256"] == MODULE.A186_SHA256
    assert protocol["anchors"]["A186"]["causal_sha256"] == MODULE.A186_CAUSAL_SHA256
    assert protocol["prospective_prediction"]["claim_type"] == (
        "prospective_shared_key_causal_stacking_transfer"
    )
    assert protocol["prospective_prediction"]["frozen_before_solver_execution"] is True
    boundary = protocol["information_boundary"]
    assert boundary["unknown_assignment_generated_once_from_os_randomness"] is True
    assert boundary["unknown_assignment_used_only_to_form_eight_public_targets_before_freeze"] is True
    assert boundary["unknown_assignment_persisted_before_execution"] is False
    assert boundary["unknown_assignment_in_protocol_or_source"] is False
    assert boundary["unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["A187_solver_outcomes_used_before_protocol_freeze"] is False
    assert boundary["variant_order_or_budget_changed_after_any_outcome"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["solver_execution_started"] is False


def test_a187_public_challenge_derivation_targets_and_secret_structure(
    analysis: dict[str, Any],
) -> None:
    challenge = analysis["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
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
        "3601335d1f54c775dfed03db9421ab83965d2c07407ac796ed89b686fe0da488"
    )
    assert int(words[0]) & 0xFFFFFF00 == challenge["known_key_word1_upper24"]
    assert [int(value) for value in words[1:7]] == challenge["known_key_words_2_through_7"]
    assert int(words[7]) == challenge["counter_start"]
    assert [int(value) for value in words[8:11]] == challenge["nonce_words"]

    assert len(challenge["target_words"]) == 8
    for target, expected in zip(
        challenge["target_words"], challenge["target_block_sha256"], strict=True
    ):
        raw = np.array(target, dtype="<u4").tobytes()
        assert hashlib.sha256(raw).hexdigest() == expected
    control = np.array(challenge["control_target_words"], dtype="<u4")
    assert hashlib.sha256(control.tobytes()).hexdigest() == (
        challenge["control_target_block_sha256"]
    )
    assert challenge["control_target_words"][0] == challenge["target_words"][0][0] ^ 1
    assert challenge["control_target_words"][1:] == challenge["target_words"][0][1:]

    forbidden_fields = {
        "unknown_assignment",
        "unknown_key_word0",
        "unknown_key_word1_low_value",
        "secret",
        "ground_truth",
    }
    assert forbidden_fields.isdisjoint(challenge)
    source = MODULE_PATH.read_text().lower()
    assert "import secrets" not in source
    assert "os.urandom" not in source
    assert "token_bytes" not in source


def test_a187_reconstructs_all_ten_formula_bytes_without_solver(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["variants"] == list(MODULE.VARIANTS)
    assert plan["variant_execution_order"] == list(MODULE.VARIANTS)
    assert plan["z3_rlimit_per_variant"] == 10_000_000
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    observed = analysis["formula_plan"]
    assert MODULE._canonical_sha256(observed) == FORMULA_PLAN_SHA256
    assert [row["variant"] for row in observed] == list(MODULE.VARIANTS)
    for row in observed:
        formula = analysis["formulas"][row["variant"]]
        expected_bytes, expected_sha = FORMULA_IDENTITY[row["variant"]]
        assert len(formula.encode()) == expected_bytes == row["bytes"]
        assert hashlib.sha256(formula.encode()).hexdigest() == expected_sha == row["sha256"]
        assert "(set-option :rlimit 10000000)" in formula
        assert formula.count("(check-sat-using ") == 1
        assert formula.endswith("(get-value (k0 lo8))\n")
        assert "(declare-fun lo8 () (_ BitVec 8))" in formula
        assert "(declare-fun k0 () (_ BitVec 32))" in formula


def test_a187_retained_execution_statistics_and_search_shape_are_exact(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A187"
    assert payload["evidence_stage"] == (
        "PROSPECTIVE_SHARED_KEY_CAUSAL_STACKING_TRANSFER_RETAINED"
    )
    assert payload["protocol_gate"]["artifact_sha256"] == MODULE.PROTOCOL_SHA256
    assert payload["anchor_gates"]["A186_result_sha256"] == MODULE.A186_SHA256
    assert payload["anchor_gates"]["A186_causal_sha256"] == MODULE.A186_CAUSAL_SHA256
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan"] == analysis["execution_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["status"] for row in observations] == ["unknown"] * 10
    assert [row["statistics"] for row in observations] == [
        STATISTICS[variant] for variant in MODULE.VARIANTS
    ]
    assert all(row["model"] is None for row in observations)
    assert all(row["returncode"] == 1 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_assignment_count"] == 0
    assert execution["fully_confirmed_assignments"] == []
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == payload["execution_sha256"] == EXECUTION_SHA256

    comparisons = payload["comparisons"]
    assert comparisons == {
        "fixed_512_bit_sparse_winners": [
            "split4_sparse512_b2",
            "split4_sparse512_b4",
            "split4_sparse512_b8",
        ],
        "fixed_rlimit": 10_000_000,
        "full_b1": {"conflicts": 29_385, "decisions": 35_285},
        "full_b8": {"conflicts": 389, "decisions": 1_686},
        "primary_prediction_retained": True,
        "prospective_prediction_retained": True,
        "secondary_prediction_retained": True,
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert 35_285 / 1_686 == pytest.approx(20.928232502966786)
    assert 29_385 / 389 == pytest.approx(75.53984575835475)
    baseline = STATISTICS["split4_full_b1"]
    for variant in comparisons["fixed_512_bit_sparse_winners"]:
        assert STATISTICS[variant]["sat-decisions"] < baseline["sat-decisions"]
        assert STATISTICS[variant]["sat-conflicts"] < baseline["sat-conflicts"]

    assert payload["confirmations"] == []
    assert MODULE._canonical_sha256([]) == payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a187_causal_reader_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    ids = [
        "chacha20-a186-round5-single-block-boundary",
        "chacha20-a187-fresh-eight-block-challenge",
        "chacha20-a187-stacking-compression-delta-formulas",
        "chacha20-a187-fixed-rlimit-complete-execution",
        "chacha20-a187-prospective-search-shape-transfer",
        "chacha20-a187-independent-model-confirmation",
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
