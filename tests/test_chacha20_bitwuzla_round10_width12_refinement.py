from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "chacha20_bitwuzla_round10_width12_refinement.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_bitwuzla_round10_width12_refinement_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ROOT = Path(__file__).parents[1]
RESULTS_DIR = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = (
    ROOT / "research" / "configs" / "chacha20_bitwuzla_round10_width12_refinement_v1.json"
)
RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width12_refinement_v1.json"
CAUSAL_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width12_refinement_v1.causal"
A195_RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
A196_RESULT_PATH = RESULTS_DIR / "chacha20_bitwuzla_round10_split9_transfer_v1.json"

RUNNER_SHA256 = "df45551daa0abb67337061bded931f54b3c18d6dedecf6a1f40f09104eab2fa6"
RESULT_SHA256 = "177a76c130d3705e8e3ebcd35f517486b204c6f7d501adaae1cdba8dca90060c"
CAUSAL_SHA256 = "f180d14b244a91d5dcbe22acd4972590d9facfb8099ee8846fb3d0d5cae92561"
CAUSAL_GRAPH_SHA256 = "c533fd9ce46f3db8cbe444d24cb0228391ee325cf09ad7cc4d74477658b28879"
EXECUTION_PLAN_SHA256 = "65a0f30c1c6b45f2d3bafca613460ef921a34c35b47274459cbceb2968120329"
FORMULA_PLAN_SHA256 = "5307cfeb49b31cc0f6ad6178d1cf99d0e8d3640003bfcadbba72191722e8c076"
EXECUTION_SHA256 = "784676f6de00e328c190b5bcd23485cd5e01e54a5d803b06532ee1d347230ee1"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "9c284d155210f6aab491ab65299e269616d46ff8f49f873f0a59dfe40c71e299"
A195_CAUSAL_GRAPH_SHA256 = "552018924f0fdb83e82ed507aa6301440d1c46dba8e4ea992406905c73e80f01"
A196_CAUSAL_GRAPH_SHA256 = "9d1909f592c522e0841ff0d9bb79c14011213e7e69715ccab302e9225899eb54"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_a197_frozen_protocol_runner_and_width15_anchors_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    assert hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest() == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_complete_A195_A196_boundaries_before_any_A197_solver_execution"
    )
    assert protocol["public_challenge_sha256"] == MODULE.PUBLIC_CHALLENGE_SHA256
    assert protocol["anchors"]["A195"]["sha256"] == MODULE.A195_SHA256
    assert protocol["anchors"]["A196"]["sha256"] == MODULE.A196_SHA256
    assert protocol["anchors"]["A195"]["returned_model_count"] == 0
    assert protocol["anchors"]["A196"]["returned_model_count"] == 0
    assert protocol["anchors"]["A195"]["statuses"] == "all_unknown"
    assert protocol["anchors"]["A196"]["statuses"] == "all_unknown"
    assert analysis["anchor_gates"] == {
        "A195_result_sha256": MODULE.A195_SHA256,
        "A195_causal_sha256": MODULE.A195_CAUSAL_SHA256,
        "A195_causal_graph_sha256": A195_CAUSAL_GRAPH_SHA256,
        "A195_causal_provenance_verified": True,
        "A196_result_sha256": MODULE.A196_SHA256,
        "A196_causal_sha256": MODULE.A196_CAUSAL_SHA256,
        "A196_causal_graph_sha256": A196_CAUSAL_GRAPH_SHA256,
        "A196_causal_provenance_verified": True,
        "complete_split8_split9_width15_boundaries_retained": True,
    }
    assert protocol["information_boundary"] == {
        "A197_solver_outcomes_used_before_protocol_freeze": False,
        "cell_order_wave_cut_or_budget_changed_after_any_A197_outcome": False,
        "early_stop_permitted": False,
        "prior_attempts_revealed_no_model_or_correct_prefix": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_assignment_in_protocol_or_source": False,
    }
    assert (
        protocol["challenge_reuse_boundary"]["public_challenge_reused_byte_for_byte_from_A195_A196"]
        is True
    )
    assert protocol["challenge_reuse_boundary"]["unknown_assignment_recovered_before_A197"] is False
    assert protocol["challenge_reuse_boundary"]["correct_prefix_known_before_A197"] is False
    assert analysis["solver_execution_started"] is False


def test_a197_refinement_preserves_the_complete_domain_and_secret_boundary(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    basis = protocol["refinement_basis"]
    assert basis == {
        "same_challenge_cut_factorial_complete": True,
        "split8_width15_cells": "32_of_32_unknown",
        "split9_width15_cells": "32_of_32_unknown",
        "refinement_rule": (
            "hold_the_full_2^20_domain_and_split8_semantics_fixed_while_increasing_fixed_prefix_bits_from_5_to_8"
        ),
        "source_cell_count": 32,
        "source_free_bits": 15,
        "target_cell_count": 256,
        "target_free_bits": 12,
        "target_candidate_count": 1 << 20,
        "pairwise_disjoint": True,
        "union_equals_original_domain": True,
        "assignment_used_for_partition_order_or_waves": False,
        "wave_rule": "consecutive_numeric_groups_of_four",
    }
    challenge = analysis["public_challenge"]
    a195 = json.loads(A195_RESULT_PATH.read_bytes())
    a196 = json.loads(A196_RESULT_PATH.read_bytes())
    assert challenge == a195["public_challenge"] == a196["public_challenge"]
    assert MODULE._canonical_sha256(challenge) == MODULE.PUBLIC_CHALLENGE_SHA256
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_key_word0_low_value_included"] is False


def test_a197_width12_partition_structurally_covers_complete_2pow20_domain(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    assert MODULE._canonical_sha256(plan) == EXECUTION_PLAN_SHA256
    assert plan == analysis["protocol"]["execution_plan"]
    assert plan["rounds"] == 10
    assert plan["unknown_key_bits"] == 20
    assert plan["known_key_bits"] == 236
    assert plan["partition_cell_count"] == 256
    assert plan["partition_cell_free_bits"] == 12
    assert plan["partition_fixed_bits"] == 8
    assert plan["partition_prefix_order"] == [f"{value:08b}" for value in range(256)]
    assert plan["formula_representation"] == (
        "portable_SMTLIB2_round10_split8_b1_complete_8bit_prefix_partition"
    )
    assert plan["max_parallel_workers"] == 4
    assert plan["wave_count"] == 64
    assert plan["wave_size"] == 4
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False

    formula_plan = analysis["formula_plan"]
    assert formula_plan == json.loads(RESULT_PATH.read_bytes())["formula_plan"]
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert len(formula_plan) == 256
    assert sum(row["candidate_count"] for row in formula_plan) == 1 << 20
    assert [row["prefix"] for row in formula_plan] == [f"{value:08b}" for value in range(256)]
    for index, row in enumerate(formula_plan):
        variant = MODULE.VARIANTS[index]
        formula = analysis["formulas"][variant]
        assert row["variant"] == variant
        assert row["candidate_count"] == 1 << 12
        assert row["fixed_key_coordinates"] == list(reversed(range(12, 20)))
        assert row["free_key_coordinates"] == list(reversed(range(12)))
        assert row["portable_smtlib2"] is True
        assert len(formula.encode()) == row["bytes"] == 23_072
        assert hashlib.sha256(formula.encode()).hexdigest() == row["sha256"]
        assert formula.count("(check-sat)") == 1
        assert f"(assert (= ((_ extract 19 12) k0) #b{index:08b}))" in formula
        assert "(assert (= lo8 #xab))" in formula
        assert "(assert (= ((_ extract 31 20) k0) #xcb3))" in formula


def test_a197_complete_wave_execution_retains_the_width12_boundary(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A197"
    assert payload["evidence_stage"] == "ROUND10_WIDTH12_REFINEMENT_BOUNDARY_RETAINED"
    assert payload["public_challenge"] == analysis["public_challenge"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    waves = execution["wave_observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["prefix"] for row in observations] == [f"{value:08b}" for value in range(256)]
    assert [row["status"] for row in observations] == ["unknown"] * 256
    assert all(row["candidate_count"] == 1 << 12 for row in observations)
    assert all(row["free_bits"] == 12 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["model"] is None for row in observations)
    assert len(waves) == 64
    for wave_index, wave in enumerate(waves):
        group = observations[wave_index * 4 : wave_index * 4 + 4]
        assert wave["wave_index"] == wave_index
        assert wave["variants"] == [row["variant"] for row in group]
        assert wave["statuses"] == ["unknown"] * 4
        assert wave["maximum_volatile_seconds"] == max(row["volatile_seconds"] for row in group)
    assert sum(row["volatile_seconds"] for row in observations) == 1282.9209600007161
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low20_assignments"] == []
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256

    assert payload["comparisons"] == {
        "complete_domain_candidate_count": 1 << 20,
        "confirmed_variants": [],
        "deterministic_wave_count": 64,
        "fully_confirmed_unknown_low20_assignments": [],
        "maximum_parallel_workers": 4,
        "original_domain_candidate_count": 1 << 20,
        "partition_complete_and_disjoint_by_construction": True,
        "prospective_prediction_retained": False,
        "statuses": {f"prefix_{value:08b}": "unknown" for value in range(256)},
    }
    assert MODULE._canonical_sha256(payload["comparisons"]) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a197_solver_provenance_and_causal_chain_are_exact() -> None:
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
    assert len(reader.graph["parameters"]) == 4
    rows = reader.triplets(include_inferred=False)
    ids = [
        "chacha20-a197-width15-cut-boundary-anchors",
        "chacha20-a197-still-secret-round10-challenge",
        "chacha20-a197-complete-width12-prefix-refinement",
        "chacha20-a197-complete-deterministic-wave-execution",
        "chacha20-a197-independent-model-confirmation",
        "chacha20-a197-prospective-refinement-transfer",
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
