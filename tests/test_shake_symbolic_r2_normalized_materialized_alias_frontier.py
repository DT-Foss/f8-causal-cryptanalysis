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
    / "shake_symbolic_r2_normalized_materialized_alias_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_normalized_materialized_alias_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_normalized_materialized_alias_frontier_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_normalized_materialized_alias_frontier_v1.causal"
RESULT_SHA256 = "becb3013cb079c2d45ee2a297d2847d5d85542843cb598e5b6288dc45b9eab76"
CAUSAL_SHA256 = "a26f1fe696cc842a93e08d230c2d9707cf13b2670be359212f49e9e7685a2277"
CAUSAL_GRAPH_SHA256 = "c1fe0277fa2d792f0c9f72cf1b2d4c0ad4eb264b6dcc328edb3e619d8b66a2c0"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__normalized_materialized_alias",
        8_899_767,
        "08c9b39e856abf5cfcb63b88b9f2170a218419aeb15ab7d50ff5590d3f463d8d",
        "x10",
        "ece2e1c5a0bf46cd1b02e6084c712a313249108e5b4aacdd01a3561ae52bc955",
        "A164",
    ),
    (
        "weighted_degree_ascending__normalized_materialized_alias",
        8_900_275,
        "ef43719f879ffa43d79ef60deefdc9a4ef3854fc9cc6b17e4f2c9652bc7b5729",
        "x14",
        "9e0ec4c438cf69266fb6b922cb7e80f3d812908c69d83d83badb7f6988ff4a34",
        "A164",
    ),
    (
        "greedy_max_remaining_weight__normalized_materialized_alias",
        8_899_751,
        "4dbe647c784bda9b81cc6f1dbc945a56d5e4903b5cfd3d699eebaa1c291a3162",
        "x8",
        "7c2fe88c88928bb949fb81b8ebc0bd8b7d57eeb877695946183133d42a275300",
        "A163",
    ),
    (
        "greedy_min_remaining_weight__normalized_materialized_alias",
        8_900_254,
        "3b65d808d948823f700e3c0868fedf8f22a1b49501cae73b87b17552b7da3a72",
        "x9",
        "44ce0cdc5fcc98cb9d4f72eaf94ea08c25b6a87ea27d297af68c36bf3898c5a8",
        "A164",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_the_single_assertion_three_arm_question(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "b2f19699536817ed64ef31cf80015ab5ab7fb977b4f670a8682740ea99c0f7ab"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A168_solver_execution"
    assert protocol["anchors"]["A167"]["sha256"] == MODULE.A167_SHA256
    assert protocol["anchors"]["A166"]["sha256"] == MODULE.A166_SHA256
    assert protocol["anchors"]["A164"]["sha256"] == MODULE.A164_SHA256
    assert protocol["intervention"]["semantic_change"] is False
    assert protocol["intervention"]["changed_assertions_per_formula"] == 1
    assert (
        protocol["information_boundary"]["A168_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["intervention_plan_sha256"] == (
        "2c732672fdbe0ef5cb5549a3b5b73ac6c8042762d411032575cf54b1184c6944"
    )
    assert analysis["formula_plan_sha256"] == (
        "ee4cad05d03be839c54034076272e71b1426b34975e943b66597479a9bb17db9"
    )


def test_each_formula_changes_exactly_one_alias_RHS_assertion(
    analysis: dict[str, Any],
) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, intervention, expected in zip(
        analysis["rows"], analysis["intervention_plan"], EXPECTED_FORMULAS, strict=True
    ):
        name, size, formula_sha256, input_name, rewrite_sha256, source = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha256
        assert encoding["original_control_source_attempt"] == source
        assert encoding["changed_line_count_relative_to_original"] == 1
        assert encoding["single_rewrite"] == {
            "line_index_zero_based": 2_410,
            "old_line": f"(assert (= s1215 (xor true {input_name})))",
            "new_line": f"(assert (= s1215 (not {input_name})))",
        }
        assert encoding["single_rewrite_sha256"] == rewrite_sha256
        assert encoding["declaration_sequence_sha256"] == (
            "6ae51cff0ad3707df512db5933edd29dac9bf981b89b0201962ab1c1d79cfd61"
        )
        assert encoding["total_variables"] == 121_576
        assert encoding["total_assertions"] == 122_896
        assert intervention["declaration_sequences_identical"] is True
        assert intervention["total_variables_identical"] is True
        assert intervention["total_assertions_identical"] is True
        assert intervention["semantic_relation_unchanged"] is True


def test_normalized_alias_remains_one_connected_state_definition(
    analysis: dict[str, Any],
) -> None:
    for row in analysis["rows"]:
        encoding = row["encoding"]
        raw = analysis["formulas"][row["name"]]
        input_name = encoding["R2_normalized_materialized_inputs"][0]
        assert encoding["R2_state_definitions"] == 1_596
        assert encoding["R2_direct_alias_coordinates"] == [453, 516, 990, 1_454]
        assert encoding["R2_normalized_materialized_coordinates"] == [917]
        assert encoding["R2_normalized_materialized_names"] == ["s1215"]
        definition = f"(assert (= s1215 (not {input_name})))\n".encode()
        assert raw.count(definition) == 1
        assert sum(b"s1215" in line for line in raw.splitlines()) > 2


def test_all_four_model_maps_recover_the_complete_rate_witness(
    analysis: dict[str, Any],
) -> None:
    input_assignment = 9_279_571
    solver_assignment = 0
    for row in analysis["rows"]:
        shift = row["encoding"]["affine_shift_original_input_mask"]
        shifted_assignment = input_assignment ^ shift
        solver_assignment = sum(
            ((shifted_assignment >> input_coordinate) & 1) << solver_coordinate
            for solver_coordinate, input_coordinate in enumerate(
                row["encoding"]["variable_to_shifted_input_coordinate"]
            )
        )
        verified = MODULE._A163._verify_solver_row(
            dict(row),
            {"status": "sat", "solver_basis_assignment": solver_assignment},
            analysis["problem"],
            analysis["variant"],
        )
        assert verified["input_coordinate_assignment"] == input_assignment
        assert verified["independent_complete_rate_check"]["complete_rate_match"] is True

    with pytest.raises(RuntimeError, match="independently invalid"):
        MODULE._A163._verify_solver_row(
            dict(analysis["rows"][-1]),
            {"status": "sat", "solver_basis_assignment": solver_assignment ^ 1},
            analysis["problem"],
            analysis["variant"],
        )


def test_effect_decomposition_is_an_exact_per_order_identity(
    analysis: dict[str, Any],
) -> None:
    _a167, a166, a164, _a162 = analysis["anchors"]
    prospective_decisions = [6_000, 4_000, 6_000, 6_000]
    executions = [
        {
            "encoding": {"order_name": order_name},
            "solver": {"stats": {"decisions": decisions}},
        }
        for order_name, decisions in zip(
            MODULE._A158.ORDER_NAMES, prospective_decisions, strict=True
        )
    ]
    decomposition = MODULE._effect_decomposition(a164, a166, executions)
    assert [row["RHS_syntax_effect_A168_minus_A164"] for row in decomposition["rows"]] == [
        661,
        -402,
        -870,
        -505,
    ]
    assert [
        row["connected_node_removal_effect_A166_minus_A168"] for row in decomposition["rows"]
    ] == [1_347, -575, -753, -677]
    assert [row["total_A166_minus_A164"] for row in decomposition["rows"]] == [
        2_008,
        -977,
        -1_623,
        -1_182,
    ]
    assert all(row["exact_additive_identity_verified"] for row in decomposition["rows"])


def test_executor_accepts_only_proven_fixed_resource_termination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = b"(check-sat)\n"
    row = {
        "name": "fixed",
        "execution_order": 0,
        "formula_bytes": len(raw),
        "formula_sha256": MODULE._sha256(raw),
        "solver_input_names": [],
        "encoding": {},
    }
    result = {
        "status": "unknown",
        "solver_basis_assignment": None,
        "stats": {"rlimit-count": MODULE.Z3_RLIMIT + 1},
        "return_code": 1,
        "termination": "fixed_rlimit_exhausted",
    }
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(result))
    monkeypatch.setattr(
        MODULE._A163,
        "_verify_solver_row",
        lambda row, solver, *_args: {**row, "solver": solver},
    )
    executions = MODULE._execute_frontier(
        formula_rows=[row],
        formulas={"fixed": raw},
        problem={},
        variant=None,
        z3=Path("/fake/z3"),
        work_dir=tmp_path / "accepted",
    )
    assert executions[0]["solver"] == result
    assert list((tmp_path / "accepted").iterdir()) == []

    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: {**result, "return_code": 2})
    with pytest.raises(RuntimeError, match="fixed-resource execution failed"):
        MODULE._execute_frontier(
            formula_rows=[row],
            formulas={"fixed": raw},
            problem={},
            variant=None,
            z3=Path("/fake/z3"),
            work_dir=tmp_path / "rejected",
        )


def test_retained_a168_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A168"
    assert payload["evidence_stage"] == (
        "NORMALIZED_MATERIALIZED_ALIAS_COMPONENT_DECOMPOSITION_EXECUTED"
    )
    assert payload["anchor_gates"]["A168_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A167"] == {
        "artifact_sha256": MODULE.A167_SHA256,
        "downstream_ID_shift_effect_L1": 0,
        "effect_decomposition_sha256": MODULE.A167_DECOMPOSITION_SHA256,
    }
    assert payload["anchor_gates"]["A166"]["artifact_sha256"] == (MODULE.A166_SHA256)
    assert payload["anchor_gates"]["A164"]["artifact_sha256"] == (MODULE.A164_SHA256)
    assert payload["intervention_plan_sha256"] == (
        "2c732672fdbe0ef5cb5549a3b5b73ac6c8042762d411032575cf54b1184c6944"
    )
    assert payload["formula_plan_sha256"] == (
        "ee4cad05d03be839c54034076272e71b1426b34975e943b66597479a9bb17db9"
    )
    assert payload["effect_decomposition_sha256"] == (
        "138cfc343738d5d5ad4a52ebb7825c1932ad2ef314f0cdfbd7f228097b774f48"
    )
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []

    summaries = payload["execution_summary"]
    assert [row["name"] for row in summaries] == [row[0] for row in EXPECTED_FORMULAS]
    assert [row["stats"] for row in summaries] == [
        {
            "binary-propagations": 119_108_978,
            "conflicts": 2_222,
            "decisions": 5_339,
            "propagations": 444_833_576,
            "restarts": 2,
            "rlimit-count": 501_080_369,
        },
        {
            "binary-propagations": 119_185_158,
            "conflicts": 2_189,
            "decisions": 4_402,
            "propagations": 446_080_239,
            "restarts": 6,
            "rlimit-count": 501_079_875,
        },
        {
            "binary-propagations": 118_778_683,
            "conflicts": 2_431,
            "decisions": 6_870,
            "propagations": 444_872_402,
            "restarts": 3,
            "rlimit-count": 501_080_261,
        },
        {
            "binary-propagations": 117_961_641,
            "conflicts": 3_292,
            "decisions": 6_505,
            "propagations": 446_410_890,
            "restarts": 4,
            "rlimit-count": 501_079_923,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "2642afbf9c2658785db4a3d59dd8174a02a76f2c8d324d9ea0a1300d6a84331d",
        "bc3d35fc887cbf22849d38b04e5af82d69a110743bd84a54726af1d53be95d2a",
        "0e00325f48483c82c2e42cfac54d84e581b165f7313011bd53d907fca0fa05bf",
        "ed01a0daf54341fd2ead04360dbb645970e03a881bde8cef044385710a5326ad",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)

    a164_raw = (RESULTS_DIR / MODULE.A164_FILENAME).read_bytes()
    assert hashlib.sha256(a164_raw).hexdigest() == MODULE.A164_SHA256
    original = {
        row["order_name"]: row
        for row in json.loads(a164_raw)["full_factorial_matrix"]
        if row["affine_shift"] == MODULE.AFFINE_SHIFT
    }
    assert [row["canonical_observation_sha256"] for row in summaries[:3]] == [
        original[row["order_name"]]["canonical_observation_sha256"] for row in summaries[:3]
    ]
    greedy_min_control = original["greedy_min_remaining_weight"]
    assert summaries[3]["stats"]["decisions"] == greedy_min_control["decisions"]
    assert summaries[3]["stats"]["conflicts"] == greedy_min_control["conflicts"]
    assert summaries[3]["stats"]["restarts"] == 4
    assert summaries[3]["stats"]["rlimit-count"] == greedy_min_control["rlimit_count"]
    assert summaries[3]["stats"]["propagations"] - 446_410_812 == 78
    assert summaries[3]["stats"]["binary-propagations"] - 117_961_670 == -29
    assert (
        summaries[3]["canonical_observation_sha256"]
        != (greedy_min_control["canonical_observation_sha256"])
    )

    decomposition = payload["effect_decomposition"]
    assert decomposition["RHS_syntax_effect_L1"] == 0
    assert decomposition["connected_node_removal_effect_L1"] == 5_790
    assert decomposition["aggregate_dominant_component"] == "connected_node_removal"
    rows = decomposition["rows"]
    assert [row["A164_xor_materialized_decisions"] for row in rows] == [
        5_339,
        4_402,
        6_870,
        6_505,
    ]
    assert [row["A168_not_materialized_decisions"] for row in rows] == [
        5_339,
        4_402,
        6_870,
        6_505,
    ]
    assert [row["A166_not_inlined_decisions"] for row in rows] == [
        7_347,
        3_425,
        5_247,
        5_323,
    ]
    assert [row["RHS_syntax_effect_A168_minus_A164"] for row in rows] == [0, 0, 0, 0]
    assert [row["connected_node_removal_effect_A166_minus_A168"] for row in rows] == [
        2_008,
        -977,
        -1_623,
        -1_182,
    ]
    assert all(row["exact_additive_identity_verified"] for row in rows)

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A168_execution"] is True
    assert payload["posthoc"]["used_for_intervention_formula_order_or_execution"] is False
    assert all(
        row["model_matches_instrumented_input_assignment"] is None
        for row in payload["posthoc"]["model_matches"]
    )

    lowered = raw.decode().lower()
    for volatile_field in (
        '"wallclock_seconds"',
        '"elapsed_seconds"',
        '"peak_memory',
        '"memory_bytes"',
        '"allocations"',
        '"stdout_sha256"',
        '"stderr_sha256"',
    ):
        assert volatile_field not in lowered

    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    causal_rows = reader.triplets(include_inferred=False)
    assert len(causal_rows) == 5
    by_id = {row["edge_id"]: row for row in causal_rows}
    ids = [
        "shake128-a167-connected-alias-node-mechanism",
        "shake128-a168-single-RHS-rewrite",
        "shake128-a168-four-normalized-materialized-formulas",
        "shake128-a168-fixed-resource-execution",
        "shake128-a168-syntax-node-effect-decomposition",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
