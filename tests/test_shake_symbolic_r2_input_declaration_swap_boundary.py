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
    / "shake_symbolic_r2_input_declaration_swap_boundary.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_input_declaration_swap_boundary_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_input_declaration_swap_boundary_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_input_declaration_swap_boundary_v1.causal"
RESULT_SHA256 = "4b609a6f4388c9a759625169aebe94309b808608e061b4f033c66a22cc992a60"
CAUSAL_SHA256 = "fbd04db4d0bb5a70924858308d69a9bf85dc679a605218adcdb406d052848e9a"
CAUSAL_GRAPH_SHA256 = "e0ef3a520cb0d02575cde8d40f9b2a04f1ab1d967371399763c6785d46022e90"
SWAP_SHA256 = "4825c92d507e2f06341ce01f170e206cf1a282bb777148142974d44eae409f1a"
EXPECTED_FORMULAS = [
    (
        "declaration_swap_x11_x12__weighted_desc_center_22_before_12__inline_negative_alias",
        "22_before_12",
        "inline",
        8_899_711,
        "dbdd463461907e309aa845a05668d3ef599acc861651009374fdc0f8af8464af",
    ),
    (
        "declaration_swap_x11_x12__weighted_desc_center_22_before_12__materialized_negative_alias",
        "22_before_12",
        "materialized",
        8_899_767,
        "f51ea8bd7412fc4b0f8790a4fe7256b095b7de0ad886a5c416103ec47c705ed5",
    ),
    (
        "declaration_swap_x11_x12__weighted_desc_center_12_before_22__inline_negative_alias",
        "12_before_22",
        "inline",
        8_899_711,
        "f7c7eb8d643ff3027ce13623250d2d33cadb73076ed75e8bbf404d784d9c9253",
    ),
    (
        "declaration_swap_x11_x12__weighted_desc_center_12_before_22__materialized_negative_alias",
        "12_before_22",
        "materialized",
        8_899_767,
        "3413f4208cd9b2470d0b31b13071985cda95831742515e1a51c0218a6241e7ee",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_declaration_prediction_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "3b8012e534608fdc3862100f219b19db035db082468f351dacd6998ce1354683"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A176_solver_execution"
    assert protocol["anchors"]["A175"]["sha256"] == MODULE.A175_SHA256
    assert protocol["anchors"]["A174"]["sha256"] == MODULE.A174_SHA256
    assert protocol["declaration_intervention"]["semantic_change"] is False
    assert protocol["declaration_intervention"]["swapped_input_names"] == ["x11", "x12"]
    assert protocol["prospective_prediction"]["direction"] == (
        "declaration_swapped_directional_delta_remains_strictly_positive"
    )
    assert (
        protocol["information_boundary"]["A176_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["declaration_plan_sha256"] == (
        "d52797f854631ebab0c2ce26bfc87d75cf62afa5f18e0d6289b3298f1f4753a9"
    )
    assert analysis["formula_plan_sha256"] == (
        "d7aaafcd4a03708f44b946172b28b7e0c7871f00b01f57c81972ec22de40c21d"
    )


def test_declaration_swap_changes_only_lines_11_and_12(
    analysis: dict[str, Any],
) -> None:
    for row in analysis["declaration_plan"]:
        assert row["declaration_count"] in (121_575, 121_576)
        assert row["changed_declaration_indices_zero_based"] == [11, 12]
        assert row["changed_lines"] == [["x11", "x12"], ["x12", "x11"]]
        assert row["declaration_multiset_preserved"] is True
        assert row["formula_bytes_preserved"] is True
        assert row["all_assertion_bytes_preserved"] is True
        assert row["graph_topology_preserved"] is True
        assert row["symbol_names_preserved"] is True
        assert row["solver_input_get_value_order_preserved"] is True
        assert row["second_swap_recovers_original_bytes"] is True
        assert row["declaration_swap_sha256"] == (
            "4825c92d507e2f06341ce01f170e206cf1a282bb777148142974d44eae409f1a"
        )


def test_four_exact_declaration_swapped_formulas(analysis: dict[str, Any]) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected in zip(analysis["rows"], EXPECTED_FORMULAS, strict=True):
        name, orientation, arm, size, formula_sha = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["adjacent_orientation"] == orientation
        assert encoding["alias_compiler_arm"] == arm
        assert encoding["declaration_swap_sha256"] == (
            "4825c92d507e2f06341ce01f170e206cf1a282bb777148142974d44eae409f1a"
        )
        assert encoding["declaration_swap_graph_isomorphic_to_A174"] is True
        assert encoding["declaration_swap_inverse_recovers_A174_formula_bytes"] is True
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["target_rate_bits"] == 1_344
        assert row["solver_input_names"][:3] == ["x0", "x1", "x2"]
        assert row["solver_input_names"][-1] == "x23"
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_declaration_swap"] is False


def test_all_four_swapped_model_maps_recover_complete_rate_witness(
    analysis: dict[str, Any],
) -> None:
    input_assignment = 9_279_571
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
                dict(row),
                {"status": "sat", "solver_basis_assignment": solver_assignment ^ 1},
                analysis["problem"],
                analysis["variant"],
            )


def _synthetic_executions(
    a174: dict[str, Any],
    decisions: list[int],
    *,
    exact_hashes: bool,
) -> list[dict[str, Any]]:
    rows = []
    for index, (source, decision) in enumerate(
        zip(a174["execution_summary"], decisions, strict=True)
    ):
        rows.append(
            {
                "name": f"swap-{index}",
                "encoding": {
                    "A174_formula_name": source["name"],
                    "adjacent_orientation": source["adjacent_orientation"],
                    "alias_compiler_arm": source["alias_compiler_arm"],
                },
                "solver": {
                    "stats": {"decisions": decision},
                    "canonical_observation_sha256": (
                        source["canonical_observation_sha256"]
                        if exact_hashes
                        else f"changed-{index}"
                    ),
                },
            }
        )
    return rows


def test_classifier_separates_exact_directional_and_order_conditioned_results(
    analysis: dict[str, Any],
) -> None:
    _a175, a174 = analysis["anchors"]
    original = [row["stats"]["decisions"] for row in a174["execution_summary"]]
    exact = MODULE._declaration_boundary_result(
        a174,
        _synthetic_executions(a174, original, exact_hashes=True),
    )
    assert exact["classification"] == "exact_input_declaration_order_invariance"
    assert exact["all_four_canonical_observations_exactly_equal"] is True
    assert exact["declaration_swapped_directional_delta"] == 2_196

    robust = MODULE._declaration_boundary_result(
        a174,
        _synthetic_executions(a174, [10_000, 9_000, 10_000, 10_500], exact_hashes=False),
    )
    assert robust["classification"] == "central_boundary_declaration_order_robust"
    assert robust["declaration_swapped_directional_delta"] == 1_500

    conditioned = MODULE._declaration_boundary_result(
        a174,
        _synthetic_executions(a174, [10_000, 10_500, 10_000, 9_000], exact_hashes=False),
    )
    assert conditioned["classification"] == "input_declaration_order_conditioned"
    assert conditioned["declaration_swapped_directional_delta"] == -1_500


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


def test_retained_a176_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A176"
    assert payload["evidence_stage"] == "INPUT_DECLARATION_SWAP_BOUNDARY_EXECUTED"
    assert payload["anchor_gates"]["A176_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A175"]["artifact_sha256"] == MODULE.A175_SHA256
    assert payload["anchor_gates"]["A174"]["artifact_sha256"] == MODULE.A174_SHA256
    assert payload["declaration_plan_sha256"] == (
        "d52797f854631ebab0c2ce26bfc87d75cf62afa5f18e0d6289b3298f1f4753a9"
    )
    assert payload["formula_plan_sha256"] == (
        "d7aaafcd4a03708f44b946172b28b7e0c7871f00b01f57c81972ec22de40c21d"
    )
    assert payload["declaration_boundary_result_sha256"] == (
        "69055a782b8db1102d136004a7719a05fbd5c10fd918c2b8ff7a8f90321b727a"
    )
    assert payload["declaration_plan"] == analysis["declaration_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
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
            "binary-propagations": 116_972_499,
            "conflicts": 3_254,
            "decisions": 10_816,
            "propagations": 445_011_981,
            "restarts": 7,
            "rlimit-count": 501_080_358,
        },
        {
            "binary-propagations": 118_298_028,
            "conflicts": 2_448,
            "decisions": 6_837,
            "propagations": 444_884_491,
            "restarts": 8,
            "rlimit-count": 501_080_363,
        },
        {
            "binary-propagations": 117_401_951,
            "conflicts": 2_709,
            "decisions": 7_772,
            "propagations": 444_962_807,
            "restarts": 11,
            "rlimit-count": 501_080_360,
        },
        {
            "binary-propagations": 118_839_272,
            "conflicts": 2_294,
            "decisions": 5_989,
            "propagations": 444_843_918,
            "restarts": 10,
            "rlimit-count": 501_080_365,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "853a9f7869ebbea665673516846a950b52311a447631618e6b16db07ad99e76c",
        "f1c75c74b3b1fa8cd25f5185903e69cbebf4be5372af66b9b840a0684a263ccc",
        "7b455072d1093fe14f170f7814c2ae3f4c792ba71efc449851643f7f78937633",
        "4c42ebd4fdd0c1184aefe3f05377c0e018cfae0645837cb302f38525ccf53d7c",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    result = payload["declaration_boundary_result"]
    assert [row["A174_decisions"] for row in result["decision_rows"]] == [
        10_816,
        6_837,
        7_772,
        5_989,
    ]
    assert [row["declaration_swapped_decisions"] for row in result["decision_rows"]] == [
        10_816,
        6_837,
        7_772,
        5_989,
    ]
    assert [row["decision_delta_swap_minus_A174"] for row in result["decision_rows"]] == [
        0,
        0,
        0,
        0,
    ]
    assert all(
        row["canonical_observation_exactly_equal"] is True for row in result["decision_rows"]
    )
    assert [
        (
            row["adjacent_orientation"],
            row["inline_decisions"],
            row["materialized_decisions"],
            row["materialization_effect"],
        )
        for row in result["effect_rows"]
    ] == [
        ("22_before_12", 10_816, 6_837, -3_979),
        ("12_before_22", 7_772, 5_989, -1_783),
    ]
    assert result["A174_directional_delta"] == 2_196
    assert result["declaration_swapped_directional_delta"] == 2_196
    assert result["directional_delta_change"] == 0
    assert result["all_four_canonical_observations_exactly_equal"] is True
    assert result["classification"] == "exact_input_declaration_order_invariance"
    assert result["prospective_prediction_confirmed"] is True

    plan_rows = payload["declaration_plan"]
    assert all(row["changed_declaration_indices_zero_based"] == [11, 12] for row in plan_rows)
    assert all(row["changed_lines"] == [["x11", "x12"], ["x12", "x11"]] for row in plan_rows)
    assert all(row["all_assertion_bytes_preserved"] for row in plan_rows)
    assert all(row["solver_input_get_value_order_preserved"] for row in plan_rows)
    assert all(row["second_swap_recovers_original_bytes"] for row in plan_rows)
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
        "shake128-a175-alpha-robust-center-boundary",
        "shake128-a176-x11-x12-declaration-swap",
        "shake128-a176-four-declaration-isomorphic-formulas",
        "shake128-a176-fixed-resource-declaration-execution",
        "shake128-a176-declaration-boundary-result",
    ]
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
