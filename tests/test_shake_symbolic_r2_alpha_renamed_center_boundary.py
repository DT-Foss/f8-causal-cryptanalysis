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
    / "shake_symbolic_r2_alpha_renamed_center_boundary.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_alpha_renamed_center_boundary_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_alpha_renamed_center_boundary_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_alpha_renamed_center_boundary_v1.causal"
RESULT_SHA256 = "1c432037567c74397b95d0d75c84a0eac406d63398e57c7214bdf7c730cb2894"
CAUSAL_SHA256 = "069b23251855af0a9bb325cb5ad7f2ba011b30c123884e84e6b285f749040935"
CAUSAL_GRAPH_SHA256 = "019fcdbbec35bab3d6a154bb242cf268e9ca8e53dad78c65c271cc9c8f6bbfb4"
EXPECTED_FORMULAS = [
    (
        "alpha_plus_1__weighted_desc_center_22_before_12__inline_negative_alias",
        "22_before_12",
        "inline",
        8_900_139,
        "5e767d72c8da66223a3e727c05d7c61918042db8835ce6871f5e389cce2788f7",
        "cc680d0930e25c0305c249af5a5fc6d980e763fc0bbc0e07d24034002e3486c4",
    ),
    (
        "alpha_plus_1__weighted_desc_center_22_before_12__materialized_negative_alias",
        "22_before_12",
        "materialized",
        8_900_196,
        "e254879f000584b42824f9beb7ed26758fb6bf6aa0b03fcfca66f94d259d1137",
        "6c512161244eda8325d3f5f8155e774155e996e2b68f41a3021ec294aa3df585",
    ),
    (
        "alpha_plus_1__weighted_desc_center_12_before_22__inline_negative_alias",
        "12_before_22",
        "inline",
        8_900_139,
        "d0ba2dbf1e44f08b38b0f3c47dc444747ff9ab1e0b24568a0b0a727a40547332",
        "cc680d0930e25c0305c249af5a5fc6d980e763fc0bbc0e07d24034002e3486c4",
    ),
    (
        "alpha_plus_1__weighted_desc_center_12_before_22__materialized_negative_alias",
        "12_before_22",
        "materialized",
        8_900_196,
        "bf9a845ef90d65fc59af65ef497c5410cbe4f924dfc25fb68215e84319b08028",
        "6c512161244eda8325d3f5f8155e774155e996e2b68f41a3021ec294aa3df585",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_alpha_prediction_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "c1f608902bf55a7dfbc3703164124d8dcd9f83c973dc175f6b89275b496f0eb6"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A175_solver_execution"
    assert protocol["anchors"]["A174"]["sha256"] == MODULE.A174_SHA256
    assert protocol["anchors"]["A173"]["sha256"] == MODULE.A173_SHA256
    assert protocol["alpha_intervention"]["semantic_change"] is False
    assert protocol["alpha_intervention"]["numeric_suffix_offset"] == 1
    assert protocol["prospective_prediction"]["direction"] == (
        "renamed_directional_delta_remains_strictly_positive"
    )
    assert (
        protocol["information_boundary"]["A175_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["alpha_plan_sha256"] == (
        "031193f031b90706fc20c2c05a55ec191fdbec234c3181212d23ddcfb3a7e6e9"
    )
    assert analysis["formula_plan_sha256"] == (
        "c9167fc6a6ec8056135c9cd512a9e87322118addc2575e2f6cdf4e5b278e56da"
    )


def test_alpha_maps_are_bijective_and_byte_reversible(
    analysis: dict[str, Any],
) -> None:
    for alpha in analysis["alpha_plan"]:
        assert alpha["numeric_suffix_offset"] == 1
        assert alpha["declaration_count"] in (121_575, 121_576)
        assert alpha["changed_symbol_token_count"] in (529_945, 529_948)
        assert alpha["declaration_order_preserved"] is True
        assert alpha["assertion_order_preserved"] is True
        assert alpha["graph_topology_preserved"] is True
        assert alpha["symbol_prefixes_preserved"] is True
        assert alpha["inverse_transform_recovers_original_bytes"] is True
        assert alpha["first_mapping_rows"][:3] == [
            ["x0", "x1"],
            ["x1", "x2"],
            ["x2", "x3"],
        ]
        assert alpha["original_formula_sha256"] != alpha["renamed_formula_sha256"]


def test_four_exact_alpha_renamed_formulas(analysis: dict[str, Any]) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected in zip(analysis["rows"], EXPECTED_FORMULAS, strict=True):
        name, orientation, arm, size, formula_sha, mapping_sha = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["adjacent_orientation"] == orientation
        assert encoding["alias_compiler_arm"] == arm
        assert encoding["alpha_mapping_sha256"] == mapping_sha
        assert encoding["alpha_graph_isomorphic_to_A174"] is True
        assert encoding["alpha_inverse_recovers_A174_formula_bytes"] is True
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["target_rate_bits"] == 1_344
        assert row["solver_input_names"][:3] == ["x1", "x2", "x3"]
        assert row["solver_input_names"][-1] == "x24"
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_alpha_mapping"] is False


def test_all_four_renamed_model_maps_recover_complete_rate_witness(
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
                "name": f"alpha-{index}",
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


def test_classifier_separates_exact_directional_and_name_conditioned_results(
    analysis: dict[str, Any],
) -> None:
    a174, _a173 = analysis["anchors"]
    original = [row["stats"]["decisions"] for row in a174["execution_summary"]]
    exact = MODULE._alpha_boundary_result(
        a174,
        _synthetic_executions(a174, original, exact_hashes=True),
    )
    assert exact["classification"] == "exact_alpha_invariance"
    assert exact["all_four_canonical_observations_exactly_equal"] is True
    assert exact["alpha_renamed_directional_delta"] == 2_196

    robust = MODULE._alpha_boundary_result(
        a174,
        _synthetic_executions(a174, [10_000, 9_000, 10_000, 10_500], exact_hashes=False),
    )
    assert robust["classification"] == "central_boundary_alpha_robust"
    assert robust["alpha_renamed_directional_delta"] == 1_500

    conditioned = MODULE._alpha_boundary_result(
        a174,
        _synthetic_executions(a174, [10_000, 10_500, 10_000, 9_000], exact_hashes=False),
    )
    assert conditioned["classification"] == "numeric_symbol_identity_conditioned"
    assert conditioned["alpha_renamed_directional_delta"] == -1_500


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


def test_retained_a175_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A175"
    assert payload["evidence_stage"] == "ALPHA_RENAMED_CENTER_BOUNDARY_EXECUTED"
    assert payload["anchor_gates"]["A175_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A174"]["artifact_sha256"] == MODULE.A174_SHA256
    assert payload["anchor_gates"]["A173"]["artifact_sha256"] == MODULE.A173_SHA256
    assert payload["alpha_plan_sha256"] == (
        "031193f031b90706fc20c2c05a55ec191fdbec234c3181212d23ddcfb3a7e6e9"
    )
    assert payload["formula_plan_sha256"] == (
        "c9167fc6a6ec8056135c9cd512a9e87322118addc2575e2f6cdf4e5b278e56da"
    )
    assert payload["alpha_boundary_result_sha256"] == (
        "d6f1f34041830e50b86f0481d9afed748c80880fba49f04d3aabcfbfbc52df07"
    )
    assert payload["alpha_plan"] == analysis["alpha_plan"]
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
            "binary-propagations": 116_972_343,
            "conflicts": 3_254,
            "decisions": 10_816,
            "propagations": 445_011_419,
            "restarts": 7,
            "rlimit-count": 501_080_358,
        },
        {
            "binary-propagations": 118_298_311,
            "conflicts": 2_448,
            "decisions": 6_837,
            "propagations": 444_885_240,
            "restarts": 8,
            "rlimit-count": 501_080_363,
        },
        {
            "binary-propagations": 117_401_961,
            "conflicts": 2_709,
            "decisions": 7_772,
            "propagations": 444_962_977,
            "restarts": 11,
            "rlimit-count": 501_080_360,
        },
        {
            "binary-propagations": 118_363_006,
            "conflicts": 2_320,
            "decisions": 6_387,
            "propagations": 444_834_876,
            "restarts": 8,
            "rlimit-count": 501_080_365,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "9d1c035f45b7502ef8a013688b05a25f7833e99ccafbbb968e5564788aad2c99",
        "fa1daba536a48077bec52bd1520c825615615f1cddfca041f2ef04b9b1792d13",
        "f7118442c0741034b1dacdf02d9182760dabbf31f91dadd52c88162ba9da8649",
        "e72f56544eca498fec19d377e89c8a010dd82fe4c61d228c0c077ad884e57105",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    result = payload["alpha_boundary_result"]
    assert [row["A174_decisions"] for row in result["decision_rows"]] == [
        10_816,
        6_837,
        7_772,
        5_989,
    ]
    assert [row["alpha_renamed_decisions"] for row in result["decision_rows"]] == [
        10_816,
        6_837,
        7_772,
        6_387,
    ]
    assert [row["decision_delta_alpha_minus_A174"] for row in result["decision_rows"]] == [
        0,
        0,
        0,
        398,
    ]
    assert all(
        row["canonical_observation_exactly_equal"] is False for row in result["decision_rows"]
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
        ("12_before_22", 7_772, 6_387, -1_385),
    ]
    assert result["A174_directional_delta"] == 2_196
    assert result["alpha_renamed_directional_delta"] == 2_594
    assert result["directional_delta_change"] == 398
    assert result["all_four_canonical_observations_exactly_equal"] is False
    assert result["classification"] == "central_boundary_alpha_robust"
    assert result["prospective_prediction_confirmed"] is True

    alpha_rows = payload["alpha_plan"]
    assert [row["declaration_count"] for row in alpha_rows] == [
        121_575,
        121_576,
        121_575,
        121_576,
    ]
    assert [row["changed_symbol_token_count"] for row in alpha_rows] == [
        529_945,
        529_948,
        529_945,
        529_948,
    ]
    assert all(row["inverse_transform_recovers_original_bytes"] for row in alpha_rows)
    assert all(row["graph_topology_preserved"] for row in alpha_rows)
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
        "shake128-a174-prospective-central-partner-transfer",
        "shake128-a175-bijective-symbol-suffix-shift",
        "shake128-a175-four-alpha-isomorphic-formulas",
        "shake128-a175-fixed-resource-alpha-execution",
        "shake128-a175-alpha-boundary-result",
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
