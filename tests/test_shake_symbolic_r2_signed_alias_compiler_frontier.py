from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_signed_alias_compiler_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_signed_alias_compiler_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db"
CAUSAL_SHA256 = "2768b97542a5f3c90339def61c1bc61cf719b253d7e04ec2badc5983a55be641"
CAUSAL_GRAPH_SHA256 = "83229c065fdeefc654f65339b00f627301b1fb063e0dac55b2c710884c244f11"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__signed_unit_affine_alias",
        8_899_711,
        "f5e9d9843c5ff13fb3df020aaa74313ab2787487b2e51d7b872b6f4263484724",
    ),
    (
        "weighted_degree_ascending__signed_unit_affine_alias",
        8_900_219,
        "eab43da12ff6fb5afa4e62fd6d23093cad7490c8220a24bf657e7e594aa9e7f8",
    ),
    (
        "greedy_max_remaining_weight__signed_unit_affine_alias",
        8_899_694,
        "f330e85d8602ac070b398bc6c50355d1392d7e76e5ef66dffcfad39b8e020407",
    ),
    (
        "greedy_min_remaining_weight__signed_unit_affine_alias",
        8_900_197,
        "c517f3bb2b275cc37c8a97368c1fe458b2279f8fc10d6c48e7f31b745f6f61fd",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, object]:
    return MODULE.analyze(RESULTS_DIR)


def test_frozen_protocol_and_anchor_gates_bind_the_prospective_A166_plan(
    analysis: dict[str, object],
) -> None:
    protocol = analysis["protocol"]
    assert protocol["protocol_state"] == "frozen_before_any_A166_solver_execution"
    assert protocol["information_boundary"] == {
        "A164_solver_counters_used_to_select_the_universal_gauge": True,
        "A164_counters_used_to_select_signed_alias_rule": False,
        "target_bit_values_used_in_suffix_cone": False,
        "target_rate_used_in_compiler_selection": False,
        "instrumented_assignment_used": False,
        "A166_solver_outcomes_used_before_formula_freeze": False,
    }
    assert analysis["structural_analysis_sha256"] == (
        "ba3acec7cfcbf7f10e5f1fe1bc98b77a1a47aff7d85e64629319537426da75cd"
    )
    assert analysis["formula_plan_sha256"] == (
        "fd2ed7f25529335e7403aafc638d21fa07a99e8bde81333518e4e8fdbb4a25f7"
    )


def test_exact_suffix_cone_refutes_the_static_incidence_explanation(
    analysis: dict[str, object],
) -> None:
    cone = analysis["suffix_cone_frontier"]
    assert cone["depth_plan_sha256"] == (
        "b7163b88f68faf3bf8bca58c82ccb617bd060b260c23dd0cdefb92cad24538dc"
    )
    assert len(cone["depths"]) == 23
    assert cone["winner_at_every_depth"] is True
    assert cone["unique_winner_sequence"] == [0x498A92]
    assert cone["A164_winner_selected_at_any_depth"] is False
    assert all(row["minimum_affine_incidence_shift"] == 0x498A92 for row in cone["depths"])

    for initial in ([1] * 1_600, [0] * 511 + [7] + [0] * 1_088):
        backward = MODULE._backward_suffix_cone_round(initial)
        assert len(backward) == 1_600
        assert min(backward) >= 0
        assert sum(backward) == 33 * sum(initial)

    with pytest.raises(ValueError, match="1,600 nonnegative"):
        MODULE._backward_suffix_cone_round([0] * 1_599)


def test_exact_five_coordinate_signed_unit_affine_theorem(
    analysis: dict[str, object],
) -> None:
    theorem = analysis["unit_affine_theorem"]
    assert theorem["theorem_sha256"] == (
        "64c7ae36eb2c763dd29ac983addaf493b46b067b8debc78a5a218de7d531a7dc"
    )
    assert [
        (
            row["state_coordinate"],
            row["lane"],
            row["bit"],
            row["input_coordinate"],
            row["original_constant"],
        )
        for row in theorem["coordinates"]
    ] == [
        (453, 7, 5, 11, True),
        (516, 8, 4, 15, False),
        (917, 14, 21, 12, False),
        (990, 15, 30, 12, True),
        (1_454, 22, 46, 11, True),
    ]
    assert theorem["selected_gauge"] == 0x4E1E28
    assert theorem["selected_gauge_signed_literals"] == [
        {"state_coordinate": 453, "input_coordinate": 11, "signed_literal": "positive"},
        {"state_coordinate": 516, "input_coordinate": 15, "signed_literal": "positive"},
        {"state_coordinate": 917, "input_coordinate": 12, "signed_literal": "negative"},
        {"state_coordinate": 990, "input_coordinate": 12, "signed_literal": "positive"},
        {"state_coordinate": 1_454, "input_coordinate": 11, "signed_literal": "positive"},
    ]
    assert theorem["selected_negative_alias_count_materialized_under_A157_compiler"] == 1
    assert theorem["signed_alias_count_under_A166_compiler"] == 5


def test_four_exact_semantics_preserving_formulas_are_hash_frozen(
    analysis: dict[str, object],
) -> None:
    rows = analysis["rows"]
    assert [row["name"] for row in rows] == [row[0] for row in EXPECTED_FORMULAS]
    for row, expected in zip(rows, EXPECTED_FORMULAS, strict=True):
        name, size, formula_sha256 = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha256
        assert encoding["compiler"] == "signed_unit_affine_alias_normalization"
        assert encoding["affine_shift_original_input_mask"] == 0x4E1E28
        assert encoding["R2_state_definitions"] == 1_595
        assert encoding["R2_direct_alias_coordinates"] == [453, 516, 990, 1_454]
        assert encoding["R2_complement_alias_coordinates"] == [917]
        assert encoding["R2_signed_alias_coordinates"] == [453, 516, 917, 990, 1_454]
        assert encoding["total_variables"] == 121_575
        assert encoding["total_assertions"] == 122_895
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_compiler_selection"] is False


def test_all_four_model_maps_recover_the_complete_rate_witness(
    analysis: dict[str, object],
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
        assert verified["shifted_input_coordinate_assignment"] == shifted_assignment
        assert verified["input_coordinate_assignment"] == input_assignment
        assert verified["independent_complete_rate_check"]["complete_rate_match"] is True

    with pytest.raises(RuntimeError, match="independently invalid"):
        MODULE._A163._verify_solver_row(
            dict(analysis["rows"][-1]),
            {"status": "sat", "solver_basis_assignment": solver_assignment ^ 1},
            analysis["problem"],
            analysis["variant"],
        )


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


def test_retained_a166_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A166"
    assert payload["evidence_stage"] == ("SIGNED_UNIT_AFFINE_ALIAS_COMPILER_FRONTIER_EXECUTED")
    assert payload["anchor_gates"]["A166_protocol"] == {
        "artifact_sha256": MODULE.PROTOCOL_SHA256,
        "information_boundary": {
            "A164_counters_used_to_select_signed_alias_rule": False,
            "A164_solver_counters_used_to_select_the_universal_gauge": True,
            "A166_solver_outcomes_used_before_formula_freeze": False,
            "instrumented_assignment_used": False,
            "target_bit_values_used_in_suffix_cone": False,
            "target_rate_used_in_compiler_selection": False,
        },
        "protocol_state": "frozen_before_any_A166_solver_execution",
    }
    assert payload["anchor_gates"]["A164"]["artifact_sha256"] == MODULE.A164_SHA256
    assert payload["anchor_gates"]["A162"]["artifact_sha256"] == MODULE.A162_SHA256
    assert payload["structural_analysis_sha256"] == (
        "ba3acec7cfcbf7f10e5f1fe1bc98b77a1a47aff7d85e64629319537426da75cd"
    )
    assert payload["suffix_cone_frontier"]["depth_plan_sha256"] == (
        "b7163b88f68faf3bf8bca58c82ccb617bd060b260c23dd0cdefb92cad24538dc"
    )
    assert payload["unit_affine_theorem"]["theorem_sha256"] == (
        "64c7ae36eb2c763dd29ac983addaf493b46b067b8debc78a5a218de7d531a7dc"
    )
    assert payload["formula_plan_sha256"] == (
        "fd2ed7f25529335e7403aafc638d21fa07a99e8bde81333518e4e8fdbb4a25f7"
    )
    assert payload["comparison_sha256"] == (
        "1977e8c279a7d965f4723dc60de25e26a9a39b95eabcd2293d1b670cddc65418"
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
            "binary-propagations": 118_110_616,
            "conflicts": 2_557,
            "decisions": 7_347,
            "propagations": 444_906_261,
            "restarts": 8,
            "rlimit-count": 501_080_364,
        },
        {
            "binary-propagations": 118_765_120,
            "conflicts": 2_831,
            "decisions": 3_425,
            "propagations": 446_267_015,
            "restarts": 7,
            "rlimit-count": 501_079_870,
        },
        {
            "binary-propagations": 118_828_156,
            "conflicts": 2_233,
            "decisions": 5_247,
            "propagations": 444_843_111,
            "restarts": 3,
            "rlimit-count": 501_080_256,
        },
        {
            "binary-propagations": 119_416_875,
            "conflicts": 2_402,
            "decisions": 5_323,
            "propagations": 446_144_090,
            "restarts": 6,
            "rlimit-count": 501_079_918,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "73a8bac52b4f6dd9443d6d3c33a8961f296779d5b88f995ee086aca776be7486",
        "f8d58597b2b0c00936d27c25811766df8cd50005ed4c07150a47d155ca4db2b7",
        "c68872d342e6e2f22cca39abea0b7fb75009289fc067324fb0762849eacdc56e",
        "b62ce10efe662101940d1ea4fc3e44657dfabe311f50b01d7f9d58e1744297a5",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert [row["decision_delta"] for row in payload["comparison"]] == [
        2_008,
        -977,
        -1_623,
        -1_182,
    ]
    assert [row["conflict_delta"] for row in payload["comparison"]] == [
        335,
        642,
        -198,
        -890,
    ]
    assert all(row["same_configured_rlimit"] for row in payload["comparison"])
    assert all(row["semantic_relation_unchanged"] for row in payload["comparison"])
    assert all(row["removed_variables"] == 1 for row in payload["comparison"])
    assert all(row["removed_assertions"] == 1 for row in payload["comparison"])
    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A166_execution"] is True
    assert payload["posthoc"]["used_for_cone_compiler_formula_order_or_execution"] is False
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
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a164-universal-four-order-gauge",
        "shake128-a166-cone-and-unit-affine-theorem",
        "shake128-a166-four-signed-alias-formulas",
        "shake128-a166-fixed-resource-execution",
        "shake128-a166-signed-alias-intervention-comparison",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
