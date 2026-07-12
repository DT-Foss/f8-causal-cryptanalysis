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
    / "shake_symbolic_r2_four_gauge_factorial_completion.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_four_gauge_factorial_completion_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "c8b4f7446b3e78b3914f90e5fbbc201d00771a917c7fafe16eba6e134e0f55ab"
CAUSAL_SHA256 = "8935ebb8678ea545e122283d44bc4d3f1462ee8ffad7ace1905cbceb6dfc20d8"
CAUSAL_GRAPH_SHA256 = "561ce3b8ea09721a5210b8d70f0ef53fa07dc87647e2e3f7f7ae6705c26f8d90"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__gauge_4e1e28",
        0x4E1E28,
        8_899_772,
        "15d797dc7e2cdc7fdb68a03ba68a2a0e6d63385eedda9aea07782f42e98148b3",
        "3639771fbc0abb3764706920ebd3209904721db470de6899f332ede004130389",
        1_596,
        [453, 516, 990, 1_454],
    ),
    (
        "weighted_degree_descending__gauge_8c161b",
        0x8C161B,
        8_900_041,
        "4acdf793adbe5c70d143a5da8b9ccfcd7b82447d53a3ae11cf9732862f05de67",
        "71656c6853118eb3ace1ad8df9055d1d2020ae685f9dde39b7353ce02b4211dd",
        1_598,
        [516, 990],
    ),
    (
        "weighted_degree_ascending__gauge_4e1e28",
        0x4E1E28,
        8_900_280,
        "13da8bd8f6d57b9a45a7e689def2137174b9955e547acc56ea96ad596dd74e44",
        "8314f11a25bc66d3157b4ce2a83539f3826beb340f924bc87631c5025c8fc8bf",
        1_596,
        [453, 516, 990, 1_454],
    ),
    (
        "weighted_degree_ascending__gauge_8c161b",
        0x8C161B,
        8_900_345,
        "72e2729849ef404be1116cfc03bdf2ba12f662306bf5cc5b5cb74f73988a279b",
        "1fcb54c1ecbff7dd4c36fca03eba59b8e8c73468a9a4d61b72d06f1815ea1c5d",
        1_598,
        [516, 990],
    ),
    (
        "greedy_max_remaining_weight__gauge_8c161b",
        0x8C161B,
        8_900_022,
        "e1d876e8c03e0fb0f087987c9c9f2cef591140b744608cf84f7f36287ff063a6",
        "5c46bdb5ab4976f944d7422771eb8b593d3429e3abbb470352f7ded2a6ca5f27",
        1_598,
        [516, 990],
    ),
    (
        "greedy_max_remaining_weight__gauge_954b3c",
        0x954B3C,
        8_899_885,
        "342bfdbcd985215fcc8ac12f988a193878561c34c38f0fd976a27e260be670d9",
        "0a3eca911b27d7c5ec4b48f65ac60db86e8ae379e92f898bd2a4c6040e7da9e2",
        1_596,
        [453, 516, 917, 1_454],
    ),
    (
        "greedy_min_remaining_weight__gauge_498a92",
        0x498A92,
        8_899_983,
        "3410d83eb0d4c119d562a9c1f5bf9f7a1df4464efe60c59175e3dbd66e3431f2",
        "147d41449fc11aa40f162e0c8159aecbccc59e986ffe607a8ae767f124e984aa",
        1_597,
        [453, 917, 1_454],
    ),
    (
        "greedy_min_remaining_weight__gauge_4e1e28",
        0x4E1E28,
        8_900_259,
        "89632fbba577a3ede5c99aa0c77fe057882eca61bfc59ef83276935c96741e62",
        "27b475b465809dcb2dbf7a61c0cc56f1bb8da3349b02836155d2570af64b949f",
        1_596,
        [453, 516, 990, 1_454],
    ),
]


def test_a162_a163_anchors_freeze_a_nonrepeating_factorial_completion() -> None:
    protocol = MODULE._load_protocol_gate()
    a162, a163 = MODULE._load_anchor_gates(RESULTS_DIR)
    design = MODULE._factorial_design(a162)
    assert a163["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 8,
        "unsat": 0,
    }
    assert design["full_plan_sha256"] == (
        "91c0ffb122d42731a192cef73b79fd0ef4df14df91ecff6dd53738b10ed814d7"
    )
    assert design["missing_plan_sha256"] == (
        "65ed6a97f06325dcb1538b5601f650aa462135697b43575caf844474a70afb2e"
    )
    assert len(design["full_plan"]) == 16
    assert len(design["generating_pairs"]) == 8
    assert len(design["missing_plan"]) == 8
    assert design["solver_counter_target_or_assignment_used"] is False
    assert protocol["frozen_plans"]["formula_plan_sha256"] == (
        "4c68011dd6173883900828bf7f6510918c3f30776ed9b6211fb17579087e49ff"
    )
    assert protocol["selection_rule"]["uses_A163_solver_counters"] is False
    assert not {
        (row["order_name"], row["affine_shift"]) for row in design["missing_plan"]
    } & design["generating_pairs"]


def test_analyze_freezes_the_eight_exact_missing_formulas() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["formula_plan_sha256"] == (
        "4c68011dd6173883900828bf7f6510918c3f30776ed9b6211fb17579087e49ff"
    )
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected in zip(analysis["rows"], EXPECTED_FORMULAS, strict=True):
        name, shift, size, formula_sha, polynomial_sha, definitions, aliases = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["affine_shift_original_input_mask"] == shift
        assert encoding["R2_polynomial_state_sha256_in_solver_basis"] == polynomial_sha
        assert encoding["R2_state_definitions"] == definitions
        assert encoding["R2_alias_coordinates"] == aliases
        assert definitions + len(aliases) == 1_600
        assert encoding["total_variables"] == 119_980 + definitions
        assert encoding["total_assertions"] == 121_300 + definitions
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_gauge_selection"] is False


def test_all_eight_missing_cell_model_maps_recover_the_complete_rate_witness() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
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


def test_exact_factorial_decomposition_has_zero_interaction_margins() -> None:
    design = {
        "orders": ["a", "b", "c", "d"],
        "shifts": [1, 2, 3, 4],
    }
    matrix = [
        {
            "order_name": order,
            "affine_shift": shift,
            "decisions": 100 * order_index + 10 * shift_index + order_index * shift_index,
            "conflicts": order_index + shift_index,
        }
        for order_index, order in enumerate(design["orders"])
        for shift_index, shift in enumerate(design["shifts"])
    ]
    decomposition = MODULE._factorial_decomposition(design, matrix)
    interactions = decomposition["interactions"]
    assert all(
        sum(
            row["interaction_decision_residual_numerator"]
            for row in interactions
            if row["order_name"] == order
        )
        == 0
        for order in design["orders"]
    )
    assert all(
        sum(
            row["interaction_decision_residual_numerator"]
            for row in interactions
            if row["affine_shift"] == shift
        )
        == 0
        for shift in design["shifts"]
    )


def test_retained_a164_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A164"
    assert payload["anchor_gates"]["A164_protocol"]["artifact_sha256"] == (
        MODULE.PROTOCOL_SHA256
    )
    assert payload["anchor_gates"]["A162"]["artifact_sha256"] == MODULE.A162_SHA256
    assert payload["anchor_gates"]["A163"]["artifact_sha256"] == MODULE.A163_SHA256
    assert payload["factorial_design"]["full_plan_sha256"] == (
        "91c0ffb122d42731a192cef73b79fd0ef4df14df91ecff6dd53738b10ed814d7"
    )
    assert payload["factorial_design"]["missing_plan_sha256"] == (
        "65ed6a97f06325dcb1538b5601f650aa462135697b43575caf844474a70afb2e"
    )
    assert payload["formula_plan_sha256"] == (
        "4c68011dd6173883900828bf7f6510918c3f30776ed9b6211fb17579087e49ff"
    )
    assert payload["full_factorial_matrix_sha256"] == (
        "b049c248886b5eba988c9be19510b4d24b735f5b176045b60d0578e5cf63611b"
    )
    assert payload["factorial_decomposition_sha256"] == (
        "a78dbdcfa838f86a1f0884c22fb078412e0623a98bd882126e61df6f74a9d0d4"
    )
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 8,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []
    summaries = payload["execution_summary"]
    assert [row["name"] for row in summaries] == [row[0] for row in EXPECTED_FORMULAS]
    assert [row["stats"]["rlimit-count"] for row in summaries] == [
        501_080_369,
        501_080_291,
        501_079_875,
        501_079_819,
        501_080_203,
        501_080_205,
        501_079_806,
        501_079_923,
    ]
    assert [row["stats"]["decisions"] for row in summaries] == [
        5_339,
        9_800,
        4_402,
        5_462,
        9_521,
        9_694,
        12_607,
        6_505,
    ]
    assert [row["stats"]["conflicts"] for row in summaries] == [
        2_222,
        2_536,
        2_189,
        2_250,
        3_959,
        2_458,
        3_577,
        3_292,
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "2642afbf9c2658785db4a3d59dd8174a02a76f2c8d324d9ea0a1300d6a84331d",
        "2c306e082280e9142af2f2f4593bc4710698b10c637286dcb3cd4f32ce0b54e3",
        "bc3d35fc887cbf22849d38b04e5af82d69a110743bd84a54726af1d53be95d2a",
        "eae8703e312c2f54099e5487f170eebdb63f662c288d1d13b3c7b54645fb11d1",
        "4f774362d25420613f7035ff0d15e196d007b54dab1f3e124b895844891fd15d",
        "5473d4a0fd1a59f86b0442f7f6f0ea31c265d14ad1b28bb2495d7cbbc37f7463",
        "a0c7a6e40de74c2000f58b0a4e1bf2711153d1f3f781be83eaf6027c1b4c8858",
        "46d776f3609c0ac0c1334b918e15f8500bf73cf5de6ab02b46ac557eb031d445",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    matrix = payload["full_factorial_matrix"]
    assert len(matrix) == 16
    assert sum(row["source_attempt"] == "A163" for row in matrix) == 8
    assert sum(row["source_attempt"] == "A164" for row in matrix) == 8
    decomposition = payload["factorial_decomposition"]
    assert decomposition["best_cell"]["order_name"] == "weighted_degree_ascending"
    assert decomposition["best_cell"]["affine_shift"] == 0x4E1E28
    assert decomposition["best_cell"]["decisions"] == 4_402
    assert [row["decision_sum"] for row in decomposition["gauge_effects"]] == [
        38_390,
        23_116,
        37_311,
        42_917,
    ]
    assert [row["decision_sum"] for row in decomposition["order_effects"]] == [
        35_854,
        30_332,
        34_396,
        41_152,
    ]
    assert decomposition["maximum_absolute_interaction_numerator"] == 49_530
    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A164_execution"] is True
    assert payload["posthoc"]["used_for_design_formula_order_gauge_or_execution"] is False
    lowered = raw.decode().lower()
    assert '"wallclock_seconds"' not in lowered
    assert '"elapsed_seconds"' not in lowered
    assert '"stdout_sha256"' not in lowered
    assert '"stderr_sha256"' not in lowered
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 5
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a162-frozen-four-gauge-four-order-product",
        "shake128-a164-eight-missing-factorial-formulas",
        "shake128-a164-fixed-resource-execution",
        "shake128-a164-complete-four-by-four-matrix",
        "shake128-a164-exact-factorial-decomposition",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
