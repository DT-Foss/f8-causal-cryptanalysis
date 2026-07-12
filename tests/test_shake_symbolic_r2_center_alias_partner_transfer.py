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
    / "shake_symbolic_r2_center_alias_partner_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_center_alias_partner_transfer_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_center_alias_partner_transfer_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_center_alias_partner_transfer_v1.causal"
RESULT_SHA256 = "e1683380ec9f5714d2c75a700b8dd2bf50f3b9cd5ee8106c48bb21f7c1b45eae"
CAUSAL_SHA256 = "0525ec8b6030f567d8ff7573560c17a8c51b39f726b1ba70aca576ed931646b2"
CAUSAL_GRAPH_SHA256 = "cf79cb25c0d55ec7f0790bbceeadd01ef7757f47961724b492a6076be157d94f"
EXPECTED_FORMULAS = [
    (
        "weighted_desc_center_22_before_12__inline_negative_alias",
        "22_before_12",
        "inline",
        12,
        8_899_711,
        "8d5554b488a3f6edebac7fe512b506a897e0d3a9f0ca091f7273da928350fe4b",
    ),
    (
        "weighted_desc_center_22_before_12__materialized_negative_alias",
        "22_before_12",
        "materialized",
        12,
        8_899_767,
        "cbcb738e87abefd57264762b1bc39ff2ab779e7e3983eb252e263107c604b214",
    ),
    (
        "weighted_desc_center_12_before_22__inline_negative_alias",
        "12_before_22",
        "inline",
        11,
        8_899_711,
        "9c733d671b5f270e53ce2798ace93038af406338426bf259c5af854b2ea8be88",
    ),
    (
        "weighted_desc_center_12_before_22__materialized_negative_alias",
        "12_before_22",
        "materialized",
        11,
        8_899_767,
        "07c6f29091c51fc83a8af45d092e69949b30cf5cd9cc147fe24baa635c66fce6",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_partner_transfer_before_execution(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "e34edf19f6a4d3193aac3ef4f9df6df742b910d9340cb2238860fc1b61862a15"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A174_solver_execution"
    assert protocol["anchors"]["A173"]["sha256"] == MODULE.A173_SHA256
    assert protocol["anchors"]["A170"]["sha256"] == MODULE.A170_SHA256
    assert protocol["anchors"]["A166"]["sha256"] == MODULE.A166_SHA256
    assert protocol["partner_design"]["semantic_change"] is False
    assert protocol["partner_design"]["new_formula_count"] == 4
    assert protocol["prospective_prediction"]["direction"] == (
        "effect_12_before_22_is_strictly_higher_than_effect_22_before_12"
    )
    assert (
        protocol["information_boundary"]["A174_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["partner_plan_sha256"] == (
        "4fd8d79ef6581ad82303b96a2432f6f933fe55fc38e1e4e0b726f3d1508ffb46"
    )
    assert analysis["formula_plan_sha256"] == (
        "7aeb5ae8e759affecfed70292223460d30281481aeb49e955c74507719fcdb39"
    )


def test_partner_swap_crosses_only_the_same_x11_x12_boundary(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["partner_plan"]
    partner_first = plan["partner_before_alias_order"]
    alias_first = plan["alias_before_partner_order"]
    differences = [
        index
        for index, (left, right) in enumerate(zip(partner_first, alias_first, strict=True))
        if left != right
    ]
    assert plan["source_order"].index(12) + 1 == plan["source_order"].index(22)
    assert plan["control_partner_is_original_right_neighbor"] is True
    assert differences == [11, 12]
    assert [partner_first[index] for index in differences] == [22, 12]
    assert [alias_first[index] for index in differences] == [12, 22]
    assert plan["alias_solver_positions"] == {"22_before_12": 12, "12_before_22": 11}
    assert plan["A173_alias_solver_positions"] == {"0_before_12": 12, "12_before_0": 11}
    assert plan["other_22_relative_order_preserved"] is True


def test_four_exact_inline_materialized_partner_formulas(
    analysis: dict[str, Any],
) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected in zip(analysis["rows"], EXPECTED_FORMULAS, strict=True):
        name, orientation, arm, alias_position, size, formula_sha = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["adjacent_orientation"] == orientation
        assert encoding["alias_compiler_arm"] == arm
        assert encoding["alias_input_solver_position"] == alias_position
        assert encoding["control_partner_coordinate"] == 22
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_partner_selection"] is False


def test_all_four_model_maps_recover_the_complete_rate_witness(
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


def _synthetic_executions(first_effect: int, second_effect: int) -> list[dict[str, Any]]:
    rows = []
    for orientation, effect in zip(MODULE.ORIENTATIONS, (first_effect, second_effect), strict=True):
        rows.extend(
            [
                {
                    "encoding": {
                        "adjacent_orientation": orientation,
                        "alias_compiler_arm": "inline",
                    },
                    "solver": {"stats": {"decisions": 10_000}},
                },
                {
                    "encoding": {
                        "adjacent_orientation": orientation,
                        "alias_compiler_arm": "materialized",
                    },
                    "solver": {"stats": {"decisions": 10_000 + effect}},
                },
            ]
        )
    return rows


@pytest.mark.parametrize(
    ("first_effect", "second_effect", "classification", "confirmed"),
    [
        (-500, 500, "central_alias_boundary_transfers", True),
        (500, 500, "exact_partner_boundary", False),
        (500, -500, "coordinate_0_specific_direction", False),
    ],
)
def test_prospective_classifier_has_three_exhaustive_outcomes(
    analysis: dict[str, Any],
    first_effect: int,
    second_effect: int,
    classification: str,
    confirmed: bool,
) -> None:
    a173, _a170, _a166 = analysis["anchors"]
    result = MODULE._partner_transfer_result(
        a173, _synthetic_executions(first_effect, second_effect)
    )
    assert result["directional_delta_alias_position_11_minus_12"] == (second_effect - first_effect)
    assert result["classification"] == classification
    assert result["prospective_prediction_confirmed"] is confirmed
    assert result["A173_coordinate_0_partner_delta"] == 10_955


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


def test_retained_a174_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A174"
    assert payload["evidence_stage"] == "CENTER_ALIAS_PARTNER_TRANSFER_EXECUTED"
    assert payload["anchor_gates"]["A174_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A173"]["artifact_sha256"] == MODULE.A173_SHA256
    assert payload["anchor_gates"]["A170"]["artifact_sha256"] == MODULE.A170_SHA256
    assert payload["partner_plan_sha256"] == (
        "4fd8d79ef6581ad82303b96a2432f6f933fe55fc38e1e4e0b726f3d1508ffb46"
    )
    assert payload["formula_plan_sha256"] == (
        "7aeb5ae8e759affecfed70292223460d30281481aeb49e955c74507719fcdb39"
    )
    assert payload["partner_transfer_result_sha256"] == (
        "a874c0d51d7eb38bb97e1a997113021b69af2aa5da3e087250a18868df11b3c0"
    )
    assert payload["partner_plan"] == analysis["partner_plan"]
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
    assert [row["alias_input_solver_position"] for row in summaries] == [12, 12, 11, 11]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    transfer = payload["partner_transfer_result"]
    assert [
        (
            row["adjacent_orientation"],
            row["alias_input_solver_position"],
            row["inline_decisions"],
            row["materialized_decisions"],
            row["materialization_effect"],
        )
        for row in transfer["rows"]
    ] == [
        ("22_before_12", 12, 10_816, 6_837, -3_979),
        ("12_before_22", 11, 7_772, 5_989, -1_783),
    ]
    assert transfer["directional_delta_alias_position_11_minus_12"] == 2_196
    assert transfer["A173_coordinate_0_partner_delta"] == 10_955
    assert transfer["magnitude_ratio_numerator_denominator"] == [2_196, 10_955]
    assert transfer["classification"] == "central_alias_boundary_transfers"
    assert transfer["prospective_prediction_confirmed"] is True
    assert transfer["partner_independent_direction_match"] is True

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A174_execution"] is True
    assert payload["posthoc"]["used_for_partner_formula_order_or_execution"] is False
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
        "shake128-a173-central-x11-x12-boundary",
        "shake128-a174-original-neighbor-22-partner",
        "shake128-a174-four-prospective-partner-formulas",
        "shake128-a174-fixed-resource-execution",
        "shake128-a174-partner-independent-boundary-result",
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
