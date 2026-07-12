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
    / "shake_symbolic_r2_adjacent_0_12_transfer_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_adjacent_0_12_transfer_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.causal"
RESULT_SHA256 = "f1252babeb729f9b58102d24d522daa0fa337506e25f9f282b2b4fb9a4d693c3"
CAUSAL_SHA256 = "e4df47fe3657f5b0d785d3ee6f142ad807b05a5d27320ef2ed6e183e62a9f2e6"
CAUSAL_GRAPH_SHA256 = "652c5c0db4c9ef682a2f69d16ed8256c10fad7f252e5d854c2f3ea09a6896bd2"
EXPECTED_FORMULAS = [
    (
        "greedy_max_center_0_before_12__inline_negative_alias",
        "0_before_12",
        "inline",
        8_899_715,
        "e883450ba22cff021b4bd816375b89c5f652f1af78fa55d4e9705cfd61ea3fba",
    ),
    (
        "greedy_max_center_0_before_12__materialized_negative_alias",
        "0_before_12",
        "materialized",
        8_899_771,
        "e846ab0386b692a1363724726c6e67575ecd333bf1a4b607433ce25e5fbe7a5e",
    ),
    (
        "greedy_max_center_12_before_0__inline_negative_alias",
        "12_before_0",
        "inline",
        8_899_715,
        "8d4ba9f22615e9c848e4d9901c9bcab9e74e26b9ec615a7b9dc92f547354fb93",
    ),
    (
        "greedy_max_center_12_before_0__materialized_negative_alias",
        "12_before_0",
        "materialized",
        8_899_771,
        "6076d05cd2c15478af715e6c96045951cc1d89a9668e048d7db3de1f9240c5d5",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_the_cross_family_directional_prediction(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "27be9da4897c9cde913db8a40aa169322a8a7c5dbec805878ec188dfec06c151"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A172_solver_execution"
    assert protocol["anchors"]["A170"]["sha256"] == MODULE.A170_SHA256
    assert protocol["anchors"]["A169"]["sha256"] == MODULE.A169_SHA256
    assert protocol["prospective_prediction"]["frozen_before_execution"] is True
    assert protocol["prospective_prediction"]["direction"] == (
        "effect_12_before_0_is_strictly_lower_than_effect_0_before_12"
    )
    assert (
        protocol["information_boundary"]["A172_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["discovery_evidence_sha256"] == (
        "d74aada82dace4327f3820493eff50c704e32a6ebd27ccf7d1bc11b1a953b098"
    )
    assert analysis["transfer_plan_sha256"] == (
        "de15046300be637bcf4fa9de7183c1fbd4d619265455f8edc274f086920be424"
    )
    assert analysis["formula_plan_sha256"] == (
        "bedd957db8a405bdecd98a0f4742842362888eea58e02df8262d98e22eecdf95"
    )


def test_two_matched_discovery_contexts_have_the_same_direction() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    evidence = analysis["discovery_evidence"]
    assert [row["adjacent_positions"] for row in evidence] == [[13, 14], [9, 10]]
    assert [row["only_changed_coordinates"] for row in evidence] == [[0, 12], [0, 12]]
    assert [row["directional_delta"] for row in evidence] == [-2_258, -890]
    assert all(row["predicted_direction_satisfied"] for row in evidence)


def test_transfer_orders_differ_only_by_the_central_adjacent_pair(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["transfer_plan"]
    zero_first = plan["zero_before_twelve_order"]
    twelve_first = plan["twelve_before_zero_order"]
    differences = [
        index
        for index, (left, right) in enumerate(zip(zero_first, twelve_first, strict=True))
        if left != right
    ]
    assert plan["source_order_name"] == "greedy_max_remaining_weight"
    assert plan["adjacent_positions"] == [11, 12]
    assert differences == [11, 12]
    assert [zero_first[index] for index in differences] == [0, 12]
    assert [twelve_first[index] for index in differences] == [12, 0]
    assert plan["other_22_relative_order_preserved"] is True
    assert sorted(zero_first) == list(range(24))
    assert sorted(twelve_first) == list(range(24))


def test_four_exact_inline_materialized_transfer_formulas(
    analysis: dict[str, Any],
) -> None:
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
        assert encoding["adjacent_positions"] == [11, 12]
        assert encoding["prospective_directional_prediction"] == (
            "effect_12_before_0_is_strictly_lower_than_effect_0_before_12"
        )
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_transfer_selection"] is False


def test_all_four_model_maps_and_prospective_classifier(
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

    executions = [
        {
            "encoding": {"adjacent_orientation": "0_before_12", "alias_compiler_arm": "inline"},
            "solver": {"stats": {"decisions": 5_000}},
        },
        {
            "encoding": {
                "adjacent_orientation": "0_before_12",
                "alias_compiler_arm": "materialized",
            },
            "solver": {"stats": {"decisions": 6_000}},
        },
        {
            "encoding": {"adjacent_orientation": "12_before_0", "alias_compiler_arm": "inline"},
            "solver": {"stats": {"decisions": 5_000}},
        },
        {
            "encoding": {
                "adjacent_orientation": "12_before_0",
                "alias_compiler_arm": "materialized",
            },
            "solver": {"stats": {"decisions": 5_500}},
        },
    ]
    result = MODULE._transfer_result(executions)
    assert [row["materialization_effect"] for row in result["rows"]] == [1_000, 500]
    assert result["directional_delta_12_before_0_minus_0_before_12"] == -500
    assert result["prospective_prediction_confirmed"] is True
    assert result["direction_classification"] == "confirmed_lower"


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
        MODULE._A163, "_verify_solver_row", lambda row, solver, *_args: {**row, "solver": solver}
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


def test_retained_a172_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A172"
    assert payload["evidence_stage"] == "PROSPECTIVE_ADJACENT_0_12_TRANSFER_EXECUTED"
    assert payload["anchor_gates"]["A172_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A170"]["artifact_sha256"] == MODULE.A170_SHA256
    assert payload["anchor_gates"]["A169"]["artifact_sha256"] == MODULE.A169_SHA256
    assert payload["discovery_evidence_sha256"] == (
        "d74aada82dace4327f3820493eff50c704e32a6ebd27ccf7d1bc11b1a953b098"
    )
    assert payload["transfer_plan_sha256"] == (
        "de15046300be637bcf4fa9de7183c1fbd4d619265455f8edc274f086920be424"
    )
    assert payload["formula_plan_sha256"] == (
        "bedd957db8a405bdecd98a0f4742842362888eea58e02df8262d98e22eecdf95"
    )
    assert payload["transfer_result_sha256"] == (
        "7b20ad6787fb555b55239522a43977ac268a7423c0f5d067def935ca27b6a4fd"
    )
    assert payload["discovery_evidence"] == analysis["discovery_evidence"]
    assert payload["transfer_plan"] == analysis["transfer_plan"]
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
            "binary-propagations": 118_657_697,
            "conflicts": 2_440,
            "decisions": 4_870,
            "propagations": 444_895_479,
            "restarts": 6,
            "rlimit-count": 501_080_276,
        },
        {
            "binary-propagations": 118_502_948,
            "conflicts": 2_286,
            "decisions": 4_289,
            "propagations": 444_860_135,
            "restarts": 3,
            "rlimit-count": 501_080_281,
        },
        {
            "binary-propagations": 118_672_810,
            "conflicts": 2_400,
            "decisions": 5_790,
            "propagations": 444_879_535,
            "restarts": 11,
            "rlimit-count": 501_080_272,
        },
        {
            "binary-propagations": 118_539_888,
            "conflicts": 2_253,
            "decisions": 5_665,
            "propagations": 444_837_453,
            "restarts": 5,
            "rlimit-count": 501_080_277,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "89ecfd9f4a169d98e486ae2a1c155485c325970bc3d03907551c51cac7b65c26",
        "63ad1f6649de967a0826fe55b1d550f522ae3987aa1900f0974cd7e3a2554f49",
        "d42df17c79e3ea3e37ef840282832903ae62adce96b94085aa323f93db4a2eea",
        "4a597cc93cce3eb441fa09b8e5664c085a944876f317e6529c918b3f39d10c61",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    transfer = payload["transfer_result"]
    assert transfer["prospective_prediction"] == (
        "effect_12_before_0_is_strictly_lower_than_effect_0_before_12"
    )
    assert transfer["prospective_prediction_confirmed"] is False
    assert transfer["direction_classification"] == "reversed_direction"
    assert transfer["directional_delta_12_before_0_minus_0_before_12"] == 456
    assert transfer["signs"] == {"0_before_12": -1, "12_before_0": -1}
    assert [
        (
            row["adjacent_orientation"],
            row["inline_decisions"],
            row["materialized_decisions"],
            row["materialization_effect"],
        )
        for row in transfer["rows"]
    ] == [
        ("0_before_12", 4_870, 4_289, -581),
        ("12_before_0", 5_790, 5_665, -125),
    ]

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A172_execution"] is True
    assert payload["posthoc"]["used_for_transfer_formula_order_or_execution"] is False
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
        "shake128-a170-two-matched-weighted-adjacent-swaps",
        "shake128-a172-cross-family-central-adjacent-pair",
        "shake128-a172-four-prospective-transfer-formulas",
        "shake128-a172-fixed-resource-execution",
        "shake128-a172-adjacent-order-transfer-result",
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
