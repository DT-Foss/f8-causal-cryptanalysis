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
    / "shake_symbolic_r2_center_position_family_contrast.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_center_position_family_contrast_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_center_position_family_contrast_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_center_position_family_contrast_v1.causal"
RESULT_SHA256 = "b3ae48350a75430b1b1aea55ebe59442949dd6b5fe19f30453583ede6da6d01b"
CAUSAL_SHA256 = "da252d66daac4971324679b2911926b562f9edc65edfd5546a5ac5e7a8ad7234"
CAUSAL_GRAPH_SHA256 = "f4f5d38e9e328de2d6383d57230176b4efee0057be3a993bab65406412c65cfd"
EXPECTED_FORMULAS = [
    (
        "weighted_desc_center_0_before_12__inline_negative_alias",
        "0_before_12",
        "inline",
        8_899_674,
        "b2c62ea34bef321dbf4f8bfbaf54333052c3f22f4324ab147b509985427c3c7c",
    ),
    (
        "weighted_desc_center_0_before_12__materialized_negative_alias",
        "0_before_12",
        "materialized",
        8_899_730,
        "f5fef9ba963c416b9fa2a69ea62cdb87ac89e576334d115f849be5c62e3753f6",
    ),
    (
        "weighted_desc_center_12_before_0__inline_negative_alias",
        "12_before_0",
        "inline",
        8_899_674,
        "bd09f8dfe0709e038f0b9e8670e8e93bceedd5f486cded456cd1e922848c1889",
    ),
    (
        "weighted_desc_center_12_before_0__materialized_negative_alias",
        "12_before_0",
        "materialized",
        8_899_730,
        "f6a3b7da24bc6e2e18575949c59969b19657f7ac84201b0b4c2669688ced73fa",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_the_position_matched_family_classifier(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "82cd65e9ecc51ba40ec16871cae182ed35f8ad9be5be63ff40806ed9161c91d9"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A173_solver_execution"
    assert protocol["anchors"]["A172"]["sha256"] == MODULE.A172_SHA256
    assert protocol["anchors"]["A170"]["sha256"] == MODULE.A170_SHA256
    assert protocol["contrast_design"]["semantic_change"] is False
    assert protocol["contrast_design"]["position_matched_to_A172"] == [11, 12]
    assert protocol["mechanism_rules"] == {
        "weighted_center_delta_negative": "family_context_supported",
        "weighted_center_delta_positive": "central_position_supported",
        "weighted_center_delta_zero": "weighted_center_boundary",
        "directional_delta": "effect_12_before_0_minus_effect_0_before_12",
        "A172_greedy_max_center_delta": 456,
    }
    assert (
        protocol["information_boundary"]["A173_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["contrast_plan_sha256"] == (
        "2ab440c8cc5cbdf7d8896b2cead2c5f13499cda1ecfebef9ccde18798c14a99e"
    )
    assert analysis["formula_plan_sha256"] == (
        "aa400b39dff773acf94c5aca38de11a6e26503e84dfd986482adbc6f38e7696f"
    )


def test_weighted_contrast_is_position_matched_to_A172(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["contrast_plan"]
    zero_first = plan["zero_before_twelve_order"]
    twelve_first = plan["twelve_before_zero_order"]
    differences = [
        index
        for index, (left, right) in enumerate(zip(zero_first, twelve_first, strict=True))
        if left != right
    ]
    assert plan["source_order_name"] == "weighted_degree_descending"
    assert plan["adjacent_positions"] == [11, 12]
    assert plan["position_matched_to_A172"] is True
    assert plan["family_changed_relative_to_A172"] == (
        "greedy_max_remaining_weight_to_weighted_degree_descending"
    )
    assert differences == [11, 12]
    assert [zero_first[index] for index in differences] == [0, 12]
    assert [twelve_first[index] for index in differences] == [12, 0]
    assert plan["other_22_relative_order_preserved"] is True


def test_four_exact_inline_materialized_contrast_formulas(
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
        assert encoding["position_matched_A172_family_contrast"] is True
        assert encoding["mechanism_classification_rule"] == (
            "negative_delta_family_context_positive_delta_central_position_zero_boundary"
        )
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_contrast_selection"] is False


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


def test_family_contrast_classifier_separates_context_from_position(
    analysis: dict[str, Any],
) -> None:
    a172, _a170, _a166 = analysis["anchors"]
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
    result = MODULE._family_contrast_result(a172, executions)
    assert result["greedy_max_directional_delta"] == 456
    assert result["weighted_desc_directional_delta"] == -500
    assert result["mechanism_classification"] == "family_context_supported"
    assert result["family_context_supported"] is True
    assert result["central_position_supported"] is False


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


def test_retained_a173_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A173"
    assert payload["evidence_stage"] == "CENTER_POSITION_FAMILY_CONTRAST_EXECUTED"
    assert payload["anchor_gates"]["A173_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A172"]["artifact_sha256"] == MODULE.A172_SHA256
    assert payload["anchor_gates"]["A170"]["artifact_sha256"] == MODULE.A170_SHA256
    assert payload["contrast_plan_sha256"] == (
        "2ab440c8cc5cbdf7d8896b2cead2c5f13499cda1ecfebef9ccde18798c14a99e"
    )
    assert payload["formula_plan_sha256"] == (
        "aa400b39dff773acf94c5aca38de11a6e26503e84dfd986482adbc6f38e7696f"
    )
    assert payload["family_contrast_result_sha256"] == (
        "7cffb3b309666c431ec056c24101512b167550db2a5a0085b1ed8ffde5dcb909"
    )
    assert payload["contrast_plan"] == analysis["contrast_plan"]
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
            "binary-propagations": 115_437_252,
            "conflicts": 3_872,
            "decisions": 16_006,
            "propagations": 446_693_994,
            "restarts": 4,
            "rlimit-count": 501_080_364,
        },
        {
            "binary-propagations": 118_968_562,
            "conflicts": 2_279,
            "decisions": 10_919,
            "propagations": 444_801_371,
            "restarts": 8,
            "rlimit-count": 501_080_369,
        },
        {
            "binary-propagations": 118_146_935,
            "conflicts": 2_468,
            "decisions": 6_020,
            "propagations": 444_875_193,
            "restarts": 11,
            "rlimit-count": 501_080_364,
        },
        {
            "binary-propagations": 119_232_944,
            "conflicts": 2_317,
            "decisions": 11_888,
            "propagations": 444_813_428,
            "restarts": 4,
            "rlimit-count": 501_080_369,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "031aebd93fc67cf2bb4e0a10921a7dacff465bfc45a3629e68e46a16e6b4b619",
        "0c9fa8d2ee614e69ded5bf2eccc71e0f392e50c6537f09120f16dfa5ef8d9ccb",
        "c8466ac57a87d8bbe5bd8a5ebc27a2cca76c880dba3f27cbaecb220be5edb773",
        "a94428be4b074128589ba728a24c72f594a06173bcf7eda2d00db82eff1284cc",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    contrast = payload["family_contrast_result"]
    weighted = contrast["A173_weighted_desc_center"]
    assert [
        (
            row["adjacent_orientation"],
            row["inline_decisions"],
            row["materialized_decisions"],
            row["materialization_effect"],
        )
        for row in weighted["rows"]
    ] == [
        ("0_before_12", 16_006, 10_919, -5_087),
        ("12_before_0", 6_020, 11_888, 5_868),
    ]
    assert weighted["directional_delta_12_before_0_minus_0_before_12"] == 10_955
    assert weighted["signs"] == {"0_before_12": -1, "12_before_0": 1}
    assert contrast["greedy_max_directional_delta"] == 456
    assert contrast["weighted_desc_directional_delta"] == 10_955
    assert contrast["same_position_opposite_family_delta_difference"] == 10_499
    assert contrast["mechanism_classification"] == "central_position_supported"
    assert contrast["central_position_supported"] is True
    assert contrast["family_context_supported"] is False
    assert contrast["weighted_center_boundary"] is False

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A173_execution"] is True
    assert payload["posthoc"]["used_for_contrast_formula_order_or_execution"] is False
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
        "shake128-a172-greedy-center-reversed-direction",
        "shake128-a173-weighted-center-position-match",
        "shake128-a173-four-family-contrast-formulas",
        "shake128-a173-fixed-resource-execution",
        "shake128-a173-family-versus-position-classification",
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
