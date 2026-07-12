from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_id_preserving_signed_alias_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_id_preserving_signed_alias_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.causal"
RESULT_SHA256 = "24ad17ce715c3471bef30979a16e973f742163931e9cd9e4acae93562f00fcdc"
CAUSAL_SHA256 = "c922135a3a191c33a393a43d649b6eb595de34aadc36cd5ec20e45c063f81419"
CAUSAL_GRAPH_SHA256 = "4c5d50f49327f380b1748cdee878c93a96ef4bfbcadd406ea639f03d58796843"
DECLARATION_SHA256 = "6ae51cff0ad3707df512db5933edd29dac9bf981b89b0201962ab1c1d79cfd61"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__id_preserving_signed_alias",
        8_899_746,
        "820a8194d49d916fc8a758e06b4caf2f0f39ca1653340c0a8aa704da63e29095",
        "A164",
    ),
    (
        "weighted_degree_ascending__id_preserving_signed_alias",
        8_900_254,
        "21e6f5e9f5c4369d60eb19cb971d92e5d6fe67142df7ba69faf47ac14cf2f6ca",
        "A164",
    ),
    (
        "greedy_max_remaining_weight__id_preserving_signed_alias",
        8_899_729,
        "b185f101a58c369d915a329cb194da1c7965e46cbe3492dd6688e46517a53ffa",
        "A163",
    ),
    (
        "greedy_min_remaining_weight__id_preserving_signed_alias",
        8_900_232,
        "55575f27f1524e9382adf77c2535c1f0e8932cff3afc97b472d5e176a196f14c",
        "A164",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_the_three_arm_component_decomposition(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "a26e101e0d7e993dd5cd27485adf0e4d04e4f30f7c3c42a25db7a22ddee9d1c9"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A167_solver_execution"
    assert protocol["anchors"]["A166"]["sha256"] == MODULE.A166_SHA256
    assert protocol["anchors"]["A164"]["sha256"] == MODULE.A164_SHA256
    assert protocol["anchors"]["A163"]["sha256"] == MODULE.A163_SHA256
    assert protocol["control_intervention"]["semantic_change"] is False
    assert protocol["control_intervention"]["downstream_declaration_sequence_equal_to_A164"] is True
    assert (
        protocol["information_boundary"]["A167_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["control_plan_sha256"] == (
        "055c3c829573cbe39c783a686fbe2fc9665ec081b6857cdad04d8133a55650e7"
    )
    assert analysis["formula_plan_sha256"] == (
        "ecdd9c3d43173ae07921f635c831bc67223215589d6aeaff17032d146c8a03cc"
    )


def test_four_formulas_preserve_every_A164_declaration_ID(
    analysis: dict[str, Any],
) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, control, expected in zip(
        analysis["rows"], analysis["control_plan"], EXPECTED_FORMULAS, strict=True
    ):
        name, size, formula_sha256, source_attempt = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha256
        assert encoding["original_control_source_attempt"] == source_attempt
        assert encoding["declaration_sequence_sha256"] == DECLARATION_SHA256
        assert encoding["declaration_sequence_equal_to_A164"] is True
        assert encoding["total_variables"] == 121_576
        assert encoding["total_assertions"] == 122_895
        assert control["original_control_total_variables"] == 121_576
        assert control["original_control_total_assertions"] == 122_896
        assert control["declaration_sequences_identical"] is True
        assert control["semantic_relation_unchanged"] is True


def test_ID_padding_is_declared_at_the_alias_position_but_never_connected(
    analysis: dict[str, Any],
) -> None:
    token = re.compile(rb"(?<![A-Za-z0-9_])s1215(?![A-Za-z0-9_])")
    for row in analysis["rows"]:
        encoding = row["encoding"]
        raw = analysis["formulas"][row["name"]]
        assert encoding["R2_direct_alias_coordinates"] == [453, 516, 990, 1_454]
        assert encoding["R2_complement_alias_coordinates"] == [917]
        assert encoding["R2_id_padding_coordinates"] == [917]
        assert encoding["R2_id_padding_names"] == ["s1215"]
        assert encoding["R2_id_padding_connected_to_formula"] is False
        assert raw.count(b"(declare-fun s1215 () Bool)\n") == 1
        assertion_lines = [line for line in raw.splitlines() if line.startswith(b"(assert ")]
        assert not any(token.search(line) for line in assertion_lines)


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
    a166, a164, _a162 = analysis["anchors"]
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
    assert [row["alias_node_effect_A167_minus_A164"] for row in decomposition["rows"]] == [
        661,
        -402,
        -870,
        -505,
    ]
    assert [row["downstream_ID_shift_effect_A166_minus_A167"] for row in decomposition["rows"]] == [
        1_347,
        -575,
        -753,
        -677,
    ]
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


def test_retained_a167_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A167"
    assert payload["evidence_stage"] == (
        "ID_PRESERVING_SIGNED_ALIAS_COMPONENT_DECOMPOSITION_EXECUTED"
    )
    assert payload["anchor_gates"]["A167_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A166"] == {
        "artifact_sha256": MODULE.A166_SHA256,
        "comparison_sha256": MODULE.A166_COMPARISON_SHA256,
        "decision_deltas": [2_008, -977, -1_623, -1_182],
    }
    assert payload["anchor_gates"]["A164"]["artifact_sha256"] == MODULE.A164_SHA256
    assert payload["formula_plan_sha256"] == (
        "ecdd9c3d43173ae07921f635c831bc67223215589d6aeaff17032d146c8a03cc"
    )
    assert payload["control_plan_sha256"] == (
        "055c3c829573cbe39c783a686fbe2fc9665ec081b6857cdad04d8133a55650e7"
    )
    assert payload["effect_decomposition_sha256"] == (
        "524a5f785e461ba210652f3337be915ecac06ff4e8cf7701a58de51caaebcfde"
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
            "binary-propagations": 118_110_635,
            "conflicts": 2_557,
            "decisions": 7_347,
            "propagations": 444_907_485,
            "restarts": 8,
            "rlimit-count": 501_080_364,
        },
        {
            "binary-propagations": 118_765_094,
            "conflicts": 2_831,
            "decisions": 3_425,
            "propagations": 446_266_704,
            "restarts": 7,
            "rlimit-count": 501_079_870,
        },
        {
            "binary-propagations": 118_828_202,
            "conflicts": 2_233,
            "decisions": 5_247,
            "propagations": 444_843_241,
            "restarts": 3,
            "rlimit-count": 501_080_256,
        },
        {
            "binary-propagations": 119_417_006,
            "conflicts": 2_402,
            "decisions": 5_323,
            "propagations": 446_144_254,
            "restarts": 6,
            "rlimit-count": 501_079_918,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "ab6168baadc3191e523614b4d18e4f87b8b5644edc7c9d06d58ec04d12bf3e0d",
        "618197b2ad48f4fb124acf2bbb115a960bca17ce7f520dff9d271052f03a593f",
        "696daccf9b51d8605d64c0dc3dfc5ff9e668e66652c8a86e191226a541e6b39a",
        "874209fcc6d34e8e45438818dc7da5b19617e54d0feb95b2b5778ce89f80864b",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)

    a166_raw = (RESULTS_DIR / MODULE.A166_FILENAME).read_bytes()
    assert hashlib.sha256(a166_raw).hexdigest() == MODULE.A166_SHA256
    a166_summaries = json.loads(a166_raw)["execution_summary"]
    for field in ("decisions", "conflicts", "restarts", "rlimit-count"):
        assert [row["stats"][field] for row in summaries] == [
            row["stats"][field] for row in a166_summaries
        ]
    assert [
        row["stats"]["propagations"] - control["stats"]["propagations"]
        for row, control in zip(summaries, a166_summaries, strict=True)
    ] == [1_224, -311, 130, 164]
    assert [
        row["stats"]["binary-propagations"] - control["stats"]["binary-propagations"]
        for row, control in zip(summaries, a166_summaries, strict=True)
    ] == [19, -26, 46, 131]

    decomposition = payload["effect_decomposition"]
    assert decomposition["alias_node_effect_L1"] == 5_790
    assert decomposition["downstream_ID_shift_effect_L1"] == 0
    assert decomposition["aggregate_dominant_component"] == "alias_node_removal"
    assert decomposition["all_alias_node_directions_match_A166_total"] is True
    rows = decomposition["rows"]
    assert [row["A164_materialized_original_ID_decisions"] for row in rows] == [
        5_339,
        4_402,
        6_870,
        6_505,
    ]
    assert [row["A166_inlined_shifted_ID_decisions"] for row in rows] == [
        7_347,
        3_425,
        5_247,
        5_323,
    ]
    assert [row["A167_inlined_original_ID_decisions"] for row in rows] == [
        7_347,
        3_425,
        5_247,
        5_323,
    ]
    assert [row["alias_node_effect_A167_minus_A164"] for row in rows] == [
        2_008,
        -977,
        -1_623,
        -1_182,
    ]
    assert [row["downstream_ID_shift_effect_A166_minus_A167"] for row in rows] == [
        0,
        0,
        0,
        0,
    ]
    assert all(row["exact_additive_identity_verified"] for row in rows)

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A167_execution"] is True
    assert payload["posthoc"]["used_for_control_formula_order_or_execution"] is False
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
        "shake128-a164-materialized-alias-original-IDs",
        "shake128-a166-inlined-alias-shifted-IDs",
        "shake128-a167-inlined-alias-original-IDs",
        "shake128-a167-fixed-resource-execution",
        "shake128-a167-two-component-effect-decomposition",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
