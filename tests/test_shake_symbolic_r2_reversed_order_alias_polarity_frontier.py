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
    / "shake_symbolic_r2_reversed_order_alias_polarity_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_reversed_order_alias_polarity_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / "shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json"
CAUSAL_PATH = RESULTS_DIR / "shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.causal"
RESULT_SHA256 = "f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f"
CAUSAL_SHA256 = "94ee3ba158d853b1e2e1fb8eeead5de2dadaacda0d47dce10f942643cad98921"
CAUSAL_GRAPH_SHA256 = "6b5a7e11aeaa68c87a6de3c5000f7f21e1d493b0aac97fbab5f1da18a150a77b"
EXPECTED_FORMULAS = [
    (
        "reversed_weighted_degree_descending__inline_negative_alias",
        "inline",
        8_900_219,
        "8906897c35310a08afe3a9eb5f6f411d8d244547d0401a525107a483d38aa25c",
    ),
    (
        "reversed_weighted_degree_descending__materialized_negative_alias",
        "materialized",
        8_900_275,
        "7a7394570d07eeaff46f100a2091fda57afa25a774c7402748f911838694bafd",
    ),
    (
        "reversed_weighted_degree_ascending__inline_negative_alias",
        "inline",
        8_899_679,
        "0e4f73be83500b4a0de23d96d7467e0edf63323b904729129c5006348db229f8",
    ),
    (
        "reversed_weighted_degree_ascending__materialized_negative_alias",
        "materialized",
        8_899_736,
        "0895eeb15b51628be63633bf81462299d5ea6cd793dc39c238dd23828f9c0585",
    ),
    (
        "reversed_greedy_max_remaining_weight__inline_negative_alias",
        "inline",
        8_900_242,
        "89381620ea9e766af21f35d80011ab7772b90a3d3668f5cc5cc32f60765241a9",
    ),
    (
        "reversed_greedy_max_remaining_weight__materialized_negative_alias",
        "materialized",
        8_900_298,
        "2621f5939fbb6e6bfaf2c293054429263282ad52c9c3526803ff1c2044812c0e",
    ),
    (
        "reversed_greedy_min_remaining_weight__inline_negative_alias",
        "inline",
        8_899_708,
        "280a345ce28c55fea735b48b6c209f07f0f5e5021715f7c3056478bda4ee928e",
    ),
    (
        "reversed_greedy_min_remaining_weight__materialized_negative_alias",
        "materialized",
        8_899_764,
        "376775bc43a872597b6b84c6664e48db13b50f6aeb768bb61d7bea19407db6db",
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_four_new_paired_order_reversals(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "683d8363bc0865e48df13a880d9e9344d4acdd2faaf15d1f9eaa03f90ded3012"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A170_solver_execution"
    assert protocol["anchors"]["A169"]["sha256"] == MODULE.A169_SHA256
    assert protocol["anchors"]["A168"]["sha256"] == MODULE.A168_SHA256
    assert protocol["anchors"]["A166"]["sha256"] == MODULE.A166_SHA256
    assert protocol["reversal_design"]["semantic_change"] is False
    assert protocol["reversal_design"]["new_formula_count"] == 8
    assert (
        protocol["information_boundary"]["A170_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["reversal_plan_sha256"] == (
        "ad32560fae33eac765403ae6cc5de579ca13d07561707c78a75ce740870c661a"
    )
    assert analysis["formula_plan_sha256"] == (
        "7f23984189baf93086fec55ab053d2396d9e48855ddaeef55ec1298e13201f68"
    )


def test_reversals_are_unique_complete_permutation_involutions(
    analysis: dict[str, Any],
) -> None:
    base = [row["base_order"] for row in analysis["reversal_plan"]]
    reversed_orders = [row["reversed_order"] for row in analysis["reversal_plan"]]
    assert len({tuple(row) for row in reversed_orders}) == 4
    for row in analysis["reversal_plan"]:
        assert row["reversed_order"] == list(reversed(row["base_order"]))
        assert list(reversed(row["reversed_order"])) == row["base_order"]
        assert row["reversed_order"] not in base
        assert sorted(row["reversed_order"]) == list(range(24))
        assert row["involution_verified"] is True
        assert row["reversed_order_absent_from_four_base_orders"] is True
        assert (
            row["base_alias_input_solver_position"] + row["reversed_alias_input_solver_position"]
            == 23
        )


def test_eight_exact_inline_materialized_formula_pairs(
    analysis: dict[str, Any],
) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected in zip(analysis["rows"], EXPECTED_FORMULAS, strict=True):
        name, arm, size, formula_sha = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["alias_compiler_arm"] == arm
        assert encoding["order_transform"] == "exact_vector_reversal"
        assert encoding["order_reversal_involution_verified"] is True
        assert encoding["affine_shift_original_input_mask"] == 0x4E1E28
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["total_variables"] == (121_575 if arm == "inline" else 121_576)
        assert encoding["total_assertions"] == (122_895 if arm == "inline" else 122_896)
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_reversal_selection"] is False


def test_all_eight_model_maps_recover_the_complete_rate_witness(
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


def test_polarity_frontier_classifies_an_exact_universal_flip(
    analysis: dict[str, Any],
) -> None:
    a169, _a168, _a166 = analysis["anchors"]
    base_effects = {
        row["order_name"]: row["total_materialization_effect"]
        for row in a169["mobius_decomposition"]["rows"]
    }
    executions = []
    for order_name in MODULE._A158.ORDER_NAMES:
        inline = 10_000
        flipped = -base_effects[order_name]
        executions.extend(
            [
                {
                    "encoding": {"base_order_name": order_name, "alias_compiler_arm": "inline"},
                    "solver": {"stats": {"decisions": inline}},
                },
                {
                    "encoding": {
                        "base_order_name": order_name,
                        "alias_compiler_arm": "materialized",
                    },
                    "solver": {"stats": {"decisions": inline + flipped}},
                },
            ]
        )
    frontier = MODULE._polarity_frontier(a169, executions)
    assert frontier["polarity_counts"] == {"flipped": 4, "preserved": 0, "zero": 0}
    assert frontier["all_four_polarities_flipped"] is True
    assert frontier["reversal_rule"] == "universal_flip"
    assert [row["reversed_materialization_effect"] for row in frontier["rows"]] == [
        2_008,
        -977,
        -1_623,
        -1_182,
    ]


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


def test_retained_a170_artifacts_are_hash_pinned_and_reader_valid(
    analysis: dict[str, Any],
) -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A170"
    assert payload["evidence_stage"] == "REVERSED_ORDER_ALIAS_POLARITY_FRONTIER_EXECUTED"
    assert payload["anchor_gates"]["A170_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A169"]["artifact_sha256"] == MODULE.A169_SHA256
    assert payload["anchor_gates"]["A168"]["artifact_sha256"] == MODULE.A168_SHA256
    assert payload["anchor_gates"]["A166"]["artifact_sha256"] == MODULE.A166_SHA256
    assert payload["reversal_plan_sha256"] == (
        "ad32560fae33eac765403ae6cc5de579ca13d07561707c78a75ce740870c661a"
    )
    assert payload["formula_plan_sha256"] == (
        "7f23984189baf93086fec55ab053d2396d9e48855ddaeef55ec1298e13201f68"
    )
    assert payload["polarity_frontier_sha256"] == (
        "8fe2d08594044697a0aa27f17c3fd1dda253b76eea6ae2bca39a6f6da24e9a92"
    )
    assert payload["reversal_plan"] == analysis["reversal_plan"]
    assert payload["formula_plan"] == analysis["formula_plan"]
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 8,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []

    summaries = payload["execution_summary"]
    assert [row["name"] for row in summaries] == [row[0] for row in EXPECTED_FORMULAS]
    assert [row["stats"] for row in summaries] == [
        {
            "binary-propagations": 118_747_520,
            "conflicts": 2_569,
            "decisions": 6_735,
            "propagations": 446_177_696,
            "restarts": 5,
            "rlimit-count": 501_079_864,
        },
        {
            "binary-propagations": 117_927_172,
            "conflicts": 2_551,
            "decisions": 5_454,
            "propagations": 446_182_164,
            "restarts": 9,
            "rlimit-count": 501_079_869,
        },
        {
            "binary-propagations": 117_798_350,
            "conflicts": 2_652,
            "decisions": 8_543,
            "propagations": 444_930_912,
            "restarts": 10,
            "rlimit-count": 501_080_360,
        },
        {
            "binary-propagations": 118_866_200,
            "conflicts": 2_430,
            "decisions": 5_645,
            "propagations": 444_887_132,
            "restarts": 14,
            "rlimit-count": 501_080_365,
        },
        {
            "binary-propagations": 118_343_171,
            "conflicts": 2_399,
            "decisions": 5_159,
            "propagations": 446_097_130,
            "restarts": 2,
            "rlimit-count": 501_079_942,
        },
        {
            "binary-propagations": 120_271_484,
            "conflicts": 2_266,
            "decisions": 4_217,
            "propagations": 446_124_625,
            "restarts": 5,
            "rlimit-count": 501_079_947,
        },
        {
            "binary-propagations": 119_177_813,
            "conflicts": 2_265,
            "decisions": 4_693,
            "propagations": 444_877_807,
            "restarts": 5,
            "rlimit-count": 501_080_338,
        },
        {
            "binary-propagations": 118_654_955,
            "conflicts": 2_323,
            "decisions": 5_711,
            "propagations": 444_859_581,
            "restarts": 7,
            "rlimit-count": 501_080_343,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "dab7bf13ac023e7a526bd1a292590f12c8c889e9cfada1d23ab0796ba6f29797",
        "7e62d2383ff2523e5f5b864d28ce32af3d2ab75afe078e8ee3d437d7bf461a95",
        "e2f403b79a27a34423cdcd74ffb1d06d0ffe2a9fe113b43db66a75bcfcc9a17c",
        "ef43beddf5f4f25fdc00b37ab76643f5c5ea964c7efe24be025a86ddc4e60cce",
        "729114a296879cb9311f55dd8817a0388221ee03a338cbdf89dc0c64f509e42d",
        "4eb130691e980c65fa0d2045c869bbf0556d44748068c20e9ecee5d5723008df",
        "a812bec06e2b4f81769f162df0e985deb060ebc47781997e36a63c5efd10ece6",
        "c31cda468e087742a91010623fd4cf4f8b71b1a7a3e95dda3e2245eac12ba5b5",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert all(row["independently_confirmed_model"] is False for row in summaries)

    polarity = payload["polarity_frontier"]
    assert polarity["polarity_counts"] == {"flipped": 2, "preserved": 2, "zero": 0}
    assert polarity["all_four_polarities_flipped"] is False
    assert polarity["all_four_polarities_preserved"] is False
    assert polarity["reversal_rule"] == "mixed_reversal_response"
    assert [
        (
            row["reversed_inline_decisions"],
            row["reversed_materialized_decisions"],
            row["reversed_materialization_effect"],
            row["polarity_relation"],
        )
        for row in polarity["rows"]
    ] == [
        (6_735, 5_454, -1_281, "preserved"),
        (8_543, 5_645, -2_898, "flipped"),
        (5_159, 4_217, -942, "flipped"),
        (4_693, 5_711, 1_018, "preserved"),
    ]

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A170_execution"] is True
    assert payload["posthoc"]["used_for_reversal_formula_order_or_execution"] is False
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
        "shake128-a169-order-dependent-two-path-polarity",
        "shake128-a170-four-exact-order-reversals",
        "shake128-a170-eight-inline-materialized-formulas",
        "shake128-a170-fixed-resource-execution",
        "shake128-a170-reversal-polarity-frontier",
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
