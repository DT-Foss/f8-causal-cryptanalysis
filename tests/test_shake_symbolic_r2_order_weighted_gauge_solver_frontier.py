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
    / "shake_symbolic_r2_order_weighted_gauge_solver_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_order_weighted_gauge_solver_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "6528a62e4c12739966d06a0eff910fdf3b2739b53e83cc0dd2577a4afa1d6c8d"
CAUSAL_SHA256 = "4131017442be841af656011b1c9e2543ad48496a2fa247c97cbc49d4775ff045"
CAUSAL_GRAPH_SHA256 = "5fe9b646a12f3071513713f725e6eec985eb403b198c6b6b7e77f5dbce2a8f44"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__front_loaded_declaration_position",
        0x498A92,
        8_899_622,
        "c914f68875fa0ebc91e2c46106bad5afd1bb230ac2c0bf001dcc784c17027ff2",
        "117adf3baf0ce9fe55d55376f5a293026610a9461416eed64d1724a33daf97c2",
    ),
    (
        "weighted_degree_descending__back_loaded_declaration_position",
        0x954B3C,
        8_899_887,
        "139c6c248012e5da1e2b44cd3173ac9b52fe65b36279c3f84effdde327d4e11c",
        "1e0da10c2733200ffa788fefdae92aa7e9236b26f16fda60ab87138455f06eac",
    ),
    (
        "weighted_degree_ascending__front_loaded_declaration_position",
        0x954B3C,
        8_900_448,
        "4e1b71ffe89ce55a09f4c34b6bc7057acdcb52988d5efc9541cdf6a31ba025f6",
        "40a6881b60252a3404d7aeab45cceb05c78357c0555a9a9a06b057acad902280",
    ),
    (
        "weighted_degree_ascending__back_loaded_declaration_position",
        0x498A92,
        8_899_998,
        "b84b069305ab537c951499dbaf2c20d256154a981356f0a3a9f82d410bed56c4",
        "9b92b8ce667bc51d33b451461347473929248ae181309f62e04206c836681552",
    ),
    (
        "greedy_max_remaining_weight__front_loaded_declaration_position",
        0x498A92,
        8_899_624,
        "067c602a220621369b9666940c1605724969d07df739791c5b4ffbe23442ffe7",
        "0f493de2867c215b8b379e7a6ad3a35012d0ee5b8c5c09d0139afc5655289edc",
    ),
    (
        "greedy_max_remaining_weight__back_loaded_declaration_position",
        0x4E1E28,
        8_899_756,
        "8b832e1ed4b05222eb49bf0569176031cfaf8a55a1a6333dac6a1d02ec9fd3b3",
        "9d5efe4aa870f0257f176651347647fc0c84a5c5e0e4ca6e3acf35f4b1fdfa3c",
    ),
    (
        "greedy_min_remaining_weight__front_loaded_declaration_position",
        0x954B3C,
        8_900_427,
        "8619575a9a833163a320ae9252d87e553608fd81ae7c748a8e8ecd70b0c9741d",
        "3a0843d275b8a8c45d13f34d102b24c4f3a2bcd44d4c79ff5bb4364df6d652a4",
    ),
    (
        "greedy_min_remaining_weight__back_loaded_declaration_position",
        0x8C161B,
        8_900_329,
        "4c2969ed9d31c668e82bcea974f5cf379fd5db99eb9a3b10d97faee194a24790",
        "1420329f4e7094c8f9d5444106b9eb4b50a7d8b8d01f0d97d23c0caed6fa7a9a",
    ),
]
EXPECTED_ENCODER_SHAPES = [
    (1_597, [453, 917, 1_454], 121_577, 122_897),
    (1_596, [453, 516, 917, 1_454], 121_576, 122_896),
    (1_596, [453, 516, 917, 1_454], 121_576, 122_896),
    (1_597, [453, 917, 1_454], 121_577, 122_897),
    (1_597, [453, 917, 1_454], 121_577, 122_897),
    (1_596, [453, 516, 990, 1_454], 121_576, 122_896),
    (1_596, [453, 516, 917, 1_454], 121_576, 122_896),
    (1_598, [516, 990], 121_578, 122_898),
]


def test_a159_a161_a162_anchor_gates_freeze_all_eight_pairs() -> None:
    a162, a161, a159 = MODULE._load_anchor_gates(RESULTS_DIR)
    assert [row["name"] for row in a162["landscapes"]] == MODULE._expected_names()
    assert all(row["minimum_tie_count"] == 1 for row in a162["landscapes"])
    assert a161["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert a159["parameters"]["rlimit_per_formula"] == 500_000_000
    assert all(row["rlimit"] == 500_000_000 for row in a159["fixed_resource_plan"])


def test_analyze_freezes_eight_exact_order_weighted_gauge_formulas() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["formula_plan_sha256"] == (
        "0c14756cb1c5f8dd0cd9403f4f6d963bb4aab0800cf73dd4791509c62f7c2f30"
    )
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, expected, shape in zip(
        analysis["rows"], EXPECTED_FORMULAS, EXPECTED_ENCODER_SHAPES, strict=True
    ):
        name, shift, formula_bytes, formula_sha, polynomial_sha = expected
        definitions, aliases, total_variables, total_assertions = shape
        encoding = row["encoding"]
        assert row["name"] == name
        assert row["formula_bytes"] == formula_bytes
        assert row["formula_sha256"] == formula_sha
        assert encoding["affine_shift_original_input_mask"] == shift
        assert encoding["R2_polynomial_state_sha256_in_solver_basis"] == polynomial_sha
        assert encoding["shared_monomial_count"] == 301
        assert encoding["quadratic_monomials"] == 276
        assert encoding["R2_state_definitions"] == definitions
        assert encoding["R2_alias_coordinates"] == aliases
        assert encoding["total_variables"] == total_variables
        assert encoding["total_assertions"] == total_assertions
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_gauge_selection"] is False


def test_all_eight_model_maps_recover_the_complete_rate_witness() -> None:
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
        verified = MODULE._verify_solver_row(
            dict(row),
            {"status": "sat", "solver_basis_assignment": solver_assignment},
            analysis["problem"],
            analysis["variant"],
        )
        assert verified["shifted_input_coordinate_assignment"] == shifted_assignment
        assert verified["input_coordinate_assignment"] == input_assignment
        assert verified["independent_complete_rate_check"]["complete_rate_match"] is True

    with pytest.raises(RuntimeError, match="independently invalid"):
        MODULE._verify_solver_row(
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


def test_retained_a163_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A163"
    assert payload["anchor_gates"]["A159"]["artifact_sha256"] == MODULE.A159_SHA256
    assert payload["anchor_gates"]["A161"]["artifact_sha256"] == MODULE.A161_SHA256
    assert payload["anchor_gates"]["A162"]["artifact_sha256"] == MODULE.A162_SHA256
    assert payload["formula_plan_sha256"] == (
        "0c14756cb1c5f8dd0cd9403f4f6d963bb4aab0800cf73dd4791509c62f7c2f30"
    )
    assert payload["control_comparison_sha256"] == (
        "94e16df30eb35f7a98fc7a1384991dc2f9784884e657f48397ad0ac494172d39"
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
        501_080_246,
        501_080_301,
        501_079_775,
        501_079_766,
        501_080_152,
        501_080_261,
        501_079_839,
        501_079_865,
    ]
    assert [row["stats"]["decisions"] for row in summaries] == [
        6_785,
        13_930,
        9_781,
        10_687,
        8_311,
        6_870,
        9_512,
        12_528,
    ]
    assert [row["stats"]["conflicts"] for row in summaries] == [
        2_350,
        2_334,
        2_274,
        2_781,
        2_252,
        2_431,
        2_496,
        2_428,
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "2aa7271ffabfdfc81ec3595a4c58d8724c27cd24aabdb00205e370559ce8d2dd",
        "22ff0f937f196ac4dafbc5505c77a15c815ac7974f72a3c5fa57c9b7db47a06a",
        "d6037d3e7f691badc03ada39e406bf30b8b67f6c7dcfedf094ac15d9c5f330d6",
        "4f1cb8f84ac144ca02ae2ccfd4fd62f231a54bbd77bea6929adb54f3a749a50e",
        "0997395525393fba5eaa54eaed08d393d62623d377e6b40bd8cfe482c16aa217",
        "0e00325f48483c82c2e42cfac54d84e581b165f7313011bd53d907fca0fa05bf",
        "db1aa472dc5bb2b5c63c67cf12d2b10106fed30c3dbbf806087e781e3f1d0929",
        "fd3eece2212f08995b1ebe9797d6a383de2c730d9a55b5b35f3c438042dc347a",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    comparisons = payload["control_comparison"]
    assert [row["decision_delta_from_zero_gauge"] for row in comparisons] == [
        -155,
        6_990,
        -4_605,
        -3_699,
        -4_987,
        -6_428,
        -9_424,
        -6_408,
    ]
    assert [row["decision_delta_from_A160_gauge"] for row in comparisons] == [
        -5_074,
        2_071,
        -712,
        194,
        2_487,
        1_046,
        1_975,
        4_991,
    ]
    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_encoder_execution"] is True
    assert payload["posthoc"]["used_for_formula_construction_order_gauge_or_execution"] is False
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
    assert len(rows) == 4
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a162-eight-order-weighted-gauges",
        "shake128-a163-eight-fullround-formulas",
        "shake128-a163-fixed-resource-execution",
        "shake128-a163-factorial-control-comparison",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
    ]
