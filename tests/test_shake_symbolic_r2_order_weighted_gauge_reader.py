from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_order_weighted_gauge_reader.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_order_weighted_gauge_reader_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "d91b3210a107a815934ee7498c37f9da2740e2c03019feb8af23fe8c9df3549a"
CAUSAL_SHA256 = "c3faa490a32feca55e10dcb9f5e890053fb6791049e3b29ee470b980e00aadb4"
CAUSAL_GRAPH_SHA256 = "91a520c2e5a0f377503c4b3dd14d3b60bbf2acaaa85bcc1bd7f6ae79b975707e"
EXPECTED_LANDSCAPES = [
    (
        "weighted_degree_descending__front_loaded_declaration_position",
        0x498A92,
        108_353,
        112_928,
        109_031,
    ),
    (
        "weighted_degree_descending__back_loaded_declaration_position",
        0x954B3C,
        101_056,
        104_522,
        101_294,
    ),
    (
        "weighted_degree_ascending__front_loaded_declaration_position",
        0x954B3C,
        101_053,
        104_526,
        101_275,
    ),
    (
        "weighted_degree_ascending__back_loaded_declaration_position",
        0x498A92,
        108_342,
        112_924,
        109_050,
    ),
    (
        "greedy_max_remaining_weight__front_loaded_declaration_position",
        0x498A92,
        108_134,
        112_932,
        108_975,
    ),
    (
        "greedy_max_remaining_weight__back_loaded_declaration_position",
        0x4E1E28,
        101_145,
        104_518,
        101_350,
    ),
    (
        "greedy_min_remaining_weight__front_loaded_declaration_position",
        0x954B3C,
        101_218,
        104_577,
        101_395,
    ),
    (
        "greedy_min_remaining_weight__back_loaded_declaration_position",
        0x8C161B,
        108_363,
        112_873,
        108_930,
    ),
]


def test_a160_a161_anchor_chain_is_exact_and_objective_independent() -> None:
    a160, a161 = MODULE._load_anchor_gates(RESULTS_DIR)
    assert a160["global_optimum"]["minimum_shift"] == MODULE.A160_SHIFT
    assert a160["walsh_objective"]["linear_coefficient_positions"] == 38_400
    assert a161["formula_plan_sha256"] == (
        "e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3"
    )
    assert [row["decision_delta"] for row in a161["baseline_comparison"]] == [
        4_919,
        -3_893,
        -7_474,
        -11_399,
    ]


def test_front_and_back_position_weights_are_exact_complements() -> None:
    baseline = MODULE._A159.analyze(RESULTS_DIR)
    for order in baseline["orders"].values():
        front = MODULE._input_weights(order, "front_loaded_declaration_position")
        back = MODULE._input_weights(order, "back_loaded_declaration_position")
        assert sorted(front) == list(range(1, 25))
        assert sorted(back) == list(range(1, 25))
        assert [left + right for left, right in zip(front, back, strict=True)] == [25] * 24


def test_full_order_weighted_landscapes_reproduce_exactly() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["objective_plan_sha256"] == (
        "82d519e297cd4c27cce2aca04ddcec2e81fab3fbdb25df75dc96c549a1916cd7"
    )
    assert analysis["landscape_plan_sha256"] == (
        "69731436c46e6ad8472fb453fdbb963b8fa95554609291c2e7d621e5a4177367"
    )
    observed = [
        (
            row["name"],
            row["minimum_shift"],
            row["minimum_weighted_linear_incidence"],
            row["zero_shift_weighted_linear_incidence"],
            row["A160_shift_weighted_linear_incidence"],
        )
        for row in analysis["landscapes"]
    ]
    assert observed == EXPECTED_LANDSCAPES
    assert all(row["minimum_tie_count"] == 1 for row in analysis["landscapes"])
    assert all(row["walsh_parseval_verified"] is True for row in analysis["landscapes"])
    assert all(
        row["minimum_weighted_linear_incidence"]
        < row["A160_shift_weighted_linear_incidence"]
        < row["zero_shift_weighted_linear_incidence"]
        for row in analysis["landscapes"]
    )
    assert [row["shift"] for row in analysis["unique_selected_shifts"]] == [
        0x498A92,
        0x4E1E28,
        0x8C161B,
        0x954B3C,
    ]
    assert analysis["semantic_gate_plan_sha256"] == (
        "d4a1f290e5dc651a22a15c88a0d8f76a19351ce30578315419bb3d446d2b53ba"
    )
    assert all(
        row["per_coordinate_quadratic_terms_unchanged"] is True
        and row["coefficient_incidence"]["quadratic"] == 15_972
        and row["verification"]["three_way_state_bits_checked"] == 307_200
        for row in analysis["semantic_gates"]
    )


def test_retained_a162_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gates"]["A160"]["artifact_sha256"] == MODULE.A160_SHA256
    assert payload["anchor_gates"]["A161"]["artifact_sha256"] == MODULE.A161_SHA256
    assert payload["anchor_gates"]["A161"]["solver_counters_used_in_objective"] is False
    assert payload["parameters"]["target_rate_input_used"] is False
    assert payload["parameters"]["solver_observations_used_in_objective"] is False
    assert payload["parameters"]["instrumented_assignment_used"] is False
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 4
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a161-gauge-by-order-interaction",
        "shake128-a162-order-weighted-walsh-objectives",
        "shake128-a162-eight-complete-gauge-landscapes",
        "shake128-a162-selected-gauge-semantic-gates",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
    ]
