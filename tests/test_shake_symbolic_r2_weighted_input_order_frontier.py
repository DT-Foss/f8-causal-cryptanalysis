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
    / "shake_symbolic_r2_weighted_input_order_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_weighted_input_order_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "f8852a160b11094a5d5b3a2a4c193575a849f15c4e6f489527df391566ff9382"
CAUSAL_SHA256 = "ff063a9e225c135aa7972bf8b18b3d6241633526316baca11ef61a1b6598bf51"
CAUSAL_GRAPH_SHA256 = "6df9ddf1d65b86a6295f87476a9ee26271c4b76040f39a23057403022acb8d8d"
EXPECTED_ORDERS = {
    "weighted_degree_descending": [
        11,
        2,
        15,
        7,
        16,
        4,
        8,
        9,
        3,
        0,
        12,
        22,
        21,
        20,
        18,
        5,
        10,
        19,
        6,
        17,
        14,
        13,
        23,
        1,
    ],
    "weighted_degree_ascending": [
        1,
        23,
        13,
        14,
        17,
        6,
        19,
        10,
        5,
        18,
        20,
        21,
        22,
        0,
        12,
        3,
        9,
        8,
        4,
        16,
        7,
        15,
        2,
        11,
    ],
    "greedy_max_remaining_weight": [
        11,
        2,
        15,
        7,
        4,
        16,
        3,
        9,
        12,
        22,
        20,
        8,
        21,
        10,
        0,
        5,
        6,
        18,
        19,
        17,
        14,
        1,
        13,
        23,
    ],
    "greedy_min_remaining_weight": [
        1,
        23,
        13,
        6,
        14,
        17,
        10,
        5,
        19,
        12,
        20,
        21,
        3,
        18,
        22,
        0,
        9,
        8,
        4,
        7,
        15,
        11,
        2,
        16,
    ],
}
EXPECTED_FORMULAS = {
    "weighted_degree_descending": (
        8_900_978,
        "742fafd690f71aa93ec98a9b24f84fa51d4715103eecea03843d9bd46c977295",
    ),
    "weighted_degree_ascending": (
        8_901_450,
        "7b64ba9a3509fff7b28026e2c07af35da0ee9609fed9f163842b39ddf4f1ea66",
    ),
    "greedy_max_remaining_weight": (
        8_900_967,
        "81e97db7caa37668f070b1348be25868f6525269fa1bd5f7744610f1bdd67581",
    ),
    "greedy_min_remaining_weight": (
        8_901_423,
        "a6c2041dfe0cf6d1dcb48870c96798902fd21e36e40f781a5ee607f8819ad1d2",
    ),
}


def test_a157_anchor_gate_retains_exact_order_separation() -> None:
    payload = MODULE._load_a157_gate(RESULTS_DIR)
    decisions = {
        row["name"]: int(row["solver"]["stats"]["decisions"]) for row in payload["execution"]
    }
    assert decisions == {
        "original_lazy": 20_649,
        "original_frequency": 20_703,
        "pivot_lazy": 11_853,
        "pivot_frequency": 12_284,
    }


def test_weighted_graph_and_orders_are_exact_and_assignment_free() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    weighted = analysis["weighted"]
    assert weighted["edge_count"] == 276
    assert weighted["minimum_edge_weight"] == 35
    assert weighted["maximum_edge_weight"] == 88
    assert weighted["total_edge_weight"] == 15_972
    assert weighted["weighted_matrix_sha256"] == (
        "bd7e5fbf292b0912dc143fbfbc8c7a8f9aec13a7ac29633f86835306c4004c1b"
    )
    assert weighted["weighted_degrees"] == [
        1358,
        1122,
        1505,
        1371,
        1415,
        1291,
        1250,
        1426,
        1375,
        1372,
        1280,
        1528,
        1358,
        1219,
        1237,
        1452,
        1425,
        1243,
        1292,
        1276,
        1321,
        1330,
        1339,
        1159,
    ]
    assert analysis["orders"] == EXPECTED_ORDERS
    assert len({tuple(order) for order in analysis["orders"].values()}) == 4


def test_analyze_freezes_four_exact_weighted_order_formulas() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["formula_plan_sha256"] == (
        "aca15c4f43d960814f86a58d459f9f1a38714dab8152483eeb68f4c58eb08911"
    )
    assert [row["name"] for row in analysis["rows"]] == list(EXPECTED_ORDERS)
    for row in analysis["rows"]:
        expected_bytes, expected_sha = EXPECTED_FORMULAS[row["name"]]
        assert row["formula_bytes"] == expected_bytes
        assert row["formula_sha256"] == expected_sha
        encoding = row["encoding"]
        assert encoding["variable_to_input_coordinate"] == EXPECTED_ORDERS[row["name"]]
        assert encoding["shared_monomial_count"] == 301
        assert encoding["quadratic_monomials"] == 276
        assert encoding["R2_state_definitions"] == 1598
        assert encoding["total_variables"] == 121_578
        assert encoding["total_assertions"] == 122_898
        assert encoding["target_rate_bits"] == 1344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_order_derivation"] is False


def test_retained_a158_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gate"]["A157_artifact_sha256"] == MODULE.A157_SHA256
    assert payload["weighted_graph"]["weighted_matrix_sha256"] == (
        MODULE.EXPECTED_WEIGHTED_MATRIX_SHA256
    )
    assert payload["orders"] == EXPECTED_ORDERS
    assert payload["orders_sha256"] == (
        "f92fbe97375e284626ed4632bdd7b064b2f04531b8a87fbb59375bd33823208e"
    )
    assert payload["formula_plan_sha256"] == (
        "aca15c4f43d960814f86a58d459f9f1a38714dab8152483eeb68f4c58eb08911"
    )
    assert payload["status_counts"] == {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
    assert payload["confirmed_models"] == []
    assert [row["name"] for row in payload["execution"]] == list(EXPECTED_ORDERS)
    assert [int(row["solver"]["stats"]["decisions"]) for row in payload["execution"]] == [
        10_990,
        18_485,
        17_799,
        23_097,
    ]
    assert all(row["solver"]["status"] == "unknown" for row in payload["execution"])
    assert all(row["solver"]["return_code"] == 0 for row in payload["execution"])
    assert all(row["solver"]["external_timeout"] is False for row in payload["execution"])
    assert all(row["solver"]["solver_basis_assignment"] is None for row in payload["execution"])
    assert payload["posthoc"]["instrumented_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_encoder_execution"] is True
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert len(reader.triplets(include_inferred=False)) == 4
