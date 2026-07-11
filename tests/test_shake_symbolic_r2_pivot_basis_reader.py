from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_pivot_basis_reader.py"
)
SPEC = importlib.util.spec_from_file_location("shake_symbolic_r2_pivot_basis_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULT_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.RESULT_FILENAME
CAUSAL_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.CAUSAL_FILENAME
ANCHOR_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.A154_FILENAME
RESULT_SHA256 = "ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80"
CAUSAL_SHA256 = "9fb214d4348cb13304a0af15022b4699d646f9c406ce94c5c5bc9b8d24756d23"
CAUSAL_GRAPH_SHA256 = "baa6c92ef15f075361071e7112363f906b49cc07139f4cbdc1f2c133b4e8be7f"


def test_a154_systematic_basis_gate_is_exact() -> None:
    payload, gate = MODULE._load_a154_gate(ANCHOR_PATH)
    assert gate["artifact_sha256"] == MODULE.A154_SHA256
    assert gate["rank"] == 24
    assert gate["systematic_unit_row_basis"] is True
    assert sorted(payload["basis"]["pivot_delta_to_input_coordinate"]) == list(range(24))


def test_linear_basis_substitution_is_exact_on_toy_polynomials() -> None:
    # x0 = z1, x1 = z0, so 1 + x0*x1 maps to 1 + z0*z1.
    original = [frozenset({0, 0b11})]
    transformed = MODULE._substitute_linear_basis(original, [0b10, 0b01], 2)
    assert transformed == original
    # x0 = z0+z1 and x1 = z1 gives x0*x1 = z0*z1+z1 over Boolean GF(2).
    transformed = MODULE._substitute_linear_basis([frozenset({0b11})], [0b11, 0b10], 2)
    assert transformed == [frozenset({0b11, 0b10})]


def test_complete_graph_proof_has_exact_cover_boundary() -> None:
    edges = [list(edge) for edge in itertools.combinations(range(5), 2)]
    proof = MODULE._complete_graph_proof(edges, 5)
    assert proof["graph"] == "K5"
    assert proof["observed_edges"] == 10
    assert proof["minimum_vertex_cover_size"] == 4
    assert proof["minimum_vertex_cover_count"] == 5
    assert proof["maximum_independent_set_size"] == 1
    with pytest.raises(RuntimeError, match="not complete"):
        MODULE._complete_graph_proof(edges[:-1], 5)


def test_retained_a155_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gate"]["artifact_sha256"] == MODULE.A154_SHA256
    original = payload["original_R2"]
    pivot = payload["pivot_basis_R2"]
    assert original["polynomial_state_sha256"] == (
        "d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752"
    )
    assert pivot["polynomial_state_sha256"] == (
        "556506048288ec925953fe8044f22cec3b4913e7259529d15568c53d1ddce2e7"
    )
    for row in (original, pivot):
        assert row["maximum_algebraic_degree"] == 2
        assert row["global_monomial_count"] == 301
        assert row["degree_histogram"] == {"0": 1, "1": 24, "2": 276}
        assert row["quadratic_monomial_count"] == 276
        assert len(row["interaction_edges"]) == 276
    proof = payload["complete_graph_proof"]
    assert proof["graph"] == "K24"
    assert proof["minimum_vertex_cover_size"] == 23
    assert proof["minimum_vertex_cover_count"] == 24
    assert payload["transition"]["pairwise_interaction_saturation_first_observed_round"] == 2
    assert payload["verification"]["three_way_state_bits_checked"] == 307_200
    assert payload["basis_map"]["mapped_interaction_edges_equal_transformed_edges"] is True
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert len(reader.triplets(include_inferred=False)) == 4


def test_complete_a155_rerun_is_byte_deterministic(tmp_path: Path) -> None:
    output = tmp_path / MODULE.RESULT_FILENAME
    causal = tmp_path / MODULE.CAUSAL_FILENAME
    summary = MODULE.run(ANCHOR_PATH, output, causal)
    assert summary["json_sha256"] == RESULT_SHA256
    assert summary["causal_sha256"] == CAUSAL_SHA256
    assert summary["causal_graph_sha256"] == CAUSAL_GRAPH_SHA256
    assert summary["quadratic_edges"] == 276
    assert summary["minimum_vertex_cover_size"] == 23
