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
    / "shake_symbolic_r1_affine_basis_reader.py"
)
SPEC = importlib.util.spec_from_file_location("shake_symbolic_r1_affine_basis_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULT_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.RESULT_FILENAME
CAUSAL_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.CAUSAL_FILENAME
ANCHOR_PATH = Path(__file__).parents[1] / "research" / "results" / "v1" / MODULE.A152_FILENAME
RESULT_SHA256 = "108cbcadcbd7cfc3831712b8d2073aab42d42cca098db162d1d63627882d21dd"
CAUSAL_SHA256 = "0bc86a07227c59f33008f709f0e114acf3f7b8457532f9ff508d4037e071c5fd"
CAUSAL_GRAPH_SHA256 = "c0f8255ca4aa8f7bc3d61a527392cc2294624b5849efac331f23914de6418d0b"
SELECTED_OUTPUTS = [
    3,
    5,
    6,
    10,
    14,
    17,
    18,
    60,
    61,
    63,
    73,
    75,
    76,
    77,
    79,
    80,
    123,
    126,
    128,
    129,
    130,
    132,
    135,
    136,
]


def test_a152_anchor_and_structural_instance_are_exact() -> None:
    gate = MODULE._load_a152_gate(ANCHOR_PATH)
    assert gate["artifact_sha256"] == MODULE.A152_SHA256
    assert gate["quadratic_edge_count"] == 0
    variant = MODULE._BASE.VARIANTS["shake128"]
    _, positions, instance = MODULE._structural_instance(variant)
    assert positions.tolist() == list(range(143, 167))
    assert instance["cleared_template_sha256"] == MODULE.A152_TEMPLATE_SHA256
    assert instance["target_rate_constructed"] is False
    assert instance["instrumented_assignment_extracted"] is False


def test_affine_extractor_rebuilds_rows_and_rejects_quadratic_terms() -> None:
    polynomials = [frozenset() for _ in range(MODULE.STATE_BITS)]
    polynomials[0] = frozenset({0, 1, 4})
    extracted = MODULE._affine_rows(polynomials, 3)
    assert extracted["row_masks"][0] == 0b101
    assert extracted["constants"][0] == 1
    polynomials[1] = frozenset({3})
    with pytest.raises(RuntimeError, match="not affine"):
        MODULE._affine_rows(polynomials, 3)


def test_lexicographic_basis_and_two_sided_inverse_are_exact() -> None:
    rows = [0, 0b011, 0b110, 0b101, 0b001]
    basis = MODULE._lexicographic_row_basis(rows, 3)
    assert basis["rank"] == 3
    assert basis["selected_output_coordinates"] == [1, 2, 4]
    inverse = MODULE._invert_square_gf2(basis["selected_row_masks"], 3)
    proof = MODULE._inverse_proof(basis["selected_row_masks"], inverse)
    assert proof["left_inverse_exact"] is True
    assert proof["right_inverse_exact"] is True
    with pytest.raises(ValueError, match="singular"):
        MODULE._invert_square_gf2([1, 1], 2)


def test_pivot_delta_inverse_recovers_every_input() -> None:
    rows = [0b010, 0b100, 0b001]
    inverse = MODULE._invert_square_gf2(rows, 3)
    for assignment in range(8):
        delta = sum(((row & assignment).bit_count() & 1) << index for index, row in enumerate(rows))
        assert MODULE._recover_input(delta, inverse) == assignment


def test_retained_a154_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gate"]["artifact_sha256"] == MODULE.A152_SHA256
    interface = payload["affine_interface"]
    assert interface["polynomial_state_sha256"] == MODULE.A152_POLYNOMIAL_SHA256
    assert interface["maximum_algebraic_degree"] == 1
    assert interface["constant_term_one_count"] == 788
    assert len(interface["constant_term_one_coordinates"]) == 788
    assert "constant_output_count" not in interface
    assert "constant_output_coordinates" not in interface
    assert interface["matrix_sha256"] == (
        "b79deb595d61764a1eff90120696c462c80bb5bd774605af54947c5b5a4040a0"
    )
    assert interface["row_weight_histogram"] == {"0": 1098, "1": 475, "2": 27}
    basis = payload["basis"]
    assert basis["rank"] == 24
    assert basis["input_nullity"] == 0
    assert basis["output_affine_relation_dimension"] == 1576
    assert basis["selected_output_coordinates"] == SELECTED_OUTPUTS
    assert basis["first_coordinate_reaching_full_rank"] == 136
    assert basis["systematic_unit_row_basis"] is True
    assert sorted(basis["pivot_delta_to_input_coordinate"]) == list(range(24))
    assert payload["inverse_proof"]["left_inverse_exact"] is True
    assert payload["inverse_proof"]["right_inverse_exact"] is True
    verification = payload["verification"]
    assert verification["assignments_checked"] == 64
    assert verification["three_way_state_bits_checked"] == 307_200
    assert verification["pivot_output_inverse_recovers_every_checked_input"] is True
    lowered = raw.decode().lower()
    assert '"instrumented_assignment":' not in lowered
    assert '"target_rate_sha256":' not in lowered
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert len(reader.triplets(include_inferred=False)) == 4


def test_complete_a154_rerun_is_byte_deterministic(tmp_path: Path) -> None:
    output = tmp_path / MODULE.RESULT_FILENAME
    causal = tmp_path / MODULE.CAUSAL_FILENAME
    summary = MODULE.run(ANCHOR_PATH, output, causal)
    assert summary["json_sha256"] == RESULT_SHA256
    assert summary["causal_sha256"] == CAUSAL_SHA256
    assert summary["causal_graph_sha256"] == CAUSAL_GRAPH_SHA256
    assert summary["rank"] == 24
    assert summary["selected_output_coordinates"] == SELECTED_OUTPUTS
