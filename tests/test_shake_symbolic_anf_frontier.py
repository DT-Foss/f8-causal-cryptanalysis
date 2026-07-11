from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_anf_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_anf_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_SYMBOLIC = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SYMBOLIC
_SPEC.loader.exec_module(_SYMBOLIC)


def _evaluate(polynomial: frozenset[int], assignment: int) -> int:
    return sum((mask & ~assignment) == 0 for mask in polynomial) & 1


def test_boolean_ring_multiplication_is_exact_and_idempotent() -> None:
    x0 = frozenset({1})
    x1 = frozenset({2})
    first = _SYMBOLIC._poly_xor(_SYMBOLIC.ONE, x0)
    second = _SYMBOLIC._poly_xor(x0, x1)
    product = _SYMBOLIC._poly_mul(first, second)
    assert _SYMBOLIC._poly_mul(second, second) == second
    for assignment in range(4):
        assert _evaluate(product, assignment) == (
            _evaluate(first, assignment) & _evaluate(second, assignment)
        )


def test_symbolic_two_round_assignment_reader_matches_bitsliced_core() -> None:
    variant = _SYMBOLIC._BASE.VARIANTS["shake128"]
    row = _SYMBOLIC._trial(variant, 8, 89806001, 8)
    assert row["truth_table_assignments_materialized"] == 0
    assert row["assignment_gate"]["exact_match"]
    assert row["assignment_gate"]["state_bits_checked"] == 8 * 1600
    assert row["observations"][2]["maximum_degree"] <= 4


def test_symbolic_k16_matches_complete_mobius_artifact() -> None:
    for variant_index, variant in enumerate(_SYMBOLIC._BASE.VARIANTS.values()):
        row = _SYMBOLIC._trial(
            variant, 16, 89806001 + 100_003 * variant_index, 2
        )
        assert row["cross_gate"]["exact_match"]
        assert all(item["exact_match"] for item in row["cross_gate"]["rounds"])


def test_symbolic_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-symbolic-anf.causal"
    _SYMBOLIC._build_graph(path, [16, 32], 4)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 6
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"]
        == "reader_evaluate_symbolic_formulas_on_independent_assignments"
    ]
    assert len(recipes) == 2
    assert all(recipe["rounds"] == 2 for recipe in recipes)
