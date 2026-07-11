from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_affine_hull_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location("shake_affine_hull_frontier", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_AFFINE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _AFFINE
_SPEC.loader.exec_module(_AFFINE)


def test_candidate_coordinate_conversion_is_exact() -> None:
    gate = _AFFINE._conversion_gate(89773101)
    assert gate["exact_match"]
    assert gate["coordinate_values_checked"] == 8192


def test_affine_basis_membership_and_exclusion() -> None:
    origin, basis = _AFFINE._affine_basis([0b0011, 0b0101, 0b1001, 0b1111])
    assert len(basis) == 2
    assert _AFFINE._in_affine_hull(origin, basis, 0b0011)
    assert _AFFINE._in_affine_hull(origin, basis, 0b1111)
    assert not _AFFINE._in_affine_hull(origin, basis, 0b0000)


def test_fullround_affine_branch_reader_retains_one_prefix() -> None:
    variant = _AFFINE._BASE.VARIANTS["shake128"]
    row = _AFFINE._trial(variant, 8, 89773001, [24], [4, 5, 6])
    fullround = row["observations"][0]
    assert [
        item["survivor_count"]
        for item in fullround["all_branch_target_membership"]
    ] == [1, 1, 1]
    assert all(
        item["actual_prefix_retained"]
        for item in fullround["all_branch_target_membership"]
    )


def test_affine_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-affine.causal"
    _AFFINE._build_graph(path, 8, [0, 3, 24], [4, 5, 6])
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 4
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_exact_gf2_affine_hull_membership"
    ]
    assert len(recipes) == 2
    assert all(recipe["output_coordinates"] == 128 for recipe in recipes)
