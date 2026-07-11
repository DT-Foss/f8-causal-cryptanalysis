from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_prefix_observability_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_prefix_observability_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_FRONTIER = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _FRONTIER
_SPEC.loader.exec_module(_FRONTIER)


def test_round_composition_matches_independent_full_permutation() -> None:
    gate = _FRONTIER._round_composition_gate(89762101)
    assert gate["exact_direct_bitslice_match"]
    assert gate["exact_scalar_match"]
    assert gate["state_bits_checked"] == 102_400


def test_fullround_prefix_frontier_localizes_exact_boundary() -> None:
    variant = _FRONTIER._BASE.VARIANTS["shake128"]
    result = _FRONTIER._trial(variant, 8, 89762001, [0, 3, 24])
    initial = result["observations"][0]["rate_prefix_frontier"]
    round3 = result["observations"][1]["rate_prefix_frontier"]
    fullround = result["observations"][2]
    assert initial[0]["constant_coordinates"] == variant.rate_lanes * 64
    assert round3[0]["constant_coordinates"] == 0
    assert fullround["rate_prefix_frontier"][4]["constant_coordinates"] == 0
    assert fullround["rate_prefix_frontier"][8]["constant_coordinates"] == (
        variant.rate_lanes * 64
    )
    assert fullround["actual_target_prefix_matches"]["32"] == 1


def test_random_constant_expectation_matches_closed_form() -> None:
    assert _FRONTIER._random_constant_expectation(1344, 0) == 1344.0
    assert _FRONTIER._random_constant_expectation(1344, 1) == 672.0
    assert _FRONTIER._random_constant_expectation(1344, 2) == 168.0
    assert _FRONTIER._random_constant_expectation(1344, 3) == 10.5


def test_prefix_frontier_recipe_is_reopened_from_causal_reader(tmp_path: Path) -> None:
    path = tmp_path / "shake-prefix.causal"
    _FRONTIER._build_graph(path, 8, [0, 3, 24])
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 4
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_exact_constant_coordinate_count"
    ]
    assert len(recipes) == 2
    assert {recipe["capacity_bits"] for recipe in recipes} == {256, 512}
