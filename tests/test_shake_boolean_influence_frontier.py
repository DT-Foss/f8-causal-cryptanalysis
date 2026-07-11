from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_boolean_influence_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_boolean_influence_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_INFLUENCE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INFLUENCE
_SPEC.loader.exec_module(_INFLUENCE)


def test_influence_gate_recovers_exact_boolean_derivatives() -> None:
    gate = _INFLUENCE._influence_gate()
    assert gate["exact_match"]
    assert gate["observed_counts"] == gate["expected_counts"]


def test_influence_counts_match_manual_three_variable_functions() -> None:
    assignments = np.arange(8, dtype=np.uint8)
    x0 = assignments & 1
    x1 = (assignments >> 1) & 1
    x2 = (assignments >> 2) & 1
    truth = np.column_stack([x2, x0 ^ (x1 & x2)])
    assert _INFLUENCE._influence_counts(truth).tolist() == [
        [0, 4],
        [0, 2],
        [4, 2],
    ]


def test_round_four_has_complete_window_to_state_coupling() -> None:
    variant = _INFLUENCE._BASE.VARIANTS["shake128"]
    row = _INFLUENCE._trial(variant, 8, 89795001, [0, 3, 4, 24])
    observations = {item["round"]: item for item in row["observations"]}
    assert observations[0]["nonzero_intervention_cells"] == 8
    assert observations[3]["fully_coupled_coordinates"] < 1600
    assert observations[4]["nonzero_intervention_cells"] == 8 * 1600
    assert observations[4]["fully_coupled_coordinates"] == 1600
    assert observations[24]["fully_coupled_coordinates"] == 1600


def test_influence_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-influence.causal"
    _INFLUENCE._build_graph(path, 8, [0, 3, 4, 24], 1)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 6
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"]
        == "reader_pair_every_assignment_under_each_single_bit_intervention"
    ]
    assert len(recipes) == 2
    assert all(recipe["cells_per_observation"] == 8 * 1600 for recipe in recipes)
