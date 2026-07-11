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
    / "shake_algebraic_degree_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_algebraic_degree_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_ANF = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _ANF
_SPEC.loader.exec_module(_ANF)


def test_mobius_gate_has_exact_declared_degrees() -> None:
    gate = _ANF._mobius_gate()
    assert gate["exact_match"]
    assert gate["observed_degrees"] == [0, 1, 2, 3]


def test_mobius_transform_recovers_known_anf_coefficients() -> None:
    assignments = np.arange(8, dtype=np.uint8)
    x0 = assignments & 1
    x1 = (assignments >> 1) & 1
    x2 = (assignments >> 2) & 1
    truth = (1 ^ x0 ^ (x1 & x2)).reshape(-1, 1)
    coefficients = _ANF._mobius_transform(truth)
    assert np.flatnonzero(coefficients[:, 0]).tolist() == [0, 1, 6]
    assert np.array_equal(_ANF._mobius_transform(coefficients), truth)


def test_fullround_anf_frontier_reaches_saturated_window_degree() -> None:
    variant = _ANF._BASE.VARIANTS["shake128"]
    row = _ANF._trial(variant, 8, 89784001, [0, 3, 6, 24])
    observations = {item["round"]: item for item in row["observations"]}
    assert observations[0]["maximum_degree"] == 0
    assert observations[3]["maximum_degree"] == 4
    assert observations[6]["maximum_degree"] == 8
    assert observations[24]["maximum_degree"] == 8
    assert 0.49 < observations[24]["coefficient_density"] < 0.51
    assert len(observations[24]["degree_by_coordinate"]) == 128


def test_anf_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-anf.causal"
    _ANF._build_graph(path, 8, [0, 3, 6, 24])
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 4
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_exact_fast_mobius_transform"
    ]
    assert len(recipes) == 2
    assert all(recipe["output_coordinates"] == 128 for recipe in recipes)
