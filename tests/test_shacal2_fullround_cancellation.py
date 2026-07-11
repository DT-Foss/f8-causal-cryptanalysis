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
    / "shacal2_fullround_cancellation_reader.py"
)
_SPEC = importlib.util.spec_from_file_location("shacal2_fullround_cancellation_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SHACAL2 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SHACAL2
_SPEC.loader.exec_module(_SHACAL2)


def test_shacal2_nessie_vectors() -> None:
    kat = _SHACAL2._kat()
    assert len(kat["vectors"]) == 2
    assert all(vector["match"] for vector in kat["vectors"])


def test_shacal2_fullround_shared_t1_cancellation() -> None:
    rng = np.random.default_rng(88828001)
    key = rng.bytes(64)
    plaintexts = rng.integers(0, 256, size=(128, 32), dtype=np.uint8)
    trace = _SHACAL2._trace(plaintexts, key)
    r63, r64 = trace[63], trace[64]
    inputs = {
        "a63": r63[:, 0],
        "b63": r63[:, 1],
        "c63": r63[:, 2],
        "a64": r64[:, 0],
        "e64": r64[:, 4],
    }
    reconstructed = _SHACAL2._execute_recipe(inputs, _SHACAL2.READER_RECIPE)
    assert np.array_equal(reconstructed, r63[:, 3])


def test_shacal2_reader_supplies_cancellation_recipe(tmp_path: Path) -> None:
    path = tmp_path / "shacal2.causal"
    _SHACAL2._build_graph(path, pairs=128, keys=1, routes=4)
    recipe, rows = _SHACAL2._recipe_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 3
    assert recipe["output"] == "d63"
