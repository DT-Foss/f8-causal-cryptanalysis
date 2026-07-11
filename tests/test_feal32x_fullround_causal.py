from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader


_ROOT = Path(__file__).parents[1]
_BASE_PATH = _ROOT / "research" / "experiments" / "feal32x_fullround_distance2_causal.py"
_BASE_SPEC = importlib.util.spec_from_file_location("feal32x_fullround_distance2_causal", _BASE_PATH)
assert _BASE_SPEC is not None and _BASE_SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(_BASE)

_INVERSE_PATH = _ROOT / "research" / "experiments" / "feal32x_fullround_reader_inverse.py"
_INVERSE_SPEC = importlib.util.spec_from_file_location("feal32x_fullround_reader_inverse", _INVERSE_PATH)
assert _INVERSE_SPEC is not None and _INVERSE_SPEC.loader is not None
_INVERSE = importlib.util.module_from_spec(_INVERSE_SPEC)
_INVERSE_SPEC.loader.exec_module(_INVERSE)


def test_feal32x_official_ntt_vector_and_intermediates() -> None:
    kat = _BASE._kat()
    assert kat["official_vector_match"]
    assert kat["ciphertext"] == "9c9b54973df685f8"
    assert kat["initial_state"] == "196a9ab1f97f1b21"
    assert kat["r32_state"] == "932ddf1603e932d4"
    assert kat["first_eight_round_subkeys"] == "751971f984e9488688e5523b4ea47ade"


def test_feal32x_fullround_distance2_and_inverse() -> None:
    rng = np.random.default_rng(88728001)
    key = rng.bytes(16)
    plaintexts = rng.integers(0, 256, size=(128, 8), dtype=np.uint8)
    trace, _, expanded = _BASE._encrypt_trace(plaintexts, key)
    left30, right30 = trace[30]
    left32, _ = trace[32]
    delta = left30 ^ left32
    subkey = expanded[60:62]
    assert np.array_equal(delta, _BASE._f(right30, subkey))
    reconstructed = _INVERSE._execute_reader_recipe(
        delta,
        subkey,
        _INVERSE.INVERSE_RECIPE,
    )
    assert np.array_equal(reconstructed, right30)


def test_feal32x_causal_reader_supplies_executable_inverse(tmp_path: Path) -> None:
    path = tmp_path / "feal32x-inverse.causal"
    _INVERSE._build_graph(path, pairs=128, keys=1, routes=4)
    recipe, rows = _INVERSE._recipe_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 5
    assert recipe["output_order"] == ["x0", "x1", "x2", "x3"]
