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
    / "shake_capacity_window_inference.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_capacity_window_inference", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_WINDOW = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _WINDOW
_SPEC.loader.exec_module(_WINDOW)


def _base_and_wrong(variant, seed: int):
    rng = np.random.default_rng(seed)
    first_message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    second_message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    first = _WINDOW._BASE._first_squeeze_state(first_message, variant)[0]
    second = _WINDOW._BASE._first_squeeze_state(second_message, variant)[0]
    return first, second


def test_capacity_window_clear_inject_and_extract_roundtrip() -> None:
    variant = _WINDOW._BASE.VARIANTS["shake128"]
    base, _ = _base_and_wrong(variant, 89628001)
    positions = _WINDOW._window_positions(variant.capacity_bits, 12, 89628002)
    actual = _WINDOW._extract_window(base, variant, positions)
    template = _WINDOW._clear_window(base, variant, positions)
    restored = _WINDOW._inject_candidates(
        template,
        variant,
        positions,
        np.array([actual], dtype=np.uint64),
    )
    assert np.array_equal(restored, base)


def test_capacity_window_reader_uniquely_recovers_small_window() -> None:
    variant = _WINDOW._BASE.VARIANTS["shake128"]
    base, wrong = _base_and_wrong(variant, 89628111)
    target = _WINDOW._BASE._keccak_f1600(base)[:, : variant.rate_lanes]
    wrong_target = _WINDOW._BASE._keccak_f1600(wrong)[:, : variant.rate_lanes]
    positions = _WINDOW._window_positions(variant.capacity_bits, 8, 89628112)
    result = _WINDOW._infer_window(
        base,
        target,
        wrong_target,
        variant,
        _WINDOW._reader_recipe(variant),
        positions,
        batch_size=64,
    )
    assert result["candidate_count"] == 256
    assert result["unique_exact_recovery"]
    assert result["factual_full_matches"] == [result["actual_assignment"]]
    assert result["wrong_target_rejected"]


def test_capacity_window_recipes_are_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "shake-window.causal"
    _WINDOW._build_graph(path, [4, 8], batch_size=64)
    recipes, rows = _WINDOW._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 6
    assert recipes["shake128"]["capacity_bits"] == 256
    assert recipes["shake256"]["capacity_bits"] == 512
    assert all(recipe["permutation_rounds"] == 24 for recipe in recipes.values())


def test_capacity_window_trial_is_deterministic() -> None:
    variant = _WINDOW._BASE.VARIANTS["shake256"]
    recipe = _WINDOW._reader_recipe(variant)
    first = _WINDOW._trial(variant, recipe, 6, batch_size=64, seed=89628222)
    second = _WINDOW._trial(variant, recipe, 6, batch_size=64, seed=89628222)
    assert first == second
    assert first["unique_exact_recovery"]
    assert first["wrong_target_rejected"]
