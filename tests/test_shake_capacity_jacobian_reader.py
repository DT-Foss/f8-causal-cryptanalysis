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
    / "shake_capacity_jacobian_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_capacity_jacobian_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_JACOBIAN = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _JACOBIAN
_SPEC.loader.exec_module(_JACOBIAN)


def _base_state(variant, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    message = rng.integers(
        0,
        256,
        size=(1, variant.message_bytes),
        dtype=np.uint8,
    )
    return _JACOBIAN._BASE._first_squeeze_state(message, variant)[0]


def test_shake_capacity_boolean_jacobians_have_full_rank() -> None:
    for index, variant in enumerate(_JACOBIAN._BASE.VARIANTS.values()):
        responses = _JACOBIAN._intervention_responses(
            _base_state(variant, 89528001 + index),
            variant,
            _JACOBIAN._reader_recipe(variant),
        )
        assert responses.shape == (variant.capacity_bits, variant.rate_lanes)
        assert _JACOBIAN._gf2_rank(responses) == variant.capacity_bits
        assert len(set(_JACOBIAN._signature_bytes(responses))) == variant.capacity_bits


def test_shake_same_base_signature_reader_identifies_every_capacity_bit() -> None:
    variant = _JACOBIAN._BASE.VARIANTS["shake128"]
    responses = _JACOBIAN._intervention_responses(
        _base_state(variant, 89528111),
        variant,
        _JACOBIAN._reader_recipe(variant),
    )
    expected = np.arange(variant.capacity_bits, dtype=np.int64)
    result = _JACOBIAN._signature_reader_accuracy(responses, responses, expected)
    assert result["matches"] == variant.capacity_bits
    assert result["accuracy"] == 1.0


def test_shake_capacity_recipe_is_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "shake-capacity.causal"
    _JACOBIAN._build_graph(path, bases=2, routes=2, pair_tests=8)
    recipes, rows = _JACOBIAN._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 6
    assert recipes["shake128"]["capacity_bits"] == 256
    assert recipes["shake256"]["capacity_bits"] == 512
    assert all(recipe["permutation_rounds"] == 24 for recipe in recipes.values())


def test_shake_capacity_controls_separate_local_rank_from_global_linearity() -> None:
    variant = _JACOBIAN._BASE.VARIANTS["shake128"]
    recipe = _JACOBIAN._reader_recipe(variant)
    first = _base_state(variant, 89528222)
    second = _base_state(variant, 89528223)
    first_responses = _JACOBIAN._intervention_responses(first, variant, recipe)
    second_responses = _JACOBIAN._intervention_responses(second, variant, recipe)
    expected = np.arange(variant.capacity_bits, dtype=np.int64)
    cross = _JACOBIAN._signature_reader_accuracy(
        second_responses, first_responses, expected
    )
    assert cross["matches"] == 0
    routes = _JACOBIAN._route_controls(first_responses, 4, 89528224)
    assert routes["total_matches"] == 0
    pairs = _JACOBIAN._two_bit_interactions(
        first,
        variant,
        recipe,
        first_responses,
        count=32,
        rng=np.random.default_rng(89528225),
    )
    assert pairs["exact_superpositions"] == 0
    assert 0.45 < pairs["bit_agreement"] < 0.55
