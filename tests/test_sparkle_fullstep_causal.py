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
    / "sparkle_fullstep_causal.py"
)
_SPEC = importlib.util.spec_from_file_location("sparkle_fullstep_causal", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SPARKLE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SPARKLE
_SPEC.loader.exec_module(_SPARKLE)


def test_sparkle_official_zero_state_vectors_and_inverse() -> None:
    kat = _SPARKLE._kat()
    assert kat["official_raw_sha256"] == _SPARKLE.OFFICIAL_RAW_SHA256
    assert len(kat["vectors"]) == 3
    assert all(row["forward_match"] and row["inverse_match"] for row in kat["vectors"])


def test_sparkle_layers_and_full_permutations_roundtrip() -> None:
    rng = np.random.default_rng(88928001)
    for variant in _SPARKLE.VARIANTS.values():
        states = rng.integers(
            0,
            1 << 32,
            size=(19, 2 * variant.branches),
            dtype=np.uint32,
        )
        alzette = _SPARKLE._alzette_layer(states, variant.branches)
        assert np.array_equal(
            _SPARKLE._alzette_inverse(alzette, variant.branches), states
        )
        linear = _SPARKLE._linear_layer(states, variant.branches)
        assert np.array_equal(
            _SPARKLE._linear_inverse(linear, variant.branches), states
        )
        for step_index in (0, variant.steps - 1):
            stepped = _SPARKLE._step(states, variant.branches, step_index)
            assert np.array_equal(
                _SPARKLE._step_inverse(stepped, variant.branches, step_index), states
            )
        permuted = _SPARKLE._permute(states, variant.branches, variant.steps)
        assert np.array_equal(
            _SPARKLE._permute_inverse(permuted, variant.branches, variant.steps),
            states,
        )


def test_sparkle_exact_linear_and_quotient_orders() -> None:
    expected_linear = {"sparkle256": 6, "sparkle384": 30, "sparkle512": 12}
    expected_quotient = {"sparkle256": 3, "sparkle384": 10, "sparkle512": 3}
    proofs = _SPARKLE._proofs()
    for key, variant in _SPARKLE.VARIANTS.items():
        linear = proofs[key]["linear"]
        quotient = proofs[key]["quotient"]
        assert linear["minimal_order_proved"]
        assert linear["identity_exponent"] == expected_linear[key]
        assert linear["basis_vectors_checked"] == variant.state_bits
        assert quotient["minimal_order_proved"]
        assert quotient["identity_exponent"] == expected_quotient[key]
        assert quotient["full_state_relation_basis_vectors_checked"] == variant.state_bits


def test_sparkle_causal_reader_executes_endpoint_recipes(tmp_path: Path) -> None:
    causal_path = tmp_path / "sparkle.causal"
    proofs = _SPARKLE._proofs()
    _SPARKLE._build_graph(causal_path, proofs, pairs=32, seeds=1, routes=2)
    recipes = _SPARKLE._recipes_from_reader(causal_path)
    reader = CryptoCausalReader(causal_path)
    assert reader.verify_provenance()
    assert len(reader.triplets(include_inferred=False)) == 15

    rng = np.random.default_rng(88928111)
    for key, variant in _SPARKLE.VARIANTS.items():
        initial = rng.integers(
            0,
            1 << 32,
            size=(31, 2 * variant.branches),
            dtype=np.uint32,
        )
        trace = _SPARKLE._trace(initial, variant.branches, variant.steps)
        reconstructed_half = _SPARKLE._execute_projection_recipe(
            trace[-1], variant, recipes[key]["projection"]
        )
        reconstructed_full = _SPARKLE._execute_fullstep_recipe(
            trace[-1], variant, recipes[key]["fullstep"]
        )
        assert np.array_equal(reconstructed_half, trace[-2][:, : variant.branches])
        assert np.array_equal(reconstructed_full, trace[-2])


def test_sparkle_bvn_routes_break_projection_pairing() -> None:
    variant = _SPARKLE.VARIANTS["sparkle256"]
    rng = np.random.default_rng(88928222)
    initial = rng.integers(
        0,
        1 << 32,
        size=(128, 2 * variant.branches),
        dtype=np.uint32,
    )
    recipes = {
        "projection": _SPARKLE._projection_recipe(variant),
        "fullstep": _SPARKLE._fullstep_recipe(variant),
    }
    result = _SPARKLE._confirm_seed(variant, initial, recipes, routes=4, seed=88928223)
    assert result["factual_projection_reader"]["state_accuracy"] == 1.0
    assert result["factual_forward_power_fullstep_reader"]["state_accuracy"] == 1.0
    assert result["bvn_routes"]["total_state_matches"] == 0
    assert result["factual_projection_above_all_bvn_routes"]
