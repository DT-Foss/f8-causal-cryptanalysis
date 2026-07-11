from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.live_casi_v091.ciphers import _chacha_block


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "chacha20_fullround_feedforward_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "chacha20_fullround_feedforward_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_CHACHA = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHACHA
_SPEC.loader.exec_module(_CHACHA)


def test_chacha20_rfc8439_vector_and_existing_implementation() -> None:
    kat = _CHACHA._kat()
    assert kat["match"]
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    assert _chacha_block(key, 1, nonce, 20).hex() == kat["expected"]


def test_chacha20_public_reader_never_receives_key_addends() -> None:
    rng = np.random.default_rng(89228001)
    keys, counters, nonces = _CHACHA._fixed_key_inputs(rng, 73)
    initial, core, output = _CHACHA._block_trace(keys, counters, nonces)
    public_addends = _CHACHA._public_addends(counters, nonces)
    assert set(public_addends) == set(_CHACHA.PUBLIC_LANES)
    reconstructed = _CHACHA._execute_reader_recipe(
        output,
        public_addends,
        _CHACHA.PUBLIC_RECIPE,
    )
    assert np.array_equal(reconstructed, core[:, _CHACHA.PUBLIC_LANES])
    assert initial.shape == core.shape == output.shape == (73, 16)


def test_chacha20_known_key_reader_recovers_complete_core() -> None:
    rng = np.random.default_rng(89228111)
    inputs = _CHACHA._fixed_key_inputs(rng, 79)
    initial, core, output = _CHACHA._block_trace(*inputs)
    reconstructed = _CHACHA._execute_reader_recipe(
        output,
        _CHACHA._all_addends(initial),
        _CHACHA.FULL_RECIPE,
    )
    assert np.array_equal(reconstructed, core)


def test_chacha20_reader_recipes_are_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "chacha20.causal"
    _CHACHA._build_graph(path, pairs=64, seeds=1, routes=2)
    recipes, rows = _CHACHA._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 18
    assert recipes["public"]["required_addend_lanes"] == list(_CHACHA.PUBLIC_LANES)
    assert recipes["full"]["required_addend_lanes"] == list(range(16))


def test_chacha20_route_and_addend_controls_localize_lanes() -> None:
    rng = np.random.default_rng(89228222)
    result = _CHACHA._confirm_seed(
        _CHACHA._fixed_key_inputs(rng, 128),
        {"public": _CHACHA.PUBLIC_RECIPE, "full": _CHACHA.FULL_RECIPE},
        route_count=4,
        seed=89228223,
    )
    assert result["factual_public_reader"]["state_accuracy"] == 1.0
    assert result["factual_known_key_reader"]["state_accuracy"] == 1.0
    assert result["public_bvn_routes"]["total_state_matches"] == 0
    assert result["known_key_bvn_routes"]["total_state_matches"] == 0
    assert result["previous_counter_localization"]["word_matches"] == 7 * 128
    assert result["rotated_constants_localization"]["word_matches"] == 4 * 128
    assert result["factual_above_all_routes"]
