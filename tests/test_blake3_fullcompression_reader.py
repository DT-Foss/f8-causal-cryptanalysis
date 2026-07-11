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
    / "blake3_fullcompression_reader.py"
)
_SPEC = importlib.util.spec_from_file_location("blake3_fullcompression_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_BLAKE3 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BLAKE3
_SPEC.loader.exec_module(_BLAKE3)


def test_blake3_official_single_chunk_xof_vectors() -> None:
    kat = _BLAKE3._kat()
    assert kat["reference_raw_sha256"] == _BLAKE3.REFERENCE_RAW_SHA256
    assert kat["test_vectors_raw_sha256"] == _BLAKE3.TEST_VECTORS_RAW_SHA256
    assert len(kat["vectors"]) == 7
    assert all(row["match"] and row["output_bytes"] == 131 for row in kat["vectors"])


def test_blake3_output_equations_hold_after_seven_rounds() -> None:
    rng = np.random.default_rng(89028001)
    inputs = _BLAKE3._random_inputs(rng, 137)
    chaining_value = inputs[0]
    trace, output = _BLAKE3._compress_trace(*inputs)
    post_round7 = trace[-1]
    assert len(trace) == 8
    assert np.array_equal(output[:, :8], post_round7[:, :8] ^ post_round7[:, 8:])
    assert np.array_equal(output[:, 8:], post_round7[:, 8:] ^ chaining_value)


def test_blake3_reader_recipe_reconstructs_complete_post_round_state() -> None:
    rng = np.random.default_rng(89028111)
    inputs = _BLAKE3._random_inputs(rng, 129)
    chaining_value = inputs[0]
    trace, output = _BLAKE3._compress_trace(*inputs)
    reconstructed = _BLAKE3._execute_reader_recipe(
        output,
        chaining_value,
        _BLAKE3.READER_RECIPE,
    )
    assert np.array_equal(reconstructed, trace[-1])


def test_blake3_causal_reader_supplies_typed_recipe(tmp_path: Path) -> None:
    path = tmp_path / "blake3.causal"
    _BLAKE3._build_graph(path, pairs=64, seeds=1, routes=2)
    recipe, rows = _BLAKE3._recipe_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 25
    assert len(recipe["operations"]) == 16
    assert len(recipe["output_order"]) == 16

    rng = np.random.default_rng(89028222)
    inputs = _BLAKE3._random_inputs(rng, 67)
    trace, output = _BLAKE3._compress_trace(*inputs)
    reconstructed = _BLAKE3._execute_reader_recipe(output, inputs[0], recipe)
    assert np.array_equal(reconstructed, trace[-1])


def test_blake3_bvn_and_formula_controls_localize_reader() -> None:
    rng = np.random.default_rng(89028333)
    result = _BLAKE3._confirm_seed(
        _BLAKE3._random_inputs(rng, 128),
        _BLAKE3.READER_RECIPE,
        route_count=4,
        seed=89028334,
    )
    assert result["default_32_byte_pair_xor_projection"]["state_accuracy"] == 1.0
    assert result["factual_full_output_reader"]["state_accuracy"] == 1.0
    assert result["bvn_routes"]["total_state_matches"] == 0
    assert result["wrong_cv_lane_control"]["state_matches"] == 0
    assert result["wrong_high_lane_pairing_control"]["state_matches"] == 0
    assert result["swapped_output_halves_partial_control"]["state_matches"] == 0
    assert result["swapped_output_halves_partial_control"]["word_matches"] == 8 * 128
    assert result["wrong_xor_to_subtraction_control"]["state_matches"] == 0
    assert result["factual_above_all_bvn_routes"]
