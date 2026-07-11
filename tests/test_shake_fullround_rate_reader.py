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
    / "shake_fullround_rate_reader.py"
)
_SPEC = importlib.util.spec_from_file_location("shake_fullround_rate_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SHAKE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SHAKE
_SPEC.loader.exec_module(_SHAKE)


def test_keccak_zero_state_and_shake_vectors() -> None:
    kat = _SHAKE._kat()
    assert kat["keccak_f1600_zero_state_match"]
    assert len(kat["keccak_f1600_zero_state_lanes"]) == 25
    assert len(kat["vectors"]) == 4
    assert all(row["hashlib_full_rate_match"] for row in kat["vectors"])
    assert all(row["embedded_empty_vector_match"] for row in kat["vectors"])


def test_shake_projection_rank_and_kernel_dimensions() -> None:
    expected = {"shake128": (1344, 256), "shake256": (1088, 512)}
    for key, variant in _SHAKE.VARIANTS.items():
        proof = _SHAKE._projection_proof(variant)
        assert proof["basis_vectors_checked"] == 1600
        assert proof["complete_coordinate_projection_proof"]
        assert (
            proof["projection_rank_bits"],
            proof["kernel_dimension_bits"],
        ) == expected[key]


def test_shake_reader_reconstructs_post_permutation_rate_lanes() -> None:
    rng = np.random.default_rng(89428001)
    for variant in _SHAKE.VARIANTS.values():
        messages = rng.integers(
            0,
            256,
            size=(67, variant.message_bytes),
            dtype=np.uint8,
        )
        state, output = _SHAKE._first_squeeze_state(messages, variant)
        reconstructed = _SHAKE._execute_reader_recipe(
            output, _SHAKE._reader_recipe(variant)
        )
        assert np.array_equal(reconstructed, state[:, : variant.rate_lanes])


def test_shake_causal_reader_supplies_both_rate_recipes(tmp_path: Path) -> None:
    path = tmp_path / "shake.causal"
    proofs = {
        key: _SHAKE._projection_proof(variant)
        for key, variant in _SHAKE.VARIANTS.items()
    }
    _SHAKE._build_graph(path, proofs, pairs=64, seeds=1, routes=2)
    recipes, rows = _SHAKE._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 42
    assert recipes["shake128"]["output_lanes"] == 21
    assert recipes["shake256"]["output_lanes"] == 17


def test_shake_routes_and_representation_controls_localize_projection() -> None:
    rng = np.random.default_rng(89428111)
    variant = _SHAKE.VARIANTS["shake128"]
    messages = rng.integers(
        0,
        256,
        size=(128, variant.message_bytes),
        dtype=np.uint8,
    )
    result = _SHAKE._confirm_seed(
        messages,
        variant,
        _SHAKE._reader_recipe(variant),
        route_count=4,
        seed=89428112,
    )
    assert result["factual_rate_reader"]["state_accuracy"] == 1.0
    assert result["prefix_32_byte_projection"]["state_accuracy"] == 1.0
    assert result["bvn_routes"]["total_state_matches"] == 0
    assert result["wrong_lane_rotation_control"]["state_matches"] == 0
    assert result["wrong_lane_endianness_control"]["state_matches"] == 0
    assert result["hashlib_oracle_matches"] == result["hashlib_oracle_total"]
    assert result["factual_above_all_bvn_routes"]
