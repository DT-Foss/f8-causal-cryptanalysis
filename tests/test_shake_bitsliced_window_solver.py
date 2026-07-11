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
    / "shake_bitsliced_window_solver.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_bitsliced_window_solver", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_BITSLICE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BITSLICE
_SPEC.loader.exec_module(_BITSLICE)


def test_bitsliced_keccak_matches_64_scalar_states() -> None:
    gate = _BITSLICE._cross_implementation_gate(89728001)
    assert gate["exact_match"]
    assert gate["states"] == 64
    assert gate["state_bits_checked"] == 102_400


def test_bitsliced_scalar_roundtrip_preserves_candidate_axis() -> None:
    rng = np.random.default_rng(89728111)
    states = rng.integers(0, 1 << 64, size=(37, 25), dtype=np.uint64)
    planes = _BITSLICE._scalar_to_bitsliced(states)
    assert np.array_equal(_BITSLICE._bitsliced_to_scalar(planes, 37), states)


def test_bitsliced_window_consistency_matches_ground_truth() -> None:
    variant = _BITSLICE._BASE.VARIANTS["shake128"]
    rng = np.random.default_rng(89728222)
    message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    wrong_message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    base = _BITSLICE._BASE._first_squeeze_state(message, variant)[0]
    wrong = _BITSLICE._BASE._first_squeeze_state(wrong_message, variant)[0]
    positions = _BITSLICE._WINDOW._window_positions(
        variant.capacity_bits, 8, 89728223
    )
    result = _BITSLICE._solve_window(
        base,
        wrong,
        variant,
        _BITSLICE._reader_recipe(variant),
        positions,
        pack_batch=2,
    )
    assert result["unique_exact_consistency"]
    assert result["factual_full_matches"] == [result["actual_assignment"]]
    assert result["wrong_target_rejected"]
    assert result["candidate_count"] == 256
    assert result["packed_state_count"] == 4
    assert result["packed_evaluation_reduction_factor"] == 64.0


def test_bitsliced_recipes_are_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "shake-bitsliced.causal"
    _BITSLICE._build_graph(path, [8, 12], pack_batch=16)
    recipes, rows = _BITSLICE._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 6
    assert recipes["shake128"]["candidates_per_machine_word"] == 64
    assert recipes["shake256"]["permutation_rounds"] == 24
