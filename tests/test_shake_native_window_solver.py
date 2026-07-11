from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_native_window_solver.py"
)
_SPEC = importlib.util.spec_from_file_location("shake_native_window_solver", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_NATIVE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _NATIVE
_SPEC.loader.exec_module(_NATIVE)


def _kernel(tmp_path: Path) -> tuple[object, dict]:
    library, metadata = _NATIVE._compile_native(tmp_path)
    return _NATIVE.NativeBitSliceKernel(library), metadata


def test_native_window_parser_extends_beyond_scalar_baseline() -> None:
    assert _NATIVE._parse_windows("24,28,32") == [24, 28, 32]


def test_native_keccak_matches_64_independent_states(tmp_path: Path) -> None:
    kernel, metadata = _kernel(tmp_path)
    gate = _NATIVE._cross_implementation_gate(kernel, 89739101)
    assert gate["exact_match"]
    assert gate["state_bits_checked"] == 102_400
    assert metadata["candidate_pack_width"] == 64


def test_native_candidate_masks_equal_numpy_masks(tmp_path: Path) -> None:
    kernel, _ = _kernel(tmp_path)
    gate = _NATIVE._native_numpy_mask_gate(
        kernel, 89739202, threads=2, window_bits=8
    )
    assert set(gate) == {"shake128", "shake256"}
    assert all(row["exact_native_numpy_identity"] for row in gate.values())


def test_native_window_reader_recovers_exact_assignment(tmp_path: Path) -> None:
    kernel, metadata = _kernel(tmp_path)
    variant = _NATIVE._BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, 8, 89739303)
    result = _NATIVE._solve_window(
        kernel,
        problem["base_state"],
        problem["wrong_state"],
        variant,
        _NATIVE._reader_recipe(variant, metadata["source_sha256"]),
        problem["positions"],
        threads=2,
        stream_packs=2,
        label="test",
    )
    assert result["unique_exact_consistency"]
    assert result["factual_full_matches"] == [result["actual_assignment"]]
    assert result["wrong_target_rejected"]
    assert result["candidate_count"] == 256
    assert result["packed_state_count"] == 4


def test_native_recipes_are_reopened_from_causal_reader(tmp_path: Path) -> None:
    source_sha = _NATIVE._source_sha256()
    path = tmp_path / "shake-native.causal"
    _NATIVE._build_graph(path, [8, 12], source_sha, threads=2, stream_packs=64)
    recipes, rows = _NATIVE._recipes_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 8
    assert recipes["shake128"]["native_source_sha256"] == source_sha
    assert recipes["shake256"]["permutation_rounds"] == 24
