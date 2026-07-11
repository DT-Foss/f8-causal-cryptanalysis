from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r1_scaling_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_scaling_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_R1 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _R1
_SPEC.loader.exec_module(_R1)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_window_parser_is_sorted_and_bounded() -> None:
    assert _R1._parse_windows("24,16,20,16") == [16, 20, 24]
    with pytest.raises(ValueError):
        _R1._parse_windows("41")


def test_r1_reader_reconstructs_and_proves_small_window(tmp_path: Path) -> None:
    variant = _R1._BASE.VARIANTS["shake128"]
    row = _R1._trial(
        variant,
        4,
        89751001,
        30,
        _z3(),
        tmp_path,
        False,
    )
    assert row["matches_instrumented_assignment"]
    assert row["independent_verification"]["complete_rate_match"]
    assert row["unique_assignment_proved"]
    assert row["encoding"]["symbolic_prefix_rounds"] == 1


def test_r1_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-symbolic-r1.causal"
    _R1._build_graph(path, [16, 20], 60)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"]
        == "attach_exact_remaining_23_rounds_and_read_consistent_model"
    ]
    assert len(recipes) == 1
    assert recipes[0]["symbolic_prefix_rounds"] == 1
