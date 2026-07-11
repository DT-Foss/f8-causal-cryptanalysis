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
    / "shake_symbolic_r2_smt_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_smt_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_SMT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SMT
_SPEC.loader.exec_module(_SMT)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_boolean_smt_preserves_native_nary_xor_and_blocking_clause() -> None:
    writer = _SMT.BooleanSMT(123)
    inputs = [writer.declare("x") for _ in range(3)]
    writer.define(writer.xor(inputs), "s")
    raw = writer.render(inputs, blocked_assignment=0b101).decode()
    assert "(xor x0 x1 x2)" in raw
    assert "(assert (or (not x0) x1 (not x2)))" in raw


def test_smt_model_and_statistics_parser() -> None:
    output = "sat\n((x0 true)\n (x1 false))\n(:decisions 17 :conflicts 3)\n"
    assert _SMT._parse_status(output) == "sat"
    assert _SMT._parse_assignment(output, ["x0", "x1"]) == 1
    assert _SMT._parse_stats(output)["decisions"] == 17
    assert _SMT._parse_status("timeout\n(:decisions 99)\n") == "unknown"


def test_native_xor_reader_reconstructs_and_proves_small_window(tmp_path: Path) -> None:
    variant = _SMT._BASE.VARIANTS["shake128"]
    baseline = _SMT._load_baseline(
        Path(__file__).parents[1]
        / "research"
        / "results"
        / "v1"
        / "shake_boolean_cnf_reader_v1.json"
    )[4]
    row = _SMT._trial(
        variant,
        4,
        89751001,
        30,
        _z3(),
        tmp_path,
        False,
        baseline,
    )
    assert row["reconstruction_matches_ground_truth"]
    assert row["unique_assignment_proved"]
    assert row["encoding"]["native_xor_equations"]
    assert row["native_xor_decision_ratio_vs_cnf"] < 0.1


def test_symbolic_smt_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-symbolic-smt.causal"
    _SMT._build_graph(path, [4, 8], 30)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"]
        == "reader_encode_exact_R3_through_R24_boolean_suffix"
    ]
    assert len(recipes) == 1
    assert recipes[0]["suffix_rounds"] == list(range(2, 24))
