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
    / "shake_symbolic_r2_partition_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_partition_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_PARTITION = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PARTITION
_SPEC.loader.exec_module(_PARTITION)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_branch_schedule_fixes_only_declared_prefix() -> None:
    writer = _PARTITION._SMT.BooleanSMT(123)
    inputs = [writer.declare("x") for _ in range(4)]
    raw = _PARTITION._branch_raw(writer, inputs, 2, 0b01).decode()
    assert "(assert x0)" in raw
    assert "(assert (not x1))" in raw
    assert "(assert x2)" not in raw
    assert "(assert x3)" not in raw


def test_independent_model_verifier_checks_complete_rate() -> None:
    variant = _PARTITION._BASE.VARIANTS["shake128"]
    problem = _PARTITION._NATIVE._problem(variant, 4, 89751001)
    actual = _PARTITION._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    assert _PARTITION._verify_assignment(problem, variant, actual)[
        "complete_rate_match"
    ]
    assert not _PARTITION._verify_assignment(problem, variant, actual ^ 1)[
        "complete_rate_match"
    ]


def test_two_branch_reader_finds_and_proves_small_window(tmp_path: Path) -> None:
    variant = _PARTITION._BASE.VARIANTS["shake128"]
    row = _PARTITION._partition_trial(
        variant,
        4,
        89751001,
        1,
        30,
        2,
        _z3(),
        tmp_path,
        False,
    )
    assert row["ground_truth_used_for_branch_schedule"] is False
    assert row["reconstruction_matches_ground_truth"]
    assert row["global_uniqueness_proved"]
    assert row["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }


def test_partition_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-partition.causal"
    _PARTITION._build_graph(path, 16, 4, 60, 8)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"]
        == "reader_solve_each_exact_R2_plus_R3_R24_native_xor_branch"
    ]
    assert len(recipes) == 1
    assert recipes[0]["prefix_source"] == "none_from_ground_truth"
