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
    / "shake_symbolic_split_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_split_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_SPLIT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SPLIT
_SPEC.loader.exec_module(_SPLIT)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_generalized_r2_prefix_matches_retained_compiler() -> None:
    variant = _SPLIT._BASE.VARIANTS["shake128"]
    problem = _SPLIT._NATIVE._problem(variant, 4, 89751001)
    template = _SPLIT._WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    first_writer = _SPLIT._SMT.BooleanSMT(123)
    _, _, generalized = _SPLIT._compile_symbolic_prefix(
        first_writer, template, variant, problem["positions"], 2
    )
    second_writer = _SPLIT._SMT.BooleanSMT(123)
    _, _, retained = _SPLIT._SMT._compile_symbolic_r2(
        second_writer, template, variant, problem["positions"]
    )
    assert generalized["polynomial_state_sha256"] == retained[
        "r2_polynomial_state_sha256"
    ]
    assert generalized["symbolic_monomials"] == retained[
        "r2_symbolic_monomials"
    ]


@pytest.mark.parametrize("prefix_rounds", [1, 3])
def test_new_split_reconstructs_small_window(
    tmp_path: Path, prefix_rounds: int
) -> None:
    variant = _SPLIT._BASE.VARIANTS["shake128"]
    row = _SPLIT._new_trial(
        variant=variant,
        window_bits=4,
        seed=89751001,
        prefix_rounds=prefix_rounds,
        fixed_prefix_bits=0,
        fixed_prefix_value=None,
        timeout_seconds=30,
        z3=_z3(),
        work_dir=tmp_path,
        keep_smt=False,
    )
    assert row["matches_instrumented_assignment"]
    assert row["independent_verification"]["complete_rate_match"]
    assert row["encoding"]["symbolic_prefix_rounds"] == prefix_rounds


def test_retained_artifacts_are_hash_gated_and_exact() -> None:
    root = Path(__file__).parents[1]
    a135 = _SPLIT._load_hashed_json(
        root / "research/results/v1/shake_symbolic_r2_smt_reader_v1.json",
        _SPLIT.A135_SHA256,
    )
    a136 = _SPLIT._load_hashed_json(
        root / "research/results/v1/shake_symbolic_r2_partition_reader_v1.json",
        _SPLIT.A136_SHA256,
    )
    rows = _SPLIT._retained_r2_trials(a135, a136)
    assert [row["window_bits"] for row in rows] == [12, 16]
    assert all(row["matches_instrumented_assignment"] for row in rows)
    assert all(
        row["independent_verification"]["complete_rate_match"] for row in rows
    )


def test_split_frontier_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-symbolic-split.causal"
    _SPLIT._build_graph(path, [1, 2, 3], 60)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3
    assert any(
        row["mechanism"]
        == "select_minimum_decisions_among_exact_verified_models"
        for row in rows
    )
