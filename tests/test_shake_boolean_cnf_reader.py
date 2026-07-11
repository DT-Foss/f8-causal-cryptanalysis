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
    / "shake_boolean_cnf_reader.py"
)
_SPEC = importlib.util.spec_from_file_location("shake_boolean_cnf_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_CNF = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CNF
_SPEC.loader.exec_module(_CNF)


def _z3() -> Path:
    executable = shutil.which("z3") or "/opt/homebrew/bin/z3"
    path = Path(executable)
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_streaming_header_survives_blocking_clause_append(tmp_path: Path) -> None:
    path = tmp_path / "header.cnf"
    cnf = _CNF.StreamingCNF(path)
    variable = cnf.new_variable()
    cnf.add_clause([variable])
    cnf.finalize()
    cnf.add_clause([-variable])
    cnf.finalize()
    cnf.close()
    result = _CNF._run_z3(_z3(), path, 10, 123, "chb")
    assert result["status"] == "unsat"


def test_boolean_reader_reconstructs_and_proves_small_window(tmp_path: Path) -> None:
    variant = _CNF._BASE.VARIANTS["shake128"]
    row = _CNF._trial(
        variant,
        window_bits=4,
        seed=89751001,
        output_lanes=variant.rate_lanes,
        timeout_seconds=30,
        z3_path=_z3(),
        work_dir=tmp_path,
        keep_cnf=False,
        branching_heuristic="chb",
    )
    assert row["reconstruction_matches_ground_truth"]
    assert row["reconstructed_assignment"] == row["actual_assignment"]
    assert row["unique_assignment_proved"]
    assert row["encoding"]["output_bits"] == variant.rate_lanes * 64


def test_boolean_reader_graph_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-cnf.causal"
    _CNF._build_graph(path, ["shake128"], [4, 8], 21, 30, "Z3 test")
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 2
    assert {row["trigger"].split(":", 1)[0] for row in rows} == {"shake128"}
