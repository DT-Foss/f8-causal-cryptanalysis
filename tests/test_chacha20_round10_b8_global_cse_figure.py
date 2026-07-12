from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
P = ROOT / "research/experiments/chacha20_round10_b8_global_cse_figure.py"
S = importlib.util.spec_from_file_location("a202fig", P)
assert S and S.loader
M = importlib.util.module_from_spec(S)
sys.modules[S.name] = M
S.loader.exec_module(M)
R = ROOT / "research/results/v1" / M.RESULT_FILENAME
F = ROOT / "research/results/v1" / M.FIGURE_FILENAME
FIGURE_SHA = "f2a55ed174737529869e1b01eac41b024257a642bfa22cddb1c26870dc4a692e"


def test_a202_figure():
    raw = M.render(M._load(R))
    assert raw == F.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIGURE_SHA
    assert raw.count(b'data-cell="') == 32
    assert b"byte-identical" in raw
    assert b"UNKNOWN is not UNSAT" in raw


def test_a202_figure_cli():
    M.main(["--result", str(R), "--output", str(F), "--check"])
