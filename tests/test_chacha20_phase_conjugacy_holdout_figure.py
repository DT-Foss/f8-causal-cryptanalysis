from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
P = ROOT / "research/experiments/chacha20_phase_conjugacy_holdout_figure.py"
S = importlib.util.spec_from_file_location("a201_figure", P)
assert S and S.loader
M = importlib.util.module_from_spec(S)
sys.modules[S.name] = M
S.loader.exec_module(M)
R = ROOT / "research/results/v1" / M.RESULT_FILENAME
F = ROOT / "research/results/v1" / M.FIGURE_FILENAME
FIGURE_SHA256 = "e5c18f576e98310a1d2c8986da40577e6be52d8346579fd4a37e7db9ee3e9cd5"


def test_a201_figure_is_exact_and_scoped():
    raw = M.render(M._load(R))
    assert raw == F.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIGURE_SHA256
    assert raw.count(b'data-series="') == 32
    assert b"known Column/Diagonal row-rotation conjugacy" in raw
    assert b"not a new carry leak or cryptanalytic break" in raw


def test_a201_figure_cli_check():
    M.main(["--result", str(R), "--output", str(F), "--check"])
