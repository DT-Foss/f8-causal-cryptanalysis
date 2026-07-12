import hashlib
import importlib.util
from pathlib import Path

R = Path(__file__).parents[1]
P = R / "research/experiments/chacha20_round10_b8_lane_major_figure.py"
S = importlib.util.spec_from_file_location("f", P)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)
J = R / "research/results/v1" / M.RESULT
F = R / "research/results/v1" / M.FIG
H = "2327dd88dbb0f3e432d3e34904f0abed475cb4e5c5f5c9c428f62c10b046dd54"


def test_figure():
    raw = M.render(__import__("json").loads(J.read_bytes()))
    assert raw == F.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == H
    assert raw.count(b"data-cell=") == 32
    assert b"UNKNOWN is not UNSAT" in raw
