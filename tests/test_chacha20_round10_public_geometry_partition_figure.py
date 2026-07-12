from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research/experiments/chacha20_round10_public_geometry_partition_figure.py"
SPEC = importlib.util.spec_from_file_location("a200_figure_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
RESULT = ROOT / "research/results/v1" / MODULE.RESULT_FILENAME
FIGURE = ROOT / "research/results/v1" / MODULE.FIGURE_FILENAME
FIGURE_SHA256 = "3bec6b195d6a22549085961d1765a50a3761271584f38a0fd07608ac5668c777"


def test_a200_figure_is_exact_honest_and_deterministic() -> None:
    raw = MODULE.render(MODULE._load(RESULT))
    assert raw == FIGURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIGURE_SHA256
    assert raw.count(b'data-geometry="') == 128
    assert raw.count(b"32 UNKNOWN") == 4
    assert b"Gray = A198 numeric-prefix row span exactly" in raw
    assert b"UNKNOWN is not UNSAT" in raw
    assert b"no absence, recovery, or uniqueness claim" in raw


def test_a200_figure_check_cli_accepts_retained_bytes() -> None:
    MODULE.main(["--result", str(RESULT), "--output", str(FIGURE), "--check"])
