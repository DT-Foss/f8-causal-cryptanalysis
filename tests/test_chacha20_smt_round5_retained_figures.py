from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "chacha20_smt_round5_retained_figures.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_smt_round5_retained_figures_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
A187_FIGURE_PATH = RESULTS_DIR / MODULE.A187_FIGURE
A188_FIGURE_PATH = RESULTS_DIR / MODULE.A188_FIGURE
A189_FIGURE_PATH = RESULTS_DIR / MODULE.A189_FIGURE
A187_FIGURE_SHA256 = (
    "7b857aef108c5b6735ce5929a80f42073a689974036fe0ad0eab7e688a195be5"
)
A188_FIGURE_SHA256 = (
    "05ad13e0c16d8fa7eca0b960e17595e22d206553e032a32a0792033a04c035aa"
)
A189_FIGURE_SHA256 = (
    "ec6d4dcc0cc07514313fc9bca446076a36f3547c8fb929e98c5e7775c912d9cc"
)


def test_retained_a187_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A187_FILENAME).read_bytes())
    rendered = MODULE.render_a187(payload)
    assert rendered == A187_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A187_FIGURE_SHA256
    assert b"35,285" in rendered
    assert b"1,686" in rendered
    assert b"20.93" in rendered
    assert b"75.54" in rendered


def test_retained_a188_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A188_FILENAME).read_bytes())
    rendered = MODULE.render_a188(payload)
    assert rendered == A188_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A188_FIGURE_SHA256
    assert b"0x5345585503" in rendered
    assert b"4096/4096 bits" in rendered
    assert b"b4 prediction not retained" in rendered


def test_retained_a189_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A189_FILENAME).read_bytes())
    rendered = MODULE.render_a189(payload)
    assert rendered == A189_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A189_FIGURE_SHA256
    assert b"low20 = 0x6fa70" in rendered
    assert b"Prospective bitblast b8 prediction retained" in rendered
    assert b"independent 512-bit check" in rendered
