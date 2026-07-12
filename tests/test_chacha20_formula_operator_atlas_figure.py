from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_formula_operator_atlas_figure.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_formula_operator_atlas_figure_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULT_PATH = ROOT / "research" / "results" / "v1" / MODULE.RESULT_FILENAME
FIGURE_PATH = ROOT / "research" / "results" / "v1" / MODULE.FIGURE_FILENAME
FIGURE_SHA256 = "ea1aca532e540a04c1bdecd2d9cee2744331e7c44aa6596b045bed3db5846cd0"


def test_a199_figure_is_deterministic_exact_and_scoped() -> None:
    payload = MODULE._load(RESULT_PATH)
    rendered = MODULE.render(payload)
    assert rendered == FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == FIGURE_SHA256
    assert rendered.count(b'data-series="adjacent-column-diagonal"') == 20
    assert rendered.count(b'data-series="same-phase-lag2"') == 19
    assert rendered.count(b'data-null-replicate="') == 32
    assert b"mean contrast = 40.12" in rendered
    assert b"H2 not retained" in rendered
    assert b"Fiedler filtration" in rendered
    assert b"not a demonstrated multimode mixture" in rendered
    assert b"no hidden assignment" in rendered
    assert b"no key-recovery claim" in rendered


def test_a199_figure_cli_check_accepts_the_retained_svg() -> None:
    MODULE.main(["--result", str(RESULT_PATH), "--output", str(FIGURE_PATH), "--check"])
