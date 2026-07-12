from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research/experiments/chacha20_cnf_structural_figures.py"
SPEC = importlib.util.spec_from_file_location("chacha20_cnf_structural_figures", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RESULTS = ROOT / "research/results/v1"


def test_a204_a206_figures_are_byte_exact_and_semantically_gated() -> None:
    rendered = MODULE.render_all(RESULTS)
    assert set(rendered) == {row[2] for row in MODULE.RESULTS.values()}
    for filename, raw in rendered.items():
        assert raw == (RESULTS / filename).read_bytes()
        assert raw.startswith(b'<?xml version="1.0"?>')

    a204 = rendered[MODULE.RESULTS["A204"][2]]
    assert a204.count(b"data-cell=") == 32
    assert b"1 SAT \xc2\xb7 25 UNKNOWN" in a204

    a205 = rendered[MODULE.RESULTS["A205"][2]]
    assert a205.count(b"data-candidate=") == 24
    assert b"16 SAT \xc2\xb7 30 UNKNOWN" in a205
    assert b"unique structural candidate confirmed in both modes" in a205

    a206 = rendered[MODULE.RESULTS["A206"][2]]
    assert a206.count(b"data-cell=") == 64
    assert b"64/64 valid UNKNOWN" in a206

    a207 = rendered[MODULE.RESULTS["A207"][2]]
    assert a207.count(b"data-candidate=") == 22
    assert b"352 new cells \xc2\xb7 416 combined calibrated cells" in a207
    assert b"output_unit_bfs_far: 2.759\xc3\x97 conflicts" in a207
