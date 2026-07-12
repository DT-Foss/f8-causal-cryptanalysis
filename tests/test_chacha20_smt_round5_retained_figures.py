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
A190_FIGURE_PATH = RESULTS_DIR / MODULE.A190_FIGURE
A191_FIGURE_PATH = RESULTS_DIR / MODULE.A191_FIGURE
A192_FIGURE_PATH = RESULTS_DIR / MODULE.A192_FIGURE
A193_FIGURE_PATH = RESULTS_DIR / MODULE.A193_FIGURE
A194_FIGURE_PATH = RESULTS_DIR / MODULE.A194_FIGURE
A195_FIGURE_PATH = RESULTS_DIR / MODULE.A195_FIGURE
A196_FIGURE_PATH = RESULTS_DIR / MODULE.A196_FIGURE
A197_FIGURE_PATH = RESULTS_DIR / MODULE.A197_FIGURE
A198_FIGURE_PATH = RESULTS_DIR / MODULE.A198_FIGURE
A187_FIGURE_SHA256 = "7b857aef108c5b6735ce5929a80f42073a689974036fe0ad0eab7e688a195be5"
A188_FIGURE_SHA256 = "05ad13e0c16d8fa7eca0b960e17595e22d206553e032a32a0792033a04c035aa"
A189_FIGURE_SHA256 = "ec6d4dcc0cc07514313fc9bca446076a36f3547c8fb929e98c5e7775c912d9cc"
A190_FIGURE_SHA256 = "fd9c684ff353dd05cd40675b8835e8a8d1cdb014eb2cb944fe710e85d2958a6e"
A191_FIGURE_SHA256 = "85589e6ebadf0fbf8fdc6c8c43c2deb5b7e1dbd15734871d539996db206652ad"
A192_FIGURE_SHA256 = "94f042a20b5867366eb9f4797fc4a6f2f35e1428d90e0a4f76b0ad89f1fbfff4"
A193_FIGURE_SHA256 = "416ff628af2e69d2c35c03c18fd2eeaa62914a50020a1508e45295eb84f34ecd"
A194_FIGURE_SHA256 = "04623342965baea8d9490b8421ea2d21b76129d1e8de654b95687b4d15013b2f"
A195_FIGURE_SHA256 = "6ac8d351204d9bf77ba53b1ebaeb444b486b0ba6e971cc0c685adfcd09faee87"
A196_FIGURE_SHA256 = "64f1fe8b1595a827ce722d3211b5ea0a8a13dd667100ed8f799741781a667e58"
A197_FIGURE_SHA256 = "e6bc70a5b3a05f92ffe36e17afa3c714a8bf4372fe22a8eb6d159689079cd700"
A198_FIGURE_SHA256 = "4ff39853b0f4c5ec6ee7baa1686d2e69f797fcf61ada46d4fdece8a880554e23"


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


def test_retained_a190_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A190_FILENAME).read_bytes())
    rendered = MODULE.render_a190(payload)
    assert rendered == A190_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A190_FIGURE_SHA256
    assert rendered.count(b">UNKNOWN<") == 8
    assert rendered.count(b">INVALID<") == 1
    assert b"zero models were returned" in rendered
    assert b"not an absence claim" in rendered


def test_retained_a191_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A191_FILENAME).read_bytes())
    rendered = MODULE.render_a191(payload)
    assert rendered == A191_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A191_FIGURE_SHA256
    assert rendered.count(b">UNSAT<") == 7
    assert rendered.count(b">SAT<") == 1
    assert b"low18 = 0x3d051" in rendered
    assert b"8 \xc3\x97 2\xc2\xb9\xe2\x81\xb5 = 2\xc2\xb9\xe2\x81\xb8" in rendered
    assert b"does not shrink the candidate domain" in rendered


def test_retained_a192_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A192_FILENAME).read_bytes())
    rendered = MODULE.render_a192(payload)
    assert rendered == A192_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A192_FIGURE_SHA256
    assert rendered.count(b">UNSAT<") == 31
    assert rendered.count(b">SAT<") == 1
    assert b"low20 0x05eb0" in rendered
    assert b"32 \xc3\x97 2\xc2\xb9\xe2\x81\xb5 = 2\xc2\xb2\xe2\x81\xb0" in rendered
    assert b"all 1,048,576 original candidates" in rendered


def test_retained_a193_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A193_FILENAME).read_bytes())
    rendered = MODULE.render_a193(payload)
    assert rendered == A193_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A193_FIGURE_SHA256
    assert rendered.count(b">UNKNOWN<") == 31
    assert rendered.count(b">SAT<") == 1
    assert b"low20 0x5a40a" in rendered
    assert b"structural partition coverage" in rendered
    assert b"uniqueness is not adjudicated" in rendered


def test_retained_a194_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A194_FILENAME).read_bytes())
    rendered = MODULE.render_a194(payload)
    assert rendered == A194_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A194_FIGURE_SHA256
    assert rendered.count(b">UNKNOWN<") == 31
    assert rendered.count(b">SAT<") == 1
    assert b"low20 0x8675b" in rendered
    assert b"structural partition coverage" in rendered
    assert b"uniqueness is not adjudicated" in rendered


def test_retained_a195_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A195_FILENAME).read_bytes())
    rendered = MODULE.render_a195(payload)
    assert rendered == A195_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A195_FIGURE_SHA256
    assert rendered.count(b">UNKNOWN<") == 32
    assert b"zero models are returned" in rendered
    assert b"fresh-instance/cut transfer boundary" in rendered
    assert b"makes no recovery claim" in rendered


def test_retained_a196_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A196_FILENAME).read_bytes())
    a195_payload = json.loads((RESULTS_DIR / MODULE.A195_FILENAME).read_bytes())
    rendered = MODULE.render_a196(payload, a195_payload)
    assert rendered == A196_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A196_FIGURE_SHA256
    assert rendered.count(b"UNKNOWN") == 68
    assert b"A195 \xc2\xb7 split8" in rendered
    assert b"A196 \xc2\xb7 split9" in rendered
    assert b"status-equivalent complete boundaries" in rendered
    assert b"no absence, recovery, or uniqueness claim" in rendered


def test_retained_a197_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A197_FILENAME).read_bytes())
    a195_payload = json.loads((RESULTS_DIR / MODULE.A195_FILENAME).read_bytes())
    a196_payload = json.loads((RESULTS_DIR / MODULE.A196_FILENAME).read_bytes())
    rendered = MODULE.render_a197(payload, a195_payload, a196_payload)
    assert rendered == A197_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A197_FIGURE_SHA256
    assert rendered.count(b'data-prefix="') == 256
    assert b"256 \xc3\x97 2\xc2\xb9\xc2\xb2" in rendered
    assert b"64 deterministic waves" in rendered
    assert b"UNKNOWN is not UNSAT" in rendered
    assert b"no absence, recovery, or uniqueness claim" in rendered


def test_retained_a198_figure_is_deterministic_and_exact() -> None:
    payload = json.loads((RESULTS_DIR / MODULE.A198_FILENAME).read_bytes())
    rendered = MODULE.render_a198(payload)
    assert rendered == A198_FIGURE_PATH.read_bytes()
    assert hashlib.sha256(rendered).hexdigest() == A198_FIGURE_SHA256
    assert rendered.count(b'data-budget="') == 64
    assert b"8 shared-key blocks" in rendered
    assert b"formula bytes and hashes are identical across budgets" in rendered
    assert b"UNKNOWN is not UNSAT" in rendered
    assert b"no absence, recovery, or uniqueness claim" in rendered
