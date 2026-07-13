from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "research" / "experiments" / "chacha20_round20_symbolic_template.py"


def _load():
    spec = importlib.util.spec_from_file_location("test_symbolic_template", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_binary_pattern_decoder_recovers_coordinates() -> None:
    module = _load()
    width = 5
    baseline = [-11, -12, -13, -14, -15]
    rows = [(-1, baseline)]
    for dimension in range(5):
        values = []
        for coordinate, literal in enumerate(baseline):
            values.append(-literal if (coordinate >> dimension) & 1 else literal)
        rows.append((dimension, values))
    assert module._decode_mapping(rows, width=width) == [11, 12, 13, 14, 15]


def test_output_instantiation_changes_only_header_and_units() -> None:
    module = _load()
    base = b"p cnf 600 1\n1 2 0\n"
    mapping = [list(range(2 + 32 * lane, 34 + 32 * lane)) for lane in range(16)]
    words = [0] * 16
    raw, units, manifest = module.instantiate_output(base, mapping, words)
    assert manifest["header"] == "p cnf 600 513"
    assert raw.splitlines()[1] == b"1 2 0"
    assert len(units) == 512
    assert all(value < 0 for value in units)
