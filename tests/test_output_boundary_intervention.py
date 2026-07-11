from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np

from arx_carry_leak.live_casi_v091.ciphers import generate_chacha_stream


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/output_boundary_intervention_suite.py"
    spec = spec_from_file_location("output_boundary_intervention_suite_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_custom_chacha_blocks_match_existing_generator() -> None:
    suite = _load_suite()
    actual = suite._chacha_blocks(4, 3, 42).tobytes()
    expected = generate_chacha_stream(8, rounds=3, seed=42)
    assert actual == expected


def test_phase_pairing_finds_identity_and_repairing_breaks_it() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(17)
    source = rng.integers(0, 256, size=(20_000, 4), dtype=np.uint8)
    paired_next = source ^ np.roll(source, 1, axis=1)
    result = suite._paired_control(source, paired_next, shift=5, routes=3, seed=99)
    assert result["observed"].max() > 2.9
    assert result["excess"].max() > 2.8
