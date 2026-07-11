from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_r4_counter_domain_suite.py"
    spec = spec_from_file_location("chacha_r4_counter_domain_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_domain_invariants_and_orientations() -> None:
    suite = _load_suite()
    low = suite._domain("low_range", 1000, 42)
    shuffled = suite._domain("low_range_shuffled", 1000, 42)
    reversed_bits = suite._domain("bit_reversed_low_range", 1000, 42)
    assert np.array_equal(np.sort(low), np.sort(shuffled))
    assert np.array_equal(suite._bit_reverse32(reversed_bits), low)
    assert np.all((suite._domain("fixed_high16_random_low16", 1000, 42) >> 16) == (
        suite._domain("fixed_high16_random_low16", 1000, 42)[0] >> 16
    ))
