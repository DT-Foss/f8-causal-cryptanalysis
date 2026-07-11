from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_r4_parity_discovery.py"
    spec = spec_from_file_location("chacha_r4_parity_discovery_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_moments_recover_fixed_pair_parity() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(4)
    difference = rng.integers(0, 256, size=(5000, 64), dtype=np.uint8)
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    bits[:, 11] = bits[:, 7]
    packed = np.packbits(bits, axis=1, bitorder="little")
    unary, pair = suite._moments(packed)
    assert abs(unary[7]) < 0.05
    assert pair[7, 11] > 0.99


def test_pair_ranker_uses_global_null_maximum() -> None:
    suite = _load_suite()
    effects = np.zeros((3, 8, 8))
    null = np.zeros_like(effects)
    effects[:, 2, 5] = 0.2
    effects[:, 5, 2] = 0.2
    null[:, 1, 4] = 0.05
    null[:, 4, 1] = 0.05
    rows, maximum = suite._rank_pairs(effects, null, 2)
    assert np.isclose(maximum, 0.05)
    assert rows[0]["first"]["flat_bit"] == 2
    assert rows[0]["second"]["flat_bit"] == 5
    assert rows[0]["absolute_effect_over_global_null_max"] == 4.0
