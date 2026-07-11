from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_bit_round_frontier_screen.py"
    spec = spec_from_file_location("chacha_bit_round_frontier_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_screen_metrics_separate_constant_from_random_difference() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(7)
    constant = np.zeros((5000, 64), dtype=np.uint8)
    random = rng.integers(0, 256, size=(5000, 64), dtype=np.uint8)
    structured = suite._metrics(constant, 5)
    null = suite._metrics(random, 5)
    assert structured["entropy_deficit_sum"] > null["entropy_deficit_sum"] + 400
    assert structured["mean_reduced_byte_chi2"] > null["mean_reduced_byte_chi2"] * 100
    assert structured["zlib_savings"] > 0.9


def test_pairing_control_detects_fixed_differential() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(11)
    first = rng.integers(0, 256, size=(2000, 64), dtype=np.uint8)
    second = first ^ np.uint8(1)
    result = suite._analyse_pair(first, second, shift=5, routes=3, seed=12)
    assert result["effects"]["entropy_deficit_sum"]["difference"] > 400
