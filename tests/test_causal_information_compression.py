from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/causal_information_compression_suite.py"
    spec = spec_from_file_location("causal_information_compression_suite", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_conditional_code_gain_separates_identity_from_independence() -> None:
    suite = _load_suite()
    rng = np.random.default_rng(42)
    first = rng.integers(0, 256, size=(20_000, 1), dtype=np.uint8)
    identical_next = np.zeros_like(first)
    independent_next = rng.integers(0, 256, size=(20_000, 1), dtype=np.uint8)
    identity_gain = suite._mutual_information_matrix(first, identical_next, 5)[0, 0]
    independent_gain = suite._mutual_information_matrix(first, independent_next, 5)[0, 0]
    assert identity_gain > 2.9
    assert independent_gain < 0.01
