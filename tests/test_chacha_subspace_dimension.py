from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_subspace_dimension_suite.py"
    spec = spec_from_file_location("chacha_subspace_dimension_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_subspaces_are_unique_and_oriented() -> None:
    suite = _load_suite()
    low = suite._subspace("low", 14, 10000, 42)
    high = suite._subspace("high", 14, 10000, 42)
    assert len(np.unique(low)) == len(low)
    assert len(np.unique(high)) == len(high)
    assert len(np.unique(low >> 14)) == 1
    assert len(np.unique(high & ((1 << 18) - 1))) == 1
