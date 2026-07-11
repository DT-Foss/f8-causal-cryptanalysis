from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_counter_traversal_suite.py"
    spec = spec_from_file_location("chacha_counter_traversal_suite_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_traversals_are_deterministic_and_unique() -> None:
    suite = _load_suite()
    for name in suite.TRAVERSALS:
        first = suite._traversal(name, 1000, 42)
        second = suite._traversal(name, 1000, 42)
        assert first.dtype == np.uint32
        assert np.array_equal(first, second)
        assert len(np.unique(first)) == len(first)


def test_shuffle_preserves_binary_multiset_and_bit_reverse_is_involution() -> None:
    suite = _load_suite()
    binary = suite._traversal("binary", 1000, 17)
    shuffled = suite._traversal("binary_shuffled", 1000, 17)
    assert np.array_equal(np.sort(binary), np.sort(shuffled))
    assert np.array_equal(suite._bit_reverse32(suite._bit_reverse32(binary)), binary)
