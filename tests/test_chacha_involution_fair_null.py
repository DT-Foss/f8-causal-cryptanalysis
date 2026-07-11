from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_involution_fair_null_suite.py"
    spec = spec_from_file_location("chacha_involution_fair_null_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_random_matching_is_fixed_point_free_bijective_involution() -> None:
    suite = _load_suite()
    mapping = suite._perfect_matching(1000, np.random.default_rng(4))
    indices = np.arange(1000)
    assert np.array_equal(np.sort(mapping), indices)
    assert np.array_equal(mapping[mapping], indices)
    assert not np.any(mapping == indices)


def test_factual_xor_mapping_has_same_invariants() -> None:
    indices = np.arange(256)
    mapping = indices ^ 1
    assert np.array_equal(np.sort(mapping), indices)
    assert np.array_equal(mapping[mapping], indices)
    assert not np.any(mapping == indices)
