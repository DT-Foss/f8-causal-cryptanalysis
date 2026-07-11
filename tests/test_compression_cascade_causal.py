from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/compression_cascade_causal_suite.py"
    spec = spec_from_file_location("compression_cascade_causal_suite", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_all_single_and_double_compressor_paths_are_lossless() -> None:
    suite = _load_suite()
    data = np.random.default_rng(42).bytes(4096)
    for first in suite.COMPRESSORS:
        encoded, exact = suite._apply_path(data, (first,))
        assert encoded
        assert exact
        for second in suite.COMPRESSORS:
            encoded, exact = suite._apply_path(data, (first, second))
            assert encoded
            assert exact


def test_bh_qvalues_are_monotone_in_rank() -> None:
    suite = _load_suite()
    p_values = [0.001, 0.04, 0.02, 0.8]
    q_values = suite._bh_qvalues(p_values)
    ordered = sorted(zip(p_values, q_values))
    assert all(ordered[index][1] <= ordered[index + 1][1] for index in range(3))
