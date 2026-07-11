from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_involution_conditional_code_suite.py"
    spec = spec_from_file_location("chacha_involution_conditional_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_conditional_analysis_returns_finite_matrix() -> None:
    suite = _load_suite()
    matching = suite._load_matching()
    rng = np.random.default_rng(4)
    outputs = rng.integers(0, 256, size=(256, 32), dtype=np.uint8)
    result = suite._analyse(
        outputs, counter_bit=0, shift=5, routes=3, seed=9, matching=matching
    )
    assert result["effect_matrix"].shape == (32, 32)
    assert np.isfinite(result["effect_matrix"]).all()
