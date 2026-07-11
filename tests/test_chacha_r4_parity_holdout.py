from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_r4_parity_holdout.py"
    spec = spec_from_file_location("chacha_r4_parity_holdout_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_frozen_features_and_auc() -> None:
    suite = _load_suite()
    difference = np.zeros((100, 64), dtype=np.uint8)
    candidates = [{"first": 0, "second": 1, "training_effect": 1.0}]
    feature = suite._features(difference, candidates)
    assert np.all(feature == 1)
    assert suite._auc(np.ones(100), np.zeros(100)) == 1.0
    assert suite._auc(np.zeros(100), np.ones(100)) == 0.0
