from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.trajectory_atlas import FeatureView

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_knownkey_trajectory_atlas.py"


def _module():
    spec = importlib.util.spec_from_file_location("a218_atlas_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_null_permutations_are_deterministic_unique_complete_key_units() -> None:
    module = _module()
    first = module._null_permutations()
    second = module._null_permutations()
    assert first == second
    assert len(first) == 64
    assert len({(tuple(train), tuple(validation)) for train, validation in first}) == 64
    for train, validation in first:
        assert sorted(train) == list(range(16))
        assert sorted(validation) == list(range(8))
        assert train != list(range(16))
        assert validation != list(range(8))


def test_selection_key_obeys_predeclared_metric_then_complexity_order() -> None:
    module = _module()
    base = {
        "feature_family": "F1_local",
        "feature_count": 24,
        "readout": "ridge_logistic",
        "ridge_lambda": 0.01,
        "validation": {
            "mean_log2_rank": 4.0,
            "median_rank": 16.0,
            "hit_at_16": 4,
            "mean_reciprocal_rank": 0.1,
        },
    }
    better_primary = {
        **base,
        "feature_family": "F5_all",
        "feature_count": 120,
        "validation": {**base["validation"], "mean_log2_rank": 3.9},
    }
    assert module._selection_key(better_primary) < module._selection_key(base)
    same_metrics_complex = {
        **base,
        "feature_family": "F2_cross",
        "feature_count": 48,
    }
    assert module._selection_key(base) < module._selection_key(same_metrics_complex)


def test_training_matrix_preserves_one_positive_per_complete_key() -> None:
    module = _module()
    names = ("a", "b")
    challenges = [
        {
            "views": {
                "F1_local": FeatureView(
                    names=names,
                    matrix=np.full((256, 2), float(index)),
                )
            }
        }
        for index in range(3)
    ]
    matrix, labels, returned_names = module._training_matrix(
        challenges,
        family="F1_local",
        target_prefixes=[1, 7, 255],
    )
    assert matrix.shape == (768, 2)
    assert returned_names == names
    assert labels.sum() == 3
    assert np.flatnonzero(labels).tolist() == [1, 256 + 7, 512 + 255]
