from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_trajectory_shape_preflight.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("a267_preflight", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a267_preflight_is_synthetic_and_complete() -> None:
    payload = _load_runner().build_preflight()
    assert payload["geometry"]["base_feature_count"] == 133
    assert payload["geometry"]["orbit_feature_count"] == 532
    assert payload["synthetic_nested_transfer"]["mean_log2_rank"] == 0.0
    assert payload["synthetic_nested_transfer"]["exact_shared_xor_p"] == 1.0 / 256.0
    assert payload["information_boundary"]["used_any_A251_measurement_shard"] is False
