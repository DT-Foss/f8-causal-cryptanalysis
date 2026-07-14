from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_fresh_trajectory_shape_reader.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("a267_reader", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a267_frozen_protocol_is_replayable_without_measurement_work() -> None:
    module = _load_runner()
    assert module.analyze() == {
        "attempt_id": "A267",
        "protocol_sha256": module.PROTOCOL_SHA256,
        "known_key_count": 20,
        "candidate_measurements": 5120,
        "base_feature_count": 133,
        "orbit_feature_count": 532,
        "operator_settings": 4,
        "new_solver_measurements_permitted": False,
        "trajectory_shape_table_construction_started": False,
    }
    protocol = json.loads(module.PROTOCOL.read_bytes())
    assert protocol["information_boundary"][
        "any_A251_trajectory_shape_table_constructed_before_protocol_freeze"
    ] is False
    assert protocol["feature_contract"][
        "candidate_numeric_value_or_bits_included"
    ] is False
