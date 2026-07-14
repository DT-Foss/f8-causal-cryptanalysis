from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest
import zstandard

ROOT = Path(__file__).parents[1]
PREFLIGHT = (
    ROOT
    / "research/experiments/chacha20_round20_selected_channel_target_preflight.py"
)
RUNNER = ROOT / "research/experiments/chacha20_round20_selected_channel_target_measure.py"
A272_SHARD = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_prospective_validation_v1"
    / "a272_channel_p00_fit_s00.numeric.measurement.json.zst"
)
A268_RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_prospective_trajectory_shape_validation.py"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a273_preflight_discards_injected_generation_label(tmp_path: Path) -> None:
    module = _load(PREFLIGHT, "a273_preflight_test")
    prior = module._prior_geometry()
    injected = next(
        value
        for value in range(2**20)
        if value not in prior["low20"]
        and value >> 12 not in prior["prefix8"]
        and value & 0xFFF not in prior["suffix12"]
    )
    module.OUTPUT = tmp_path / "not-existing-a273.json"
    protocol = module.build_protocol(low20_source=lambda: injected)
    module.assert_secret_free(protocol)
    assert protocol["target"]["ephemeral_generation_label_returned_or_serialized"] is False
    assert protocol["information_boundary"][
        "target_generation_label_discarded_before_protocol_serialization"
    ] is True
    assert protocol["readout"]["target_label_available_to_readout"] is False
    assert protocol["next_execution"]["logical_domain_covered_if_exhausted"] == 2**19


def test_a273_label_free_feature_matrix_exactly_matches_labeled_a272_table() -> None:
    runner = _load(RUNNER, "a273_matrix_test")
    a268 = _load(A268_RUNNER, "a273_a268_matrix_test")
    raw = zstandard.ZstdDecompressor().decompress(A272_SHARD.read_bytes())
    measurement = json.loads(raw)
    expected = a268.build_trajectory_shape_table(measurement).matrix
    actual = runner._target_feature_matrix(measurement)
    np.testing.assert_array_equal(actual, expected)


def test_a273_candidate_order_is_total_deterministic_and_tie_stable() -> None:
    runner = _load(RUNNER, "a273_order_test")
    equal = np.zeros(256, dtype=np.float64)
    assert runner._candidate_order(equal) == list(range(256))
    scores = np.arange(256, dtype=np.float64)
    assert runner._candidate_order(scores) == list(reversed(range(256)))


def test_a273_rejects_any_terminal_stage_or_model_before_serialization() -> None:
    runner = _load(RUNNER, "a273_no_model_gate_test")
    raw = zstandard.ZstdDecompressor().decompress(A272_SHARD.read_bytes())
    measurement = json.loads(raw)
    runner._require_unresolved_measurement(measurement)

    leaked = copy.deepcopy(measurement)
    leaked["run"]["stages"][-1]["status"] = "sat"
    leaked["run"]["stages"][-1]["terminal"] = True
    leaked["run"]["stages"][-1]["model_bits_bit0_through_bit19"] = [0] * 20
    leaked["run"]["cells"][-1]["final_status"] = "sat"
    leaked["run"]["cells"][-1]["terminal_stage_index"] = 3
    with pytest.raises(RuntimeError, match="terminal solver outcome or model"):
        runner._target_feature_matrix(leaked)
