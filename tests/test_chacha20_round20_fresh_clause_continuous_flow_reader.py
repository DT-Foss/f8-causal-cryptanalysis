from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT
    / "research/experiments/chacha20_round20_fresh_clause_continuous_flow_reader.py"
)
PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_fresh_clause_continuous_flow_reader_v1.json"
)


def _load() -> object:
    spec = importlib.util.spec_from_file_location("a262_reader_test_module", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def test_a262_frozen_protocol_and_analyze_gate() -> None:
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    protocol = json.loads(PROTOCOL.read_bytes())
    assert protocol["attempt_id"] == "A262"
    assert protocol["operator"]["operator_setting_count"] == 27
    analyzed = MODULE.analyze()
    assert analyzed["continuous_counter_reconstruction_started"] is False
    assert analyzed["new_solver_measurements_permitted"] is False


def test_a262_information_boundary_and_continuous_contract() -> None:
    protocol = json.loads(PROTOCOL.read_bytes())
    boundary = protocol["information_boundary"]
    feature = protocol["feature_contract"]
    assert boundary["any_A251_measurement_shard_opened_by_A262_before_protocol_freeze"] is False
    assert boundary["any_A251_clause_counter_reconstructed_by_A262_before_protocol_freeze"] is False
    assert boundary["any_A262_continuous_feature_support_effect_rank_or_model_fit_known_before_protocol_freeze"] is False
    assert feature["candidate_numeric_value_or_bits_included"] is False
    assert feature["target_output_bit_values_included"] is False
    assert feature["outer_test_true_prefix_used_for_fit_selection_or_weighting"] is False
