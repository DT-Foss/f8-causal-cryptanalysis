from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT
    / "research/experiments/chacha20_round20_fresh_clause_operation_flow_reader.py"
)
PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_fresh_clause_operation_flow_reader_v1.json"
)


def _load() -> object:
    spec = importlib.util.spec_from_file_location("a261_flow_reader_test_module", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def test_a261_frozen_protocol_and_analyze_gate() -> None:
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    protocol = json.loads(PROTOCOL.read_bytes())
    assert protocol["attempt_id"] == "A261"
    assert protocol["public_preflight"]["directed_edge_count"] == 1232
    assert protocol["public_preflight"]["mapped_original_variables"] == 80767
    analyzed = MODULE.analyze()
    assert analyzed["clause_flow_projection_started"] is False
    assert analyzed["new_solver_measurements_permitted"] is False


def test_a261_information_boundary_and_residual_contract() -> None:
    protocol = json.loads(PROTOCOL.read_bytes())
    boundary = protocol["information_boundary"]
    feature = protocol["feature_contract"]
    assert boundary["any_A251_measurement_shard_opened_by_A261_before_protocol_freeze"] is False
    assert boundary["any_A251_learned_clause_projected_through_directed_flow_before_protocol_freeze"] is False
    assert boundary["any_operation_flow_PoE_fit_before_protocol_freeze"] is False
    assert feature["candidate_numeric_value_or_bits_included"] is False
    assert feature["target_output_bit_values_included"] is False
    assert feature["true_prefix_used_during_counter_residual_or_feature_selection"] is False
    assert feature["maximum_target_blind_high_dispersion_features_per_key"] == 512
    assert feature["residual_quantile_bins"] == 8
