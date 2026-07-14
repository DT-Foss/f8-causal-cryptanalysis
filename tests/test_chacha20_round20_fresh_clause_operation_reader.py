from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_fresh_clause_operation_reader.py"
PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_clause_operation_reader_v1.json"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("a260_test_module", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def test_a260_frozen_protocol_and_analyze_gate() -> None:
    assert hashlib.sha256(PROTOCOL.read_bytes()).hexdigest() == MODULE.PROTOCOL_SHA256
    protocol = json.loads(PROTOCOL.read_bytes())
    assert protocol["attempt_id"] == "A260"
    assert protocol["operation_tap_preflight"]["named_word_count"] == 640
    assert protocol["operation_tap_preflight"]["operation_bit_count"] == 20480
    assert protocol["operation_tap_preflight"]["mapping_export_count"] == 16
    assert protocol["operation_tap_preflight"]["original_252375_clause_body_is_exact_augmented_prefix"] is True
    assert protocol["operation_tap_preflight"]["total_anchor_group_count"] == 141
    assert protocol["operation_tap_preflight"]["semantic_readout_feature_count_per_variable"] == 23
    analyzed = MODULE.analyze()
    assert analyzed["operation_projection_started"] is False
    assert analyzed["new_solver_measurements_permitted"] is False


def test_a260_information_boundary_and_feature_exclusions() -> None:
    protocol = json.loads(PROTOCOL.read_bytes())
    boundary = protocol["information_boundary"]
    features = protocol["feature_contract"]
    assert boundary["any_A251_learned_clause_projected_through_operation_topology_before_protocol_freeze"] is False
    assert boundary["any_operation_topology_PoE_fit_before_protocol_freeze"] is False
    assert boundary["future_prospective_unknown_target_generated_or_opened"] is False
    assert features["candidate_numeric_value_or_bits_included"] is False
    assert features["target_output_bit_values_included"] is False
    assert features["absolute_learned_variable_or_clause_ID_included"] is False
    assert protocol["input"]["new_solver_measurements_permitted"] is False
