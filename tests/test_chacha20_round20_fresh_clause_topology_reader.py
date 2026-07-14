from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/chacha20_round20_fresh_clause_topology_reader.py"


def _load():
    name = "a259_clause_topology_reader_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_A259_protocol_is_frozen_before_clause_topology_projection() -> None:
    module = _load()
    analysis = module.analyze()
    assert analysis["attempt_id"] == "A259"
    assert analysis["input_solver_measurements"] == 5120
    assert analysis["new_solver_measurements_permitted"] is False
    assert analysis["public_topology_anchor_groups"] == 51
    assert analysis["operator_settings"] == 27
    assert analysis["clause_topology_projection_started"] is False


def test_A259_anchor_groups_ignore_signs_and_preserve_lane_bit_geometry() -> None:
    module = _load()
    key = [(-1 if bit & 1 else 1) * (100 + bit) for bit in range(20)]
    outputs = [
        [(-1 if (lane + bit) & 1 else 1) * (1000 + 32 * lane + bit) for bit in range(32)]
        for lane in range(16)
    ]
    groups = module._anchor_groups(key, outputs)
    assert len(groups) == 51
    assert groups["key_suffix"] == list(range(100, 112))
    assert groups["key_candidate_prefix"] == list(range(112, 120))
    assert groups["output_lane_03"] == list(range(1096, 1128))
    assert groups["output_bit_07"] == [1007 + 32 * lane for lane in range(16)]
    assert len(groups["output_all"]) == 512
