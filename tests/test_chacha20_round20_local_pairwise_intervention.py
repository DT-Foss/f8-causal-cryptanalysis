from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_local_pairwise_intervention.py"


def _load():
    spec = importlib.util.spec_from_file_location("a270_local_pairwise", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a270_fixed_operator_can_improve_a_synthetic_local_peak() -> None:
    module = _load()
    scores = np.full(256, 4.0)
    scores[37] = 3.0
    for bit in range(8):
        scores[37 ^ (1 << bit)] = 0.0
    local = module.local_pairwise_residual(scores)
    assert module.descending_midrank(scores, 37) > 1
    assert module.descending_midrank(local, 37) == 1


def test_a270_protocol_freezes_one_parameter_free_operator(tmp_path: Path) -> None:
    preflight_path = RUNNER.with_name(
        "chacha20_round20_local_pairwise_intervention_preflight.py"
    )
    spec = importlib.util.spec_from_file_location("a270_preflight", preflight_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.OUTPUT = tmp_path / "not-existing-protocol.json"
    protocol = module.build_protocol()
    assert protocol["operator"]["fitted_parameters"] == 0
    assert protocol["controls"]["operator_family_selection"] == 1
    assert protocol["information_boundary"]["local_pairwise_residual_computed_at_freeze"] is False
    assert protocol["information_boundary"]["model_refit_or_coefficient_update_permitted"] is False
