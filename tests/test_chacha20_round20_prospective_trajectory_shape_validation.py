from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_prospective_trajectory_shape_validation.py"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("a268_validation", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a268_frozen_protocol_and_model_are_replayable_before_measurement() -> None:
    module = _load_runner()
    summary = module.analyze()
    assert summary == {
        "attempt_id": "A268",
        "protocol_sha256": module.PROTOCOL_SHA256,
        "prospective_key_count": 20,
        "candidate_measurements": 5120,
        "frozen_model_sha256": "b096c08616a81712da881862b65f0c95388e4db3cf6b8e462bf7c2a072cb0da4",
        "prospective_design_sha256": "3e9802757bf3fc93de0d4253e1f5991ba4b067e1f5b373a9bc6ff906eff1cbb4",
        "solver_measurement_started": False,
    }


def test_a268_frozen_model_scores_without_refit() -> None:
    module = _load_runner()
    protocol, preflight, *_ = module._load_protocol()
    model = module._frozen_model(protocol, preflight)
    assert len(model.coefficients) == 532
    assert model.ridge_lambda == 10.0
    assert preflight["information_boundary"]["any_A268_solver_measurement_started"] is False


def test_a268_terminal_prefix_label_parser_ignores_prospective_prefix() -> None:
    module = _load_runner()
    assert module._prefix_index_from_label("a268_prospective_p00_fit_s03") == 0
    assert module._prefix_index_from_label("a268_prospective_p04_fit_s02") == 4
    with pytest.raises(RuntimeError, match="terminal prefix index"):
        module._prefix_index_from_label("a268_prospective_without_index")
