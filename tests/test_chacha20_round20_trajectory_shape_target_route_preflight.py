from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT
    / "research/experiments/chacha20_round20_trajectory_shape_target_route_preflight.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("a269_target_route_preflight", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_route_is_fixed_from_a267_before_a268_result(tmp_path: Path) -> None:
    module = _load()
    module.A268_RESULT = tmp_path / "not-yet-created-a268-result.json"
    payload = module.build_preflight()
    basis = payload["A267_fixed_route_basis"]
    plan = payload["frozen_plan"]
    assert payload["attempt_id"] == "A269"
    assert basis["top128_count"] == 17
    assert basis["top128_fraction"] == 0.85
    assert plan["target_count"] == 4
    assert plan["deep_recovery"]["maximum_candidate_regions"] == 128
    assert plan["deep_recovery"]["strict_subset_of_complete_256_region_cover"] is True
    assert plan["shallow_measurement"]["model_refit_or_coefficient_update_permitted"] is False
    assert payload["information_boundary"]["A268_scores_ranks_or_XOR_controls_read_at_freeze"] is False
    assert payload["information_boundary"]["future_target_generated_at_freeze"] is False


def test_preflight_source_has_no_a268_result_reader() -> None:
    source = SOURCE.read_text()
    assert "json.loads(A268_RESULT" not in source
    assert "A268_RESULT.read" not in source
    assert "DEEP_MAX_CELLS = 128" in source
    assert "DEEP_SECONDS_PER_CELL = 30.0" in source
