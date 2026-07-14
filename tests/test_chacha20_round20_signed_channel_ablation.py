from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
PREFLIGHT = ROOT / "research/experiments/chacha20_round20_signed_channel_ablation_preflight.py"


def _load():
    spec = importlib.util.spec_from_file_location("a271_preflight", PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a271_preflight_freezes_complete_signed_channel_family(tmp_path: Path) -> None:
    module = _load()
    module.OUTPUT = tmp_path / "not-existing-a271.json"
    protocol = module.build_protocol()
    rows = protocol["frozen_model"]["signed_semantic_groups"]
    covered = [index for row in rows for index in row["feature_indices"]]
    assert protocol["view_family"]["group_count"] == 32
    assert protocol["view_family"]["view_count"] == 64
    assert len(covered) == 476
    assert len(covered) == len(set(covered))
    assert protocol["controls"]["shared_XOR_offsets"] == 256
    assert protocol["information_boundary"]["any_A268_grouped_contribution_computed_at_freeze"] is False
    assert protocol["information_boundary"]["model_refit_or_coefficient_update_permitted"] is False
