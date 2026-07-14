from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_cross_material_composite_recovery.py"
)
PROTOCOL = ROOT / "research/configs/chacha20_round20_cross_material_composite_recovery_v1.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a281_preflight_and_analyze_preserve_the_complete_frozen_schedule(
    tmp_path: Path,
) -> None:
    del tmp_path
    protocol = json.loads(PROTOCOL.read_bytes())
    assert protocol["information_boundary"]["target_generation_label_available"] is False
    assert protocol["information_boundary"]["correct_prefix_or_rank_known"] is False
    assert protocol["information_boundary"]["any_A281_solver_execution_started"] is False
    order = protocol["frozen_order"]
    assert len(order["top128_cell_order"]) == 128
    assert len(order["residual_cell_order"]) == 128
    assert order["top128_cell_order"] == order["complete_cell_order"][:128]
    assert order["residual_cell_order"] == order["complete_cell_order"][128:]
    assert not set(order["top128_cell_order"]) & set(order["residual_cell_order"])
    assert protocol["information_boundary"][
        "residual_phase_permitted_only_after_all_top128_cells_exact_UNSAT"
    ] is True


def test_a281_top_summary_distinguishes_exact_boundary_from_unknown() -> None:
    runner = _load(RUNNER, "a281_top_summary_test")
    exact = {
        "rows": [{"status": "unsat"}] * 128,
        "sat_found": False,
        "retained_state_continuity_verified": True,
    }
    summary = runner._top_summary(exact)
    assert summary["all_attempted_cells_exact_UNSAT"] is True
    assert summary["logical_assignments_inside_attempted_cells"] == 2**19
    unknown = {
        **exact,
        "rows": [{"status": "unsat"}] * 127 + [{"status": "unknown"}],
    }
    assert runner._top_summary(unknown)["all_attempted_cells_exact_UNSAT"] is False
