from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).parents[1] / "research" / "experiments" / "present_fullround_exact_mechanism.py"
_SPEC = importlib.util.spec_from_file_location("present_fullround_exact_mechanism", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MECHANISM = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MECHANISM)


def test_present_exact_single_bit_support() -> None:
    support = _MECHANISM.derive_population_support()
    cells = {
        (row["source_bit"], row["target_bit"])
        for row in support["nonzero_cells"]
    }
    assert support["pLayer_fixed_points"] == [0, 21, 42, 63]
    assert cells == {
        (3, 0),
        (20, 21),
        (23, 21),
        (40, 42),
        (43, 42),
        (60, 63),
        (62, 63),
    }
    assert support["zero_cell_count"] == 4089
    assert support["population_total_mi_nats"] == pytest.approx(0.550893415117103)


def test_present_round_recurrence_identity() -> None:
    gate = _MECHANISM.verify_round_identity(seed=88328001)
    assert gate["all_passed"]
    assert gate["exact_equalities_checked"] == 576
