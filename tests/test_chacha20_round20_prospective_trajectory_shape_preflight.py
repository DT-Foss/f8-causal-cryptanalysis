from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_prospective_trajectory_shape_preflight.py"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("a268_preflight", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a268_prospective_design_is_deterministic_balanced_and_disjoint() -> None:
    module = _load_runner()
    first = module.prospective_design()
    second = module.prospective_design()
    assert first == second
    module.validate_design(first)
    assert len(first) == 20
    assert not {row["prefix8"] for row in first} & module.OLD_PREFIXES
    assert not {row["suffix12"] for row in first} & module.OLD_SUFFIXES


def test_a268_design_labels_expose_only_frozen_group_coordinates() -> None:
    rows = _load_runner().prospective_design()
    assert [row["label"] for row in rows] == [
        f"a268_prospective_p{prefix:02d}_fit_s{suffix:02d}"
        for prefix in range(5)
        for suffix in range(4)
    ]
